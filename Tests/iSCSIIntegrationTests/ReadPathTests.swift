import Foundation
import Testing
@testable import iSCSIMockTarget
@testable import iSCSIKit

/// Hands on what it receives cut into pieces of awkward sizes, so a PDU's
/// header, data and digest each arrive split across chunks.
final class FragmentingTransport: ConnectionTransport, @unchecked Sendable {
    private let inner: any ConnectionTransport
    private let sizes: [Int]
    private var leftover = Data()
    private var turn = 0

    init(wrapping inner: any ConnectionTransport, sizes: [Int]) {
        self.inner = inner
        self.sizes = sizes
    }

    func send(_ data: Data) async throws { try await inner.send(data) }

    // One reader at a time, as every transport's contract has it.
    func receive() async throws -> Data? {
        if leftover.isEmpty {
            guard let chunk = try await inner.receive() else { return nil }
            leftover = chunk
        }
        let size = min(sizes[turn % sizes.count], leftover.count)
        turn += 1
        let piece = leftover.prefix(size)
        leftover = leftover.dropFirst(size)
        return piece
    }

    func close() async { await inner.close() }
}

@Suite("Integration: the read path", .timeLimit(.minutes(1)))
struct ReadPathTests {

    private static func pattern(_ count: Int, seed: Int = 1) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: ($0 &* 31 &+ seed) ^ ($0 >> 8)) })
    }

    /// Data-In is received straight into the read's buffer, a piece at a
    /// time as chunks arrive. Whatever the PDU size, the digests, where the
    /// status rides and how the stream is cut up, a read split over several
    /// commands comes back byte-exact, and so does one that fits in one.
    @Test(arguments: [
        // (Data-In size, digests, separate status PDU, receive fragment sizes)
        (8192, false, false, [1 << 20]),
        (8192, true, false, [1 << 20]),
        (512, true, true, [1, 47, 48, 49, 3, 700]),
        (65536, false, true, [5000, 13, 48]),
        (65536, true, false, [52, 65536, 1, 4, 99_999]),
        (262_144, true, true, [4096]),
    ])
    func readsComeBackByteExact(
        dataInSize: Int, digests: Bool, separateStatus: Bool, fragments: [Int]
    ) async throws {
        var config = MockTargetConfig()
        config.separateReadStatus = separateStatus
        if digests { config.digestPick = "CRC32C" }
        let disk = RAMDisk(blockSize: 512, capacityBlocks: 8192)
        let stored = Self.pattern(700 << 10, seed: dataInSize)
        #expect(await disk.write(lba: 32, data: stored))
        let harness = TargetHarness.start(config: config, disk: disk)
        let session = ISCSISession(
            login: standardLogin {
                $0.desired.offerDigests = digests
                $0.desired.maxRecvDataSegmentLength = UInt32(dataInSize)
            },
            policy: testPolicy(),
            transportFactory: { FragmentingTransport(wrapping: harness.transport, sizes: fragments) })
        let result = try await session.activate()
        #expect(result.parameters.dataDigest == digests)
        let device = ISCSIBlockDevice(session: session, lun: 0, maxTransferBytes: 256 << 10)

        // Three commands, the last one short.
        let large = try await device.read(offset: 512 * 32, length: 600 << 10)
        #expect(large == stored.prefix(600 << 10))
        // One command.
        let small = try await device.read(offset: 512 * 40, length: 8192)
        #expect(small == stored.subdata(in: 4096 ..< 4096 + 8192))
        // Several reads at once, overlapping in time on one connection.
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0 ..< 6 {
                group.addTask {
                    let offset = index * (100 << 10)
                    let data = try await device.read(offset: UInt64(512 * 32 + offset), length: 100 << 10)
                    #expect(data == stored.subdata(in: offset ..< offset + (100 << 10)), "read \(index)")
                }
            }
            try await group.waitForAll()
        }
        try await session.logout()
        await harness.finish()
    }

    /// A read retried after its connection died receives into the same
    /// buffer again, from the start. What the first attempt left there must
    /// not survive into the answer.
    @Test func aReadRetriedAfterADropMidDataInIsStillByteExact() async throws {
        var dropping = MockTargetConfig()
        dropping.maxRecvDataSegmentLength = 4096
        dropping.faults.dropDuringDataInAt = 5
        let disk = RAMDisk(blockSize: 512, capacityBlocks: 8192)
        let stored = Self.pattern(600 << 10, seed: 7)
        #expect(await disk.write(lba: 0, data: stored))
        let fleet = TargetFleet(disk: disk, configs: [dropping, MockTargetConfig()])
        let session = ISCSISession(
            login: standardLogin { $0.desired.maxRecvDataSegmentLength = 4096 },
            policy: testPolicy(),
            transportFactory: { await fleet.makeTransport() })
        try await session.activate()
        let device = ISCSIBlockDevice(session: session, lun: 0, maxTransferBytes: 256 << 10)
        let data = try await device.read(offset: 0, length: 600 << 10)
        #expect(data == stored)
        #expect(await session.recoveryCount >= 1, "the drop should have forced a recovery")
        try await session.logout()
        await fleet.shutdown(expectingViolations: true)
    }

    /// The two ways a task can be told where its data goes.
    @Test func aTaskReadsIntoTheCallersRegionOrItsOwnBuffer() async throws {
        let disk = RAMDisk(blockSize: 512, capacityBlocks: 8192)
        let stored = Self.pattern(8192, seed: 3)
        #expect(await disk.write(lba: 8, data: stored))
        let (connection, harness, _) = try await loggedInConnection(disk: disk)

        // Its own: the result carries the data.
        let own = try await connection.execute(SCSITask(
            lun: 0, cdb: CDB.read16(lba: 8, blocks: 16), direction: .read(expectedLength: 8192)))
        #expect(own.isGood)
        #expect(own.data == stored)

        // The caller's: the result carries none, and the region holds it,
        // with the rest of the buffer untouched.
        let buffer = ReadBuffer(count: 3 * 8192)
        buffer.bytes(0 ..< 3 * 8192).initializeMemory(as: UInt8.self, repeating: 0xEE)
        let region = ReadBuffer.Region(buffer: buffer, offset: 8192, count: 8192)
        let placed = try await connection.execute(SCSITask(
            lun: 0, cdb: CDB.read16(lba: 8, blocks: 16), direction: .read(expectedLength: 8192),
            readDestination: region))
        #expect(placed.isGood)
        #expect(placed.data.isEmpty)
        #expect(buffer.data() == Data(repeating: 0xEE, count: 8192) + stored + Data(repeating: 0xEE, count: 8192))

        // A region too small for the read is refused before anything is sent.
        let cramped = ReadBuffer.Region(buffer: buffer, offset: 0, count: 4096)
        await #expect(throws: ConnectionError.self) {
            _ = try await connection.execute(SCSITask(
                lun: 0, cdb: CDB.read16(lba: 8, blocks: 16), direction: .read(expectedLength: 8192),
                readDestination: cramped))
        }
        await connection.close()
        await harness.finish()
    }
}
