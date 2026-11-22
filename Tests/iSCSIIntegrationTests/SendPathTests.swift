import Foundation
import Testing
@testable import iSCSIMockTarget
@testable import iSCSIKit

/// A transport the test steers: it can hold what the connection has received
/// before handing it over, and hold a send that starts with a Data-Out PDU,
/// which is what a full socket buffer does to an R2T answer.
final class SteeredTransport: ConnectionTransport, @unchecked Sendable {
    /// Lets waiters through while open; holds them while closed.
    final class Gate: @unchecked Sendable {
        private let lock = NSLock()
        private var open = true
        private var waiters: [CheckedContinuation<Void, Never>] = []
        private var held = 0

        func close() { lock.lock(); open = false; lock.unlock() }
        func release() {
            lock.lock()
            open = true
            let resume = waiters
            waiters = []
            lock.unlock()
            for c in resume { c.resume() }
        }
        /// Waiters held so far, whether or not they have been released.
        var everHeld: Int { lock.lock(); defer { lock.unlock() }; return held }

        func pass() async {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                lock.lock()
                if open {
                    lock.unlock()
                    c.resume()
                } else {
                    held += 1
                    waiters.append(c)
                    lock.unlock()
                }
            }
        }
    }

    private let inner: any ConnectionTransport
    let inbound = Gate()
    let dataOut = Gate()
    private let lock = NSLock()
    private var sent = 0
    /// Sends handed to the transport so far, held ones included.
    var sendCount: Int { lock.lock(); defer { lock.unlock() }; return sent }

    init(wrapping inner: any ConnectionTransport) { self.inner = inner }

    private func noteSend() { lock.lock(); sent += 1; lock.unlock() }

    func send(_ data: Data) async throws {
        noteSend()
        if let first = data.first, first & 0x3F == Opcode.scsiDataOut.rawValue {
            await dataOut.pass()
        }
        try await inner.send(data)
    }

    func receive() async throws -> Data? {
        let chunk = try await inner.receive()
        await inbound.pass()
        return chunk
    }

    func close() async {
        inbound.release()
        dataOut.release()
        await inner.close()
    }
}

@Suite("Integration: the send path", .timeLimit(.minutes(1)))
struct SendPathTests {

    private static func pattern(_ count: Int, seed: Int = 1) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: ($0 &* 31 &+ seed) ^ ($0 >> 8)) })
    }

    private func eventually(_ what: String, within: Duration = .seconds(5),
                            _ condition: () async -> Bool) async {
        let deadline = ContinuousClock.now.advanced(by: within)
        while ContinuousClock.now < deadline {
            if await condition() { return }
            try? await Task.sleep(for: .milliseconds(2))
        }
        Issue.record("never happened: \(what)")
    }

    /// The regression test for the read loop waiting on its own send. With an
    /// R2T's Data-Out stuck in the transport, PDUs that arrive after the R2T
    /// must still be handled: here a read's Data-In.
    @Test func aStuckR2TAnswerDoesNotStopTheConnectionReceiving() async throws {
        let disk = RAMDisk(blockSize: 512, capacityBlocks: 8192)
        let stored = Self.pattern(4096, seed: 9)
        #expect(await disk.write(lba: 1000, data: stored))
        let harness = TargetHarness.start(disk: disk)
        let transport = SteeredTransport(wrapping: harness.transport)
        let connection = ISCSIConnection(transport: transport, login: standardLogin())
        let login = try await connection.login()
        // The shape under test needs an R2T: a write larger than the first burst.
        let firstBurst = Int(login.parameters.firstBurstLength)
        let payload = Self.pattern(2 * firstBurst)

        // Hold everything received from here on, so the R2T and the read's
        // Data-In reach the connection together, in the order the target
        // sent them.
        transport.inbound.close()
        let sendsBefore = transport.sendCount
        let write = Task {
            try await connection.execute(SCSITask(
                lun: 0, cdb: CDB.write16(lba: 0, blocks: UInt32(payload.count / 512)),
                direction: .write(payload)))
        }
        await eventually("the write command was sent") { transport.sendCount == sendsBefore + 1 }
        let read = Task {
            try await connection.execute(SCSITask(
                lun: 0, cdb: CDB.read16(lba: 1000, blocks: 8),
                direction: .read(expectedLength: 4096)))
        }
        await eventually("the read command was sent") { transport.sendCount == sendsBefore + 2 }

        transport.dataOut.close()
        transport.inbound.release()

        // The read finishes although the write's Data-Out has not left.
        let result = try await withDeadline(.seconds(5)) { try await read.value }
        #expect(result.isGood)
        #expect(result.data == stored)
        #expect(transport.dataOut.everHeld == 1, "the R2T answer should be the send in the gate")

        transport.dataOut.release()
        let written = try await withDeadline(.seconds(5)) { try await write.value }
        #expect(written.isGood)
        #expect(await disk.read(lba: 0, blocks: UInt32(payload.count / 512)) == payload)
        await connection.close()
        await harness.finish()
    }

    /// A stuck send still ends when the connection is closed, and the command
    /// it belonged to fails rather than waiting.
    @Test func closingTheConnectionEndsACommandWhoseDataOutNeverLeft() async throws {
        let harness = TargetHarness.start(disk: RAMDisk(blockSize: 512, capacityBlocks: 8192))
        let transport = SteeredTransport(wrapping: harness.transport)
        let connection = ISCSIConnection(transport: transport, login: standardLogin())
        let login = try await connection.login()
        let payload = Self.pattern(2 * Int(login.parameters.firstBurstLength))

        transport.dataOut.close()
        let write = Task {
            try await connection.execute(SCSITask(
                lun: 0, cdb: CDB.write16(lba: 0, blocks: UInt32(payload.count / 512)),
                direction: .write(payload)))
        }
        await eventually("the R2T answer reached the transport") { transport.dataOut.everHeld == 1 }
        await connection.close()
        await #expect(throws: (any Error).self) {
            _ = try await withDeadline(.seconds(5)) { try await write.value }
        }
        await harness.finish(expectingViolations: true)
    }

    /// Write data stays a slice of the caller's buffer down to the transport.
    /// A slice does not start at index zero, so every offset taken on the way
    /// — immediate data, the unsolicited tail, each R2T's range, each Data-Out
    /// PDU — has to be relative to it.
    @Test(arguments: [
        // (immediate data, InitialR2T, FirstBurstLength, target MRDSL, digests)
        (true, false, 65536, 8192, false),
        (true, false, 65536, 8192, true),
        (false, true, 65536, 8192, false),
        (true, true, 4096, 512, true),
        (false, false, 262_144, 65536, false),
        (true, false, 1 << 20, 262_144, true),
    ])
    func aWriteHandedOverAsASliceLandsByteExact(
        immediate: Bool, initialR2T: Bool, firstBurst: Int, mrdsl: Int, digests: Bool
    ) async throws {
        var config = MockTargetConfig()
        config.preferImmediateData = immediate
        config.preferInitialR2T = initialR2T
        config.firstBurstLength = UInt32(firstBurst)
        config.maxBurstLength = UInt32(max(firstBurst, 262_144))
        config.maxRecvDataSegmentLength = UInt32(mrdsl)
        if digests { config.digestPick = "CRC32C" }
        let disk = RAMDisk(blockSize: 512, capacityBlocks: 8192)
        let harness = TargetHarness.start(config: config, disk: disk)
        let session = ISCSISession(
            login: standardLogin { $0.desired.offerDigests = digests },
            policy: testPolicy(),
            transportFactory: { harness.transport })
        let result = try await session.activate()
        #expect(result.parameters.dataDigest == digests)

        // 600 KiB in 256 KiB commands: three chunks, the last one short, each
        // a slice of a slice.
        let device = ISCSIBlockDevice(session: session, lun: 0, maxTransferBytes: 256 << 10)
        let length = 600 << 10
        let buffer = Self.pattern(length + 12_345 + 777, seed: firstBurst)
        let slice = buffer[12_345 ..< 12_345 + length]
        #expect(slice.startIndex != 0)
        try await device.write(offset: 512 * 16, data: slice)

        #expect(await disk.read(lba: 16, blocks: UInt32(length / 512)) == Data(slice))
        #expect(try await device.read(offset: 512 * 16, length: length) == Data(slice))
        // The blocks either side were not touched.
        #expect(await disk.read(lba: 15, blocks: 1) == Data(count: 512))
        #expect(await disk.read(lba: 16 + UInt64(length / 512), blocks: 1) == Data(count: 512))
        try await session.logout()
        await harness.finish()
    }
}
