import Foundation
import Testing
@testable import iSCSIKit

/// `PDUDeframer` taken in steps — header, then data moved to where it
/// belongs, then the close — must see exactly the PDUs `next()` sees in the
/// same bytes, however those bytes are cut into chunks.
@Suite("PDU deframing in steps")
struct StepwiseDeframerTests {
    private static func bytes(_ count: Int, seed: Int) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: ($0 &* 131 &+ seed) ^ ($0 >> 7)) })
    }

    /// A stream of PDUs of every shape: no data, data at each padding
    /// length, a large segment, and one with an AHS.
    private static func stream(_ digests: DigestConfig) -> (wire: Data, pdus: [RawPDU]) {
        let serializer = PDUSerializer(digests: digests)
        var pdus: [RawPDU] = []
        for (index, size) in [0, 1, 2, 3, 4, 48, 0, 4097, 65536, 5, 0, 8192].enumerated() {
            var pdu = DataInPDU()
            pdu.initiatorTaskTag = UInt32(index + 1)
            pdu.bufferOffset = UInt32(index * 100)
            pdu.dataSegment = bytes(size, seed: index)
            pdus.append(pdu.encode())
        }
        var withAHS = NopInPDU().encode()
        withAHS.ahs = bytes(8, seed: 99)
        withAHS.data = bytes(10, seed: 98)
        pdus.insert(withAHS, at: 4)
        var wire = Data()
        for raw in pdus { wire.append(serializer.serialize(raw)) }
        // What the deframer hands back has the lengths written into the BHS.
        var expected: [RawPDU] = []
        var check = PDUDeframer(digests: digests)
        check.append(wire)
        while let raw = try? check.next() { expected.append(raw) }
        return (wire, expected)
    }

    @Test(arguments: [1, 5, 47, 48, 49, 52, 1000, 4096, 100_000])
    func stepsSeeWhatNextSees(chunkSize: Int) throws {
        for digests in [DigestConfig(), DigestConfig(headerDigest: true, dataDigest: true),
                        DigestConfig(headerDigest: true, dataDigest: false),
                        DigestConfig(headerDigest: false, dataDigest: true)] {
            let (wire, expected) = Self.stream(digests)
            #expect(expected.count == 13)
            var deframer = PDUDeframer(digests: digests)
            var got: [RawPDU] = []
            var head: PDUDeframer.Head?
            var data = Data()
            var fed = 0
            var pduIndex = 0

            // Pull everything the buffered bytes allow, alternating between
            // taking the data whole and moving it out in small pieces.
            func pump() throws {
                while true {
                    if head == nil {
                        guard let next = try deframer.nextHead() else { return }
                        head = next
                        data = Data()
                        #expect(deframer.dataRemaining == next.dataLength)
                    }
                    guard let current = head else { return }
                    if pduIndex % 2 == 0 {
                        guard let whole = try deframer.takeData() else { return }
                        data = whole
                    } else {
                        var piece = Data(count: 333)
                        while deframer.dataRemaining > 0 {
                            let moved = piece.withUnsafeMutableBytes { deframer.readData(into: $0) }
                            if moved == 0 { return }
                            data.append(piece.prefix(moved))
                        }
                        guard try deframer.finishData() else { return }
                    }
                    #expect(data.count == current.dataLength)
                    got.append(RawPDU(bhs: current.bhs, ahs: current.ahs, data: data))
                    head = nil
                    pduIndex += 1
                }
            }

            while fed < wire.count {
                let end = min(fed + chunkSize, wire.count)
                deframer.append(wire[fed ..< end])
                fed = end
                try pump()
            }
            #expect(got == expected, "chunks of \(chunkSize), digests \(digests)")
            #expect(deframer.buffered == 0)
            #expect(head == nil)
        }
    }

    @Test func aBadDataDigestIsCaughtWhenTheSegmentIsClosed() throws {
        let digests = DigestConfig(headerDigest: true, dataDigest: true)
        var pdu = DataInPDU()
        pdu.dataSegment = Self.bytes(1001, seed: 3)
        var wire = PDUSerializer(digests: digests).serialize(pdu)
        wire[wire.count - 600] ^= 0x01           // inside the data segment

        var deframer = PDUDeframer(digests: digests)
        deframer.append(wire)
        let head = try #require(try deframer.nextHead())
        var sink = Data(count: head.dataLength)
        #expect(sink.withUnsafeMutableBytes { deframer.readData(into: $0) } == 1001)
        #expect(throws: PDUError.dataDigestMismatch) { _ = try deframer.finishData() }

        var whole = PDUDeframer(digests: digests)
        whole.append(wire)
        _ = try #require(try whole.nextHead())
        #expect(throws: PDUError.dataDigestMismatch) { _ = try whole.takeData() }
    }

    @Test func aBadHeaderDigestOrAnOversizeSegmentStopsAtTheHeader() throws {
        let digests = DigestConfig(headerDigest: true, dataDigest: true)
        var pdu = DataInPDU()
        pdu.dataSegment = Self.bytes(64, seed: 4)
        var wire = PDUSerializer(digests: digests).serialize(pdu)
        wire[20] ^= 0x80
        var deframer = PDUDeframer(digests: digests)
        deframer.append(wire)
        #expect(throws: PDUError.headerDigestMismatch) { _ = try deframer.nextHead() }

        var small = PDUDeframer(maxDataSegmentLength: 32)
        small.append(PDUSerializer().serialize(pdu).prefix(48))
        #expect(throws: PDUError.self) { _ = try small.nextHead() }
    }

    /// The header is available before the data is: that is the point.
    @Test func theHeaderComesBeforeItsData() throws {
        var pdu = DataInPDU()
        pdu.initiatorTaskTag = 77
        pdu.dataSegment = Self.bytes(4096, seed: 5)
        let wire = PDUSerializer().serialize(pdu)
        var deframer = PDUDeframer()
        deframer.append(wire.prefix(47))
        #expect(try deframer.nextHead() == nil)
        deframer.append(wire[47 ..< 60])
        let head = try #require(try deframer.nextHead())
        #expect(head.bhs.beU32(16) == 77)
        #expect(head.dataLength == 4096)
        var sink = Data(count: 4096)
        #expect(sink.withUnsafeMutableBytes { deframer.readData(into: $0) } == 12)
        deframer.append(wire[60...])
        let rest = sink.withUnsafeMutableBytes {
            deframer.readData(into: UnsafeMutableRawBufferPointer(rebasing: $0[12...]))
        }
        #expect(rest == 4084)
        #expect(try deframer.finishData())
        #expect(sink == pdu.dataSegment)
    }
}
