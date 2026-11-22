import Foundation

/// Digest configuration for one connection direction pair, fixed at the end
/// of login negotiation.
public struct DigestConfig: Sendable, Equatable {
    public var headerDigest: Bool
    public var dataDigest: Bool

    public init(headerDigest: Bool = false, dataDigest: Bool = false) {
        self.headerDigest = headerDigest
        self.dataDigest = dataDigest
    }
}

/// Serializes framed PDUs to wire bytes: BHS + AHS [+ HeaderDigest] + data
/// (4-byte padded) [+ DataDigest].
public struct PDUSerializer: Sendable {
    public var digests: DigestConfig

    public init(digests: DigestConfig = DigestConfig()) {
        self.digests = digests
    }

    /// The PDU's wire bytes as up to three buffers, in order: the header
    /// (BHS, AHS and HeaderDigest), the data segment exactly as the caller
    /// holds it, and whatever follows it (padding, DataDigest). Sent with
    /// `ConnectionTransport.send(contentsOf:)`, a megabyte of write data
    /// reaches the socket without first being copied in behind its header.
    public func serializeParts(_ raw: RawPDU) -> [Data] {
        precondition(raw.ahs.count % 4 == 0, "AHS must be 4-byte aligned")
        var head = Data(capacity: 48 + raw.ahs.count + 4)
        var bhs = raw.bhs
        bhs.setU8(UInt8(raw.ahs.count / 4), 4)
        bhs.setBE24(UInt32(raw.data.count), 5)
        head.append(bhs)
        head.append(raw.ahs)
        if digests.headerDigest {
            head.append(CRC32C.wireDigest(head))
        }
        guard !raw.data.isEmpty else { return [head] }

        let padLen = padded4(raw.data.count) - raw.data.count
        var tail = Data(count: padLen)
        if digests.dataDigest {
            // Chained over segment then pad, without joining them.
            var crc = CRC32C.initial
            crc = raw.data.withUnsafeBytes { CRC32C.update(crc, $0) }
            crc = tail.withUnsafeBytes { CRC32C.update(crc, $0) }
            tail.append(CRC32C.wireBytes(CRC32C.finalize(crc)))
        }
        return tail.isEmpty ? [head, raw.data] : [head, raw.data, tail]
    }

    public func serializeParts(_ pdu: some ProtocolDataUnit) -> [Data] {
        serializeParts(pdu.encode())
    }

    /// The same bytes as one buffer, which costs a copy of the data segment.
    public func serialize(_ raw: RawPDU) -> Data {
        let parts = serializeParts(raw)
        if parts.count == 1 { return parts[0] }
        var out = Data(capacity: parts.reduce(0) { $0 + $1.count })
        for part in parts { out.append(part) }
        return out
    }

    public func serialize(_ pdu: some ProtocolDataUnit) -> Data {
        serialize(pdu.encode())
    }
}

/// Incremental deframer: feed arbitrary byte chunks, pull complete PDUs.
/// Verifies digests and enforces a data-segment length limit (protects the
/// receive path from a hostile/broken peer allocating unbounded memory).
///
/// Two ways to pull. `next()` returns a whole PDU once all of it has
/// arrived, its data segment copied out once. The other takes a PDU in
/// steps, for a receiver that knows where the data belongs: `nextHead()`
/// returns the header as soon as that has arrived, and then the data segment
/// is moved with `readData(into:)` straight from the chunks it came in to
/// the buffer of the read it answers, piece by piece as it arrives, and
/// closed with `finishData()`. Bytes go from the transport's chunk to their
/// destination and are never copied in between.
///
/// On a thrown error the deframer state is poisoned — at ERL0 any framing or
/// digest error tears down the connection, so no resync is attempted.
public struct PDUDeframer: Sendable {
    public var digests: DigestConfig
    /// Upper bound accepted for DataSegmentLength; our negotiated
    /// MaxRecvDataSegmentLength plus slack for login-phase PDUs.
    public var maxDataSegmentLength: Int

    /// Received and not yet consumed. Chunks are kept as they arrived and
    /// released as they are used up, so nothing here grows with the bytes
    /// that have passed through.
    private var queue = ReceiveQueue()

    /// A data segment whose header `nextHead()` has returned and which has
    /// not been closed yet.
    private struct Segment: Sendable {
        /// Data bytes still to be taken.
        var remaining: Int
        let padLength: Int
        /// Running digest over the bytes taken so far, when one is checked.
        var crc: UInt32
        let checked: Bool
        /// Bytes after the data: padding, then the digest.
        var trailerLength: Int { padLength + (checked ? 4 : 0) }
    }

    private var segment: Segment?

    public init(digests: DigestConfig = DigestConfig(), maxDataSegmentLength: Int = 1 << 24) {
        self.digests = digests
        self.maxDataSegmentLength = min(maxDataSegmentLength, 1 << 24)
    }

    public mutating func append(_ bytes: Data) {
        queue.append(bytes)
    }

    /// Bytes buffered but not yet consumed.
    public var buffered: Int { queue.count }

    /// A PDU's header, with the length of the data segment that follows it.
    public struct Head: Sendable {
        /// Exactly 48 bytes.
        public let bhs: Data
        public let ahs: Data
        public let dataLength: Int
    }

    /// The header at the front of the queue, parsed far enough to know how
    /// long it and its data are. nil until its first 48 bytes have arrived.
    private func lengths() throws -> (header: Int, data: Int)? {
        guard queue.count >= 48 else { return nil }
        let ahsLen = Int(queue.byte(at: 4)) * 4
        let dataLen = Int(queue.byte(at: 5)) << 16 | Int(queue.byte(at: 6)) << 8 | Int(queue.byte(at: 7))
        guard dataLen <= maxDataSegmentLength else {
            throw PDUError.dataSegmentTooLarge(length: dataLen, limit: maxDataSegmentLength)
        }
        return (48 + ahsLen, dataLen)
    }

    /// Copy the header out and check its digest. Consumes nothing.
    private func header(length: Int) throws -> (bhs: Data, ahs: Data) {
        let bhs = queue.peek(48)
        let ahs = length > 48 ? queue.peek(length - 48, skippingFirst: 48) : Data()
        if digests.headerDigest {
            var crc = bhs.withUnsafeBytes { CRC32C.update(CRC32C.initial, $0) }
            crc = ahs.withUnsafeBytes { CRC32C.update(crc, $0) }
            guard CRC32C.finalize(crc) == wireDigestValue(at: length) else {
                throw PDUError.headerDigestMismatch
            }
        }
        return (bhs, ahs)
    }

    /// Returns the next complete PDU, or nil if more bytes are needed.
    public mutating func next() throws -> RawPDU? {
        precondition(segment == nil, "a data segment begun with nextHead() has not been finished")
        guard let (headerLen, dataLen) = try lengths() else { return nil }
        let headerDigestLen = digests.headerDigest ? 4 : 0
        let paddedData = padded4(dataLen)
        let dataDigestLen = (digests.dataDigest && dataLen > 0) ? 4 : 0
        let total = headerLen + headerDigestLen + paddedData + dataDigestLen
        guard queue.count >= total else { return nil }

        let (bhs, ahs) = try header(length: headerLen)
        let dataStart = headerLen + headerDigestLen
        let data = queue.peek(dataLen, skippingFirst: dataStart)
        if dataDigestLen > 0 {
            var crc = data.withUnsafeBytes { CRC32C.update(CRC32C.initial, $0) }
            let pad = queue.peek(paddedData - dataLen, skippingFirst: dataStart + dataLen)
            crc = pad.withUnsafeBytes { CRC32C.update(crc, $0) }
            guard CRC32C.finalize(crc) == wireDigestValue(at: dataStart + paddedData) else {
                throw PDUError.dataDigestMismatch
            }
        }
        queue.skip(total)
        return RawPDU(bhs: bhs, ahs: ahs, data: data)
    }

    // MARK: - A PDU in steps

    /// The next PDU's header, consumed with its digest, or nil if it has not
    /// all arrived. When `dataLength` is not zero the data segment must be
    /// taken — `readData(into:)` then `finishData()`, or `takeData()` —
    /// before this is called again.
    public mutating func nextHead() throws -> Head? {
        precondition(segment == nil, "the previous PDU's data segment has not been finished")
        guard let (headerLen, dataLen) = try lengths() else { return nil }
        let headerDigestLen = digests.headerDigest ? 4 : 0
        guard queue.count >= headerLen + headerDigestLen else { return nil }
        let (bhs, ahs) = try header(length: headerLen)
        queue.skip(headerLen + headerDigestLen)
        if dataLen > 0 {
            segment = Segment(remaining: dataLen, padLength: padded4(dataLen) - dataLen,
                              crc: CRC32C.initial, checked: digests.dataDigest)
        }
        return Head(bhs: bhs, ahs: ahs, dataLength: dataLen)
    }

    /// Data-segment bytes not yet taken.
    public var dataRemaining: Int { segment?.remaining ?? 0 }

    /// Move data-segment bytes that have arrived into `destination`: as many
    /// as it holds, as remain in the segment, and as are buffered, whichever
    /// is least. Returns how many. They are not known to be good until
    /// `finishData()` has checked the digest.
    @discardableResult
    public mutating func readData(into destination: UnsafeMutableRawBufferPointer) -> Int {
        guard var current = segment, current.remaining > 0, destination.count > 0 else { return 0 }
        let room = UnsafeMutableRawBufferPointer(
            rebasing: destination[0 ..< min(current.remaining, destination.count)])
        let moved = queue.read(into: room)
        if current.checked, moved > 0 {
            current.crc = CRC32C.update(current.crc, UnsafeRawBufferPointer(rebasing: room[0 ..< moved]))
        }
        current.remaining -= moved
        segment = current
        return moved
    }

    /// Close the data segment once all of it has been taken: consume its
    /// padding and check its digest. false if those bytes have not arrived.
    public mutating func finishData() throws -> Bool {
        guard let current = segment else { return true }
        precondition(current.remaining == 0, "data segment bytes not yet taken")
        guard queue.count >= current.trailerLength else { return false }
        if current.checked {
            let pad = queue.peek(current.padLength)
            let crc = pad.withUnsafeBytes { CRC32C.update(current.crc, $0) }
            guard CRC32C.finalize(crc) == wireDigestValue(at: current.padLength) else {
                throw PDUError.dataDigestMismatch
            }
        }
        queue.skip(current.trailerLength)
        segment = nil
        return true
    }

    /// The whole data segment as one buffer, checked and closed, for a PDU
    /// whose data has nowhere better to go. nil until all of it has arrived.
    /// Not to be mixed with `readData(into:)` on the same segment.
    public mutating func takeData() throws -> Data? {
        guard var current = segment else { return Data() }
        guard queue.count >= current.remaining + current.trailerLength else { return nil }
        let data = queue.read(current.remaining)
        if current.checked {
            current.crc = data.withUnsafeBytes { CRC32C.update(current.crc, $0) }
        }
        current.remaining = 0
        segment = current
        _ = try finishData()
        return data
    }

    /// Little-endian digest value `offset` bytes into the queue.
    private func wireDigestValue(at offset: Int) -> UInt32 {
        let bytes = queue.peek(4, skippingFirst: offset)
        return UInt32(bytes.u8(0))
            | UInt32(bytes.u8(1)) << 8
            | UInt32(bytes.u8(2)) << 16
            | UInt32(bytes.u8(3)) << 24
    }
}
