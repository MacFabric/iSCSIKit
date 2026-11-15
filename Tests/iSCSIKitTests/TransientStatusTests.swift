import Foundation
import Testing
@testable import iSCSIKit

/// Which SCSI statuses the block device retries rather than report.
@Suite("Transient SCSI status")
struct TransientStatusTests {
    private func checkCondition(key: UInt8, asc: UInt8, ascq: UInt8) -> SCSITaskResult {
        var sense = Data(count: 18)
        sense[0] = 0x70
        sense[2] = key
        sense[12] = asc
        sense[13] = ascq
        return SCSITaskResult(status: 0x02, sense: sense)
    }

    @Test func busyAndTaskSetFullAreRetriedLater() {
        #expect(TransientStatus.classify(SCSITaskResult(status: 0x08)) == .retryLater)
        #expect(TransientStatus.classify(SCSITaskResult(status: 0x28)) == .retryLater)
    }

    @Test func unitAttentionIsRetriedAtOnce() {
        #expect(TransientStatus.classify(checkCondition(key: 0x06, asc: 0x29, ascq: 0)) == .unitAttention)
    }

    @Test func aLogicalUnitBecomingReadyIsRetriedLater() {
        #expect(TransientStatus.classify(checkCondition(key: 0x02, asc: 0x04, ascq: 0x01)) == .retryLater)
    }

    @Test func everythingElseIsFinal() {
        #expect(TransientStatus.classify(SCSITaskResult(status: 0x00)) == nil)
        // NOT READY, but not "becoming ready": medium not present.
        #expect(TransientStatus.classify(checkCondition(key: 0x02, asc: 0x3A, ascq: 0)) == nil)
        #expect(TransientStatus.classify(checkCondition(key: 0x03, asc: 0x11, ascq: 0)) == nil)
        #expect(TransientStatus.classify(SCSITaskResult(status: 0x18)) == nil) // reservation conflict
        #expect(TransientStatus.classify(SCSITaskResult(status: 0x02)) == nil) // no sense
    }
}
