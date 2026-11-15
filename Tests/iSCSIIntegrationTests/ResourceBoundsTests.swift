//
//  ResourceBoundsTests.swift
//
//  Tests that assert a property of the *process* rather than of the output:
//  the worst bugs here were resources flowing one way with every output
//  correct (the deframer's 37 GB retention, KeychainStore's silent no-op).
//  Thresholds carry wide headroom over the measured steady state, and each
//  measurement warms up first, so a failure means behaviour changed.
//

import Foundation
import Testing
@testable import iSCSIMockTarget
@testable import iSCSIKit

@Suite("Resource bounds", .timeLimit(.minutes(2)))
struct ResourceBoundsTests {

    private func footprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size) / 4
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? UInt64(info.phys_footprint) : 0
    }

    private func mib(_ bytes: UInt64) -> UInt64 { bytes / (1 << 20) }

    // MARK: - The session does not accumulate per operation

    /// Every command allocates a task record, read buffer, and pending-map
    /// entries; a thousand round trips would expose a per-operation leak.
    @Test func completedCommandsLeaveNothingBehind() async throws {
        let disk = RAMDisk(blockSize: 512, capacityBlocks: 8192)
        let harness = TargetHarness.start(disk: disk)
        defer { harness.serveTask.cancel() }
        let session = ISCSISession(login: standardLogin(), policy: testPolicy(),
                                   transportFactory: { harness.transport })
        try await session.activate()
        let device = ISCSIBlockDevice(session: session, lun: 0, maxTransferBytes: 64 << 10)

        for _ in 0 ..< 100 { _ = try await device.read(offset: 0, length: 4096) }
        let before = footprint()

        for i in 0 ..< 1000 {
            let offset = UInt64((i % 64) * 4096)
            _ = try await device.read(offset: offset, length: 4096)
            try await device.write(offset: offset, data: Data(repeating: 0xEE, count: 4096))
        }
        // A footprint can shrink between samples (the VM returns pages), and
        // an unsigned wrap then reads as a 16 EiB "growth".
        let after = footprint()
        let grew = after > before ? after - before : 0

        #expect(grew < 32 << 20,
                "2000 completed commands grew the process by \(mib(grew)) MiB")
    }

    // No leak-on-drop test here: the leak would be ~64 KiB per cycle, inside
    // the noise of a shared test process, and detecting it honestly needs a
    // dedicated process. Don't re-add it as a footprint assertion.

    // A large write's fan-out bound is asserted in
    // `WriteConcurrencyTests.aLargeWriteKeepsOnlyAWindowInFlight` by counting
    // commands against a stalled target — exact, unlike process footprint
    // measured after three hundred other tests.
}
