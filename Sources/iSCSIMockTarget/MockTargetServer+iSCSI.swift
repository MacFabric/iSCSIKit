import FabricTestSupport

extension MockTargetServer {
    /// The iSCSI form: one `MockTarget` per connection over a shared disk.
    public init(
        port: UInt16 = 0,
        disk: RAMDisk = RAMDisk(),
        faultBox: FaultBox = FaultBox(),
        config: @escaping @Sendable () -> MockTargetConfig = { MockTargetConfig() }
    ) throws {
        try self.init(port: port) { transport in
            await MockTarget(config: config(), disk: disk, faultBox: faultBox, transport: transport).run()
        }
    }
}
