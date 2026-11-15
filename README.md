# iSCSIKit

An iSCSI initiator engine in Swift (RFC 7143). It opens no sockets of its own
and has no side effects, so every path is unit-testable and fuzzable; the
transport comes from [FabricKit](https://github.com/MacFabric/FabricKit), which
iSCSIKit re-exports.

- **PDU layer.** All 17 PDU types, a serializer, and an incremental deframer
  that verifies header and data digests and bounds `DataSegmentLength` against
  a hostile peer.
- **Login.** RFC 7143 negotiation with strict validation of the target's
  answers; a login state machine through the security and operational stages;
  CHAP (MD5, forward and mutual); redirects, including an EqualLogic-style
  group address; continuation in both directions.
- **Session.** `ISCSIConnection` runs the full-feature phase: the CmdSN window,
  StatSN validation, Data-In reassembly, R2T-driven Data-Out (immediate,
  unsolicited and solicited), NOP keepalive and echo, task management, text
  and logout. `ISCSISession` adds ERL0 recovery (drop, backoff, re-login with
  a fresh ISID), bounded transparent retry of interrupted block I/O, and
  dead-peer detection. `Discovery.sendTargets` lists a portal's targets.
- **`ISCSIBlockDevice`**, a FabricKit `BlockDeviceBackend` over one LUN, with
  optional Force Unit Access on every write.

Scope is a daily-driver initiator: one connection per session, ERL0, no MC/S,
no iSNS.

## Products

- `iSCSIKit`
- `iSCSIMockTarget`, a scriptable in-process iSCSI target over `MemoryPipe` or
  TCP with switchable faults (drops, corruption, stalls, target power loss).
  The integration suite runs against it, and so can yours.

## Use

```swift
.package(url: "https://github.com/MacFabric/iSCSIKit", .upToNextMinor(from: "0.1.0")),
```

```swift
import iSCSIKit

let login = LoginConfig(initiatorName: "iqn.2026-11.com.example:host",
                        sessionType: .normal,
                        targetName: "iqn.2005-10.org.freenas.ctl:disk0")
let session = ISCSISession(login: login) {
    try await NetworkTransport.connect(host: "192.168.1.50", port: 3260)
}
_ = try await session.activate()
let disk = ISCSIBlockDevice(session: session, lun: 0)
let firstBlock = try await disk.read(offset: 0, length: try await disk.readCapacity().blockSize)
try await session.logout()
```

Before 1.0 a minor release may change the API, so depend up to the next minor
version.

## Requirements

macOS 15 or later, Swift 6 (language mode 6).

## Testing

```sh
swift test --no-parallel        # unit and integration suites
scripts/fuzz.sh 60              # 60 s ASan fuzz of the decoders, CHAP and login
scripts/fuzz-campaign.sh 100 20 # 100 independent seeds, 20 s each
```

Serial on purpose: several tests bound real durations, and a saturated machine
makes every continuation late without making any timeout wrong. A fuzz failure
reproduces exactly from the two numbers it prints, with
`iscsi-pdu-fuzz derive <seed> <iteration>`.

## Provenance

Developed as part of [iSCSI-NVMe-TCP](https://github.com/MacFabric/iSCSI-NVMe-TCP),
a user-space iSCSI and NVMe/TCP initiator for macOS, and split out of it with
its history on 2026-11-15. Comments that cite `docs/…` refer to that
repository, as does the record of what was tested against which targets.

## License

Apache 2.0. See [LICENSE](LICENSE).
