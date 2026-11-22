// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "iSCSIKit",
    platforms: [.macOS(.v15)],
    products: [
        // The iSCSI initiator engine: PDU codec, login negotiation, CHAP,
        // session and connection with ERL0 recovery, and a block device.
        .library(name: "iSCSIKit", targets: ["iSCSIKit"]),
        // A scriptable in-process iSCSI target, for tests and simulators.
        .library(name: "iSCSIMockTarget", targets: ["iSCSIMockTarget"]),
    ],
    dependencies: [
        // Up to the next minor: before 1.0 a minor release may break API.
        .package(url: "https://github.com/MacFabric/FabricKit", .upToNextMinor(from: "0.1.1")),
    ],
    targets: [
        // Pure protocol logic. No sockets of its own and no side effects:
        // everything here is unit-testable and fuzzable.
        .target(
            name: "iSCSIKit",
            dependencies: [.product(name: "FabricKit", package: "FabricKit")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .target(
            name: "iSCSIMockTarget",
            dependencies: [
                "iSCSIKit",
                .product(name: "FabricTestSupport", package: "FabricKit"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // Fuzz harness: built normally it's a regression-replay tool;
        // scripts/fuzz.sh rebuilds it with -sanitize=address.
        .executableTarget(
            name: "iscsi-pdu-fuzz",
            dependencies: ["iSCSIKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "iSCSIKitTests",
            dependencies: ["iSCSIKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "iSCSIIntegrationTests",
            dependencies: ["iSCSIKit", "iSCSIMockTarget"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
