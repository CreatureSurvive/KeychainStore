// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "KeychainStore",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
        .tvOS(.v17),
        .visionOS(.v1),
        .watchOS(.v10),
    ],
    products: [
        .library(name: "KeychainStore", targets: ["KeychainStore"]),
    ],
    targets: [
        .target(
            name: "KeychainStore",
            swiftSettings: [.enableUpcomingFeature("ExistentialAny")]
        ),
        .testTarget(
            name: "KeychainStoreTests",
            dependencies: ["KeychainStore"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
