// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WiSecured",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "WiSecuredCore", targets: ["WiSecuredCore"]),
        .executable(name: "WiSecured", targets: ["WiSecured"]),
    ],
    targets: [
        .target(name: "CNetInfo"),
        .target(name: "WiSecuredCore", dependencies: ["CNetInfo"],
                linkerSettings: [.linkedFramework("CoreWLAN"), .linkedFramework("SystemConfiguration")]),
        .target(name: "WiSecuredUI", dependencies: ["WiSecuredCore"],
                linkerSettings: [.linkedFramework("CoreLocation"), .linkedFramework("ServiceManagement")]),
        .executableTarget(name: "WiSecured", dependencies: ["WiSecuredUI"]),
        .testTarget(name: "WiSecuredCoreTests", dependencies: ["WiSecuredCore"]),
    ]
)
