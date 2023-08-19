// swift-tools-version:5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "sEndpointSecurity",
    platforms: [
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "sEndpointSecurity", targets: ["sEndpointSecurity"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Alkenso/SwiftConvenience.git", exact: "0.1.0"),
    ],
    targets: [
        .target(
            name: "sEndpointSecurity",
            dependencies: ["SwiftConvenience"],
            linkerSettings: [.linkedLibrary("EndpointSecurity")]
        ),
        .testTarget(
            name: "sEndpointSecurityTests",
            dependencies: [
                "sEndpointSecurity",
                .product(name: "SwiftConvenienceTestUtils", package: "SwiftConvenience"),
            ]
        ),
    ]
)
