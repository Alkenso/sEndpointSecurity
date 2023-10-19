// swift-tools-version:5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "sEndpointSecurity",
    platforms: [
        .macOS(.v11),
    ],
    products: [
        .library(name: "sEndpointSecurity", targets: ["sEndpointSecurity"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Alkenso/SwiftSpellbook.git", from: "0.3.1"),
    ],
    targets: [
        .target(
            name: "sEndpointSecurity",
            dependencies: [.product(name: "SpellbookFoundation", package: "SwiftSpellbook")],
            linkerSettings: [.linkedLibrary("EndpointSecurity")]
        ),
        .testTarget(
            name: "sEndpointSecurityTests",
            dependencies: [
                "sEndpointSecurity",
                .product(name: "SpellbookTestUtils", package: "SwiftSpellbook"),
            ]
        ),
    ]
)
