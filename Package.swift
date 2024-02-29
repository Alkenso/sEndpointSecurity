// swift-tools-version:5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "sEndpointSecurity",
    platforms: [
        .macOS(.v11),
    ],
    products: [
        .library(name: "sEndpointSecurity", targets: ["sEndpointSecurity"]),
        .library(name: "sEndpointSecurityXPC", targets: ["sEndpointSecurityXPC"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Alkenso/SwiftSpellbook.git", from: "0.3.2"),
    ],
    targets: [
        .target(
            name: "sEndpointSecurity",
            dependencies: [.product(name: "SpellbookFoundation", package: "SwiftSpellbook")],
            linkerSettings: [.linkedLibrary("EndpointSecurity")]
        ),
        .target(
            name: "sEndpointSecurityXPC",
            dependencies: ["sEndpointSecurity"]
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
