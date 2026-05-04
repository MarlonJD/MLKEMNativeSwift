// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "MLKEMNativeSwift",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "MLKEMNativeSwift",
            targets: ["MLKEMNativeSwift"]
        )
    ],
    targets: [
        .target(
            name: "CMLKEMNativeSwift",
            path: "Sources/CMLKEMNativeSwift",
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("../../Vendor/mlkem-native/mlkem"),
                .define("MLK_CONFIG_PARAMETER_SET", to: "768"),
                .define("MLK_CONFIG_NO_RANDOMIZED_API")
            ]
        ),
        .target(
            name: "MLKEMNativeSwift",
            dependencies: ["CMLKEMNativeSwift"]
        ),
        .testTarget(
            name: "MLKEMNativeSwiftTests",
            dependencies: ["MLKEMNativeSwift"]
        )
    ]
)
