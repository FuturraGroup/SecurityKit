# SecurityKit
<p align="center">
<img width="300" alt="Icon copy" src="https://github.com/user-attachments/assets/9d00b349-8254-42ab-bb0c-30640218eb2a" />
</p>

## Overview
SecurityKit is a lightweight, easy-to-use Swift library that helps protect iOS apps according to the OWASP MASVS standard, chapter v8, providing an advanced security and anti-tampering layer.

## Installation

SecurityKit is available with Swift Package Manager.

The [Swift Package Manager](https://swift.org/package-manager/) is a tool for automating the distribution of Swift code and is integrated into the `swift` compiler. 

Once you have your Swift package set up, adding SecurityKit as a dependency is as easy as adding it to the `dependencies` value of your `Package.swift`.

```swift
dependencies: [
    .package(url: "https://github.com/FuturraGroup/SecurityKit.git", .branch("main"))
]
```

## Usage

### Update Info.plist
For jailbreak detection to work correctly, you need to update your main Info.plist.
```
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
    <string>undecimus</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>filza</string>
</array>
```
### Jailbreak detection
```
if SecurityKit.isJailBroken() {
    print("This device is jailbroken")
} else {
    print("This device is not jailbroken")
}
```
### Simulator detection
```
if SecurityKit.isSimulator() {
    print("This device is jailbroken")
} else {
    print("This device is not jailbroken")
}
```
## Contribute

Contributions for improvements are welcomed. Feel free to submit a pull request to help grow the library. If you have any questions, feature suggestions, or bug reports, please send them to [Issues](https://github.com/FuturraGroup/SecurityKit/issues).

## License

```
MIT License

Copyright (c) 2025 Futurra Group

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
