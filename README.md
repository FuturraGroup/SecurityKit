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
```xml
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
* This type method is used to detect the true/false jailbreak status
```swift
if SecurityKit.isJailBroken() {
    print("This device is jailbroken")
} else {
    print("This device is not jailbroken")
}
```
* This type method is used to detect the jailbreak status with a message which jailbreak indicator was detected
```swift
let jailbreakStatus = SecurityKit.isJailBrokenWithErrorMessage()
if jailbreakStatus.jailbroken {
    print("This device is jailbroken")
    print("Because: \(jailbreakStatus.errorMessage)")
} else {
    print("This device is not jailbroken")
}
```
* This type method is used to detect the jailbreak status with a list of failed detects
```swift
let jailbreakStatus = SecurityKit.isJailBrokenWithErrorDetects()
if jailbreakStatus.jailbroken {
    print("This device is jailbroken")
    print("The following checks failed: \(jailbreakStatus.errorDetects)")
}
```
### Simulator detection
* This type method is used to detect if application is run in simulator
```swift
if SecurityKit.isSimulator() {
    print("app is running on the simulator")
} else {
    print("app is not running on the simulator")
}
```
### Reverse engineering tools detection
* This type method is used to detect if there are any popular reverse engineering tools installed on the device
```swift
if SecurityKit.isReverseEngineered() {
    print("This device has reverse engineering tools")
} else {
    print("This device does not have reverse engineering tools")
}
```
* This type method is used to detect the reverse engineered status with a list of failed detects
```swift
let reStatus = SecurityKit.isReverseEngineeredWithErrorDetect()
if reStatus.reverseEngineered {
    print("SecurityKit: This device has evidence of reverse engineering")
    print("SecurityKit: The following detects failed: \(reStatus.errorDetect)")
}
```
### Debugger detection
* This type method is used to detect if application is being debugged
```swift
let isDebugged: Bool = SecurityKit.isDebugged()
```
* This type method is used to deny debugger and improve the application resillency
```swift
SecurityKit.denyDebugger()
```
* This method is used to detect if application was launched by something other than LaunchD (i.e. the app was launched by a debugger)
```swift
let isNotLaunchD: Bool = SecurityKit.isParentPidUnexpected()
```
* This type method is used to detect if there are any breakpoints at the function
```swift
func denyDebugger() {
    // add a breakpoint at here to test
}

typealias FunctionType = @convention(thin) ()->()

let func_denyDebugger: FunctionType = denyDebugger   // `: FunctionType` is a must
let func_addr = unsafeBitCast(func_denyDebugger, to: UnsafeMutableRawPointer.self)
let hasBreakpoint: Bool = SecurityKit.hasBreakpointAt(func_addr, functionSize: nil)
```
* This type method is used to detect if a watchpoint is being used.
A watchpoint is a type of breakpoint that 'watches' an area of memory associated with a data item.
```swift
// Set a breakpoint at the testWatchpoint function
func testWatchpoint() -> Bool{
    // lldb: watchpoint set expression ptr
    var ptr = malloc(9)
    // lldb: watchpoint set variable count
    var count = 3
    return SecurityKit.hasWatchpoint()
}
```
### Integrity detection
* This type method is used to detect if application has been tampered with
```swift
if SecurityKit.isTampered(
    [.bundleID("com.app.bundle"),
     .mobileProvision("your-mobile-provision-sha256-value")]
).result {
    print("SecurityKit: I have been Tampered.")
} else {
    print("SecurityKit: I have not been Tampered.")
}
```
* This type method is used to get the SHA256 hash value of the executable file in a specified image
```swift
// Manually verify SHA256 hash value of a loaded dylib
if let hashValue = SecurityKit.getMachOFileHashValue(.custom("SecurityKit")),
   hashValue == "6d8d460b9a4ee6c0f378e30f137cebaf2ce12bf31a2eef3729c36889158aa7fc" {
    print("SecurityKit: I have not been Tampered.")
} else {
    print("SecurityKit: I have been Tampered.")
}
```
* This type method is used to find all loaded dylibs in the specified image
```swift
if let loadedDylib = SecurityKit.findLoadedDylibs() {
    print("SecurityKit: Loaded dylibs: \(loadedDylib)")
}
```
### MSHookFunction detection
* This type method is used to detect if `function_address` has been hooked by `MSHook`
```swift
func denyDebugger() { ... }

typealias FunctionType = @convention(thin) ()->()

let func_denyDebugger: FunctionType = denyDebugger // `: FunctionType` is must
let func_addr = unsafeBitCast(func_denyDebugger, to: UnsafeMutableRawPointer.self)
let isMSHooked: Bool = SecurityKit.isMSHooked(func_addr)
```
* This type method is used to get original `function_address` which has been hooked by `MSHook`
```swift
func denyDebugger(value: Int) { ... }

typealias FunctionType = @convention(thin) (Int)->()

let funcDenyDebugger: FunctionType = denyDebugger
let funcAddr = unsafeBitCast(funcDenyDebugger, to: UnsafeMutableRawPointer.self)

if let originalDenyDebugger = SecurityKit.denyMSHook(funcAddr) {
    // Call orignal function with 1337 as Int argument
    unsafeBitCast(originalDenyDebugger, to: FunctionType.self)(1337)
} else {
    denyDebugger()
}
```
### FishHook detection
* This type method is used to rebind `symbol` which has been hooked by `fishhook`
```swift
SecurityKit.denySymbolHook("$s10Foundation5NSLogyySS_s7CVarArg_pdtF") // Foudation's NSlog of Swift
NSLog("Hello Symbol Hook")

SecurityKit.denySymbolHook("abort")
abort()
```
* This type method is used to rebind `symbol` which has been hooked at one of image by `fishhook`
```swift
for i in 0..<_dyld_image_count() {
    if let imageName = _dyld_get_image_name(i) {
        let name = String(cString: imageName)
        if name.contains("SecurityKit"), let image = _dyld_get_image_header(i) {
            SecurityKit.denySymbolHook("dlsym", at: image, imageSlide: _dyld_get_image_vmaddr_slide(i))
            break
        }
    }
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
