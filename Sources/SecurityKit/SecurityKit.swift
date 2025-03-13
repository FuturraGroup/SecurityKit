//
//  SecurityKit.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 1/21/25.
//  Copyright © 2025 Futurra Group. All rights reserved.
//

import Foundation
import MachO

@MainActor
@available(iOSApplicationExtension, unavailable)
public class SecurityKit {
    /**
     This type method is used to detect the true/false jailbreak status
     
     # Example #
     ```swift
     let isJailBroken: Bool = SecurityKit.isJailBroken()
     ```
     
     - Returns: Bool indicating if the device has jailbreak (true) or not (false)
     */
    public static func isJailBroken() -> Bool {
        return JailbreakDetection.isJailBroken()
    }
    /**
     This type method is used to detect the jailbreak status with a message which jailbreak indicator was detected
     
     # Example #
     ```swift
     let jailbreakStatus = SecurityKit.isJailBrokenWithErrorMessage()
     if jailbreakStatus.jailbroken {
         print("This device is jailbroken")
         print("Because: \(jailbreakStatus.errorMessage)")
     } else {
         print("This device is not jailbroken")
     }
     ```
     
     - Returns: Tuple with with the jailbreak status (Bool) and failMessage (String)
     */
    public static func isJailBrokenWithErrorMessage() -> (jailbroken: Bool, errorMessage: String) {
        return JailbreakDetection.isJailBrokenWithErrorMessage()
    }
    /**
     This type method is used to detect the jailbreak status with a list of failed detects
    
     # Example #
     ```swift
     let jailbreakStatus = SecurityKit.isJailBrokenWithErrorDetects()
     if jailbreakStatus.jailbroken {
       print("This device is jailbroken")
       print("The following checks failed: \(jailbreakStatus.errorDetects)")
     }
     ```
    
     - Returns: Tuple with with the jailbreak status (Bool) and a list of ``ErrorDetectType``
     */
    public static func isJailBrokenWithErrorDetects() -> (jailbroken: Bool, errorDetects: [ErrorDetectType]) {
        return JailbreakDetection.isJailBrokenWithErrorDetects()
    }
    /**
     This type method is used to detect if application is run in simulator
    
     # Example #
     ```swift
     let runInSimulator: Bool = SecurityKit.isSimulator()
     ```
     - Returns: Bool indicating if the device is an simulator (true) or not (false)
     */
    public static func isSimulator() -> Bool {
        return SimulatorDetection.isSimulator()
    }
    /**
     This type method is used to detect if there are any popular reverse engineering tools installed on the device
    
     # Example #
     ```swift
     let isReverseEngineered: Bool = SecurityKit.isReverseEngineered()
     ```
     - Returns: Bool indicating if device has reverse engineering tools (true) or not (false)
     */
    public static func isReverseEngineered() -> Bool {
        return ReverseEngineeringDetection.isReverseEngineered()
    }
    /**
     This type method is used to detect the reverse engineered status with a list of failed detects
    
     # Example #
     ```swift
     let reStatus = SecurityKit.isReverseEngineeredWithErrorDetect()
     if reStatus.reverseEngineered {
       print("SecurityKit: This device has evidence of reverse engineering")
       print("SecurityKit: The following detects failed: \(reStatus.errorDetect)")
     }
     ```
    
     - Returns: Tuple with with the reverse engineered status (Bool) and a list of ``ErrorDetectType``
     */
    public static func isReverseEngineeredWithErrorDetect() -> (reverseEngineered: Bool, errorDetect: [ErrorDetectType]) {
        return ReverseEngineeringDetection.isReverseEngineeredWithErrorDetect()
    }
    /**
     This type method is used to detect if application is being debugged
    
     # Example #
     ```swift
     let isDebugged: Bool = SecurityKit.isDebugged()
     ```
     - Returns: Bool indicating if the device is being debugged (true) or not (false)
     */
    public static func isDebugged() -> Bool {
        return DebuggerDetection.isDebugged()
    }
    /**
     This type method is used to deny debugger and improve the application resillency
    
     # Example #
     ```swift
     SecurityKit.denyDebugger()
     ```
     */
    public static func denyDebugger() {
        return DebuggerDetection.denyDebugger()
    }
    /**
     This method is used to detect if application was launched by something other than LaunchD (i.e. the app was launched by a debugger)
    
     # Example #
     ```swift
     let isNotLaunchD: Bool = SecurityKit.isParentPidUnexpected()
     ```
     - Returns: Bool indicating if application was launched by something other than LaunchD (true) or not (false)
     */
    public static func isParentPidUnexpected() -> Bool {
        return DebuggerDetection.isParentPidUnexpected()
    }
    /**
     This type method is used to detect if application has been tampered with
    
     # Example #
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
    
     - Parameter checks: The file Integrity checks you want
     - Returns: The file Integrity checker result
     */
    public static func isTampered(_ checks: [FileIntegrityDetect]) -> FileIntegrityDetectResult {
        return IntegrityDetection.isTampered(checks)
    }
    /**
     This type method is used to detect if `objc call` has been RuntimeHooked by for example `Flex`
    
     # Example #
     ```swift
     class SomeClass {
       @objc dynamic func someFunction() { ... }
     }
    
     let dylds = ["SecurityKit", ...]
    
     let isRuntimeHook: Bool = SecurityKit.isRuntimeHook(
       dyldAllowList: dylds,
       detectionClass: SomeClass.self,
       selector: #selector(SomeClass.someFunction),
       isClassMethod: false
      )
     ```
    
     - Returns: Bool indicating if the method is being hooked (true) or not (false)
     */
    public static func isRuntimeHook(dyldAllowList: [String], detectionClass: AnyClass, selector: Selector, isClassMethod: Bool) -> Bool {
        return RuntimeHookDetection.isRuntimeHook(
            dyldAllowList: dyldAllowList,
            detectionClass: detectionClass,
            selector: selector,
            isClassMethod: isClassMethod
        )
    }
    /**
     This type method is used to detect if HTTP proxy or VPN was set in the iOS Settings.
    
     # Example #
     ```swift
     let isProxied: Bool = SecurityKit.isProxied()
     ```
     - Returns: Bool indicating if the device has a proxy or VPN setted (true) or not (false)
     */
    public static func isProxied(considerVPNConnectionAsProxy: Bool = false) -> Bool {
        return ProxyDetection.isProxied(considerVPNConnectionAsProxy: considerVPNConnectionAsProxy)
    }
    /**
     This type method is used to detect if the device has lockdown mode turned on.
    
     # Example #
     ```swift
     let isLockdownModeEnable: Bool = SecurityKit.isLockdownModeEnable()
     ```
     - Returns: Bool indicating if the device has lockdown mode turned on (true) or not (false)
     */
    @available(iOS 16, *)
    public static func isLockdownModeEnable() -> Bool {
        return ModesDetection.isLockdownModeEnable()
    }
    /**
     Hide Sensitive String data from run time binary
     
     - parameter String
     - parameter String
     - returns   [UInt8]
     - warning: none
     
     # Notes: #
     Use this method use for encrypt string
     base on XOR alghorithm
     # Example #
     ```
     //
     SecurityKit.stringEncryption(plainText : "String", encryptionKey: "String")
     ```
     */
    public static func stringEncryption(plainText : String, encryptionKey: String) -> [UInt8] {
        return XOREncryption.encryption(plainText: plainText, encryptionKey: encryptionKey)
    }
    /**
     Hide Sensitive String data from run time binary
     
     - parameter String
     - parameter String
     - returns   String
     - warning: none
     
     # Notes: #
     Use this method use for array of [UInt8]
     # Example #
     ```
     //
     SecurityKit.stringDecryption(cypherText: [UInt8]?, decryptionKey : "String")
     ```
     */
    public static func stringDecryption(cypherText: [UInt8]?, decryptionKey : String?) -> String {
        return XOREncryption.decryption(cypherText: cypherText, decryptionKey: decryptionKey)
    }
}

#if arch(arm64)
@available(iOSApplicationExtension, unavailable)
public extension SecurityKit {
    /**
     This type method is used to detect if there are any breakpoints at the function
    
     # Example #
     ```swift
     func denyDebugger() {
       // add a breakpoint at here to test
     }
    
     typealias FunctionType = @convention(thin) ()->()
    
     let func_denyDebugger: FunctionType = denyDebugger   // `: FunctionType` is a must
     let func_addr = unsafeBitCast(func_denyDebugger, to: UnsafeMutableRawPointer.self)
     let hasBreakpoint: Bool = SecurityKit.hasBreakpointAt(func_addr, functionSize: nil)
     ```
     - Returns: Bool indicating if the function has a breakpoint (true) or not (false)
     */
    static func hasBreakpointAt(_ functionAddr: UnsafeRawPointer, functionSize: vm_size_t?) -> Bool {
        return DebuggerDetection.hasBreakpointAt(functionAddr, functionSize: functionSize)
    }
    /**
     This type method is used to detect if a watchpoint is being used.
     A watchpoint is a type of breakpoint that 'watches' an area of memory associated with a data item.
    
     # Example #
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
     - Returns: Bool indicating if has a watchpoint setted (true) or not (false)
     */
    static func hasWatchpoint() -> Bool {
        return DebuggerDetection.hasWatchpoint()
    }
    /**
     This type method is used to get the SHA256 hash value of the executable file in a specified image
    
     - Attention: **Dylib only.** This means you should set Mach-O type as `Dynamic Library` in your *Build Settings*.
    
     Calculate the hash value of the `__TEXT.__text` data of the specified image Mach-O file.
    
     # Example #
     ```swift
     // Manually verify SHA256 hash value of a loaded dylib
     if let hashValue = SecurityKit.getMachOFileHashValue(.custom("SecurityKit")),
       hashValue == "6d8d460b9a4ee6c0f378e30f137cebaf2ce12bf31a2eef3729c36889158aa7fc" {
         print("SecurityKit: I have not been Tampered.")
     } else {
       print("SecurityKit: I have been Tampered.")
     }
     ```
    
     - Parameter target: The target image
     - Returns: A hash value of the executable file.
     */
    static func getMachOFileHashValue(_ target: IntegrityDetectionImageTarget = .default) -> String? {
        return IntegrityDetection.getMachOFileHashValue(target)
    }
    /**
     This type method is used to find all loaded dylibs in the specified image
    
     - Attention: **Dylib only.** This means you should set Mach-O type as `Dynamic Library` in your *Build Settings*.
    
     # Example #
     ```swift
     if let loadedDylib = SecurityKit.findLoadedDylibs() {
       print("SecurityKit: Loaded dylibs: \(loadedDylib)")
     }
     ```
    
     - Parameter target: The target image
     - Returns: An Array with all loaded dylib names
    */
    static func findLoadedDylibs(_ target: IntegrityDetectionImageTarget = .default) -> [String]? {
        return IntegrityDetection.findLoadedDylibs(target)
    }
    /**
     This type method is used to detect if `function_address` has been hooked by `MSHook`
    
     # Example #
     ```swift
     func denyDebugger() { ... }
    
     typealias FunctionType = @convention(thin) ()->()
    
     let func_denyDebugger: FunctionType = denyDebugger // `: FunctionType` is must
     let func_addr = unsafeBitCast(func_denyDebugger, to: UnsafeMutableRawPointer.self)
     let isMSHooked: Bool = SecurityKit.isMSHooked(func_addr)
     ```
     - Returns: Bool indicating if the function has been hooked (true) or not (false)
     */
    static func isMSHooked(_ functionAddress: UnsafeMutableRawPointer) -> Bool {
        return MSHookFunctionDetection.isMSHooked(functionAddress)
    }
    /**
     This type method is used to get original `function_address` which has been hooked by `MSHook`
    
     # Example #
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
     */
    static func denyMSHook(_ functionAddress: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
        return MSHookFunctionDetection.denyMSHook(functionAddress)
    }
    /**
     This type method is used to rebind `symbol` which has been hooked by `fishhook`
    
     # Example #
     ```swift
     SecurityKit.denySymbolHook("$s10Foundation5NSLogyySS_s7CVarArg_pdtF") // Foudation's NSlog of Swift
     NSLog("Hello Symbol Hook")
    
     SecurityKit.denySymbolHook("abort")
     abort()
     ```
     */
    static func denySymbolHook(_ symbol: String) {
        FishHookDetection.denyFishHook(symbol)
    }
    /**
     This type method is used to rebind `symbol` which has been hooked at one of image by `fishhook`
    
     # Example #
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
     */
    static func denySymbolHook(
        _ symbol: String,
        at image: UnsafePointer<mach_header>,
        imageSlide slide: Int
    ) {
        FishHookDetection.denyFishHook(symbol, at: image, imageSlide: slide)
    }
}
#endif
