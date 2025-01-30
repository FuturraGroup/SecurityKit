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
}
