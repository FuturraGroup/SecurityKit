//
//  EnvironmentDetection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/26.
//  Copyright © 2026 Futurra Group. All rights reserved.
//

import Foundation

/// Detects suspicious environment variables that indicate dylib injection, jailbreak tools, or runtime manipulation.
internal class EnvironmentDetection {
    typealias DetectResult = (passed: Bool, errorMessage: String)
    
    /// Environment variables commonly set by jailbreak tools and injection frameworks
    private static let suspiciousVariables = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_PRINT_TO_FILE",
        "_MSSafeMode",
        "INJECT_DYLIB",
        "SUBSTRATE_INSERT_LIBRARIES",
        "SIMULATED_JAILBREAK"
    ]
    
    /**
     Checks the process environment for known suspicious variables used by injection tools.
     
     - Returns: A tuple with the detection result and error message if a suspicious variable was found.
     */
    static func detectSuspiciousEnvironment() -> DetectResult {
        for envVar in suspiciousVariables {
            if let value = ProcessInfo.processInfo.environment[envVar] {
                return (false, "Suspicious environment variable set: \(envVar)=\(value)")
            }
        }
        return (true, "")
    }
    
    /**
     Convenience method that returns a simple Bool indicating whether any suspicious environment variables are set.
     
     - Returns: Bool indicating if suspicious environment variables were detected (true) or not (false)
     */
    static func hasSuspiciousEnvironment() -> Bool {
        return !detectSuspiciousEnvironment().passed
    }
}
