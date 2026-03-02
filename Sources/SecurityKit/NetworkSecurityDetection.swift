//
//  NetworkSecurityDetection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/26.
//  Copyright © 2026 Futurra Group. All rights reserved.
//

import Foundation
import MachO

/// Detects network security misconfigurations and SSL interception tools.
///
/// Checks for loaded SSL Kill Switch / SSL Unpinning dylibs via DYLD image enumeration,
/// and verifies App Transport Security (ATS) configuration from the host app's Info.plist.
internal class NetworkSecurityDetection {
    
    /// Known SSL stripping / certificate pinning bypass libraries
    private static let sslKillLibraries: Set<String> = [
        "SSLKillSwitch",
        "SSLKillSwitch2",
        "ssl_kill_switch2",
        "SSLUnpinning",
        "sslunpinning",
        "killswitch"
    ]
    
    /**
     Detects if any known SSL Kill Switch or SSL Unpinning dylibs are loaded into the process.
     
     Iterates all loaded DYLD images and checks their names against a known list of SSL interception tools.
     
     - Returns: Bool indicating if an SSL Kill Switch dylib is loaded (true) or not (false)
     */
    static func isSSLKillSwitchLoaded() -> Bool {
        for index in 0..<_dyld_image_count() {
            let imageName = String(cString: _dyld_get_image_name(index))
            for library in sslKillLibraries where imageName.localizedCaseInsensitiveContains(library) {
                return true
            }
        }
        return false
    }
    
    /**
     Checks if App Transport Security (ATS) is disabled in the host app's Info.plist.
     
     Specifically checks for `NSAllowsArbitraryLoads = true` under the `NSAppTransportSecurity` key.
     ATS being disabled allows insecure HTTP connections, which may indicate a security misconfiguration.
     
     - Returns: Bool indicating if ATS allows arbitrary loads (true) or not (false)
     */
    static func isATSDisabled() -> Bool {
        guard let infoDict = Bundle.main.infoDictionary,
              let ats = infoDict["NSAppTransportSecurity"] as? [String: Any] else {
            return false
        }
        
        if let allowsArbitrary = ats["NSAllowsArbitraryLoads"] as? Bool, allowsArbitrary {
            return true
        }
        
        return false
    }
}
