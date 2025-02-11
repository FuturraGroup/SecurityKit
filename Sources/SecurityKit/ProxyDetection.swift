//
//  ProxyDetection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/25.
//  Copyright © 2025 Futurra Group. All rights reserved.
//

import Foundation

internal class ProxyDetection {
    static func isProxied(considerVPNConnectionAsProxy: Bool = false) -> Bool {
        guard let unmanagedSettings = CFNetworkCopySystemProxySettings() else {
            return false
        }
        
        let settingsOptional = unmanagedSettings.takeRetainedValue() as? [String: Any]
        
        guard  let settings = settingsOptional else {
            return false
        }
        
        if(considerVPNConnectionAsProxy) {
            if let scoped = settings["__SCOPED__"] as? [String: Any] {
                for interface in scoped.keys {
                    
                    let names = [
                        "tap",
                        "tun",
                        "ppp",
                        "ipsec",
                        "utun"
                    ]
                    
                    for name in names {
                        if(interface.contains(name)) {
                            print("SecurityKit: detected: \(interface)")
                            return true
                        }
                    }
                }
            }
        }
        return (settings.keys.contains("HTTPProxy") || settings.keys.contains("HTTPSProxy"))
    }
}
