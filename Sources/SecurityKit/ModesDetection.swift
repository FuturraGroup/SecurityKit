//
//  ModesDetection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/25.
//  Copyright © 2025 Futurra Group. All rights reserved.
//

import Foundation

internal class ModesDetection {
    //https://support.apple.com/en-us/105120
    
    static func isLockdownModeEnable() -> Bool {
        return UserDefaults.standard.bool(forKey: "LDMGlobalEnabled")
    }
}
