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
    
    public static func isJailBroken() -> Bool {
        return JailbreakDetection.isJailBroken()
    }
    
    public static func isJailBrokenWithErrorMessage() -> (jailbroken: Bool, errorMessage: String) {
      return JailbreakDetection.isJailBrokenWithErrorMessage()
    }
    
    public static func isJailBrokenWithErrorDetects() -> (jailbroken: Bool, errorDetects: [ErrorDetectType]) {
      return JailbreakDetection.isJailBrokenWithErrorDetects()
    }
    
    public static func isSimulator() -> Bool {
      return SimulatorDetection.isSimulator()
    }
}
