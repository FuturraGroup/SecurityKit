//
//  SimulatorDetection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 1/21/25.
//  Copyright © 2025 Futurra Group. All rights reserved.
//

import Foundation

internal class SimulatorDetection {
    static func isSimulator() -> Bool {
        return detectCompile() || detectRuntime()
    }
    
    private static func detectRuntime() -> Bool {
        return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
    }
    
    private static func detectCompile() -> Bool {
#if targetEnvironment(simulator)
        return true
#else
        return false
#endif
    }
}
