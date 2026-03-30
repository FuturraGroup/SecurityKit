//
//  DeviceBindingDetection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/26.
//  Copyright © 2026 Futurra Group. All rights reserved.
//

import Foundation
import UIKit
import Security
import CommonCrypto

/// Generates a stable, unique device fingerprint by combining the vendor identifier,
/// a Keychain-persisted UUID, and the hardware model string.
///
/// The fingerprint survives app reinstalls (Keychain persists) and is hashed with SHA256
/// to produce a consistent hex string.
internal class DeviceBindingDetection {
    
    /// Keychain service used to persist the device-unique UUID
    private static let keychainService = "com.securitykit.devicebinding"
    /// Keychain account key for the persistent device ID
    private static let keychainKey = "persistent-device-id"
    
    /**
     Generates a SHA256 fingerprint combining the vendor ID, a Keychain-persisted UUID, and the hardware model.
     
     The three components are concatenated with `|` separators and hashed to produce a stable, unique identifier.
     Falls back to vendor ID alone if string encoding fails.
     
     - Returns: A 64-character lowercase hex string (SHA256 digest) uniquely identifying this device
     */
    @MainActor static func getDeviceFingerprint() -> String {
        let vendorID = UIDevice.current.identifierForVendor?.uuidString ?? "unknown"
        let persistentID = getOrCreatePersistentID()
        let model = deviceModel()
        
        let combined = "\(vendorID)|\(persistentID)|\(model)"
        
        guard let data = combined.data(using: .utf8) else {
            return vendorID
        }
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Retrieves the persisted device UUID from Keychain, or creates and stores a new one if none exists.
    private static func getOrCreatePersistentID() -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data,
           let id = String(data: data, encoding: .utf8) {
            return id
        }
        
        let newID = UUID().uuidString
        if let idData = newID.data(using: .utf8) {
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainKey,
                kSecValueData as String: idData,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            ]
            SecItemAdd(addQuery as CFDictionary, nil)
        }
        
        return newID
    }
    
    /// Returns the raw hardware model string (e.g. "iPhone14,5") via `uname()`
    private static func deviceModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        return withUnsafePointer(to: &systemInfo.machine) { ptr in
            String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
        }
    }
}
