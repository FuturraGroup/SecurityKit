//
//  SecureStorage.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/26.
//  Copyright © 2026 Futurra Group. All rights reserved.
//

import Foundation
import Security

/// A thread-safe wrapper around Apple Keychain Services for secure storage of sensitive data.
///
/// Supports configurable accessibility levels and stores data as `kSecClassGenericPassword` items.
/// Each instance is scoped to a service identifier (defaults to the app's bundle ID).
public final class SecureStorage: Sendable {
    
    /// Keychain accessibility level that controls when stored items can be accessed.
    public enum AccessLevel: Sendable {
        /// Item is accessible when the device is unlocked (can be migrated to new devices)
        case whenUnlocked
        /// Item is accessible when the device is unlocked (bound to this device only)
        case whenUnlockedThisDeviceOnly
        /// Item is accessible after first unlock until reboot (can be migrated)
        case afterFirstUnlock
        /// Item is accessible after first unlock until reboot (bound to this device only)
        case afterFirstUnlockThisDeviceOnly
        /// Item is only accessible when the device has a passcode set (bound to this device only)
        case whenPasscodeSetThisDeviceOnly
        
        /// Maps to the corresponding `kSecAttrAccessible` constant
        var secAttr: CFString {
            switch self {
            case .whenUnlocked:
                return kSecAttrAccessibleWhenUnlocked
            case .whenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlock:
                return kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .whenPasscodeSetThisDeviceOnly:
                return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }
        }
    }
    
    /// The Keychain service identifier used to scope stored items
    private let service: String
    /// The accessibility level applied to all items stored by this instance
    private let accessLevel: AccessLevel
    
    /**
     Creates a new SecureStorage instance.
     
     - Parameters:
       - service: The Keychain service identifier (defaults to the app's bundle ID)
       - accessLevel: The accessibility level for stored items (defaults to `.whenPasscodeSetThisDeviceOnly`)
     */
    public init(
        service: String = Bundle.main.bundleIdentifier ?? "com.securitykit.storage",
        accessLevel: AccessLevel = .whenPasscodeSetThisDeviceOnly
    ) {
        self.service = service
        self.accessLevel = accessLevel
    }
    
    /**
     Saves raw data to the Keychain under the specified key.
     Existing data for the same key is deleted before saving.
     
     - Parameters:
       - data: The data to store securely
       - key: A unique identifier for the stored item
     - Returns: Bool indicating if the data was saved successfully
     */
    @discardableResult
    public func save(_ data: Data, for key: String) -> Bool {
        delete(key: key)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessLevel.secAttr
        ]
        
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }
    
    /**
     Saves a UTF-8 string to the Keychain under the specified key.
     
     - Parameters:
       - string: The string to store securely
       - key: A unique identifier for the stored item
     - Returns: Bool indicating if the string was saved successfully
     */
    @discardableResult
    public func save(_ string: String, for key: String) -> Bool {
        guard let data = string.data(using: .utf8) else { return false }
        return save(data, for: key)
    }
    
    /**
     Loads raw data from the Keychain for the specified key.
     
     - Parameter key: The identifier of the stored item
     - Returns: The stored data, or nil if not found
     */
    public func loadData(for key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        return status == errSecSuccess ? result as? Data : nil
    }
    
    /**
     Loads a UTF-8 string from the Keychain for the specified key.
     
     - Parameter key: The identifier of the stored item
     - Returns: The stored string, or nil if not found or not valid UTF-8
     */
    public func loadString(for key: String) -> String? {
        guard let data = loadData(for: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    /**
     Deletes a single item from the Keychain.
     
     - Parameter key: The identifier of the item to delete
     - Returns: Bool indicating if the item was deleted (or did not exist)
     */
    @discardableResult
    public func delete(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }
    
    /**
     Deletes all items stored by this instance (scoped by service identifier).
     
     - Returns: Bool indicating if the items were deleted
     */
    @discardableResult
    public func deleteAll() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }
    
    /**
     Checks if an item exists in the Keychain for the specified key without loading its data.
     
     - Parameter key: The identifier of the item to check
     - Returns: Bool indicating if the item exists (true) or not (false)
     */
    public func exists(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false
        ]
        
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
}
