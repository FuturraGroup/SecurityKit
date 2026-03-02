//
//  MemoryProtection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/26.
//  Copyright © 2026 Futurra Group. All rights reserved.
//

import Foundation

/// Provides secure memory wiping for sensitive data types (Data, [UInt8], String).
///
/// Uses `@inline(never)` to prevent compiler optimizations from eliding zero-fill operations
/// and `withExtendedLifetime` to ensure the data is not deallocated before wiping completes.
public final class MemoryProtection: Sendable {
    
    /**
     Securely wipes the contents of a `Data` value by resetting all bytes to zero and replacing with empty Data.
     
     - Parameter data: An inout reference to the Data to wipe
     */
    @inline(never)
    public static func wipe(_ data: inout Data) {
        let count = data.count
        guard count > 0 else { return }
        data.resetBytes(in: 0..<count)
        withExtendedLifetime(data) {}
        data = Data()
    }
    
    /**
     Securely wipes the contents of a `[UInt8]` array by zeroing all elements and clearing the array.
     
     - Parameter bytes: An inout reference to the byte array to wipe
     */
    @inline(never)
    public static func wipe(_ bytes: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        for i in bytes.indices {
            bytes[i] = 0
        }
        withExtendedLifetime(bytes) {}
        bytes.removeAll()
    }
    
    /**
     Securely wipes the contents of a `String` by zeroing its UTF-8 representation and replacing with an empty string.
     
     - Parameter string: An inout reference to the String to wipe
     */
    @inline(never)
    public static func wipe(_ string: inout String) {
        guard !string.isEmpty else { return }
        var utf8 = Array(string.utf8)
        for i in utf8.indices {
            utf8[i] = 0
        }
        withExtendedLifetime(utf8) {}
        string = ""
    }
}
