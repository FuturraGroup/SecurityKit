//
//  AESEncryption.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/26.
//  Copyright © 2026 Futurra Group. All rights reserved.
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit

/// Provides AES-256-GCM authenticated encryption and decryption using Apple CryptoKit.
///
/// AES-GCM provides both confidentiality and integrity — the output includes a nonce, ciphertext, and authentication tag.
/// Key derivation from a passphrase is performed via SHA256 hashing.
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
internal class AESGCMEncryption {
    
    /// Errors that can occur during AES-GCM operations
    enum AESError: Error {
        case encryptionFailed
        case decryptionFailed
        case invalidData
    }
    
    /**
     Encrypts data using AES-256-GCM with the provided symmetric key.
     
     - Parameters:
       - data: The plaintext data to encrypt
       - key: A 256-bit symmetric key
     - Returns: Combined data containing nonce + ciphertext + authentication tag
     - Throws: `AESError.encryptionFailed` if the sealed box cannot produce combined output
     */
    static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.seal(data, using: key)
        guard let combined = sealedBox.combined else {
            throw AESError.encryptionFailed
        }
        return combined
    }
    
    /**
     Decrypts AES-256-GCM encrypted data with the provided symmetric key.
     
     - Parameters:
       - data: The combined encrypted data (nonce + ciphertext + tag) as returned by ``encrypt(data:key:)``
       - key: The same 256-bit symmetric key used for encryption
     - Returns: The decrypted plaintext data
     - Throws: `AESError.decryptionFailed` if the data is tampered or the key is wrong
     */
    static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    /**
     Generates a random AES symmetric key.
     
     - Parameter size: The key size (default: `.bits256`)
     - Returns: A cryptographically random symmetric key
     */
    static func generateKey(size: SymmetricKeySize = .bits256) -> SymmetricKey {
        return SymmetricKey(size: size)
    }
    
    /**
     Derives a 256-bit symmetric key from a passphrase string by hashing it with SHA256.
     
     - Parameter passphrase: A passphrase string to derive the key from
     - Returns: A symmetric key derived from the SHA256 hash of the passphrase, or nil if the string cannot be encoded
     */
    static func key(from passphrase: String) -> SymmetricKey? {
        guard let data = passphrase.data(using: .utf8) else { return nil }
        let hash = SHA256.hash(data: data)
        return SymmetricKey(data: hash)
    }
}
#endif
