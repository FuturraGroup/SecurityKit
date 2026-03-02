//
//  CodeSignatureDetection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/26.
//  Copyright © 2026 Futurra Group. All rights reserved.
//

import Foundation

/// Validates the app's code signature integrity and provisioning profile at runtime.
///
/// Checks for the existence of the `_CodeSignature` directory, parses the embedded provisioning profile
/// to extract team identifiers, entitlements, and development/distribution indicators.
internal class CodeSignatureDetection {
    
    /**
     Detects if the app's code signature directory has been removed or tampered with.
     
     Checks that `_CodeSignature/` and `_CodeSignature/CodeResources` exist in the app bundle.
     A missing code signature directory indicates the binary has been re-signed or modified.
     
     - Returns: Bool indicating if the code signature is missing or modified (true) or intact (false)
     */
    static func isCodeSignatureModified() -> Bool {
        let bundlePath = Bundle.main.bundlePath as NSString
        let codeSignaturePath = bundlePath.appendingPathComponent("_CodeSignature")
        
        if !FileManager.default.fileExists(atPath: codeSignaturePath) {
            return true
        }
        
        let codeResourcesPath = (codeSignaturePath as NSString).appendingPathComponent("CodeResources")
        if !FileManager.default.fileExists(atPath: codeResourcesPath) {
            return true
        }
        
        return false
    }
    
    /**
     Detects if the app is running as a development build by parsing the embedded provisioning profile.
     
     Checks for:
     - `get-task-allow` entitlement set to `true` (indicates debug/development signing)
     - Presence of `ProvisionedDevices` list (indicates ad-hoc or development distribution)
     
     - Returns: Bool indicating if the app is a development build (true) or not (false)
     */
    static func isDevelopmentBuild() -> Bool {
        guard let provisionPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
              let provisionData = FileManager.default.contents(atPath: provisionPath),
              let profile = extractProvisioningProfile(from: provisionData) else {
            return false
        }
        
        if let entitlements = profile["Entitlements"] as? [String: Any],
           let getTaskAllow = entitlements["get-task-allow"] as? Bool,
           getTaskAllow {
            return true
        }
        
        if profile["ProvisionedDevices"] != nil {
            return true
        }
        
        return false
    }
    
    /**
     Verifies that the app's provisioning profile contains the expected team identifier.
     
     Useful for detecting if the app has been re-signed with a different developer certificate.
     
     - Parameter expectedTeamID: The expected team identifier string (e.g. "ABCDEF1234")
     - Returns: Bool indicating if the team identifier matches (true) or not (false)
     */
    static func verifyTeamIdentifier(_ expectedTeamID: String) -> Bool {
        guard let provisionPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
              let provisionData = FileManager.default.contents(atPath: provisionPath),
              let profile = extractProvisioningProfile(from: provisionData),
              let teamIdentifiers = profile["TeamIdentifier"] as? [String] else {
            return false
        }
        
        return teamIdentifiers.contains(expectedTeamID)
    }
    
    /// Extracts the XML plist from a CMS/PKCS7-signed provisioning profile
    private static func extractProvisioningProfile(from data: Data) -> [String: Any]? {
        guard let xmlStartRange = data.range(of: Data("<?xml".utf8)),
              let plistEndRange = data.range(of: Data("</plist>".utf8)) else {
            return nil
        }
        
        let plistData = data.subdata(in: xmlStartRange.lowerBound..<plistEndRange.upperBound)
        
        return try? PropertyListSerialization.propertyList(
            from: plistData,
            options: [],
            format: nil
        ) as? [String: Any]
    }
}
