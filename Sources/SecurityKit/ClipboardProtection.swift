//
//  ClipboardProtection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 2/10/26.
//  Copyright © 2026 Futurra Group. All rights reserved.
//

import Foundation
import UIKit

/// Provides pasteboard clearing and timed auto-clear to prevent sensitive data leakage via the clipboard.
///
/// Uses `UIPasteboard.general` to clear all items. The auto-clear timer runs on the main thread
/// and can be cancelled at any time with ``stopAutoClear()``.
@available(iOS 13.0, *)
@available(iOSApplicationExtension, unavailable)
@MainActor
public class ClipboardProtection: Sendable {
    
    /// Shared singleton instance
    public static let shared = ClipboardProtection()
    /// Timer used for delayed clipboard clearing
    private var clearTimer: Timer?
    
    private init() {}
    
    /**
     Immediately clears all content from the system clipboard.
     */
    public func clearClipboard() {
        UIPasteboard.general.items = []
    }
    
    /**
     Clears the clipboard after a specified delay. Any previous pending auto-clear is cancelled.
     
     - Parameter seconds: The delay in seconds before the clipboard is cleared (default: 30)
     */
    public func clearAfterDelay(_ seconds: TimeInterval = 30) {
        clearTimer?.invalidate()
        clearTimer = Timer.scheduledTimer(withTimeInterval: seconds, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.clearClipboard()
            }
        }
    }
    
    /**
     Checks if the system clipboard currently has any content (strings, images, or URLs).
     
     - Returns: Bool indicating if the clipboard has content (true) or is empty (false)
     */
    public func hasContent() -> Bool {
        return UIPasteboard.general.hasStrings ||
               UIPasteboard.general.hasImages ||
               UIPasteboard.general.hasURLs
    }
    
    /**
     Cancels any pending auto-clear timer.
     */
    public func stopAutoClear() {
        clearTimer?.invalidate()
        clearTimer = nil
    }
}
