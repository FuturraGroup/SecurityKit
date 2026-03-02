//
//  BlurScreen.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 3/13/25.
//  Copyright © 2025 Futurra Group. All rights reserved.
//

import Foundation
import UIKit

@available(iOS 13.0, *)
@MainActor
public class BlurScreen: Sendable {
    public static let shared = BlurScreen()
    private var observers = [NSObjectProtocol]()
    
    private weak var view: UIView?
    private var timer: Timer?
    private var isRunning = false
    private init() {}
    
    deinit {
        MainActor.assumeIsolated {
            observers.forEach { NotificationCenter.default.removeObserver($0) }
        }
    }
    
    private var blurStyle: UIBlurEffect.Style = .dark
    
    public func start(with blurStyle: UIBlurEffect.Style = .dark) {
        guard !isRunning else { return }
        isRunning = true
        self.blurStyle = blurStyle
        
        let notifications: [Notification.Name] = [
            UIScreen.capturedDidChangeNotification,
            UIApplication.didBecomeActiveNotification,
            UIApplication.willEnterForegroundNotification,
            UIApplication.willResignActiveNotification
        ]
        
        for name in notifications {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.addRemoveBlur()
                }
            })
        }
    }
    
    public func stop() {
        guard isRunning else { return }
        isRunning = false
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        observers.removeAll()
        removeLockView(animated: false)
    }
    
    private func addRemoveBlur(){
        if UIScreen.main.isCaptured {
            self.addLockView()
        } else {
            self.removeLockView(animated: true)
        }
    }
    
    private func addLockView(animated: Bool = false) {
        guard let window = keyWindow, view == nil else { return }
        
        let blurEffect = UIBlurEffect(style: blurStyle)
        let blurredEffectView = UIVisualEffectView(frame: window.bounds)
        blurredEffectView.effect = blurEffect
        blurredEffectView.alpha = 0
        window.addSubview(blurredEffectView)
        self.view = blurredEffectView
        
        UIView.animate(withDuration: animated ? 0.175 : 0) { [weak self] in
            self?.view?.alpha = 1
        }
    }
    
    private func removeLockView(animated: Bool = false) {
        guard let view = view else { return }
        
        UIView.animate(withDuration: animated ? 0.175 : 0) { [weak view] in
            view?.alpha = 0
        } completion: { [weak self, weak view] completed in
            if completed {
                view?.removeFromSuperview()
                self?.view = nil
            }
        }
    }
    
    private var keyWindow: UIWindow? {
        return UIApplication.currentWindow
    }
}

@available(iOS 13.0, *)
extension UIApplication {
    static var currentWindow: UIWindow? {
        return shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
    }
}
