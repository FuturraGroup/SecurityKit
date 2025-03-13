//
//  ViewProtection.swift
//  SecurityKit
//
//  Created by Sergey Zhuravel on 3/4/25.
//  Copyright © 2025 Futurra Group. All rights reserved.
//

import Foundation
import UIKit

private extension UIView {
    
    enum Constant {
        case textFieldTag
        var num : Int {
            switch self {
            case .textFieldTag:
                return Int.max
            }
        }
    }
    
    // Create a layer on screen to hide sensitive data
    func makeSecureTextField() {
        
        guard superview != nil else {
            for subview in subviews { //to avoid layer cyclic crash, when it is a topmost view, adding all its subviews in textfield's layer, TODO: Find a better logic.
                subview.makeSecureTextField()
            }
            return
        }
        
        DispatchQueue.main.async {
            let field = UITextField()
            field.isSecureTextEntry = true
            field.tag = Constant.textFieldTag.num
            self.addSubview(field)
            field.centerYAnchor.constraint(equalTo: self.centerYAnchor).isActive = true
            field.centerXAnchor.constraint(equalTo: self.centerXAnchor).isActive = true
            self.layer.superlayer?.addSublayer(field.layer)
            field.layer.sublayers?.first?.addSublayer(self.layer)
        }
    }
    
    // Remove added layer to the screen
    func removeSecureTextField() {
        if let guardView = subviews.first(where: { $0.tag == Constant.textFieldTag.num }) {
            guardView.removeFromSuperview()
        }
    }
}

@MainActor
public class ViewProtection {
    
    public static let shared = ViewProtection()
    
    private init() {}
    
    public func makeProtection(`for` view: UIView) {
        view.makeSecureTextField()
    }
    
    public func removeScreenProtection(`for` view: UIView) {
        view.removeSecureTextField()
    }
}
