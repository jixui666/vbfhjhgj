//
//  isunsupported.swift
//  lara
//
//  Created by ruter on 30.03.26.
//

import UIKit
import Darwin

func devicemachine() -> String {
    var sysinfo = utsname()
    uname(&sysinfo)

    let mirror = Mirror(reflecting: sysinfo.machine)
    return mirror.children.reduce("") { identifier, element in
        guard let value = element.value as? Int8, value != 0 else { return identifier }
        return identifier + String(UnicodeScalar(UInt8(value)))
    }
}

func hasmie() -> Bool {
    let machine = devicemachine()
    
    if machine.contains("iPhone18,") {
        return true
    }
    
    return false
}

func isunsupported() -> Bool {
    let v = ProcessInfo.processInfo.operatingSystemVersion
    
    // Business build: iOS 26 only. The legacy exploit chain
    // (kfd/badRecovery/dmaFail/multicast_bytecopy/weightBufs/libjailbreak/
    // libchoma) has been removed from Frameworks/, so anything outside
    // iOS 26.x is unsupported.
    if v.majorVersion != 26 {
        return true
    }
    
    if hasmie() {
        return true
    }
    
    if isdebugged() {
        return true
    }
    
    return false
}
