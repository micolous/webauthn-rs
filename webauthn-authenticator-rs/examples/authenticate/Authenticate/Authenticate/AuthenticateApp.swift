//
//  AuthenticateApp.swift
//  Authenticate
//
//  Created by Eric M Martin on 1/15/23.
//

import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let task = Process()
        task.launchPath = Bundle.main.path(forResource: "authenticate", ofType: nil)
        task.environment = [
            "RUST_LOG": "trace"
        ]
        task.launch()
        task.waitUntilExit()
    }
}

@main
struct AuthenticateApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

