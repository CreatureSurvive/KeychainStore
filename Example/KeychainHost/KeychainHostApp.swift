import KeychainStore
import SwiftUI

/// Hosts the package tests so they run against the real data protection
/// keychain, which needs a signed app with a keychain access group.
@main
struct KeychainHostApp: App {
    var body: some Scene {
        WindowGroup {
            DemoView()
        }
    }
}

struct DemoView: View {
    @KeychainStorage("demo.apiKey", store: KeychainStore(service: "KeychainHost.demo")) private var apiKey: String?

    var body: some View {
        Form {
            SecureField("API Key", text: Binding($apiKey, default: ""))
            LabeledContent("Stored", value: apiKey == nil ? "No" : "Yes")
        }
        .padding()
    }
}
