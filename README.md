# KeychainStore

A keychain wrapper for iOS, macOS, tvOS, visionOS and watchOS. Beyond get/set it covers the
parts other libraries leave out: sync-safe identity, biometric items with real errors, changes
across processes, Secure Enclave keys, migrations, and a test backend.

```swift
import KeychainStore

let keychain = KeychainStore(service: "com.example.app")
try keychain.set("s3cr3t", for: "apiKey")
let apiKey = try keychain.string(for: "apiKey")
```

## What's different

| | KeychainStore |
| --- | --- |
| **Sync-safe identity** | Each key is exactly one item, whether or not it syncs through iCloud Keychain. Reads find synced and local items alike, and switching modes replaces the item. Most wrappers leave a hidden duplicate or can't find synced items. |
| **Correct on macOS** | Uses the data protection keychain (`kSecUseDataProtectionKeychain`), which behaves like iOS. The legacy file keychain is available for unsigned tools. `errSecMissingEntitlement` explains itself. |
| **Biometrics done properly** | `AuthenticationPolicy` mirrors `SecAccessControlCreateFlags`. `AuthenticationPrompt` sets the reason, fallback title and Touch ID reuse window. Errors are typed: `.userCanceled`, `.authenticationFailed`, `.interactionNotAllowed`. `async` reads keep prompts off the main actor. `contains` and `requiresAuthentication` never prompt. |
| **Changes across processes** | `changes(for:)` fires when a value changes in this process or another one sharing the access group, such as a widget, share extension or notification service extension. It uses Darwin notifications. |
| **SwiftUI** | `@KeychainStorage("token") var token: String?` works like `@AppStorage`. `KeychainItem<Value>` is an `@Observable` that stays current. |
| **Server logins** | `CredentialStore` saves internet passwords keyed by server and account, for apps that sign in to several self-hosted servers. It searches by host alone or by exact port, scheme and path. |
| **Migrations** | `migrate(from:)` moves items to a shared access group, into or out of iCloud Keychain, or to a new service name. It's idempotent and safe to run on every launch, and never deletes before writing. |
| **Secure Enclave** | `SecureEnclaveKeys` creates or loads P-256 signing and key-agreement keys by name, optionally requiring biometry to use them. |
| **Testable** | `InMemoryKeychain` has the same identity and sync semantics and can simulate canceled prompts. Swap it in for unit tests and previews. |
| **Typed** | Typed throws (`throws(KeychainError)`), `KeychainKey<Value>`, and Codable values stored as JSON. Strings and data are stored as raw bytes, so they interoperate with other libraries. |

## Usage

### Values

```swift
extension KeychainKey where Value == Session {
    static let session = KeychainKey("session", options: .background) // readable after first unlock
}

try keychain.set(session, for: .session)
let session = try keychain.value(for: .session)
try keychain.set(nil, for: .session) // removes it
```

### Biometric items

```swift
try keychain.set(privateNote, for: "note", options: .biometric) // current Face ID / Touch ID set, this device only

do {
    let note = try await keychain.string(for: "note", prompt: AuthenticationPrompt("Unlock your note"))
} catch .userCanceled {
    // not an error worth showing
}
```

Pass an `LAContext` you've already evaluated to `data(for:context:)` to read several items
with one prompt.

### SwiftUI

```swift
struct SettingsView: View {
    @KeychainStorage("apiKey") private var apiKey: String?

    var body: some View {
        SecureField("API Key", text: Binding($apiKey, default: ""))
    }
}
```

### Sharing with extensions

```swift
let shared = KeychainStore(service: "com.example.app", accessGroup: "TEAMID.com.example.shared")
try shared.migrate(from: KeychainStore(service: "com.example.app")) // once, safe every launch

for await _ in shared.changes(for: "session") {
    reloadSession() // fires when the app or an extension writes it
}
```

### Server logins

```swift
let logins = CredentialStore()
let server = InternetServer(url: URL(string: "https://media.example.com:8920")!)!
try logins.save(Credential(server: server, username: "dan", password: password))

let accounts = try logins.usernames(for: InternetServer(host: "media.example.com")) // any port or scheme
```

### Secure Enclave

```swift
let keys = SecureEnclaveKeys(store: keychain)
let identity = try keys.signingKey("device", authentication: .biometryCurrentSet)
let signature = try identity.signature(for: challenge)
```

### Tests and previews

```swift
let keychain = KeychainStore(service: "test", backend: InMemoryKeychain())
```

## Installation

```swift
.package(url: "https://github.com/CreatureSurvive/KeychainStore.git", from: "1.0.0")
```

Requires Swift 6 and iOS 17, macOS 14, tvOS 17, visionOS 1 or watchOS 10.

## Testing

- **`swift test`:** runs the suite against `InMemoryKeychain`, plus Secure Enclave key creation
  and use on Macs that have one.
- **Real keychain:** the system keychain needs a signed app with a keychain access group, so
  `Example/` has a host app that runs the same test file against the real data protection
  keychain on the iOS simulator:

  ```sh
  cd Example && xcodegen generate
  xcodebuild test -project KeychainHost.xcodeproj -scheme KeychainHost \
    -destination "platform=iOS Simulator,name=iPhone 16"
  ```

  In that run every backend-dependent test executes twice, once per backend.

## Limitations

- An item's access control can't be read back from the keychain. `migrate(from:options:)` takes
  the options to apply, and protected items that can't be read without a prompt are reported
  and left in place.
- Changes arriving through iCloud Keychain sync post no notification. Re-read when the app
  becomes active if that matters.
- On macOS the data protection keychain requires a signed app. Unsigned command-line tools
  should use `SystemKeychain(legacyMacOSKeychain: true)` or `InMemoryKeychain`.
- There's no authentication on tvOS, because Apple TV has no passcode or biometry. Secure
  Enclave keys aren't available on tvOS.

## License

MIT
