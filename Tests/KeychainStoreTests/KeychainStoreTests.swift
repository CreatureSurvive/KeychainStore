import Foundation
import LocalAuthentication
import Testing
@testable import KeychainStore

/// Backends under test. The system keychain runs wherever the process may
/// use it (the iOS simulator, signed macOS hosts); elsewhere it's skipped.
enum BackendKind: String, CaseIterable, CustomTestStringConvertible, Sendable {
    case memory
    case system

    var testDescription: String { rawValue }

    /// The system keychain needs a signed host app with a keychain access
    /// group (see Example/); plain `swift test` runs only the in-memory backend.
    static let systemAvailable = Bundle.main.bundleIdentifier == "com.creaturesurvive.KeychainHost"

    static var available: [BackendKind] {
        systemAvailable ? [.memory, .system] : [.memory]
    }

    func makeBackend() -> any KeychainBackend {
        switch self {
        case .memory: InMemoryKeychain()
        case .system: SystemKeychain()
        }
    }

    /// A store with a unique service, removed when the test ends.
    func withStore<T>(synchronizable: Bool = false, _ body: (KeychainStore) throws -> T) throws -> T {
        let store = KeychainStore(service: "KeychainStoreTests.\(UUID().uuidString)", synchronizable: synchronizable, backend: makeBackend())
        defer {
            try? store.removeAll()
            try? store.with(synchronizable: !synchronizable).removeAll()
        }
        return try body(store)
    }
}

struct Profile: Codable, Equatable, Sendable {
    var name: String
    var servers: [URL]
}

extension KeychainKey where Value == Profile {
    static let profile = KeychainKey("profile")
}

@Suite("KeychainStore")
struct KeychainStoreTests {
    @Test(arguments: BackendKind.available)
    func roundTripsDataStringsAndCodables(_ kind: BackendKind) throws {
        try kind.withStore { store in
            #expect(try store.data(for: "missing") == nil)
            #expect(try store.string(for: "missing") == nil)

            try store.set(Data([0, 1, 2, 255]), for: "bytes")
            #expect(try store.data(for: "bytes") == Data([0, 1, 2, 255]))

            try store.set("pässwörd 🔑", for: "password")
            #expect(try store.string(for: "password") == "pässwörd 🔑")

            let profile = Profile(name: "Dan", servers: [URL(string: "https://jellyfin.local:8096")!])
            try store.set(profile, for: "profile")
            #expect(try store.value(Profile.self, for: "profile") == profile)
        }
    }

    @Test(arguments: BackendKind.available)
    func stringsAreStoredAsRawUTF8ForInterop(_ kind: BackendKind) throws {
        try kind.withStore { store in
            try store.set("token", for: "a")
            #expect(try store.data(for: "a") == Data("token".utf8))
            try store.set(Data("raw".utf8), for: "b")
            #expect(try store.value(String.self, for: "b") == "raw")
        }
    }

    @Test(arguments: BackendKind.available)
    func overwritingReplacesTheValueAndKeepsOneItem(_ kind: BackendKind) throws {
        try kind.withStore { store in
            try store.set("one", for: "key", options: ItemOptions(label: "Label"))
            let first = try #require(try store.attributes(for: "key"))
            try store.set("two", for: "key")
            #expect(try store.string(for: "key") == "two")
            #expect(try store.allKeys() == ["key"])
            let second = try #require(try store.attributes(for: "key"))
            #expect(second.label == "Label", "an update without a label keeps the old one")
            #expect(second.creationDate == first.creationDate)
        }
    }

    @Test(arguments: BackendKind.available)
    func removeAndRemoveAllAreScopedToTheService(_ kind: BackendKind) throws {
        try kind.withStore { store in
            let other = store.with(service: store.service + ".other")
            defer { try? other.removeAll() }
            try store.set("1", for: "b")
            try store.set("2", for: "a")
            try other.set("3", for: "a")
            #expect(try store.allKeys() == ["a", "b"])
            #expect(try store.contains("a"))

            try store.remove("a")
            try store.remove("a") // removing twice is fine
            #expect(try !store.contains("a"))
            #expect(try other.string(for: "a") == "3")

            try store.removeAll()
            #expect(try store.allKeys().isEmpty)
            #expect(try other.allKeys() == ["a"])
        }
    }

    @Test(arguments: BackendKind.available)
    func typedKeys(_ kind: BackendKind) throws {
        try kind.withStore { store in
            let profile = Profile(name: "A", servers: [])
            try store.set(profile, for: .profile)
            #expect(try store.value(for: .profile) == profile)
            try store.set(nil, for: .profile)
            #expect(try store.value(for: .profile) == nil)
        }
    }

    @Test(arguments: BackendKind.available)
    func switchingSyncModeKeepsExactlyOneItem(_ kind: BackendKind) throws {
        try kind.withStore { local in
            let synced = local.with(synchronizable: true)
            try local.set("local", for: "key")
            try synced.set("synced", for: "key")
            let all = try local.allAttributes()
            #expect(all.count == 1)
            #expect(all.first?.synchronizable == true)
            #expect(try local.string(for: "key") == "synced", "reads match items in either sync state")

            try local.set("local again", for: "key")
            #expect(try synced.allAttributes().map(\.synchronizable) == [false])
        }
    }

    @Test(arguments: BackendKind.available)
    func rejectsSyncedItemsThatCantSync(_ kind: BackendKind) throws {
        try kind.withStore(synchronizable: true) { store throws in
            #expect(throws: KeychainError.self) {
                try store.set("x", for: "a", options: ItemOptions(authentication: .biometryAny))
            }
            #expect(throws: KeychainError.self) {
                try store.set("x", for: "a", options: ItemOptions(thisDeviceOnly: true))
            }
            #expect(throws: KeychainError.self) {
                try store.set("x", for: "a", options: ItemOptions(accessibility: .whenPasscodeSet))
            }
            #expect(try store.allKeys().isEmpty)
        }
    }

    @Test(arguments: BackendKind.available)
    func accessibilityIsReportedBack(_ kind: BackendKind) throws {
        try kind.withStore { store in
            try store.set("x", for: "bg", options: .background)
            #expect(try store.attributes(for: "bg")?.accessibility == .afterFirstUnlock)
            try store.set("x", for: "bg", options: ItemOptions(accessibility: .whenUnlocked))
            #expect(try store.attributes(for: "bg")?.accessibility == .whenUnlocked)
        }
    }

    @Test(arguments: BackendKind.available)
    func decodingErrorsNameTheKey(_ kind: BackendKind) throws {
        try kind.withStore { store in
            try store.set(Data([0xFF, 0xFE]), for: "binary")
            #expect(throws: KeychainError.self) { try store.string(for: "binary") }
            do {
                _ = try store.value(Profile.self, for: "binary")
                Issue.record("expected a decoding error")
            } catch {
                guard case .decodingFailed(let message)? = error as? KeychainError else { Issue.record("wrong error \(error)"); return }
                #expect(message.contains("binary"))
            }
        }
    }

    @Test(arguments: BackendKind.available)
    func concurrentWritesAreSafe(_ kind: BackendKind) async throws {
        let backend = kind.makeBackend()
        let store = KeychainStore(service: "KeychainStoreTests.\(UUID().uuidString)", backend: backend)
        defer { try? store.removeAll() }
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<40 {
                group.addTask { try? store.set("\(i)", for: "key\(i % 8)") }
            }
        }
        #expect(try store.allKeys().count == 8)
    }

    @Test(arguments: BackendKind.available)
    func asyncReadsWork(_ kind: BackendKind) async throws {
        let store = KeychainStore(service: "KeychainStoreTests.\(UUID().uuidString)", backend: kind.makeBackend())
        defer { try? store.removeAll() }
        try store.set(Profile(name: "x", servers: []), for: "p")
        let value = try await store.value(Profile.self, for: "p")
        #expect(value?.name == "x")
        let string: String? = try await store.string(for: "missing")
        #expect(string == nil)
    }
}

@Suite("Authentication")
struct AuthenticationTests {
    @Test func protectedItemsReportTheirErrors() throws {
        let memory = InMemoryKeychain()
        let store = KeychainStore(service: "auth", backend: memory)
        try store.set("secret", for: "vault", options: .biometric)
        try store.set("plain", for: "open")

        #expect(try store.requiresAuthentication("vault"))
        #expect(try !store.requiresAuthentication("open"))
        #expect(try !store.requiresAuthentication("missing"))
        #expect(try store.contains("vault"), "existence checks never prompt")

        memory.requireAuthenticationError = .userCanceled
        #expect(throws: KeychainError.userCanceled) { try store.string(for: "vault", prompt: AuthenticationPrompt("Unlock")) }
        #expect(try store.string(for: "open") == "plain")

        memory.requireAuthenticationError = nil
        #expect(try store.string(for: "vault", prompt: AuthenticationPrompt("Unlock")) == "secret")
    }

    @Test func promptConfiguresTheContext() {
        let context = AuthenticationPrompt("Sign in to Jellyfin", fallbackTitle: "", reuseDuration: 9999).makeContext()
        #expect(context.localizedReason == "Sign in to Jellyfin")
        #expect(context.localizedFallbackTitle == "")
        #if !os(tvOS) && !os(watchOS)
        #expect(context.touchIDAuthenticationAllowableReuseDuration == LATouchIDAuthenticationMaximumAllowableReuseDuration)
        #endif
    }

    @Test func policiesMapToAccessControlFlags() throws {
        #expect(AuthenticationPolicy([.biometryAny, .or, .devicePasscode]).flags == [.biometryAny, .or, .devicePasscode])
        #expect(try ItemOptions(authentication: .userPresence).accessControl() != nil)
        #expect(try ItemOptions().accessControl() == nil)
    }
}

@Suite("Errors")
struct ErrorTests {
    @Test func mapsStatusCodes() {
        #expect(KeychainError(status: errSecUserCanceled) == .userCanceled)
        #expect(KeychainError(status: errSecAuthFailed) == .authenticationFailed)
        #expect(KeychainError(status: errSecInteractionNotAllowed) == .interactionNotAllowed)
        #expect(KeychainError(status: -34018) == .missingEntitlement)
        #expect(KeychainError(status: errSecDuplicateItem) == .duplicateItem)
        #expect(KeychainError(status: errSecParam) == .unhandled(errSecParam))
        #expect(KeychainError.missingEntitlement.status == -34018)
    }

    @Test func descriptionsAreHelpful() {
        #expect(KeychainError.missingEntitlement.localizedDescription.contains("entitlement"))
        #expect(KeychainError.unhandled(errSecParam).localizedDescription.contains("-50"))
    }
}

@Suite("Credentials")
struct CredentialTests {
    @Test(arguments: BackendKind.available)
    func savesAndFindsServerLogins(_ kind: BackendKind) throws {
        let credentials = CredentialStore(backend: kind.makeBackend())
        let host = "keychainstore-\(UUID().uuidString.prefix(8)).example".lowercased()
        let lan = InternetServer(host: host, port: 8096, scheme: "http")
        let tls = InternetServer(host: host, port: 8920, scheme: "https")
        defer { try? credentials.remove(on: InternetServer(host: host)) }

        try credentials.save(Credential(server: lan, username: "dan", password: "one"))
        try credentials.save(Credential(server: tls, username: "dan", password: "two"))
        try credentials.save(Credential(server: tls, username: "kid", password: "three"))
        try credentials.save(Credential(server: tls, username: "kid", password: "four"))

        #expect(try credentials.password(for: "dan", on: lan) == "one")
        #expect(try credentials.password(for: "kid", on: tls) == "four")
        #expect(try credentials.usernames(for: tls) == ["dan", "kid"])
        #expect(try credentials.usernames(for: InternetServer(host: host)).count == 3)

        let all = try credentials.credentials(for: InternetServer(host: host))
        #expect(Set(all.map { "\($0.username)@\($0.server.port ?? 0)=\($0.password)" }) == ["dan@8096=one", "dan@8920=two", "kid@8920=four"])
        #expect(all.allSatisfy { $0.server.scheme != nil }, "results carry the exact server")

        try credentials.remove(username: "dan", on: tls)
        #expect(try credentials.usernames(for: tls) == ["kid"])
        try credentials.remove(on: InternetServer(host: host))
        #expect(try credentials.usernames(for: InternetServer(host: host)).isEmpty)
    }

    @Test func serverFromURL() throws {
        let server = try #require(InternetServer(url: URL(string: "https://Media.Example.com:8920/jellyfin")!))
        #expect(server == InternetServer(host: "media.example.com", port: 8920, scheme: "https", path: "/jellyfin"))
        #expect(InternetServer(url: URL(string: "http://nas.local/")!)?.path == nil)
        #expect(InternetServer(url: URL(string: "file:///tmp")!) == nil)
        #expect(SystemKeychain.scheme(forProtocol: SystemKeychain.protocolAttribute(for: "https") as String) == "https")
    }
}

@Suite("Migration")
struct MigrationTests {
    @Test(arguments: BackendKind.available)
    func movesItemsBetweenServices(_ kind: BackendKind) throws {
        try kind.withStore { old in
            let new = old.with(service: old.service + ".new")
            defer { try? new.removeAll() }
            try old.set("a", for: "one", options: ItemOptions(label: "One"))
            try old.set("b", for: "two", options: .background)
            try new.set("existing", for: "two")

            let report = try new.migrate(from: old)
            #expect(report.migrated == ["one"])
            #expect(report.skipped == ["two"])
            #expect(try new.string(for: "one") == "a")
            #expect(try new.attributes(for: "one")?.label == "One")
            #expect(try new.string(for: "two") == "existing")
            #expect(try old.allKeys() == ["two"], "skipped items stay in the source")

            let again = try new.migrate(from: old, overwrite: true)
            #expect(again.migrated == ["two"])
            #expect(try new.string(for: "two") == "b")
            #expect(try new.attributes(for: "two")?.accessibility == .afterFirstUnlock)
            #expect(try old.allKeys().isEmpty)
            #expect(try new.migrate(from: old) == MigrationReport(), "idempotent")
        }
    }

    @Test(arguments: BackendKind.available)
    func movesItemsIntoICloudKeychain(_ kind: BackendKind) throws {
        try kind.withStore { local in
            let synced = local.with(synchronizable: true)
            try local.set("x", for: "token")
            let report = try synced.migrate(from: local)
            #expect(report.migrated == ["token"])
            #expect(try synced.attributes(for: "token")?.synchronizable == true)
            #expect(try local.allAttributes().count == 1)
        }
    }

    @Test func leavesProtectedItemsInPlace() throws {
        let memory = InMemoryKeychain()
        let old = KeychainStore(service: "old", backend: memory)
        let new = KeychainStore(service: "new", backend: memory)
        try old.set("secret", for: "vault", options: .biometric)
        try old.set("plain", for: "open")
        let report = try new.migrate(from: old)
        #expect(report.migrated == ["open"])
        #expect(report.protected == ["vault"])
        #expect(try old.allKeys() == ["vault"])
    }
}

@Suite("Changes", .timeLimit(.minutes(1)))
struct ChangeTests {
    @Test(arguments: BackendKind.available)
    func deliversChangesAcrossStoreInstances(_ kind: BackendKind) async throws {
        let backend = kind.makeBackend()
        let service = "KeychainStoreTests.\(UUID().uuidString)"
        let writer = KeychainStore(service: service, backend: backend)
        let reader = KeychainStore(service: service, backend: backend)
        defer { try? writer.removeAll() }

        var keyChanges = reader.changes(for: "watched").makeAsyncIterator()
        var anyChanges = reader.changes().makeAsyncIterator()
        try await Task.sleep(for: .milliseconds(50)) // let the registrations land

        try writer.set("1", for: "watched")
        #expect(await keyChanges.next() != nil)
        #expect(await anyChanges.next() != nil)

        try writer.set("2", for: "other")
        #expect(await anyChanges.next() != nil)

        try writer.removeAll()
        #expect(await keyChanges.next() != nil, "clearing the store notifies key observers")
    }

    @Test func otherKeysDontWakeKeyObservers() async throws {
        let store = KeychainStore(service: "changes.\(UUID().uuidString)", backend: InMemoryKeychain())
        let received = Counter()
        let task = Task {
            for await _ in store.changes(for: "a") { received.increment() }
        }
        try await Task.sleep(for: .milliseconds(50))
        try store.set("x", for: "b")
        try store.set("y", for: "c")
        try await Task.sleep(for: .milliseconds(200))
        #expect(received.value == 0)
        try store.set("z", for: "a")
        while received.value == 0 { try await Task.sleep(for: .milliseconds(10)) }
        task.cancel()
    }

    @Test func separateInMemoryKeychainsDontShareNotifications() async throws {
        let one = KeychainStore(service: "same", backend: InMemoryKeychain())
        let two = KeychainStore(service: "same", backend: InMemoryKeychain())
        let received = Counter()
        let task = Task { for await _ in two.changes() { received.increment() } }
        try await Task.sleep(for: .milliseconds(50))
        try one.set("x", for: "a")
        try await Task.sleep(for: .milliseconds(200))
        #expect(received.value == 0)
        task.cancel()
    }

    @MainActor
    @Test func keychainItemFollowsTheStore() async throws {
        let store = KeychainStore(service: "item.\(UUID().uuidString)", backend: InMemoryKeychain())
        try store.set("initial", for: "token")
        let item = KeychainItem<String>("token", store: store)
        #expect(item.value == "initial")

        try store.set("changed elsewhere", for: "token")
        while item.value != "changed elsewhere" { try await Task.sleep(for: .milliseconds(10)) }

        try item.set("from item")
        #expect(try await store.string(for: "token") == "from item")
        try item.remove()
        #expect(item.value == nil)
        #expect(try !store.contains("token"))
    }

    @MainActor
    @Test func protectedKeychainItemsLoadOnDemand() async throws {
        let memory = InMemoryKeychain()
        let store = KeychainStore(service: "item.\(UUID().uuidString)", backend: memory)
        try store.set("secret", for: "vault", options: .biometric)
        let item = KeychainItem<String>("vault", store: store, options: .biometric)
        #expect(item.value == nil, "loading would prompt, so it waits for load()")
        memory.requireAuthenticationError = .userCanceled
        #expect(await item.load(prompt: AuthenticationPrompt("Unlock")) == nil)
        #expect(item.error == .userCanceled)
        memory.requireAuthenticationError = nil
        #expect(await item.load(prompt: AuthenticationPrompt("Unlock")) == "secret")
        #expect(item.error == nil)
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.withLock { count += 1 } }
    var value: Int { lock.withLock { count } }
}

#if !os(tvOS)
import CryptoKit

@Suite("Secure Enclave")
struct SecureEnclaveTests {
    @Test(.enabled(if: SecureEnclaveKeys.isAvailable))
    func createsAndReloadsKeysByName() throws {
        let keys = SecureEnclaveKeys(store: KeychainStore(service: "se", backend: InMemoryKeychain()))
        #expect(try !keys.containsKey("identity"))
        let key = try keys.signingKey("identity", accessibility: .afterFirstUnlock)
        #expect(try keys.containsKey("identity"))

        let reloaded = try keys.signingKey("identity")
        #expect(reloaded.publicKey.rawRepresentation == key.publicKey.rawRepresentation)

        let message = Data("challenge".utf8)
        let signature = try reloaded.signature(for: message)
        #expect(key.publicKey.isValidSignature(signature, for: message))

        let agreement = try keys.keyAgreementKey("exchange", accessibility: .afterFirstUnlock)
        let peer = P256.KeyAgreement.PrivateKey()
        let shared = try agreement.sharedSecretFromKeyAgreement(with: peer.publicKey)
        let peerShared = try peer.sharedSecretFromKeyAgreement(with: agreement.publicKey)
        #expect(shared == peerShared)

        try keys.removeKey("identity")
        #expect(try !keys.containsKey("identity"))
        let replacement = try keys.signingKey("identity", accessibility: .afterFirstUnlock)
        #expect(replacement.publicKey.rawRepresentation != key.publicKey.rawRepresentation)
    }

    @Test(.enabled(if: !SecureEnclaveKeys.isAvailable))
    func reportsUnavailability() {
        let keys = SecureEnclaveKeys(store: KeychainStore(service: "se", backend: InMemoryKeychain()))
        #expect(throws: KeychainError.self) { try keys.signingKey("x") }
    }

    @Test func handlesAreNeverSynced() {
        let keys = SecureEnclaveKeys(store: KeychainStore(service: "se", synchronizable: true, backend: InMemoryKeychain()))
        #expect(!keys.store.synchronizable)
    }
}
#endif
