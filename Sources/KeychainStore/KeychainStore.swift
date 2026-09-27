import Foundation
import Security
#if canImport(LocalAuthentication) && !os(tvOS)
import LocalAuthentication
#endif

/// A typed key for a value stored in a ``KeychainStore``.
///
/// ```swift
/// extension KeychainKey where Value == String {
///     static let accessToken = KeychainKey("accessToken")
/// }
///
/// try store.set("abc", for: .accessToken)
/// let token = try store.value(for: .accessToken)
/// ```
public struct KeychainKey<Value: Codable & Sendable>: Sendable, Hashable {
    public let name: String
    public let options: ItemOptions

    public init(_ name: String, options: ItemOptions = ItemOptions()) {
        self.name = name
        self.options = options
    }
}

/// A prompt shown when reading an item that requires authentication.
public struct AuthenticationPrompt: Sendable, Hashable {
    /// Why the app needs access, shown in the Face ID / Touch ID / passcode prompt.
    public var reason: String
    /// The title of the fallback button (for example "Enter Password"), or
    /// `nil` for the system default. An empty string hides the button.
    public var fallbackTitle: String?
    /// How long a successful Touch ID / Face ID unlock of the device can be
    /// reused instead of prompting again, up to five minutes.
    public var reuseDuration: TimeInterval

    public init(_ reason: String, fallbackTitle: String? = nil, reuseDuration: TimeInterval = 0) {
        self.reason = reason
        self.fallbackTitle = fallbackTitle
        self.reuseDuration = reuseDuration
    }

    func makeContext() -> AuthenticationContext {
        let context = AuthenticationContext()
        #if !os(tvOS)
        context.localizedReason = reason
        if let fallbackTitle { context.localizedFallbackTitle = fallbackTitle }
        #if !os(watchOS)
        context.touchIDAuthenticationAllowableReuseDuration = min(reuseDuration, LATouchIDAuthenticationMaximumAllowableReuseDuration)
        #endif
        #endif
        return context
    }
}

/// A keychain-backed key-value store for secrets.
///
/// ```swift
/// let keychain = KeychainStore(service: "com.example.app")
/// try keychain.set("hunter2", for: "password")
/// let password = try keychain.string(for: "password")
/// ```
///
/// Each key maps to exactly one generic password item, whether or not the
/// store synchronizes through iCloud Keychain. The store is thread safe
/// and posts ``changes(for:)`` notifications, which also reach other
/// processes sharing the access group, such as app extensions.
///
/// Reads of items that require authentication block while the system
/// prompt is on screen. Use the `async` overloads for those, or call from
/// a background thread.
public struct KeychainStore: Sendable {
    /// The service name that scopes this store's items.
    public let service: String
    /// The keychain access group, or `nil` for the app's default group.
    public let accessGroup: String?
    /// Whether new values sync through iCloud Keychain.
    public let synchronizable: Bool
    /// The storage backend.
    public let backend: any KeychainBackend

    /// Creates a store.
    ///
    /// - Parameters:
    ///   - service: Scopes the items. Defaults to the main bundle identifier.
    ///   - accessGroup: A shared keychain access group (with the team ID
    ///     prefix) to share items with extensions or other apps.
    ///   - synchronizable: Whether values sync through iCloud Keychain.
    ///   - backend: ``SystemKeychain`` by default. Pass ``InMemoryKeychain``
    ///     in tests and previews.
    public init(
        service: String = Bundle.main.bundleIdentifier ?? "KeychainStore",
        accessGroup: String? = nil,
        synchronizable: Bool = false,
        backend: any KeychainBackend = SystemKeychain()
    ) {
        self.service = service
        self.accessGroup = accessGroup
        self.synchronizable = synchronizable
        self.backend = backend
    }

    /// A store with the same backend but different settings.
    public func with(service: String? = nil, accessGroup: String?? = nil, synchronizable: Bool? = nil) -> KeychainStore {
        KeychainStore(
            service: service ?? self.service,
            accessGroup: accessGroup ?? self.accessGroup,
            synchronizable: synchronizable ?? self.synchronizable,
            backend: backend
        )
    }

    // MARK: - Data

    /// Returns the data stored for `key`, or `nil` if there is none.
    ///
    /// If the item requires authentication, the system prompt is shown. The
    /// call blocks until the user responds; prefer the `async` overload.
    public func data(for key: String, prompt: AuthenticationPrompt? = nil) throws(KeychainError) -> Data? {
        try backend.read(query(key), context: prompt?.makeContext())
    }

    /// Returns the data stored for `key`, authenticating with `context`.
    ///
    /// Pass a context you've already evaluated to read several protected
    /// items with one prompt, or set `interactionNotAllowed` to fail instead
    /// of prompting.
    public func data(for key: String, context: AuthenticationContext) throws(KeychainError) -> Data? {
        try backend.read(query(key), context: context)
    }

    /// Reads data off the calling thread, so a biometric prompt doesn't
    /// block the main actor.
    public func data(for key: String, prompt: AuthenticationPrompt? = nil) async throws(KeychainError) -> Data? {
        let store = self
        return try await offMainThread { () throws(KeychainError) -> Data? in
            try store.data(for: key, prompt: prompt)
        }
    }

    /// Stores data for `key`, replacing any existing value.
    public func set(_ data: Data, for key: String, options: ItemOptions = ItemOptions()) throws(KeychainError) {
        try backend.write(data, to: query(key), synchronizable: synchronizable, options: options)
        notifyChange(key)
    }

    // MARK: - Strings

    public func string(for key: String, prompt: AuthenticationPrompt? = nil) throws(KeychainError) -> String? {
        guard let data = try data(for: key, prompt: prompt) else { return nil }
        guard let string = String(data: data, encoding: .utf8) else { throw .decodingFailed("the data for \"\(key)\" isn't UTF-8") }
        return string
    }

    public func string(for key: String, prompt: AuthenticationPrompt? = nil) async throws(KeychainError) -> String? {
        guard let data = try await data(for: key, prompt: prompt) else { return nil }
        guard let string = String(data: data, encoding: .utf8) else { throw .decodingFailed("the data for \"\(key)\" isn't UTF-8") }
        return string
    }

    public func set(_ string: String, for key: String, options: ItemOptions = ItemOptions()) throws(KeychainError) {
        try set(Data(string.utf8), for: key, options: options)
    }

    // MARK: - Codable

    /// Returns the value stored for `key`, decoded as `type`.
    ///
    /// Strings and data are stored as raw bytes, compatible with other
    /// keychain libraries. Other values are stored as JSON.
    public func value<Value: Decodable>(_ type: Value.Type, for key: String, prompt: AuthenticationPrompt? = nil) throws(KeychainError) -> Value? {
        guard let data = try data(for: key, prompt: prompt) else { return nil }
        return try ValueCoding.decode(type, from: data, key: key)
    }

    public func value<Value: Decodable & Sendable>(_ type: Value.Type, for key: String, prompt: AuthenticationPrompt? = nil) async throws(KeychainError) -> Value? {
        guard let data = try await data(for: key, prompt: prompt) else { return nil }
        return try ValueCoding.decode(type, from: data, key: key)
    }

    public func set<Value: Encodable>(_ value: Value, for key: String, options: ItemOptions = ItemOptions()) throws(KeychainError) {
        try set(try ValueCoding.encode(value), for: key, options: options)
    }

    // MARK: - Typed keys

    public func value<Value>(for key: KeychainKey<Value>, prompt: AuthenticationPrompt? = nil) throws(KeychainError) -> Value? {
        try value(Value.self, for: key.name, prompt: prompt)
    }

    public func value<Value>(for key: KeychainKey<Value>, prompt: AuthenticationPrompt? = nil) async throws(KeychainError) -> Value? {
        try await value(Value.self, for: key.name, prompt: prompt)
    }

    /// Stores `value` with the key's options, or removes the item when `value` is `nil`.
    public func set<Value>(_ value: Value?, for key: KeychainKey<Value>) throws(KeychainError) {
        if let value {
            try set(value, for: key.name, options: key.options)
        } else {
            try remove(key.name)
        }
    }

    // MARK: - Management

    /// Whether an item exists for `key`. Never prompts, even for protected items.
    public func contains(_ key: String) throws(KeychainError) -> Bool {
        try !backend.attributes(query(key)).isEmpty
    }

    /// Whether reading `key` requires user authentication. Never prompts.
    ///
    /// Returns `false` if there's no item. A locked device also reports
    /// items as needing interaction, so check while unlocked.
    public func requiresAuthentication(_ key: String) throws(KeychainError) -> Bool {
        guard try contains(key) else { return false }
        let context = AuthenticationContext()
        context.interactionNotAllowed = true
        do {
            _ = try backend.read(query(key), context: context)
            return false
        } catch .interactionNotAllowed {
            return true
        }
    }

    /// Metadata for `key`, or `nil` if there's no item. Never prompts.
    public func attributes(for key: String) throws(KeychainError) -> ItemAttributes? {
        try backend.attributes(query(key)).first
    }

    /// Metadata for every item in the store, sorted by key. Never prompts.
    public func allAttributes() throws(KeychainError) -> [ItemAttributes] {
        try backend.attributes(query(nil))
    }

    /// Every key in the store, sorted.
    public func allKeys() throws(KeychainError) -> [String] {
        try allAttributes().map(\.key)
    }

    /// Removes the item for `key`. Removing a missing item isn't an error.
    public func remove(_ key: String) throws(KeychainError) {
        try backend.delete(query(key))
        notifyChange(key)
    }

    /// Removes every item in the store (this service and access group only).
    public func removeAll() throws(KeychainError) {
        try backend.delete(query(nil))
        notifyChange(nil)
    }

    // MARK: - Internals

    func query(_ key: String?) -> ItemQuery {
        ItemQuery(itemClass: .genericPassword(service: service), accessGroup: accessGroup, account: key)
    }
}

enum ValueCoding {
    static func encode<Value: Encodable>(_ value: Value) throws(KeychainError) -> Data {
        switch value {
        case let data as Data: return data
        case let string as String: return Data(string.utf8)
        default:
            do {
                return try JSONEncoder().encode(value)
            } catch {
                throw .encodingFailed(String(describing: error))
            }
        }
    }

    static func decode<Value: Decodable>(_ type: Value.Type, from data: Data, key: String) throws(KeychainError) -> Value {
        if type == Data.self, let value = data as? Value { return value }
        if type == String.self {
            guard let string = String(data: data, encoding: .utf8), let value = string as? Value else {
                throw .decodingFailed("the data for \"\(key)\" isn't UTF-8")
            }
            return value
        }
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw .decodingFailed("\"\(key)\": \(error)")
        }
    }
}

/// Runs blocking keychain work on a global queue.
func offMainThread<T: Sendable>(_ body: @escaping @Sendable () throws(KeychainError) -> T) async throws(KeychainError) -> T {
    let result: Result<T, KeychainError> = await withCheckedContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async {
            do throws(KeychainError) {
                continuation.resume(returning: .success(try body()))
            } catch {
                continuation.resume(returning: .failure(error))
            }
        }
    }
    return try result.get()
}
