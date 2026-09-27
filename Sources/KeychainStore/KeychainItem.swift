import Foundation
import Observation
import SwiftUI

/// An observable keychain value that stays current when the item changes,
/// including changes made by other processes such as app extensions.
///
/// ```swift
/// @State private var token = KeychainItem<String>("token", store: keychain)
///
/// Text(token.value ?? "Signed out")
/// Button("Sign Out") { try? token.remove() }
/// ```
///
/// Items that require authentication aren't loaded automatically, because
/// loading would prompt. Call ``load(prompt:)`` when the user asks for them.
@MainActor
@Observable
public final class KeychainItem<Value: Codable & Sendable & Equatable> {
    /// The current value, or `nil` if there's none (or it hasn't been loaded).
    public private(set) var value: Value?
    /// The error from the most recent load or write, if any.
    public private(set) var error: KeychainError?

    public let key: String
    public let options: ItemOptions
    @ObservationIgnored public let store: KeychainStore
    @ObservationIgnored private var observation: Task<Void, Never>?

    public init(_ key: String, store: KeychainStore = KeychainStore(), options: ItemOptions = ItemOptions()) {
        self.key = key
        self.store = store
        self.options = options
        if options.authentication.isEmpty {
            reload()
        }
        // Register before returning so changes made right after init aren't missed.
        let changes = store.changes(for: key)
        observation = Task { [weak self, store] in
            for await _ in changes {
                guard let self else { return }
                if self.options.authentication.isEmpty {
                    self.reload()
                } else if (try? store.contains(key)) == false {
                    self.value = nil
                }
            }
        }
    }

    public convenience init(_ key: KeychainKey<Value>, store: KeychainStore = KeychainStore()) {
        self.init(key.name, store: store, options: key.options)
    }

    deinit {
        observation?.cancel()
    }

    /// Loads the value, prompting if the item requires authentication.
    @discardableResult
    public func load(prompt: AuthenticationPrompt? = nil) async -> Value? {
        do {
            let loaded = try await store.value(Value.self, for: key, prompt: prompt)
            value = loaded
            error = nil
            return loaded
        } catch {
            self.error = error
            return nil
        }
    }

    /// Stores a new value, or removes the item when `newValue` is `nil`.
    public func set(_ newValue: Value?) throws(KeychainError) {
        do {
            if let newValue {
                try store.set(newValue, for: key, options: options)
            } else {
                try store.remove(key)
            }
            value = newValue
            error = nil
        } catch {
            self.error = error
            throw error
        }
    }

    /// Removes the item.
    public func remove() throws(KeychainError) {
        try set(nil)
    }

    private func reload() {
        do {
            value = try store.value(Value.self, for: key)
            error = nil
        } catch {
            self.error = error
        }
    }
}

/// A property wrapper that reads and writes a keychain value from SwiftUI,
/// like `@AppStorage` for secrets.
///
/// ```swift
/// @KeychainStorage("apiKey") private var apiKey: String?
///
/// SecureField("API Key", text: Binding($apiKey, default: ""))
/// ```
///
/// Writes that fail are reported through ``KeychainItem/error`` on the
/// projected value's `item`. Don't use it for items that require
/// authentication; use ``KeychainItem`` and call `load(prompt:)` instead.
@MainActor
@propertyWrapper
public struct KeychainStorage<Value: Codable & Sendable & Equatable>: DynamicProperty {
    @State private var item: KeychainItem<Value>

    public init(_ key: String, store: KeychainStore = KeychainStore(), options: ItemOptions = ItemOptions()) {
        _item = State(wrappedValue: KeychainItem(key, store: store, options: options))
    }

    public init(_ key: KeychainKey<Value>, store: KeychainStore = KeychainStore()) {
        _item = State(wrappedValue: KeychainItem(key, store: store))
    }

    public var wrappedValue: Value? {
        get { item.value }
        nonmutating set { try? item.set(newValue) }
    }

    public var projectedValue: Binding<Value?> {
        Binding(get: { item.value }, set: { try? item.set($0) })
    }
}

extension Binding {
    /// Unwraps an optional binding, reading `defaultValue` when it's `nil`.
    /// Setting the default value stores `nil`.
    public init(_ source: Binding<Value?>, default defaultValue: Value) where Value: Equatable & Sendable {
        self.init(
            get: { source.wrappedValue ?? defaultValue },
            set: { source.wrappedValue = $0 == defaultValue ? nil : $0 }
        )
    }
}
