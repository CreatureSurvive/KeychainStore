#if !os(tvOS)
import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Creates and loads Secure Enclave P-256 keys, stored by name.
///
/// The private key never leaves the Secure Enclave. What's stored in the
/// keychain is an encrypted handle that only this device's Secure Enclave
/// can use, so the item is always device-only.
///
/// ```swift
/// let keys = SecureEnclaveKeys(store: keychain)
/// let key = try keys.signingKey("device-identity", authentication: .biometryCurrentSet)
/// let signature = try key.signature(for: challenge)
/// upload(key.publicKey.derRepresentation)
/// ```
///
/// Unavailable on tvOS, which has no Secure Enclave API.
public struct SecureEnclaveKeys: Sendable {
    public let store: KeychainStore

    /// Keys are stored in `store` under names prefixed with `se.`.
    public init(store: KeychainStore = KeychainStore()) {
        // Handles are device-bound: never let them sync.
        self.store = store.with(synchronizable: false)
    }

    /// Whether this device has a Secure Enclave (false in the simulator).
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Returns the signing key named `name`, creating it if needed.
    ///
    /// - Parameters:
    ///   - accessibility: When the key can be used. Only applies when the
    ///     key is created. Unsigned macOS command-line tools can't create
    ///     ``Accessibility/whenUnlocked`` keys; use ``Accessibility/afterFirstUnlock``.
    ///   - authentication: Authentication required to use the key. Only
    ///     applies when the key is created.
    ///   - context: An authentication context for using the key, for example
    ///     one already evaluated to avoid a second prompt.
    public func signingKey(
        _ name: String,
        accessibility: Accessibility = .whenUnlocked,
        authentication: AuthenticationPolicy = [],
        context: LAContext? = nil
    ) throws(KeychainError) -> SecureEnclave.P256.Signing.PrivateKey {
        try loadOrCreate(name, authentication: authentication) { () throws(KeychainError) -> SecureEnclave.P256.Signing.PrivateKey in
            let control = try accessControl(authentication, accessibility: accessibility)
            return try wrap { try SecureEnclave.P256.Signing.PrivateKey(accessControl: control, authenticationContext: context) }
        } load: { data throws(KeychainError) in
            try wrap { try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context) }
        } represent: { $0.dataRepresentation }
    }

    /// Returns the key agreement key named `name`, creating it if needed.
    public func keyAgreementKey(
        _ name: String,
        accessibility: Accessibility = .whenUnlocked,
        authentication: AuthenticationPolicy = [],
        context: LAContext? = nil
    ) throws(KeychainError) -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        try loadOrCreate(name, authentication: authentication) { () throws(KeychainError) -> SecureEnclave.P256.KeyAgreement.PrivateKey in
            let control = try accessControl(authentication, accessibility: accessibility)
            return try wrap { try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control, authenticationContext: context) }
        } load: { data throws(KeychainError) in
            try wrap { try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data, authenticationContext: context) }
        } represent: { $0.dataRepresentation }
    }

    /// Whether a key named `name` exists.
    public func containsKey(_ name: String) throws(KeychainError) -> Bool {
        try store.contains(storageKey(name))
    }

    /// Deletes the key named `name`. The Secure Enclave key becomes unusable.
    public func removeKey(_ name: String) throws(KeychainError) {
        try store.remove(storageKey(name))
    }

    // MARK: - Private

    private func storageKey(_ name: String) -> String { "se.\(name)" }

    private func loadOrCreate<Key>(
        _ name: String,
        authentication: AuthenticationPolicy,
        create: () throws(KeychainError) -> Key,
        load: (Data) throws(KeychainError) -> Key,
        represent: (Key) -> Data
    ) throws(KeychainError) -> Key {
        guard Self.isAvailable else {
            throw .invalidConfiguration("this device has no Secure Enclave")
        }
        if let data = try store.data(for: storageKey(name)) {
            return try load(data)
        }
        let key = try create()
        // The handle is useless off this device, so keep it device-only.
        try store.set(represent(key), for: storageKey(name), options: ItemOptions(accessibility: .afterFirstUnlock, thisDeviceOnly: true))
        return key
    }

    private func accessControl(_ authentication: AuthenticationPolicy, accessibility: Accessibility) throws(KeychainError) -> SecAccessControl {
        var error: Unmanaged<CFError>?
        let flags = SecAccessControlCreateFlags.privateKeyUsage.union(authentication.flags)
        guard let control = SecAccessControlCreateWithFlags(nil, accessibility.attribute(thisDeviceOnly: true), flags, &error) else {
            throw .invalidConfiguration(error?.takeRetainedValue().localizedDescription ?? "invalid authentication policy")
        }
        return control
    }

    private func wrap<T>(_ body: () throws -> T) throws(KeychainError) -> T {
        do {
            return try body()
        } catch let error as KeychainError {
            throw error
        } catch {
            let nsError = error as NSError
            if nsError.domain == NSOSStatusErrorDomain {
                throw KeychainError(status: OSStatus(nsError.code))
            }
            if nsError.domain == LAError.errorDomain, let code = LAError.Code(rawValue: nsError.code) {
                switch code {
                case .userCancel, .appCancel, .systemCancel: throw .userCanceled
                case .notInteractive: throw .interactionNotAllowed
                default: throw .authenticationFailed
                }
            }
            throw .unhandled(OSStatus(nsError.code))
        }
    }
}
#endif
