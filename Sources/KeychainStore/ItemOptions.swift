import Foundation
import Security

/// When an item's data can be read.
public enum Accessibility: Sendable, Hashable, CaseIterable {
    /// Only while the device is unlocked. The best choice for most data.
    case whenUnlocked
    /// After the first unlock following a restart, until the next restart.
    /// Needed for data read in the background, such as by background tasks
    /// or notification extensions.
    case afterFirstUnlock
    /// Only while unlocked, and only while a passcode is set. The item is
    /// deleted if the passcode is removed. Never syncs or migrates.
    case whenPasscodeSet

    func attribute(thisDeviceOnly: Bool) -> CFString {
        switch self {
        case .whenUnlocked: thisDeviceOnly ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlock: thisDeviceOnly ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlock
        case .whenPasscodeSet: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    init?(attribute: String) {
        let whenUnlocked: Set<String> = [kSecAttrAccessibleWhenUnlocked as String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String]
        let afterFirstUnlock: Set<String> = [kSecAttrAccessibleAfterFirstUnlock as String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String]
        if whenUnlocked.contains(attribute) {
            self = .whenUnlocked
        } else if afterFirstUnlock.contains(attribute) {
            self = .afterFirstUnlock
        } else if attribute == kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String {
            self = .whenPasscodeSet
        } else {
            return nil
        }
    }
}

/// User authentication required to read an item, mirroring
/// `SecAccessControlCreateFlags`.
///
/// ```swift
/// try store.set(token, for: "token", options: .init(authentication: .biometryCurrentSet))
/// try store.set(secret, for: "secret", options: .init(authentication: [.biometryAny, .or, .devicePasscode]))
/// ```
public struct AuthenticationPolicy: OptionSet, Sendable, Hashable {
    public let rawValue: UInt

    public init(rawValue: UInt) { self.rawValue = rawValue }

    /// Biometry or the device passcode.
    public static let userPresence = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.userPresence.rawValue)
    /// Any enrolled finger or face, including ones added later.
    public static let biometryAny = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.biometryAny.rawValue)
    /// Only the fingers or faces enrolled now. Enrolling a new one
    /// invalidates the item, which protects against an attacker who learns
    /// the passcode and adds their own face.
    public static let biometryCurrentSet = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.biometryCurrentSet.rawValue)
    /// The device passcode.
    public static let devicePasscode = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.devicePasscode.rawValue)
    /// Any one of the listed constraints.
    public static let or = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.or.rawValue)
    /// All of the listed constraints.
    public static let and = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.and.rawValue)

    var flags: SecAccessControlCreateFlags { SecAccessControlCreateFlags(rawValue: rawValue) }
}

/// Options for writing an item.
public struct ItemOptions: Sendable, Hashable {
    /// When the item can be read. Defaults to ``Accessibility/whenUnlocked``.
    public var accessibility: Accessibility
    /// Keeps the item on this device: it isn't included in encrypted backups
    /// restored to other devices and never syncs.
    public var thisDeviceOnly: Bool
    /// Authentication required to read the item. Empty means none.
    public var authentication: AuthenticationPolicy
    /// A user-visible label (shown in Keychain Access on macOS and in the
    /// Passwords app for internet passwords).
    public var label: String?
    /// A user-visible comment.
    public var comment: String?

    public init(
        accessibility: Accessibility = .whenUnlocked,
        thisDeviceOnly: Bool = false,
        authentication: AuthenticationPolicy = [],
        label: String? = nil,
        comment: String? = nil
    ) {
        self.accessibility = accessibility
        self.thisDeviceOnly = thisDeviceOnly
        self.authentication = authentication
        self.label = label
        self.comment = comment
    }

    /// Readable in the background after first unlock. Suitable for tokens
    /// used by background refresh.
    public static let background = ItemOptions(accessibility: .afterFirstUnlock)

    /// Requires Face ID / Touch ID with the currently enrolled set, and stays
    /// on this device.
    public static let biometric = ItemOptions(thisDeviceOnly: true, authentication: .biometryCurrentSet)

    /// Whether the item stays on this device, taking the accessibility into account.
    var isDeviceBound: Bool {
        thisDeviceOnly || accessibility == .whenPasscodeSet || !authentication.isEmpty
    }

    /// Validates the combination for an item that may sync through iCloud Keychain.
    func validate(synchronizable: Bool) throws(KeychainError) {
        guard synchronizable else { return }
        if !authentication.isEmpty {
            throw .invalidConfiguration("items that require authentication can't sync through iCloud Keychain")
        }
        if thisDeviceOnly || accessibility == .whenPasscodeSet {
            throw .invalidConfiguration("device-only items can't sync through iCloud Keychain")
        }
    }

    func accessControl() throws(KeychainError) -> SecAccessControl? {
        guard !authentication.isEmpty else { return nil }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil,
            accessibility.attribute(thisDeviceOnly: true),
            authentication.flags,
            &error
        ) else {
            let reason = error?.takeRetainedValue().localizedDescription ?? "invalid authentication policy"
            throw .invalidConfiguration(reason)
        }
        return control
    }
}

/// Metadata about a stored item. Reading it never requires authentication.
public struct ItemAttributes: Sendable, Hashable {
    public var key: String
    public var label: String?
    public var comment: String?
    public var creationDate: Date?
    public var modificationDate: Date?
    public var accessibility: Accessibility?
    public var synchronizable: Bool
    public var accessGroup: String?
    /// The server, for internet passwords.
    public var server: InternetServer?

    public init(
        key: String,
        label: String? = nil,
        comment: String? = nil,
        creationDate: Date? = nil,
        modificationDate: Date? = nil,
        accessibility: Accessibility? = nil,
        synchronizable: Bool = false,
        accessGroup: String? = nil,
        server: InternetServer? = nil
    ) {
        self.key = key
        self.label = label
        self.comment = comment
        self.creationDate = creationDate
        self.modificationDate = modificationDate
        self.accessibility = accessibility
        self.synchronizable = synchronizable
        self.accessGroup = accessGroup
        self.server = server
    }
}
