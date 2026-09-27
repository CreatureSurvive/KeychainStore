import Foundation
import Security

/// An error from a keychain operation.
///
/// Common failures get their own cases, with explanations, so callers can
/// react to them. For example, a canceled biometric prompt isn't a
/// failure worth reporting.
public enum KeychainError: Error, Sendable, Equatable {
    /// The user canceled the authentication prompt (`errSecUserCanceled`).
    case userCanceled
    /// Authentication failed, for example the wrong passcode or too many
    /// biometric attempts (`errSecAuthFailed`).
    case authenticationFailed
    /// The item needs user interaction that isn't possible right now: the
    /// device is locked, the app is in the background, or interaction was
    /// disabled (`errSecInteractionNotAllowed`).
    case interactionNotAllowed
    /// The process lacks the keychain entitlement it needs (`errSecMissingEntitlement`,
    /// -34018). On macOS this usually means an unsigned command-line tool
    /// or test runner using the data protection keychain.
    case missingEntitlement
    /// The keychain isn't available, for example before first unlock after
    /// a reboot (`errSecNotAvailable`).
    case notAvailable
    /// An item with the same identity already exists (`errSecDuplicateItem`).
    case duplicateItem
    /// The options can't be combined, for example an access-controlled item
    /// that also syncs through iCloud Keychain.
    case invalidConfiguration(String)
    /// A stored value couldn't be decoded as the requested type.
    case decodingFailed(String)
    /// A value couldn't be encoded for storage.
    case encodingFailed(String)
    /// Any other Security framework status.
    case unhandled(OSStatus)

    /// Maps an `OSStatus` from the Security framework.
    public init(status: OSStatus) {
        switch status {
        case errSecUserCanceled: self = .userCanceled
        case errSecAuthFailed: self = .authenticationFailed
        case errSecInteractionNotAllowed: self = .interactionNotAllowed
        case errSecMissingEntitlement: self = .missingEntitlement
        case errSecNotAvailable: self = .notAvailable
        case errSecDuplicateItem: self = .duplicateItem
        default: self = .unhandled(status)
        }
    }

    /// The underlying `OSStatus`, when the error came from the Security framework.
    public var status: OSStatus? {
        switch self {
        case .userCanceled: errSecUserCanceled
        case .authenticationFailed: errSecAuthFailed
        case .interactionNotAllowed: errSecInteractionNotAllowed
        case .missingEntitlement: errSecMissingEntitlement
        case .notAvailable: errSecNotAvailable
        case .duplicateItem: errSecDuplicateItem
        case .unhandled(let status): status
        case .invalidConfiguration, .decodingFailed, .encodingFailed: nil
        }
    }
}

extension KeychainError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .userCanceled:
            return "Authentication was canceled."
        case .authenticationFailed:
            return "Authentication failed."
        case .interactionNotAllowed:
            return "The keychain item can't be accessed right now. The device may be locked or the app may be in the background."
        case .missingEntitlement:
            return "The app is missing a keychain entitlement (errSecMissingEntitlement). Sign the app with a team, check keychain-access-groups, or use the legacy macOS keychain for unsigned tools."
        case .notAvailable:
            return "The keychain is not available. The device may not have been unlocked since it restarted."
        case .duplicateItem:
            return "The keychain item already exists."
        case .invalidConfiguration(let reason):
            return "Invalid keychain configuration: \(reason)"
        case .decodingFailed(let reason):
            return "The keychain value couldn't be decoded: \(reason)"
        case .encodingFailed(let reason):
            return "The value couldn't be encoded for the keychain: \(reason)"
        case .unhandled(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            return "\(message) (OSStatus \(status))"
        }
    }
}

/// Throws a ``KeychainError`` unless `status` is `errSecSuccess`.
@inline(__always)
func check(_ status: OSStatus) throws(KeychainError) {
    guard status == errSecSuccess else { throw KeychainError(status: status) }
}
