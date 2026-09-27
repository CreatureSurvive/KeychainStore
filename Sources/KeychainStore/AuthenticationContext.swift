import Foundation
#if canImport(LocalAuthentication) && !os(tvOS)
import LocalAuthentication

/// The context used to authenticate keychain reads: `LAContext`.
public typealias AuthenticationContext = LAContext
#else
/// tvOS has no LocalAuthentication, and Apple TV has no passcode or
/// biometry, so items there never require authentication. This stand-in
/// keeps the API uniform.
public final class AuthenticationContext: @unchecked Sendable {
    /// Fail instead of prompting. Always effectively true on tvOS.
    public var interactionNotAllowed = false
    public init() {}
}
#endif
