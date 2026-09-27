import Foundation

/// A username and password for a server.
public struct Credential: Sendable, Hashable {
    public var server: InternetServer
    public var username: String
    public var password: String

    public init(server: InternetServer, username: String, password: String) {
        self.server = server
        self.username = username
        self.password = password
    }
}

/// Stores server logins as internet password items.
///
/// Internet passwords are keyed by server and account, which suits apps
/// that sign in to several self-hosted servers (media servers, NAS, Git
/// forges). On macOS they appear in Keychain Access under their server.
///
/// ```swift
/// let logins = CredentialStore()
/// try logins.save(Credential(server: InternetServer(url: serverURL)!, username: "dan", password: password))
/// let saved = try logins.credentials(for: InternetServer(host: "jellyfin.local"))
/// ```
public struct CredentialStore: Sendable {
    public let accessGroup: String?
    public let synchronizable: Bool
    public let backend: any KeychainBackend

    public init(accessGroup: String? = nil, synchronizable: Bool = false, backend: any KeychainBackend = SystemKeychain()) {
        self.accessGroup = accessGroup
        self.synchronizable = synchronizable
        self.backend = backend
    }

    /// Saves a credential, replacing the password for the same server and username.
    public func save(_ credential: Credential, options: ItemOptions = ItemOptions()) throws(KeychainError) {
        var options = options
        if options.label == nil { options.label = credential.server.host }
        try backend.write(
            Data(credential.password.utf8),
            to: query(credential.server, credential.username),
            synchronizable: synchronizable,
            options: options
        )
    }

    /// The password for a username on a server.
    public func password(for username: String, on server: InternetServer, prompt: AuthenticationPrompt? = nil) throws(KeychainError) -> String? {
        guard let data = try backend.read(query(server, username), context: prompt?.makeContext()) else { return nil }
        guard let password = String(data: data, encoding: .utf8) else { throw .decodingFailed("the password isn't UTF-8") }
        return password
    }

    /// Every username saved for servers matching `server`. `nil` fields in
    /// `server` (port, scheme, path) match any value. Never prompts.
    public func usernames(for server: InternetServer) throws(KeychainError) -> [String] {
        try backend.attributes(query(server, nil)).map(\.key)
    }

    /// Every credential saved for servers matching `server`. Reads each
    /// password, so protected items prompt.
    public func credentials(for server: InternetServer, prompt: AuthenticationPrompt? = nil) throws(KeychainError) -> [Credential] {
        var credentials: [Credential] = []
        for attributes in try backend.attributes(query(server, nil)) {
            let exact = attributes.server ?? server
            if let password = try password(for: attributes.key, on: exact, prompt: prompt) {
                credentials.append(Credential(server: exact, username: attributes.key, password: password))
            }
        }
        return credentials
    }

    /// Removes the credential for a username on a server, or every
    /// credential for the server if `username` is `nil`.
    public func remove(username: String? = nil, on server: InternetServer) throws(KeychainError) {
        try backend.delete(query(server, username))
    }

    private func query(_ server: InternetServer, _ username: String?) -> ItemQuery {
        ItemQuery(itemClass: .internetPassword(server), accessGroup: accessGroup, account: username)
    }
}
