import Foundation
import Security

/// Which kind of keychain item, and the fields that identify it besides the account.
public enum ItemClass: Sendable, Hashable {
    /// `kSecClassGenericPassword`, identified by a service name.
    case genericPassword(service: String)
    /// `kSecClassInternetPassword`, identified by a server.
    case internetPassword(InternetServer)
}

/// The server fields of an internet password. `nil` fields match any value
/// when searching.
public struct InternetServer: Sendable, Hashable {
    public var host: String
    public var port: Int?
    /// A URL scheme such as `https`, stored as the item's protocol.
    public var scheme: String?
    public var path: String?

    public init(host: String, port: Int? = nil, scheme: String? = nil, path: String? = nil) {
        self.host = host.lowercased()
        self.port = port
        self.scheme = scheme?.lowercased()
        self.path = path
    }

    /// The server a URL points at: host, explicit port, scheme and path
    /// (an empty or `/` path is omitted).
    public init?(url: URL) {
        guard let host = url.host(percentEncoded: false), !host.isEmpty else { return nil }
        let path = url.path(percentEncoded: false)
        self.init(host: host, port: url.port, scheme: url.scheme, path: path.isEmpty || path == "/" ? nil : path)
    }

    func matches(_ other: InternetServer) -> Bool {
        host == other.host
            && (port == nil || port == other.port)
            && (scheme == nil || scheme == other.scheme)
            && (path == nil || path == other.path)
    }
}

/// A set of items: one class and access group, optionally one account.
public struct ItemQuery: Sendable, Hashable {
    public var itemClass: ItemClass
    public var accessGroup: String?
    /// The account (the store's key), or `nil` for every account.
    public var account: String?

    public init(itemClass: ItemClass, accessGroup: String?, account: String?) {
        self.itemClass = itemClass
        self.accessGroup = accessGroup
        self.account = account
    }
}

/// Storage used by ``KeychainStore``. The system keychain is the real
/// implementation; ``InMemoryKeychain`` is a drop-in replacement for tests
/// and previews.
///
/// Implementations match items regardless of their synchronizable state
/// and keep at most one item per class, access group and account.
public protocol KeychainBackend: Sendable {
    /// Reads the data of the single item matching `query` (which has an account).
    func read(_ query: ItemQuery, context: AuthenticationContext?) throws(KeychainError) -> Data?
    /// Metadata for every matching item. Never prompts.
    func attributes(_ query: ItemQuery) throws(KeychainError) -> [ItemAttributes]
    /// Creates or replaces the item matching `query` (which has an account).
    func write(_ data: Data, to query: ItemQuery, synchronizable: Bool, options: ItemOptions) throws(KeychainError)
    /// Deletes every matching item. Deleting nothing is not an error.
    func delete(_ query: ItemQuery) throws(KeychainError)
}

// MARK: - System keychain

/// The system keychain through `SecItem`.
///
/// On macOS it uses the data protection keychain (`kSecUseDataProtectionKeychain`),
/// which behaves like iOS and supports access groups, synchronization and
/// access control. That keychain requires a signed app. Unsigned tools can
/// opt into the legacy file-based keychain with `legacyMacOSKeychain: true`.
public struct SystemKeychain: KeychainBackend {
    /// Uses the macOS file-based keychain instead of the data protection
    /// keychain. Ignored on other platforms.
    public var legacyMacOSKeychain: Bool

    public init(legacyMacOSKeychain: Bool = false) {
        self.legacyMacOSKeychain = legacyMacOSKeychain
    }

    public func read(_ query: ItemQuery, context: AuthenticationContext?) throws(KeychainError) -> Data? {
        var dictionary = base(query)
        dictionary[kSecReturnData as String] = true
        dictionary[kSecMatchLimit as String] = kSecMatchLimitOne
        #if !os(tvOS)
        if let context {
            dictionary[kSecUseAuthenticationContext as String] = context
        }
        #endif
        var result: CFTypeRef?
        let status = SecItemCopyMatching(dictionary as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status)
        return result as? Data
    }

    public func attributes(_ query: ItemQuery) throws(KeychainError) -> [ItemAttributes] {
        var dictionary = base(query)
        dictionary[kSecReturnAttributes as String] = true
        dictionary[kSecMatchLimit as String] = kSecMatchLimitAll
        // Attribute reads never need the item's secret, so never prompt.
        #if !os(tvOS)
        let context = AuthenticationContext()
        context.interactionNotAllowed = true
        dictionary[kSecUseAuthenticationContext as String] = context
        #endif
        var result: CFTypeRef?
        let status = SecItemCopyMatching(dictionary as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try check(status)
        let items = (result as? [[String: Any]]) ?? []
        return items.compactMap(Self.attributes(from:)).sorted { $0.key < $1.key }
    }

    public func write(_ data: Data, to query: ItemQuery, synchronizable: Bool, options: ItemOptions) throws(KeychainError) {
        try options.validate(synchronizable: synchronizable)
        let accessControl = try options.accessControl()
        let existing = try attributes(query).first

        if let existing, existing.synchronizable == synchronizable, accessControl == nil {
            // Update in place: atomic, and keeps the creation date. Updating
            // an access-controlled item would need authentication, so the
            // update runs non-interactively and falls back to replacing it.
            var match = base(query, synchronizableAny: false)
            match[kSecAttrSynchronizable as String] = synchronizable
            #if !os(tvOS)
            let context = AuthenticationContext()
            context.interactionNotAllowed = true
            match[kSecUseAuthenticationContext as String] = context
            #endif
            var changes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: options.accessibility.attribute(thisDeviceOnly: options.thisDeviceOnly),
            ]
            if let label = options.label { changes[kSecAttrLabel as String] = label }
            if let comment = options.comment { changes[kSecAttrComment as String] = comment }
            let status = SecItemUpdate(match as CFDictionary, changes as CFDictionary)
            switch status {
            case errSecSuccess:
                return
            case errSecInteractionNotAllowed, errSecAuthFailed, errSecItemNotFound:
                break // replace below
            default:
                try check(status)
            }
        }

        // Changing access control or sync state needs a new item. Deleting an
        // access-controlled item doesn't require authentication.
        if existing != nil {
            try delete(query)
        }
        var item = base(query, synchronizableAny: false)
        item[kSecAttrSynchronizable as String] = synchronizable
        item[kSecValueData as String] = data
        if let accessControl {
            item[kSecAttrAccessControl as String] = accessControl
        } else {
            item[kSecAttrAccessible as String] = options.accessibility.attribute(thisDeviceOnly: options.thisDeviceOnly)
        }
        if let label = options.label ?? existing?.label { item[kSecAttrLabel as String] = label }
        if let comment = options.comment ?? existing?.comment { item[kSecAttrComment as String] = comment }
        try check(SecItemAdd(item as CFDictionary, nil))
    }

    public func delete(_ query: ItemQuery) throws(KeychainError) {
        let status = SecItemDelete(base(query) as CFDictionary)
        if status == errSecItemNotFound { return }
        try check(status)
    }

    // MARK: Queries

    private func base(_ query: ItemQuery, synchronizableAny: Bool = true) -> [String: Any] {
        var dictionary: [String: Any] = [:]
        switch query.itemClass {
        case .genericPassword(let service):
            dictionary[kSecClass as String] = kSecClassGenericPassword
            dictionary[kSecAttrService as String] = service
        case .internetPassword(let server):
            dictionary[kSecClass as String] = kSecClassInternetPassword
            dictionary[kSecAttrServer as String] = server.host
            if let port = server.port { dictionary[kSecAttrPort as String] = port }
            if let scheme = server.scheme { dictionary[kSecAttrProtocol as String] = Self.protocolAttribute(for: scheme) }
            if let path = server.path { dictionary[kSecAttrPath as String] = path }
        }
        if let account = query.account {
            dictionary[kSecAttrAccount as String] = account
        }
        if let group = query.accessGroup {
            dictionary[kSecAttrAccessGroup as String] = group
        }
        if synchronizableAny {
            dictionary[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        }
        #if os(macOS)
        if !legacyMacOSKeychain {
            dictionary[kSecUseDataProtectionKeychain as String] = true
        }
        #endif
        return dictionary
    }

    static func attributes(from item: [String: Any]) -> ItemAttributes? {
        guard let account = item[kSecAttrAccount as String] as? String else { return nil }
        let accessibility = (item[kSecAttrAccessible as String] as? String).flatMap(Accessibility.init(attribute:))
        let synchronizable = (item[kSecAttrSynchronizable as String] as? Bool)
            ?? ((item[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue ?? false)
        return ItemAttributes(
            key: account,
            label: item[kSecAttrLabel as String] as? String,
            comment: item[kSecAttrComment as String] as? String,
            creationDate: item[kSecAttrCreationDate as String] as? Date,
            modificationDate: item[kSecAttrModificationDate as String] as? Date,
            accessibility: accessibility,
            synchronizable: synchronizable,
            accessGroup: item[kSecAttrAccessGroup as String] as? String,
            server: (item[kSecAttrServer as String] as? String).map { host in
                InternetServer(
                    host: host,
                    port: (item[kSecAttrPort as String] as? NSNumber).flatMap { $0.intValue == 0 ? nil : $0.intValue },
                    scheme: (item[kSecAttrProtocol as String] as? String).map(Self.scheme(forProtocol:)),
                    path: (item[kSecAttrPath as String] as? String).flatMap { $0.isEmpty ? nil : $0 }
                )
            }
        )
    }

    static let knownSchemes = ["https", "http", "ftp", "ftps", "ssh", "smb", "afp", "imap", "imaps", "smtp", "ldap", "ldaps", "telnet"]

    /// Maps a `kSecAttrProtocol` value back to a URL scheme.
    static func scheme(forProtocol value: String) -> String {
        knownSchemes.first { protocolAttribute(for: $0) as String == value } ?? value
    }

    /// Maps common URL schemes to `kSecAttrProtocol` values.
    static func protocolAttribute(for scheme: String) -> CFString {
        switch scheme {
        case "https": kSecAttrProtocolHTTPS
        case "http": kSecAttrProtocolHTTP
        case "ftp": kSecAttrProtocolFTP
        case "ftps": kSecAttrProtocolFTPS
        case "ssh": kSecAttrProtocolSSH
        case "smb": kSecAttrProtocolSMB
        case "afp": kSecAttrProtocolAFP
        case "imap": kSecAttrProtocolIMAP
        case "imaps": kSecAttrProtocolIMAPS
        case "smtp": kSecAttrProtocolSMTP
        case "ldap": kSecAttrProtocolLDAP
        case "ldaps": kSecAttrProtocolLDAPS
        case "telnet": kSecAttrProtocolTelnet
        default: scheme as CFString
        }
    }
}

// MARK: - In memory

/// A keychain held in memory, with the same identity and sync semantics as
/// the system keychain. Use it for unit tests, previews and command-line
/// tools without keychain entitlements.
///
/// Access control is recorded but not enforced. Set ``requireAuthenticationError``
/// to simulate how protected items behave.
public final class InMemoryKeychain: KeychainBackend, @unchecked Sendable {
    private struct Item {
        var data: Data
        var attributes: ItemAttributes
        var itemClass: ItemClass
        var requiresAuthentication: Bool
    }

    let id = UUID().uuidString
    private let lock = NSLock()
    private var items: [Item] = []
    private var simulatedAuthenticationError: KeychainError?

    public init() {}

    /// When set, reading an item that requires authentication throws this
    /// error, simulating a canceled or failed prompt.
    public var requireAuthenticationError: KeychainError? {
        get { lock.withLock { simulatedAuthenticationError } }
        set { lock.withLock { simulatedAuthenticationError = newValue } }
    }

    /// The number of stored items.
    public var count: Int { lock.withLock { items.count } }

    public func read(_ query: ItemQuery, context: AuthenticationContext?) throws(KeychainError) -> Data? {
        let result: Result<Data?, KeychainError> = lock.withLock {
            guard let item = items.first(where: { matches($0, query) }) else { return .success(nil) }
            if item.requiresAuthentication {
                if context?.interactionNotAllowed == true { return .failure(.interactionNotAllowed) }
                if let error = simulatedAuthenticationError { return .failure(error) }
            }
            return .success(item.data)
        }
        return try result.get()
    }

    public func attributes(_ query: ItemQuery) throws(KeychainError) -> [ItemAttributes] {
        lock.withLock { items.filter { matches($0, query) }.map(\.attributes).sorted { $0.key < $1.key } }
    }

    public func write(_ data: Data, to query: ItemQuery, synchronizable: Bool, options: ItemOptions) throws(KeychainError) {
        try options.validate(synchronizable: synchronizable)
        _ = try options.accessControl()
        guard let account = query.account else { throw .invalidConfiguration("writes need a key") }
        lock.withLock {
            let now = Date()
            let previous = items.firstIndex(where: { matches($0, query) })
            let created = previous.flatMap { items[$0].attributes.creationDate } ?? now
            let attributes = ItemAttributes(
                key: account,
                label: options.label ?? previous.flatMap { items[$0].attributes.label },
                comment: options.comment ?? previous.flatMap { items[$0].attributes.comment },
                creationDate: created,
                modificationDate: now,
                accessibility: options.accessibility,
                synchronizable: synchronizable,
                accessGroup: query.accessGroup,
                server: { if case .internetPassword(let server) = query.itemClass { server } else { nil } }()
            )
            let item = Item(data: data, attributes: attributes, itemClass: query.itemClass, requiresAuthentication: !options.authentication.isEmpty)
            if let previous { items[previous] = item } else { items.append(item) }
        }
    }

    public func delete(_ query: ItemQuery) throws(KeychainError) {
        lock.withLock { items.removeAll { matches($0, query) } }
    }

    private func matches(_ item: Item, _ query: ItemQuery) -> Bool {
        if let account = query.account, item.attributes.key != account { return false }
        if let group = query.accessGroup, item.attributes.accessGroup != group { return false }
        switch (query.itemClass, item.itemClass) {
        case (.genericPassword(let a), .genericPassword(let b)): return a == b
        case (.internetPassword(let pattern), .internetPassword(let server)): return pattern.matches(server)
        default: return false
        }
    }
}
