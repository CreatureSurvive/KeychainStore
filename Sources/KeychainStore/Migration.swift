import Foundation

/// The result of a migration.
public struct MigrationReport: Sendable, Hashable {
    /// Keys copied to the destination.
    public var migrated: [String] = []
    /// Keys left alone because the destination already had a value.
    public var skipped: [String] = []
    /// Keys that couldn't be read without authentication and were left in place.
    public var protected: [String] = []
}

extension KeychainStore {
    /// Moves every item from `source` into this store, then removes it from `source`.
    ///
    /// Use this to adopt a shared access group (so an extension can read
    /// existing items), move items into or out of iCloud Keychain, or rename
    /// a service. The migration is idempotent and safe to run on every
    /// launch: an item is only removed from the source after it has been
    /// written to the destination.
    ///
    /// - Parameters:
    ///   - source: The store to move items from.
    ///   - options: Options for the migrated items. Access control can't be
    ///     read back from the keychain, so re-apply it here if needed.
    ///   - overwrite: Whether to replace values that already exist in this store.
    @discardableResult
    public func migrate(from source: KeychainStore, options: ItemOptions = ItemOptions(), overwrite: Bool = false) throws(KeychainError) -> MigrationReport {
        var report = MigrationReport()
        let context = AuthenticationPrompt("").makeContext()
        context.interactionNotAllowed = true
        for attributes in try source.allAttributes() {
            let key = attributes.key
            if !overwrite, try isDistinct(from: source), try contains(key) {
                report.skipped.append(key)
                continue
            }
            let data: Data?
            do {
                data = try source.data(for: key, context: context)
            } catch .interactionNotAllowed {
                report.protected.append(key)
                continue
            }
            guard let data else { continue }
            var itemOptions = options
            if itemOptions.label == nil { itemOptions.label = attributes.label }
            if itemOptions.comment == nil { itemOptions.comment = attributes.comment }
            if itemOptions.accessibility == .whenUnlocked, let accessibility = attributes.accessibility, !synchronizable || accessibility != .whenPasscodeSet {
                itemOptions.accessibility = accessibility
            }
            if try isDistinct(from: source) {
                try set(data, for: key, options: itemOptions)
                try source.remove(key)
            } else {
                // Same item identity (only the sync flag differs): rewrite in place.
                try set(data, for: key, options: itemOptions)
            }
            report.migrated.append(key)
        }
        return report
    }

    /// Whether `other` addresses different items than this store, rather than
    /// the same items with a different sync setting.
    private func isDistinct(from other: KeychainStore) throws(KeychainError) -> Bool {
        other.service != service || other.accessGroup != accessGroup
    }
}
