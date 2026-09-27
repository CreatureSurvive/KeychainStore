import Foundation
import notify

extension KeychainBackend {
    /// Namespaces change notifications. The system keychain shares one
    /// namespace across processes; in-memory keychains get their own.
    var changeNamespace: String {
        if let memory = self as? InMemoryKeychain { return "memory.\(memory.id)" }
        return "system"
    }
}

extension KeychainStore {
    /// Streams an element whenever the value for `key` changes, or whenever
    /// any value in the store changes if `key` is `nil`.
    ///
    /// Changes made through any `KeychainStore` with the same service and
    /// access group are delivered, including ones made by other processes on
    /// this device (an app and its extensions sharing an access group).
    /// Changes that arrive through iCloud Keychain sync aren't observable;
    /// re-read when the app becomes active if that matters.
    public func changes(for key: String? = nil) -> AsyncStream<Void> {
        let names = [key.map(changeName(forKey:)) ?? changeName(forKey: nil), clearedName]
        return AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            var tokens: [Int32] = []
            for name in names {
                var token: Int32 = NOTIFY_TOKEN_INVALID
                let status = notify_register_dispatch(name, &token, .global()) { _ in
                    continuation.yield()
                }
                if status == NOTIFY_STATUS_OK { tokens.append(token) }
            }
            let registered = tokens
            continuation.onTermination = { _ in
                registered.forEach { notify_cancel($0) }
            }
        }
    }

    func notifyChange(_ key: String?) {
        if let key {
            notify_post(changeName(forKey: key))
            notify_post(changeName(forKey: nil))
        } else {
            notify_post(clearedName)
        }
    }

    private var namePrefix: String {
        "KeychainStore.\(backend.changeNamespace).\(accessGroup ?? "-").\(service)"
    }

    private func changeName(forKey key: String?) -> String {
        key.map { "\(namePrefix).key.\($0)" } ?? "\(namePrefix).any"
    }

    private var clearedName: String {
        "\(namePrefix).cleared"
    }
}
