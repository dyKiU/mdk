import Foundation

// Actual synthetic SDK identity; no secret, account, or ciphertext in diagnostics.
enum StoreControls {
    static func expectDenied(_ body: () throws -> Void) throws {
        do { try body() } catch { return }
        throw AcceptanceFailure.unexpectedAccount
    }

    static func run(root: URL) async throws {
        var stage = "create"
        do {
            guard !FileManager.default.fileExists(atPath: root.path) else {
                throw AcceptanceFailure.invalidArguments
            }
            let original = try AcceptanceAgent(root: root)
            try await original.runtime.start()
            let account = try await original.runtime.createIdentity(
                defaultRelays: [try NativeAcceptance.relayURL()], bootstrapRelays: [try NativeAcceptance.relayURL()],
                inboxRelays: [try NativeAcceptance.relayURL()])
            let secret = try original.store.loadSecret(label: account.label, accountIdHex: account.accountIdHex)
            original.session = try await original.runtime.beginDeviceLinkingSession(accountRef: account.accountIdHex)
            try await original.close()
            stage = "reopen"
            let reopened = try AcceptanceAgent(root: root)
            try await reopened.runtime.start()
            do {
                guard reopened.session == nil,
                    try reopened.store.loadSecret(label: account.label, accountIdHex: account.accountIdHex) == secret,
                    try reopened.runtime.listAccounts().contains(where: { $0.accountIdHex == account.accountIdHex })
                else { throw AcceptanceFailure.unexpectedAccount }
                try await reopened.close()
            } catch {
                let originalError = error
                do { try await reopened.close() } catch { fputs("{\"cleanup_failed\":true}\n", stderr) }
                throw originalError
            }
            stage = "account-mismatch"
            try expectDenied {
                _ = try reopened.store.loadSecret(label: account.label, accountIdHex: String(repeating: "0", count: 64))
            }
            let directory = root.appendingPathComponent("credentials", isDirectory: true)
            let key = directory.appendingPathComponent("credentials.key")
            let sealed = directory.appendingPathComponent("signing-credentials.sealed")
            stage = "permissions"
            for (path, expected) in [(root, 0o700), (directory, 0o700), (key, 0o600), (sealed, 0o600)] {
                let mode = try FileManager.default.attributesOfItem(atPath: path.path)[.posixPermissions] as? NSNumber
                guard mode?.intValue == expected else { throw AcceptanceFailure.unexpectedAccount }
            }
            stage = "tampered-ciphertext"
            let ciphertext = try Data(contentsOf: sealed)
            var tampered = ciphertext
            guard !tampered.isEmpty else { throw AcceptanceFailure.unexpectedAccount }
            tampered[tampered.count - 1] ^= 1
            try tampered.write(to: sealed)
            try expectDenied { _ = try TaskSecretStore(directory: directory) }
            try ciphertext.write(to: sealed)
            stage = "missing-key"
            let keyBytes = try Data(contentsOf: key)
            try FileManager.default.removeItem(at: key)
            try expectDenied { _ = try TaskSecretStore(directory: directory) }
            try keyBytes.write(to: key, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: key.path)
            print("{\"gate\":\"native-store-controls\",\"passed\":1,\"failed\":0,\"controls\":5}")
        } catch {
            fputs("{\"gate\":\"native-store-controls\",\"stage\":\"\(stage)\",\"passed\":0,\"failed\":1}\n", stderr)
            exit(1)
        }
    }
}
