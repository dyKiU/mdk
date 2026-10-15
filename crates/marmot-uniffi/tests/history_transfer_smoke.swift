import Foundation

private final class HistorySmokeStore: SecretStore, @unchecked Sendable {
    func hasSecretForLabel(label: String) throws -> Bool { false }
    func hasSecretForAccountId(accountIdHex: String) throws -> Bool { false }
    func writeSecret(label: String, accountIdHex: String, secretKeyHex: String) throws {
        preconditionFailure("factory refusal must not write a secret")
    }
    func loadSecret(label: String, accountIdHex: String) throws -> String {
        preconditionFailure("factory refusal must not load a secret")
    }
    func removeSecret(label: String, accountIdHex: String) throws {
        preconditionFailure("factory refusal must not remove a secret")
    }
}

@main
struct HistoryTransferSmoke {
    static func main() async throws {
        let experimental = ProcessInfo.processInfo.environment["EXPERIMENTAL_DEVICE_SYNC"] == "1"
        for complete in [false, true] {
            let value = HistoryTransferSnapshotFfi(revision: UInt64.max, importedRecords: 199,
                complete: complete, groupIdHex: "00ff01", sourceDevice: Data(repeating: 1, count: 32),
                recipientDevice: Data(repeating: 2, count: 32), snapshotTimestampCeiling: UInt64.max,
                recordCount: 200, encodedBytes: 196608, fragmentCount: 128)
            let copy = try FfiConverterTypeHistoryTransferSnapshotFfi.lift(
                FfiConverterTypeHistoryTransferSnapshotFfi.lower(value))
            precondition(copy == value)
        }
        for index in [UInt32(2), UInt32.max] {
            let value = HistoryTransferRecipientFfi(leafIndex: index, device: Data(repeating: 3, count: 32))
            let copy = try FfiConverterTypeHistoryTransferRecipientFfi.lift(
                FfiConverterTypeHistoryTransferRecipientFfi.lower(value))
            precondition(copy == value)
        }
        for value in [MarmotKitError.HistoryTransferUnsupported, .HistoryTransferNotReady,
            .HistoryTransferClosed, .HistoryTransferStaleRevision, .HistoryTransferRuntimeUnavailable] {
            let copy = try FfiConverterTypeMarmotKitError.lift(FfiConverterTypeMarmotKitError.lower(value))
            precondition(copy == value)
        }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let kit = try Marmot.newWithConfiguration(rootPath: root.path,
            relayUrls: ["ws://127.0.0.1:1"], options: MarmotOptions(
                relayPolicy: .allowLoopbackRelaysAndBlobs, secretStore: HistorySmokeStore()))
        do {
            _ = try await kit.beginHistoryTransfer(accountRef: "missing", groupIdHex: "invalid",
                recipientDevice: Data(repeating: 0, count: 65536))
            preconditionFailure("factory must refuse")
        } catch MarmotKitError.HistoryTransferUnsupported { precondition(!experimental)
        } catch MarmotKitError.HistoryTransferNotReady { precondition(experimental) }
        do {
            _ = try await kit.beginHistoryTransfer(accountRef: "missing", groupIdHex: "01",
                recipientDevice: Data(repeating: 0, count: 32))
            preconditionFailure("missing account must refuse")
        } catch MarmotKitError.HistoryTransferUnsupported { precondition(!experimental)
        } catch MarmotKitError.HistoryTransferRuntimeUnavailable { precondition(experimental) }
        for group in ["invalid", String(repeating: "ab", count: 16)] {
            do {
                _ = try await kit.historyTransferRecipients(accountRef: "missing", groupIdHex: group)
                preconditionFailure("query must refuse without an account")
            } catch MarmotKitError.HistoryTransferUnsupported { precondition(!experimental)
            } catch MarmotKitError.HistoryTransferNotReady { precondition(experimental && group == "invalid")
            } catch MarmotKitError.HistoryTransferRuntimeUnavailable { precondition(experimental && group != "invalid") }
        }
        do {
            _ = try await kit.pendingHistoryRequests(accountRef: "missing")
            preconditionFailure("missing account must not return originals")
        } catch MarmotKitError.HistoryTransferUnsupported { precondition(!experimental)
        } catch MarmotKitError.HistoryTransferRuntimeUnavailable { precondition(experimental) }
        let accounts = try kit.listAccounts()
        precondition(accounts.isEmpty)
        try await kit.shutdownAndClose()
        print("history Swift ABI: snapshots=2 recipient-records=2 errors=5 factory-gates=3 query-gates=2 no-account-effects=1 experimental=\(experimental)")
    }
}
