import CryptoKit
import Foundation

// Task-only signing keys stay in this callback; no platform Keychain is used.
final class TaskSecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]
    private let credentials: URL?
    private let encryptionKey: SymmetricKey?

    init(directory: URL? = nil) throws {
        credentials = directory?.appendingPathComponent("signing-credentials.sealed")
        if let directory {
            let sealedFile = directory.appendingPathComponent("signing-credentials.sealed")
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let keyFile = directory.appendingPathComponent("credentials.key")
            let key: SymmetricKey
            if FileManager.default.fileExists(atPath: keyFile.path) {
                let bytes = try Data(contentsOf: keyFile)
                guard bytes.count == 32 else { throw AcceptanceFailure.secretMissing }
                key = SymmetricKey(data: bytes)
            } else {
                guard !FileManager.default.fileExists(atPath: sealedFile.path) else {
                    throw AcceptanceFailure.secretMissing
                }
                key = SymmetricKey(size: .bits256)
                try key.withUnsafeBytes { try Data($0).write(to: keyFile, options: .atomic) }
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)
            }
            encryptionKey = key
            if FileManager.default.fileExists(atPath: sealedFile.path) {
                let box = try AES.GCM.SealedBox(combined: Data(contentsOf: sealedFile))
                values = try JSONDecoder().decode([String: String].self, from: AES.GCM.open(box, using: key))
            }
        } else {
            encryptionKey = nil
        }
    }

    private func persist(_ next: [String: String]) throws {
        if let credentials, let encryptionKey {
            guard let bytes = try AES.GCM.seal(JSONEncoder().encode(next), using: encryptionKey).combined else {
                throw AcceptanceFailure.secretMissing
            }
            try bytes.write(to: credentials, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: credentials.path)
        }
        values = next
    }
    func hasSecretForLabel(label: String) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return values[label] != nil
    }
    func hasSecretForAccountId(accountIdHex: String) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return values[accountIdHex] != nil
    }
    func writeSecret(label: String, accountIdHex: String, secretKeyHex: String) throws {
        lock.lock()
        defer { lock.unlock() }
        var next = values
        next[label] = secretKeyHex
        next[accountIdHex] = secretKeyHex
        try persist(next)
    }
    func loadSecret(label: String, accountIdHex: String) throws -> String {
        lock.lock()
        defer { lock.unlock() }
        guard let secret = values[accountIdHex] else { throw AcceptanceFailure.secretMissing }
        return secret
    }
    func removeSecret(label: String, accountIdHex: String) throws {
        lock.lock()
        defer { lock.unlock() }
        var next = values
        next.removeValue(forKey: label)
        next.removeValue(forKey: accountIdHex)
        try persist(next)
    }
}

enum AcceptanceFailure: Error {
    case secretMissing, invalidArguments, capabilityUnavailable, unexpectedAccount, onboardingBlocked,
        comparisonMismatch, enrollmentTimeout
}

@main
struct NativeAcceptance {
    static func relayURL() throws -> String {
        #if NATIVE_ONE_SCAN_ACCEPTANCE
            if let publicRelay = ProcessInfo.processInfo.environment["NATIVE_ACCEPTANCE_PUBLIC_CHAT_RELAY"],
                !publicRelay.isEmpty
            {
                guard ["wss://relay.eu.whitenoise.chat", "wss://relay.us.whitenoise.chat"].contains(publicRelay)
                else { throw AcceptanceFailure.invalidArguments }
                return publicRelay
            }
            guard let raw = ProcessInfo.processInfo.environment["NATIVE_ACCEPTANCE_RELAY_PORT"],
                let port = Int(raw), String(port) == raw, (1024...65535).contains(port)
            else { throw AcceptanceFailure.invalidArguments }
            return "ws://127.0.0.1:\(port)"
        #else
            return "ws://127.0.0.1:18181"
        #endif
    }

    static func main() async {
        var stage = "arguments"
        let gate = CommandLine.arguments.dropFirst().first == "qr" ? "native-real-packet-qr" :
            (CommandLine.arguments.dropFirst().first == "pair" ? "native-first-pair" : "native-api")
        do {
            #if NATIVE_PAIRING_QR_ACCEPTANCE
                if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "qr" {
                    try await PairingQRControls.run(root: URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true), stage: &stage)
                    return
                }
            #endif
            if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "store" {
                try await StoreControls.run(root: URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true))
                return
            }
            if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "serve" {
                try await AcceptanceAgent.serve(root: URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true))
                return
            }
            guard CommandLine.arguments.count == 3, ["api", "pair"].contains(CommandLine.arguments[1]) else {
                throw AcceptanceFailure.invalidArguments
            }
            let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
            guard !FileManager.default.fileExists(atPath: root.path) else { throw AcceptanceFailure.invalidArguments }
            try FileManager.default.createDirectory(
                at: root, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let store = try TaskSecretStore()
            let relay = try NativeAcceptance.relayURL()
            stage = "runtime-open"
            let runtime = try Marmot.newWithConfiguration(
                rootPath: root.path, relayUrls: [relay],
                options: MarmotOptions(
                    relayPolicy: .allowLoopback, clientName: "native-acceptance",
                    secretStore: store, deployment: marmotDeploymentWhiteNoise()))
            stage = "runtime-start"
            try await runtime.start()
            do {
                stage = "capabilities"
                let capabilities = runtime.deviceLinkingCapabilities()
                guard capabilities.verificationSupported, capabilities.enrollmentSupported else {
                    throw AcceptanceFailure.capabilityUnavailable
                }
                stage = "create-identity"
                let account = try await runtime.createIdentity(
                    defaultRelays: [relay], bootstrapRelays: [relay], inboxRelays: [relay])
                guard account.localSigning, !account.signedOut else { throw AcceptanceFailure.unexpectedAccount }
                if CommandLine.arguments[1] == "pair" {
                    try await pair(runtime: runtime, account: account, store: store, root: root, stage: &stage)
                    stage = "shutdown"
                    try await runtime.shutdownAndClose()
                    print("{\"gate\":\"native-first-pair\",\"passed\":1,\"failed\":0}")
                    return
                }
                stage = "targets"
                let targets = try await runtime.deviceLinkingTargets(accountRef: account.accountIdHex)
                guard targets.isEmpty else { throw AcceptanceFailure.unexpectedAccount }
                stage = "begin-session"
                let session = try await runtime.beginDeviceLinkingSession(accountRef: account.accountIdHex)
                stage = "snapshot"
                let snapshot = try await session.snapshot()
                guard snapshot.phase == .awaitingSetup else { throw AcceptanceFailure.unexpectedAccount }
                stage = "cancel"
                try await session.cancel()
                stage = "shutdown"
                try await runtime.shutdownAndClose()
                print("{\"gate\":\"native-api\",\"passed\":1,\"failed\":0}")
            } catch {
                let original = error
                do { try await runtime.shutdownAndClose() } catch {
                    fputs("{\"cleanup_failed\":true,\"stage\":\"shutdown\"}\n", stderr)
                }
                throw original
            }
        } catch {
            // SDK error payloads can contain account IDs or private packet metadata.
            let category = error is MarmotKitError ? "sdk" : "harness"
            fputs(
                "{\"gate\":\"\(gate)\",\"stage\":\"\(stage)\",\"category\":\"\(category)\",\"passed\":0,\"failed\":1}\n",
                stderr)
            exit(1)
        }
    }
    static func drain(_ source: DeviceLinkingSession, _ recipient: DeviceLinkingSession) async throws {
        for packet in try await source.outgoingPackets() {
            guard !packet.bytes.isEmpty, packet.bytes.count <= 16384 else { throw AcceptanceFailure.unexpectedAccount }
            try await recipient.receivePacket(packet: packet.bytes)
            try await source.acknowledgePacket(acknowledgementId: packet.acknowledgementId)
        }
    }

    static func pair(
        runtime a: Marmot, account: AccountSummaryFfi, store: TaskSecretStore,
        root: URL, stage: inout String
    ) async throws {
        stage = "second-runtime-open"
        let relay = try NativeAcceptance.relayURL()
        let bStore = try TaskSecretStore()
        let bRoot = root.deletingLastPathComponent().appendingPathComponent(
            root.lastPathComponent + "-recipient", isDirectory: true)
        try FileManager.default.createDirectory(
            at: bRoot, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let b = try Marmot.newWithConfiguration(
            rootPath: bRoot.path, relayUrls: [relay],
            options: MarmotOptions(
                relayPolicy: .allowLoopback, clientName: "native-acceptance-recipient", secretStore: bStore, deployment: marmotDeploymentWhiteNoise()))
        try await b.start()
        do {
            stage = "second-public-onboarding"
            let secret = try store.loadSecret(label: account.label, accountIdHex: account.accountIdHex)
            let imported = try await onboard(runtime: b, secret: secret, stage: &stage)
            guard imported == account.accountIdHex else { throw AcceptanceFailure.unexpectedAccount }
            stage = "recipient-begin"
            let recipient = try await b.beginDeviceLinkingSession(accountRef: account.accountIdHex)
            stage = "approver-explicit-bootstrap"
            let approver = try await a.approveDeviceLinkingSession(
                accountRef: account.accountIdHex,
                request: recipient.setupPacket(), target: nil)
            do {
                stage = "sdk-setup-exchange"
                try await recipient.receiveSetupPacket(packet: approver.setupPacket())
                for _ in 0..<8 {
                    try await drain(approver, recipient)
                    try await drain(recipient, approver)
                }
                stage = "two-sided-comparison"
                let av = try await approver.snapshot()
                let bv = try await recipient.snapshot()
                guard av.phase == .comparisonAvailable, bv.phase == .comparisonAvailable,
                    av.decimals != nil, av.decimals == bv.decimals
                else { throw AcceptanceFailure.comparisonMismatch }
                try await approver.confirmComparison(displayedRevision: av.revision)
                try await recipient.confirmComparison(displayedRevision: bv.revision)
                for _ in 0..<8 {
                    try await drain(approver, recipient)
                    try await drain(recipient, approver)
                }
                stage = "explicit-enrollment"
                try await recipient.continueLinking(displayedRevision: recipient.snapshot().revision)
                try await approver.continueLinking(displayedRevision: approver.snapshot().revision)
                stage = "actual-enrollment-completion"
                var completed = false
                for _ in 0..<400 {
                    let av = try await approver.snapshot()
                    let bv = try await recipient.snapshot()
                    if av.phase == .enrollmentComplete && bv.phase == .enrollmentComplete {
                        completed = true
                        break
                    }
                    try await Task.sleep(nanoseconds: 50_000_000)
                }
                guard completed else { throw AcceptanceFailure.enrollmentTimeout }
                for runtime in [a, b] {
                    let targets = try await runtime.deviceLinkingTargets(accountRef: account.accountIdHex)
                    guard targets.count == 1, targets[0].deviceCount == 2 else {
                        throw AcceptanceFailure.unexpectedAccount
                    }
                }
                try await approver.cancel()
                try await recipient.cancel()
            } catch {
                let original = error
                for session in [approver, recipient] {
                    do { try await session.cancel() } catch {
                        fputs("{\"cleanup_failed\":true,\"stage\":\"session-cancel\"}\n", stderr)
                    }
                }
                throw original
            }
            try await b.shutdownAndClose()
        } catch {
            let original = error
            do { try await b.shutdownAndClose() } catch {
                fputs("{\"cleanup_failed\":true,\"stage\":\"recipient-shutdown\"}\n", stderr)
            }
            throw original
        }
    }

    static func onboard(runtime: Marmot, secret: String, stage: inout String) async throws -> String {
        let relay = try NativeAcceptance.relayURL()
        var onboard = try await runtime.beginOnboarding(
            nsec: secret,
            options: OnboardingOptionsFfi(defaultRelays: [relay], discoveryRelays: [relay], inboxRelays: [relay]))
        for _ in 0..<32 {
            if onboard.ready { break }
            onboard = try await runtime.runOnboarding(accountRef: onboard.accountIdHex)
            if onboard.ready { break }
            guard
                let blocked = onboard.steps.first(where: {
                    $0.status == .needsInput || $0.status == .retryableFailure
                })
            else {
                try await Task.sleep(nanoseconds: 100_000_000)
                continue
            }
            stage =
                "second-onboarding-" + String(describing: blocked.step) + "-" + String(describing: blocked.status)
            if blocked.actions.contains(.continueWithout) {
                onboard = try await runtime.continueOnboardingWithout(
                    accountRef: onboard.accountIdHex, step: blocked.step)
            } else if blocked.step == .singleDevice && blocked.actions.contains(.continueAnyway) {
                onboard = try await runtime.acknowledgeOnboardingSingleDevice(
                    accountRef: onboard.accountIdHex, revision: onboard.revision)
            } else if blocked.step == .relays || blocked.step == .inboxRelays {
                let proposal = try await runtime.proposeOnboardingRelays(
                    accountRef: onboard.accountIdHex,
                    step: blocked.step, readRelays: [relay], writeRelays: [relay])
                onboard = try await runtime.approveOnboardingRepair(
                    accountRef: onboard.accountIdHex, revision: proposal.revision)
            } else {
                throw AcceptanceFailure.onboardingBlocked
            }
        }
        guard onboard.ready else { throw AcceptanceFailure.onboardingBlocked }
        return onboard.accountIdHex
    }

}
