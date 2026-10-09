import Foundation

private final class DeviceSmokeStore: SecretStore, @unchecked Sendable {
    func hasSecretForLabel(label: String) throws -> Bool { false }
    func hasSecretForAccountId(accountIdHex: String) throws -> Bool { false }
    func writeSecret(label: String, accountIdHex: String, secretKeyHex: String) throws {}
    func loadSecret(label: String, accountIdHex: String) throws -> String { fatalError("no accounts") }
    func removeSecret(label: String, accountIdHex: String) throws {}
}

@main
struct DeviceLinkingSmoke {
    static func main() async throws {
        let phases: [DeviceLinkingPhaseFfi] = [.awaitingSetup, .awaitingPeer,
            .comparisonAvailable, .awaitingPeerVerification,
            .verificationCompleteEnrollmentPending, .cancelled, .expired, .failed, .enrollmentComplete]
        for phase in phases {
            for decimals in [nil, DeviceLinkingDecimalsFfi(first: 1234, second: 5678, third: 9012)] {
                let value = DeviceLinkingSnapshotFfi(revision: UInt64.max, phase: phase, decimals: decimals)
                let copy = try FfiConverterTypeDeviceLinkingSnapshotFfi.lift(
                    FfiConverterTypeDeviceLinkingSnapshotFfi.lower(value))
                precondition(copy == value)
            }
        }
        let approvalPhases: [DeviceLinkingApprovalPhaseFfi] = [.awaitingApproval,
            .approvedAwaitingPacket, .awaitingSettlement, .settled, .cancelled, .expired]
        for phase in approvalPhases {
            let value = DeviceLinkingApprovalSnapshotFfi(revision: UInt64.max, phase: phase)
            let copy = try FfiConverterTypeDeviceLinkingApprovalSnapshotFfi.lift(
                FfiConverterTypeDeviceLinkingApprovalSnapshotFfi.lower(value))
            precondition(copy == value)
        }
        let target = DeviceLinkingTargetFfi(selector: Data([0, 255, 0, 1]), deviceCount: 3)
        let targetCopy = try FfiConverterTypeDeviceLinkingTargetFfi.lift(
            FfiConverterTypeDeviceLinkingTargetFfi.lower(target))
        precondition(targetCopy == target)
        let packet = DeviceLinkingOutgoingPacketFfi(acknowledgementId: "frame/probe", bytes: Data([0, 255, 0, 1]))
        let packetCopy = try FfiConverterTypeDeviceLinkingOutgoingPacketFfi.lift(
            FfiConverterTypeDeviceLinkingOutgoingPacketFfi.lower(packet))
        precondition(packetCopy == packet)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let kit = try Marmot.newWithConfiguration(rootPath: root.path,
            relayUrls: ["ws://127.0.0.1:1"], options: MarmotOptions(
                relayPolicy: .allowLoopbackRelaysAndBlobs, secretStore: DeviceSmokeStore()))
        let caps = kit.deviceLinkingCapabilities()
        precondition(!caps.enrollmentSupported)
        if caps.verificationSupported {
            do {
                _ = try await kit.approveDeviceLinkingSession(accountRef: "missing", request: Data(), target: Data([1]))
                preconditionFailure("missing account must not reserve an existing-group action")
            } catch MarmotKitError.DeviceLinkingRuntimeUnavailable {}
        } else {
            do {
                _ = try await kit.beginDeviceLinkingSession(accountRef: "missing")
                preconditionFailure("default factory must return Unsupported")
            } catch MarmotKitError.DeviceLinkingUnsupported {}
        }
        do {
            _ = try await kit.deviceLinkingTargets(accountRef: "missing")
            preconditionFailure("missing account must not expose a target")
        } catch MarmotKitError.DeviceLinkingUnsupported {
            precondition(!caps.verificationSupported)
        } catch MarmotKitError.DeviceLinkingRuntimeUnavailable {
            precondition(caps.verificationSupported)
        }
        do {
            _ = try await kit.pendingDeviceLinkingApprovals(accountRef: "missing")
            preconditionFailure("missing account must not reserve approval handles")
        } catch MarmotKitError.DeviceLinkingUnsupported {
            precondition(!caps.verificationSupported)
        } catch MarmotKitError.DeviceLinkingRuntimeUnavailable {
            precondition(caps.verificationSupported)
        }
        let accounts = try kit.listAccounts()
        precondition(accounts.isEmpty)
        try await kit.shutdownAndClose()
        print("Swift device linking ABI: 18 session + 6 approval snapshots, binary target/packet round trips, capability, typed factory/observation gates and shutdown passed; experimental=\(caps.verificationSupported)")
    }
}
