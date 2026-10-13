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
        let sharingTargets = AccountSharingTargetsFfi(
            protectedGroupIdHex: String(repeating: "08", count: 16),
            protectedEpoch: UInt64.max,
            targets: [AccountSharingTargetFfi(leafIndex: 2, device: Data(repeating: 3, count: 32)),
                      AccountSharingTargetFfi(leafIndex: 7, device: Data(repeating: 4, count: 32))])
        let sharingTargetsCopy = try FfiConverterTypeAccountSharingTargetsFfi.lift(
            FfiConverterTypeAccountSharingTargetsFfi.lower(sharingTargets))
        precondition(sharingTargetsCopy == sharingTargets)
        let sharingReview = AccountSharingSnapshotFfi(
            protectedGroupIdHex: sharingTargets.protectedGroupIdHex,
            protectedEpoch: UInt64.max, sourceDevice: Data(repeating: 2, count: 32),
            recipientDevice: Data(repeating: 3, count: 32), revision: UInt64.max,
            approved: false, complete: false)
        let sharingReviewCopy = try FfiConverterTypeAccountSharingSnapshotFfi.lift(
            FfiConverterTypeAccountSharingSnapshotFfi.lower(sharingReview))
        precondition(sharingReviewCopy == sharingReview)
        let packet = DeviceLinkingOutgoingPacketFfi(acknowledgementId: "frame/probe", bytes: Data([0, 255, 0, 1]))
        let packetCopy = try FfiConverterTypeDeviceLinkingOutgoingPacketFfi.lift(
            FfiConverterTypeDeviceLinkingOutgoingPacketFfi.lower(packet))
        precondition(packetCopy == packet)
        let copyPhases: [SelectedChatCopyPhaseFfi] = [.awaitingSiblingConsent, .cancelled, .expired, .closed, .inviteConfirmed]
        for phase in copyPhases {
            let value = SelectedChatCopySnapshotFfi(revision: UInt64.max, phase: phase,
                siblingCount: 2, consentingSiblingCount: 2, offeredSiblingCount: 2)
            let copy = try FfiConverterTypeSelectedChatCopySnapshotFfi.lift(
                FfiConverterTypeSelectedChatCopySnapshotFfi.lower(value))
            precondition(copy == value)
        }
        let consentPhases: [SelectedChatConsentPhaseFfi] = [.awaitingApproval, .approved, .cancelled, .expired, .closed]
        for phase in consentPhases {
            let value = SelectedChatConsentSnapshotFfi(revision: UInt64.max, phase: phase,
                chatSelector: Data([0, 255, 0, 1]))
            let copy = try FfiConverterTypeSelectedChatConsentSnapshotFfi.lift(
                FfiConverterTypeSelectedChatConsentSnapshotFfi.lower(value))
            precondition(copy == value)
        }
        let revocation = DeviceRevocationSnapshotFfi(revision: UInt64.max, complete: false,
            protectedGroupIdHex: "00ff", ordinaryGroupIdsHex: ["01", "aabb"],
            completedGroupIdsHex: ["01"], targetDevice: Data([0, 255, 0, 1]))
        let revocationCopy = try FfiConverterTypeDeviceRevocationSnapshotFfi.lift(
            FfiConverterTypeDeviceRevocationSnapshotFfi.lower(revocation))
        precondition(revocationCopy == revocation)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let kit = try Marmot.newWithConfiguration(rootPath: root.path,
            relayUrls: ["ws://127.0.0.1:1"], options: MarmotOptions(
                relayPolicy: .allowLoopbackRelaysAndBlobs, secretStore: DeviceSmokeStore()))
        let caps = kit.deviceLinkingCapabilities()
        precondition(caps.enrollmentSupported == caps.verificationSupported)
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
        for action in 0..<3 {
            do {
                switch action {
                case 0: _ = try await kit.accountChatSharingTargets(accountRef: "missing")
                case 1: _ = try await kit.beginAccountChatSharing(
                    accountRef: "missing", recipientDevice: Data(repeating: 0, count: 32))
                default: _ = try await kit.pendingAccountChatSharing(accountRef: "missing")
                }
                preconditionFailure("missing account must not expose sharing originals")
            } catch MarmotKitError.AccountSharingUnsupported {
                precondition(!caps.verificationSupported)
            } catch MarmotKitError.AccountSharingRuntimeUnavailable {
                precondition(caps.verificationSupported)
            }
        }
        do {
            _ = try await kit.beginSelectedChatCopy(accountRef: "missing", groupIdHex: "01", linkedRosterSelector: Data([2]))
            preconditionFailure("missing account must not create a selected-chat request")
        } catch MarmotKitError.SelectedChatCopyUnsupported {
            precondition(!caps.verificationSupported)
        } catch MarmotKitError.SelectedChatCopyRuntimeUnavailable {
            precondition(caps.verificationSupported)
        }
        do {
            _ = try await kit.receiveSelectedChatCopyRequest(accountRef: "missing", packet: Data([1]))
            preconditionFailure("missing account must not create a selected-chat consent")
        } catch MarmotKitError.SelectedChatCopyUnsupported {
            precondition(!caps.verificationSupported)
        } catch MarmotKitError.SelectedChatCopyRuntimeUnavailable {
            precondition(caps.verificationSupported)
        }
        do {
            _ = try await kit.beginDeviceRevocation(accountRef: "missing", targetDevice: Data(repeating: 1, count: 32))
            preconditionFailure("missing account must not create an original revocation")
        } catch MarmotKitError.DeviceRevocationUnsupported {
            precondition(!caps.verificationSupported)
        } catch MarmotKitError.DeviceRevocationRuntimeUnavailable {
            precondition(caps.verificationSupported)
        }
        precondition(accounts.isEmpty)
        try await kit.shutdownAndClose()
        print("Swift device linking ABI: session/approval/selected-chat and account-sharing DTO round trips, ordered device inventory, capability, typed factory/observation gates and shutdown passed; experimental=\(caps.verificationSupported)")
    }
}
