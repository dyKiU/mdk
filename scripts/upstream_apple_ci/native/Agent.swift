import Foundation
#if NATIVE_AUTOMATIC_ACCEPTANCE
    import CryptoKit
#endif

// Private test-controller IPC, not a native application permission surface.
struct AgentCommand: Decodable {
    let command: String
    let secret: String?
    let packet: String?
    let revision: UInt64?
    let target: String?
    let acknowledgement: String?
    let group: String?
    let member: String?
    let text: String?
    let message: String?
    let tags: [[String]]?
    let token: String?
}

final class AcceptanceAgent {
    let runtime: Marmot
    let store: TaskSecretStore
    var account: String?
    var session: DeviceLinkingSession?
    var approvals: [DeviceLinkingApproval] = []
    var copy: SelectedChatCopy?
    var consent: SelectedChatConsent?
    #if NATIVE_AUTOMATIC_ACCEPTANCE
        var sharingOriginal: AccountSharingApproval?
        var sharingPending: [AccountSharingApproval] = []
    #endif
    #if NATIVE_DEVICE_REVOCATION_ACCEPTANCE
        var revocation: DeviceRevocation?
    #endif
    #if NATIVE_HISTORY_ACCEPTANCE
        var history: HistoryTransfer?
        var historyConsents: [HistoryConsent] = []
    #endif

    init(root: URL) throws {
        let marker = root.appendingPathComponent(".native-acceptance")
        let markerBytes = Data("native-sdk83-test-only-v1\n".utf8)
        if FileManager.default.fileExists(atPath: root.path) {
            guard try Data(contentsOf: marker) == markerBytes else { throw AcceptanceFailure.invalidArguments }
        } else {
            try FileManager.default.createDirectory(
                at: root, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            try markerBytes.write(to: marker)
        }
        store = try TaskSecretStore(directory: root.appendingPathComponent("credentials", isDirectory: true))
        let relay = try NativeAcceptance.relayURL()
        var options = MarmotOptions(
            relayPolicy: .allowLoopback, clientName: "native-cross-host-acceptance", secretStore: store,
            deployment: marmotDeploymentWhiteNoise())
        #if NATIVE_ONE_SCAN_ACCEPTANCE
            if relay.hasPrefix("wss://") {
                options.relayPolicy = .publicOnly
                options.pairingRelayUrls = ["wss://nos.lol", "wss://relay.primal.net"]
            }
        #endif
        runtime = try Marmot.newWithConfiguration(
            rootPath: root.appendingPathComponent("runtime", isDirectory: true).path,
            relayUrls: [relay], options: options)
    }

    static func serve(root: URL) async throws {
        let agent = try AcceptanceAgent(root: root)
        do {
            try await agent.runtime.start()
            while let data = try boundedLine() {
                var stage = "decode-command"
                do {
                    let request = try JSONDecoder().decode(AgentCommand.self, from: data)
                    let value = try await agent.execute(request, stage: &stage)
                    try respond(["ok": true, "value": value])
                    if request.command == "close" { return }
                } catch {
                    try respond(["ok": false, "stage": stage, "category": category(error)])
                }
            }
            try await agent.close()
        } catch {
            let original = error
            do { try await agent.close() } catch {
                fputs("{\"cleanup_failed\":true,\"stage\":\"agent-close\"}\n", stderr)
            }
            throw original
        }
    }

    static func category(_ error: Error) -> String {
        switch error {
        case MarmotKitError.DeviceLinkingNotReady: return "sdk-not-ready"
        case MarmotKitError.DeviceLinkingStaleRevision: return "sdk-stale-revision"
        case MarmotKitError.DeviceLinkingClosed: return "sdk-closed"
        #if NATIVE_AUTOMATIC_ACCEPTANCE
            case MarmotKitError.UnknownGroup: return "sdk-unknown-group"
            case MarmotKitError.GroupRemoved: return "sdk-group-removed"
            case MarmotKitError.GroupDisbanding: return "sdk-group-disbanding"
            case MarmotKitError.GroupUnrecoverableRepairRequired: return "sdk-group-repair-required"
            // The owned forwarder currently exposes its no-approved-route
            // refusal through Runtime. Classify only that exact fixed literal;
            // never emit details or accept unrelated runtime failures.
            case MarmotKitError.Runtime(let details) where details == "invalid app message payload: approved chat forwarding is unavailable":
                return "sdk-forwarding-unavailable"
            case MarmotKitError.Runtime: return "sdk-runtime"
            case MarmotKitError.StorageBusy: return "sdk-storage-busy"
            case MarmotKitError.AccountSharingUnsupported: return "sdk-sharing-unsupported"
            case MarmotKitError.AccountSharingNotReady: return "sdk-sharing-not-ready"
            case MarmotKitError.AccountSharingClosed: return "sdk-sharing-closed"
            case MarmotKitError.AccountSharingStaleRevision: return "sdk-sharing-stale-revision"
            case MarmotKitError.AccountSharingRuntimeUnavailable: return "sdk-sharing-runtime-unavailable"
        #endif
        #if NATIVE_HISTORY_ACCEPTANCE
            case MarmotKitError.HistoryTransferNotReady: return "sdk-history-not-ready"
            case MarmotKitError.HistoryTransferClosed: return "sdk-history-closed"
            case MarmotKitError.HistoryTransferStaleRevision: return "sdk-history-stale-revision"
        #endif
        #if NATIVE_DEVICE_REVOCATION_ACCEPTANCE
            case MarmotKitError.DeviceRevocationUnsupported: return "sdk-device-revocation-unsupported"
            case MarmotKitError.DeviceRevocationNotReady: return "sdk-device-revocation-not-ready"
            case MarmotKitError.DeviceRevocationClosed: return "sdk-device-revocation-closed"
            case MarmotKitError.DeviceRevocationInvalidSelection: return "sdk-device-revocation-invalid-selection"
            case MarmotKitError.DeviceRevocationBusy: return "sdk-device-revocation-busy"
            case MarmotKitError.DeviceRevocationStaleRevision: return "sdk-device-revocation-stale-revision"
            case MarmotKitError.DeviceRevocationRuntimeUnavailable: return "sdk-device-revocation-runtime-unavailable"
        #endif
        default: return error is MarmotKitError ? "sdk" : "harness"
        }
    }

    static func boundedLine() throws -> Data? {
        var data = Data()
        while let byte = try FileHandle.standardInput.read(upToCount: 1), !byte.isEmpty {
            if byte[0] == 10 { return data }
            guard data.count < 65536 else { throw AcceptanceFailure.invalidArguments }
            data.append(byte)
        }
        guard data.isEmpty else { throw AcceptanceFailure.invalidArguments }
        return nil
    }

    static func respond(_ value: [String: Any]) throws {
        var data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        data.append(10)
        try FileHandle.standardOutput.write(contentsOf: data)
    }

    func bytes(_ encoded: String?) throws -> Data {
        guard let encoded, encoded.utf8.count <= 21848, let bytes = Data(base64Encoded: encoded),
            !bytes.isEmpty, bytes.count <= 16384, bytes.base64EncodedString() == encoded
        else {
            throw AcceptanceFailure.invalidArguments
        }
        return bytes
    }

    func requireAccount() throws -> String {
        guard let account else { throw AcceptanceFailure.unexpectedAccount }
        return account
    }

    func requireSession() throws -> DeviceLinkingSession {
        guard let session else { throw AcceptanceFailure.unexpectedAccount }
        return session
    }

    func requireApproval() throws -> DeviceLinkingApproval {
        guard approvals.count == 1, let original = approvals.first else {
            throw AcceptanceFailure.unexpectedAccount
        }
        return original
    }

    func requireCopy() throws -> SelectedChatCopy {
        guard let copy else { throw AcceptanceFailure.unexpectedAccount }
        return copy
    }

    func requireConsent() throws -> SelectedChatConsent {
        guard let consent else { throw AcceptanceFailure.unexpectedAccount }
        return consent
    }

    func identifier(_ value: String?) throws -> String {
        guard let value, !value.isEmpty, value.utf8.count <= 512,
            value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw AcceptanceFailure.invalidArguments }
        return value
    }

    func encoded(_ packet: Data) throws -> Any {
        guard !packet.isEmpty, packet.count <= 16384 else { throw AcceptanceFailure.invalidArguments }
        return ["packet": packet.base64EncodedString()]
    }

    func revision(_ request: AgentCommand) throws -> UInt64 {
        guard let revision = request.revision else { throw AcceptanceFailure.invalidArguments }
        return revision
    }

    func execute(_ request: AgentCommand, stage: inout String) async throws -> Any {
        switch request.command {
        #if NATIVE_DEVICE_REVOCATION_ACCEPTANCE
        case "revocation-begin":
            stage = "original-exact-device-revocation-begin"
            guard revocation == nil else { throw AcceptanceFailure.unexpectedAccount }
            let target = try bytes(request.target)
            guard target.count == 32 else { throw AcceptanceFailure.invalidArguments }
            let original = try await runtime.beginDeviceRevocation(
                accountRef: requireAccount(), targetDevice: target)
            revocation = original
            return Self.revocationObservation(try await original.snapshot())
        case "revocation-snapshot", "revocation-approve":
            stage = "held-exact-device-revocation-original"
            guard let original = revocation else { throw AcceptanceFailure.unexpectedAccount }
            if request.command == "revocation-approve" {
                try await original.approve(revision: revision(request))
            }
            return Self.revocationObservation(try await original.snapshot())
        case "revocation-cancel":
            stage = "original-exact-device-revocation-cancel"
            guard let original = revocation else { throw AcceptanceFailure.unexpectedAccount }
            original.cancel()
        case "revocation-drop":
            stage = "original-exact-device-revocation-final-alias-drop"
            guard revocation != nil else { throw AcceptanceFailure.unexpectedAccount }
            revocation = nil
        #endif
        #if NATIVE_AUTOMATIC_ACCEPTANCE
        case "package-observation":
            stage = "public-slot-observation"
            let rows = try await runtime.accountKeyPackages(
                accountRef: requireAccount(), bootstrapRelays: [try NativeAcceptance.relayURL()])
            return ["count": rows.count, "slot_set_digest": SHA256.hash(data: Data(rows.map(\.keyPackageId).sorted().joined(separator: "\n").utf8)).map { String(format: "%02x", $0) }.joined()]
        case "onboarding-begin":
            stage = "supported-onboarding-original"
            guard account == nil, let secret = request.secret, secret.utf8.count <= 256 else {
                throw AcceptanceFailure.invalidArguments
            }
            let value = try await runtime.beginOnboarding(nsec: secret, options: OnboardingOptionsFfi(
                defaultRelays: [try NativeAcceptance.relayURL()],
                discoveryRelays: [try NativeAcceptance.relayURL()],
                inboxRelays: [try NativeAcceptance.relayURL()]))
            account = value.accountIdHex
            return Self.onboardingObservation(value)
        case "onboarding-run":
            stage = "supported-onboarding-run"
            return Self.onboardingObservation(try await runtime.runOnboarding(accountRef: requireAccount()))
        case "onboarding-ack":
            stage = "supported-onboarding-explicit-revision"
            return Self.onboardingObservation(try await runtime.acknowledgeOnboardingSingleDevice(
                accountRef: requireAccount(), revision: revision(request)))
        case "continue-share":
            stage = "original-explicit-broad-pairing"
            try await requireSession().continueLinkingAndShareChats(displayedRevision: revision(request))
        case "approval-share":
            stage = "original-explicit-broad-sibling"
            try await requireApproval().approveAndShareChats(displayedRevision: revision(request))
        case "ordinary-invitations":
            stage = "ordinary-pending-invitations"
            return try runtime.chatList(accountRef: requireAccount(), includeArchived: true).filter(\.pendingConfirmation).map(\.groupIdHex)
        case "ordinary-accept":
            stage = "ordinary-explicit-invitation-accept"
            _ = try await runtime.acceptGroupInvite(accountRef: requireAccount(), groupIdHex: identifier(request.group))
        case "ordinary-invite":
            stage = "ordinary-explicit-existing-group-invite"
            let value = try await runtime.inviteMembers(
                accountRef: requireAccount(), groupIdHex: identifier(request.group),
                memberRefs: [identifier(request.member)])
            return ["published": value.published]
        #if NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE
        case "account-departure-denied-send":
            stage = "typed-account-departure-normal-send-denial"
            guard let token = request.token, !token.isEmpty, token.utf8.count <= 128,
                let text = request.text, !text.isEmpty, text.utf8.count <= 1024 else {
                throw AcceptanceFailure.invalidArguments
            }
            do {
                _ = try await runtime.sendTextWithClientToken(
                    accountRef: requireAccount(), groupIdHex: identifier(request.group),
                    text: text, clientToken: token)
                return ["denied": false]
            } catch MarmotKitError.AccountChatDepartureDenied {
                return ["denied": true]
            }
        case "account-departure-state", "account-departure-leave":
            stage = "authenticated-account-chat-departure"
            let value: AccountChatDepartureStateFfi
            if request.command == "account-departure-leave" {
                value = try await runtime.leaveAccountChat(
                    accountRef: requireAccount(), groupIdHex: identifier(request.group))
            } else {
                value = try await runtime.accountChatDepartureState(
                    accountRef: requireAccount(), groupIdHex: identifier(request.group))
            }
            return ["state": String(describing: value.status), "operation": value.operationId ?? ""]
        #endif
        case "ordinary-decline":
            stage = "actual-ordinary-explicit-invitation-decline"
            _ = try await runtime.declineGroupInvite(
                accountRef: requireAccount(), groupIdHex: identifier(request.group))
            return ["declined": true]
        case "ordinary-leave":
            stage = "actual-ordinary-nonadmin-leave"
            let value = try await runtime.leaveGroup(
                accountRef: requireAccount(), groupIdHex: identifier(request.group))
            return ["published": value.published]
        case "ordinary-delete-local":
            stage = "actual-local-only-chat-hide"
            let changed = try await runtime.deleteGroupLocal(
                accountRef: requireAccount(), groupIdHex: identifier(request.group))
            return ["changed": changed]
        case "sharing-targets":
            stage = "fresh-protected-sharing-observations"
            let value = try await runtime.accountChatSharingTargets(accountRef: requireAccount())
            return value.targets.map { ["device": $0.device.map { String(format: "%02x", $0) }.joined()] }
        case "sharing-begin":
            stage = "original-existing-pair-sharing"
            guard sharingOriginal == nil, let key = request.member, key.count == 64 else {
                throw AcceptanceFailure.invalidArguments
            }
            let bytes = stride(from: 0, to: key.count, by: 2).compactMap { offset -> UInt8? in
                let start = key.index(key.startIndex, offsetBy: offset)
                return UInt8(key[start..<key.index(start, offsetBy: 2)], radix: 16)
            }
            guard bytes.count == 32 else { throw AcceptanceFailure.invalidArguments }
            sharingOriginal = try await runtime.beginAccountChatSharing(accountRef: requireAccount(), recipientDevice: Data(bytes))
            return Self.sharingObservation(try sharingOriginal!.snapshot())
        case "sharing-pending":
            stage = "authenticated-sharing-original-intake"
            if sharingPending.isEmpty { sharingPending = try await runtime.pendingAccountChatSharing(accountRef: requireAccount()) }
            guard sharingPending.count <= 128 else { throw AcceptanceFailure.unexpectedAccount }
            return ["count": sharingPending.count]
        case "sharing-snapshot", "sharing-approve":
            stage = "held-sharing-original"
            guard let original = sharingOriginal ?? (sharingPending.count == 1 ? sharingPending.first : nil) else {
                throw AcceptanceFailure.unexpectedAccount
            }
            if request.command == "sharing-approve" { try await original.approve(displayedRevision: revision(request)) }
            return Self.sharingObservation(try original.snapshot())
        case "automatic-list":
            stage = "normal-account-list-window"
            let window = try await runtime.openAccountChatListWindow(accountRef: requireAccount(), initialRows: 128)
            defer { window.cancel() }
            guard let value = window.snapshot() else { throw AcceptanceFailure.unexpectedAccount }
            var paired: [String] = []
            var local = 0
            var localGroups: [String] = []
            for row in value.rows {
                switch row {
                case .localMls(let row):
                    local += 1
                    localGroups.append(row.row.groupIdHex)
                case .pairedSource(let row): paired.append(row.groupIdHex)
                }
            }
            return ["paired_groups": paired, "local_count": local, "local_groups": localGroups, "sequence": value.sequence]
        case "automatic-conversation":
            stage = "normal-source-qualified-conversation-window"
            let window = try await runtime.openAccountConversationWindow(
                accountRef: requireAccount(), groupIdHex: identifier(request.group), initialRows: 128)
            defer { window.cancel() }
            guard let value = window.snapshot() else { throw AcceptanceFailure.unexpectedAccount }
            let paired: Bool
            switch value.header { case .pairedSource: paired = true; case .localMls: paired = false }
            var matching: [String] = []
            for row in value.rows {
                if case .pairedSource(let actual) = row, actual.content == request.text, !actual.deleted {
                    matching.append(actual.messageIdHex)
                }
            }
            return ["paired_source": paired, "matching_ids": matching, "row_count": value.rows.count]
        case "send-token":
            stage = "durable-normal-client-token-send"
            guard let token = request.token, !token.isEmpty, token.utf8.count <= 128,
                let text = request.text, !text.isEmpty, text.utf8.count <= 1024 else { throw AcceptanceFailure.invalidArguments }
            let value = try await runtime.sendTextWithClientToken(
                accountRef: requireAccount(), groupIdHex: identifier(request.group), text: text, clientToken: token)
            return ["token": value.clientToken, "admission_id": value.messageIdHex]
        case "send-token-status":
            stage = "durable-normal-client-token-status"
            guard let token = request.token, token.utf8.count <= 128 else { throw AcceptanceFailure.invalidArguments }
            guard let status = try runtime.localSendStatus(accountRef: requireAccount(), groupIdHex: identifier(request.group), clientToken: token) else {
                return ["state": "missing"]
            }
            switch status {
            case .queued: return ["state": "queued"]
            case .engineOwned: return ["state": "engine-owned"]
            case .rejected: return ["state": "rejected"]
            case .completed(let summary): return ["state": "completed", "ordinary_ids": summary.messageIds]
            }
        #endif
        case "create":
            stage = "create-identity"
            guard account == nil, session == nil else { throw AcceptanceFailure.unexpectedAccount }
            let result = try await runtime.createIdentity(
                defaultRelays: [try NativeAcceptance.relayURL()],
                bootstrapRelays: [try NativeAcceptance.relayURL()], inboxRelays: [try NativeAcceptance.relayURL()])
            account = result.accountIdHex
            // Only the private controller pipe receives this fresh synthetic credential.
            return [
                "account": result.accountIdHex,
                "secret": try store.loadSecret(label: result.label, accountIdHex: result.accountIdHex),
            ]
        case "import":
            stage = "public-onboarding"
            guard account == nil, session == nil, let secret = request.secret, secret.utf8.count <= 256 else {
                throw AcceptanceFailure.invalidArguments
            }
            account = try await NativeAcceptance.onboard(runtime: runtime, secret: secret, stage: &stage)
            return ["account": try requireAccount()]
        case "resume":
            stage = "public-account-reopen"
            guard account == nil, session == nil, approvals.isEmpty else {
                throw AcceptanceFailure.unexpectedAccount
            }
            let accounts = try runtime.listAccounts()
            guard accounts.count == 1, let original = accounts.first, original.localSigning, !original.signedOut else {
                throw AcceptanceFailure.unexpectedAccount
            }
            account = original.accountIdHex
            return ["account": original.accountIdHex, "original_session_restored": false]
        #if NATIVE_ONE_SCAN_ACCEPTANCE
            case "create-direct-chat":
                stage = "ordinary-direct-chat-creation"
                let created = try await runtime.createGroupWithOptionsDetailed(
                    accountRef: requireAccount(), name: "", memberRefs: [identifier(request.member)],
                    options: CreateGroupOptionsFfi(description: nil, initialImage: nil, disappearingMessageSecs: 0))
                guard created.chatListRow.conversationKind == .direct else {
                    throw AcceptanceFailure.unexpectedAccount
                }
                return ["group": created.groupIdHex]
            case "direct-lookup":
                stage = "account-existing-direct-lookup"
                guard let existing = try await runtime.existingAccountDirectConversation(
                    accountRef: requireAccount(), peerAccountId: identifier(request.member)) else {
                    return ["found": false, "same_group": false, "reusable": false, "paired_source": false]
                }
                switch existing {
                case .localMls(let conversation):
                    return ["found": true, "same_group": conversation.groupIdHex == request.group,
                            "reusable": conversation.reusable, "paired_source": false]
                case .pairedSource(let conversation):
                    return ["found": true, "same_group": conversation.groupIdHex == request.group,
                            "reusable": true, "paired_source": true]
                }
            case "contact-list":
                stage = "contact-list"
                return ["accounts": try runtime.accountFollows(accountRef: requireAccount())]
            case "contact-follow", "contact-unfollow":
                stage = "contact-mutation"
                guard let member = request.member, member.utf8.count == 64,
                    member.allSatisfy({ $0.isHexDigit })
                else { throw AcceptanceFailure.invalidArguments }
                let follows = request.command == "contact-follow"
                    ? try await runtime.followUser(accountRef: requireAccount(), userRef: member)
                    : try await runtime.unfollowUser(accountRef: requireAccount(), userRef: member)
                return ["accounts": follows]
            case "one-scan-begin":
                stage = "one-scan-begin"
                guard session == nil else { throw AcceptanceFailure.unexpectedAccount }
                session = try await runtime.beginDeviceLinkingSession(accountRef: requireAccount())
                let code = try await requireSession().automaticPairingCode()
                guard code.utf8.count <= 1024, code.hasPrefix("WNPAIR1:") else {
                    throw AcceptanceFailure.invalidArguments
                }
                return ["packet": Data(code.utf8).base64EncodedString()]
            case "one-scan-approve":
                stage = "one-scan-approve"
                guard session == nil, let code = String(data: try bytes(request.packet), encoding: .utf8),
                    code.utf8.count <= 1024, code.hasPrefix("WNPAIR1:")
                else { throw AcceptanceFailure.invalidArguments }
                let target = try request.target.map { try bytes($0) }
                session = try await runtime.approveAutomaticDeviceLinkingSession(
                    accountRef: requireAccount(), code: code, target: target)
                _ = try await requireSession().automaticPairingCode()
            case "one-scan-share":
                stage = "one-scan-share"
                try await requireSession().continueAutomaticLinking(
                    displayedRevision: revision(request), shareChats: true)
        #endif
        case "begin":
            stage = "original-begin"
            guard session == nil else { throw AcceptanceFailure.unexpectedAccount }
            session = try await runtime.beginDeviceLinkingSession(accountRef: requireAccount())
            return ["packet": try requireSession().setupPacket().base64EncodedString()]
        case "approve":
            stage = "original-approve-setup"
            guard session == nil else { throw AcceptanceFailure.unexpectedAccount }
            let target = try request.target.map { try bytes($0) }
            session = try await runtime.approveDeviceLinkingSession(
                accountRef: requireAccount(), request: bytes(request.packet), target: target)
            return ["packet": try requireSession().setupPacket().base64EncodedString()]
        case "setup":
            stage = "original-receive-setup"
            try await requireSession().receiveSetupPacket(packet: bytes(request.packet))
        case "packets":
            stage = "original-outgoing-packets"
            return try await requireSession().outgoingPackets().map {
                ["acknowledgement": $0.acknowledgementId, "packet": $0.bytes.base64EncodedString()]
            }
        case "receive":
            stage = "original-receive-packet"
            try await requireSession().receivePacket(packet: bytes(request.packet))
        case "acknowledge":
            stage = "original-acknowledge-delivery"
            guard let acknowledgement = request.acknowledgement, acknowledgement.utf8.count <= 512 else {
                throw AcceptanceFailure.invalidArguments
            }
            try await requireSession().acknowledgePacket(acknowledgementId: acknowledgement)
        case "snapshot":
            stage = "original-snapshot"
            let value = try await requireSession().snapshot()
            var result: [String: Any] = ["revision": value.revision, "phase": String(describing: value.phase)]
            if let sas = value.decimals { result["comparison"] = [sas.first, sas.second, sas.third] }
            return result
        case "confirm":
            stage = "original-confirm-comparison"
            try await requireSession().confirmComparison(displayedRevision: revision(request))
        case "continue":
            stage = "original-explicit-enrollment"
            try await requireSession().continueLinking(displayedRevision: revision(request))
        case "enrollment-packet":
            stage = "original-enrollment-packet"
            let packet = try await requireSession().enrollmentPacket(displayedRevision: revision(request))
            guard !packet.isEmpty, packet.count <= 16384 else { throw AcceptanceFailure.invalidArguments }
            return ["packet": packet.base64EncodedString()]
        case "enrollment-receive":
            stage = "original-enrollment-receive"
            try await requireSession().receiveEnrollmentPacket(
                displayedRevision: revision(request), packet: bytes(request.packet))
        case "finalize":
            stage = "original-enrollment-finalize"
            try await requireSession().finalizeLinking(displayedRevision: revision(request))
        case "approval-pending":
            stage = "original-approval-acquire"
            if approvals.isEmpty {
                approvals = try await runtime.pendingDeviceLinkingApprovals(accountRef: requireAccount())
            }
            // Preserve every returned original on bounded refusal; never choose implicitly.
            guard approvals.count <= 128 else { throw AcceptanceFailure.unexpectedAccount }
            return ["count": approvals.count]
        case "approval-snapshot":
            stage = "original-approval-snapshot"
            let observed = try await requireApproval().snapshot()
            return ["revision": observed.revision, "phase": String(describing: observed.phase)]
        case "approval-review":
            stage = "original-approval-review"
            let reviewed = try await requireApproval().reviewMetadata(displayedRevision: revision(request))
            guard reviewed.revision == request.revision, reviewed.existingDeviceCount == 2,
                reviewed.sourceDevicePublicKey.count == 32, reviewed.joiningDevicePublicKey.count == 32,
                reviewed.sourceDevicePublicKey != reviewed.joiningDevicePublicKey
            else { throw AcceptanceFailure.unexpectedAccount }
            return [
                "review_valid": true,
                "source": reviewed.sourceDevicePublicKey.map { String(format: "%02x", $0) }.joined(),
                "joining": reviewed.joiningDevicePublicKey.map { String(format: "%02x", $0) }.joined(),
            ]
        case "approval-explicit":
            stage = "original-approval-explicit"
            try await requireApproval().approve(displayedRevision: revision(request))
        case "approval-receive":
            stage = "original-approval-receive"
            try await requireApproval().receiveEnrollmentPacket(
                displayedRevision: revision(request), packet: bytes(request.packet))
        case "publish-key-package":
            stage = "ordinary-key-package-publication"
            _ = try await runtime.publishNewKeyPackage(accountRef: requireAccount())
        case "create-chat":
            stage = "ordinary-create-chat"
            let group = try await runtime.createGroup(
                accountRef: requireAccount(), name: "Native acceptance chat", memberRefs: [identifier(request.member)],
                description: nil)
            return ["group": group]
        case "group-state":
            stage = "actual-chat-membership"
            let actual = try await runtime.groupMlsState(
                accountRef: requireAccount(), groupIdHex: identifier(request.group))
            return ["members": actual.memberCount, "epoch": actual.epoch]
        case "copy-begin":
            stage = "original-chat-copy-begin"
            guard copy == nil else { throw AcceptanceFailure.unexpectedAccount }
            copy = try await runtime.beginSelectedChatCopy(
                accountRef: requireAccount(), groupIdHex: identifier(request.group),
                linkedRosterSelector: bytes(request.target))
        case "copy-snapshot":
            stage = "original-chat-copy-snapshot"
            let actual = try await requireCopy().snapshot()
            return [
                "revision": actual.revision, "phase": String(describing: actual.phase), "siblings": actual.siblingCount,
                "consenting": actual.consentingSiblingCount, "offered": actual.offeredSiblingCount,
            ]
        case "copy-request":
            stage = "original-chat-copy-request"
            return try encoded(await requireCopy().requestPacket(revision: revision(request)))
        case "consent-receive":
            stage = "original-chat-consent-receive"
            guard consent == nil else { throw AcceptanceFailure.unexpectedAccount }
            consent = try await runtime.receiveSelectedChatCopyRequest(
                accountRef: requireAccount(), packet: bytes(request.packet))
        case "consent-snapshot":
            stage = "original-chat-consent-snapshot"
            let actual = try await requireConsent().snapshot()
            return [
                "revision": actual.revision, "phase": String(describing: actual.phase),
                "selector": actual.chatSelector.map { String(format: "%02x", $0) }.joined(),
            ]
        case "consent-explicit":
            stage = "original-chat-consent-explicit"
            try await requireConsent().approve(revision: revision(request))
        case "consent-response":
            stage = "original-chat-consent-response"
            return try encoded(await requireConsent().responsePacket(revision: revision(request)))
        case "consent-offer":
            stage = "original-chat-consent-offer"
            return try encoded(await requireConsent().offerPacket(revision: revision(request)))
        case "copy-response":
            stage = "original-chat-copy-response"
            try await requireCopy().receiveConsentPacket(revision: revision(request), packet: bytes(request.packet))
        case "copy-offer":
            stage = "original-chat-copy-offer"
            try await requireCopy().receiveOfferPacket(revision: revision(request), packet: bytes(request.packet))
        case "copy-continue":
            stage = "original-chat-copy-continue"
            try await requireCopy().continueCopy(revision: revision(request))
        #if NATIVE_HISTORY_ACCEPTANCE
            case "send-history-text":
                stage = "ordinary-history-tagged-text"
                guard let text = request.text, text.utf8.count == 8192,
                    let tags = request.tags, tags == [["t", "native-history"]]
                else { throw AcceptanceFailure.invalidArguments }
                let actual = try await runtime.sendTaggedText(
                    accountRef: requireAccount(), groupIdHex: identifier(request.group), text: text, tags: tags)
                guard actual.messageIds.count == 1, let id = actual.messageIds.first else {
                    throw AcceptanceFailure.unexpectedAccount
                }
                return ["message": id]
            #if NATIVE_HISTORY_RECIPIENT_QUERY
                case "history-recipients":
                    stage = "actual-history-recipient-observations"
                    let values = try await runtime.historyTransferRecipients(
                        accountRef: requireAccount(), groupIdHex: identifier(request.group))
                    return values.map {
                        [
                            "leaf_index": $0.leafIndex,
                            "device": $0.device.map { String(format: "%02x", $0) }.joined(),
                        ] as [String: Any]
                    }
            #endif
            case "history-begin":
                stage = "original-history-begin"
                guard history == nil, let key = request.member, key.count == 64,
                    key.allSatisfy({ "0123456789abcdef".contains($0) })
                else { throw AcceptanceFailure.invalidArguments }
                let decoded = stride(from: 0, to: key.count, by: 2).map { offset in
                    let start = key.index(key.startIndex, offsetBy: offset)
                    let end = key.index(start, offsetBy: 2)
                    return UInt8(key[start..<end], radix: 16)
                }
                guard decoded.allSatisfy({ $0 != nil }) else { throw AcceptanceFailure.invalidArguments }
                let recipient = decoded.compactMap { $0 }
                history = try await runtime.beginHistoryTransfer(
                    accountRef: requireAccount(), groupIdHex: identifier(request.group),
                    recipientDevice: Data(recipient))
                return historySnapshot(try await requireHistory().snapshot())
            case "history-snapshot":
                stage = "original-history-snapshot"
                return historySnapshot(try await requireHistory().snapshot())
            case "history-continue":
                stage = "original-history-continue"
                try await requireHistory().continueTransfer(revision: revision(request))
            case "history-pending":
                stage = "original-history-pending"
                if historyConsents.isEmpty {
                    historyConsents = try await runtime.pendingHistoryRequests(accountRef: requireAccount())
                }
                return ["count": historyConsents.count]
            case "history-alias-cancel":
                stage = "original-history-alias-cancellation"
                let original = try requireHistoryConsent()
                let before = try await original.snapshot()
                let aliases = try await runtime.pendingHistoryRequests(accountRef: requireAccount())
                guard aliases.count == 1, let alias = aliases.first else { throw AcceptanceFailure.unexpectedAccount }
                let same = try await alias.snapshot()
                guard same == before else { throw AcceptanceFailure.unexpectedAccount }
                alias.cancel()
                do {
                    _ = try await original.snapshot()
                    throw AcceptanceFailure.unexpectedAccount
                } catch MarmotKitError.HistoryTransferClosed {
                    return ["same_owner_cancelled": true]
                }
            case "history-alias-drop":
                stage = "original-history-final-alias-drop"
                try await dropHistoryConsentAliases()
                return ["remaining_live": true]
            case "history-cancel":
                stage = "original-history-cancellation"
                try requireHistory().cancel()
            case "history-reset":
                stage = "negative-history-owner-retirement"
                history?.cancel()
                history = nil
                for original in historyConsents { original.cancel() }
                historyConsents = []
            case "history-consent-snapshot":
                stage = "original-history-consent-snapshot"
                return historySnapshot(try await requireHistoryConsent().snapshot())
            case "history-approve":
                stage = "original-history-explicit-approval"
                try await requireHistoryConsent().approve(revision: revision(request))
            case "history-page":
                stage = "actual-synchronized-history-page"
                let page = try runtime.synchronizedHistoryPage(
                    accountRef: requireAccount(), groupIdHex: identifier(request.group),
                    afterMessageIdHex: nil, limit: 200)
                guard page.nextMessageIdHex == nil else { throw AcceptanceFailure.unexpectedAccount }
                return [
                    "records": page.records.map { record -> [String: Any] in
                        [
                            "message": record.messageIdHex, "author": record.authorPubkey,
                            "created_at": record.createdAt,
                            "expires_at": record.expiresAt.map { $0 as Any } ?? NSNull(),
                            "deleted": record.deleted, "content": record.content, "tags": record.tags.map(\.values),
                            "media_count": record.mediaAttachments.count,
                            "source": record.sourceDevice.map { String(format: "%02x", $0) }.joined(),
                            "transfer": record.transferId.map { String(format: "%02x", $0) }.joined(),
                            "manifest": record.manifestDigest.map { String(format: "%02x", $0) }.joined(),
                        ]
                    }
                ]
        #endif
        case "send-text":
            stage = "ordinary-send-text"
            guard let text = request.text, !text.isEmpty, text.utf8.count <= 1024 else {
                throw AcceptanceFailure.invalidArguments
            }
            let actual = try await runtime.sendText(
                accountRef: requireAccount(), groupIdHex: identifier(request.group), text: text)
            guard actual.messageIds.count == 1, let id = actual.messageIds.first else {
                throw AcceptanceFailure.unexpectedAccount
            }
            return ["message": id]
        case "message-seen":
            stage = "actual-delivered-message"
            let id = try identifier(request.message)
            let actual = try runtime.messages(
                accountRef: requireAccount(), groupIdHex: identifier(request.group), limit: 128, kinds: nil)
            return ["seen": actual.contains { $0.messageIdHex == id && $0.plaintext == request.text }]
        case "targets":
            stage = "actual-protected-targets"
            return try await runtime.deviceLinkingTargets(accountRef: requireAccount()).map {
                ["selector": $0.selector.base64EncodedString(), "device_count": $0.deviceCount]
            }
        case "cancel":
            stage = "original-cancel"
            try await requireSession().cancel()
            session = nil
        case "close":
            stage = "agent-close"
            try await close()
        default: throw AcceptanceFailure.invalidArguments
        }
        return NSNull()
    }

    #if NATIVE_HISTORY_ACCEPTANCE
        // Keep snapshot values, not local wrapper aliases, across the final release.
        // A later controller RPC checks pending owners after this async frame exits.
        func dropHistoryConsentAliases() async throws {
            guard historyConsents.count == 1 else { throw AcceptanceFailure.unexpectedAccount }
            let before = try await historyConsents[0].snapshot()
            var second = try await runtime.pendingHistoryRequests(accountRef: requireAccount())
            guard second.count == 1 else { throw AcceptanceFailure.unexpectedAccount }
            let same = try await second[0].snapshot()
            guard same == before, !before.complete, before.importedRecords == 0 else {
                throw AcceptanceFailure.unexpectedAccount
            }
            withExtendedLifetime(second) {}
            second.removeAll()
            let remaining = try await historyConsents[0].snapshot()
            guard remaining == before else { throw AcceptanceFailure.unexpectedAccount }
            // No cancel/approve and no returned wrapper. Generated deinit must
            // release the actual last Rust host alias; native execution tests it.
            historyConsents.removeAll()
        }

        func requireHistory() throws -> HistoryTransfer {
            guard let history else { throw AcceptanceFailure.unexpectedAccount }
            return history
        }

        func requireHistoryConsent() throws -> HistoryConsent {
            guard historyConsents.count == 1, let original = historyConsents.first else {
                throw AcceptanceFailure.unexpectedAccount
            }
            return original
        }

        func historySnapshot(_ observed: HistoryTransferSnapshotFfi) -> [String: Any] {
            [
                "revision": observed.revision, "complete": observed.complete, "imported": observed.importedRecords,
                "group": observed.groupIdHex, "records": observed.recordCount, "encoded_bytes": observed.encodedBytes,
                "fragments": observed.fragmentCount, "ceiling": observed.snapshotTimestampCeiling,
                "source": observed.sourceDevice.map { String(format: "%02x", $0) }.joined(),
                "recipient": observed.recipientDevice.map { String(format: "%02x", $0) }.joined(),
            ]
        }
    #endif

    #if NATIVE_AUTOMATIC_ACCEPTANCE
        static func sharingObservation(_ value: AccountSharingSnapshotFfi) -> [String: Any] {
            ["revision": value.revision, "approved": value.approved, "complete": value.complete,
             "protected_group": value.protectedGroupIdHex, "protected_epoch": value.protectedEpoch]
        }
        static func onboardingObservation(_ value: OnboardingSnapshotFfi) -> [String: Any] {
            ["account": value.accountIdHex, "revision": value.revision, "ready": value.ready,
             "needs_companion_ack": value.steps.contains { $0.step == .singleDevice && $0.actions.contains(.continueAnyway) }]
        }
    #endif

    #if NATIVE_DEVICE_REVOCATION_ACCEPTANCE
        static func revocationObservation(_ value: DeviceRevocationSnapshotFfi) -> [String: Any] {
            ["revision": value.revision, "complete": value.complete,
             "protected_group": value.protectedGroupIdHex,
             "ordinary_groups": value.ordinaryGroupIdsHex,
             "completed_groups": value.completedGroupIdsHex,
             "target_device": value.targetDevice.base64EncodedString()]
        }
    #endif

    func close() async throws {
        var failure: Error?
        #if NATIVE_DEVICE_REVOCATION_ACCEPTANCE
            revocation?.cancel()
            revocation = nil
        #endif
        #if NATIVE_AUTOMATIC_ACCEPTANCE
            sharingOriginal?.cancel()
            sharingOriginal = nil
            for original in sharingPending { original.cancel() }
            sharingPending = []
        #endif
        #if NATIVE_HISTORY_ACCEPTANCE
            history?.cancel()
            history = nil
            for original in historyConsents { original.cancel() }
            historyConsents = []
        #endif
        if let session {
            do {
                try await session.cancel()
                self.session = nil
            } catch MarmotKitError.DeviceLinkingClosed {
                // The SDK has already retired this exact original and its automatic transport.
                self.session = nil
            } catch {
                Self.reportCleanupFailure(error, stage: "cancel-session")
                failure = error
            }
        }
        var failedApprovals: [DeviceLinkingApproval] = []
        for original in approvals {
            do { try await original.cancel() } catch MarmotKitError.DeviceLinkingClosed {
                // A retired original has no remaining approval authority to release.
            } catch {
                Self.reportCleanupFailure(error, stage: "cancel-approval")
                failedApprovals.append(original)
                if failure == nil { failure = error }
            }
        }
        approvals = failedApprovals
        if let copy {
            do {
                try await copy.cancel()
                self.copy = nil
            } catch { if failure == nil { failure = error } }
        }
        if let consent {
            do {
                try await consent.cancel()
                self.consent = nil
            } catch { if failure == nil { failure = error } }
        }
        do { try await runtime.shutdownAndClose() } catch {
            Self.reportCleanupFailure(error, stage: "shutdown-runtime")
            if failure == nil { failure = error }
        }
        if let failure { throw failure }
    }

    private static func reportCleanupFailure(_ error: Error, stage: String) {
        // Stage arguments and categories are fixed literals; no SDK error text or payloads.
        fputs("{\"cleanup_failed\":true,\"stage\":\"\(stage)\",\"category\":\"\(category(error))\"}\n", stderr)
    }
}
