#!/usr/bin/env python3
"""Derive a bounded hosted acceptance agent without modifying frozen native sources."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="Fresh source directory in the runner's temporary workspace")
    parser.add_argument("--history-pagination", action="store_true",
                        help="Add a read-only history cursor command with a fixed page limit of 37")
    parser.add_argument("--automatic-history", action="store_true",
                        help="Add read-only paired chronological pagination and complete bounded live observations")
    parser.add_argument("--current-factories", action="store_true",
                        help="Separate actual beginAutomatic/scanAutomatic public fixture identity")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent / "native"
    manifest = json.loads((source / "SOURCE.json").read_text())
    if manifest["workspace_commit"] != "be04fc60b6a4c40bd85423fbf9e35e8982ae4b84":
        raise ValueError("Unexpected frozen native source cohort")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    provenance = {"frozen_workspace_commit": manifest["workspace_commit"],
                  "adapter_sha256": digest(Path(__file__).read_bytes()), "files": {},
                  "history_pagination": args.history_pagination, "automatic_history": args.automatic_history,
                  "current_factories": args.current_factories,
                  "adaptation": "Optionally add read-only bounded cursor and exact-ID observation commands; classify non-SDK failures by fixed cases and the closed no-Tokio-runtime panic category; never emit descriptions or payloads."}
    for name in ("build.sh", "Acceptance.swift", "Agent.swift", "StoreControls.swift"):
        original = (source / name).read_bytes()
        if digest(original) != manifest["files"][name]:
            raise ValueError("Frozen native source hash mismatch: " + name)
        derived = original
        if name == "Agent.swift":
            old = '        default: return error is MarmotKitError ? "sdk" : "harness"'
            new = '''        default:
            if error is MarmotKitError { return "sdk" }
            if error is CancellationError { return "harness-cancelled" }
            // Generated converters are fileprivate. Inspect only a closed set
            // of enum case names. Associated panic text remains private; only
            // the fixed missing-Tokio-context classification can leave here.
            if String(reflecting: type(of: error)).hasSuffix(".UniffiInternalError") {
                let names: Set<String> = [
                    "bufferOverflow", "incompleteData", "unexpectedOptionalTag", "unexpectedEnumCase",
                    "unexpectedNullPointer", "unexpectedRustCallStatusCode", "unexpectedRustCallError",
                    "unexpectedStaleHandle"
                ]
                let name = String(describing: error)
                if names.contains(name) { return "harness-uniffi-" + name }
                if let panic = Mirror(reflecting: error).children.first, panic.label == "rustPanic" {
                    let message = (panic.value as? String)
                        ?? (Mirror(reflecting: panic.value).children.first?.value as? String)
                    if let message,
                        message.contains("there is no reactor running"),
                        message.contains("Tokio") {
                        return "harness-uniffi-rustPanic-no-tokio-runtime"
                    }
                    return "harness-uniffi-rustPanic"
                }
                return "harness-uniffi-unclassified"
            }
            if error is DecodingError { return "harness-decoding" }
            if error is EncodingError { return "harness-encoding" }
            let cocoa = error as NSError
            let domains: Set<String> = [NSCocoaErrorDomain, NSPOSIXErrorDomain, NSURLErrorDomain]
            if domains.contains(cocoa.domain) {
                return "harness-foundation-" + cocoa.domain + "-" + String(cocoa.code)
            }
            return "harness-unclassified"'''
            text = original.decode()
            if text.count(old) != 1:
                raise ValueError("Expected one original harness category branch")
            text = text.replace(old, new)
            if args.history_pagination:
                start = text.index('            case "history-page":')
                end = text.index('        #endif', start)
                original_page = text[start:end]
                if original_page.count('case "history-page":') != 1:
                    raise ValueError("Expected one frozen history page command")
                cursor_page = original_page.replace('case "history-page":', 'case "history-page-37":')
                cursor_page = cursor_page.replace('stage = "actual-synchronized-history-page"',
                    'stage = "actual-synchronized-history-cursor-page"')
                cursor_page = cursor_page.replace('                let page = try runtime.synchronizedHistoryPage(',
                    '                if let cursor = request.message {\n'
                    '                    guard cursor.count == 64, cursor.allSatisfy({ "0123456789abcdef".contains($0) })\n'
                    '                    else { throw AcceptanceFailure.invalidArguments }\n'
                    '                }\n'
                    '                let page = try runtime.synchronizedHistoryPage(')
                cursor_page = cursor_page.replace('afterMessageIdHex: nil, limit: 200)',
                    'afterMessageIdHex: request.message, limit: 37)')
                cursor_page = cursor_page.replace('                guard page.nextMessageIdHex == nil else { throw AcceptanceFailure.unexpectedAccount }\n', '')
                cursor_page = cursor_page.replace('                return [\n',
                    '                return [\n                    "next": page.nextMessageIdHex.map { $0 as Any } ?? NSNull(),\n', 1)
                observed_id = """            case "message-seen-bounded-id":
                stage = "actual-bounded-delivered-message-id"
                let id = try identifier(request.message)
                guard id.count == 64 else { throw AcceptanceFailure.invalidArguments }
                // This fixture has at most 200 live kind-9 records. Read one
                // extra to reject an overflowing scope rather than overlook
                // an older ID hidden by the frozen controller's 128-row tail.
                let actual = try runtime.messages(
                    accountRef: requireAccount(), groupIdHex: identifier(request.group), limit: 201, kinds: [9])
                guard actual.count <= 200 else { throw AcceptanceFailure.unexpectedAccount }
                let matching = actual.filter { $0.messageIdHex == id }
                guard matching.count <= 1 else { throw AcceptanceFailure.unexpectedAccount }
                return ["seen": matching.contains { $0.plaintext == request.text }]
"""
                text = text[:end] + cursor_page + observed_id + text[end:]
            if args.automatic_history:
                fragment = Path(__file__).with_name("automatic-history-commands.swift.txt")
                fragment_bytes = fragment.read_bytes()
                additions = json.loads(Path(__file__).with_name("HOSTED-SOURCE.json").read_text())
                if digest(fragment_bytes) != additions["files"][fragment.name]["sha256"]:
                    raise ValueError("Read-only automatic-history command hash mismatch")
                fields = "    let token: String?\n"
                if text.count(fields) != 1:
                    raise ValueError("Expected one original native IPC field anchor")
                text = text.replace(fields, fields + "    let afterCreatedAt: UInt64?\n    let afterMessage: String?\n")
                anchor = '        case "automatic-list":'
                if text.count(anchor) != 1:
                    raise ValueError("Expected one original automatic observation anchor")
                text = text.replace(anchor, fragment_bytes.decode() + anchor)
                start = text.index('        case "message-seen":')
                end = text.index('        case "targets":', start)
                observed = text[start:end].replace('case "message-seen":', 'case "message-seen-256":')
                observed = observed.replace('stage = "actual-delivered-message"', 'stage = "actual-complete-bounded-live-message"')
                observed = observed.replace('limit: 128, kinds: nil)', 'limit: 257, kinds: [9])')
                observed = observed.replace('            return ["seen":',
                    '            guard actual.count <= 256 else { throw AcceptanceFailure.unexpectedAccount }\n            return ["seen":')
                text = text[:end] + observed + text[end:]
                provenance["automatic_commands_sha256"] = digest(fragment_bytes)
            if args.current_factories:
                fragment = Path(__file__).with_name("current-factory-commands.swift.txt")
                content = fragment.read_bytes()
                additions = json.loads(Path(__file__).with_name("HOSTED-SOURCE.json").read_text())
                if digest(content) != additions["files"][fragment.name]["sha256"]:
                    raise ValueError("Current-factory command source hash mismatch")
                anchor = '            case "one-scan-begin":'
                if text.count(anchor) != 1:
                    raise ValueError("Exactly one frozen automatic command anchor required")
                text = text.replace(anchor, content.decode() + anchor, 1)
                provenance["current_factory_commands_sha256"] = digest(content)
                provenance["current_factory_identity"] = "current-automatic-factories-public-existing-roster-v1"
            derived = text.encode()
        (args.output / name).write_bytes(derived)
        provenance["files"][name] = {"original_sha256": digest(original), "derived_sha256": digest(derived)}
    (args.output / "DERIVED-SOURCE.json").write_text(json.dumps(provenance, indent=2) + "\n")


if __name__ == "__main__":
    main()
