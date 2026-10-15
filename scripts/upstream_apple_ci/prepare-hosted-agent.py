#!/usr/bin/env python3
"""Derive a diagnostic-only hosted agent without modifying frozen native sources."""
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
    args = parser.parse_args()
    source = Path(__file__).resolve().parent / "native"
    manifest = json.loads((source / "SOURCE.json").read_text())
    if manifest["workspace_commit"] != "3048d444ffe681fbae2dc1fb8e4f49d2a1c14372":
        raise ValueError("Unexpected frozen native source cohort")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    provenance = {"frozen_workspace_commit": manifest["workspace_commit"],
                  "adapter_sha256": digest(Path(__file__).read_bytes()), "files": {},
                  "adaptation": "Only classify non-SDK failures by fixed cases and the closed no-Tokio-runtime panic category; never emit descriptions or payloads."}
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
            derived = text.replace(old, new).encode()
        (args.output / name).write_bytes(derived)
        provenance["files"][name] = {"original_sha256": digest(original), "derived_sha256": digest(derived)}
    (args.output / "DERIVED-SOURCE.json").write_text(json.dumps(provenance, indent=2) + "\n")


if __name__ == "__main__":
    main()
