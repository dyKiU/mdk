#!/usr/bin/env python3
"""Build frozen Apple hosted products or execute one attach-only unit/UI pair in CI."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import time

# Adapted from the qualified workspace tools/run-ios-native-source-ui.py.

SDK_PATHS = (
    "Packages/MarmotKit/MARMOT_VERSION",
    "Packages/MarmotKit/Package.swift",
    "Packages/MarmotKit/Sources/MarmotKit/MarmotKit.swift",
    "Packages/MarmotKit/Sources/MarmotKit/MarmotKitVersion.swift",
    "Packages/MarmotKit/Sources/MarmotKit/Resources/PrivacyInfo.xcprivacy",
    "Vendored/MarmotKit/MARMOT_VERSION",
    "Vendored/MarmotKit/Package.swift",
    "Vendored/MarmotKit/Sources/MarmotKit/MarmotKit.swift",
    "Vendored/MarmotKit/Sources/MarmotKit/MarmotKitVersion.swift",
    "Vendored/MarmotKit/Sources/MarmotKit/Resources/PrivacyInfo.xcprivacy",
)
CONFIGURATIONS = {
    "ios": {"directory": "Debug-Staging-iphonesimulator", "target": "whitenoise-ios",
            "app": "whitenoise-ios.app", "runner": "whitenoise-iosUITests-Runner.app",
            "plan_glob": "Whitenoise (Hosted Automation)*.xctestrun", "native": "ios-arm64-simulator"},
    "macos": {"directory": "Debug", "target": "whitenoise-mac",
              "app": "White Noise Unit Host.app", "runner": "whitenoise-macUITests-Runner.app",
              "plan_glob": "whitenoise-mac*.xctestrun", "native": "macos-arm64"},
}
CONFIG = CONFIGURATIONS["ios"]
CASES = {
    "mac-source-picker": ("GenuineHistorySourcePickerTests/testHostedNativePickerButtonsWithExternalDriver",
                          "HostedHistorySourcePickerUITests/testNativeSourceSelectionRequestAndCancelButtons",
                          {}, "ready"),
    "control": ("ExternalHostedUIControlTests/testExternalDriverAttachesWithoutReplacingHostedApp",
                "HostedHistoryApprovalUITests/testExternalHostedControlTap", {"WN_EXTERNAL_UI_CONTROL": "1"}, None),
    "source-picker": ("GenuineHistorySourcePickerTests/testHostedNativeChoiceRequestAndCancelThroughPublicDriver",
                      "HostedHistorySourcePickerUITests/testExternalNativeChoiceRequestAndCancel",
                      {"WN_HISTORY_SOURCE_UI_DRIVER": "1"}, "ui-ready.json"),
    "source-transfer": ("GenuineHistorySourceTransferTests/testHostedFreshSourceTransferThroughPublicButtons",
                        "HostedHistorySourceTransferUITests/testExternalNativeChoiceRequestRefreshAndContinue",
                        {}, "ui-ready.json"),
    "approval": ("GenuineHistoryApprovalPaneTests/testHostedExplicitOriginalApprovalCommitsRealRelayImport",
                 "HostedHistoryApprovalUITests/testExternalOriginalHistoryApprovalTap",
                 {"WN_HISTORY_APPROVAL_UI_DRIVER": "1"}, "ui-ready.json"),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def freeze_source(source, commit):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if head != commit:
        raise ValueError("source-commit-mismatch")
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=source
    ).decode().split("\0")
    hashes = {}
    for name in filter(None, paths):
        path = source / name
        if not path.is_file():
            raise ValueError("tracked-or-untracked-source-file-missing")
        hashes[name] = digest(path)
        if name not in SDK_PATHS:
            original = subprocess.check_output(["git", "show", "HEAD:" + name], cwd=source)
            actual = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
            if actual != original:
                raise ValueError("non-sdk-source-diff")
    return hashes


def freeze_sdk(package, source_sha):
    manifest = package / "LOCAL_BUILD.json"
    data = json.loads(manifest.read_text())
    if data["source_sha"] != data["builder_sha"] or data["source_sha"] != source_sha or data["workflow_run_id"] != os.environ["SDK_RUN_ID"] or data["features"] != [
        "otlp-export", "product-analytics-export", "experimental-device-sync"
    ]:
        raise ValueError("sdk-cohort-mismatch")
    swift = package / "Sources/MarmotKit/MarmotKit.swift"
    if digest(swift) != data.get("installed_swift_sha256"):
        raise ValueError("installed-generated-Swift-drift")
    if "mdk-sha: " + source_sha + "\n" not in (package / "MARMOT_VERSION").read_text():
        raise ValueError("installed-SDK-version-source-mismatch")
    framework = package / "Artifacts/MarmotKit.xcframework"
    for name, value in data["artifacts"].items():
        if name.startswith("MarmotKit.xcframework/"):
            if digest(package / "Artifacts" / name) != value["sha256"]:
                raise ValueError("sdk-artifact-mismatch")
    files = {str(p.relative_to(package)): digest(p) for p in framework.rglob("*") if p.is_file()}
    for name in ["LOCAL_BUILD.json", "MARMOT_VERSION", "Package.swift",
                 "Sources/MarmotKit/MarmotKit.swift", "Sources/MarmotKit/MarmotKitVersion.swift"]:
        files[name] = digest(package / name)
    return files


def reserve_paths(prefix, bridge):
    if bridge.is_symlink():
        raise ValueError("bridge-symlink-refused")
    if not prefix.parent.is_dir() or not bridge.parent.is_dir():
        raise ValueError("existing-output-parent-required")
    if any(prefix.parent.glob(prefix.name + "-*")):
        raise ValueError("prefix-must-be-fresh")


def freeze_products(products):
    roots = [products / CONFIG["directory"] / name for name in (CONFIG["runner"], CONFIG["app"])]
    if any(not root.is_dir() for root in roots):
        raise ValueError("hosted-products-missing")
    unit_name = CONFIG["target"] + "Tests.xctest"
    standalone = products / CONFIG["directory"] / unit_name
    if standalone.is_dir():
        roots.append(standalone)
    elif not any(root.name == unit_name for root in roots[1].rglob("*.xctest")):
        raise ValueError("compiled-unit-test-bundle-missing")
    files = {str(path.relative_to(products)): digest(path)
             for root in roots for path in root.rglob("*") if path.is_file()}
    for name in ("libmarmot_uniffi.a", "include/marmot_uniffiFFI.h"):
        path = products / CONFIG["directory"] / name
        files[str(path.relative_to(products))] = digest(path)
    return files


def verify_build(manifest, frozen, sdk, products):
    result = Path(str(manifest).replace("-input.json", "-results.json"))
    receipt = json.loads(result.read_text())
    if (result == manifest or receipt.get("exit_code") != 0
            or receipt.get("unchanged") is not True or receipt.get("error_category") is not None):
        raise ValueError("successful-hosted-build-required")
    compiled = json.loads(manifest.read_text())
    plans = {str(path.relative_to(products)): digest(path) for path in products.glob(CONFIG["plan_glob"])}
    if (compiled != frozen or receipt.get("sdk") != sdk
            or receipt.get("products") != freeze_products(products) or receipt.get("plans") != plans):
        raise ValueError("compiled-input-mismatch")


def require_owned_simulator(simulator, environment):
    devices = json.loads(subprocess.check_output(["xcrun", "simctl", "list", "devices", "--json"],
                                                env=environment, text=True))["devices"]
    matches = [device for group in devices.values() for device in group if device["udid"] == simulator]
    if len(matches) != 1 or matches[0]["name"] != "WN-Upstream-UI-" + os.environ["GITHUB_RUN_ID"]:
        raise ValueError("fresh-job-owned-simulator-required")


def make_plans(original, case, environment):
    unit_id, driver_id, required, _ = CASES[case]
    environment = dict(environment, **required)
    def select(target_name, identifier):
        result = copy.deepcopy(original)
        if "TestConfigurations" in result:
            for configuration in result["TestConfigurations"]:
                targets = [target for target in configuration["TestTargets"]
                           if target.get("BlueprintName") == target_name or target.get("TargetName") == target_name]
                if len(targets) != 1:
                    raise ValueError("exactly-one-selected-test-target-required")
                configuration["TestTargets"] = targets
                entries = targets
                for entry in entries:
                    entry["OnlyTestIdentifiers"] = [identifier]
                    entry.pop("SkipTestIdentifiers", None)
                    entry.setdefault("EnvironmentVariables", {}).update(environment)
        else:
            entry = result[target_name]
            entry["OnlyTestIdentifiers"] = [identifier]
            entry.pop("SkipTestIdentifiers", None)
            entry.setdefault("EnvironmentVariables", {}).update(environment)
            result = {target_name: entry, "__xctestrun_metadata__": result["__xctestrun_metadata__"]}
        return result
    return select(CONFIG["target"] + "Tests", unit_id), select(CONFIG["target"] + "UITests", driver_id)


def exact_pass(summary):
    return (summary.get("passedTests") == 1 and summary.get("failedTests") == 0
            and summary.get("skippedTests") == 0 and summary.get("totalTestCount") == 1)


def wait_ready(process, bridge, seconds, case, log):
    deadline = time.monotonic() + seconds
    ready = CASES[case][3]
    def has_started():
        if ready is not None:
            return (bridge / ready).exists()
        return "testExternalDriverAttachesWithoutReplacingHostedApp' started" in log.read_text(errors="replace")
    while not has_started():
        if process.poll() is not None:
            raise RuntimeError("unit-ended-before-ui-ready")
        if time.monotonic() >= deadline:
            raise TimeoutError("ui-ready-timeout")
        time.sleep(0.1)


def finish(process, seconds):
    try:
        return process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        raise TimeoutError("owned-test-runner-timeout")


def summary(path, env):
    result = subprocess.run(
        ["xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(path),
         "--format", "json"], env=env, capture_output=True, text=True
    )
    if result.returncode:
        return {"summary_exit_code": result.returncode}
    value = json.loads(result.stdout)
    return {k: value[k] for k in ("result", "totalTestCount", "passedTests", "failedTests", "skippedTests")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "products", "prefix", "bridge", "sdk-package"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--build-input", type=Path)
    parser.add_argument("--stage", choices=["build", "run"], default="run")
    parser.add_argument("--case", choices=CASES, default="control")
    parser.add_argument("--environment", type=Path, help="Private fixture environment JSON; never uploaded")
    for name in ("sdk-source", "source-commit"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--simulator")
    parser.add_argument("--platform", choices=CONFIGURATIONS, default="ios")
    parser.add_argument("--developer-dir", default="/Applications/Xcode.app/Contents/Developer")
    args = parser.parse_args()
    global CONFIG
    CONFIG = CONFIGURATIONS[args.platform]
    if (args.platform == "macos") != (args.case == "mac-source-picker"):
        raise ValueError("case-platform-mismatch")
    if args.platform == "ios" and not args.simulator:
        raise ValueError("owned-simulator-required")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "macOS":
        raise ValueError("hosted-macOS-CI-only")
    os.umask(0o077)
    source, products, prefix, bridge = [p.absolute() for p in
        (args.source, args.products, args.prefix, args.bridge)]
    expected_package = source / ("Packages/MarmotKit" if args.platform == "ios" else "Vendored/MarmotKit")
    if args.sdk_package.resolve(strict=True) != expected_package.resolve(strict=True):
        raise ValueError("SDK-package-must-be-the-actual-app-overlay")
    if args.sdk_source != os.environ["SOURCE_SHA"]:
        raise ValueError("SDK-source-must-match-the-qualified-workflow-cohort")
    reserve_paths(prefix, bridge)
    frozen = freeze_source(source, args.source_commit)
    sdk = freeze_sdk(args.sdk_package, args.sdk_source)
    if args.platform == "ios":
        require_owned_simulator(args.simulator, dict(os.environ, DEVELOPER_DIR=args.developer_dir))
    subprocess.run(["bash", "-c", 'repo_root=$1; source "$repo_root/scripts/local-device-sync-settings.sh"',
                    "verify-overlay", str(source)], check=True,
                   env=dict(os.environ, WN_EXPERIMENTAL_DEVICE_SYNC="1"))
    if args.stage == "build":
        if products.name != "Products" or products.parent.name != "Build":
            raise ValueError("supported-derived-data-products-path-required")
        build_input = Path(str(prefix) + "-input.json")
        write_json(build_input, frozen)
        environment = dict(os.environ, DEVELOPER_DIR=args.developer_dir)
        command = ["xcodebuild", "build-for-testing", "-project", "whitenoise-ios.xcodeproj",
                   "-scheme", "Whitenoise (Hosted Automation)", "-destination",
                   "platform=iOS Simulator,id=" + (args.simulator or ""),
                   "-derivedDataPath", str(products.parent.parent), "-jobs", "2",
                   "-skipPackagePluginValidation", "-skipMacroValidation", "ONLY_ACTIVE_ARCH=YES",
                   "CODE_SIGN_STYLE=Manual", "DEVELOPMENT_TEAM=", "PROVISIONING_PROFILE_SPECIFIER=",
                   "CODE_SIGN_IDENTITY=-", "CODE_SIGNING_ALLOWED=YES",
                   "OTHER_SWIFT_FLAGS=$(inherited) -D WN_EXPERIMENTAL_DEVICE_SYNC"]
        build_error = None
        if args.platform == "macos":
            command = ["xcodebuild", "build-for-testing", "-project", "whitenoise-mac.xcodeproj",
                       "-scheme", "whitenoise-mac", "-configuration", "Debug", "-testPlan", "HostedAutomation",
                       "-destination", "platform=macOS,arch=arm64", "-derivedDataPath", str(products.parent.parent),
                       "-jobs", "2", "WN_APP_BUNDLE_IDENTIFIER=dev.ipf.whitenoise.mac.tests",
                       "WN_APP_PRODUCT_NAME=White Noise Unit Host", "WN_APP_DISPLAY_NAME=White Noise Unit Host",
                       "WN_APP_URL_SCHEME=marmot-tests", "CODE_SIGNING_ALLOWED=NO",
                       "OTHER_SWIFT_FLAGS=$(inherited) -D WN_EXPERIMENTAL_DEVICE_SYNC"]
        with Path(str(prefix) + "-build.log").open("x") as log:
            process = subprocess.Popen(command, cwd=source, env=environment, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                build_exit = finish(process, 1800)
            except subprocess.SubprocessError as error:
                build_error = type(error).__name__
                build_exit = process.returncode
            except TimeoutError as error:
                build_error = type(error).__name__
                build_exit = process.returncode

        if args.platform == "macos" and build_exit == 0 and build_error is None:
            for name in (CONFIG["target"] + "Tests.xctest", CONFIG["app"], CONFIG["runner"]):
                bundle = products / CONFIG["directory"] / name
                subprocess.run(["codesign", "--force", "--deep", "--sign", "-", "--timestamp=none", str(bundle)],
                               env=environment, check=True)
                subprocess.run(["codesign", "--verify", "--deep", "--strict", str(bundle)],
                               env=environment, check=True)
        unchanged = freeze_source(source, args.source_commit) == frozen and freeze_sdk(args.sdk_package, args.sdk_source) == sdk
        write_json(Path(str(prefix) + "-results.json"), {"exit_code": build_exit, "error_category": build_error,
                   "source_commit": args.source_commit, "sdk_source": args.sdk_source,
                   "unchanged": unchanged, "command": command, "sdk": sdk,
                   "products": freeze_products(products) if build_exit == 0 else {},
                   "plans": {str(path.relative_to(products)): digest(path)
                             for path in products.glob(CONFIG["plan_glob"])}})
        return 0 if build_exit == 0 and unchanged and build_error is None else 1
    if args.build_input is None:
        raise ValueError("successful-frozen-build-input-required")
    verify_build(args.build_input, frozen, sdk, products)
    plans = list(products.glob(CONFIG["plan_glob"]))
    if len(plans) != 1:
        raise ValueError("exactly-one-hosted-plan-required")
    input_plan = plans[0]
    original = plistlib.loads(input_plan.read_bytes())
    environment = json.loads(args.environment.read_text()) if args.environment else {}
    if not isinstance(environment, dict) or any(
        not isinstance(k, str) or not isinstance(v, str)
        or not (k.startswith("WN_") or k in ("GITHUB_ACTIONS", "GITHUB_RUN_ID"))
        or (k in ("GITHUB_ACTIONS", "GITHUB_RUN_ID") and v != os.environ[k])
        for k, v in environment.items()
    ):
        raise ValueError("string-fixture-environment-required")
    unit, driver = make_plans(original, args.case, environment)
    unit_plan = products / (prefix.name + "-unit.xctestrun")
    driver_plan = products / (prefix.name + "-driver.xctestrun")
    if unit_plan.exists() or driver_plan.exists():
        raise ValueError("slim-plan-must-be-fresh")
    # Keep __TESTROOT__ relative paths at the supported Build/Products location.
    unit_plan.write_bytes(plistlib.dumps(unit))
    driver_plan.write_bytes(plistlib.dumps(driver))
    plan_files = {str(path): digest(path) for path in (input_plan, unit_plan, driver_plan)}
    runner = products / CONFIG["directory"] / CONFIG["runner"]
    if args.platform == "macos":
        host = products / CONFIG["directory"] / CONFIG["app"]
        identity = plistlib.loads((host / "Contents/Info.plist").read_bytes())["CFBundleIdentifier"]
        if identity != "dev.ipf.whitenoise.mac.tests":
            raise ValueError("dedicated-Mac-test-host-identity-required")
        for bundle in (products / CONFIG["directory"] / (CONFIG["target"] + "Tests.xctest"), host, runner):
            subprocess.run(["codesign", "--verify", "--deep", "--strict", str(bundle)], check=True)
    native_archive = products / CONFIG["directory"] / "libmarmot_uniffi.a"
    native_header = products / CONFIG["directory"] / "include/marmot_uniffiFFI.h"
    if digest(native_archive) != sdk["Artifacts/MarmotKit.xcframework/" + CONFIG["native"] + "/libmarmot_uniffi.a"]:
        raise ValueError("compiled-native-archive-mismatch")
    if digest(native_header) != sdk["Artifacts/MarmotKit.xcframework/" + CONFIG["native"] + "/Headers/marmot_uniffiFFI.h"]:
        raise ValueError("compiled-native-header-mismatch")
    product_files = freeze_products(products)
    write_json(Path(str(prefix) + "-input.json"), {"source_commit": args.source_commit,
        "source": frozen, "sdk_source": args.sdk_source, "sdk": sdk,
        "products": product_files, "original_plan_sha256": digest(input_plan),
        "slim_plans": {"unit": digest(unit_plan), "driver": digest(driver_plan)},
        "build_input_sha256": digest(args.build_input)})
    env = dict(os.environ, DEVELOPER_DIR=args.developer_dir)
    report = {"source_commit": args.source_commit, "sdk_source": args.sdk_source,
              "sdk_run_id": os.environ["SDK_RUN_ID"], "case": args.case, "platform": args.platform, "source_inputs": len(frozen),
              "scope": "Actual original source unit + external public UI driver; no build or physical installation",
              "unit_exit_code": None, "driver_exit_code": None}
    start = time.monotonic()
    running = None
    ui = None
    try:
        if args.platform == "ios":
            subprocess.run(["xcrun", "simctl", "install", args.simulator, str(runner)], env=env, check=True)
        destination = "platform=iOS Simulator,id=" + args.simulator if args.platform == "ios" else "platform=macOS,arch=arm64"
        base = ["xcodebuild", "test-without-building", "-destination", destination,
                "-parallel-testing-enabled", "NO"]
        with Path(str(prefix) + "-unit.log").open("x") as output:
            running = subprocess.Popen(base + ["-xctestrun", str(unit_plan), "-resultBundlePath",
                str(prefix) + "-unit.xcresult"], stdout=output, stderr=subprocess.STDOUT,
                env=env, start_new_session=True)
            try:
                wait_ready(running, bridge, 140, args.case, Path(str(prefix) + "-unit.log"))
                with Path(str(prefix) + "-driver.log").open("x") as output_driver:
                    ui = subprocess.Popen(base + ["-xctestrun", str(driver_plan), "-resultBundlePath",
                        str(prefix) + "-driver.xcresult"], stdout=output_driver, stderr=subprocess.STDOUT,
                        env=env, start_new_session=True)
                    report["driver_exit_code"] = finish(ui, 120)
            finally:
                report["unit_exit_code"] = finish(running, 120)
    except Exception as error:
        report["runner_error_category"] = type(error).__name__
    finally:
        for owned in (ui, running):
            if owned is not None and owned.poll() is None:
                os.killpg(owned.pid, signal.SIGTERM)
                try:
                    owned.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(owned.pid, signal.SIGKILL)
                    owned.wait(timeout=10)
                report["runner_error_category"] = "OwnedRunnerRequiredTermination"
        if args.platform == "macos":
            host = products / CONFIG["directory"] / CONFIG["app"]
            registration = subprocess.run([
                "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
                "-u", str(host)], capture_output=True)
            report["owned_host_registration_cleanup_exit"] = registration.returncode
        report["seconds"] = round(time.monotonic() - start, 2)
        for key, check in [
            ("source_unchanged", lambda: freeze_source(source, args.source_commit) == frozen),
            ("sdk_unchanged", lambda: freeze_sdk(args.sdk_package, args.sdk_source) == sdk),
            ("products_unchanged", lambda: freeze_products(products) == product_files),
            ("plans_unchanged", lambda: all(digest(Path(path)) == value for path, value in plan_files.items()))
        ]:
            try:
                report[key] = check()
            except Exception:
                report[key] = False
                report["runner_error_category"] = "InputVerificationFailed"
        report["logs"] = {}
        for name in ("unit", "driver"):
            log = Path(str(prefix) + "-" + name + ".log")
            result = Path(str(prefix) + "-" + name + ".xcresult")
            if log.exists():
                report["logs"][name] = digest(log)
            if result.exists():
                try:
                    report[name] = summary(result, env)
                except (ValueError, OSError, KeyError) as error:
                    report["runner_error_category"] = type(error).__name__
        complete = bridge / "completed.json"
        # Private fixture descriptors and observations can contain synthetic account/message
        # data. Record only the finite completion booleans, never the descriptor contents.
        try:
            completion = json.loads(complete.read_text()) if complete.exists() else {}
        except (ValueError, OSError) as error:
            completion = {}
            report["runner_error_category"] = type(error).__name__
        expected = {"source-picker": {"public_actions": True, "original_cancelled": True, "runtime_closed": True},
                    "source-transfer": {"source_complete": True, "original_retired": True, "runtime_closed": True},
                    "approval": {"consent_complete": True, "imported_records": 1,
                                 "reader_verified": True, "owner_retired": True}}.get(args.case)
        report["completion_verified"] = expected is None or all(completion.get(k) == v for k, v in expected.items())
        report["passed"] = int(all(report.get(k) == 0 for k in ("unit_exit_code", "driver_exit_code"))
            and all(exact_pass(report.get(k, {})) for k in ("unit", "driver"))
            and all(report[k] for k in ("source_unchanged", "sdk_unchanged", "products_unchanged", "plans_unchanged"))
            and report["completion_verified"]
            and "runner_error_category" not in report)
        write_json(Path(str(prefix) + "-results.json"), report)
        print(json.dumps({k: report[k] for k in ("passed", "seconds", "unit_exit_code", "driver_exit_code")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
