#!/usr/bin/env python3
"""Execute missing archive coverage without retrying or erasing original failures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

from recover_experimental_coverage import ANSI, make_plan, recover

REPOSITORY = "dyKiU/mdk"
COHORTS = {
    "default": (".github/workflows/ci.yml", "rust-test", "tests.tar.zst", "Rust tests"),
    "experimental": (".github/workflows/experimental-sync-ci.yml",
                     "experimental-sync-tests", "experimental-tests.tar.zst", "Experimental sync tests"),
}
PRODUCERS = {"default": "Build workspace tests", "experimental": "Build experimental sync tests"}
TERMINAL = re.compile(r"^\s*(PASS|FAIL|TIMEOUT|LEAK)\s+\[[^\]\n]+\]"
                      r"\s+\(\s*\d+/\d+\)\s+(\S+)\s+(.+?)\s*$", re.M)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def validate_origin(run, jobs, artifact, cohort, run_id, source):
    workflow, name, _, label = COHORTS[cohort]
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("Full immutable source SHA required")
    if (run["id"] != run_id or run["head_sha"] != source or run["run_attempt"] != 1
            or run["repository"]["full_name"] != REPOSITORY or run["path"] != workflow
            or run["status"] != "completed"
            or run["event"] not in ("push", "workflow_dispatch", "pull_request")):
        raise ValueError("Original run provenance mismatch or still running")
    if run["event"] == "pull_request":
        heads = run.get("pull_requests", [])
        if not heads or any(pr.get("head", {}).get("sha") != source for pr in heads):
            raise ValueError("Exact original PR head required")
        producer = pr_producer(jobs, cohort, run_id, source)
    else:
        producer = None
    if (artifact["name"] != name or artifact["expired"]
            or artifact["workflow_run"]["id"] != run_id
            or artifact["workflow_run"]["head_sha"] != source
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", ""))):
        raise ValueError("Immutable artifact provenance mismatch")
    selected = [job for job in jobs if re.fullmatch(re.escape(label) + r" \([1-5]/5\)", job["name"])]
    if ({job["name"] for job in selected} != {f"{label} ({i}/5)" for i in range(1, 6)}
            or len(selected) != 5 or len({job["id"] for job in selected}) != 5
            or (producer is not None and producer["id"] in {job["id"] for job in selected})
            or any(job["run_id"] != run_id or job["head_sha"] != source
                   or job["run_attempt"] != 1 or job["status"] != "completed" for job in selected)):
        raise ValueError("Five distinct terminal original partitions required")
    return sorted(selected, key=lambda job: job["name"])


def pr_producer(jobs, cohort, run_id, source):
    selected = [job for job in jobs if job["name"] == PRODUCERS[cohort]]
    if (len(selected) != 1 or selected[0]["run_id"] != run_id
            or selected[0]["head_sha"] != source or selected[0]["run_attempt"] != 1
            or selected[0]["status"] != "completed" or selected[0].get("conclusion") != "success"):
        raise ValueError("One successful original PR archive producer required")
    return selected[0]


def validate_pr_checkout(log, source, tree):
    clean = ANSI.sub("", log)
    for label, expected in (("source", source), ("tree", tree)):
        observed = re.findall(r"^(?:\d{4}-\d\d-\d\dT\S+\s+)?qualification-" + label
                              + r": ([^\r\n]*)\r?$", clean, re.M)
        if observed != [expected]:
            raise ValueError("PR archive checkout source/tree mismatch or missing marker")


def gh_json(endpoint):
    pages = json.loads(subprocess.check_output(["gh", "api", "--paginate", "--slurp", endpoint]))
    return pages


def fetch(args):
    args.directory.mkdir(exist_ok=False)
    endpoint = f"repos/{REPOSITORY}/actions/runs/{args.run}"
    run = gh_json(endpoint)[0]
    jobs = [job for page in gh_json(endpoint + "/attempts/1/jobs") for job in page["jobs"]]
    candidates = [item for page in gh_json(endpoint + "/artifacts") for item in page["artifacts"]
                  if item["name"] == COHORTS[args.cohort][1]]
    if len(candidates) != 1:
        raise ValueError("One original artifact required")
    artifact = candidates[0]
    selected = validate_origin(run, jobs, artifact, args.cohort, args.run, args.source)
    subprocess.run(["git", "merge-base", "--is-ancestor", args.source, "HEAD"], check=True)
    for name, value in (("original-run", run), ("original-jobs", jobs), ("original-artifact", artifact)):
        write(args.directory / (name + ".json"), value)
    hashes = {}
    pr_checkout = None
    captured = list(selected)
    if run["event"] == "pull_request":
        producer = pr_producer(jobs, args.cohort, args.run, args.source)
        captured.append(producer)
        tree = subprocess.check_output(["git", "rev-parse", args.source + "^{tree}"], text=True).strip()
    for job in captured:
        path = args.directory / f"{job['id']}.log"
        with path.open("xb") as stream:
            subprocess.run(["gh", "api", "--allow-escape-sequences",
                            f"repos/{REPOSITORY}/actions/jobs/{job['id']}/logs"], stdout=stream, check=True)
        if run["event"] == "pull_request":
            validate_pr_checkout(path.read_text(), args.source, tree)
        if job in selected:
            hashes[str(job["id"])] = digest(path)
        else:
            pr_checkout = dict(tree=tree, producer_id=job["id"], producer_log_sha256=digest(path))
    archive = args.directory / "original.zip"
    with archive.open("xb") as stream:
        subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"],
                       stdout=stream, check=True)
    if digest(archive) != artifact["digest"].removeprefix("sha256:"):
        raise ValueError("Original artifact download digest mismatch")
    tar = COHORTS[args.cohort][2]
    with zipfile.ZipFile(archive) as packed:
        members = packed.infolist()
        if (len(members) != 1 or members[0].filename != tar
                or members[0].file_size > 4 * 1024**3):
            raise ValueError("Unexpected archive members or size")
        packed.extract(members[0], args.directory)
    write(args.directory / "provenance.json", dict(source=args.source, run=args.run, cohort=args.cohort,
          artifact_id=artifact["id"], zip_sha256=digest(archive), tar=tar,
          tar_sha256=digest(args.directory / tar), original_log_hashes=hashes, pr_checkout=pr_checkout))
    archive.unlink()


def prepare_plan(inventory, logs, partitions):
    passed, remaining = recover(inventory, logs)
    missing = [row for row in remaining if row["status"] == "uncompleted"]
    failures = [row for row in remaining if row["status"] != "uncompleted"]
    plan, replacements = make_plan(missing, partitions, replace_known=False)
    if replacements:
        raise ValueError("Recovery cannot substitute cases")
    return passed, failures, [row for row in plan if row["count"]]


def plan(args):
    provenance = json.loads((args.directory / "provenance.json").read_text())
    logs = {}
    for job, expected in provenance["original_log_hashes"].items():
        path = args.directory / f"{job}.log"
        if digest(path) != expected:
            raise ValueError("Original log changed")
        logs[job] = path.read_text()
    passed, failures, selected = prepare_plan(json.loads(args.inventory.read_text()), logs, args.partitions)
    write(args.directory / "execution-plan.json", selected)
    write(args.directory / "retained-passes.json", passed)
    write(args.directory / "retained-failures.json", failures)
    write(args.directory / "summary.json", dict(provenance, retained_passes=len(passed),
          original_failures=len(failures), missing=sum(row["count"] for row in selected),
          inventory_sha256=digest(args.inventory), qualified=False,
          scope="Uncompleted cases only. Original failures require separate repair; no retry or promotion."))
    with args.github_output.open("a") as stream:
        stream.write("has_gaps=" + str(bool(selected)).lower() + "\n")
        stream.write("matrix=" + json.dumps(dict(include=[dict(partition=r["partition"])
                     for r in selected]), separators=(",", ":")) + "\n")


def verify_selection(row, inventory, execution=None):
    expected = {(case["suite"], case["test"]) for case in row["cases"]}
    selected = {(suite_id, name) for suite_id, suite in inventory["rust-suites"].items()
                for name, case in suite["testcases"].items()
                if case["filter-match"]["status"] == "matches" and not case["ignored"]}
    if not expected or len(expected) != row["count"] or selected != expected:
        raise ValueError("Actual runnable selection differs from frozen missing cases")
    if execution is not None:
        observed = {}
        for status, suite, name in TERMINAL.findall(ANSI.sub("", execution)):
            key = (suite, name)
            if key in observed or key not in expected:
                raise ValueError("Duplicate or unexpected terminal case")
            observed[key] = status
        if set(observed) != expected or any(status != "PASS" for status in observed.values()):
            raise ValueError("Missing cases did not each execute once and pass")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    f = commands.add_parser("fetch")
    f.add_argument("--run", type=int, required=True)
    f.add_argument("--source", required=True)
    f.add_argument("--cohort", choices=COHORTS, required=True)
    p = commands.add_parser("plan")
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--partitions", type=int, default=8, choices=range(1, 17))
    p.add_argument("--github-output", type=Path, required=True)
    for command in (f, p):
        command.add_argument("--directory", type=Path, required=True)
    v = commands.add_parser("verify")
    v.add_argument("--plan", type=Path, required=True)
    v.add_argument("--partition", type=int, required=True)
    v.add_argument("--inventory", type=Path, required=True)
    v.add_argument("--executed-log", type=Path)
    args = parser.parse_args()
    if args.mode == "fetch":
        if args.run <= 0:
            parser.error("positive run id required")
        fetch(args)
    elif args.mode == "plan":
        plan(args)
    else:
        rows = [row for row in json.loads(args.plan.read_text()) if row["partition"] == args.partition]
        if len(rows) != 1:
            raise ValueError("One frozen partition required")
        verify_selection(rows[0], json.loads(args.inventory.read_text()),
                         args.executed_log.read_text() if args.executed_log else None)


if __name__ == "__main__":
    main()
