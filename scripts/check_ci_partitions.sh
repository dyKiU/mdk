#!/usr/bin/env bash
# Every selected test must appear in exactly one shard, including ignored tests.
set -euo pipefail

partitions="$1"
shift
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

list_tests() {
    cargo nextest list --message-format json "$@" |
        jq -r '."rust-suites" | to_entries[] | .key as $suite | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches") | "\($suite)::\(.key)"'
}

# Reuse the required complete inventory to report ignored cases separately from
# runnable selections and partition filters; archive size is not an execution count.
cargo nextest list --message-format json "$@" > "$work_dir/inventory.json"
jq -r '."rust-suites" | to_entries[] | .key as $suite | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches") | "\($suite)::\(.key)"' \
    "$work_dir/inventory.json" | sort > "$work_dir/expected"
jq -c '[."rust-suites"[].testcases[]] as $cases |
    ($cases | map(select(.["filter-match"].status == "matches"))) as $selected |
    {inventory_total: ($cases | length),
     selected_total: ($selected | length),
     ignored_total: ($cases | map(select(.ignored)) | length),
     selected_ignored: ($selected | map(select(.ignored)) | length),
     selected_runnable: ($selected | map(select(.ignored | not)) | length),
     filtered: (($cases | length) - ($selected | length))}' "$work_dir/inventory.json" >&2
test -s "$work_dir/expected"
for ((partition = 1; partition <= partitions; partition++)); do
    list_tests "$@" --partition "count:$partition/$partitions" >> "$work_dir/actual"
done
sort "$work_dir/actual" -o "$work_dir/actual"
diff -u "$work_dir/expected" "$work_dir/actual"
