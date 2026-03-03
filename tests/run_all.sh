#!/usr/bin/env bash
# run_all.sh - Run all proxy test scripts and summarize results

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

total_pass=0
total_fail=0
total_tests=0
failed_scripts=()

echo "========================================"
echo "  Proxy Test Suite"
echo "========================================"
echo ""

for test_script in "$SCRIPT_DIR"/test_*.sh; do
    name="$(basename "$test_script")"
    echo "----------------------------------------"
    echo "Running: $name"
    echo "----------------------------------------"

    output="$(bash "$test_script" 2>&1)"
    script_exit=$?

    echo "$output"
    echo ""

    # Parse TAP-style counts from the summary line
    p="$(echo "$output" | grep '^# pass:' | awk '{print $3}')"
    f="$(echo "$output" | grep '^# fail:' | awk '{print $3}')"

    p="${p:-0}"
    f="${f:-0}"

    total_pass=$((total_pass + p))
    total_fail=$((total_fail + f))
    total_tests=$((total_tests + p + f))

    if [ "$script_exit" -ne 0 ] || [ "$f" -gt 0 ]; then
        failed_scripts+=("$name")
    fi
done

echo "========================================"
echo "  Summary"
echo "========================================"
echo "Total tests: $total_tests"
echo "Passed:      $total_pass"
echo "Failed:      $total_fail"

if [ ${#failed_scripts[@]} -gt 0 ]; then
    echo ""
    echo "Failed scripts:"
    for s in "${failed_scripts[@]}"; do
        echo "  - $s"
    done
fi

echo "========================================"

if [ "$total_fail" -gt 0 ]; then
    exit 1
fi
exit 0
