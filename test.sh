#!/usr/bin/env bash
# Copyright (c) 2026 bentzn
# SPDX-License-Identifier: Apache-2.0
# Author Claude/bentzn
#
# The one-command all-green check, and the build. Same shape as
# `raposza/test.sh` and for the same reason.
#
# A GREEN REACTOR DOES NOT PROVE THE TESTS RAN: a module whose sources failed
# to be picked up reports SUCCESS in the same column as one that executed every
# case. Every module below must produce a surefire report with a non-zero
# EXECUTED count.
#
# "Executed" and "total" are separate on purpose. Surefire's tests= attribute
# counts SKIPPED cases too, so a suite that was entirely disabled yields the
# same total as one that fully ran.
#
# The reports are DELETED before the run: surefire writes one file per test
# class and never removes one, so a renamed class leaves its last result behind
# for ever and every later run adds it to the totals.
#
# The module list is DERIVED, not maintained - `raposza/test.sh` records what a
# hand-edited list cost twice.
set -eu
cd "$(dirname "$0")"

MODULES_WITH_TESTS=$(find . \
        -path './*/target/*' -prune -o \
        -path '*/src/test/java/*' \
        \( -name '*Test.java' -o -name 'Test*.java' \
           -o -name '*Tests.java' -o -name '*TestCase.java' \) \
        -print \
    | sed 's|/src/test/java/.*||; s|^\./||' | sort -u)

if [ -z "$MODULES_WITH_TESTS" ]; then
    echo "FAIL: no module under this tree holds a test source at all" >&2
    exit 1
fi

for m in $MODULES_WITH_TESTS; do
    rm -rf "$m/target/surefire-reports"
done

mvn -B install

echo
rc=0
for m in $MODULES_WITH_TESTS; do
    dir="$m/target/surefire-reports"
    if [ ! -d "$dir" ]; then
        echo "FAIL: $m produced no surefire reports - its tests did not run"
        rc=1
        continue
    fi

    cnt_total=$(grep -ho 'tests="[0-9]*"' "$dir"/TEST-*.xml 2>/dev/null |
                sed 's/[^0-9]//g' | awk '{s+=$1} END {print s+0}')
    cnt_skip=$(grep -ho 'skipped="[0-9]*"' "$dir"/TEST-*.xml 2>/dev/null |
               sed 's/[^0-9]//g' | awk '{s+=$1} END {print s+0}')
    cnt_run=$((cnt_total - cnt_skip))

    if [ "$cnt_run" -eq 0 ]; then
        echo "FAIL: $m reported $cnt_total tests but EXECUTED none"
        rc=1
    elif [ "$cnt_skip" -gt 0 ]; then
        echo "ran: $m - $cnt_run executed, $cnt_skip SKIPPED"
    else
        echo "ran: $m - $cnt_run executed"
    fi
done

if [ "$rc" -ne 0 ]; then
    echo "test: FAILED"
    exit 1
fi

echo "test: OK"
