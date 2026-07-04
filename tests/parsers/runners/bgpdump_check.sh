#!/usr/bin/env bash
set -Eeuo pipefail

CORPUS_DIR="${1:-/corpus}"
STRICT="${MRTGEN_STRICT:-0}"
FAILURES=()

run_one() {
    local label="$1"
    local path="$2"
    local mode="$3"
    local out="/tmp/${label//\//_}.out"
    local err="/tmp/${label//\//_}.err"
    local rc

    set +e
    timeout 30s bgpdump -m "$path" >"$out" 2>"$err"
    rc=$?
    set -e

    local lines stderr_bytes
    lines="$(wc -l <"$out")"
    stderr_bytes="$(wc -c <"$err")"
    echo "$label: rc=$rc; output_lines=$lines; stderr_bytes=$stderr_bytes"

    if [[ "$mode" == "valid" ]]; then
        if [[ "$rc" -ne 0 || "$lines" -eq 0 ]]; then
            FAILURES+=("bgpdump failed to parse the valid-only corpus")
        fi
        return
    fi

    if [[ "$rc" -eq 124 ]]; then
        FAILURES+=("bgpdump timed out on $label")
    elif [[ "$rc" -ge 128 ]]; then
        FAILURES+=("bgpdump crashed or was killed on $label with rc=$rc")
    elif [[ "$STRICT" == "1" && "$mode" == "full" && "$rc" -ne 0 ]]; then
        FAILURES+=("bgpdump returned non-zero on malformed full corpus in strict mode")
    elif [[ "$STRICT" == "1" && "$mode" == "fatal" && "$rc" -eq 0 ]]; then
        FAILURES+=("bgpdump accepted fatal-tail file in strict mode: $label")
    fi
}

run_one "bgp-valid.mrt" "$CORPUS_DIR/bgp-valid.mrt" valid
run_one "bgp-corpus.mrt" "$CORPUS_DIR/bgp-corpus.mrt" full

for fatal in "$CORPUS_DIR"/bgp-fatal/*.mrt; do
    [[ -e "$fatal" ]] || continue
    run_one "bgp-fatal/$(basename "$fatal")" "$fatal" fatal
done

if ((${#FAILURES[@]})); then
    echo "failures:" >&2
    for failure in "${FAILURES[@]}"; do
        echo "  - $failure" >&2
    done
    exit 1
fi
