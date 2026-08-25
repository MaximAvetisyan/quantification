#!/bin/sh
# W0.3 — generator for the GENERATED stage-1b fixtures (tasks/W0.3-corpus.md).
#
# Deterministic: POSIX sh + coreutils tr only; fixed inputs, no clock/RNG.
# Outputs are committed; rerunning must be byte-idempotent (self-checked below).
#
# All lengths are raw escaped bytes inside the JSON string value.
#   record      = {"pad":"<pad>","k":<d>}   escaped -> 22 + len(pad) bytes
#   record line = "[" R1 "," ... "," R5 "]"          -> 5*reclen + 6 bytes
#   envelope    = 51-byte prefix + line + 4-byte suffix + trailing LF
set -eu

here=$(dirname "$0")
edges="$here/../edges"

# E is the two-byte sequence backslash + double-quote, as it appears inside a
# JSON string value. Single-quoted so nothing processes the backslash.
E='\"'
prefix='{"model":"m","messages":[{"role":"user","content":"'
suffix='"}]}'

check_size() { # $1=file $2=expected
    got=$(wc -c < "$1")
    if [ "$got" -ne "$2" ]; then
        echo "FAIL $1: expected $2 bytes, got $got" >&2
        exit 1
    fi
}

# --- stage1b-record-len-{16383,16384,16385}.json -----------------------------
# Five records of exactly the target length (max_record_bytes +/- 1), joined by
# commas inside brackets; whole line exceeds max_line_bytes (65536).
for reclen in 16383 16384 16385; do
    pad_len=$((reclen - 22))
    pad=$(printf '%*s' "$pad_len" '' | tr ' ' 'x')
    out="$edges/stage1b-record-len-$reclen.json"
    {
        printf '%s[' "$prefix"
        k=1
        while [ "$k" -le 5 ]; do
            [ "$k" -gt 1 ] && printf ','
            printf '%s' "{" "$E" 'pad' "$E" ':' "$E" "$pad" "$E" ',' \
                "$E" 'k' "$E" ':' "$k" "}"
            k=$((k + 1))
        done
        printf ']%s\n' "$suffix"
    } > "$out"
    # 51 (prefix) + (5*reclen + 4 commas + 2 brackets) + 4 (suffix) + 1 (LF)
    check_size "$out" $((51 + 5 * reclen + 6 + 4 + 1))
done

# --- single-line-tool-dump-overcap.json --------------------------------------
# One line > max_line_bytes, dense with "},{" separators; every record stays
# far below max_record_bytes. 3072 records cycling three shapes.
shape() { # $1=key $2=value1 $3=key2 $4=value2 -> one escaped record
    printf '%s' "{" "$E" "$1" "$E" ":" "$E" "$2" "$E" "," \
        "$E" "$3" "$E" ":" "$4" "$E" "}"
}
out="$edges/single-line-tool-dump-overcap.json"
{
    printf '%s[' "$prefix"
    i=0
    while [ "$i" -lt 3072 ]; do
        [ "$i" -gt 0 ] && printf ','
        case $(($i % 3)) in
            0) shape lvl info msg heartbeat ;;
            1) shape lvl warn msg 'slow disk 42' ;;
            2) shape lvl info msg 'retry ok' ;;
        esac
        i=$((i + 1))
    done
    printf ']%s\n' "$suffix"
} > "$out"

# --- stage1b-no-separator-overcap.json ---------------------------------------
# One line > max_line_bytes with zero "},{" occurrences: must stay verbatim.
out="$edges/stage1b-no-separator-overcap.json"
{
    printf '%s' "$prefix"
    unit=0123456789abcdef
    i=0
    while [ "$i" -lt 13 ]; do
        unit="$unit$unit"
        i=$((i + 1))
    done
    printf '%s' "$unit" # 16 * 2^13 = 131072 bytes
    printf '%s\n' "$suffix"
} > "$out"
check_size "$edges/stage1b-no-separator-overcap.json" $((51 + 131072 + 4 + 1))

echo "generated:"
wc -c "$edges"/stage1b-record-len-*.json \
      "$edges"/single-line-tool-dump-overcap.json \
      "$edges"/stage1b-no-separator-overcap.json
