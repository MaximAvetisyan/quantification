#!/bin/sh
set -eu

here=$(dirname "$0")
edges="$here/../edges"

E='\"'
prefix='{"model":"m","messages":[{"role":"user","content":"'
suffix='"}]}'

check_size() {
    got=$(wc -c < "$1")
    if [ "$got" -ne "$2" ]; then
        echo "FAIL $1: expected $2 bytes, got $got" >&2
        exit 1
    fi
}

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
    check_size "$out" $((51 + 5 * reclen + 6 + 4 + 1))
done

shape() {
    printf '%s' "{" "$E" "$1" "$E" ":" "$E" "$2" "$E" "," \
        "$E" "$3" "$E" ":" "$E" "$4" "$E" "}"
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
check_size "$out" $((51 + 128001 + 4 + 1))

out="$edges/stage1b-no-separator-overcap.json"
{
    printf '%s' "$prefix"
    unit=0123456789abcdef
    i=0
    while [ "$i" -lt 13 ]; do
        unit="$unit$unit"
        i=$((i + 1))
    done
    printf '%s' "$unit"
    printf '%s\n' "$suffix"
} > "$out"
check_size "$edges/stage1b-no-separator-overcap.json" $((51 + 131072 + 4 + 1))

echo "generated:"
wc -c "$edges"/stage1b-record-len-*.json \
      "$edges"/single-line-tool-dump-overcap.json \
      "$edges"/stage1b-no-separator-overcap.json
