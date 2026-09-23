#!/usr/bin/env bash
# End-to-end over pseudo-terminals:  dev1 <-> A [serial-passthrough] B <-> dev2
set -eu
bin=$1
d=$(mktemp -d)
pids=()
trap 'kill "${pids[@]}" 2>/dev/null; rm -rf "$d"' EXIT
spec='sync:u8=0x02, msg:text(5), end:u8=0x03'

socat pty,rawer,link="$d/dev1" pty,rawer,link="$d/a" & pids+=($!)
socat pty,rawer,link="$d/dev2" pty,rawer,link="$d/b" & pids+=($!)
sleep 1
cat "$d/dev1" > "$d/got1" & pids+=($!)
cat "$d/dev2" > "$d/got2" & pids+=($!)

# Two devices, different bauds, smallest queue so 20 kB has to wait on backpressure.
"$bin" -a "$d/a,115200" -b "$d/b,9600" -q 4096 -p "$spec" > "$d/log" & pt=$!; pids+=($pt)
sleep 1
head -c 20000 /dev/urandom > "$d/big"
{ printf '\002HELLO\003'; cat "$d/big"; } > "$d/sent"
cat "$d/sent" > "$d/dev1"
printf 'reply' > "$d/dev2"
sleep 3
cmp "$d/sent" "$d/got2"
cmp <(printf 'reply') "$d/got1"
grep -q 'A>B    sync=0x02 msg="HELLO" end=0x03' "$d/log"
kill "$pt"
wait "$pt" 2>/dev/null || true

# One device: the app sends from stdin and decodes what the device sends back.
printf 'pkt msg="HI"\nhex 41 42\n' | "$bin" -a "$d/a" -p "$spec" > "$d/log2" 2>/dev/null & pt=$!; pids+=($pt)
sleep 1
printf '\002WORLD\003' > "$d/dev1"
sleep 1
cmp <(printf 'reply\002HI\0\0\0\003AB') "$d/got1"
grep -q 'APP>A  sync=0x02 msg="HI\\x00\\x00\\x00" end=0x03' "$d/log2"
grep -q 'A>APP  sync=0x02 msg="WORLD" end=0x03' "$d/log2"
kill "$pt"
wait "$pt" 2>/dev/null || true

# Scripts: an expect that is met lets the script run on to quit (exit 0) ...
(sleep 1; printf '\002PONG!\003' > "$d/dev1") & pids+=($!)
printf '# ping\npkt msg="PING"\nexpect 3000 A>APP*msg="PONG!"\nwait 100\nquit\n' |
    "$bin" -a "$d/a" -p "$spec" > /dev/null 2>&1
# ... and one that isn't exits 1; what we send ourselves never satisfies it.
if printf 'pkt msg="NEVER"\nexpect 300 msg="NEVER"\nquit\n' | "$bin" -a "$d/a" -p "$spec" > /dev/null 2>&1; then
    echo "unmet expect should fail"; exit 1
fi
echo ok
