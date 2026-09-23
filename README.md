# serial-passthrough

Sit between two serial devices, forward everything in both directions, and watch what passes, optionally
decoded into named packet fields. Or connect one device and talk to it yourself.

```
device A <──> [ serial-passthrough ] <──> device B
                      │
                   your terminal
```

## Usage

```
serial-passthrough -a PORT[,BAUD[,FRAME[,FLOW]]] [-b PORT[,...]] [-p SPEC|FILE] [-q BYTES]
```

| Option | |
|---|---|
| `-a`, `-b` | Ports with their own settings, e.g. `COM3,115200,8N1` or `/dev/ttyUSB0,9600,7E1,rtscts`. BAUD default `115200`, FRAME `<5-8><N\|E\|O\|M\|S><1\|2>` default `8N1`, FLOW `none\|rtscts\|xonxoff`. |
| `-p` | Packet structure (see below), inline or a file containing it. |
| `-q` | Queue size per direction in bytes (default 1 MiB, min 4096). |

```sh
# watch a 115200 baud controller talk to a 9600 baud module
serial-passthrough -a COM3,115200 -b COM4,9600 -p "sync:u8=0x02, msg:text(16), end:u8=0x03"
```
```
14:02:11.482 A>B    sync=0x02 msg="HELLO WORLD 1234" end=0x03
14:02:11.519 B>A    unframed 41 43 4B 0D 0A                                 |ACK..|
```
Without `-p` every chunk prints as hex + ASCII. Redirect stdout to keep a log.

### Different baud rates, no dropped bytes

Each direction has its own queue. Bytes read from the sender go into the queue and leave at the speed the
receiver's port can send, so the slow side gets everything, just later. If a queue fills, the tool stops reading
from the sender and the bytes wait in the OS driver. Enable `rtscts` or `xonxoff` on the sender's port so the OS
can pause the sending device. Without flow control, a sender that keeps outpacing the receiver will eventually
overflow its OS buffer; no software can prevent that.

### One device: talk to it yourself

Leave out `-b` and the app is the other end. Incoming data is displayed (`A>APP`), and lines you type are sent
(`APP>A`):

```
text Hello\r\n          send text (escapes: \r \n \t \0 \xNN \\ \")
hex 02 48 49 03         send raw bytes
pkt msg="HELLO"         build a packet from -p and send it
```

`pkt` fills in constants, length fields and CRCs for you, other integers default to 0 (`pkt cmd=5 data=0A0B`), and
fixed-size fields are zero-padded. A blob value can mix hex and quoted text with no spaces between them:
`payload=0007"HomeNet"`.

### Scripts

Commands can be piped in from a file: `serial-passthrough -a COM3 -p spec.txt < script.txt`. These commands
make that file a test:

```
wait 1500                       pause before the next command (e.g. while the device boots)
expect 1000 type=2*seq=5        wait up to 1000 ms for a received line matching the pattern, else exit 1
quit                            exit 0 once everything queued has been sent
# comment
```

The pattern is matched against the displayed line of each packet (or hex dump line) the device sends, and
`*` matches anything, so `expect 500 flags=1 type=2 seq=5` checks fields. Nothing after an `expect` is sent
until it's met. A script that doesn't end in `quit` stays connected so you can keep watching.

## Packet structure

Fields separated by commas or newlines, `#` starts a comment:

| Type | |
|---|---|
| `name:u8`, `u16`, `u32` | Integer, little-endian by default; add `be`/`le` (`u16be`). |
| `name:u8=0x02` | Constant: used to find where packets start (and end). |
| `name:bytes(16)` / `name:text(16)` | Fixed-size blob, shown as hex / as text. |
| `name:bytes(len)` / `name:text(len-2)` | Size taken from an earlier integer field, with an optional `+N`/`-N` adjustment. |
| `name:crc16ccitt(first..last)` | CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) over fields `first` through `last`, little-endian unless `be`. Checked when decoding, computed by `pkt`. |

```
# spec.txt
sync:u16be=0xAA55
len:u16be          # payload + crc
payload:bytes(len-2)
crc:crc16ccitt(len..payload)
```

Bytes that don't fit the structure (including a bad CRC) are shown as `unframed` and the decoder resyncs on the next byte.
Only display is affected; the bytes are always forwarded unchanged. Packets are capped at 4096 bytes.

## Build

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release     # packet tests; plus an end-to-end pty test on Linux if socat is installed
```

Windows (MSVC or MinGW), Linux and macOS. Pushing a `v*` tag builds all three and publishes a GitHub release.
