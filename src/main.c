#include "packet.h"
#include "serial.h"
#include "template.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char usage_text[] =
    "usage: serial-passthrough -a PORT[,BAUD[,FRAME[,FLOW]]] [-b PORT[,...]] [-p SPEC|FILE] [-t FILE] [-q BYTES]\n"
    "\n"
    "  -a, -b  serial ports, e.g. COM3,115200,8N1 or /dev/ttyUSB0,9600,7E1,rtscts\n"
    "          BAUD default 115200, FRAME <5-8><N|E|O|M|S><1|2> default 8N1, FLOW none|rtscts|xonxoff\n"
    "          without -b the app is the other end: type lines on stdin to send to A\n"
    "  -p      packet structure, e.g. \"sync:u8=0x02, msg:text(16), end:u8=0x03\" (or a file of it)\n"
    "  -t      template file: show each packet as readable text (needs -p)\n"
    "  -q      queue size per direction in bytes (default 1048576, min 4096)\n"
    "\n"
    "stdin commands (single-device mode):\n"
    "  text Hello\\r\\n     send text, C escapes allowed\n"
    "  hex 02 48 49 03     send raw bytes\n"
    "  pkt msg=\"HELLO\"     build a packet from -p (constants, lengths and CRCs fill themselves in)\n"
    "  wait MS             pause before the next command\n"
    "  expect MS PATTERN   wait up to MS for a received line matching PATTERN (* = anything), else exit 1\n"
    "  quit                exit once everything queued has been sent\n"
    "  # ...               comment\n";

struct queue {
    uint8_t *buf;
    size_t cap, head, len;
};

struct dir {
    const char *label;
    int from_device; /* single-device mode: what the device sent us */
    struct queue q;
    uint8_t pkt[2 * PKT_MAX_LEN]; /* bytes waiting to be framed for display */
    size_t plen;
};

static struct spec spec;
static struct tmpl tmpl;

/* script state (single-device mode) */
static long long wait_until;   /* no commands before this */
static char expect_pat[256];   /* waiting for a received line matching this */
static long long expect_by;
static long expect_ms;
static int quitting;
/* device lines since the last send: a reply can beat the expect line that checks it */
static char recent[16][1024];
static int nrecent;

static void usage(void)
{
    fputs(usage_text, stderr);
    exit(2);
}

static long long now_ms(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Does text contain pat, where '*' in pat matches any run of characters? */
static int glob_in(const char *text, const char *pat)
{
    char piece[sizeof expect_pat];
    while (*pat) {
        size_t n = strcspn(pat, "*");
        memcpy(piece, pat, n);
        piece[n] = '\0';
        if (n && !(text = strstr(text, piece))) return 0;
        text += n;
        pat += n;
        while (*pat == '*') pat++;
    }
    return 1;
}

/* Print one display line and check it against a pending expect. */
static void emit(const struct dir *d, const char *line)
{
    puts(line);
    if (d->from_device && nrecent < (int)(sizeof recent / sizeof *recent))
        snprintf(recent[nrecent++], sizeof recent[0], "%s", line);
    if (expect_pat[0] && d->from_device && glob_in(line, expect_pat)) {
        fflush(stdout); /* keep the ok after the line it matched */
        fprintf(stderr, "expect ok: %s\n", expect_pat);
        expect_pat[0] = '\0';
    }
}

/* Timestamp and direction label at the start of a display line; returns its length. */
static int stamp(char *out, size_t cap, const char *label)
{
    struct timespec ts;
    char t[16];
    timespec_get(&ts, TIME_UTC);
    strftime(t, sizeof t, "%H:%M:%S", localtime(&ts.tv_sec));
    return snprintf(out, cap, "%s.%03ld %-6s", t, (long)ts.tv_nsec / 1000000, label);
}

static void hexdump(const struct dir *d, const char *tag, const uint8_t *p, size_t n)
{
    char line[160];
    for (size_t i = 0; i < n; i += 16) {
        size_t m = n - i < 16 ? n - i : 16;
        int k = stamp(line, sizeof line, d->label);
        k += snprintf(line + k, sizeof line - k, "%s", tag);
        for (size_t j = 0; j < 16; j++)
            k += snprintf(line + k, sizeof line - k, j < m ? "%02X " : "   ", j < m ? p[i + j] : 0);
        line[k++] = '|';
        for (size_t j = 0; j < m; j++) line[k++] = isprint(p[i + j]) ? (char)p[i + j] : '.';
        line[k++] = '|';
        line[k] = '\0';
        emit(d, line);
    }
}

/* Frame buffered bytes into packets; bytes that don't start a packet are shown as unframed. */
static void decode(struct dir *d)
{
    static char line[6 * PKT_MAX_LEN];
    size_t pos = 0, junk = 0;
    while (pos < d->plen) {
        long r = spec_match(&spec, d->pkt + pos, d->plen - pos);
        int k;
        if (r == 0) break;
        if (r < 0) {
            junk++;
            pos++;
            continue;
        }
        if (junk) hexdump(d, "unframed ", d->pkt + pos - junk, junk);
        junk = 0;
        k = stamp(line, sizeof line, d->label);
        if (tmpl.nr && tmpl_render(&tmpl, &spec, d->pkt + pos, (size_t)r, line + k + 1, sizeof line - k - 3)) {
            line[k] = ' ';
            k += (int)strlen(line + k);
            k += snprintf(line + k, sizeof line - k, "  |");
        }
        spec_format(line + k, sizeof line - k, &spec, d->pkt + pos, (size_t)r);
        emit(d, line);
        pos += (size_t)r;
    }
    if (junk) hexdump(d, "unframed ", d->pkt + pos - junk, junk);
    d->plen -= pos;
    memmove(d->pkt, d->pkt + pos, d->plen);
}

static void show(struct dir *d, const uint8_t *p, size_t n)
{
    if (!spec.n) hexdump(d, "", p, n);
    while (spec.n && n) {
        size_t m = n < PKT_MAX_LEN ? n : PKT_MAX_LEN;
        memcpy(d->pkt + d->plen, p, m);
        d->plen += m;
        p += m;
        n -= m;
        decode(d);
    }
    fflush(stdout);
}

/* Read what `from` has into d's queue (or just display it when not forwarding). */
static int rx(sp_t from, struct dir *d, int forward)
{
    static uint8_t tmp[PKT_MAX_LEN];
    struct queue *q = &d->q;
    uint8_t *p = tmp;
    size_t n = sizeof tmp;
    long r;

    if (forward) {
        size_t tail = (q->head + q->len) % q->cap;
        p = q->buf + tail;
        n = q->cap - tail < q->cap - q->len ? q->cap - tail : q->cap - q->len;
        if (n > PKT_MAX_LEN) n = PKT_MAX_LEN;
        if (!n) return 0; /* queue full: leave bytes in the driver until the other side catches up */
    }
    if ((r = sp_read(from, p, n)) < 0) exit(1);
    show(d, p, (size_t)r);
    if (forward) q->len += (size_t)r;
    return r > 0;
}

/* Write as much of d's queue as `to` accepts right now; the port drains at its own baud rate. */
static int tx(sp_t to, struct dir *d)
{
    struct queue *q = &d->q;
    size_t n = q->cap - q->head < q->len ? q->cap - q->head : q->len;
    long r;

    if (!n) return 0;
    if ((r = sp_write(to, q->buf + q->head, n)) < 0) exit(1);
    q->head = (q->head + (size_t)r) % q->cap;
    q->len -= (size_t)r;
    return r > 0;
}

/* Turn a stdin command into bytes and queue them for the device. */
static void send_line(const char *line, struct dir *d)
{
    static uint8_t buf[PKT_MAX_LEN];
    char err[160] = "bad input or too long";
    long n;

    while (isspace((unsigned char)*line)) line++;
    if (!*line || *line == '#') return;
    if (!strncmp(line, "wait ", 5)) {
        wait_until = now_ms() + strtol(line + 5, NULL, 10);
        return;
    }
    if (!strncmp(line, "expect ", 7)) {
        char *end;
        size_t len;
        expect_ms = strtol(line + 7, &end, 10);
        while (isspace((unsigned char)*end)) end++;
        len = strlen(end);
        while (len && isspace((unsigned char)end[len - 1])) len--;
        if (end == line + 7 || !len || len >= sizeof expect_pat) {
            fputs("usage: expect MS PATTERN\n", stderr);
            return;
        }
        memcpy(expect_pat, end, len);
        expect_pat[len] = '\0';
        expect_by = now_ms() + expect_ms;
        for (int i = 0; i < nrecent && expect_pat[0]; i++) {
            if (glob_in(recent[i], expect_pat)) {
                fflush(stdout);
                fprintf(stderr, "expect ok: %s\n", expect_pat);
                expect_pat[0] = '\0';
            }
        }
        return;
    }
    if (!strcmp(line, "quit")) {
        quitting = 1;
        return;
    }
    if (!strncmp(line, "text ", 5))
        n = unescape(line + 5, '\0', buf, sizeof buf, NULL);
    else if (!strncmp(line, "hex ", 4))
        n = unhex(line + 4, strlen(line + 4), buf, sizeof buf);
    else if (!strncmp(line, "pkt", 3) && (!line[3] || line[3] == ' ') && spec.n)
        n = spec_build(&spec, line + 3, buf, sizeof buf, err, sizeof err);
    else {
        fputs("commands: text <text> | hex <bytes> | pkt field=value ... (needs -p) | wait MS"
              " | expect MS PATTERN | quit\n", stderr);
        return;
    }
    if (n < 0) {
        fprintf(stderr, "not sent: %s\n", err);
        return;
    }
    nrecent = 0; /* an expect after this send checks only replies to it */
    show(d, buf, (size_t)n);
    for (long i = 0; i < n; i++) d->q.buf[(d->q.head + d->q.len++) % d->q.cap] = buf[i];
}

/* The contents of the file at arg, or arg itself if no such file (inline specs). */
static const char *read_arg(const char *arg)
{
    static char text[65536];
    FILE *f = fopen(arg, "r");
    if (!f) return arg;
    text[fread(text, 1, sizeof text - 1, f)] = '\0';
    fclose(f);
    return text;
}

static int load_spec(const char *arg)
{
    char err[160];
    if (spec_parse(&spec, read_arg(arg), err, sizeof err)) {
        fprintf(stderr, "packet spec: %s\n", err);
        return -1;
    }
    return 0;
}

static int load_tmpl(const char *path)
{
    char err[200];
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "template: can't open %s\n", path);
        return -1;
    }
    fclose(f);
    if (tmpl_parse(&tmpl, read_arg(path), err, sizeof err)) {
        fprintf(stderr, "template %s: %s\n", path, err);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static struct dir ab, ba;
    const char *cfg_a = NULL, *cfg_b = NULL;
    size_t qsize = 1 << 20;
    char line[4096];
    int stdin_open = 1;
    sp_t a, b = 0;

    for (int i = 1; i < argc; i++) {
        const char *o = argv[i], *v = argv[i + 1];
        if (o[0] != '-' || !o[1] || o[2] || !v) usage();
        i++;
        if (o[1] == 'a') cfg_a = v;
        else if (o[1] == 'b') cfg_b = v;
        else if (o[1] == 'p' && load_spec(v)) return 2;
        else if (o[1] == 't' && load_tmpl(v)) return 2;
        else if (o[1] == 'q') qsize = strtoul(v, NULL, 0);
        else if (o[1] != 'p' && o[1] != 't') usage();
    }
    if (!cfg_a || (tmpl.nr && !spec.n) || qsize < PKT_MAX_LEN) usage();

    ab.label = cfg_b ? "A>B" : "A>APP";
    ba.label = cfg_b ? "B>A" : "APP>A";
    ab.from_device = !cfg_b;
    ab.q.cap = ba.q.cap = qsize;
    if (!(ab.q.buf = malloc(qsize)) || !(ba.q.buf = malloc(qsize))) return 1;
    if (sp_open(&a, cfg_a) || (cfg_b && sp_open(&b, cfg_b))) return 1;
    if (!cfg_b) fputs("connected; type text/hex/pkt commands to send\n", stderr);

    /* ponytail: single-threaded 1 ms poll loop; move to threads/overlapped I/O if sub-ms latency matters */
    for (;;) {
        int busy = rx(a, &ab, cfg_b != NULL);
        if (cfg_b) {
            busy |= tx(b, &ab) | rx(b, &ba, 1);
        } else if (expect_pat[0]) {
            if (now_ms() > expect_by) {
                fflush(stdout);
                fprintf(stderr, "FAIL: nothing matching \"%s\" within %ld ms\n", expect_pat, expect_ms);
                return 1;
            }
        } else if (quitting) {
            if (!ba.q.len) return 0;
        } else if (stdin_open && now_ms() >= wait_until && ba.q.cap - ba.q.len >= PKT_MAX_LEN) {
            int r = sp_stdin_line(line, sizeof line);
            if (r < 0) stdin_open = 0;
            if (r > 0) send_line(line, &ba);
        }
        busy |= tx(a, &ba);
        if (!busy) sp_idle();
    }
}
