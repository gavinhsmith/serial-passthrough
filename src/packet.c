#include "packet.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do { snprintf(err, errlen, __VA_ARGS__); return -1; } while (0)

static int find(const struct spec *s, const char *name, size_t len)
{
    for (int i = 0; i < s->n; i++)
        if (strlen(s->f[i].name) == len && !strncmp(s->f[i].name, name, len))
            return i;
    return -1;
}

static int parse_field(struct spec *s, char *tok, char *err, size_t errlen)
{
    struct field *f = &s->f[s->n];
    char *type = strchr(tok, ':'), *val, *end;

    if (s->n == PKT_MAX_FIELDS) FAIL("too many fields (max %d)", PKT_MAX_FIELDS);
    if (!type) FAIL("'%s': expected name:type", tok);
    *type++ = '\0';
    if ((val = strchr(type, '='))) *val++ = '\0';
    memset(f, 0, sizeof *f);
    f->ref = -1;
    if (!*tok || strlen(tok) >= sizeof f->name) FAIL("bad field name '%s'", tok);
    if (find(s, tok, strlen(tok)) >= 0) FAIL("duplicate field '%s'", tok);
    strcpy(f->name, tok);

    if (s->n && s->f[s->n - 1].rest) FAIL("%s: nothing can follow a (*) field", tok);
    if (type[0] == 'u' || type[0] == 'i') {
        long bits = strtol(type + 1, &end, 10);
        if (bits != 8 && bits != 16 && bits != 32) FAIL("%s: integer type must be u8/i8, u16/i16 or u32/i32", tok);
        f->width = (int)bits / 8;
        f->sign = type[0] == 'i';
        if (!strcmp(end, "be")) f->be = 1;
        else if (*end && strcmp(end, "le")) FAIL("%s: unknown byte order '%s'", tok, end);
    } else if (!strncmp(type, "bytes(", 6) || !strncmp(type, "text(", 5)) {
        char *arg = strchr(type, '(') + 1, *close = strchr(arg, ')');
        f->text = type[0] == 't';
        if (!close || close[1]) FAIL("%s: expected %s(size)", tok, f->text ? "text" : "bytes");
        *close = '\0';
        if (!strcmp(arg, "*")) {
            f->rest = 1;
        } else if (isdigit((unsigned char)*arg)) {
            unsigned long c = strtoul(arg, &end, 10);
            if (*end || c == 0 || c > PKT_MAX_LEN) FAIL("%s: size must be 1..%d", tok, PKT_MAX_LEN);
            f->count = c;
        } else {
            size_t nl = strcspn(arg, "+-");
            f->ref = find(s, arg, nl);
            if (f->ref < 0 || !s->f[f->ref].width)
                FAIL("%s: length '%.*s' must be an earlier integer field", tok, (int)nl, arg);
            f->adj = arg[nl] ? strtol(arg + nl, &end, 0) : 0;
            if (arg[nl] && *end) FAIL("%s: bad length adjustment '%s'", tok, arg + nl);
        }
    } else if (!strncmp(type, "crc16ccitt(", 11)) {
        char *arg = type + 11, *close = strchr(arg, ')'), *dots = strstr(arg, "..");
        if (!close || !dots || dots > close) FAIL("%s: expected crc16ccitt(first..last)", tok);
        f->crc_from = find(s, arg, (size_t)(dots - arg));
        f->crc_to = find(s, dots + 2, (size_t)(close - dots - 2));
        if (f->crc_from < 0 || f->crc_to < f->crc_from)
            FAIL("%s: crc range must be earlier fields, first..last", tok);
        f->crc = 1;
        f->width = 2;
        if (!strcmp(close + 1, "be")) f->be = 1;
        else if (close[1] && strcmp(close + 1, "le")) FAIL("%s: unknown byte order '%s'", tok, close + 1);
    } else {
        FAIL("%s: unknown type '%s'", tok, type);
    }

    if (val) {
        if (!f->width || f->crc) FAIL("%s: only integer fields can have a constant", tok);
        f->value = (uint32_t)strtoul(val, &end, 0);
        if (!*val || *end || (f->width < 4 && f->value >> (8 * f->width)))
            FAIL("%s: bad constant '%s'", tok, val);
        f->is_const = 1;
    }
    s->n++;
    return 0;
}

int spec_parse(struct spec *s, const char *text, char *err, size_t errlen)
{
    char tok[128];
    size_t n = 0;

    s->n = 0;
    for (const char *p = text;; p++) {
        if (*p == '#') p += strcspn(p, "\n");
        if (*p == ',' || *p == '\n' || *p == '\0') {
            tok[n] = '\0';
            if (n && parse_field(s, tok, err, errlen)) return -1;
            n = 0;
            if (!*p) break;
        } else if (!isspace((unsigned char)*p)) {
            if (n == sizeof tok - 1) FAIL("field definition too long");
            tok[n++] = *p;
        }
    }
    if (!s->n) FAIL("empty packet spec");
    return 0;
}

static uint32_t rd(const uint8_t *p, int w, int be)
{
    uint32_t v = 0;
    for (int i = 0; i < w; i++) v |= (uint32_t)p[be ? w - 1 - i : i] << (8 * i);
    return v;
}

static void wr(uint8_t *p, int w, int be, uint32_t v)
{
    for (int i = 0; i < w; i++) p[be ? w - 1 - i : i] = (uint8_t)(v >> (8 * i));
}

/* Byte length of a field given the integer values before it and the bytes left; -1 if out of range. */
static long flen(const struct field *f, const uint32_t *v, size_t left)
{
    long long l;
    if (f->width) return f->width;
    if (f->rest) return left > PKT_MAX_LEN ? -1 : (long)left;
    if (f->ref < 0) return (long)f->count;
    l = (long long)v[f->ref] + f->adj;
    return l < 0 || l > PKT_MAX_LEN ? -1 : (long)l;
}

uint16_t crc16_ccitt(const uint8_t *p, size_t n)
{
    uint16_t crc = 0xFFFF;
    while (n--) {
        crc ^= (uint16_t)(*p++ << 8);
        for (int k = 0; k < 8; k++) crc = (uint16_t)(crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1);
    }
    return crc;
}

/* Text output that truncates instead of overflowing. */
struct out {
    char *p;
    size_t cap, len;
};

static void put(struct out *o, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (!o || o->len + 1 >= o->cap) return;
    va_start(ap, fmt);
    n = vsnprintf(o->p + o->len, o->cap - o->len, fmt, ap);
    va_end(ap);
    if (n > 0) o->len = o->len + (size_t)n < o->cap ? o->len + (size_t)n : o->cap - 1;
}

static void put_val(struct out *o, const struct fval *v)
{
    const struct field *f = v->f;
    if (f->width && (f->is_const || f->crc)) {
        put(o, "0x%0*lX", f->width * 2, (unsigned long)v->v);
    } else if (f->width && f->sign) {
        int sh = 32 - 8 * f->width;
        put(o, "%ld", (long)((int32_t)(v->v << sh) >> sh));
    } else if (f->width) {
        put(o, "%lu", (unsigned long)v->v);
    } else {
        for (size_t i = 0; i < v->len; i++) {
            uint8_t c = v->p[i];
            if (!f->text) put(o, i ? " %02X" : "%02X", c);
            else if (c == '"' || c == '\\') put(o, "\\%c", c);
            else if (isprint(c)) put(o, "%c", c);
            else put(o, "\\x%02X", c);
        }
    }
}

void fval_str(const struct fval *v, char *buf, size_t cap)
{
    struct out o = {buf, cap, 0};
    buf[0] = '\0';
    put_val(&o, v);
}

/* Walks n bytes at b, filling vals (when set) with each field.
 * Returns the byte count, -1 if they don't fit the spec, -2 if more bytes are needed. */
static long walk(const struct spec *s, const uint8_t *b, size_t n, struct fval *vals)
{
    uint32_t v[PKT_MAX_FIELDS];
    size_t start[PKT_MAX_FIELDS + 1], off = 0;

    for (int i = 0; i < s->n; i++) {
        const struct field *f = &s->f[i];
        long len = flen(f, v, n - off);
        start[i] = off;
        if (len < 0 || off + len > PKT_MAX_LEN) return -1;
        if (off + len > n) return -2;
        if (f->width) {
            v[i] = rd(b + off, f->width, f->be);
            if (f->is_const && v[i] != f->value) return -1;
            if (f->crc && v[i] != crc16_ccitt(b + start[f->crc_from], start[f->crc_to + 1] - start[f->crc_from]))
                return -1;
        }
        if (vals) {
            vals[i].f = f;
            vals[i].v = f->width ? v[i] : 0;
            vals[i].p = b + off;
            vals[i].len = (size_t)len;
        }
        off += len;
        start[i + 1] = off;
    }
    return (long)off;
}

long spec_match(const struct spec *s, const uint8_t *buf, size_t n)
{
    long r = walk(s, buf, n, NULL);
    return r == -2 ? 0 : r == 0 ? -1 : r; /* an empty match can't frame anything */
}

int spec_values(const struct spec *s, const uint8_t *b, size_t n, struct fval *out)
{
    return walk(s, b, n, out) >= 0 ? s->n : -1;
}

void spec_format(char *buf, size_t cap, const struct spec *s, const uint8_t *pkt, size_t n)
{
    struct fval v[PKT_MAX_FIELDS];
    struct out o = {buf, cap, 0};
    buf[0] = '\0';
    if (walk(s, pkt, n, v) < 0) return;
    for (int i = 0; i < s->n; i++) {
        const struct field *f = v[i].f;
        put(&o, " %s=%s", f->name, f->width ? "" : f->text ? "\"" : "[");
        put_val(&o, &v[i]);
        put(&o, "%s", f->width ? "" : f->text ? "\"" : "]");
    }
}

long spec_build(const struct spec *s, const char *args, uint8_t *out, size_t cap, char *err, size_t errlen)
{
    static uint8_t data[PKT_MAX_FIELDS][PKT_MAX_LEN];
    long dlen[PKT_MAX_FIELDS] = {0};
    uint32_t v[PKT_MAX_FIELDS] = {0};
    int set[PKT_MAX_FIELDS] = {0};
    size_t start[PKT_MAX_FIELDS + 1];
    const char *p = args;
    size_t off = 0;

    for (;;) {
        const struct field *f;
        size_t nl;
        int i;
        while (isspace((unsigned char)*p)) p++;
        if (!*p) break;
        nl = strcspn(p, "= \t");
        if ((i = find(s, p, nl)) < 0) FAIL("unknown field '%.*s'", (int)nl, p);
        f = &s->f[i];
        if (p[nl] != '=') FAIL("expected %s=value", f->name);
        if (f->is_const || f->crc) FAIL("%s is %s", f->name, f->crc ? "computed" : "a constant");
        p += nl + 1;
        set[i] = 1;
        if (f->width) {
            char *end;
            if (f->sign) {
                long sv = strtol(p, &end, 0), lim = 1L << (8 * f->width - 1);
                if (f->width < 4 && (sv < -lim || sv >= lim)) FAIL("%s: value out of range", f->name);
                v[i] = f->width < 4 ? (uint32_t)sv & ((1u << (8 * f->width)) - 1) : (uint32_t)sv;
            } else {
                v[i] = (uint32_t)strtoul(p, &end, 0);
            }
            if (end == p || (*end && !isspace((unsigned char)*end))) FAIL("%s: bad number", f->name);
            p = end;
        } else {
            /* hex digits and "quoted text", mixed, up to the next space */
            dlen[i] = 0;
            while (*p && !isspace((unsigned char)*p)) {
                long m;
                if (*p == '"') {
                    m = unescape(p + 1, '"', data[i] + dlen[i], PKT_MAX_LEN - (size_t)dlen[i], &p);
                    if (m < 0 || *p != '"') FAIL("%s: unterminated or too long string", f->name);
                    p++;
                } else {
                    size_t tl = strcspn(p, " \t\"");
                    if ((m = unhex(p, tl, data[i] + dlen[i], PKT_MAX_LEN - (size_t)dlen[i])) < 0)
                        FAIL("%s: value must be hex digits and/or \"text\"", f->name);
                    p += tl;
                }
                dlen[i] += m;
            }
        }
    }

    for (int i = 0; i < s->n; i++) {
        const struct field *f = &s->f[i];
        if (f->is_const) v[i] = f->value;
        else if (f->ref >= 0 && !set[f->ref]) v[f->ref] = (uint32_t)(dlen[i] - f->adj);
    }

    for (int i = 0; i < s->n; i++) {
        const struct field *f = &s->f[i];
        long len = f->rest ? dlen[i] : flen(f, v, 0);
        start[i] = off;
        if (len < 0 || off + len > cap) FAIL("%s: length out of range", f->name);
        if (f->crc)
            v[i] = crc16_ccitt(out + start[f->crc_from], start[f->crc_to + 1] - start[f->crc_from]);
        if (f->width) {
            if (f->width < 4 && v[i] >> (8 * f->width)) FAIL("%s: value too large", f->name);
            wr(out + off, f->width, f->be, v[i]);
        } else {
            if (dlen[i] > len) FAIL("%s: longer than %ld bytes", f->name, len);
            memcpy(out + off, data[i], dlen[i]);
            memset(out + off + dlen[i], 0, len - dlen[i]);
        }
        off += len;
        start[i + 1] = off;
    }
    return (long)off;
}

long unescape(const char *s, char stop, uint8_t *out, size_t cap, const char **endp)
{
    size_t n = 0;
    while (*s && *s != stop) {
        int c = (unsigned char)*s++;
        if (c == '\\' && *s) {
            c = (unsigned char)*s++;
            if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
            else if (c == '0') c = 0;
            else if (c == 'x' && isxdigit((unsigned char)*s)) {
                char h[3] = {s[0], isxdigit((unsigned char)s[1]) ? s[1] : 0, 0};
                c = (int)strtol(h, NULL, 16);
                s += h[1] ? 2 : 1;
            }
        }
        if (n == cap) return -1;
        out[n++] = (uint8_t)c;
    }
    if (endp) *endp = s;
    return (long)n;
}

long unhex(const char *s, size_t len, uint8_t *out, size_t cap)
{
    const char *e = s + len;
    size_t n = 0;
    while (s < e) {
        char h[3] = {0};
        if (isspace((unsigned char)*s)) { s++; continue; }
        if (e - s < 2 || !isxdigit((unsigned char)s[0]) || !isxdigit((unsigned char)s[1]) || n == cap) return -1;
        h[0] = s[0];
        h[1] = s[1];
        out[n++] = (uint8_t)strtol(h, NULL, 16);
        s += 2;
    }
    return (long)n;
}
