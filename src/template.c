#include "template.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do { snprintf(err, errlen, "line %d: ", line); \
                       snprintf(err + strlen(err), errlen - strlen(err), __VA_ARGS__); return -1; } while (0)

/* Copy the next whitespace-separated token of s into tok; returns the text after it. */
static const char *token(const char *s, char *tok, size_t cap)
{
    size_t n = 0;
    while (isspace((unsigned char)*s)) s++;
    while (*s && !isspace((unsigned char)*s)) {
        if (n + 1 < cap) tok[n++] = *s;
        s++;
    }
    tok[n] = '\0';
    return s;
}

static int parse_line(struct tmpl *t, const char *s, int line, char *err, size_t errlen)
{
    char tok[128];

    s = token(s, tok, sizeof tok);
    if (!*tok || *tok == '#') return 0;

    if (!strcmp(tok, "enum")) {
        struct tenum *e = &t->e[t->ne];
        if (t->ne == TMPL_MAX_ENUMS) FAIL("too many enums (max %d)", TMPL_MAX_ENUMS);
        s = token(s, tok, sizeof tok);
        if (!*tok || strlen(tok) >= sizeof e->name) FAIL("expected enum NAME VALUE=LABEL ...");
        strcpy(e->name, tok);
        e->n = 0;
        for (s = token(s, tok, sizeof tok); *tok; s = token(s, tok, sizeof tok)) {
            char *eq = strchr(tok, '='), *end;
            if (e->n == TMPL_MAX_LABELS) FAIL("enum %s: too many values (max %d)", e->name, TMPL_MAX_LABELS);
            if (!eq) FAIL("enum %s: expected VALUE=LABEL, got '%s'", e->name, tok);
            *eq = '\0';
            e->v[e->n] = (uint32_t)strtoul(tok, &end, 0);
            if (!*tok || *end || strlen(eq + 1) >= sizeof e->label[0])
                FAIL("enum %s: bad entry '%s=%s'", e->name, tok, eq + 1);
            strcpy(e->label[e->n++], eq + 1);
        }
        t->ne++;
        return 0;
    }

    if (!strcmp(tok, "when")) {
        struct rule *r = &t->r[t->nr];
        const char *q;
        size_t n;
        if (t->nr == TMPL_MAX_RULES) FAIL("too many rules (max %d)", TMPL_MAX_RULES);
        memset(r, 0, sizeof *r);
        for (;;) {
            char *eq, *end;
            while (isspace((unsigned char)*s)) s++;
            if (*s == '"' || !*s) break;
            s = token(s, tok, sizeof tok);
            if (r->nc == TMPL_MAX_CONDS) FAIL("too many conditions (max %d)", TMPL_MAX_CONDS);
            if (!(eq = strchr(tok, '=')) || eq == tok || eq - tok >= 32) FAIL("expected FIELD=VALUE, got '%s'", tok);
            *eq = '\0';
            strcpy(r->cond_field[r->nc], tok);
            r->cond_v[r->nc] = (uint32_t)strtol(eq + 1, &end, 0);
            if (!eq[1] || *end) FAIL("bad value in '%s=%s'", tok, eq + 1);
            r->nc++;
        }
        if (*s != '"' || !(q = strchr(s + 1, '"'))) FAIL("expected a \"format\"");
        n = (size_t)(q - s - 1);
        if (n >= sizeof r->fmt) FAIL("format too long");
        memcpy(r->fmt, s + 1, n);
        r->fmt[n] = '\0';
        s = q + 1;
        while (isspace((unsigned char)*s)) s++;
        if (*s) {
            const char *colon = strchr(s, ':');
            char sub_err[160];
            n = colon ? (size_t)(colon - s) : 0;
            if (!n || n >= sizeof r->blob) FAIL("expected BLOB: SUBSPEC after the format");
            memcpy(r->blob, s, n);
            r->blob[n] = '\0';
            if (spec_parse(&r->sub, colon + 1, sub_err, sizeof sub_err)) FAIL("%s", sub_err);
        }
        t->nr++;
        return 0;
    }
    FAIL("expected 'when' or 'enum', got '%s'", tok);
}

int tmpl_parse(struct tmpl *t, const char *text, char *err, size_t errlen)
{
    char buf[1024];
    int line = 0;

    t->nr = t->ne = 0;
    while (*text) {
        size_t n = strcspn(text, "\r\n");
        line++;
        if (n >= sizeof buf) FAIL("too long");
        memcpy(buf, text, n);
        buf[n] = '\0';
        if (parse_line(t, buf, line, err, errlen)) return -1;
        text += n;
        if (*text == '\r') text++;
        if (*text == '\n') text++;
    }
    if (!t->nr) {
        snprintf(err, errlen, "no 'when' rules");
        return -1;
    }
    return 0;
}

static const struct fval *lookup(const struct fval *v, int n, const char *name, size_t len)
{
    for (int i = 0; i < n; i++)
        if (strlen(v[i].f->name) == len && !strncmp(v[i].f->name, name, len)) return &v[i];
    return NULL;
}

int tmpl_render(const struct tmpl *t, const struct spec *s, const uint8_t *pkt, size_t n, char *out, size_t cap)
{
    struct fval ov[PKT_MAX_FIELDS], sv[PKT_MAX_FIELDS];
    int on = spec_values(s, pkt, n, ov);

    if (on < 0 || !cap) return 0;
    for (int ri = 0; ri < t->nr; ri++) {
        const struct rule *r = &t->r[ri];
        const char *f = r->fmt;
        size_t k = 0;
        int sn = 0, ok = 1;

        for (int c = 0; c < r->nc && ok; c++) {
            const struct fval *v = lookup(ov, on, r->cond_field[c], strlen(r->cond_field[c]));
            ok = v && v->f->width && v->v == (r->cond_v[c] & (v->f->width < 4 ? (1u << (8 * v->f->width)) - 1 : ~0u));
        }
        if (!ok) continue;
        if (r->blob[0]) {
            const struct fval *b = lookup(ov, on, r->blob, strlen(r->blob));
            if (!b || b->f->width || (sn = spec_values(&r->sub, b->p, b->len, sv)) < 0) continue;
        }

        while (*f && k + 1 < cap) {
            const char *close = *f == '{' ? strchr(f, '}') : NULL;
            const struct fval *v;
            size_t nl;
            if (!close) {
                out[k++] = *f++;
                continue;
            }
            nl = strcspn(f + 1, ":}");
            v = lookup(sv, sn, f + 1, nl);
            if (!v) v = lookup(ov, on, f + 1, nl);
            if (!v) { /* unknown name: leave it as written */
                out[k++] = *f++;
                continue;
            }
            {
                char val[4 * PKT_MAX_LEN + 1];
                const char *e = f + 1 + nl;
                int labelled = 0;
                if (*e == ':' && v->f->width) {
                    size_t en = (size_t)(close - e - 1);
                    for (int i = 0; i < t->ne && !labelled; i++) {
                        if (strlen(t->e[i].name) != en || strncmp(t->e[i].name, e + 1, en)) continue;
                        for (int j = 0; j < t->e[i].n && !labelled; j++) {
                            if (t->e[i].v[j] != v->v) continue;
                            snprintf(val, sizeof val, "%s", t->e[i].label[j]);
                            labelled = 1;
                        }
                    }
                }
                if (!labelled) fval_str(v, val, sizeof val); /* no enum, or a value it doesn't list */
                k += (size_t)snprintf(out + k, cap - k, "%s", val);
                if (k >= cap) k = cap - 1;
            }
            f = close + 1;
        }
        out[k] = '\0';
        return 1;
    }
    return 0;
}
