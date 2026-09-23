#ifndef TEMPLATE_H
#define TEMPLATE_H

#include "packet.h"

#define TMPL_MAX_RULES 64
#define TMPL_MAX_CONDS 8
#define TMPL_MAX_ENUMS 16
#define TMPL_MAX_LABELS 64

struct tenum {
    char name[32];
    int n;
    uint32_t v[TMPL_MAX_LABELS];
    char label[TMPL_MAX_LABELS][32];
};

struct rule {
    char cond_field[TMPL_MAX_CONDS][32];
    uint32_t cond_v[TMPL_MAX_CONDS];
    int nc;
    char fmt[256];
    char blob[32];     /* field whose bytes `sub` decodes; "" if none */
    struct spec sub;
};

struct tmpl {
    struct rule r[TMPL_MAX_RULES];
    int nr;
    struct tenum e[TMPL_MAX_ENUMS];
    int ne;
};

/* Parse a template: one rule or enum per line, '#' starts a comment line.
 *   enum NAME VALUE=LABEL ...
 *   when FIELD=VALUE ... "FORMAT" [BLOB: SUBSPEC]
 * FORMAT takes {field} or {field:enum}; fields come from the packet spec and SUBSPEC. */
int tmpl_parse(struct tmpl *t, const char *text, char *err, size_t errlen);

/* Render the first rule that matches this n-byte packet into out. Returns 1 if one matched. */
int tmpl_render(const struct tmpl *t, const struct spec *s, const uint8_t *pkt, size_t n, char *out, size_t cap);

#endif
