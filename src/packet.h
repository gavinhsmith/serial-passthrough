#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PKT_MAX_FIELDS 32
#define PKT_MAX_LEN 4096

struct field {
    char name[32];
    int width;      /* 1, 2 or 4 for integers; 0 for blobs */
    int be;         /* integer is big-endian */
    int is_const;   /* integer must equal value (sync/end markers) */
    uint32_t value;
    int text;       /* blob prints as text instead of hex */
    size_t count;   /* blob: fixed byte count */
    int ref;        /* blob: index of the integer field holding its length, or -1 */
    long adj;       /* blob: added to the referenced length */
    int crc;        /* CRC-16/CCITT-FALSE over fields crc_from..crc_to, computed */
    int crc_from, crc_to;
};

struct spec {
    struct field f[PKT_MAX_FIELDS];
    int n;
};

/* Parse "name:type[=value]" fields separated by commas or newlines; '#' starts a comment.
 * Types: u8, u16[le|be], u32[le|be], bytes(N), text(N), bytes(field[+-N]), text(field[+-N]),
 * crc16ccitt(first..last)[le|be]. */
int spec_parse(struct spec *s, const char *text, char *err, size_t errlen);

/* > 0: a whole packet of that many bytes starts at buf; 0: need more bytes; -1: no packet starts here. */
long spec_match(const struct spec *s, const uint8_t *buf, size_t n);

/* Format the fields of a packet spec_match() accepted into buf, each preceded by a space. */
void spec_format(char *buf, size_t cap, const struct spec *s, const uint8_t *pkt);

/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection. "123456789" -> 0x29B1. */
uint16_t crc16_ccitt(const uint8_t *p, size_t n);

/* Build a packet from "field=value ..." (numbers; blobs as hex digits and "quoted text", which can
 * be mixed without spaces: 0007"HomeNet"). Constants, lengths and CRCs fill themselves in. Returns the packet length, or -1 with a message in err. */
long spec_build(const struct spec *s, const char *args, uint8_t *out, size_t cap, char *err, size_t errlen);

/* Decode C escapes (\r \n \t \0 \xNN \\ \") up to `stop` or end of string. Returns bytes or -1 if over cap. */
long unescape(const char *s, char stop, uint8_t *out, size_t cap, const char **endp);

/* Decode hex byte pairs, spaces allowed between bytes. Returns bytes or -1 on bad input. */
long unhex(const char *s, size_t len, uint8_t *out, size_t cap);

#endif
