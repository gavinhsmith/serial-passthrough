#include "packet.h"
#include "template.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void)
{
    static const char *bad[] = {"", "x", "x:u12", "x:u16xx", "x:u8=0x100", "d:bytes(len)", "n:u8,d:text(n",
                                "x:bytes(0)", "x:bytes(4)=1", "x:u8,x:u8", "n:u8,d:bytes(n+)"};
    static const uint8_t want[] = {0xAA, 0x55, 0x00, 0x05, 1, 2, 3, 0x34, 0x12};
    uint8_t out[PKT_MAX_LEN];
    struct spec s;
    char err[160];

    /* sync byte, 16 chars of text, end byte */
    CHECK(spec_parse(&s, "sync:u8=0x02, msg:text(16), end:u8=0x03", err, sizeof err) == 0);
    CHECK(spec_build(&s, "msg=\"HELLO\"", out, sizeof out, err, sizeof err) == 18);
    CHECK(out[0] == 0x02 && !memcmp(out + 1, "HELLO\0", 6) && out[17] == 0x03);
    CHECK(spec_match(&s, out, 18) == 18);
    CHECK(spec_match(&s, out, 10) == 0);
    CHECK(spec_match(&s, (const uint8_t *)"X", 1) == -1);
    out[17] = 0x04;
    CHECK(spec_match(&s, out, 18) == -1);
    CHECK(spec_build(&s, "msg=\"this is longer than 16\"", out, sizeof out, err, sizeof err) == -1);
    CHECK(spec_build(&s, "sync=1", out, sizeof out, err, sizeof err) == -1);
    CHECK(spec_build(&s, "nope=1", out, sizeof out, err, sizeof err) == -1);

    /* file-style spec: big-endian length that also counts the crc */
    CHECK(spec_parse(&s, "# header\nsync:u16be=0xAA55\nlen:u16be  # payload+crc\n\ndata:bytes(len-2)\ncrc:u16\n",
                     err, sizeof err) == 0);
    CHECK(spec_build(&s, "data=010203 crc=0x1234", out, sizeof out, err, sizeof err) == sizeof want);
    CHECK(!memcmp(out, want, sizeof want));
    CHECK(spec_match(&s, out, 9) == 9);
    CHECK(spec_match(&s, out, 8) == 0);
    out[3] = 0x01; /* length says -1 bytes of data */
    CHECK(spec_match(&s, out, 9) == -1);
    out[2] = 0xFF; /* length way past the cap */
    CHECK(spec_match(&s, out, 9) == -1);

    CHECK(spec_parse(&s, "a:u8, b:u8", err, sizeof err) == 0);
    CHECK(spec_build(&s, "a=256", out, sizeof out, err, sizeof err) == -1);
    CHECK(spec_build(&s, "b=7", out, sizeof out, err, sizeof err) == 2 && out[0] == 0 && out[1] == 7);

    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
        CHECK(spec_parse(&s, bad[i], err, sizeof err) == -1);

    /* CRC-16/CCITT-FALSE check value, then a TINCLIB frame (HELLO request, a golden vector) */
    CHECK(crc16_ccitt((const uint8_t *)"123456789", 9) == 0x29B1);
    {
        static const uint8_t hello[] = {0xA5, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00,
                                        0x00, 0x01, 0xD2, 0x6A};
        char text[256];
        CHECK(spec_parse(&s, "sof:u8=0xA5, flags:u8, type:u8, seq:u8, len:u16, payload:bytes(len),"
                             "crc:crc16ccitt(flags..payload)", err, sizeof err) == 0);
        CHECK(spec_build(&s, "type=1 seq=1 payload=0001000000\"\\x01\"", out, sizeof out, err, sizeof err)
              == sizeof hello);
        CHECK(!memcmp(out, hello, sizeof hello));
        CHECK(spec_match(&s, out, sizeof hello) == sizeof hello);
        spec_format(text, sizeof text, &s, out, sizeof hello);
        CHECK(!strcmp(text, " sof=0xA5 flags=0 type=1 seq=1 len=6 payload=[00 01 00 00 00 01] crc=0x6AD2"));
        out[7] ^= 1; /* corrupt the payload: the crc no longer matches */
        CHECK(spec_match(&s, out, sizeof hello) == -1);
        CHECK(spec_build(&s, "crc=1", out, sizeof out, err, sizeof err) == -1);
        CHECK(spec_build(&s, "type=2 payload=", out, sizeof out, err, sizeof err) == 8);
        CHECK(spec_parse(&s, "a:u8, c:crc16ccitt(a..b)", err, sizeof err) == -1);
        CHECK(spec_parse(&s, "a:u8, b:u8, c:crc16ccitt(b..a)", err, sizeof err) == -1);
        CHECK(spec_parse(&s, "a:u8, c:crc16ccitt(a..a)=1", err, sizeof err) == -1);
    }

    /* signed integers and a (*) blob that takes the rest */
    {
        struct fval v[PKT_MAX_FIELDS];
        char text[128];
        CHECK(spec_parse(&s, "t:i8, n:i16, rest:text(*)", err, sizeof err) == 0);
        CHECK(spec_build(&s, "t=-61 n=-2 rest=\"hi\"", out, sizeof out, err, sizeof err) == 5);
        CHECK(out[0] == 0xC3 && out[1] == 0xFE && out[2] == 0xFF && !memcmp(out + 3, "hi", 2));
        CHECK(spec_build(&s, "t=-129", out, sizeof out, err, sizeof err) == -1);
        spec_build(&s, "t=-61 n=-2 rest=\"hi\"", out, sizeof out, err, sizeof err);
        spec_format(text, sizeof text, &s, out, 5);
        CHECK(!strcmp(text, " t=-61 n=-2 rest=\"hi\""));
        CHECK(spec_values(&s, out, 3, v) == 3 && v[2].len == 0); /* empty rest is fine */
        CHECK(spec_values(&s, out, 2, v) == -1);                /* n cut short */
        CHECK(spec_parse(&s, "a:bytes(*), b:u8", err, sizeof err) == -1);
    }

    /* templates: conditions, enums, a payload sub-spec, fallbacks */
    {
        static struct tmpl t;
        static const uint8_t err_reply[] = {0xA5, 0x05, 0x02, 0x0C, 0x01, 0x00, 0x02};
        static const uint8_t hello_resp[] = {0xA5, 0x01, 0x01, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00,
                                             0x00, 0x04, 0x60, 0x6D, 0x00, 0x00, 0xB2, 0x21};
        char text[256];
        CHECK(spec_parse(&s, "sof:u8=0xA5, flags:u8, type:u8, seq:u8, len:u16, payload:bytes(len),"
                             "crc:crc16ccitt(flags..payload)", err, sizeof err) == 0);
        CHECK(tmpl_parse(&t,
                         "# comment\n"
                         "enum type 1=HELLO 2=STATUS\n"
                         "enum err 2=NO_HELLO\r\n"
                         "when flags=5 \"#{seq} {type:type} error {code:err}\" payload: code:u8\n"
                         "when type=1 flags=1 \"HELLO ok v{major}.{minor} heap={heap} {nope}\" "
                         "payload: major:u8, minor:u8, caps:u16, max:u16, heap:u32\n"
                         "when flags=1 \"{type:type} ok\"\n",
                         err, sizeof err) == 0);
        CHECK(t.nr == 3 && t.ne == 2);
        CHECK(spec_build(&s, "flags=5 type=2 seq=12 payload=02", out, sizeof out, err, sizeof err) == 9);
        CHECK(!memcmp(out, err_reply, 7)); /* header + payload as in the golden vector */
        CHECK(tmpl_render(&t, &s, out, 9, text, sizeof text) == 1);
        CHECK(!strcmp(text, "#12 STATUS error NO_HELLO"));
        CHECK(tmpl_render(&t, &s, hello_resp, sizeof hello_resp, text, sizeof text) == 1);
        CHECK(!strcmp(text, "HELLO ok v0.1 heap=28000 {nope}"));
        /* payload too short for the HELLO sub-spec: falls through to the next rule */
        {
            uint8_t shortr[] = {0xA5, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0, 0};
            uint16_t c = crc16_ccitt(shortr + 1, 6);
            shortr[7] = (uint8_t)c;
            shortr[8] = (uint8_t)(c >> 8);
            CHECK(tmpl_render(&t, &s, shortr, sizeof shortr, text, sizeof text) == 1);
            CHECK(!strcmp(text, "HELLO ok"));
        }
        /* no rule for a request (flags=0) */
        CHECK(spec_build(&s, "type=2 seq=1", out, sizeof out, err, sizeof err) == 8);
        CHECK(tmpl_render(&t, &s, out, 8, text, sizeof text) == 0);
        /* enum value it doesn't list prints the number */
        CHECK(spec_build(&s, "flags=5 type=9 payload=07", out, sizeof out, err, sizeof err) == 9);
        CHECK(tmpl_render(&t, &s, out, 9, text, sizeof text) == 1 && !strcmp(text, "#0 9 error 7"));

        CHECK(tmpl_parse(&t, "when x \"y\"\n", err, sizeof err) == -1);
        CHECK(tmpl_parse(&t, "enum e 1\n", err, sizeof err) == -1);
        CHECK(tmpl_parse(&t, "bogus\n", err, sizeof err) == -1);
        CHECK(tmpl_parse(&t, "when a=1 \"unterminated\n", err, sizeof err) == -1);
        CHECK(tmpl_parse(&t, "when a=1 \"x\" payload: q:u12\n", err, sizeof err) == -1);
        CHECK(tmpl_parse(&t, "# nothing\n", err, sizeof err) == -1);
    }

    CHECK(unescape("a\\r\\n\\x41\\\\", '\0', out, sizeof out, NULL) == 5 && !memcmp(out, "a\r\nA\\", 5));
    CHECK(unhex("02 4a ff", 8, out, sizeof out) == 3 && out[1] == 0x4A);
    CHECK(unhex("123", 3, out, sizeof out) == -1);

    puts("ok");
    return 0;
}
