/*
 * test-braille — verify dot-pattern → codepoint → UTF-8 byte sequence.
 *
 * U+2800..U+28FF lives in the 3-byte UTF-8 range. world-map.c encodes those
 * bytes directly, so this test verifies the exact UTF-8 layout.
 */

#include "geotrace/util.h"
#include "geotrace/world-map.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void must_encode(uint8_t pattern, const unsigned char expected[3])
{
    char out[4];
    int n = braille_encode(pattern, out);
    if (n != 3) {
        fprintf(stderr, "FAIL: pattern=0x%02x produced %d bytes\n", pattern, n);
        exit(1);
    }
    for (int i = 0; i < 3; i++) {
        if ((unsigned char) out[i] != expected[i]) {
            fprintf(stderr,
                    "FAIL: pattern=0x%02x byte%d=0x%02x expected 0x%02x\n",
                    pattern, i, (unsigned char) out[i], expected[i]);
            exit(1);
        }
    }
    if (out[3] != '\0') {
        fprintf(stderr, "FAIL: pattern=0x%02x missing NUL terminator\n",
                pattern);
        exit(1);
    }
}

int main(void)
{
    static const struct {
        uint8_t pattern;
        unsigned char utf8[3];
    } CASES[] = {
        {0x00, {0xE2, 0xA0, 0x80}}, /* U+2800 (empty braille) */
        {0x01, {0xE2, 0xA0, 0x81}}, /* U+2801 (single dot 1) */
        {0x3F, {0xE2, 0xA0, 0xBF}}, /* U+283F (lower-half block) */
        {0x40, {0xE2, 0xA1, 0x80}}, /* U+2840 (single dot 7) */
        {0x7F, {0xE2, 0xA1, 0xBF}}, /* U+287F */
        {0x80, {0xE2, 0xA2, 0x80}}, /* U+2880 */
        {0xFF, {0xE2, 0xA3, 0xBF}}, /* U+28FF (full block) */
    };

    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(CASES); i++)
        must_encode(CASES[i].pattern, CASES[i].utf8);

    /* Round-trip exhaustive: encode every pattern, decode the codepoint,
     * compare.
     */
    for (int p = 0; p < 256; p++) {
        char out[4];
        braille_encode((uint8_t) p, out);

        unsigned cp = (unsigned) ((unsigned char) out[0] & 0x0F) << 12 |
                      (unsigned) ((unsigned char) out[1] & 0x3F) << 6 |
                      (unsigned) ((unsigned char) out[2] & 0x3F);

        if (cp != (unsigned) (0x2800 + p)) {
            fprintf(stderr,
                    "FAIL: pattern=0x%02x decoded codepoint U+%04X (expected "
                    "U+%04X)\n",
                    p, cp, 0x2800 + p);
            return 1;
        }
    }

    fprintf(stderr, "braille tests passed\n");
    return 0;
}
