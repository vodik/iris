#include "base64.h"
#include <stdlib.h>
#include <stdint.h>

static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                                     "ghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *data, size_t data_length,
                    size_t *output_length)
{
    const size_t length = 4 * ((data_length + 2) / 3);
    char *encoded_data = malloc(length + 1), *p = encoded_data;
    if (encoded_data == NULL)
        return NULL;

    for (size_t i = 0; i < data_length; i += 3) {
        const uint8_t lookahead[2] = {
            i + 1 < data_length,
            i + 2 < data_length
        };

        const uint8_t octets[3] = {
            data[i],
            lookahead[0] ? data[i + 1] : 0,
            lookahead[1] ? data[i + 2] : 0
        };

        const uint32_t bitpattern = (octets[0] << 16) + (octets[1] << 8) + octets[2];
        *p++ = encoding_table[(bitpattern >> 18) & 0x3F];
        *p++ = encoding_table[(bitpattern >> 12) & 0x3F];
        *p++ = lookahead[0] ? encoding_table[(bitpattern >> 6) & 0x3F] : '=';
        *p++ = lookahead[1] ? encoding_table[bitpattern & 0x3F] : '=';
    }

    *p = '\0';
    if (output_length)
    	*output_length = length;
    return encoded_data;
}
