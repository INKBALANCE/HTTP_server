#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "auth.h"
#include "log.h"

#define USERNAME "admin"
#define PASSWORD "password"
#define AUTH_REALM "Restricted Area"

int base64_decode(const char *input, char *output) {
    static const unsigned char d[] = {
        62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 0, 0, 0, 0, 0,
        0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };

    int len = strlen(input);
    if (len % 4 != 0) return -1;

    int padding = 0;
    if (input[len - 1] == '=') padding++;
    if (input[len - 2] == '=') padding++;

    int output_len = (len * 3) / 4 - padding;
    for (int i = 0, j = 0; i < len;) {
        uint32_t a = input[i] == '=' ? 0 & i++ : d[input[i++] - 43];
        uint32_t b = input[i] == '=' ? 0 & i++ : d[input[i++] - 43];
        uint32_t c = input[i] == '=' ? 0 & i++ : d[input[i++] - 43];
        uint32_t e = input[i] == '=' ? 0 & i++ : d[input[i++] - 43];

        uint32_t triple = (a << 18) | (b << 12) | (c << 6) | e;
        if (j < output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < output_len) output[j++] = triple & 0xFF;
    }

    output[output_len] = '\0';
    return output_len;
}

int is_authorized(const char *auth_header) {
    char expected_auth[256];
    snprintf(expected_auth, sizeof(expected_auth), "%s:%s", USERNAME, PASSWORD);

    char encoded_auth[256];
    const char *encoded = auth_header + strlen("Authorization: Basic ");
    snprintf(encoded_auth, sizeof(encoded_auth), "%s", encoded);

    char decoded_auth[256];
    memset(decoded_auth, 0, sizeof(decoded_auth));
    int len = base64_decode(encoded_auth, decoded_auth);

    log_message(LOG_DEBUG, "Expected: %s", expected_auth);  // Debugging
    log_message(LOG_DEBUG, "Decoded: %s", decoded_auth);    // Debugging

    return (len > 0) && (strcmp(decoded_auth, expected_auth) == 0);
}

