/*
 * ascon_trace.c - Ascon-AEAD128 (NIST SP 800-232) step-by-step trace demo
 *
 * Runs Ascon-AEAD128 encrypt + decrypt with hardcoded test vectors (taken
 * from the official LWC KAT file) and prints every internal state transition.
 * Compile with -DASCON_PRINT_STATE to enable the state print-outs (already
 * done by the CMake target "ascon_trace").
 *
 * Optional command-line arguments (all hex strings, no 0x prefix):
 *   ascon_trace [key] [nonce] [ad] [plaintext]
 *
 * Examples:
 *   ascon_trace
 *   ascon_trace 000102030405060708090a0b0c0d0e0f \
 *               101112131415161718191a1b1c1d1e1f \
 *               "" "48656c6c6f"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Pull in the reference implementation header */
#include "api.h"
#include "crypto_aead.h"

/* ------------------------------------------------------------------ helpers */

static void print_hex(const char* label, const uint8_t* buf, size_t len) {
    size_t i;
    printf("  %-20s = ", label);
    if (len == 0) {
        printf("(empty)");
    } else {
        for (i = 0; i < len; ++i) printf("%02x", buf[i]);
    }
    printf("\n");
}

/* Parse a hex string into a byte buffer.  Returns the number of bytes written,
   or -1 on error.  *out is malloc'd by this function; caller must free. */
static int hex_to_bytes(const char* hex, uint8_t** out) {
    size_t hlen, i;
    if (!hex || hex[0] == '\0') {
        *out = NULL;
        return 0;
    }
    hlen = strlen(hex);
    if (hlen % 2 != 0) {
        fprintf(stderr, "Error: hex string has odd length: %s\n", hex);
        return -1;
    }
    *out = (uint8_t*)malloc(hlen / 2);
    if (!*out) { perror("malloc"); return -1; }
    for (i = 0; i < hlen / 2; ++i) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) {
            fprintf(stderr, "Error: invalid hex character near '%s'\n",
                    hex + 2 * i);
            free(*out);
            return -1;
        }
        (*out)[i] = (uint8_t)byte;
    }
    return (int)(hlen / 2);
}

/* -------------------------------------------------------------------- main */

int main(int argc, char** argv) {
    int ret = 0;

    /* ---- default test vector (KAT Count=33, 16-byte AD + 16-byte PT) ---- */
    static const uint8_t default_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t default_nonce[16] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t default_ad[16] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    static const uint8_t default_msg[16] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };

    /* pointers used during the run */
    const uint8_t* key   = default_key;
    const uint8_t* nonce = default_nonce;
    const uint8_t* ad    = default_ad;
    const uint8_t* msg   = default_msg;
    size_t key_len   = sizeof(default_key);
    size_t nonce_len = sizeof(default_nonce);
    size_t ad_len    = sizeof(default_ad);
    size_t msg_len   = sizeof(default_msg);

    /* heap allocations from CLI (freed at exit) */
    uint8_t* cli_key   = NULL;
    uint8_t* cli_nonce = NULL;
    uint8_t* cli_ad    = NULL;
    uint8_t* cli_msg   = NULL;

    /* ---- parse optional CLI arguments ---- */
    if (argc > 1) {
        int n = hex_to_bytes(argv[1], &cli_key);
        if (n < 0) { ret = 1; goto cleanup; }
        if (n != CRYPTO_KEYBYTES) {
            fprintf(stderr, "Error: key must be %d bytes (%d hex chars), got %d bytes\n",
                    CRYPTO_KEYBYTES, CRYPTO_KEYBYTES * 2, n);
            ret = 1; goto cleanup;
        }
        key     = cli_key;
        key_len = (size_t)n;
    }
    if (argc > 2) {
        int n = hex_to_bytes(argv[2], &cli_nonce);
        if (n < 0) { ret = 1; goto cleanup; }
        if (n != CRYPTO_NPUBBYTES) {
            fprintf(stderr, "Error: nonce must be %d bytes (%d hex chars), got %d bytes\n",
                    CRYPTO_NPUBBYTES, CRYPTO_NPUBBYTES * 2, n);
            ret = 1; goto cleanup;
        }
        nonce     = cli_nonce;
        nonce_len = (size_t)n;
    }
    if (argc > 3) {
        int n = hex_to_bytes(argv[3], &cli_ad);
        if (n < 0) { ret = 1; goto cleanup; }
        ad     = cli_ad ? cli_ad : (const uint8_t*)"";
        ad_len = (size_t)n;
    }
    if (argc > 4) {
        int n = hex_to_bytes(argv[4], &cli_msg);
        if (n < 0) { ret = 1; goto cleanup; }
        msg     = cli_msg ? cli_msg : (const uint8_t*)"";
        msg_len = (size_t)n;
    }

    (void)key_len;
    (void)nonce_len;

    /* ------------------------------------------------------------------ */
    printf("============================================================\n");
    printf(" Ascon-AEAD128 Trace  (NIST SP 800-232)\n");
    printf("============================================================\n");
    printf("\n");
    printf("[INPUT]\n");
    print_hex("key",       key,   CRYPTO_KEYBYTES);
    print_hex("nonce",     nonce, CRYPTO_NPUBBYTES);
    print_hex("assoc data", ad,   ad_len);
    print_hex("plaintext",  msg,  msg_len);
    printf("\n");

    /* ------------------------------------------------------------------ */
    /* Allocate ciphertext buffer: plaintext + tag */
    size_t ct_buf_len = msg_len + CRYPTO_ABYTES;
    uint8_t* ct = (uint8_t*)malloc(ct_buf_len > 0 ? ct_buf_len : 1);
    if (!ct) { perror("malloc"); ret = 1; goto cleanup; }

    /* ------------------------------------------------------------------ */
    printf("============================================================\n");
    printf(" ENCRYPTION  (state trace printed by the ref implementation)\n");
    printf("============================================================\n");
    printf("\n");

    unsigned long long clen = 0;
    int enc_ret = crypto_aead_encrypt(ct, &clen,
                                      msg, (unsigned long long)msg_len,
                                      ad,  (unsigned long long)ad_len,
                                      NULL, nonce, key);
    if (enc_ret != 0) {
        fprintf(stderr, "Encryption failed (returned %d)\n", enc_ret);
        free(ct);
        ret = 1;
        goto cleanup;
    }

    printf("\n[ENCRYPTION RESULT]\n");
    print_hex("ciphertext", ct,                    clen - CRYPTO_ABYTES);
    print_hex("tag",        ct + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);
    printf("\n");

    /* ------------------------------------------------------------------ */
    printf("============================================================\n");
    printf(" DECRYPTION  (state trace printed by the ref implementation)\n");
    printf("============================================================\n");
    printf("\n");

    uint8_t* recovered = (uint8_t*)malloc(msg_len > 0 ? msg_len : 1);
    if (!recovered) { perror("malloc"); free(ct); ret = 1; goto cleanup; }

    unsigned long long recovered_len = 0;
    int dec_ret = crypto_aead_decrypt(recovered, &recovered_len,
                                      NULL, ct, clen,
                                      ad, (unsigned long long)ad_len,
                                      nonce, key);

    printf("\n[DECRYPTION RESULT]\n");
    if (dec_ret != 0) {
        printf("  Tag verification FAILED (returned %d)\n", dec_ret);
        ret = 1;
    } else {
        print_hex("recovered plaintext", recovered, (size_t)recovered_len);

        /* Verify plaintext matches original */
        if (recovered_len == (unsigned long long)msg_len &&
            memcmp(recovered, msg, msg_len) == 0) {
            printf("\n  [OK] Decrypted plaintext matches original!\n");
        } else {
            printf("\n  [FAIL] Decrypted plaintext does NOT match original!\n");
            ret = 1;
        }
    }
    printf("\n");
    printf("============================================================\n");

    free(recovered);
    free(ct);

cleanup:
    free(cli_key);
    free(cli_nonce);
    free(cli_ad);
    free(cli_msg);
    return ret;
}
