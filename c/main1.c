/*
 * Copyright 2021 tevador <tevador@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <polyseed.h>

#include <sodium/core.h>
#include <sodium/utils.h>
#include <sodium/randombytes.h>
#include <utf8proc.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pbkdf2.h"

#define MIN(a,b) ((a)>(b)?(b):(a))

static size_t utf8_nfc(const char* str, polyseed_str norm) {
    utf8proc_uint8_t* s = utf8proc_NFC((const utf8proc_uint8_t*)str);
    size_t len = strlen((const char*)s);
    size_t size = MIN(len, (size_t)POLYSEED_STR_SIZE - 1);
    memcpy(norm, s, size);
    norm[size] = '\0';
    sodium_memzero(s, len);
    free(s);
    return size;
}

static size_t utf8_nfkd(const char* str, polyseed_str norm) {
    utf8proc_uint8_t* s = utf8proc_NFKD((const utf8proc_uint8_t*)str);
    size_t len = strlen((const char*)s);
    size_t size = MIN(len, (size_t)POLYSEED_STR_SIZE - 1);
    memcpy(norm, s, size);
    norm[size] = '\0';
    sodium_memzero(s, len);
    free(s);
    return size;
}

static void polyseed_init() {
    polyseed_dependency pd = {
        .randbytes = &randombytes_buf,
        .pbkdf2_sha256 = &crypto_pbkdf2_sha256,
        .memzero = &sodium_memzero,
        .u8_nfc = &utf8_nfc,
        .u8_nfkd = &utf8_nfkd,
        .time = NULL,
        .alloc = NULL,
        .free = NULL,
    };
    polyseed_inject(&pd);
}

static const polyseed_lang* get_lang_by_name(const char* name) {
    for (int i = 0; i < polyseed_get_num_langs(); ++i) {
        const polyseed_lang* lang = polyseed_get_lang(i);
        if (0 == strcmp(name, polyseed_get_lang_name_en(lang))) {
            return lang;
        }
        if (0 == strcmp(name, polyseed_get_lang_name(lang))) {
            return lang;
        }
    }
    return NULL;
}

#define FEATURE_FOO 1
#define FEATURE_BAR 2
#define FEATURE_QUX 4

int main(int argc, char* argv[]) {

    if (sodium_init() == -1) {
        printf("sodium_init failed\n");
        return 1;
    }

    polyseed_init();

    polyseed_enable_features(FEATURE_FOO | FEATURE_BAR);

    const char* password = "password123";
    polyseed_status result;
    polyseed_data* seed1;

    //create a new seed
    printf("Generating new seed...\n");
    result = polyseed_create(argc > 1 ? FEATURE_FOO : 0, &seed1);
    if (result != POLYSEED_OK) {
        printf("ERROR: %i\n", result);
        return 1;
    }

    //generate a key from the seed
    uint8_t key1[32];
    polyseed_keygen(seed1, POLYSEED_MONERO, sizeof(key1), key1);
    printf("Private key: ");
    for (unsigned i = 0; i < sizeof(key1); ++i)
		printf("%02x", key1[i] & 0xff);
    printf("\n");

    //protect the seed with a password
    printf("Encrypting with password '%s' ...\n", password);
    polyseed_crypt(seed1, password);

    //encode into a mnemonic phrase
    polyseed_str phrase;
    polyseed_encode(seed1, get_lang_by_name("English"), POLYSEED_MONERO, phrase);
    printf("Mnemonic: %s\n", phrase);

    polyseed_free(seed1);

    printf("-------------------------------------------------\n");

    //decode a seed from the phrase
    printf("Decoding mnemonic phrase...\n");

    polyseed_data* seed2;
    const polyseed_lang* lang;
    result = polyseed_decode(phrase, POLYSEED_MONERO, &lang, &seed2);
    if (result != POLYSEED_OK) {
        printf("ERROR: %i\n", result);
        return 1;
    }
    printf("Detected language: %s\n", polyseed_get_lang_name_en(lang));

    printf("Encrypted: %s\n", polyseed_is_encrypted(seed2) ? "true" : "false");

    if (polyseed_get_feature(seed2, FEATURE_FOO)) {
        printf("Seed has the 'Foo' feature\n");
    }

    //decrypt
    if (polyseed_is_encrypted(seed2)) {
        printf("Decrypting with password '%s' ...\n", password);
        polyseed_crypt(seed2, password);
    }

    //recover the key
    uint8_t key2[32];
    polyseed_keygen(seed2, POLYSEED_MONERO, sizeof(key2), key2);
    printf("Private key: ");
    for (unsigned i = 0; i < sizeof(key2); ++i)
		printf("%02x", key2[i] & 0xff);
    printf("\n");

    polyseed_free(seed2);

    return 0;
}
