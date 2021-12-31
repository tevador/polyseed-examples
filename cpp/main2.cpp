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

#include "polyseed.hpp"

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <string>

constexpr polyseed::feature_type FEATURE_FOO = 1;
constexpr polyseed::feature_type FEATURE_BAR = 2;
constexpr polyseed::feature_type FEATURE_QUX = 2;

int main(int argc, char* argv[]) {

    const char* password = "password123";
    std::string phrase;

    polyseed::enable_features(FEATURE_FOO | FEATURE_BAR);

    {
        //create a new seed
        std::cout << "Generating new seed..." << std::endl;
        polyseed::data seed1(POLYSEED_MONERO);
        seed1.create(argc > 1 ? FEATURE_FOO : 0);

        //generate a key from the seed
        uint8_t key1[32];
        seed1.keygen(&key1, sizeof(key1));
        std::cout << "Private key: ";
        for (unsigned i = 0; i < sizeof(key1); ++i) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)key1[i];
        }
        std::cout << std::dec << std::endl;

        //protect the seed with a password
        std::cout << "Encrypting with password '" << password << "' ..." << std::endl;
        seed1.crypt(password);

        //encode into a mnemonic phrase
        try {
            seed1.encode(polyseed::get_lang_by_name("English"), phrase);
            std::cout << "Mnemonic: " << phrase << std::endl;
        }
        catch (const polyseed::error& ex) {
            std::cout << ex.what() << std::endl;
            return 1;
        }
    }

    std::cout << "-------------------------------------------------" << std::endl;

    {
        //decode a seed from the phrase
        polyseed::data seed2(POLYSEED_MONERO);

        std::cout << "Decoding mnemonic phrase..." << std::endl;
        try {
            auto lang = seed2.decode(phrase.c_str());
            std::cout << "Detected language: " << lang.name_en() << std::endl;
        }
        catch (const polyseed::error& ex) {
            std::cout << ex.what() << std::endl;
            return 1;
        }

        std::cout << "Encrypted: " << (seed2.encrypted() ? "true" : "false") << std::endl;

        if (seed2.has_feature(FEATURE_FOO)) {
            std::cout << "Seed has the 'Foo' feature" << std::endl;
        }

        //decrypt
        if (seed2.encrypted()) {
            std::cout << "Decrypting with password '" << password << "' ..." << std::endl;
            seed2.crypt(password);
        }

        //recover the key
        uint8_t key2[32];
        seed2.keygen(&key2, sizeof(key2));
        std::cout << "Private key: ";
        for (unsigned i = 0; i < sizeof(key2); ++i) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)key2[i];
        }
        std::cout << std::dec << std::endl;
    }

    return 0;
}
