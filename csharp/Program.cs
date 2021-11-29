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

using PolyseedSharp;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

const string password = "password123";
string phrase;

//create a new seed
Console.WriteLine("Generating new seed...");
using (var seed1 = Polyseed.Create())
{
    //generate a key from the seed
    Span<byte> key1 = stackalloc byte[32];
    seed1.GenerateKey(Coin.MONERO, key1);
    Console.WriteLine($"Private key: {Convert.ToHexString(key1).ToLower()}");

    //protect the seed with a password
    Console.WriteLine($"Encrypting with password '{password}' ...");
    seed1.Crypt(password);

    //encode into a mnemonic phrase
    phrase = seed1.ToString(Language.List.Single(x => x.Name == "English"), Coin.MONERO);
    Console.WriteLine($"Mnemonic: {phrase}");
}

Console.WriteLine("-------------------------------------------------");

//decode a seed from the phrase
Console.WriteLine("Decoding mnemonic phrase...");

Polyseed seed2;
try
{
    seed2 = Polyseed.Parse(phrase, Coin.MONERO, out Language lang);
    Console.WriteLine($"Detected language: {lang}");
}
catch(PolyseedException ex)
{
    Console.WriteLine($"ERROR: {ex.Message}");
    return 1;
}

using (seed2)
{
    Console.WriteLine($"Encrypted: {seed2.IsEncrypted}");

    //decrypt
    if (seed2.IsEncrypted)
    {
        Console.WriteLine($"Encrypting with password '{password}' ...");
        seed2.Crypt(password);
    }

    //recover the key
    Span<byte> key2 = stackalloc byte[32];
    seed2.GenerateKey(Coin.MONERO, key2);
    Console.WriteLine($"Private key: {Convert.ToHexString(key2).ToLower()}");
}

return 0;
