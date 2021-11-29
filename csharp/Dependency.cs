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

using System;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace PolyseedSharp
{
    unsafe delegate void BytesDelegate(void* ptr, IntPtr size);
    unsafe delegate void KdfDelegate(byte* pw, IntPtr pwlen, byte* salt,
        IntPtr saltlen, ulong iterations, byte* key, IntPtr keylen);
    unsafe delegate IntPtr Utf8NormDelegate(byte* str, byte* norm);
    unsafe delegate long TimeDelegate(long* t);
    unsafe delegate void* AllocDelegate(IntPtr n);
    unsafe delegate void FreeDelegate(void* ptr);

    internal unsafe class Dependency
    {
        [StructLayout(LayoutKind.Sequential)]
        struct PolyseedDependency
        {
            public IntPtr Randbytes { get; set; }
            public IntPtr Pbkdf2Sha256 { get; set; }
            public IntPtr Memzero { get; set; }
            public IntPtr Utf8Nfc { get; set; }
            public IntPtr Utf8Nfkd { get; set; }
            public IntPtr Time { get; set; }
            public IntPtr Alloc { get; set; }
            public IntPtr Free { get; set; }
        }

        static readonly RandomNumberGenerator s_rand = RandomNumberGenerator.Create();

        static readonly BytesDelegate s_randBytes = new BytesDelegate(RandomBytes);
        static readonly KdfDelegate s_pbkdf2 = new KdfDelegate(Pbkdf2);
        static readonly Utf8NormDelegate s_compose = new Utf8NormDelegate(Utf8Compose);
        static readonly Utf8NormDelegate s_decompose = new Utf8NormDelegate(Utf8Decompose);
        static readonly BytesDelegate s_memzero = new BytesDelegate(ZeroMemory);
        static readonly TimeDelegate s_time = new TimeDelegate(Time);

        static Dependency()
        {
            var deps = new PolyseedDependency
            {
                Randbytes = Marshal.GetFunctionPointerForDelegate(s_randBytes),
                Pbkdf2Sha256 = Marshal.GetFunctionPointerForDelegate(s_pbkdf2),
                Utf8Nfc = Marshal.GetFunctionPointerForDelegate(s_compose),
                Utf8Nfkd = Marshal.GetFunctionPointerForDelegate(s_decompose),
                Memzero = Marshal.GetFunctionPointerForDelegate(s_memzero),
                Time = Marshal.GetFunctionPointerForDelegate(s_time),
            };
            polyseed_inject(&deps);
        }

        public static void Init()
        {
        }

        public static int WriteNullTerminatedUtf8(string s, byte* buf, int maxSize)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            var size = Math.Min(bytes.Length, maxSize);
            var span = new ReadOnlySpan<byte>(bytes, 0, size);
            span.CopyTo(new Span<byte>(buf, size));
            buf[size] = 0;
            return size;
        }

        private static void RandomBytes(void* ptr, IntPtr size)
        {
            lock (s_rand)
            {
                var span = new Span<byte>(ptr, size.ToInt32());
                s_rand.GetBytes(span);
            }
        }

        private static void Pbkdf2(byte* pw, IntPtr pwlen, byte* salt, IntPtr saltlen, ulong iterations, byte* key, IntPtr keylen)
        {
            var keySpan = new Span<byte>(key, keylen.ToInt32());
#if NET6_0_OR_GREATER
            Rfc2898DeriveBytes.Pbkdf2(
                new ReadOnlySpan<byte>(pw, pwlen.ToInt32()),
                new ReadOnlySpan<byte>(salt, saltlen.ToInt32()),
                keySpan,
                (int)iterations, HashAlgorithmName.SHA256);
#else
            var passArr = new ReadOnlySpan<byte>(pw, pwlen.ToInt32()).ToArray();
            var saltArr = new ReadOnlySpan<byte>(salt, saltlen.ToInt32()).ToArray();
            var pkdf = new Rfc2898DeriveBytes(passArr, saltArr, (int)iterations, HashAlgorithmName.SHA256);
            var keyArr = pkdf.GetBytes(keySpan.Length);
            keyArr.CopyTo(keySpan);
#endif
        }

        private static IntPtr Utf8Compose(byte* str, byte* norm)
        {
            var s = Marshal.PtrToStringUTF8(new IntPtr(str));
            s = s!.Normalize(NormalizationForm.FormC);
            var count = WriteNullTerminatedUtf8(s, norm, Polyseed.StrSize - 1);
            return new IntPtr(count);
        }

        private static IntPtr Utf8Decompose(byte* str, byte* norm)
        {
            var s = Marshal.PtrToStringUTF8(new IntPtr(str));
            s = s!.Normalize(NormalizationForm.FormKD);
            var count = WriteNullTerminatedUtf8(s, norm, Polyseed.StrSize - 1);
            return new IntPtr(count);
        }

        public static void ZeroMemory(void* ptr, IntPtr len)
        {
            CryptographicOperations.ZeroMemory(new Span<byte>(ptr, len.ToInt32()));
        }

        private static long Time(long* t)
        {
            var unixTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            if (t != null)
            {
                *t = unixTime;
            }
            return unixTime;
        }

        [DllImport(Polyseed.LibName)]
        static extern void polyseed_inject(PolyseedDependency* deps);
    }
}
