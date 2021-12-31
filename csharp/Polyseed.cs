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
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace PolyseedSharp
{
    public class Polyseed : SafeHandle
    {
        public override bool IsInvalid => this.handle == IntPtr.Zero;

        public bool IsEncrypted => polyseed_is_encrypted(this);

        public DateTimeOffset Birthday => DateTimeOffset.FromUnixTimeSeconds(polyseed_get_birthday(this));

        private static void CheckEnum<TFeatures>()
            where TFeatures : Enum
        {
            if (!typeof(TFeatures).IsDefined(typeof(FlagsAttribute), false))
            {
                throw new ArgumentException($"Type {typeof(TFeatures)} must have the Flags attribute");
            }
        }

        public static int EnableFeatures<TFeatures>()
            where TFeatures : Enum
        {
            CheckEnum<TFeatures>();
            uint features = 0;
            foreach(var feature in Enum.GetValues(typeof(TFeatures)))
            {
                features |= Convert.ToUInt32(feature);
            }
            return polyseed_enable_features(features);
        }

        public static Polyseed Create<TFeatures>(TFeatures features)
            where TFeatures : Enum
        {
            Dependency.Init();
            CheckEnum<TFeatures>();
            IntPtr ptr = IntPtr.Zero;
            var status = polyseed_create(Convert.ToUInt32(features), ref ptr);
            if (status != Status.OK)
            {
                throw new PolyseedException(status);
            }
            return new Polyseed(ptr);
        }

        public static Polyseed Parse(string phrase, Coin coin, out Language lang)
        {
            Dependency.Init();
            phrase = phrase ?? throw new ArgumentNullException(nameof(phrase));
            IntPtr langPtr = IntPtr.Zero;
            IntPtr seedPtr = IntPtr.Zero;
            var status = polyseed_decode(phrase, coin, ref langPtr, ref seedPtr);
            if (status != Status.OK)
            {
                throw new PolyseedException(status);
            }
            lang = Language.List.Single(x => x.Handle == langPtr);
            return new Polyseed(seedPtr);
        }

        public static unsafe Polyseed Load(ReadOnlySpan<byte> buf)
        {
            Dependency.Init();
            fixed (byte* ptr = buf)
            {
                IntPtr seedPtr = IntPtr.Zero;
                var status = polyseed_load(ptr, ref seedPtr);
                if (status != Status.OK)
                {
                    throw new PolyseedException(status);
                }
                return new Polyseed(seedPtr);
            }
        }

        public bool HasFeature<TFeatures>(TFeatures feature)
            where TFeatures : Enum
        {
            CheckEnum<TFeatures>();
            return polyseed_get_feature(this, Convert.ToUInt32(feature)) != 0;
        }

        public unsafe void GenerateKey(Coin coin, Span<byte> key)
        {
            fixed (byte* ptr = key)
            {
                polyseed_keygen(this, coin, new IntPtr(key.Length), ptr);
            }
        }

        public unsafe string ToString(Language lang, Coin coin)
        {
            lang = lang ?? throw new ArgumentNullException(nameof(lang));
            byte* str = stackalloc byte[StrSize];
            var size = polyseed_encode(this, lang.Handle, coin, str);
            return Marshal.PtrToStringUTF8(new IntPtr(str), size.ToInt32())!.ToString();
        }

        public unsafe int Store(Span<byte> buf)
        {
            if (buf.Length < Size)
            {
                throw new ArgumentException($"Span must be at least {Size} bytes");
            }
            fixed (byte* ptr = buf)
            {
                polyseed_store(this, ptr);
            }
            return Size;
        }

        public void Crypt(string password)
        {
            polyseed_crypt(this, password);
        }

        internal const int Size = 32;
        internal const int StrSize = 360;
        internal const string LibName = "polyseed";

        protected override bool ReleaseHandle()
        {
            polyseed_free(this.handle);
            return true;
        }

        Polyseed(IntPtr validHandle) : this()
        {
            SetHandle(validHandle);
        }

        Polyseed() : base(IntPtr.Zero, true)
        {
        }

        [DllImport(LibName)]
        static extern int polyseed_enable_features(uint features);

        [DllImport(LibName)]
        static extern Status polyseed_create(uint features, ref IntPtr seed_out);

        [DllImport(LibName)]
        static extern void polyseed_free(IntPtr handle);

        [DllImport(LibName)]
        static extern long polyseed_get_birthday(Polyseed seed);

        [DllImport(LibName)]
        static extern uint polyseed_get_feature(Polyseed seed, uint mask);

        [DllImport(LibName)]
        static extern unsafe void polyseed_keygen(Polyseed seed, Coin coin,
            IntPtr key_size, byte* key_out);

        [DllImport(LibName)]
        static extern unsafe IntPtr polyseed_encode(Polyseed seed, IntPtr lang,
            Coin coin, byte* str_out);

        [DllImport(LibName)]
        static extern Status polyseed_decode(
            [MarshalAs(UnmanagedType.LPUTF8Str)]
            string str,
            Coin coin, ref IntPtr lang_out, ref IntPtr seed_out);

        [DllImport(LibName)]
        static extern unsafe void polyseed_store(Polyseed seed, byte* buf);

        [DllImport(LibName)]
        static extern unsafe Status polyseed_load(byte* buf, ref IntPtr seed_out);

        [DllImport(LibName)]
        static extern void polyseed_crypt(Polyseed seed,
            [MarshalAs(UnmanagedType.LPUTF8Str)]
            string str);

        [DllImport(LibName)]
        static extern bool polyseed_is_encrypted(Polyseed seed);
    }
}
