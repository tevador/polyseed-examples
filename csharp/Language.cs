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
using System.Text;
using System.Runtime.InteropServices;

namespace PolyseedSharp
{
    public class Language
    {
        public static IReadOnlyList<Language> List => s_list.Value;
        public string Name { get; }
        public string EnglishName { get; }

        public override string ToString()
        {
            return this.EnglishName;
        }

        internal IntPtr Handle { get; }

        static readonly Lazy<IReadOnlyList<Language>> s_list = new Lazy<IReadOnlyList<Language>>(InitLanguages);

        Language(string name, string englishName, IntPtr handle)
        {
            this.Name = name;
            this.EnglishName = englishName;
            this.Handle = handle;
        }

        static IReadOnlyList<Language> InitLanguages()
        {
            var list = new List<Language>();
            var numLangs = polyseed_get_num_langs();
            for (int i = 0; i < numLangs; i++)
            {
                var langPtr = polyseed_get_lang(i);
                var name = Marshal.PtrToStringUTF8(polyseed_get_lang_name(langPtr))!.ToString();
                var englishName = Marshal.PtrToStringUTF8(polyseed_get_lang_name_en(langPtr))!.ToString();
                list.Add(new Language(name, englishName, langPtr));
            }
            return list.AsReadOnly();
        }

        [DllImport(Polyseed.LibName)]
        static extern int polyseed_get_num_langs();

        [DllImport(Polyseed.LibName)]
        static extern IntPtr polyseed_get_lang(int i);

        [DllImport(Polyseed.LibName)]
        static extern IntPtr polyseed_get_lang_name(IntPtr lang);

        [DllImport(Polyseed.LibName)]
        static extern IntPtr polyseed_get_lang_name_en(IntPtr lang);
    }
}
