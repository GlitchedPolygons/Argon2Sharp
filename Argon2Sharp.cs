//   Copyright 2020 Raphael Beck
// 
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
// 
//       http://www.apache.org/licenses/LICENSE-2.0
// 
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming

namespace Argon2Sharp
{
    /// <summary>
    /// Argon2 class that wraps the native C functions from the Argon2OptDll library. <para> </para>
    /// Copy this class into your own C# project and then don't forget to
    /// copy the lib/ folder to your own project's build output directory! <para> </para>
    /// By referencing <c>Argon2Sharp.csproj</c>, this should happen automatically!
    /// </summary>
    public class Argon2SharpContext : IDisposable
    {
        #region Shared library loaders (per platform implementations)

        private interface ISharedLibLoadUtils
        {
            IntPtr LoadLibrary(string fileName);
            void FreeLibrary(IntPtr handle);
            IntPtr GetProcAddress(IntPtr handle, string name);
        }

        private class SharedLibLoadUtilsWindows : ISharedLibLoadUtils
        {
            [DllImport("kernel32.dll")]
            private static extern IntPtr LoadLibrary(string fileName);

            [DllImport("kernel32.dll")]
            private static extern int FreeLibrary(IntPtr handle);

            [DllImport("kernel32.dll")]
            private static extern IntPtr GetProcAddress(IntPtr handle, string procedureName);

            void ISharedLibLoadUtils.FreeLibrary(IntPtr handle)
            {
                FreeLibrary(handle);
            }

            IntPtr ISharedLibLoadUtils.GetProcAddress(IntPtr dllHandle, string name)
            {
                return GetProcAddress(dllHandle, name);
            }

            IntPtr ISharedLibLoadUtils.LoadLibrary(string fileName)
            {
                return LoadLibrary(fileName);
            }
        }

        private class SharedLibLoadUtilsLinux : ISharedLibLoadUtils
        {
            const int RTLD_NOW = 2;

            [DllImport("libdl.so")]
            private static extern IntPtr dlopen(string fileName, int flags);

            [DllImport("libdl.so")]
            private static extern IntPtr dlsym(IntPtr handle, string symbol);

            [DllImport("libdl.so")]
            private static extern int dlclose(IntPtr handle);

            [DllImport("libdl.so")]
            private static extern IntPtr dlerror();

            public IntPtr LoadLibrary(string fileName)
            {
                return dlopen(fileName, RTLD_NOW);
            }

            public void FreeLibrary(IntPtr handle)
            {
                dlclose(handle);
            }

            public IntPtr GetProcAddress(IntPtr dllHandle, string name)
            {
                dlerror();
                IntPtr res = dlsym(dllHandle, name);
                IntPtr err = dlerror();
                if (err != IntPtr.Zero)
                {
                    throw new Exception("dlsym: " + Marshal.PtrToStringAnsi(err));
                }

                return res;
            }
        }

        private class SharedLibLoadUtilsMac : ISharedLibLoadUtils
        {
            const int RTLD_NOW = 2;

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlopen(string fileName, int flags);

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlsym(IntPtr handle, string symbol);

            [DllImport("libdl.dylib")]
            private static extern int dlclose(IntPtr handle);

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlerror();

            public IntPtr LoadLibrary(string fileName)
            {
                return dlopen(fileName, RTLD_NOW);
            }

            public void FreeLibrary(IntPtr handle)
            {
                dlclose(handle);
            }

            public IntPtr GetProcAddress(IntPtr dllHandle, string name)
            {
                dlerror();
                IntPtr res = dlsym(dllHandle, name);
                IntPtr err = dlerror();
                if (err != IntPtr.Zero)
                {
                    throw new Exception("dlsym: " + Marshal.PtrToStringAnsi(err));
                }

                return res;
            }
        }

        #endregion

        #region Function mapping

        private delegate int Argon2_HashEncoded_Delegate(
            [MarshalAs(UnmanagedType.U4)] uint t_cost,
            [MarshalAs(UnmanagedType.U4)] uint m_cost,
            [MarshalAs(UnmanagedType.U4)] uint parallelism,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pwd,
            [MarshalAs(UnmanagedType.U8)] ulong pwdlen,
            [MarshalAs(UnmanagedType.LPArray)] byte[] salt,
            [MarshalAs(UnmanagedType.U8)] ulong saltlen,
            [MarshalAs(UnmanagedType.U8)] ulong hashlen,
            [MarshalAs(UnmanagedType.LPArray)] byte[] encoded,
            [MarshalAs(UnmanagedType.U8)] ulong encodedlen
        );

        private delegate int Argon2_HashRaw_Delegate(
            [MarshalAs(UnmanagedType.U4)] uint t_cost,
            [MarshalAs(UnmanagedType.U4)] uint m_cost,
            [MarshalAs(UnmanagedType.U4)] uint parallelism,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pwd,
            [MarshalAs(UnmanagedType.U8)] ulong pwdlen,
            [MarshalAs(UnmanagedType.LPArray)] byte[] salt,
            [MarshalAs(UnmanagedType.U8)] ulong saltlen,
            [MarshalAs(UnmanagedType.LPArray)] byte[] hash,
            [MarshalAs(UnmanagedType.U8)] ulong hashlen
        );

        private delegate int Argon2_Verify_Delegate(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string encoded,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pwd,
            [MarshalAs(UnmanagedType.U8)] ulong pwdlen
        );

        private Argon2_HashEncoded_Delegate argon2i_HashEncoded_Delegate;
        private Argon2_HashEncoded_Delegate argon2d_HashEncoded_Delegate;
        private Argon2_HashEncoded_Delegate argon2id_HashEncoded_Delegate;
        private Argon2_HashRaw_Delegate argon2i_HashRaw_Delegate;
        private Argon2_HashRaw_Delegate argon2d_HashRaw_Delegate;
        private Argon2_HashRaw_Delegate argon2id_HashRaw_Delegate;
        private Argon2_Verify_Delegate argon2i_Verify_Delegate;
        private Argon2_Verify_Delegate argon2d_Verify_Delegate;
        private Argon2_Verify_Delegate argon2id_Verify_Delegate;

        #endregion

        private IntPtr lib;
        private ISharedLibLoadUtils loadUtils = null;

        /// <summary>
        /// Absolute path to the shared library that is currently loaded into memory for Argon2Sharp.
        /// </summary>
        public string LoadedLibraryPath { get; }

        /// <summary>
        /// Creates a new Argon2Sharp instance. <para> </para>
        /// Make sure to create one only once and cache it as needed, since loading the DLLs into memory could be, well, not so performant.
        /// <param name="sharedLibPathOverride">[OPTIONAL] Don't look for a <c>lib/</c> folder and directly use this path as a pre-resolved, platform-specific shared lib/DLL file path. Pass this if you want to handle the various platform's paths yourself.</param>
        /// </summary>
        public Argon2SharpContext(string sharedLibPathOverride = null)
        {
            string os;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                os = "windows";
                loadUtils = new SharedLibLoadUtilsWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                os = "linux";
                loadUtils = new SharedLibLoadUtilsLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                os = "mac";
                loadUtils = new SharedLibLoadUtilsMac();
            }
            else
            {
                throw new PlatformNotSupportedException("Unsupported OS");
            }

            if (!string.IsNullOrEmpty(sharedLibPathOverride))
            {
                LoadedLibraryPath = sharedLibPathOverride;
            }
            else
            {
                string cpu = RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.X64 => "x64",
                    Architecture.X86 => "x86",
                    Architecture.Arm => "armeabi-v7a",
                    Architecture.Arm64 => "arm64-v8a",
                    _ => throw new PlatformNotSupportedException("CPU Architecture not supported!")
                };

                string path = Path.Combine(Path.GetFullPath(Path.GetDirectoryName(Assembly.GetCallingAssembly().Location) ?? "."), "lib", cpu, os);

                if (!Directory.Exists(path))
                {
                    throw new PlatformNotSupportedException($"Shared library not found in {path} and/or unsupported CPU architecture. Please don't forget to copy the shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory. ");
                }

                bool found = false;
                foreach (string file in Directory.GetFiles(path))
                {
                    if (file.ToLower().Contains("argon2"))
                    {
                        LoadedLibraryPath = Path.GetFullPath(Path.Combine(path, file));
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    throw new FileLoadException($"Shared library not found in {path} and/or unsupported CPU architecture. Please don't forget to copy the shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory. ");
                }
            }

            lib = loadUtils.LoadLibrary(LoadedLibraryPath);
            if (lib == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2i_hash_encoded = loadUtils.GetProcAddress(lib, "argon2i_hash_encoded");
            if (argon2i_hash_encoded == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2d_hash_encoded = loadUtils.GetProcAddress(lib, "argon2d_hash_encoded");
            if (argon2d_hash_encoded == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2id_hash_encoded = loadUtils.GetProcAddress(lib, "argon2id_hash_encoded");
            if (argon2id_hash_encoded == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2i_hash_raw = loadUtils.GetProcAddress(lib, "argon2i_hash_raw");
            if (argon2i_hash_raw == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2d_hash_raw = loadUtils.GetProcAddress(lib, "argon2d_hash_raw");
            if (argon2d_hash_raw == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2id_hash_raw = loadUtils.GetProcAddress(lib, "argon2id_hash_raw");
            if (argon2id_hash_raw == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2i_verify = loadUtils.GetProcAddress(lib, "argon2i_verify");
            if (argon2i_verify == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2d_verify = loadUtils.GetProcAddress(lib, "argon2d_verify");
            if (argon2d_verify == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr argon2id_verify = loadUtils.GetProcAddress(lib, "argon2id_verify");
            if (argon2id_verify == IntPtr.Zero)
            {
                goto hell;
            }

            argon2i_HashEncoded_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_HashEncoded_Delegate>(argon2i_hash_encoded);
            argon2d_HashEncoded_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_HashEncoded_Delegate>(argon2d_hash_encoded);
            argon2id_HashEncoded_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_HashEncoded_Delegate>(argon2id_hash_encoded);
            argon2i_HashRaw_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_HashRaw_Delegate>(argon2i_hash_raw);
            argon2d_HashRaw_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_HashRaw_Delegate>(argon2d_hash_raw);
            argon2id_HashRaw_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_HashRaw_Delegate>(argon2id_hash_raw);
            argon2i_Verify_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_Verify_Delegate>(argon2i_verify);
            argon2d_Verify_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_Verify_Delegate>(argon2d_verify);
            argon2id_Verify_Delegate = Marshal.GetDelegateForFunctionPointer<Argon2_Verify_Delegate>(argon2id_verify);

            return;

            hell:
            throw new Exception($"Failed to load one or more functions from the shared library \"{LoadedLibraryPath}\"!");
        }

        /// <summary>
        /// Frees unmanaged resources (unloads the shared lib/dll).
        /// </summary>
        public void Dispose()
        {
            loadUtils.FreeLibrary(lib);
        }

        private static string Argon2_HashEncoded(Argon2_HashEncoded_Delegate algo, uint t_cost, uint m_cost, uint parallelism, byte[] password, byte[] salt = null, ulong hashlen = 64)
        {
            try
            {
                if (salt is null || salt.Length == 0)
                {
                    salt = new byte[32];
                    using var rng = new RNGCryptoServiceProvider();
                    rng.GetBytes(salt);
                }

                byte[] output = new byte[hashlen * 4];
                for (int i = 0; i < output.Length; i++)
                {
                    output[i] = 0x00;
                }

                int r = algo(t_cost, m_cost, parallelism, password, (ulong)password.LongLength, salt, (ulong)salt.LongLength, hashlen, output, (ulong)output.LongLength);
                if (r != 0)
                {
                    return null;
                }

                return Encoding.UTF8.GetString(output).TrimEnd('\0');
            }
            catch
            {
                return null;
            }
        }

        private static byte[] Argon2_HashRaw(Argon2_HashRaw_Delegate algo, uint t_cost, uint m_cost, uint parallelism, byte[] password, byte[] salt, ulong hashlen = 64)
        {
            try
            {
                byte[] output = new byte[hashlen];

                int r = algo(t_cost, m_cost, parallelism, password, (ulong)password.LongLength, salt, (ulong)(salt?.LongLength ?? 0), output, hashlen);
                if (r != 0)
                {
                    return null;
                }

                return output;
            }
            catch
            {
                return null;
            }
        }

        private static bool Argon2_Verify(Argon2_Verify_Delegate algo, string encoded, byte[] password)
        {
            try
            {
                int r = algo(encoded, password, (ulong)password.LongLength);
                return r == 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Hashes a password using Argon2i and encodes it along with its salt into a string.
        /// </summary>
        /// <param name="timeCost">The Argon2 time cost parameter (number of iterations) to use.</param>
        /// <param name="memoryCostKiB">The Argon2 memory cost parameter (in KiB) to use.</param>
        /// <param name="parallelism">Degree of parallelism to use for Argon2.</param>
        /// <param name="password">The password bytes.</param>
        /// <param name="salt">[OPTIONAL] Salt bytes; if left out (set to <c>null</c>), a random salt will be generated and used!</param>
        /// <param name="hashLength">[OPTIONAL] Desired hash length (default is <c>64</c>).</param>
        /// <returns>The encoded Argon2 hash; <c>null</c> if hashing and/or encoding failed.</returns>
        public string Argon2i_HashEncoded(uint timeCost, uint memoryCostKiB, uint parallelism, byte[] password, byte[] salt = null, ulong hashLength = 64)
        {
            return Argon2_HashEncoded(argon2i_HashEncoded_Delegate, timeCost, memoryCostKiB, parallelism, password, salt, hashLength);
        }

        /// <summary>
        /// Hashes a password using Argon2d and encodes it along with its salt into a string.
        /// </summary>
        /// <param name="timeCost">The Argon2 time cost parameter (number of iterations) to use.</param>
        /// <param name="memoryCostKiB">The Argon2 memory cost parameter (in KiB) to use.</param>
        /// <param name="parallelism">Degree of parallelism to use for Argon2.</param>
        /// <param name="password">The password bytes.</param>
        /// <param name="salt">[OPTIONAL] Salt bytes; if left out (set to <c>null</c>), a random salt will be generated and used!</param>
        /// <param name="hashLength">[OPTIONAL] Desired hash length (default is <c>64</c>).</param>
        /// <returns>The encoded Argon2 hash; <c>null</c> if hashing and/or encoding failed.</returns>
        public string Argon2d_HashEncoded(uint timeCost, uint memoryCostKiB, uint parallelism, byte[] password, byte[] salt = null, ulong hashLength = 64)
        {
            return Argon2_HashEncoded(argon2d_HashEncoded_Delegate, timeCost, memoryCostKiB, parallelism, password, salt, hashLength);
        }

        /// <summary>
        /// Hashes a password using Argon2id and encodes it along with its salt into a string.
        /// </summary>
        /// <param name="timeCost">The Argon2 time cost parameter (number of iterations) to use.</param>
        /// <param name="memoryCostKiB">The Argon2 memory cost parameter (in KiB) to use.</param>
        /// <param name="parallelism">Degree of parallelism to use for Argon2.</param>
        /// <param name="password">The password bytes.</param>
        /// <param name="salt">[OPTIONAL] Salt bytes; if left out (set to <c>null</c>), a random salt will be generated and used!</param>
        /// <param name="hashLength">[OPTIONAL] Desired hash length (default is <c>64</c>).</param>
        /// <returns>The encoded Argon2 hash; <c>null</c> if hashing and/or encoding failed.</returns>
        public string Argon2id_HashEncoded(uint timeCost, uint memoryCostKiB, uint parallelism, byte[] password, byte[] salt = null, ulong hashLength = 64)
        {
            return Argon2_HashEncoded(argon2id_HashEncoded_Delegate, timeCost, memoryCostKiB, parallelism, password, salt, hashLength);
        }

        /// <summary>
        /// Hashes a password using Argon2i and a given salt.
        /// </summary>
        /// <param name="timeCost">The Argon2 time cost parameter (number of iterations) to use.</param>
        /// <param name="memoryCostKiB">The Argon2 memory cost parameter (in KiB) to use.</param>
        /// <param name="parallelism">Degree of parallelism to use for Argon2.</param>
        /// <param name="password">The password bytes.</param>
        /// <param name="salt">Salt bytes: this is supposed to be a random array of bytes!</param>
        /// <param name="hashLength">[OPTIONAL] Desired hash length (default is <c>64</c>).</param>
        /// <returns>The hash bytes; <c>null</c> if hashing failed.</returns>
        public byte[] Argon2i_HashRaw(uint timeCost, uint memoryCostKiB, uint parallelism, byte[] password, byte[] salt, ulong hashLength = 64)
        {
            return Argon2_HashRaw(argon2i_HashRaw_Delegate, timeCost, memoryCostKiB, parallelism, password, salt, hashLength);
        }

        /// <summary>
        /// Hashes a password using Argon2d and a given salt.
        /// </summary>
        /// <param name="timeCost">The Argon2 time cost parameter (number of iterations) to use.</param>
        /// <param name="memoryCostKiB">The Argon2 memory cost parameter (in KiB) to use.</param>
        /// <param name="parallelism">Degree of parallelism to use for Argon2.</param>
        /// <param name="password">The password bytes.</param>
        /// <param name="salt">Salt bytes: this is supposed to be a random array of bytes!</param>
        /// <param name="hashLength">[OPTIONAL] Desired hash length (default is <c>64</c>).</param>
        /// <returns>The hash bytes; <c>null</c> if hashing failed.</returns>
        public byte[] Argon2d_HashRaw(uint timeCost, uint memoryCostKiB, uint parallelism, byte[] password, byte[] salt, ulong hashLength = 64)
        {
            return Argon2_HashRaw(argon2d_HashRaw_Delegate, timeCost, memoryCostKiB, parallelism, password, salt, hashLength);
        }

        /// <summary>
        /// Hashes a password using Argon2id and a given salt.
        /// </summary>
        /// <param name="timeCost">The Argon2 time cost parameter (number of iterations) to use.</param>
        /// <param name="memoryCostKiB">The Argon2 memory cost parameter (in KiB) to use.</param>
        /// <param name="parallelism">Degree of parallelism to use for Argon2.</param>
        /// <param name="password">The password bytes.</param>
        /// <param name="salt">Salt bytes: this is supposed to be a random array of bytes!</param>
        /// <param name="hashLength">[OPTIONAL] Desired hash length (default is <c>64</c>).</param>
        /// <returns>The hash bytes; <c>null</c> if hashing failed.</returns>
        public byte[] Argon2id_HashRaw(uint timeCost, uint memoryCostKiB, uint parallelism, byte[] password, byte[] salt, ulong hashLength = 64)
        {
            return Argon2_HashRaw(argon2id_HashRaw_Delegate, timeCost, memoryCostKiB, parallelism, password, salt, hashLength);
        }

        /// <summary>
        /// Verifies an Argon2i encoded hash against a given password.
        /// </summary>
        /// <param name="encoded">The encoded Argon2 hash to verify.</param>
        /// <param name="password">The password bytes to verify against.</param>
        /// <returns>Whether the password could be verified or not.</returns>
        public bool Argon2i_Verify(string encoded, byte[] password)
        {
            return Argon2_Verify(argon2i_Verify_Delegate, encoded, password);
        }

        /// <summary>
        /// Verifies an Argon2d encoded hash against a given password.
        /// </summary>
        /// <param name="encoded">The encoded Argon2 hash to verify.</param>
        /// <param name="password">The password bytes to verify against.</param>
        /// <returns>Whether the password could be verified or not.</returns>
        public bool Argon2d_Verify(string encoded, byte[] password)
        {
            return Argon2_Verify(argon2d_Verify_Delegate, encoded, password);
        }

        /// <summary>
        /// Verifies an Argon2id encoded hash against a given password.
        /// </summary>
        /// <param name="encoded">The encoded Argon2 hash to verify.</param>
        /// <param name="password">The password bytes to verify against.</param>
        /// <returns>Whether the password could be verified or not.</returns>
        public bool Argon2id_Verify(string encoded, byte[] password)
        {
            return Argon2_Verify(argon2id_Verify_Delegate, encoded, password);
        }

        /// <summary>
        /// Verifies an Argon2 encoded hash against a given password.
        /// </summary>
        /// <param name="encoded">The encoded Argon2 hash to verify.</param>
        /// <param name="password">The password bytes to verify against.</param>
        /// <returns>Whether the password could be verified or not.</returns>
        public bool Argon2_Verify(string encoded, byte[] password)
        {
            if (string.IsNullOrEmpty(encoded) || encoded.Length < 10)
            {
                return false;
            }

            if (encoded.StartsWith("$argon2i$"))
            {
                return Argon2i_Verify(encoded, password);
            }

            if (encoded.StartsWith("$argon2d$"))
            {
                return Argon2d_Verify(encoded, password);
            }

            if (encoded.StartsWith("$argon2id$"))
            {
                return Argon2id_Verify(encoded, password);
            }

            return false;
        }
    }

    //  --------------------------------------------------------------------
    //  ------------------------------> DEMO <------------------------------
    //  --------------------------------------------------------------------

    internal static class Example
    {
        // DEMO
        // This is an example Main method that shows how the various Argon2Sharp wrapper functionalities can be used.
        // Don't forget to copy the Argon2Sharp/src/lib folder into your output build directory, otherwise Argon2Sharp doesn't know from where to load the DLL/shared lib!

        private static void Main(string[] args)
        {
            using var argon2 = new Argon2SharpContext();

            Console.WriteLine("\nArgon2Sharp test\n");

            byte[] test_pw = Encoding.UTF8.GetBytes("Test PW");
            byte[] wrong_pw = Encoding.UTF8.GetBytes("Wrong PW");

            string argon2i_hash = argon2.Argon2i_HashEncoded(64, 65536, 4, test_pw);

            Console.WriteLine(argon2i_hash);
            Console.WriteLine("Valid: " + argon2.Argon2i_Verify(argon2i_hash, test_pw));
            Console.WriteLine("Valid (Generic) : " + argon2.Argon2_Verify(argon2i_hash, test_pw));
            Console.WriteLine("Test against wrong pw: " + (argon2.Argon2i_Verify(argon2i_hash, wrong_pw) ? "FAIL" : "PASS"));

            string argon2d_hash = argon2.Argon2d_HashEncoded(64, 65536, 4, test_pw);

            Console.WriteLine(argon2d_hash);
            Console.WriteLine("Valid: " + argon2.Argon2d_Verify(argon2d_hash, test_pw));
            Console.WriteLine("Valid (Generic) : " + argon2.Argon2_Verify(argon2d_hash, test_pw));
            Console.WriteLine("Test against wrong pw: " + (argon2.Argon2d_Verify(argon2d_hash, wrong_pw) ? "FAIL" : "PASS"));

            string argon2id_hash = argon2.Argon2id_HashEncoded(64, 65536, 4, test_pw);

            Console.WriteLine(argon2id_hash);
            Console.WriteLine("Valid: " + argon2.Argon2id_Verify(argon2id_hash, test_pw));
            Console.WriteLine("Valid (Generic) : " + argon2.Argon2_Verify(argon2id_hash, test_pw));
            Console.WriteLine("Test against wrong pw: " + (argon2.Argon2id_Verify(argon2id_hash, wrong_pw) ? "FAIL" : "PASS"));

            byte[] test_salt = Encoding.UTF8.GetBytes("Test Salt 123!!!");

            Console.WriteLine("Testing raw hash... Salt: " + Convert.ToBase64String(test_salt));

            byte[] argon2i_raw = argon2.Argon2i_HashRaw(64, 65536, 4, test_pw, test_salt);

            Console.WriteLine("Argon2i raw hash: " + Convert.ToBase64String(argon2i_raw));

            byte[] argon2d_raw = argon2.Argon2d_HashRaw(64, 65536, 4, test_pw, test_salt);

            Console.WriteLine("Argon2d raw hash: " + Convert.ToBase64String(argon2d_raw));

            byte[] argon2id_raw = argon2.Argon2id_HashRaw(64, 65536, 4, test_pw, test_salt);

            Console.WriteLine("Argon2id raw hash: " + Convert.ToBase64String(argon2id_raw));
        }
    }
}