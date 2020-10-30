﻿using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming

namespace Argon2Sharp
{
    /// <summary>
    /// Argon2 class that wraps the native C functions from the Argon2OptDll library. <para> </para>
    /// Copy this class into your own C# project and then don't forget to
    /// copy the lib/ folder to your own project's build output directory!
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

        #region Struct mapping

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

            if (string.IsNullOrEmpty(sharedLibPathOverride))
            {
                StringBuilder pathBuilder = new StringBuilder(256);
                pathBuilder.Append("lib/");

                switch (RuntimeInformation.ProcessArchitecture)
                {
                    case Architecture.X64:
                        pathBuilder.Append("x64/");
                        break;
                    case Architecture.X86:
                        pathBuilder.Append("x86/");
                        break;
                    case Architecture.Arm:
                        pathBuilder.Append("armeabi-v7a/");
                        break;
                    case Architecture.Arm64:
                        pathBuilder.Append("arm64-v8a/");
                        break;
                }

                if (!Directory.Exists(pathBuilder.ToString()))
                {
                    throw new PlatformNotSupportedException($"shared library not found in {pathBuilder.ToString()} and/or unsupported CPU architecture. Please don't forget to copy the shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory. ");
                }

                pathBuilder.Append(os);
                pathBuilder.Append('/');

                string[] l = Directory.GetFiles(pathBuilder.ToString());
                if (l == null || l.Length != 1)
                {
                    throw new FileLoadException("There should only be exactly one shared library file per supported platform!");
                }

                pathBuilder.Append(Path.GetFileName(l[0]));
                LoadedLibraryPath = Path.GetFullPath(pathBuilder.ToString());
                pathBuilder.Clear();
            }
            else
            {
                LoadedLibraryPath = sharedLibPathOverride;
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

                int r = algo(t_cost, m_cost, parallelism, password, (ulong)password.LongLength, salt, (ulong)salt.LongLength, hashlen, output, (ulong)output.LongLength);
                if (r != 0)
                {
                    return null;
                }

                return Encoding.UTF8.GetString(output);
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

        public string Argon2i_HashEncoded(uint t_cost, uint m_cost, uint parallelism, byte[] password, byte[] salt = null, ulong hashlen = 64)
        {
            return Argon2_HashEncoded(argon2i_HashEncoded_Delegate, t_cost, m_cost, parallelism, password, salt, hashlen);
        }

        public string Argon2d_HashEncoded(uint t_cost, uint m_cost, uint parallelism, byte[] password, byte[] salt = null, ulong hashlen = 64)
        {
            return Argon2_HashEncoded(argon2d_HashEncoded_Delegate, t_cost, m_cost, parallelism, password, salt, hashlen);
        }

        public string Argon2id_HashEncoded(uint t_cost, uint m_cost, uint parallelism, byte[] password, byte[] salt = null, ulong hashlen = 64)
        {
            return Argon2_HashEncoded(argon2id_HashEncoded_Delegate, t_cost, m_cost, parallelism, password, salt, hashlen);
        }

        public byte[] Argon2i_HashRaw(uint t_cost, uint m_cost, uint parallelism, byte[] password, byte[] salt, ulong hashlen = 64)
        {
            return Argon2_HashRaw(argon2i_HashRaw_Delegate, t_cost, m_cost, parallelism, password, salt, hashlen);
        }

        public byte[] Argon2d_HashRaw(uint t_cost, uint m_cost, uint parallelism, byte[] password, byte[] salt, ulong hashlen = 64)
        {
            return Argon2_HashRaw(argon2d_HashRaw_Delegate, t_cost, m_cost, parallelism, password, salt, hashlen);
        }

        public byte[] Argon2id_HashRaw(uint t_cost, uint m_cost, uint parallelism, byte[] password, byte[] salt, ulong hashlen = 64)
        {
            return Argon2_HashRaw(argon2id_HashRaw_Delegate, t_cost, m_cost, parallelism, password, salt, hashlen);
        }

        public bool Argon2i_Verify(string encoded, byte[] password)
        {
            return Argon2_Verify(argon2i_Verify_Delegate, encoded, password);
        }

        public bool Argon2d_Verify(string encoded, byte[] password)
        {
            return Argon2_Verify(argon2d_Verify_Delegate, encoded, password);
        }

        public bool Argon2id_Verify(string encoded, byte[] password)
        {
            return Argon2_Verify(argon2id_Verify_Delegate, encoded, password);
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
            
            Console.WriteLine("\n\nArgon2 test\n");

            byte[] test_pw = Encoding.UTF8.GetBytes("Test PW");
            byte[] wrong_pw = Encoding.UTF8.GetBytes("Wrong PW");

            string argon2i_hash = argon2.Argon2i_HashEncoded(64, 65536, 4, test_pw);
            
            Console.WriteLine(argon2i_hash);
            Console.WriteLine("Valid: " + argon2.Argon2i_Verify(argon2i_hash, test_pw));
            Console.WriteLine("Test against wrong pw: " + (argon2.Argon2i_Verify(argon2i_hash, wrong_pw) ? "FAIL" : "OK"));

            string argon2d_hash = argon2.Argon2d_HashEncoded(64, 65536, 4, test_pw);
            
            Console.WriteLine(argon2d_hash);
            Console.WriteLine("Valid: " + argon2.Argon2d_Verify(argon2d_hash, test_pw));
            Console.WriteLine("Test against wrong pw: " + (argon2.Argon2d_Verify(argon2d_hash, wrong_pw) ? "FAIL" : "OK"));

            string argon2id_hash = argon2.Argon2id_HashEncoded(64, 65536, 4, test_pw);
            
            Console.WriteLine(argon2id_hash);
            Console.WriteLine("Valid: " + argon2.Argon2id_Verify(argon2id_hash, test_pw));
            Console.WriteLine("Test against wrong pw: " + (argon2.Argon2id_Verify(argon2id_hash, wrong_pw) ? "FAIL" : "OK"));

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