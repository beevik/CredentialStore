using System;
using System.Runtime.InteropServices;
using System.Text;


namespace CredentialStore
{
    /// <summary>
    /// Represents a credential that may be loaded from or saved to a secure
    /// credential management system.
    /// </summary>
    public class Credential
    {
        /// <summary>
        /// The credential's identifier name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The password stored with the credential.
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// The optional user name associated with the credential. May be null.
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Construct a credential.
        /// </summary>
        /// <param name="name">The credential's identifier name.</param>
        public Credential(string name)
        {
            this.Name = name;
        }

        /// <summary>
        /// Construct a credential.
        /// </summary>
        /// <param name="name">The credential's identifier name.</param>
        /// <param name="userName">The user name associated with the credential.</param>
        public Credential(string name, string userName)
        {
            this.Name = name;
            this.UserName = userName;
        }

        /// <summary>
        /// Construct a credential.
        /// </summary>
        /// <param name="name">The credential's identifier name.</param>
        /// <param name="userName">The user name associated with the credential.</param>
        /// <param name="password">The password.</param>
        public Credential(string name, string userName, string password)
        {
            this.Name = name;
            this.UserName = userName;
            this.Password = password;
        }

        /// <summary>
        /// Delete the credential from the credential storage.
        /// </summary>
        public void Delete()
        {
            bool result = CredDelete(this.Name, (uint)CredentialType.Generic, 0);
            if (!result)
            {
                throw new Exception("failed to delete credential");
            }
        }

        /// <summary>
        /// Load the credential from secure credential storage.
        /// </summary>
        public void Load()
        {
            this.UserName = null;
            this.Password = null;

            IntPtr dataPtr = IntPtr.Zero;
            try
            {
                bool result = CredRead(this.Name, (uint)CredentialType.Generic, 0, out dataPtr);
                if (!result)
                {
                    throw new Exception("failed to load credential");
                }

                var data = (Data)Marshal.PtrToStructure(dataPtr, typeof(Data));
                this.UserName = data.UserName;

                if (data.CredentialBlobSize > 0)
                {
                    this.Password = Marshal.PtrToStringUTF8(data.CredentialBlob, (int)data.CredentialBlobSize);
                }
            }
            finally
            {
                if (dataPtr != IntPtr.Zero)
                {
                    CredFree(dataPtr);
                }
            }
        }

        /// <summary>
        /// Save the credential to secure credential storage.
        /// </summary>
        public void Save()
        {
            Data data = new Data
            {
                Flags = 0,
                Type = (uint)CredentialType.Generic,
                TargetName = this.Name,
                Comment = null,
                Persist = (uint)PersistenceType.LocalComputer,
                UserName = this.UserName
            };

            try
            {
                data.CredentialBlobSize = (uint)Encoding.UTF8.GetByteCount(this.Password);
                data.CredentialBlob = Marshal.StringToCoTaskMemUTF8(this.Password);

                bool result = CredWrite(ref data, 0);
                if (!result)
                {
                    throw new Exception("failed to save credential");
                }
            }
            finally
            {
                if (data.CredentialBlob != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(data.CredentialBlob);
                }
            }
        }

        private enum CredentialType : uint
        {
            None = 0,
            Generic = 1,
            DomainPassword = 2,
            DomainCertificate = 3,
            DomainVisiblePassword = 4
        }

        private enum PersistenceType : uint
        {
            Session = 1,
            LocalComputer = 2,
            Enterprise = 3
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Data
        {
            public uint Flags;

            public uint Type;

            [MarshalAs(UnmanagedType.LPStr)]
            public string TargetName;

            [MarshalAs(UnmanagedType.LPStr)]
            public string Comment;

            public long LastWritten;

            public uint CredentialBlobSize;

            public IntPtr CredentialBlob;

            public uint Persist;

            public uint AttributeCount;

            public IntPtr Attributes;

            [MarshalAs(UnmanagedType.LPStr)]
            public string TargetAlias;

            [MarshalAs(UnmanagedType.LPStr)]
            public string UserName;
        }

        [DllImport("advapi32", EntryPoint = "CredDeleteA", CharSet = CharSet.Ansi)]
        private static extern bool CredDelete(string target, uint type, uint flags);

        [DllImport("advapi32", EntryPoint = "CredReadA", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool CredRead(string target, uint type, uint flags, out IntPtr dataPtr);

        [DllImport("advapi32", EntryPoint = "CredWriteA", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool CredWrite([In] ref Data data, [In] UInt32 flags);

        [DllImport("advapi32", EntryPoint = "CredFree", SetLastError = true)]
        private static extern bool CredFree([In] IntPtr dataPtr);
    }
}
