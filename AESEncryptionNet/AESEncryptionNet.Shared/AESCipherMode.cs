namespace AESEncryptionNet
{
    using System;

    public enum AESCipherMode
    {
        ECB,
        ECB_PKCS7,
        CBC,
        CBC_PKCS7
    }

    public static class AESCipherModeExtensions
    {
#if WINDOWS_UWP
        public static string ToSymmetricAlgorithmName(this AESCipherMode source)
        {
            switch (source)
            {
                case AESCipherMode.ECB:
                    return Windows.Security.Cryptography.Core.SymmetricAlgorithmNames.AesEcb;

                case AESCipherMode.ECB_PKCS7:
                    return Windows.Security.Cryptography.Core.SymmetricAlgorithmNames.AesEcbPkcs7;

                case AESCipherMode.CBC:
                    return Windows.Security.Cryptography.Core.SymmetricAlgorithmNames.AesCbc;

                case AESCipherMode.CBC_PKCS7:
                    return Windows.Security.Cryptography.Core.SymmetricAlgorithmNames.AesCbcPkcs7;

                default:
                    throw new ArgumentException($"Could not convert AESCipherMode {source} to SymmetricAlgorithmName");
            }
        }
#endif
#if NETFX_FULL
        public static System.Security.Cryptography.CipherMode ToCipherMode(this AESCipherMode source)
        {
            switch (source)
            {
                case AESCipherMode.ECB:
                case AESCipherMode.ECB_PKCS7:
                    return System.Security.Cryptography.CipherMode.ECB;

                case AESCipherMode.CBC:
                case AESCipherMode.CBC_PKCS7:
                    return System.Security.Cryptography.CipherMode.CBC;

                default:
                    throw new ArgumentException($"Could not convert AESCipherMode {source} to type System.Security.Cryptography.CipherMode");
            }
        }

        public static System.Security.Cryptography.PaddingMode ToPaddingMode(this AESCipherMode source)
        {
            switch (source)
            {
                case AESCipherMode.CBC:
                case AESCipherMode.ECB:
                    return System.Security.Cryptography.PaddingMode.None;

                case AESCipherMode.ECB_PKCS7:
                case AESCipherMode.CBC_PKCS7:
                    return System.Security.Cryptography.PaddingMode.PKCS7;

                default:
                    throw new ArgumentException($"Could not convert AESCipherMode {source} to type System.Security.Cryptography.PaddingMode");
            }
        }
#endif
    }
}
