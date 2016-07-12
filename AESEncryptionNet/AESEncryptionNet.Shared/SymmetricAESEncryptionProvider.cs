#if WINDOWS_UWP
namespace AESEncryptionNet
{
    using System;
    using System.Linq;
    using System.Runtime.InteropServices.WindowsRuntime;
    using Windows.Security.Cryptography;
    using Windows.Security.Cryptography.Core;

    internal class SymmetricAESEncryptionProvider : IAESEncryptionProvider
    {
        public byte[] Encrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode)
        {
            SymmetricKeyAlgorithmProvider keyAlgorithmProvider;

            switch (cipherMode)
            {
                case AESCipherMode.CBC:
                    keyAlgorithmProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbc);
                    break;

                case AESCipherMode.ECB:
                    keyAlgorithmProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesEcb);
                    break;

                default:
                    throw new ArgumentException($"Unsupported AESCipherMode: {cipherMode}");
            }

            var cryptoKey = keyAlgorithmProvider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(key));
            var buffer = CryptographicBuffer.CreateFromByteArray(inputData);
            var encrypted = CryptographicEngine.Encrypt(cryptoKey, buffer, iv.AsBuffer());

            return encrypted.ToArray();
        }


        public byte[] Decrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode)
        {
            SymmetricKeyAlgorithmProvider keyAlgorithmProvider;

            switch (cipherMode)
            {
                case AESCipherMode.CBC:
                    keyAlgorithmProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbc);
                    break;

                case AESCipherMode.ECB:
                    keyAlgorithmProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesEcb);
                    break;

                default:
                    throw new ArgumentException($"Unsupported AESCipherMode: {cipherMode}");
            }

            var cryptoKey = keyAlgorithmProvider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(key));
            var buffer = CryptographicBuffer.CreateFromByteArray(inputData);
            var decrypted = CryptographicEngine.Decrypt(cryptoKey, buffer, iv.AsBuffer());

            return decrypted.ToArray();
        }
    }
}
#endif