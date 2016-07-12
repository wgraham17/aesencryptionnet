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
            var keyAlgorithmProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(cipherMode.ToSymmetricAlgorithmName());
            var cryptoKey = keyAlgorithmProvider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(key));
            var buffer = CryptographicBuffer.CreateFromByteArray(inputData);
            var encrypted = CryptographicEngine.Encrypt(cryptoKey, buffer, cipherMode == AESCipherMode.ECB || cipherMode == AESCipherMode.ECB_PKCS7 ? null : iv.AsBuffer());

            return encrypted.ToArray();
        }


        public byte[] Decrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode)
        {
            var keyAlgorithmProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(cipherMode.ToSymmetricAlgorithmName());
            var cryptoKey = keyAlgorithmProvider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(key));
            var buffer = CryptographicBuffer.CreateFromByteArray(inputData);
            var decrypted = CryptographicEngine.Decrypt(cryptoKey, buffer, cipherMode == AESCipherMode.ECB || cipherMode == AESCipherMode.ECB_PKCS7 ? null : iv.AsBuffer());

            return decrypted.ToArray();
        }
    }
}
#endif