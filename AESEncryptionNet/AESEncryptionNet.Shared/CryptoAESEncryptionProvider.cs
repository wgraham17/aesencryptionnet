#if NETFX_FULL
namespace AESEncryptionNet
{
    using System.IO;
    using System.Security.Cryptography;

    internal class CryptoAESEncryptionProvider : IAESEncryptionProvider
    {
        public byte[] Encrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode)
        {
            var aes = new AesManaged();
            aes.IV = iv;
            aes.Key = key;
            aes.Mode = cipherMode.ToCipherMode();
            aes.Padding = cipherMode.ToPaddingMode();

            using (var transform = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                {
                    cs.Write(inputData, 0, inputData.Length);
                }

                return ms.ToArray();
            }
        }

        public byte[] Decrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode)
        {
            var aes = new AesManaged();
            aes.IV = iv;
            aes.Key = key;
            aes.Mode = cipherMode.ToCipherMode();
            aes.Padding = cipherMode.ToPaddingMode();

            using (var transform = aes.CreateDecryptor())
            using (var ms = new MemoryStream(inputData))
            using (var msOut = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
                {
                    cs.CopyTo(msOut);
                }

                return msOut.ToArray();
            }
        }
    }
}
#endif