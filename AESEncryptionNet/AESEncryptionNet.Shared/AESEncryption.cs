namespace AESEncryptionNet
{
    public static class AESEncryption
    {
        private static IAESEncryptionProvider encryptionProvider;

        static AESEncryption()
        {
#if NETFX_FULL
            encryptionProvider = new CryptoAESEncryptionProvider();
#elif WINDOWS_UWP
            encryptionProvider = new SymmetricAESEncryptionProvider();
#else
            throw new System.PlatformNotSupportedException();
#endif
        }

        public static byte[] Encrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode)
        {
            return encryptionProvider.Encrypt(inputData, key, iv, cipherMode);
        }

        public static byte[] Decrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode)
        {
            return encryptionProvider.Decrypt(inputData, key, iv, cipherMode);
        }
    }
}
