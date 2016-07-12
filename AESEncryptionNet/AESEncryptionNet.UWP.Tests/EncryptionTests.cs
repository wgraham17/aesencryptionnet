namespace AESEncryptionNet.Tests
{
#if WINDOWS_UWP
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
#endif
    using System.Text;

    [TestClass]
    public class EncryptionTests
    {
        private static byte[] IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private static byte[] Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        [TestMethod]
        public void Test_AES_CBC()
        {
            var testMessage = "Hello World 1234";
            var data = Encoding.ASCII.GetBytes(testMessage);
            var encrypted = AESEncryption.Encrypt(data, Key, IV, AESCipherMode.CBC);
            var decrypted = AESEncryption.Decrypt(encrypted, Key, IV, AESCipherMode.CBC);
            var decryptedMessage = Encoding.ASCII.GetString(decrypted);

            Assert.AreEqual(testMessage, decryptedMessage);
        }

        [TestMethod]
        public void Test_AES_CBC_PKCS7()
        {
            var testMessage = "Hello World";
            var data = Encoding.ASCII.GetBytes(testMessage);
            var encrypted = AESEncryption.Encrypt(data, Key, IV, AESCipherMode.CBC_PKCS7);
            var decrypted = AESEncryption.Decrypt(encrypted, Key, IV, AESCipherMode.CBC_PKCS7);
            var decryptedMessage = Encoding.ASCII.GetString(decrypted);

            Assert.AreEqual(testMessage, decryptedMessage);
        }

        [TestMethod]
        public void Test_AES_ECB()
        {
            var testMessage = "Hello World 1234";
            var data = Encoding.ASCII.GetBytes(testMessage);
            var encrypted = AESEncryption.Encrypt(data, Key, IV, AESCipherMode.ECB);
            var decrypted = AESEncryption.Decrypt(encrypted, Key, IV, AESCipherMode.ECB);
            var decryptedMessage = Encoding.ASCII.GetString(decrypted);

            Assert.AreEqual(testMessage, decryptedMessage);
        }

        [TestMethod]
        public void Test_AES_ECB_PKCS7()
        {
            var testMessage = "Hello World";
            var data = Encoding.ASCII.GetBytes(testMessage);
            var encrypted = AESEncryption.Encrypt(data, Key, IV, AESCipherMode.ECB_PKCS7);
            var decrypted = AESEncryption.Decrypt(encrypted, Key, IV, AESCipherMode.ECB_PKCS7);
            var decryptedMessage = Encoding.ASCII.GetString(decrypted);

            Assert.AreEqual(testMessage, decryptedMessage);
        }
    }
}
