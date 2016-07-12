using System;
using System.Collections.Generic;
using System.Text;

namespace AESEncryptionNet
{
    internal interface IAESEncryptionProvider
    {
        byte[] Encrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode);

        byte[] Decrypt(byte[] inputData, byte[] key, byte[] iv, AESCipherMode cipherMode);
    }
}
