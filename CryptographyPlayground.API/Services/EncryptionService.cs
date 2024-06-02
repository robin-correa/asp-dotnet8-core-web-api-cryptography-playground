using System.Security.Cryptography;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;


namespace CryptographyPlayground.API.Services
{
    public class EncryptionService
    {
        public string GenerateRandomSymmetricKey(int length)
        {
            using var rng = new RNGCryptoServiceProvider();
            byte[] key = new byte[length];
            rng.GetBytes(key);
            return Convert.ToBase64String(key);
        }

        public string EncryptSymmetricKey(string symmetricKey, string publicKeyPath)
        {
            var publicKey = File.ReadAllText(publicKeyPath);
            var rsaKeyParameters = (RsaKeyParameters)new PemReader(new StringReader(publicKey)).ReadObject();
            var rsaEngine = new OaepEncoding(new RsaEngine(), new Sha256Digest());
            rsaEngine.Init(true, rsaKeyParameters);

            byte[] inputBytes = Convert.FromBase64String(symmetricKey);
            byte[] encryptedBytes = rsaEngine.ProcessBlock(inputBytes, 0, inputBytes.Length);

            return Convert.ToBase64String(encryptedBytes);
        }

        public string EncryptDataBySymmetricKey(string dataToEncrypt, string base64SymmetricKey)
        {
            byte[] key = Convert.FromBase64String(base64SymmetricKey);
            byte[] iv = new byte[16]; // Zero initialization vector

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (var swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
            {
                swEncrypt.Write(dataToEncrypt);
            }

            byte[] encryptedData = msEncrypt.ToArray();
            return Convert.ToBase64String(encryptedData);
        }

        public string DecryptSymmetricKey(string encryptedSymmetricKey, string privateKeyPath)
        {
            var privateKey = File.ReadAllText(privateKeyPath);
            var rsaKeyParameters = (AsymmetricCipherKeyPair)new PemReader(new StringReader(privateKey)).ReadObject();
            var rsaEngine = new OaepEncoding(new RsaEngine(), new Sha256Digest());
            rsaEngine.Init(false, rsaKeyParameters.Private);

            byte[] encryptedBytes = Convert.FromBase64String(encryptedSymmetricKey);
            byte[] decryptedBytes = rsaEngine.ProcessBlock(encryptedBytes, 0, encryptedBytes.Length);

            return Convert.ToBase64String(decryptedBytes); // Return Base64 encoded key
        }

        public string DecryptData(string encryptedSymmetricKey, string encryptedData, string privateKeyPath)
        {
            string base64DecryptedSymmetricKey = DecryptSymmetricKey(encryptedSymmetricKey, privateKeyPath);
            byte[] key = Convert.FromBase64String(base64DecryptedSymmetricKey);

            if (key.Length != 32)
            {
                throw new CryptographicException("The symmetric key is not 256 bits (32 bytes) long.");
            }

            byte[] iv = new byte[16]; // Zero initialization vector
            byte[] cipherText = Convert.FromBase64String(encryptedData);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var msDecrypt = new MemoryStream(cipherText);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8);
            return srDecrypt.ReadToEnd();
        }
    }
}
