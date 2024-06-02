using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace CryptographyPlayground.API.Services
{
    public class PGPService
    {
        public string EncryptMessage(string message, string publicKeyPath)
        {
            try
            {
                var publicKey = ReadPublicKey(publicKeyPath);
                var literalData = Encoding.UTF8.GetBytes(message);
                using (var outputStream = new MemoryStream())
                {
                    var encryptedData = EncryptData(literalData, publicKey);
                    return Convert.ToBase64String(encryptedData);
                }
            }
            catch (Exception)
            {
                return null; // Indicate failure
            }
        }

        public string DecryptMessage(string encryptedMessage, string privateKeyPath, string password)
        {
            try
            {
                var privateKey = ReadPrivateKey(privateKeyPath, password);
                var encryptedData = Convert.FromBase64String(encryptedMessage);
                using (var inputStream = new MemoryStream(encryptedData))
                {
                    var decryptedData = DecryptData(inputStream, privateKey);
                    return Encoding.UTF8.GetString(decryptedData);
                }
            }
            catch (Exception)
            {
                return null; // Indicate failure
            }
        }

        private PgpPublicKey ReadPublicKey(string publicKeyPath)
        {
            using (StreamReader reader = File.OpenText(publicKeyPath))
            {
                PgpPublicKeyRingBundle keyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(reader.BaseStream));
                foreach (PgpPublicKeyRing keyRing in keyRingBundle.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        if (key.IsEncryptionKey)
                        {
                            return key;
                        }
                    }
                }
            }
            throw new ArgumentException("Can't find encryption key in public key ring.");
        }

        private PgpPrivateKey ReadPrivateKey(string privateKeyPath, string password)
        {
            using (StreamReader reader = File.OpenText(privateKeyPath))
            {
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(reader.BaseStream));
                foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                    {
                        PgpPrivateKey privateKey = key.ExtractPrivateKey(password.ToCharArray());
                        if (privateKey != null)
                        {
                            return privateKey;
                        }
                    }
                }
            }
            throw new ArgumentException("Can't find private key in key ring.");
        }

        private byte[] EncryptData(byte[] data, PgpPublicKey publicKey)
        {
            using (MemoryStream bOut = new MemoryStream())
            {
                using (Stream literalOut = new MemoryStream(data))
                {
                    PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
                    Stream pOut = lData.Open(bOut, PgpLiteralData.Binary, "filename", data.Length, DateTime.UtcNow);

                    int ch;
                    while ((ch = literalOut.ReadByte()) >= 0)
                    {
                        pOut.WriteByte((byte)ch);
                    }
                    pOut.Close();
                }

                PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, true, new SecureRandom());
                encGen.AddMethod(publicKey);
                byte[] bytes = bOut.ToArray();
                bOut.Close();

                using (MemoryStream cOut = new MemoryStream())
                {
                    Stream outStr = encGen.Open(cOut, bytes.Length);
                    outStr.Write(bytes, 0, bytes.Length);
                    outStr.Close();

                    return cOut.ToArray();
                }
            }
        }
        private byte[] DecryptData(Stream inputStream, PgpPrivateKey privateKey)
        {
            PgpObjectFactory pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            PgpEncryptedDataList enc;
            PgpObject o = pgpF.NextPgpObject();

            if (o is PgpEncryptedDataList)
            {
                enc = (PgpEncryptedDataList)o;
            }
            else
            {
                enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
            }

            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                if (pked.KeyId == privateKey.KeyId)
                {
                    Stream clear = pked.GetDataStream(privateKey);
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                    PgpObject message = plainFact.NextPgpObject();

                    if (message is PgpCompressedData)
                    {
                        PgpCompressedData cData = (PgpCompressedData)message;
                        PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

                        message = pgpFact.NextPgpObject();
                    }

                    if (message is PgpLiteralData)
                    {
                        PgpLiteralData ld = (PgpLiteralData)message;
                        MemoryStream ms = new MemoryStream();
                        Stream unc = ld.GetInputStream();
                        int ch;
                        while ((ch = unc.ReadByte()) >= 0)
                        {
                            ms.WriteByte((byte)ch);
                        }
                        return ms.ToArray();
                    }
                }
            }
            throw new ArgumentException("Decryption failed.");
        }
    }
}