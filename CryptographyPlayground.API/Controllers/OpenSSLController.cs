using CryptographyPlayground.API.Services;

using Microsoft.AspNetCore.Mvc;

namespace CryptographyPlayground.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OpenSSLController : ControllerBase
    {
        private readonly OpenSSLService _encryptionService;

        public OpenSSLController(OpenSSLService encryptionService)
        {
            _encryptionService = encryptionService;
        }

        [HttpPost("encrypt")]
        public IActionResult EncryptData([FromBody] EncryptRequest request)
        {
            string randomSymmetricKey = _encryptionService.GenerateRandomSymmetricKey(32); // 32 bytes for AES-256
            string encryptedSymmetricKey = _encryptionService.EncryptSymmetricKey(randomSymmetricKey, "./RSAKeys/OpenSSL/public.pem");
            if (encryptedSymmetricKey == null)
            {
                return BadRequest("Failed to encrypt the symmetric key.");
            }

            string encryptedData = _encryptionService.EncryptDataBySymmetricKey(request.DataToEncrypt, randomSymmetricKey);
            if (encryptedData == null)
            {
                return BadRequest("Failed to encrypt the data.");
            }

            var result = new
            {
                DataToEncrypt = request.DataToEncrypt,
                SymmetricKey = randomSymmetricKey,
                EncryptedSymmetricKey = encryptedSymmetricKey,
                EncryptedData = encryptedData
            };

            return Ok(result);
        }

        [HttpPost("decrypt")]
        public IActionResult DecryptData([FromBody] DecryptRequest request)
        {
            string decryptedData = _encryptionService.DecryptData(request.EncryptedSymmetricKey, request.EncryptedData, "./RSAKeys/OpenSSL/private.pem");
            if (decryptedData == null)
            {
                return BadRequest("Failed to decrypt the data.");
            }

            var result = new
            {
                DecryptedData = decryptedData
            };

            return Ok(result);
        }
    }

    public class EncryptRequest
    {
        public string DataToEncrypt { get; set; }
    }

    public class DecryptRequest
    {
        public string EncryptedSymmetricKey { get; set; }
        public string EncryptedData { get; set; }
    }
}
