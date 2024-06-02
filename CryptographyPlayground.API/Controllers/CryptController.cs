using CryptographyPlayground.API.Services;

using Microsoft.AspNetCore.Mvc;

namespace CryptographyPlayground.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CryptController : ControllerBase
    {
        private readonly EncryptionService _encryptionService;

        public CryptController(EncryptionService encryptionService)
        {
            _encryptionService = encryptionService;
        }

        [HttpPost("encrypt")]
        public IActionResult EncryptData([FromBody] EncryptRequest request)
        {
            string randomSymmetricKey = _encryptionService.GenerateRandomSymmetricKey(32);
            string encryptedSymmetricKey = _encryptionService.EncryptSymmetricKey(randomSymmetricKey, "./RSAKeys/public.pem");
            string encryptedData = _encryptionService.EncryptDataBySymmetricKey(request.DataToEncrypt, randomSymmetricKey);

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
            string decryptedData = _encryptionService.DecryptData(request.EncryptedSymmetricKey, request.EncryptedData, "./RSAKeys/private.pem");

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
