using CryptographyPlayground.API.Services;

using Microsoft.AspNetCore.Mvc;

namespace CryptographyPlayground.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PGPController : ControllerBase
    {
        private readonly PGPService _pgpService;

        public PGPController(PGPService pgpService)
        {
            _pgpService = pgpService;
        }

        [HttpPost("encrypt")]
        public IActionResult EncryptMessage([FromBody] PgpEncryptRequest request)
        {
            string encryptedMessage = _pgpService.EncryptMessage(request.Message, "./RSAKeys/PGP/public.asc");
            if (encryptedMessage == null)
            {
                return BadRequest("Failed to encrypt the message.");
            }

            var result = new
            {
                EncryptedMessage = encryptedMessage
            };

            return Ok(result);
        }

        [HttpPost("decrypt")]
        public IActionResult DecryptMessage([FromBody] PgpDecryptRequest request)
        {
            string decryptedMessage = _pgpService.DecryptMessage(request.EncryptedMessage, "./RSAKeys/PGP/private.asc", request.Password);
            if (decryptedMessage == null)
            {
                return BadRequest("Failed to decrypt the message.");
            }

            var result = new
            {
                DecryptedMessage = decryptedMessage
            };

            return Ok(result);
        }

    }
    public class PgpEncryptRequest
    {
        public string Message { get; set; }
    }

    public class PgpDecryptRequest
    {
        public string EncryptedMessage { get; set; }
        public string Password { get; set; }
    }
}
