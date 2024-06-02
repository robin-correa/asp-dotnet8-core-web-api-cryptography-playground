using System.Text;

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

            // Wrap encrypted message with PGP header and footer
            string pgpMessage = $"-----BEGIN PGP MESSAGE-----\n\n{encryptedMessage}\n\n-----END PGP MESSAGE-----";

            return Content(pgpMessage, "text/plain");
        }

        [HttpPost("decrypt")]
        public async Task<IActionResult> DecryptMessage([FromServices] IHttpContextAccessor httpContextAccessor)
        {
            var request = httpContextAccessor.HttpContext.Request;
            using (StreamReader reader = new StreamReader(request.Body, Encoding.UTF8))
            {
                string pgpMessage = await reader.ReadToEndAsync();
                Console.WriteLine(pgpMessage);
                string decryptedMessage = _pgpService.DecryptMessage(pgpMessage, "./RSAKeys/PGP/private.asc");

                if (decryptedMessage == null)
                {
                    return BadRequest("Failed to decrypt the message.");
                }

                return Ok(decryptedMessage);
            }
        }
    }
    public class PgpEncryptRequest
    {
        public string Message { get; set; }
    }

    public class PgpDecryptRequest
    {
        public string EncryptedMessage { get; set; }
    }
}
