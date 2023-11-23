using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace jwt.api.Controllers
{
	[ApiController]
	[Route("ecdsa")]
	public class EcdsaController : ControllerBase
	{
		/*
			 #gerar chave privada
			 openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem


			 #gerar chave publica
			 openssl ec -in private-key.pem -pubout -out public-key.pem

		 */
		private readonly string _privateKey = @"
											-----BEGIN EC PRIVATE KEY-----
											MHcCAQEEIGZ+wF0L0syW0ksmM8qY9CEQ5OfQfCMh3yYrLewOZbCYoAoGCCqGSM49
											AwEHoUQDQgAE3ownykOrdQW1KVC8y7i/5weT0j2ggH+ahmeomuMEo4TxdurIY+Ao
											Okci1B+pbuuuSP0YF8LBgwhOMT3Hzt7k6w==
											-----END EC PRIVATE KEY-----
										  ".Trim();

		private readonly string _publicKey = @"
											-----BEGIN PUBLIC KEY-----
											MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3ownykOrdQW1KVC8y7i/5weT0j2g
											gH+ahmeomuMEo4TxdurIY+AoOkci1B+pbuuuSP0YF8LBgwhOMT3Hzt7k6w==
											-----END PUBLIC KEY-----
									  	".Trim();


		[HttpGet("generate")]
		public IActionResult Generate()
		{
			return Ok(GenerateToken());
		}

		[HttpGet("validate")]
		public IActionResult Validate([FromHeader] string token)
		{
			return Ok(ValidateToken(token));
		}



		private string GenerateToken()
		{
			var ecDsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
			ecDsa.ImportFromPem(_privateKey.Trim().ToCharArray());

			var securityKey = new ECDsaSecurityKey(ecDsa)
			{
				KeyId = Guid.NewGuid().ToString()
			};

			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);

			var claims = new[] { new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()) };

			var token = new JwtSecurityToken("issuer", "audience", claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: credentials);

			var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

			return tokenString;

		}

		private bool ValidateToken(string token)
		{
			try
			{
				var ecDsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
				ecDsa.ImportFromPem(_publicKey.Trim().ToCharArray());

				var tokenHandler = new JwtSecurityTokenHandler();
				var validationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = new ECDsaSecurityKey(ecDsa),
					ValidateIssuer = false,
					ValidateAudience = false,
				};

				var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

				return true;
			}
			catch
			{
				return false;
			}
		}
	}
}