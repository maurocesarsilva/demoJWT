using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace jwt.api.Controllers
{
	[ApiController]
	[Route("jwe-rsa")]
	public class JweRsaController : ControllerBase
	{
		private static JsonWebKey _privateJwks;
		private static JsonWebKey _publicJwks;

		[HttpGet("generate")]
		public IActionResult Generate()
		{
			GenerateJwks();

			return Ok(GenerateToken());
		}

		[HttpGet("validate")]
		public IActionResult Validate([FromHeader] string token)
		{
			return Ok(ValidateToken(token));
		}


		private static void GenerateJwks()
		{
			var rsa = RSA.Create(2048);
			var parametersPrivate = rsa.ExportParameters(includePrivateParameters: true);
			var securityKey = new RsaSecurityKey(parametersPrivate)
			{
				KeyId = Guid.NewGuid().ToString()
			};

			_privateJwks = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);

			var parametersPublic = rsa.ExportParameters(includePrivateParameters: false);
			var securityKeyPublic = new RsaSecurityKey(parametersPublic);
			_publicJwks = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKeyPublic);
		}

		private static string GenerateToken()
		{
			var tokenHandler = new JwtSecurityTokenHandler();

			var enc = new EncryptingCredentials(_publicJwks, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256);
			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Issuer = "me",
				Audience = "you",
				Subject = new ClaimsIdentity(new Claim[]
				{
					new Claim("cc", "4000-0000-0000-0002"),
				}),
				EncryptingCredentials = enc
			};

			var token = tokenHandler.CreateToken(tokenDescriptor);

			return tokenHandler.WriteToken(token);
		}

		private static bool ValidateToken(string token)
		{
			try
			{
				var handler = new JsonWebTokenHandler();

				var result = handler.ValidateToken(token,
					new TokenValidationParameters
					{
						ValidIssuer = "me",
						ValidAudience = "you",
						RequireSignedTokens = false,
						TokenDecryptionKey = _privateJwks,
					});

				return result.IsValid;
			}
			catch
			{
				return false;
			}
		}
	}
}
