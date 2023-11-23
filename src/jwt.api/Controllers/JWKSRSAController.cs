using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace jwt.api.Controllers
{
	[ApiController]
	[Route("jwks-rsa")]
	public class JWKSRSAController : ControllerBase
	{
		private static JsonWebKey _privateJwks;
		private static JsonWebKey _publicJwks;


		[HttpGet("generate-jwks")]
		public IActionResult GenerateJwksEndPoint()
		{
			GenerateJwks();

			return Ok(new { public_jwks = _publicJwks, private_jwks = _privateJwks });
		}

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
			if (_privateJwks != null) return;

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
			var credentials = new SigningCredentials(_privateJwks, SecurityAlgorithms.RsaSsaPssSha256);
			var claims = new[] { new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()) };
			var token = new JwtSecurityToken("issuer", "audience", claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: credentials);
			var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

			return tokenString;
		}

		private static bool ValidateToken(string token)
		{
			try
			{
				var validationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = _publicJwks,
					ValidateIssuer = false,
					ValidateAudience = false,
				};

				new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out SecurityToken validatedToken);

				return true;
			}
			catch
			{
				return false;
			}
		}
	}
}