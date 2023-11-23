using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace jwt.api.Controllers
{
	[ApiController]
	[Route("jwks-ecdsa")]
	public class JwksEcdsaController : ControllerBase
	{
		private static JsonWebKey _privateJwks;
		private static JsonWebKey _publicJwks;


		[HttpGet("generate-jwks")]
		public IActionResult GenerateJwks()
		{
			Generate();

			return Ok(new { public_jwks = _publicJwks, private_jwks = _privateJwks });
		}

		[HttpGet("generate")]
		public IActionResult GenerateEndPoint()
		{
			Generate();

			return Ok(GenerateToken());
		}

		[HttpGet("validate")]
		public IActionResult Validate([FromHeader] string token)
		{
			return Ok(ValidateToken(token));
		}


		private static void Generate()
		{
			if (_privateJwks != null) return;

			var ecDsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
			var securityKey = new ECDsaSecurityKey(ecDsa)
			{
				KeyId = Guid.NewGuid().ToString()
			};

			_privateJwks = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);


			var parametersPublic = ecDsa.ExportParameters(includePrivateParameters: false);
			var ecDsaPublic = ECDsa.Create(parametersPublic);
			var securityKeyPublic = new ECDsaSecurityKey(ecDsaPublic);
			_publicJwks = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKeyPublic);
		}


		private static string GenerateToken()
		{
			var credentials = new SigningCredentials(_privateJwks, SecurityAlgorithms.EcdsaSha256);
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