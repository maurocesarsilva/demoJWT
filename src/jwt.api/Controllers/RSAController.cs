using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace jwt.api.Controllers
{
	[ApiController]
	[Route("rsa")]
	public class RSAController : ControllerBase
	{
		/*
			 #gerar chave privada
			 openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

			 #gerar chave publica
			 openssl rsa -pubout -in private_key.pem -out public_key.pem
		 */
		private readonly string _privateKey = @"
											-----BEGIN PRIVATE KEY-----
								MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0f+ZZkWDpdps6
								QZJn/u7b3skd4kEn9jrgXWRNGHxrXjC/+2qo22ymJhdkPFqlyt4YvOIuNqSEmgrb
								gvrnJMWtZHFIOGKMaHVox6lsst3jy8VYIpVNsFXXFd8xitI9IrGgMVc7m8OVC/Mw
								EwlcAvVUrceBt/zRN1LOQxK97ihJOvBkcJYrdOhG6o3Agg8nzivIQmo+v36iinsz
								DUdKmwpEbhROW6IzX0bc0T4q2eKWTRgUFwndnrpW3WX3R/4OcGh00Og4kQP9tlC5
								hpD0MVrZyqmFelno6LbqzpL1lwVlHTSCjEkD5NVRCqc4i6a/pSxe6myAKZMv3Mc9
								rQllcqD/AgMBAAECggEAAwNXjws0OPF36eMKVJ4W0qjHZq5ONCKSHQiyEe9ktE4g
								NjQ2NZdkGunr3gp74OSgDH2qsObMnEIOCFgJZC5i9mAE3BXE318nBpa+p0fdGF5g
								bvY009Urualtzl/o3ohjuq7YK/CPtT870gOfVl/eRImaGPo/SCbKRRMtjuoY1hAU
								mQo3JFRy2X6UIPlzamiWy/kPcwATKrCcKhawJcjMK33ExAbIJCCmdlPk+9N2Z2q7
								IzFnTOApfon8Eywvp5mvFf5cBH9dWEiUOGRdsKHfMgtPsM+q5c9WwB+pxIsMFkcY
								3MvcnkV5AyuePTLaWYNsfcXFRTs6Q3cqm6zFY/iRgQKBgQDtPfehDk9hZCeQ+1b4
								WjcNPGsZwNus7eWX8hAMD3LqgzVJ2S/pgr011WYAhAO/1I8E56KvzxAMpj2oMDNJ
								9EVJY7BAe0bYHpgRL1POiUt1h2a2rB6laSgnfBozQdNHR+u18FqJp8LPkfSQjt6R
								qt3YtpVs1El46tmlJdCLJo2R4QKBgQDCxWeZQb85rYrqJ4xX45XmuM2fGlDTZhIz
								lm9esGfIo0ikmNhgfecxj4aL39Q1vUPLlhj5lQBRVBSZeGUB12XuAGi5yonbdOX4
								LO15pJDCPa30sUKANFj/4UUDdNxmSWB/EGMGd0GL6f7Ti++lJEafqay9cql2xdj+
								y7is325O3wKBgQCxai/vP3ZZjL6SC4PEgiK9QTuOrM0bC2UxNhKOEleLzMdjDIpq
								BB1fTtDS/eaX5Gt37YmaFC0aaI+fYTxZx9Swx14dOpOGN4rc/xmbUM0ffTxwy1K3
								vGYM8R/eyREpMz2wd6gdXVmwRKQyHsWPBcqVsCUal77CME7G0/qatSAVwQKBgGDl
								jHC2QMgVCjMLkcp3sq+h6MnqcaN5+Dwp7yYQZNFwSkd4sszuVgJWAP29UPmbOwsh
								lTM1aX8McWMYfke4PUF2eqNTm9nOAkrBLzOBJ3M69Dvzo73cTRqfm5HopW1Nu+/6
								2wjwc2+D7f6Yc5SYw3nTE9j8Hkq0iwvXlfyK+3nJAoGBAIYx7nS/NE9vby6DtKHZ
								MuMyBR51ot9ufrLEzu+Bhy6wPhufbFJqyCtJIw0TfVrw1dIJVJeDnMV4es1Fvowj
								z+ILz/ltw0Ep5Ciqg0H7PJrlj/9T/5KoZ+HahL6gd78GlRPGOaxN07Auao3jdi+8
								QhCBpGd/r5JZYZATQUEc9Bmh
													-----END PRIVATE KEY-----
								";

		private readonly string _publicKey = @"
							-----BEGIN PUBLIC KEY-----
							MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtH/mWZFg6XabOkGSZ/7u
							297JHeJBJ/Y64F1kTRh8a14wv/tqqNtspiYXZDxapcreGLziLjakhJoK24L65yTF
							rWRxSDhijGh1aMepbLLd48vFWCKVTbBV1xXfMYrSPSKxoDFXO5vDlQvzMBMJXAL1
							VK3Hgbf80TdSzkMSve4oSTrwZHCWK3ToRuqNwIIPJ84ryEJqPr9+oop7Mw1HSpsK
							RG4UTluiM19G3NE+Ktnilk0YFBcJ3Z66Vt1l90f+DnBodNDoOJED/bZQuYaQ9DFa
							2cqphXpZ6Oi26s6S9ZcFZR00goxJA+TVUQqnOIumv6UsXupsgCmTL9zHPa0JZXKg
							/wIDAQAB
							-----END PUBLIC KEY-----
						";



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
			var rsa = RSA.Create();
			rsa.ImportFromPem(_privateKey.Trim().ToCharArray());

			var securityKey = new RsaSecurityKey(rsa)
			{
				KeyId = Guid.NewGuid().ToString()
			};
			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSsaPssSha256);

			var claims = new[] { new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()) };

			var token = new JwtSecurityToken("issuer", "audience", claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: credentials);

			var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

			return tokenString;
		}

		private bool ValidateToken(string token)
		{
			try
			{
				var rsa = RSA.Create();
				rsa.ImportFromPem(_publicKey.Trim().ToCharArray());

				var validationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = new RsaSecurityKey(rsa),
					ValidateIssuer = false,
					ValidateAudience = false,
				};

				var principal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out SecurityToken validatedToken);

				return true;
			}
			catch
			{
				return false;
			}
		}
	}
}