using System;
using Org.AlbertSchmitt.Crypto;
using Org.BouncyCastle.Security;
using System.Text;

namespace Examples
{
	public static class Example_070
	{
		public static void Test()
		{
			Console.Out.WriteLine("Begin Example_070.");
			string password = "password1";
			string secret_key = "secret-shared-key";
			string content = "Lorem ipsum dolor sit amet, duo cu nobis epicurei hendrerit, mei agam elit an.";

			string hmac = HMAC.Sha256(content, secret_key);
			Console.Out.WriteLine("HMAC_sha256: " + hmac);

			string hex_string = Hex.Encode(UTF8Encoding.UTF8.GetBytes(content));
			Console.Out.WriteLine("Content Hex String: " + hex_string);

			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[AESService.SALT_SIZE];
			random.NextBytes(salt);

			hmac = HMAC.Sha256(content, password);
			Console.Out.WriteLine("HMAC_sha256: " + hmac);
			Console.Out.WriteLine("End Example_070.");
		}
	}
}

