using System;
using Org.AlbertSchmitt.Crypto;
using Org.BouncyCastle.Security;
using System.Text;

namespace Examples
{
	public static class Example_060
	{
		public static void Test()
		{
			Console.Out.WriteLine("Begin Example_060.");
			// Create the AES Service
			AESService aes = new AESService();

			string password = "password";
			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[AESService.SALT_SIZE];
			random.NextBytes(salt);

			// Create the AES Key using password and salt.
			aes.GenerateKey(password, salt);

			// Encode and Decode a string then compare to verify they are the same.
			string clear_text = "This is a test";
			byte[] enc_bytes = aes.Encode(UTF8Encoding.UTF8.GetBytes(clear_text));
			byte[] dec_bytes = aes.Decode(enc_bytes);
			string dec_text = UTF8Encoding.UTF8.GetString(dec_bytes);

			/**
			 * Compare the original and decrypted files.
			 */
			if (Compare.SafeEquals(UTF8Encoding.UTF8.GetBytes(clear_text), UTF8Encoding.UTF8.GetBytes(dec_text)))
			{
				Console.Out.WriteLine("Original and Decrypted are the same!");
			}
			else
			{
				Console.Out.WriteLine("Original and Decrypted are NOT the same!");
			}
			Console.Out.WriteLine("End Example_060.");
		}
	}
}

