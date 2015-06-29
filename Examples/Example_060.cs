using System;
using org.albertschmitt.crypto;
using Org.BouncyCastle.Security;
using System.Text;

namespace Examples
{
	public static class Example_060
	{
		public static void main()
		{
			// Create the AES Service
			AESService aes = new AESService();

			string password = "password";
			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[AESService.SALT_SIZE];
			random.NextBytes(salt);

			// Create the AES Key using password and salt.
			aes.generateKey(password, salt);

			// Encode and Decode a string then compare to verify they are the same.
			string clear_text = "This is a test";
			byte[] enc_bytes = aes.encode(UTF8Encoding.UTF8.GetBytes(clear_text));
			byte[] dec_bytes = aes.decode(enc_bytes);
			string dec_text = UTF8Encoding.UTF8.GetString(dec_bytes);

			/**
			 * Compare the original and decrypted files.
			 */
			if (Compare.safeEquals(UTF8Encoding.UTF8.GetBytes(clear_text), UTF8Encoding.UTF8.GetBytes(dec_text)))
			{
				Console.Out.WriteLine("Original and Decrypted are the same!");
			}
			else
			{
				Console.Out.WriteLine("Original and Decrypted are NOT the same!");
			}
		}
	}
}

