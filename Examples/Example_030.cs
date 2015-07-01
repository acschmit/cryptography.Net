using System;
using System.IO;
using Org.AlbertSchmitt.Crypto;
using System.Text;

namespace Examples
{
	public static class Example_030
	{
		private const string TESTDATA_DEC_FILE = "./Example_030.dec.txt";
		private const string TESTDATA_ENC_FILE = "./Example_030.enc.txt";
		private const string TESTDATA_FILE = "./Example_030.txt";

		public static void Test()
		{
			Console.Out.WriteLine("Begin Example_030.");
			// Create some data to test with.
			Support.TestData(TESTDATA_FILE);

			/**
			 * Create a 256-bit AES key. AES keys are synchronous. One key can both
			 * encrypt and decrypt data.
			 */
			Console.Out.WriteLine("Begin Create AES Key.");
			AESService aes = new AESService();
			aes.GenerateKey();
			Console.Out.WriteLine("End Create AES Key.");

			/**
			 * Use AES key to encrypt a file stream directly to another file stream.
			 */
			Console.Out.WriteLine("Begin Encrypt Data.");
			using (FileStream outstream = new FileStream(TESTDATA_ENC_FILE, FileMode.Create),
				   instream = new FileStream(TESTDATA_FILE, FileMode.Open))
			{
					aes.Encode(instream, outstream);
			}
			Console.Out.WriteLine("End Encrypt Data.");

			/**
			 * Now decrypt the encrypted file using the same AES key.
			 */
			Console.Out.WriteLine("Begin Decrypt Data.");
			using (FileStream outstream = new FileStream(TESTDATA_DEC_FILE, FileMode.Create),
				   instream = new FileStream(TESTDATA_ENC_FILE, FileMode.Open))
			{
					aes.Decode(instream, outstream);
			}
			Console.Out.WriteLine("End Decrypt Data.");
					
			/**
			 * Compare the original and decrypted files.
			 */
			string shaOriginal = DigestSHA.Sha256(new FileStream(TESTDATA_FILE, FileMode.Open));
			string shaDecripted = DigestSHA.Sha256(new FileStream(TESTDATA_DEC_FILE, FileMode.Open));
			if (Compare.SafeEquals(UTF8Encoding.UTF8.GetBytes(shaOriginal), UTF8Encoding.UTF8.GetBytes(shaDecripted)))
			{
				Console.Out.WriteLine("Encrypted and decrypted files are the same.");
			}
			else
			{
				Console.Out.WriteLine("Encrypted and decrypted files are NOT the same.");
			}
			Console.Out.WriteLine("End Example_030.");
		}
	}
}
