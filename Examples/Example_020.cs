using System;
using org.albertschmitt.crypto;
using System.IO;
using System.Text;

namespace Examples
{
	public static class Example_020
	{
		private const string TESTDATA_FILE = "./Example_020.txt";
		private const string privateKeyfile = "./Example_020_private_key.pem";
		private const string publicKeyfile = "./Example_020_public_key.pem";

		public static void main()
		{
			Console.Out.WriteLine("Begin Example_020.");
			// Create some data to test with.
			Support.testData(TESTDATA_FILE);

			/**
			 * Create a public / private RS key pair.
			 */
			RSAService rsa = new RSAService();
			if (!rsa.areKeysPresent(privateKeyfile, publicKeyfile))
			{
				Console.Out.WriteLine("Begin Create RSA Keys.");
				rsa.generateKey(privateKeyfile, publicKeyfile);
				Console.Out.WriteLine("End Create RSA Keys.");
			}

			/**
			 * RSA keys are asynchronous; there is a public and private key. Each
			 * key can only decrypt data encrypted with the other key. A client
			 * process would not have both keys, this is only for demonstration
			 * purposes.
			 */
			Console.Out.WriteLine("Begin Read RSA Keys.");
			RSAPrivateKey privateKey = rsa.readPrivateKey(privateKeyfile);
			RSAPublicKey publicKey = rsa.readPublicKey(publicKeyfile);
			Console.Out.WriteLine("End Read RSA Keys.");

			/**
			 * Read the test data into a byte array. Be sure to use UTF-8 when
			 * converting between strings and byte arrays.
			 */
			Console.Out.WriteLine("Begin Read Data.");
			string testdata = File.ReadAllText(TESTDATA_FILE);
			byte[] testdata_bytes = UTF8Encoding.UTF8.GetBytes(testdata);
			Console.Out.WriteLine("End Read Data.");

			/**
			 * Use public key to encrypt a byte array to another byte array.
			 */
			Console.Out.WriteLine("Begin Encrypt Data.");
			byte[] testdata_enc = rsa.encode(testdata_bytes, publicKey);
			Console.Out.WriteLine("End Encrypt Data.");

			/**
			 * Now decrypt the encrypted file using the private key.
			 */
			Console.Out.WriteLine("Begin Decrypt Data.");
			byte[] testdata_dec = rsa.decode(testdata_enc, privateKey);
			Console.Out.WriteLine("End Decrypt Data.");

			/**
			 * Compare the original and decrypted files.
			 */
			String shaOriginal = DigestSHA.sha256(testdata_bytes);
			String shaDecripted = DigestSHA.sha256(testdata_dec);
			if (Compare.safeEquals(UTF8Encoding.UTF8.GetBytes(shaOriginal), UTF8Encoding.UTF8.GetBytes(shaDecripted)))
			{
				Console.Out.WriteLine("Encrypted and decrypted files are the same.");
			}
			else
			{
				Console.Out.WriteLine("Encrypted and decrypted files are NOT the same.");
			}
			Console.Out.WriteLine("End Example_020.");
		}
	}
}

