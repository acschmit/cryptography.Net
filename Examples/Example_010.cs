using System;
using System.IO;
using System.Text;
using org.albertschmitt.crypto;

namespace Examples
{
	/**
	 * Example 010.
	 * Demonstrate the following techniques:
	 * 	Check for existence of RSA Keys.
	 * 	Generate RSA Keys using FileOutputStream.
	 * 	Read RSA Keys FileInputStream.
	 * 	Encrypt and Decrypt a data file using streams.
	 * 	Compare the decrypted file to the original.
	 */
	public static class Example_010
	{
		private const string TESTDATA_DEC_FILE = "./Example_010.dec.txt";
		private const string TESTDATA_ENC_FILE = "./Example_010.enc.txt";
		private const string TESTDATA_FILE = "./Example_010.txt";
		private const string privateKeyfile = "./Example_010_private_key.pem";
		private const string publicKeyfile = "./Example_010_public_key.pem";

		public static void main()
		{
			Console.Out.WriteLine("Begin Example_010.");
			
			// Create some data to test with.
			Support.testData(TESTDATA_FILE);

			/**
			 * Create a public / private RSA key pair.
			 */
			RSAService rsa = new RSAService();
			if (!rsa.areKeysPresent(privateKeyfile, publicKeyfile))
			{
				Console.Out.WriteLine("Begin Create RSA Keys.");
				using (FileStream os_private = new FileStream(privateKeyfile, FileMode.Create),
					   os_public = new FileStream(publicKeyfile, FileMode.Create))
				{
					rsa.generateKey(os_private, os_public);
				}
				Console.Out.WriteLine("End Create RSA Keys.");
			}

			/**
			 * RSA keys are asynchronous; there is a public and private key. Each
			 * key can only decrypt data encrypted with the other key. A client
			 * process would not have both keys, this is only for demonstration
			 * purposes.
			 */

			Console.Out.WriteLine("Begin Read RSA Keys.");
			RSAPrivateKey privateKey = null;
			RSAPublicKey publicKey = null;
			using (FileStream is_private = new FileStream(privateKeyfile, FileMode.Open),
				   is_public = new FileStream(publicKeyfile, FileMode.Open))
			{
				privateKey = rsa.readPrivateKey(is_private);
				publicKey = rsa.readPublicKey(is_public);
			}
			Console.Out.WriteLine("End Read RSA Keys.");

			/**
			 * Use public key to encrypt a file stream directly to another file
			 * stream.
			 */
			Console.Out.WriteLine("Begin Encrypt Data.");
			using (FileStream outstream = new FileStream(TESTDATA_ENC_FILE, FileMode.Create),
				   instream = new FileStream(TESTDATA_FILE, FileMode.Open))
			{
				rsa.encode(instream, outstream, publicKey);
			}
			Console.Out.WriteLine("End Encrypt Data.");

			/**
			 * Now decrypt the encrypted file using the private key.
			 */
			Console.Out.WriteLine("Begin Decrypt Data.");
			using (FileStream outstream = new FileStream(TESTDATA_DEC_FILE, FileMode.Create),
				instream = new FileStream(TESTDATA_ENC_FILE, FileMode.Open))
			{
				rsa.decode(instream, outstream, privateKey);
			}
			Console.Out.WriteLine("End Decrypt Data.");

			/**
			 * Compare the original and decrypted files.
			 */
			string shaOriginal = DigestSHA.sha256(new FileStream(TESTDATA_FILE, FileMode.Open));
			string shaDecripted = DigestSHA.sha256(new FileStream(TESTDATA_DEC_FILE, FileMode.Open));
			if (Compare.safeEquals(UTF8Encoding.UTF8.GetBytes(shaOriginal), UTF8Encoding.UTF8.GetBytes(shaDecripted)))
			{
				Console.Out.WriteLine("Encrypted and decrypted files are the same.");
			}
			else
			{
				Console.Out.WriteLine("Encrypted and decrypted files are NOT the same.");
			}
			Console.Out.WriteLine("End Example_010.");
		}
	}
}

