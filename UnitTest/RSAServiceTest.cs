/*
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Albert C Schmitt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
using NUnit.Framework;
using System;
using System.Text;
using System.IO;
using org.albertschmitt.crypto;

namespace UnitTest
{
	[TestFixture()]
	public class RSAServiceTest
	{
		private const string privateKeyfile = "./private_key.pem";
		private const string publicKeyfile = "./public_key.pem";

		private byte[] msgBytes;

		public RSAServiceTest()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append("esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
			sb.Append("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ");
			sb.Append("veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit");

			msgBytes = UTF8Encoding.UTF8.GetBytes(sb.ToString());

			testGenerateKey_String_String();
		}

		[Test()]
		public void testGenerateKey_String_String ()
		{
			Console.Out.WriteLine("generateKey");
			RSAService rsa = new RSAService();
			if (!rsa.areKeysPresent(privateKeyfile, publicKeyfile))
			{
				Console.Out.WriteLine("Begin Generating RSA Key Pair.");
				using (FileStream fos_private = new FileStream(privateKeyfile, FileMode.Create))
				{
					using (FileStream fos_public = new FileStream(publicKeyfile, FileMode.Create))
					{
						rsa.generateKey(fos_private, fos_public);
					}
				}
				Console.Out.WriteLine("Finish Generating RSA Key Pair.");
			}
			Assert.IsTrue(true);
		}

		[Test()]
		public void testEncodeAndDecode_byteArr_Key ()
		{
			Console.Out.WriteLine("encode and decode");

			RSAService instance = new RSAService();
			RSAPrivateKey privateKey = instance.readPrivateKey(privateKeyfile);
			RSAPublicKey publicKey = instance.readPublicKey(publicKeyfile);

			byte[] encData = instance.encode(msgBytes, privateKey);
			byte[] decData = instance.decode(encData, publicKey);

			Boolean bCompare = Compare.safeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);

			encData = instance.encode(msgBytes, publicKey);
			decData = instance.decode(encData, privateKey);

			bCompare = Compare.safeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);

		}

		[Test()]
		public void testEncodeAndDecode_3args ()
		{
			Console.Out.WriteLine("encode and decode stream");

			RSAService instance = new RSAService();
			RSAPrivateKey privateKey = instance.readPrivateKey(privateKeyfile);
			RSAPublicKey publicKey = instance.readPublicKey(publicKeyfile);

			byte[] decData;
			using (MemoryStream outstream = new MemoryStream())
			{
				using (MemoryStream instream = new MemoryStream(msgBytes))
				{
					instance.encode(instream, outstream, privateKey);
					byte[] encData = outstream.ToArray();
					decData = instance.decode(encData, publicKey);
				}
			}

			Boolean bCompare = Compare.safeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);

			using (MemoryStream outstream = new MemoryStream())
			{
				using (MemoryStream instream = new MemoryStream(msgBytes))
				{
					instance.encode(instream, outstream, publicKey);
					byte[] encData = outstream.ToArray();
					decData = instance.decode(encData, privateKey);
				}
			}

			bCompare = Compare.safeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);
		}

		[Test()]
		public void testReadPrivateKey_String ()
		{
			Console.Out.WriteLine("readPrivateKey");
			RSAService instance = new RSAService();
			RSAPrivateKey privateKey = instance.readPrivateKey(privateKeyfile);
			Assert.IsNotNull(privateKey);
		}

		[Test()]
		public void testReadPrivateKey_InputStream ()
		{
			Console.Out.WriteLine("readPrivateKey");

			using (FileStream instream = new FileStream(privateKeyfile, FileMode.Open))
			{
				RSAService instance = new RSAService();
				RSAPrivateKey result = instance.readPrivateKey(instream);
				Assert.IsNotNull(result);
			}
		}

		[Test()]
		public void testReadPublicKey_String ()
		{
			Console.Out.WriteLine("readPublicKey");
			RSAService instance = new RSAService();
			RSAPublicKey publicKey = instance.readPublicKey(publicKeyfile);
			Assert.IsNotNull(publicKey);
		}

		[Test()]
		public void testReadPublicKey_InputStream ()
		{
			Console.Out.WriteLine("readPublicKey");
			using (FileStream instream = new FileStream(publicKeyfile, FileMode.Open))
			{
				RSAService instance = new RSAService();
				RSAPublicKey result = instance.readPublicKey(instream);
				Assert.IsNotNull(result);
			}
		}
#if false
		// Not yet implemented.
		[Test()]
		public void testReadPublicKeyFromPrivate_String()
		{
		Console.Out.WriteLine("readPublicKeyFromPrivate");
		RSAService instance = new RSAService();
		RSAPublicKey result = instance.readPublicKeyFromPrivate(privateKeyfile);
		Assert.IsNotNull(result);
		}
#endif
		[Test()]
		public void testReadPublicKeyFromPrivate_InputStream ()
		{
			Console.Out.WriteLine("readPublicKeyFromPrivate");
			using (FileStream instream = new FileStream(privateKeyfile, FileMode.Open))
			{
				RSAService instance = new RSAService();
				RSAPrivateKey result = instance.readPrivateKey(instream);
				Assert.IsNotNull(result);
			}
		}
	}
}

