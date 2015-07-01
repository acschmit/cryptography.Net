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
using Org.AlbertSchmitt.Crypto;

namespace UnitTest
{
	[TestFixture()]
	public class RSAServiceTest
	{
		public const string privateKeyfile = "./private_key.pem";
		public const string publicKeyfile = "./public_key.pem";

		private byte[] msgBytes;

		// This is the RSA key size we will use for the tests.
		private RSAService.KEYSIZE keysize = RSAService.KEYSIZE.RSA_3K;

		public RSAServiceTest()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append("esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
			sb.Append("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ");
			sb.Append("veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit");

			msgBytes = UTF8Encoding.UTF8.GetBytes(sb.ToString());

			TestGenerateKey_String_String();
		}

		[Test()]
		public void TestGenerateKey_String_String()
		{
			Console.Out.WriteLine("generateKey");
			RSAService rsa = new RSAService(keysize);
			if (!rsa.AreKeysPresent(privateKeyfile, publicKeyfile))
			{
				Console.Out.WriteLine("Begin Generating RSA Key Pair.");
				using (FileStream fos_private = new FileStream(privateKeyfile, FileMode.Create))
				{
					using (FileStream fos_public = new FileStream(publicKeyfile, FileMode.Create))
					{
						rsa.GenerateKey(fos_private, fos_public);
					}
				}
				Console.Out.WriteLine("Finish Generating RSA Key Pair.");
			}
			Assert.IsTrue(true);
		}

		[Test()]
		public void TestEncodeAndDecode_byteArr_Key()
		{
			Console.Out.WriteLine("encode and decode");

			RSAService instance = new RSAService(keysize);
			RSAPrivateKey privateKey = instance.ReadPrivateKey(privateKeyfile);
			RSAPublicKey publicKey = instance.ReadPublicKey(publicKeyfile);

			byte[] encData = instance.Encode(msgBytes, privateKey);
			byte[] decData = instance.Decode(encData, publicKey);

			Boolean bCompare = Compare.SafeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);

			encData = instance.Encode(msgBytes, publicKey);
			decData = instance.Decode(encData, privateKey);

			bCompare = Compare.SafeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);

		}

		[Test()]
		public void TestEncodeAndDecode_3args()
		{
			Console.Out.WriteLine("encode and decode stream");

			RSAService instance = new RSAService(keysize);
			RSAPrivateKey privateKey = instance.ReadPrivateKey(privateKeyfile);
			RSAPublicKey publicKey = instance.ReadPublicKey(publicKeyfile);

			byte[] decData;
			using (MemoryStream outstream = new MemoryStream())
			{
				using (MemoryStream instream = new MemoryStream(msgBytes))
				{
					instance.Encode(instream, outstream, privateKey);
					byte[] encData = outstream.ToArray();
					decData = instance.Decode(encData, publicKey);
				}
			}

			Boolean bCompare = Compare.SafeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);

			using (MemoryStream outstream = new MemoryStream())
			{
				using (MemoryStream instream = new MemoryStream(msgBytes))
				{
					instance.Encode(instream, outstream, publicKey);
					byte[] encData = outstream.ToArray();
					decData = instance.Decode(encData, privateKey);
				}
			}

			bCompare = Compare.SafeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);
		}

		[Test()]
		public void TestReadPrivateKey_String()
		{
			Console.Out.WriteLine("readPrivateKey");
			RSAService instance = new RSAService(keysize);
			RSAPrivateKey privateKey = instance.ReadPrivateKey(privateKeyfile);
			Assert.IsNotNull(privateKey);
		}

		[Test()]
		public void TestReadPrivateKey_InputStream()
		{
			Console.Out.WriteLine("readPrivateKey");

			using (FileStream instream = new FileStream(privateKeyfile, FileMode.Open))
			{
				RSAService instance = new RSAService(keysize);
				RSAPrivateKey result = instance.ReadPrivateKey(instream);
				Assert.IsNotNull(result);
			}
		}

		[Test()]
		public void TestReadPublicKey_String()
		{
			Console.Out.WriteLine("readPublicKey");
			RSAService instance = new RSAService(keysize);
			RSAPublicKey publicKey = instance.ReadPublicKey(publicKeyfile);
			Assert.IsNotNull(publicKey);
		}

		[Test()]
		public void TestReadPublicKey_InputStream()
		{
			Console.Out.WriteLine("readPublicKey");
			using (FileStream instream = new FileStream(publicKeyfile, FileMode.Open))
			{
				RSAService instance = new RSAService(keysize);
				RSAPublicKey result = instance.ReadPublicKey(instream);
				Assert.IsNotNull(result);
			}
		}
			
		// Beef this up to actually encode something with the key to see if it works.
		[Test()]
		public void TestReadPublicKeyFromPrivate_String()
		{
			Console.Out.WriteLine("readPublicKeyFromPrivate");
			RSAService instance = new RSAService(keysize);
			RSAPublicKey result = instance.ReadPublicKeyFromPrivate(privateKeyfile);
			Assert.IsNotNull(result);
		}

		// Beef this up to actually encode something with the key to see if it works.
		[Test()]
		public void TestReadPublicKeyFromPrivate_InputStream()
		{
			Console.Out.WriteLine("readPublicKeyFromPrivate");
			RSAService instance = new RSAService(keysize);
			using (FileStream instream = new FileStream(privateKeyfile, FileMode.Open))
			{
				RSAPublicKey result = instance.ReadPublicKeyFromPrivate(instream);
				Assert.IsNotNull(result);
			}
		}
	}
}

