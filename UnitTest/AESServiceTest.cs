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
	public class AESServiceTest
	{
		private string password;
		private byte[] msgBytes;
        private string msgString;

		private const string SALT_DAT = "./salt.dat";
		const int SALT_LENGTH = 32;

		public AESServiceTest()
		{
			StringBuilder sb = new StringBuilder();
			sb.Append("esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
			sb.Append("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ");
			sb.Append("veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit");

            msgString = sb.ToString();
			msgBytes = UTF8Encoding.UTF8.GetBytes(msgString);
			password = "ZJ=ENY'2H+0bm'oyIe6J";

			testGenerateSalt();
		}

		[Test()]
		public void testGenerateSalt ()
		{
			Console.Out.WriteLine("generateSalt");
			AESService instance = new AESService();
			byte[] saltBytes = instance.generateSalt();

			writeSaltBytes(saltBytes);

			Assert.IsNotNull(saltBytes);
		}


		[Test()]
		public void testGetAesKey ()
		{
			Console.Out.WriteLine("getAesKey");
			AESService instance = new AESService();
			instance.generateKey();

			byte[] result = instance.getAesKey();

			Assert.IsNotNull(result);
		}

		[Test()]
		public void testGetHmac256Digest ()
		{
			Console.Out.WriteLine("getHmac256Digest");

			// Need to use a hard coded salt so we get a predictable result from getHmac256Digest().
			string saltString = "253a3dd3a9aef71ca1fa2b8b3704d6724ba474342e3c2e4fd124ee74d2c56017f4a7c22951a99978c6fdfbbefb4cf775d5642ea6dcb4d9b8e164fc23099f36c4";
			byte[] saltBytes = Hex.decode(saltString);

			AESService instance = new AESService();
			instance.generateKey(password, saltBytes);

			String result = DigestSHA.sha512(msgBytes);
			String expResult = "25296335d88536dddd09ffb7bcc09646dd9b3f537beb78cf89c76077d39daedd0cb8e46cf1e9b06a99e59e5b8b7f66f307978dc6413426b13d1f724a0a030529";

			Assert.IsTrue(expResult == result);
		}

		[Test()]
		public void testEncodeAndDecode_byteArr ()
		{
			Console.Out.WriteLine("encode and decode byte array");

			byte[] saltBytes = readSaltBytes();

			AESService instance = new AESService();
			instance.generateKey(password, saltBytes);

			byte[] encData = instance.encode(msgBytes);
			byte[] decData = instance.decode(encData);

			Boolean bCompare = Compare.safeEquals(msgBytes, decData);
			Assert.IsTrue(bCompare);
		}

        [Test()]
        public void testEncodeAndDecode_String()
        {
            Console.Out.WriteLine("encode and decode byte string");

            byte[] saltBytes = readSaltBytes();

            AESService instance = new AESService();
            instance.generateKey(password, saltBytes);

            byte[] encData = instance.encode(msgString);
            string encString = Hex.encode(encData);
            byte[] decData = instance.decode(encString);

            Boolean bCompare = Compare.safeEquals(msgBytes, decData);
            Assert.IsTrue(bCompare);
        }

		[Test()]
		public void testEncodeAndDecode_InputStream_OutputStream ()
		{
			Console.Out.WriteLine("encode and decode stream");

			byte[] saltBytes = readSaltBytes();

			AESService instance = new AESService();
			instance.generateKey(password, saltBytes);

			byte[] decData;
            byte[] encData;
			using (MemoryStream outstream = new MemoryStream())
			{
				using (MemoryStream instream = new MemoryStream(msgBytes))
				{
					instance.encode(instream, outstream);
				}
				encData = outstream.ToArray();
				decData = instance.decode(encData);

				Boolean bCompare = Compare.safeEquals(msgBytes, decData);
				Assert.IsTrue(bCompare);
			}

            using (MemoryStream outstream = new MemoryStream())
            {
                using (MemoryStream instream = new MemoryStream(encData))
                {
                    instance.decode(instream, outstream);
                }
                decData = outstream.ToArray();

                Boolean bCompare = Compare.safeEquals(msgBytes, decData);
                Assert.IsTrue(bCompare);
            }
        }

		[Test()]
		public void testGenerateKey_0args ()
		{
			Console.Out.WriteLine("generateKey");

			byte[] saltBytes = readSaltBytes();

			AESService instance = new AESService();
			instance.generateKey(password, saltBytes);

			byte[] aes_key = instance.getAesKey();
			Assert.IsNotNull(aes_key);
		}

		[Test()]
		public void testGenerateKey_String_byteArr ()
		{
			Console.Out.WriteLine("generateKey");

			byte[] saltBytes = readSaltBytes();

			AESService instance = new AESService();
			instance.generateKey(password, saltBytes);

			byte[] aes_key = instance.getAesKey();
			Assert.IsNotNull(aes_key);
		}

		[Test()]
		public void testSetAesKey ()
		{
			Console.Out.WriteLine("setAesKey");
			AESService instance = new AESService();
			instance.generateKey();

			byte[] result = instance.getAesKey();
			Assert.IsNotNull(result);

			instance.setAesKey(result);
		}

		//--------------------------------------------------------------------------
		// Support functions.
		//--------------------------------------------------------------------------
		private byte[] readSaltBytes ()
		{
			byte[] saltBytes = null;
			using (FileStream instream = new FileStream(SALT_DAT, FileMode.Open))
			{
				saltBytes = new byte[SALT_LENGTH];
				instream.Read(saltBytes, 0, SALT_LENGTH);
			}
			return saltBytes;
		}

		private void writeSaltBytes (byte[] saltBytes1)
		{
			using (FileStream os = new FileStream(SALT_DAT, FileMode.Create))
			{
				os.Write(saltBytes1, 0, SALT_LENGTH);
			}
		}
	}
}

