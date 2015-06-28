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
	public class DigestSHATest
	{
		/**
		 * String that SHA Digest function will be tested with. Do not change this
		 * string or the tests will all fail.
		 */
		private const string TEST_DATA = "Lorem ipsum dolor sit amet, inceptos mauris nec, ut id, orci nulla lectus ornare nam sit dui, cras malesuada neque dicta vestibulum.";

		public DigestSHATest ()
		{
		}

		[Test()]
		public void testMd5()
		{
			Console.Out.WriteLine("md5");
			byte[] data = UTF8Encoding.UTF8.GetBytes(TEST_DATA);
			String expResult = "8d51d5a313d44e1a7a9698731813add7";
			String result = DigestSHA.md5(data);
			Boolean bCompare = Compare.safeEquals(UTF8Encoding.UTF8.GetBytes(expResult), UTF8Encoding.UTF8.GetBytes(result));
			Assert.IsTrue(bCompare);
		}

		[Test()]
		public void testSha1_byteArr()
		{
			Console.Out.WriteLine("sha1");
			byte[] data = UTF8Encoding.UTF8.GetBytes(TEST_DATA);
			String expResult = "526d5ab7f4f28b1db8d2a4f54e3f93cbc38d7a5d";
			String result = DigestSHA.sha1(data);
			Boolean bCompare = Compare.safeEquals(UTF8Encoding.UTF8.GetBytes(expResult), UTF8Encoding.UTF8.GetBytes(result));
			Assert.IsTrue(bCompare);
		}

		[Test()]
		public void testSha1_InputStream()
		{
			Console.Out.WriteLine("sha1");
			using (MemoryStream instream = new MemoryStream(UTF8Encoding.UTF8.GetBytes(TEST_DATA)))
			{
				String expResult = "526d5ab7f4f28b1db8d2a4f54e3f93cbc38d7a5d";
				String result = DigestSHA.sha1(instream);
				Boolean bCompare = Compare.safeEquals(UTF8Encoding.UTF8.GetBytes(expResult), UTF8Encoding.UTF8.GetBytes(result));
				Assert.IsTrue(bCompare);
			}
		}
	}
}

