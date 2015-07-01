/*
 * The MIT License
 *
 * Copyright 2015 acschmit.
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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
using System;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto;
using System.Text;

namespace Org.AlbertSchmitt.Crypto
{
	/// <summary>
	/// Keyed-Hash Message Authentication Code class.  Use this class to verify the
	/// data integrity and authenticity of a message.
	/// </summary>
	public static class HMAC
	{
		/// <summary>
		/// Return the HMAC of a message using the key and given digest.
		/// </summary>
		/// <returns>HMAC value of the byte array as a hex string.</returns>
		/// <param name="msg">Message.</param>
		/// <param name="keyBytes">The private key.</param>
		/// <param name="algorithm">The digest to be used.</param>
		private static string HMacDigest(byte[] msg, byte[] keyBytes, IDigest algorithm)
		{
			HMac mac = new HMac(algorithm);
			mac.Init(new KeyParameter(keyBytes));

			mac.BlockUpdate(msg, 0, msg.Length);
			byte[] data = new byte[mac.GetMacSize()];
			mac.DoFinal (data, 0);

			return Hex.Encode(data);
		}

		/// <summary>
		/// Return the md5 HMAC of the message and given digest.
		/// </summary>
		/// <param name="msg">The message to be encoded.</param>
		/// <param name="keyString">The secret key to be used.</param>
		public static string MD5(string msg, string keyString)
		{
			MD5Digest digest = new MD5Digest();
			return HMacDigest(ASCIIEncoding.ASCII.GetBytes(msg), UTF8Encoding.UTF8.GetBytes(keyString), digest);
		}

		/// <summary>
		/// Return the sha1 HMAC of the message and given digest.
		/// </summary>
		/// <param name="msg">The message to be encoded.</param>
		/// <param name="keyString">The secret key to be used.</param>
		public static string Sha1(string msg, string keyString)
		{
			Sha1Digest digest = new Sha1Digest();
			return HMacDigest(ASCIIEncoding.ASCII.GetBytes(msg), UTF8Encoding.UTF8.GetBytes(keyString), digest);
		}

		/// <summary>
		/// Return the 256 HMAC of the message and given digest.
		/// </summary>
		/// <param name="msg">The message to be encoded.</param>
		/// <param name="keyString">The secret key to be used.</param>

		public static string Sha256(string msg, string keyString)
		{
			Sha256Digest digest = new Sha256Digest();
			return HMacDigest(ASCIIEncoding.ASCII.GetBytes(msg), UTF8Encoding.UTF8.GetBytes(keyString), digest);
		}

		/// <summary>
		/// Return the sha512 HMAC of the message and given digest.
		/// </summary>
		/// <param name="msg">The message to be encoded.</param>
		/// <param name="keyString">The secret key to be used.</param>
		public static string Sha512(string msg, string keyString)
		{
			Sha512Digest digest = new Sha512Digest();
			return HMacDigest(ASCIIEncoding.ASCII.GetBytes(msg), UTF8Encoding.UTF8.GetBytes(keyString), digest);
		}

		/// <summary>
		/// Return the md5 HMAC of the message and given digest.
		/// </summary>
		/// <param name="msg">The message to be encoded.</param>
		/// <param name="keyBytes">The secret key to be used.</param>
		public static string MD5(string msg, byte[] keyBytes)
		{
			MD5Digest digest = new MD5Digest();
			return HMacDigest(ASCIIEncoding.ASCII.GetBytes(msg), keyBytes, digest);
		}

		/// <summary>
		/// Return the sha1 HMAC of the message and given digest.
		/// </summary>
		/// <param name="msg">The message to be encoded.</param>
		/// <param name="keyBytes">The secret key to be used.</param>
		public static string Sha1(string msg, byte[] keyBytes)
		{
			Sha1Digest digest = new Sha1Digest();
			return HMacDigest(ASCIIEncoding.ASCII.GetBytes(msg), keyBytes, digest);
		}

		/// <summary>
		/// Return the sha256 HMAC of the message and given digest.
		/// </summary>
		/// <param name="msg">The message to be encoded.</param>
		/// <param name="keyBytes">The secret key to be used.</param>
		public static string Sha256(string msg, byte[] keyBytes)
		{
			Sha256Digest digest = new Sha256Digest();
			return HMacDigest(ASCIIEncoding.ASCII.GetBytes(msg), keyBytes, digest);
		}

		/// <summary>
		/// Return the sha512 HMAC of the message and given digest.
		/// </summary>
		/// <param name="msg">The message to be encoded.</param>
		/// <param name="keyBytes">The secret key to be used.</param>
		public static string Sha512(string msg, byte[] keyBytes)
		{
			Sha512Digest digest = new Sha512Digest();
			return HMacDigest(ASCIIEncoding.ASCII.GetBytes(msg), keyBytes, digest);
		}
	}
}

