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
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto;
using System.IO;

namespace Org.AlbertSchmitt.Crypto
{
	/// <summary>
	/// SHA classes.
	/// </summary>
	public static class DigestSHA
	{
		// InputStream buffer size.
		private const int BUFFER_SIZE = 8192;

		/// <summary>
		/// Encode the stream with the given digest.
		/// </summary>
		/// <param name="data">The byte array to be encoded.</param>
		/// <param name="digest">The digest to be used.</param>
		/// <returns>Hashed value of the byte array as a hex string.</returns>
		private static string Encode(byte[] data, IDigest digest)
		{
			digest.BlockUpdate(data, 0, data.Length);
			byte[] output = new byte[digest.GetDigestSize()];
			digest.DoFinal (output, 0);
			return Hex.Encode(output);
		}

		/// <summary>
		/// Encode the stream with the given digest.
		/// </summary>
		/// <param name="instream">The stream to be encoded.</param>
		/// <param name="digest">The digest to be used.</param>
		/// <returns>Hashed value of the stream as a hex string.</returns>
		private static string Encode(Stream instream , IDigest digest)
		{
			byte[] buffer = new byte[BUFFER_SIZE];
			int read;
			while ((read = instream.Read(buffer, 0, BUFFER_SIZE)) > 0)
			{
				digest.BlockUpdate(buffer, 0, read);
			}
			byte[] output = new byte[digest.GetDigestSize()];
			digest.DoFinal(output, 0);
			return Hex.Encode(output);
		}

		/// <summary>
		/// Return the md5 hash of the byte array.
		/// </summary>
		/// <param name="data">Data to be hashed.</param>
		public static string MD5(byte[] data)
		{
			MD5Digest digest = new MD5Digest();
			return Encode(data, digest);
		}

		/// <summary>
		/// Return the md5 hash of the stream.
		/// </summary>
		/// <param name="instream">Data to be hashed.</param>
		public static string MD5(Stream instream)
		{
			MD5Digest digest = new MD5Digest();
			return Encode(instream, digest);
		}

		/// <summary>
		/// Return the sha1 hash of the byte array.
		/// </summary>
		/// <param name="data">Data to be hashed.</param>
		public static string Sha1(byte[] data)
		{
			Sha1Digest digest = new Sha1Digest();
			return Encode(data, digest);
		}

		/// <summary>
		/// Return the sha1 hash of the stream.
		/// </summary>
		/// <param name="instream">Data to be hashed.</param>
		public static string Sha1(Stream instream)
		{
			Sha1Digest digest = new Sha1Digest();
			return Encode(instream, digest);
		}

		/// <summary>
		/// Return the sha256 hash of the byte array.
		/// </summary>
		/// <param name="data">Data to be hashed.</param>
		public static string Sha256(byte[] data)
		{
			Sha256Digest digest = new Sha256Digest();
			return Encode(data, digest);
		}

		/// <summary>
		/// Return the sha256 hash of the stream.
		/// </summary>
		/// <param name="instream">Data to be hashed.</param>
		public static string Sha256(Stream instream)
		{
			Sha256Digest digest = new Sha256Digest();
			return Encode(instream, digest);
		}

		/// <summary>
		/// Return the sha384 hash of the byte array.
		/// </summary>
		/// <param name="data">Data to be hashed.</param>
		public static string Sha384(byte[] data)
		{
			Sha384Digest digest = new Sha384Digest();
			return Encode(data, digest);
		}

		/// <summary>
		/// Return the sha384 hash of the stream.
		/// </summary>
		/// <param name="instream">Data to be hashed.</param>
		public static string Sha384(Stream instream)
		{
			Sha384Digest digest = new Sha384Digest();
			return Encode(instream, digest);
		}

		/// <summary>
		/// Return the sha512 hash of the byte array.
		/// </summary>
		/// <param name="data">Data to be hashed.</param>
		public static string Sha512(byte[] data)
		{
			Sha512Digest digest = new Sha512Digest();
			return Encode(data, digest);
		}

		/// <summary>
		/// Return the sha512 hash of the stream.
		/// </summary>
		/// <param name="instream">Data to be hashed.</param>
		public static string Sha512(Stream instream)
		{
			Sha512Digest digest = new Sha512Digest();
			return Encode(instream, digest);
		}
	}
}

