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
using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace org.albertschmitt.crypto
{
	/// <summary>
	/// This class implements AES 256-bit encryption using the Bouncy Castle API
	/// which gets around the 128-bit limitation imposed by the java runtime. Clients
	/// can use this class to easily incorporate encryption into their applications.
	/// Note when converting between strings and byte arrays clients should be sure
	/// to convert using the UTF-8 character set.
	///
	/// External Dependencies:
	/// Bouncy Castle Release 1.7
	/// </summary>
	public class AESService
	{
		/**
	 	 * The size in bytes of the salt.
	 	 */
		private const int		SALT_SIZE		= 32;

		private const int		IV_LENGTH		= 16;
		private const int		AES_128			= 128;
		private const int 		AES_256 		= 256;

		private static int		key_size		= 0;
		private KeyParameter 	aes_key 		= null;

		private const string	TRANSFORMATION	= "AES/CBC/PKCS7Padding";

		/// <summary>
		/// Initializes a new instance of the <see cref="AESService"/> class.
		/// </summary>
		public AESService()
		{
			key_size = AES_256;
		}

		/**
		 * Returns the AES key size. This is a protected function so the programmer
		 * can changed the default key size to 128 bits by sub-classing this
		 * AESService and using #setAESKeySize(int key_size) in the constructor to
		 * change it.
		 *
		 * @return The key size.
		 */
		/// <summary>
		/// Gets the size of the AES key. This is a protected function so the programmer
		/// can changed the default key size to 128 bits by sub-classing this
		/// AESService and using #setAESKeySize(int key_size) in the constructor to
		/// change it.
		/// 
		/// </summary>
		/// <returns>The AES key size.</returns>
		protected static int getAESKeySize()
		{
			return key_size;
		}

		/// <summary>
		/// Sets the size of the AES key.  Inherit from this class and call this function 
		/// in the constructor to set the key size if you want it to be 128 bits instead of the default.
		/// </summary>
		/// <param name="key_size">he desired AES key size. Only 128 and 256 are valid.</param>
		protected static void setAESKeySize(int key_size)
		{
			if (key_size == AES_128 || key_size == AES_256)
			{
				AESService.key_size = key_size;
			}
			else
			{
				throw new Exception("Illegal AES key size.  Must be 128 or 256");
			}
		}

		/// <summary>
		/// Concatenate two byte arrays together.
		/// </summary>
		/// <param name="a">First byte array.</param>
		/// <param name="b">Second byte array.</param>
		/// <returns>Byte array containing First + Second byte array.</returns>
		private byte[] concatenate(byte[] a, byte[] b)
		{
			byte[] dest = new byte[a.Length + b.Length];
			Buffer.BlockCopy(a, 0, dest, 0, a.Length);
			Buffer.BlockCopy(b, 0, dest, a.Length, b.Length);
			return dest;
		}

		/// <summary>
		/// Return a IBufferedCipher for encryption or decryption.
		/// </summary>
		/// <param name="iv">The initialization vector.</param>
		/// <param name="forEncryption">forEncryption <c>true</c> to encrypt, <c>false</c> to decrypt.</param>
		/// <returns>IBufferedCipher configured to encrypt or decrypt</returns>
		private IBufferedCipher getCipher(byte[] iv, Boolean forEncryption)
		{
			ParametersWithIV ivKeyParam = new ParametersWithIV(aes_key, iv);
			IBufferedCipher cipher = CipherUtilities.GetCipher(TRANSFORMATION);
			cipher.Init(forEncryption, ivKeyParam);

			return cipher;
		}

		/// <summary>
		/// Encode the byte data to AES256 and return it in byte array.
		/// </summary>
		/// <param name="data">Byte array to be encoded.</param>
		/// <returns>AES256 encoded byte array of input data.</returns>
		public byte[] encode(byte[] data)
		{
			byte[] iv = new byte[IV_LENGTH];
			SecureRandom secure = new SecureRandom();
			secure.NextBytes(iv);
			IBufferedCipher cipher = getCipher(iv, true);

			byte[] enc = cipher.DoFinal(data);
			byte[] encrypted = concatenate(iv, enc);
			return encrypted;
		}

		/// <summary>
		/// Encode the String to AES256 and return it in byte array.
		/// </summary>
		/// <param name="data">String to be encoded.</param>
		/// <returns>AES256 encoded byte array of input data.</returns>
		public byte[] encode(String data)
		{
			byte[] bytes = UTF8Encoding.UTF8.GetBytes(data);
			return encode(bytes);
		}

		/// <summary>
		/// Decode the AES256 encoded byte data and return it in an byte array.
		/// </summary>
		/// <param name="data">AES256 encoded byte array.</param>
		/// <returns>Decoded byte array of AES256 encoded input data.</returns>
		public byte[] decode(byte[] data)
		{
			byte[] iv = new byte[IV_LENGTH];
			Buffer.BlockCopy(data, 0, iv, 0, IV_LENGTH);
			IBufferedCipher cipher = getCipher(iv, false);

			byte[] dec = cipher.DoFinal(data, iv.Length, data.Length - IV_LENGTH);
			return dec;
		}

		/// <summary>
		/// Decode the AES256 encoded String and return it in an byte array.
		/// </summary>
		/// <param name="data">AES256 encoded String.</param>
		/// <returns>Decoded byte array of AES256 encoded input data.</returns>
		public byte[] decode(String data)
		{
            byte[] bytes = Hex.decode(data);
			return decode(bytes);
		}

		/// <summary>
		/// Encrypt or decrypt a stream and send the result to an output stream.
		/// </summary>
		/// <param name="instream">The input stream to be encrypted.</param>
		/// <param name="outstream">The encrypted stream.</param>
		/// <param name="cipher">A PaddedBufferedBlockCipher configured to encrypt or decrypt.</param>
		private void doCipher(Stream instream, Stream outstream, IBufferedCipher cipher)
		{
			byte[] buffer = new byte[1024];
			int blocksize = buffer.Length;
			while((blocksize = instream.Read(buffer, 0, blocksize)) != 0)
			{
				byte[] enc = cipher.ProcessBytes(buffer, 0, blocksize);
				outstream.Write(enc, 0, enc.Length);
			}
			byte[] enc2 = cipher.DoFinal();
			outstream.Write(enc2, 0, enc2.Length);
			outstream.Flush();
		}

		/// <summary>
		/// Encode the input stream to AES256 and return it in an output stream.
		/// </summary>
		/// <param name="instream">Stream to be encoded.</param>
		/// <param name="outstream">AES256 encoded output stream of input stream.</param>
		public void encode(Stream instream, Stream outstream)
		{
			byte[] iv = new byte[IV_LENGTH];
			SecureRandom secure = new SecureRandom();
			secure.NextBytes(iv);
			IBufferedCipher cipher = getCipher(iv, true);
			outstream.Write(iv, 0, iv.Length);

			doCipher(instream, outstream, cipher);
		}

		/// <summary>
		/// Decode the AES256 encoded input stream and return it in an output stream.
		/// </summary>
		/// <param name="instream">AES256 encoded input stream to be decoded.</param>
		/// <param name="outstream">Decoded output stream of input stream.</param>
		public void decode(Stream instream, Stream outstream)
		{
			byte[] iv = new byte[IV_LENGTH];
			instream.Read(iv, 0, IV_LENGTH);
			IBufferedCipher cipher = getCipher(iv, false);

			doCipher(instream, outstream, cipher);
		}

		/// <summary>
		/// Generate an AES key. A key generated by this method would typically be
		/// encrypted using RSA and sent to the recipient along with data that was
		/// encrypted with the key. The recipient would then decrypt the key using
		/// RSA then use the key to decrypt the data.
		/// </summary>
		public void generateKey()
		{
			Pkcs5S2ParametersGenerator generator = new Pkcs5S2ParametersGenerator();

			SecureRandom random = new SecureRandom();
			byte[] password = new byte[SALT_SIZE];
			random.NextBytes(password);

			generator.Init(password, generateSalt(), 20000);
			aes_key = (KeyParameter) generator.GenerateDerivedMacParameters(AES_256);
		}

		/// <summary>
		/// Generate an AES key using a given password and salt.
		/// </summary>
		/// <param name="password">The password to be used to create the key.</param>
		/// <param name="salt">The 32 byte long array to be used to create the key.</param>
		public void generateKey(string password, byte[] salt)
		{
			Pkcs5S2ParametersGenerator generator = new Pkcs5S2ParametersGenerator();

			byte[] passwordBytes = Pkcs5S2ParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray());
			generator.Init(passwordBytes, salt, 20000);
			aes_key = (KeyParameter) generator.GenerateDerivedMacParameters(AES_256);
		}

		/// <summary>
		/// Generate a salt value using SecureRandom() that can be used to generate
		/// an AES256 key. The salt is 32 bytes in length.
		/// </summary>
		/// <returns>Byte array containing the salt.</returns>
		public byte[] generateSalt()
		{
			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[SALT_SIZE];
			random.NextBytes(salt);
			return salt;
		}

		/// <summary>
		/// Get the AES key that was created by <c>generateKey()</c> 
		/// or <c>generateKey(String password, byte[] salt)</c>
		/// </summary>
		/// <returns>Byte array containing the AES key.</returns>
		public byte[] getAesKey()
		{
			return aes_key.GetKey();
		}

		/// <summary>
		/// Sets the AES key that was retrieved by the <c>getAesKey()</c> method.
		/// </summary>
		/// <param name="data">Byte array containing the AES key.</param>
		public void setAesKey(byte[] data)
		{
			aes_key = new KeyParameter(data);
		}
	}
}

