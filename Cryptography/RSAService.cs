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
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.OpenSsl;
using org.albertschmitt.crypto;
using Org.BouncyCastle.Asn1;
using System.Text;

namespace org.albertschmitt.crypto
{
	/// <summary>
	/// This class implements RSA private/public key encryption with a 2048 bit key
	/// using the Bouncy Castle API. Clients can use this class to easily incorporate
	/// encryption into their applications. Note when converting between strings and
	/// byte arrays clients should be sure to convert using the UTF-8 character set.
	///
	/// External Dependencies:
	/// Bouncy Castle Release 1.7
	/// </summary>
	public class RSAService
	{
		private const int RSA_STRENGTH = 1024 * 2;			// size of the RSA Key.
		private const int ENC_LENGTH = RSA_STRENGTH / 8;	// max len of the encrypted byte array.
		private const int PADDING_PKCS1	= 11;

		/// <summary>
		/// Create an instance of the <see cref="RSAService"/> class using a 2048 bit key.
		/// </summary>
		public RSAService()
		{
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
		/// Return an IAsymmetricBlockCipher for encryption or decryption.
		/// </summary>
		/// <returns>The block cipher.</returns>
		/// <param name="key">The RSA key.</param>
		/// <param name="forEncryption"><c>true</c> if encrypting, <c>false</c> if decrypting.</param>
		/// <returns>IAsymmetricBlockCipher configured to encrypt or decrypt.</returns>
		static IAsymmetricBlockCipher AsymmetricBlockCipher(Key key, bool forEncryption)
		{
			RsaKeyParameters rsaKey =(RsaKeyParameters)key.getKey();
			IAsymmetricBlockCipher cipher = new RsaEngine();
			cipher = new Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding(cipher);
			cipher.Init(forEncryption, rsaKey);
			return cipher;
		}

		/// <summary>
		/// Encrypt or decrypt a stream and send the result to an output stream. TBD
		/// explain data size limit and why we're using a loop to get around it.
		/// </summary>
		/// <param name="data">The data to be encrypted.</param>
		/// <param name="key">The key to be used.</param>
		/// <param name="forEncryption"><c>true</c> to encrypt, <c>false</c> to decrypt.</param>
		/// <returns>The encrypted data.</returns>
		private byte[] doCipher(byte[] data, Key key, Boolean forEncryption)
		{
			IAsymmetricBlockCipher cipher = AsymmetricBlockCipher(key, forEncryption);

			int enc_length =(forEncryption) ? ENC_LENGTH - PADDING_PKCS1 : ENC_LENGTH;
			int blocksize = enc_length;
			int offset = 0;
			byte[] bytes = new byte[0];

			while(blocksize == enc_length)
			{
				int remainder = data.Length - offset;
				blocksize =(remainder > enc_length) ? enc_length : remainder;
				if(blocksize != 0)
				{
					byte[] enc = cipher.ProcessBlock(data, offset, blocksize);
					bytes = concatenate(bytes, enc);
				}
				offset += enc_length;
			}
			if(bytes.Length == 0)
			{
				bytes = null;
			}
			return bytes;
		}

		/// <summary>
		/// Encrypt or decrypt a stream and send the result to an output stream.
		/// </summary>
		/// <param name="instream">The input stream to be encrypted.</param>
		/// <param name="outstream">The encrypted stream.</param>
		/// <param name="key">The key to be used.</param>
		/// <param name="forEncryption"><c>true</c> to encrypt, <c>false</c> to decrypt.</param>
		private void doCipher(Stream instream, Stream outstream, Key key, Boolean forEncryption)
		{
			IAsymmetricBlockCipher cipher = AsymmetricBlockCipher(key, forEncryption);

			int enc_length =(forEncryption) ? ENC_LENGTH - PADDING_PKCS1 : ENC_LENGTH;
			byte[] inbuf = new byte[enc_length];
			int blocksize = enc_length;

			while((blocksize = instream.Read(inbuf, 0, blocksize)) != 0) 
			{
				byte[] enc = cipher.ProcessBlock(inbuf, 0, blocksize);
				outstream.Write(enc, 0, enc.Length);
			}
			outstream.Flush();
		}

		/// <summary>
		/// Encode the byte data and return it in an byte array.
		/// </summary>
		/// <param name="data">The byte array to be encoded.</param>
		/// <param name="key">The key to be used.</param>
		/// <returns>The RSA encoded data.</returns>
		public byte[] encode(byte[] data, Key key)
		{
			return doCipher(data, key, true);
		}

		/// <summary>
		/// Encode the String and return it in an byte array.
		/// </summary>
		/// <param name="data">The String to be encoded.</param>
		/// <param name="key">The key to be used.</param>
		/// <returns>The RSA encoded data.</returns>
		public byte[] encode(String data, Key key)
		{
			byte[] bytes = UTF8Encoding.UTF8.GetBytes(data);
			return doCipher(bytes, key, true);
		}

		/// <summary>
		/// Decode the RSA encoded byte data and return it in an byte array.
		/// </summary>
		/// <param name="data">RSA encoded byte array.</param>
		/// <param name="key">The key to be used.</param>
		/// <returns>Decoded byte array of RSA encoded input data.</returns>
		public byte[] decode(byte[] data, Key key)
		{
			return doCipher(data, key, false);
		}

		/// <summary>
		/// Decode the RSA encoded String and return it in an byte array.
		/// </summary>
		/// <param name="data">RSA encoded String.</param>
		/// <param name="key">The key to be used.</param>
		/// <returns>Decoded byte array of RSA encoded input data.</returns>
		public byte[] decode(String data, Key key)
		{
			byte[] bytes = UTF8Encoding.UTF8.GetBytes(data);
			return doCipher(bytes, key, true);
		}

		/// <summary>
		/// Encode the input stream to RSA and return it in an output stream.
		/// </summary>
		/// <param name="instream">Stream to be encoded.</param>
		/// <param name="outstream">RSA encoded output stream of input stream.</param>
		/// <param name="key">The key to be used.</param>
		public void encode(Stream instream, Stream outstream, Key key)
		{
			doCipher(instream, outstream, key, true);
		}

		/// <summary>
		/// Decode the RSA encoded input stream and return it in an output stream.
		/// </summary>
		/// <param name="instream">RSA encoded input stream to be decoded.</param>
		/// <param name="outstream">Decoded output stream of input stream.</param>
		/// <param name="key">The key to be used.</param>
		public void decode(Stream instream, Stream outstream, Key key)
		{
			doCipher(instream, outstream, key, false);
		}

		/// <summary>
		/// Read the RSA Private Key from the specified filename.
		/// </summary>
		/// <param name="filename">The file that contains the RSA Private Key.</param>
		/// <returns>The RSAPrivateKey.</returns>
		public RSAPrivateKey readPrivateKey(string filename)
		{
			RSAPrivateKey key = null;
			using (FileStream instream = new FileStream (filename, FileMode.Open)) 
			{
				key = readPrivateKey(instream);
			}
			return key;
		}

		/// <summary>
		/// The input stream that contains the RSA Private Key.
		/// </summary>
		/// <param name="instream">The input stream that contains the RSA Private Key.</param>
		/// <returns>The RSAPrivateKey.</returns>
		public RSAPrivateKey readPrivateKey(Stream instream)
		{
			RSAPrivateKey key = new RSAPrivateKey();
			using(StreamReader reader = new StreamReader(instream))
			{
				PemReader pem = new PemReader(reader);
				AsymmetricCipherKeyPair acp =(AsymmetricCipherKeyPair)pem.ReadObject();
				pem.Reader.Close();
				key.setPki(acp);
			}
			return key;
		}

		/// <summary>
		/// Read the RSA Public Key from the specified filename.
		/// </summary>
		/// <param name="filename">The file that contains the RSA Public Key.</param>
		/// <returns>The RSAPublicKey.</returns>
		public RSAPublicKey readPublicKey(string filename)
		{
			RSAPublicKey key = null;
			using (FileStream instream = new FileStream (filename, FileMode.Open)) 
			{
				key = readPublicKey (instream);
			}
			return key;
		}

		/// <summary>
		/// Read the RSA Public Key from the specified input stream.
		/// </summary>
		/// <param name="instream">The input stream that contains the RSA Public Key.</param>
		/// <returns>The RSAPublicKey.</returns>
		public RSAPublicKey readPublicKey(Stream instream)
		{
			RSAPublicKey key = new RSAPublicKey();
			using(StreamReader reader = new StreamReader(instream))
			{
				PemReader pem = new PemReader(reader);
				key.setKey((AsymmetricKeyParameter)pem.ReadObject());
				pem.Reader.Close();
			}
			return key;
		}

		// ** Implement below to match Java **
		// public RSAPublicKey readPublicKeyFromPrivate(String filename)
		// public RSAPublicKey readPublicKeyFromPrivate(InputStream in)

		/// <summary>
		/// Reads the public Key Der.
		/// </summary>
		/// <returns>The public key der.</returns>
		/// <param name="filename">The file name of the Key Der.</param>
		public RSAPublicKey readPublicKeyDer(string filename)
		{
			RSAPublicKey key = null;
			using (FileStream instream = new FileStream(filename, FileMode.Open))
			{
				key = readPublicKeyDer(instream);
			}
			return key;
		}

		/// <summary>
		/// Reads the public Key Der.
		/// </summary>
		/// <returns>The public key der.</returns>
		/// <param name="instream">The input stream that contains the Key Der.</param>
		public RSAPublicKey readPublicKeyDer(Stream instream)
		{
			RSAPublicKey key = null;
			using(MemoryStream ms = new MemoryStream())
			{
				instream.CopyTo(ms);
				byte[] data =  ms.ToArray();
				AsymmetricKeyParameter keyParam = PublicKeyFactory.CreateKey(data);

				key = new RSAPublicKey();
				key.setKey (keyParam);
			}
			return key;
		}

		/// <summary>
		/// Utility function that writes an RSA Public or Private key to an output
		/// stream.
		/// </summary>
		/// <param name="os">The stream to write the RSA key to.</param>
		/// <param name="key">The Key to be written to the stream.</param>
		private static void writeKey (Stream os, AsymmetricKeyParameter key)
		{
			// Write the public or private key.
			using (StreamWriter writer = new StreamWriter (os)) 
			{
				PemWriter pem = new PemWriter (writer);
				pem.WriteObject (key);
				pem.Writer.Close ();
			}
		}

		/// <summary>
		/// Construct a Private Key from an AsymmetricCipherKeyPair and write it to
		/// the Output Stream.
		/// </summary>
		/// <param name="keyPair">The Private Key.</param>
		/// <param name="os">The stream the Private Key is to be written to.</param>
		private void writePrivateKey(AsymmetricCipherKeyPair keyPair, Stream os)
		{
			// Extract the private key.
			PrivateKeyInfo pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
			byte[] data = pki.ToAsn1Object().GetDerEncoded();

			AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey (data);
			writeKey (os, key);
		}

		/// <summary>
		/// Construct a Public Key from an AsymmetricCipherKeyPair and write it to
		/// the Output Stream.
		/// </summary>
		/// <param name="keyPair">The Public Key.</param>
		/// <param name="os">The stream the Public Key is to be written to.</param>
		private void writePublicKey(AsymmetricCipherKeyPair keyPair, Stream os)
		{
			// Extract the public key.
			SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
			byte[] data = pki.ToAsn1Object().GetDerEncoded();

			AsymmetricKeyParameter key = PublicKeyFactory.CreateKey(data);
			writeKey (os, key);
		}
		
		/// <summary>
		/// Generate a Public / Private RSA key pair and write them to the designated
		/// file names.
		/// </summary>
		/// <param name="private_keyfile">The file name to which the RSA Private Key will be written.</param>
		/// <param name="public_keyfile">public_filename The file name to which the RSA Public Key will be written.</param>
		public void generateKey(string private_keyfile, string public_keyfile)
		{
			FileStream fos_private = new FileStream (private_keyfile, FileMode.Create);
			FileStream fos_public = new FileStream (public_keyfile, FileMode.Create);
			generateKey(fos_private, fos_public);
		}

		/// <summary>
		/// Generate a Public / Private RSA key pair and write them to the designated
		/// Output Streams.
		/// </summary>
		/// <param name="os_private">The stream to which the RSA Private Key will be written.</param>
		/// <param name="os_public">The stream to which the RSA Public Key will be written.</param>
		public void generateKey(Stream os_private, Stream os_public)
		{
			RsaKeyPairGenerator kpg = new RsaKeyPairGenerator();
			KeyGenerationParameters kparams = new KeyGenerationParameters(new SecureRandom(), RSA_STRENGTH);
			kpg.Init(kparams);
			AsymmetricCipherKeyPair keyPair = kpg.GenerateKeyPair();

			writePrivateKey(keyPair, os_private);
			writePublicKey(keyPair, os_public);
		}

		/// <summary>
		/// Checks for the existence of the RSA Private and Public Key and returns
		/// true if they exist or false if they don't.
		/// </summary>
		/// <param name="private_keyfile">The file containing the RSA Private Key.</param>
		/// <param name="public_keyfile">The file containing the RSA Public Key.</param>
		/// <returns><c>true</c> if the key pair exist <c>false</c> if they do not.</returns>
		public Boolean areKeysPresent(string private_keyfile, string public_keyfile)
		{
			Boolean bOK = false;
			if(File.Exists(private_keyfile) && File.Exists(public_keyfile))
			{
				bOK = true;
			}
			return bOK;
		}
	}
}

