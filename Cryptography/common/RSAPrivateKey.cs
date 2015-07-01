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
using Org.BouncyCastle.Crypto;

namespace Org.AlbertSchmitt.Crypto
{
	/// <summary>
	/// This class represents a strongly typed private RSA key.
	/// </summary>
	public class RSAPrivateKey : Key
	{
		private AsymmetricCipherKeyPair pki = null;

		/// <summary>
		/// Sets the AsymmetricCipherKeyPair.
		/// </summary>
		/// <returns>The pki.</returns>
		public AsymmetricCipherKeyPair GetPki()
		{
			return this.pki;
		}

		/// <summary>
		/// Gets the AsymmetricCipherKeyPair.
		/// </summary>
		/// <param name="acp">Acp.</param>
		public void SetPki(AsymmetricCipherKeyPair acp)
		{
			this.pki = acp;
			SetKey(pki.Private);
		}
	}
}

