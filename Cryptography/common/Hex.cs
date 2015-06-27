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
using System.Text;

namespace org.albertschmitt.crypto
{
	/// <summary>
	/// Convert byte arrays to hexadecimal strings and visa-versa. This class is
	/// useful in situations where you want to store byte data in a text file.
	/// </summary>
	public static class Hex
	{
		/// <summary>
		/// Convert a hexadecimal string back into a byte array. This function
		/// reverses the action of the encode(byte data[]) function.
		/// </summary>
		/// <param name="hexString">A hexadecimal string.</param>
		public static byte[] decode(String hexString)
		{
			var len = hexString.Length;
			byte[] data = new byte[len / 2];
			for (int i = 0, j = 0; i < len; i += 2, j++)
			{
				int low = Convert.ToInt32(hexString[i + 1].ToString(), 16);
				int high = Convert.ToInt32(hexString[i].ToString(), 16);
				data[j] = (byte) ((high << 4) | low);
			}
			return data;
		}

		/// <summary>
		/// Convert a byte array into a hexadecimal string.
		/// </summary>
		/// <param name="data">The byte array to be converted into a hexadecimal string.</param>
		public static string encode(byte[] data)
		{
			string hexString = BitConverter.ToString(data);
			hexString = hexString.Replace("-", "");
			return hexString.ToLower();
		}
	}
}

