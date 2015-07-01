# cryptography.Net
An easy to use AES and RSA cryptography library written in C#, built on the Bouncy Castle API. With this library you can quickly and easily incorporate AES-256 and RSA encryption into your project. The C# and Java version of these projects are the same at the API level.

If you develop in both Java and C# then this project and the <a href="https://github.com/acschmit/cryptography" target="_blank">Java project</a> are worth taking a look at.  They share the same API.  The Unit Tests and Examples are the same between them as well to illustrate their similarity.

##License
The [license](LICENSE.txt), including licenses for dependent software, can be read [here](LICENSE.txt).

##External Dependencies
This library is dependent on the following jar files in <a href="http://www.bouncycastle.org" target="_blank">Bouncy Castle C# library Version 1.7</a> which are included in this project.

* BouncyCastle.Crypto.dll

##Compiling
This project can be compiled in Xamarin or Visual Studio 2012.  To run the Unit Tests in Visual Studio 2012 you must install the **NUnit Test Adapter** in the **Tools / Extensions and Updates** menu.  The Unit Test should already work in Xamarin.

Either download the zip file or clone the repository to obtain the full project source.  After you compile the source you can find the following files in Cryptography/bin/Release which you can copy into your project:

* BouncyCastle.Crypto.dll
* Cryptography.dll

##Examples
For comprehensive examples either look at the Nunit Test or examine the Examples project included in this distribution.

####Example 1

Adding AES256 encryption to your project can be as simple as this:
```java
using System;
using Org.AlbertSchmitt.Crypto;
using Org.BouncyCastle.Security;
using System.Text;

namespace Examples
{
	public static class Example_060
	{
		public static void main()
		{
			// Create the AES Service
			AESService aes = new AESService();

			string password = "password";
			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[AESService.SALT_SIZE];
			random.NextBytes(salt);

			// Create the AES Key using password and salt.
			aes.generateKey(password, salt);

			// Encode and Decode a string then compare to verify they are the same.
			string clear_text = "This is a test";
			byte[] enc_bytes = aes.encode(UTF8Encoding.UTF8.GetBytes(clear_text));
			byte[] dec_bytes = aes.decode(enc_bytes);
			string dec_text = UTF8Encoding.UTF8.GetString(dec_bytes);

			/**
			 * Compare the original and decrypted files.
			 */
			if (Compare.safeEquals(UTF8Encoding.UTF8.GetBytes(clear_text), UTF8Encoding.UTF8.GetBytes(dec_text)))
			{
				Console.Out.WriteLine("Original and Decrypted are the same!");
			}
			else
			{
				Console.Out.WriteLine("Original and Decrypted are NOT the same!");
			}
		}
	}
}
```
