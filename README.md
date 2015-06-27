# cryptography.Net
An easy to use AES and RSA cryptography library written in C#, built on the Bouncy Castle API. With this library you can quickly and easily incorporate AES-256 and RSA encryption into your project. The C# and Java version of these projects are the same at the API level.

If you develop in both Java and C# then this project and the <a href="https://github.com/acschmit/cryptography" target="_blank">Java project</a> are worth taking a look at.  They share the same API.  The Unit Tests and Examples are the same between them as well to illustrate their similarity.

##License
The [license](LICENSE.txt), including licenses for dependent software, can be read [here](LICENSE.txt).

##External Dependencies
This library is dependent on the following jar files in <a href="http://www.bouncycastle.org" target="_blank">Bouncy Castle C# library Version 1.7</a> which are included in this project.

* BouncyCastle.Crypto.dll

#Compiling
This project can be compiled in Xamarin or Visual Studio 2012.  To run the Unit Tests in Visual Studio 2012 you must install the **NUnit Test Adapter** in the **Tools / Extensions and Updates** menu.  The Unit Test should already work in Xamarin.
