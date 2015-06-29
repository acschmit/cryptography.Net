using System;
using NUnit.Framework;
using System.IO;

namespace UnitTest
{
	[SetUpFixture]
	public class MySetupClass
	{
		[SetUp]
		public void Setup()
		{
			Console.Out.WriteLine("Deleting data files.");
			File.Delete(AESServiceTest.SALT_DAT);
			File.Delete(RSAServiceTest.privateKeyfile);
			File.Delete(RSAServiceTest.publicKeyfile);
		}

		[TearDown]
		public void Teardown()
		{
		}
	}
}

