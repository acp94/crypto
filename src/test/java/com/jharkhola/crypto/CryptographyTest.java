package com.jharkhola.crypto;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;


public class CryptographyTest {
	
	@Test
	public void generateHash() throws Exception {
		String[] testStrings = { "some string", "some string", "hello	", "password123", "Some Nasty!!123 %&ÅAsdd", "Simple sting","An1!23klsdf123" };
		for(String string: testStrings) {
			String hash = PBKDF2Crypto.createHash( string );
			boolean result = PBKDF2Crypto.validatePassword( string , hash);
			Assert.assertTrue(result);
		}
	}
	
	@Test
	public void base64EncodeDecode() {
		String testString = "some string";
		byte[] testStringInBytes = testString.getBytes();
		Base64 base64 = new Base64();
		String encoded = base64.encodeAsString(testStringInBytes);
		String decoded = new String(base64.decode(encoded));
		Assert.assertEquals(testString, decoded);
	}
}
