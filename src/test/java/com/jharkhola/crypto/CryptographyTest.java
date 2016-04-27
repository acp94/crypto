package com.jharkhola.crypto;

import org.junit.Assert;
import org.junit.Test;


public class CryptographyTest {
	
	@Test
	public void generateHash() throws Exception {
		String hash = Cryptography.createHash( "some string" );
		String result = "1000:B@153f5a29:B@7f560810";
		Assert.assertEquals(result, hash);
	}
}
