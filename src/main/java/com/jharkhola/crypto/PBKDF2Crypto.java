package com.jharkhola.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.jharkhola.crypto.common.Constants;
import com.jharkhola.crypto.common.JharCryptoException;

public class PBKDF2Crypto {

	public static final String DIGESTER_ALGO = Constants.DIGESTER_PBKDF2;
	public static final int KEY_LENGTH = 128;
	public static final int PBKDF2_ITERATIONS = 1000;

	public static final int ITERATION_INDEX = 0;
	public static final int SALT_INDEX = 1;
	public static final int HASH_INDEX = 2;

	private static byte[] doFinal( final char[] password, final byte[] salt, final int iterations, final int keyLength ) throws JharCryptoException {

		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance( DIGESTER_ALGO );
			PBEKeySpec spec = new PBEKeySpec( password, salt, iterations, keyLength );
			SecretKey key = skf.generateSecret( spec );
			byte[] res = key.getEncoded();
			return res;

		} catch ( NoSuchAlgorithmException | InvalidKeySpecException e ) {
			throw new JharCryptoException( "No such algo or invalid key exception.", e );
		}
	}

	public static String createHash( String password ) throws JharCryptoException {
		return createHash( password.toCharArray() );
	}

	public static String createHash( char[] password ) throws JharCryptoException {

		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[KEY_LENGTH];
		random.nextBytes(salt);

		byte[] hash = doFinal( password, salt, PBKDF2_ITERATIONS, KEY_LENGTH );

		Base64 base64 = new Base64();

		return PBKDF2_ITERATIONS + ":" + base64.encodeAsString( salt ) + ":" + base64.encodeAsString( hash );
	}
	
	public static boolean validatePassword( String password, String hash) throws JharCryptoException {
		
		return validatePassword( password.toCharArray(), hash );
	}

	public static boolean validatePassword( char[] password, String hashedValue ) throws JharCryptoException {
        String[] params = hashedValue.split(":");
        int iterations = Integer.parseInt(params[ITERATION_INDEX]);
        
        Base64 base64 = new Base64();
        byte[] salt = base64.decode(params[SALT_INDEX]);
        byte[] hash = base64.decode(params[HASH_INDEX]);
        byte[] testHash = doFinal(password, salt, iterations, hash.length * 8);
        return slowEquals(hash, testHash);
	}

	private static boolean slowEquals( byte[] hash, byte[] testHash ) {
		int diff = hash.length ^ testHash.length;
        for( int i = 0; i < hash.length && i < testHash.length; i++ ) {
            diff |= hash[i] ^ testHash[i];
        }
        return diff == 0;
	}

}
