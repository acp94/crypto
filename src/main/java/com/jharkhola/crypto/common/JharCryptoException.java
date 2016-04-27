package com.jharkhola.crypto.common;

public class JharCryptoException extends Exception {
	
	private static final long serialVersionUID = 1L;

		public JharCryptoException(String message) {
				super(message);
		}
		
		public JharCryptoException(String message, Throwable th) {
			super(message, th);
		}
		
}
