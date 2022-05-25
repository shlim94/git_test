package com.wise.authn.exception;

public class SessionNotFoundException extends Exception {
	private static final long serialVersionUID = 1697489987477373513L;
	
	public SessionNotFoundException() {
		super();
	}

	public SessionNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	public SessionNotFoundException(String message) {
		super(message);
	}

	public SessionNotFoundException(Throwable cause) {
		super(cause);
	}
}
