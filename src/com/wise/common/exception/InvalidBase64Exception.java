package com.wise.common.exception;

public class InvalidBase64Exception extends Exception {
	private static final long serialVersionUID = 4383056999149966484L;

	public InvalidBase64Exception() {
		super();
	}

	public InvalidBase64Exception(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidBase64Exception(String message) {
		super(message);
	}

	public InvalidBase64Exception(Throwable cause) {
		super(cause);
	}
}
