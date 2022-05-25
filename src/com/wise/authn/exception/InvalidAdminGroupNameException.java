package com.wise.authn.exception;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 * 
 *     수정일         수정자               수정내용
 *  --------------    ------------    ---------------------------
 *  2015.06.08        DOGFOOT              최초 생성
 * </pre>
 */

public class InvalidAdminGroupNameException extends Exception  {
    private static final long serialVersionUID = -7258748748309322920L;
    
    public InvalidAdminGroupNameException() {
		super();
	}

	public InvalidAdminGroupNameException(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidAdminGroupNameException(String message) {
		super(message);
	}

	public InvalidAdminGroupNameException(Throwable cause) {
		super(cause);
	}
}
