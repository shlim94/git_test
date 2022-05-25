package com.wise.context.config;

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

public class InValidConfigLoadException extends Exception  {
	private static final long serialVersionUID = -7112622867819206464L;

	public InValidConfigLoadException() {
		super();
	}

	public InValidConfigLoadException(String message, Throwable cause) {
		super(message, cause);
	}

	public InValidConfigLoadException(String message) {
		super(message);
	}

	public InValidConfigLoadException(Throwable cause) {
		super(cause);
	}

}
