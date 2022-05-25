package com.wise.common.exception;

import javax.servlet.ServletException;

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

public class InvalidAccessException extends ServletException {
    private static final long serialVersionUID = -5070455409331912039L;

    public InvalidAccessException() {
		super();
	}

	public InvalidAccessException(String string) {
		super(string);
	}

	public InvalidAccessException(Throwable throwable) {
		super(throwable);
	}
	
	public InvalidAccessException(Throwable m, Throwable e) {
        super(m.getMessage(), e);
    }
}
