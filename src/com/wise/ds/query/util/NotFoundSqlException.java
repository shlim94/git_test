package com.wise.ds.query.util;

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

public class NotFoundSqlException extends Exception  {
    private static final long serialVersionUID = 2583186344537277499L;
    
    private int httpStatusCode;

    public NotFoundSqlException() {
		super();
	}

	public NotFoundSqlException(String message, Throwable cause) {
		super(message, cause);
	}

	public NotFoundSqlException(String message) {
		super(message);
	}

	public NotFoundSqlException(Throwable cause) {
		super(cause);
	}

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public void setHttpStatusCode(int httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

}
