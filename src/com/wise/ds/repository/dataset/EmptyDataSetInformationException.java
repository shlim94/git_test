package com.wise.ds.repository.dataset;

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

public class EmptyDataSetInformationException extends Exception  {
    private static final long serialVersionUID = -7896930587044972763L;
    
    private int httpStatusCode;

    public EmptyDataSetInformationException() {
		super();
	}

	public EmptyDataSetInformationException(String message, Throwable cause) {
		super(message, cause);
	}

	public EmptyDataSetInformationException(String message) {
		super(message);
	}

	public EmptyDataSetInformationException(Throwable cause) {
		super(cause);
	}

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public void setHttpStatusCode(int httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

}
