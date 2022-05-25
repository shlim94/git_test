package com.wise.ds.repository;

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

public class UnRegisterdReportException extends Exception  {
    private static final long serialVersionUID = 3622942389774588446L;
    
    public UnRegisterdReportException() {
		super();
	}

	public UnRegisterdReportException(String message, Throwable cause) {
		super(message, cause);
	}

	public UnRegisterdReportException(String message) {
		super(message);
	}

	public UnRegisterdReportException(Throwable cause) {
		super(cause);
	}
}
