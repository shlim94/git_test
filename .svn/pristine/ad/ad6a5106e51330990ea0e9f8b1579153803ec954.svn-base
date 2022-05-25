package com.wise.common.message;

import org.springframework.context.MessageSource;

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

public interface WiseMessageSource {
    
    public void setLocale(String locale);
    
    public void setMessageSource(MessageSource messageSource);

    public abstract String getMessage(String code);

    public abstract String getMessage(String code, String arg1);

    public abstract String getMessage(String code, String arg1, String arg2);

    public abstract String getMessage(String code, String arg1, String arg2, String arg3);

    public abstract String getMessage(String code, Object[] args);

}