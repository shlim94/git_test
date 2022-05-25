package com.wise.common.message;

import java.util.Locale;

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

public class WiseResourceMessageSource implements WiseMessageSource {

    private String locale;
    private Locale thisLocale;
    
    private MessageSource messageSource;

    public String getLocale() {
        return this.locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;

        if ("ko".equalsIgnoreCase(this.locale) || "kr".equalsIgnoreCase(this.locale)) {
            this.thisLocale = Locale.KOREA;
        } else {
            this.thisLocale = Locale.ENGLISH;
        }

    };
    
    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    private Locale getThisLocale() {
        return this.locale == null ? Locale.KOREA : this.thisLocale;
    }

    public String getMessage(String code) {
        return this.messageSource.getMessage(code, new Object[] {}, this.getThisLocale());
    }

    public String getMessage(String code, String arg1) {
        return this.messageSource.getMessage(code, new Object[] { arg1 }, this.getThisLocale());
    }

    public String getMessage(String code, String arg1, String arg2) {
        return this.messageSource.getMessage(code, new Object[] { arg1, arg2 }, this.getThisLocale());
    }

    public String getMessage(String code, String arg1, String arg2, String arg3) {
        return this.messageSource.getMessage(code, new Object[] { arg1, arg2, arg3 }, this.getThisLocale());
    }

    public String getMessage(String code, Object[] args) {
        return this.messageSource.getMessage(code, args, this.getThisLocale());
    }
}
