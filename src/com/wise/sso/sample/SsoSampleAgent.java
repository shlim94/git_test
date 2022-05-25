package com.wise.sso.sample;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SsoSampleAgent {
    private static final Logger logger = LoggerFactory.getLogger(SsoSampleAgent.class);

    private String ssoKey = "_SSO_KEY_";

    public void authn(HttpServletRequest request) {
        Map<String,String> authnInfo = new HashMap<String,String>();
        authnInfo.put("USER_ID", "tester1");
        authnInfo.put("TEL_NO", "010-1234-1234");
        
        request.getSession().setAttribute(this.ssoKey, authnInfo);
        logger.debug("sso authned> " + authnInfo);
    }

    @SuppressWarnings("unchecked")
    public Map<String,String> getAuthnInfo(HttpServletRequest request) {
        return (Map<String,String>) request.getSession().getAttribute(this.ssoKey);
    }

}
