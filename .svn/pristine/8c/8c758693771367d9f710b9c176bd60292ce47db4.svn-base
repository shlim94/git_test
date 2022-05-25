package com.wise.common.csrf;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

public class IAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {
       final Log logger = LogFactory.getLog(IAccessDeniedHandler.class);
       String ajaxHeader = ((HttpServletRequest) request).getHeader("X-Requested-With");
       String url = request.getRequestURL().toString();
	   String queryString = request.getQueryString();
	   String contentType = response.getContentType();
	   
	   logger.info("XXXXXXXXXXXXXXXXXXXXXXXXXXXX[AccessDenied]XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	   logger.info("XXXXX [X-Requested-With --------- [" + ajaxHeader + "] XXXXX");
	   logger.info("XXXXX [ContentType      --------- [" + contentType + "] XXXXX");
	   logger.info("XXXXX " + url + "?" + queryString + " XXXXX");
	   logger.info("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

	   // csrf토큰이 유효하지 않음
	   if(accessDeniedException instanceof InvalidCsrfTokenException) {
           response.setStatus(HttpServletResponse.SC_FORBIDDEN);
       }

       // csrf토큰이 없음
       if(accessDeniedException instanceof MissingCsrfTokenException) {
           response.setStatus(HttpServletResponse.SC_FORBIDDEN);
       }
    }
}