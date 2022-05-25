package com.wise.common.csrf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;
/**

 * IfpCsrfRequestMatcher.java
 * - 요청에 대해 스프링 시큐리티에서 CSRF를 적용할건지 아닐건지 판단
 * - AJAX CALL, 첫화면, 최측메뉴로딩, 팝업로등 요청은 CSRF 적용하지 않음
 * - (TEXT/HTML을 응답으로 보낸는 부분은 CsrfTokenAdder 필터에서 Csrf 히든태그 삽입함)
 * - 403 Forbidden 에러가 발생하는 부분이 있다면 이곳에서 추가할 것
 * 
 */

public class ICsrfRequestMatcher implements RequestMatcher {

	final Log logger = LogFactory.getLog(ICsrfRequestMatcher.class);

	@Override
    public boolean matches(HttpServletRequest request) {
    	String strUrl = request.getRequestURL().toString();
    	String strUri = request.getRequestURI();
    	String queryString = request.getQueryString() == null ? "" : request.getQueryString();
    	String contentType = request.getContentType() == null ? "" : request.getContentType();
    	//---------------------------------------------------------
    	// CSRF 필터링, 필요시 추가할것 여기에 추가안하면 403 오류 발생!
    	//---------------------------------------------------------
    	// AJAX CALL
    	if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
    		return false;
    	}
    	else if ("/".equals(strUri) || "/editds/".equals(strUri) || "/editds/login.do".equals(strUri)) {
        	return false;
        }
        // 디자이너
        else if ("/editds/report/edit.do".equals(strUri)) {
        	return false;
        }
    	// 환경설정
        else if ("/editds/report/config.do".equals(strUri)) {
        	return false;
        }
    	// 로그인 이미지
        else if ("/editds/report/uploadLoginImage.do".equals(strUri)) {
        	return false;
        }
    	// 첫화면
        else if ("/".equals(strUri) || "/olap/".equals(strUri) || "/olap/login.do".equals(strUri) || "/olapad/".equals(strUri) || "/olapad/login.do".equals(strUri)) {
        	return false;
        }
        // 디자이너
        else if ("/olap/report/edit.do".equals(strUri) || "/olapad/report/edit.do".equals(strUri)) {
        	return false;
        }
    	// 환경설정
        else if ("/olap/report/config.do".equals(strUri) || "/olapad/report/config.do".equals(strUri)) {
        	return false;
        }
        else if ("/olap/report/viewer.do".equals(strUri) || "/olapad/report/viewer.do".equals(strUri)) {
        	return false;
        }
        else if ("/editds/report/viewer.do".equals(strUri)) {
        	return false;
        }
        else if ("/editds/download/downloadFile.do".equals(strUri) || "/olap/download/downloadFile.do".equals(strUri) || "/olapad/download/downloadFile.do".equals(strUri)) {
        	return false;
        }
        else {
        	logger.info("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx request.getRequestURL() :: " + strUrl);
        	logger.info("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx request.getQueryString() :: " + queryString);
        	logger.info("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx request.getContentType() :: " + contentType);
        }
        return true;
    }
}