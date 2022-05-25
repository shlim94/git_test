package com.wise.ds.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.HttpHeaders;

import com.wise.authn.User;
import com.wise.context.config.Configurator;

import net.sf.json.JSONObject;

@WebFilter("/report/*")
public class LoginFilter implements Filter {

    @Override
    public void init(FilterConfig config) throws ServletException {
        // If you have any <init-param> in web.xml, then you could get them
        // here by config.getInitParameter("name") and assign it as field.
    }
    
    private User getSessionUser(HttpServletRequest request) {
        String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
        String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
        /*dogfoot 디자이너 url 로그인 shlim 20201209*/
        String userId = request.getParameter("USER");
        HttpSession session;
        if(userId == null) {
        	session = request.getSession(false);
        	if (session == null) {
        		return null;
        	}
        } else {
        	session = request.getSession(false);
        }
        
        /* DOGFOOT ktkang 뷰어로 바로 접근 할 때 로그인페이지로 이동하는 오류 수정  20200207 */
        String byPassKeyEncrypted = request.getParameter("assign_name");
        /* DOGFOOT ktkang KERIS 포탈 세션 계속 물고있는 부분 수정  20200214 */
        User user = null;
        if(byPassKeyEncrypted != null) {
        	user = new User();
        	user.setUSER_ID(userId);
        } else if (session != null) {
        	user = (User) session.getAttribute(sessionUserKey);
        }
        return user;
        /* DOGFOOT ktkang 세션 관리 예쩐 소스로 복구  20200620 */
//        HttpSession session = request.getSession(false);
//        if (session == null) {
//        	return null;
//        }
//        return (User) session.getAttribute(sessionUserKey);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate"); // HTTP 1.1.
        response.setHeader("Pragma", "no-cache"); // HTTP 1.0.
        response.setDateHeader("Expires", 0); // Proxies.
        StringBuffer url = request.getRequestURL();
        
        boolean sessionCheck = Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication.viewer.session.check", false);
        
        User user = this.getSessionUser(request);
        
        if(sessionCheck) {
	        /* DOGFOOT ktkang 프린트 삭제   20200212 */
	        if(url.substring(url.lastIndexOf("/")).equals("/viewer.do") || url.substring(url.lastIndexOf("/")).equals("/excelView.do") || url.substring(url.lastIndexOf("/")).equals("/selectReportWorks.do")) {
	        	if (user == null) {
	            	// jQuery ajax requests. Works with IE11, Chrome, Firefox
	            	if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
	                	PrintWriter out = response.getWriter();
	                	JSONObject obj = new JSONObject();
	                	obj.put("redirectUrl", "https://eis2.work.go.kr");
	                	out.print(obj);
	                	out.flush();
	                	out.close();
	                // non-ajax requests
	                } else {
	                	response.sendRedirect("https://eis2.work.go.kr");
	                }
	            } else {
	                chain.doFilter(req, res); // Logged-in user found, so just continue request.
	            }
	        }else {
	        	if (user == null) {
	            	// jQuery ajax requests. Works with IE11, Chrome, Firefox
	            	if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
	                	PrintWriter out = response.getWriter();
	                	JSONObject obj = new JSONObject();
	                	obj.put("redirectUrl", url.toString().replace(request.getRequestURI().substring(request.getRequestURI().indexOf("/", 2)), "") + "/login.do");
	                	out.print(obj);
	                	out.flush();
	                	out.close();
	                // non-ajax requests
	                } else {
	                	response.sendRedirect(url.toString().replace(request.getRequestURI().substring(request.getRequestURI().indexOf("/", 2)), "") + "/login.do");
	                }
	            } else {
	                chain.doFilter(req, res); // Logged-in user found, so just continue request.
	            }
	        }
	    } else {
	    	chain.doFilter(req, res);
        }
    }

    @Override
    public void destroy() {
        // If you have assigned any expensive resources as field of
        // this Filter class, then you could clean/close them here.
    }

}