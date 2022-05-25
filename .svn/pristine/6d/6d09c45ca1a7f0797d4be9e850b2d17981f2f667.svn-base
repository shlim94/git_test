package com.wise.sso.controller;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.wise.authn.LoginLogVO;
import com.wise.authn.User;
import com.wise.authn.UserSessionVO;
import com.wise.authn.WiseSessionListener;
import com.wise.authn.exception.NotFoundUserException;
import com.wise.authn.service.AuthenticationService;
import com.wise.context.config.Configurator;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 *     수정일                 수정자             수정내용   
 *  ----------    --------    ---------------------------
 *  2015.06.08      DOGFOOT             최초 생성
 * </pre>
 */

abstract public class SsoController {
    private static final Logger logger = LoggerFactory.getLogger(SsoController.class);
    
    @Resource(name = "authenticationService")
    protected AuthenticationService authenticationService;
    
    /**
     * Create new user session. If current session is active, invalidate it.
     * @param request
     * @param user
     */
    protected void createSession(HttpServletRequest request, User user) {
    	if (request.getSession(false) != null) {
    	/* DOGFOOT ktkang 유저 로그아웃 로그 및 세션 관리 추가  20200923 */
    		removeSession(request, user);
    	}
        String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
        String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
        
        HttpSession session = request.getSession();
        String ip = request.getRemoteAddr();
        // get client IP address for localhost
        try {
	        if (ip.equalsIgnoreCase("0:0:0:0:0:0:0:1")) {
	            InetAddress inetAddress = InetAddress.getLocalHost();
	            String ipAddress = inetAddress.getHostAddress();
	            ip = ipAddress;
	        }
        } catch (UnknownHostException e) {
        	e.printStackTrace();
        }
        session.setAttribute(sessionUserKey, user);
        session.setAttribute("IP_ADDRESS", ip);
        session.setMaxInactiveInterval(7200);
		if (user != null) {
            try {
            	// session log
				UserSessionVO sessionVo = authenticationService.selectUserSessionLog(user);
				Timestamp currentTime = new Timestamp(System.currentTimeMillis());
				if (sessionVo == null) {
					sessionVo = new UserSessionVO();
					sessionVo.setUSER_ID(user.getUSER_ID());
					sessionVo.setUSER_NO(user.getUSER_NO());
					sessionVo.setUSER_SESSION_KEY(session.getId());
					sessionVo.setLOG_TYPE("LOGIN");
					sessionVo.setACCESS_IP(ip);
					sessionVo.setLAST_MSG_DT(currentTime);
					sessionVo.setMOD_USER_NO(user.getUSER_NO());
					sessionVo.setMOD_DT(currentTime);
					authenticationService.insertUserSessionLog(sessionVo);
				} else {
					sessionVo.setUSER_SESSION_KEY(session.getId());
					sessionVo.setLOG_TYPE("LOGIN");
					sessionVo.setACCESS_IP(ip);
					sessionVo.setLAST_MSG_DT(currentTime);
					sessionVo.setMOD_USER_NO(user.getUSER_NO());
					sessionVo.setMOD_DT(currentTime);
					authenticationService.updateUserSessionLog(sessionVo);
				}
				// login & logout log
				LoginLogVO logVo = new LoginLogVO(currentTime, "LOGIN", user.getUSER_ID(),
						user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "",
						(String) session.getAttribute("IP_ADDRESS"), "", user.getUSER_NO(), currentTime, "WB");
				authenticationService.insertLoginLog(logVo);
			} catch (Exception e) {
				e.printStackTrace();
			}
        }
    }
    
    /**
     * Return User object associated with the current session.
     * @param request
     * @return
     * @throws NotFoundUserException
     */
    protected User getSessionUser(HttpServletRequest request) throws NotFoundUserException {
        String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
        String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
        
        User user = (User) request.getSession(false).getAttribute(sessionUserKey);
        if (user == null) {
        	throw new NotFoundUserException("User with attribute " + sessionUserKey + " does not exist.");
        }
        return user;
    }
    
    /**
     * Invalidate current session.
     * @param request
     */
     /* DOGFOOT ktkang 유저 로그아웃 로그 및 세션 관리 추가  20200923 */
    protected void removeSession(HttpServletRequest request, User user) {
       	UserSessionVO sessionVo = authenticationService.selectUserSessionLog(user);
    	
    	HttpSession session = request.getSession();
        String ip = request.getRemoteAddr();
        
        Timestamp currentTime = new Timestamp(System.currentTimeMillis());
        sessionVo = new UserSessionVO();
        sessionVo.setUSER_ID(user.getUSER_ID());
        sessionVo.setUSER_NO(user.getUSER_NO());
        sessionVo.setUSER_SESSION_KEY(session.getId());
        sessionVo.setLOG_TYPE("LOGOUT");
        sessionVo.setACCESS_IP(ip);
        sessionVo.setLAST_MSG_DT(currentTime);
        sessionVo.setMOD_USER_NO(user.getUSER_NO());
        sessionVo.setMOD_DT(currentTime);
        authenticationService.updateUserSessionLog(sessionVo);
		
		LoginLogVO logVo = new LoginLogVO(currentTime, "LOGOUT", user.getUSER_ID(),
				user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "",
				ip, "", user.getUSER_NO(), currentTime, "WB");
		authenticationService.insertLoginLog(logVo);
		
    	request.getSession(false).invalidate();
    }
    
    @RequestMapping(value = {"/request.do", "/req.do"})
    abstract public void request(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception;
	
	@RequestMapping(value = {"/response.do", "/resp.do"})
    abstract public void response(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception;
}
