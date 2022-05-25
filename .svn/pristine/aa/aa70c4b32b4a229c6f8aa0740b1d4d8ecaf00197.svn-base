package com.wise.authn;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import com.wise.authn.service.AuthenticationService;
import com.wise.authn.service.impl.AuthenticationServiceImpl;
import com.wise.context.config.Configurator;

/**
 * Class that handles user session events. 
 */
public class WiseSessionListener implements HttpSessionListener {
	private static Hashtable<String, HttpSession> sessions = new Hashtable<String, HttpSession>();
	
	@Autowired
	AuthenticationServiceImpl authenticationService;
    
	/**
	 * Get number of sessions logged on the server.
	 * @return number of user sessions
	 */
    public static int getTotalActiveSessions() {
    	return sessions.values().size();
    }
    
    public static void addSession(HttpSession session) {
    	sessions.put(session.getId(), session);
    }
    
    /**
     * Print a string representation of sessions Map.
     */
    public static void printSessions() {
    	String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
        String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
        
        try {
	        for (Map.Entry<String, HttpSession> entry : sessions.entrySet()) {
	        	String sessionId = entry.getKey();
	        	User user = (User) entry.getValue().getAttribute(sessionUserKey);
	        }
        } catch(Exception e) {}
    }
    
    /**
     * Get a user session by the session ID.
     * @param sessionId Unique session identifier key
     * @return session representing sessionId
     */
    public static HttpSession getSession(String sessionId) {
    	return sessions.get(sessionId);
    }
    
    /**
     * Handle session created event.
     */
	@Override
	public void sessionCreated(HttpSessionEvent se) {
		//
	}

	/**
	 * Handle session destroyed event.
	 */
	@Override
	public void sessionDestroyed(HttpSessionEvent se) {
		String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
        String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
		
        HttpSession session = se.getSession();
        
		User user = (User) session.getAttribute(sessionUserKey);
		if (user != null) {
//			try {
				// session log
				//ApplicationContext ctx = WebApplicationContextUtils.getWebApplicationContext(session.getServletContext());
			    //AuthenticationService authenticationService = ctx.getBean(AuthenticationService.class);
				if(authenticationService!=null) {
					UserSessionVO sessionVo = authenticationService.selectUserSessionLog(user);
					Timestamp currentTime = new Timestamp(System.currentTimeMillis());
					sessionVo.setACCESS_IP((String) session.getAttribute("IP_ADDRESS"));
					sessionVo.setUSER_SESSION_KEY(session.getId());
					sessionVo.setLOG_TYPE("LOGOUT");
					sessionVo.setLAST_MSG_DT(currentTime);
					sessionVo.setMOD_USER_NO(user.getUSER_NO());
					sessionVo.setMOD_DT(currentTime);
					authenticationService.updateUserSessionLog(sessionVo);
					// login & logout log
					LoginLogVO logVo = new LoginLogVO(currentTime, "LOGOUT", user.getUSER_ID(),
							user.getUSER_NM(), user.getUSER_NO(), user.getGRP_ID(), "",
							(String) session.getAttribute("IP_ADDRESS"), "", user.getUSER_NO(), currentTime, "WB");
					authenticationService.insertLoginLog(logVo);
				}
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
		}
		sessions.remove(session.getId());
		printSessions();
	}
}