package com.wise.sso.controller;

import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.util.Enumeration;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jxl.common.Logger;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.wise.authn.WiseSessionListener;
import com.wise.authn.exception.NotFoundUserException;
import com.wise.authn.exception.PermissionDeniedReportViewException;
import com.wise.authn.User;
import com.wise.authn.UserGroupVO;
import com.wise.authn.UserSessionVO;
import com.wise.authn.WebConfigMasterVO;
import com.wise.authn.service.AuthenticationService;
import com.wise.common.secure.SecureUtils;
import com.wise.authn.ConfigMasterVO;
import com.wise.authn.LoginLogVO;

@Controller
public class LoginController extends SsoController {
	@Resource(name = "authenticationService")
    private AuthenticationService authenticationService;
	
	@RequestMapping(value = {"/page.do"})
    public void response(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
	    
	}
	
	@RequestMapping(value = {"/", "/login.do"})
    public ModelAndView login(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		String redirector = "login";
        ModelAndView mv = new ModelAndView(redirector);
        ConfigMasterVO configVo = authenticationService.getConfigMstr();
		WebConfigMasterVO webConfigVo = authenticationService.getWebConfigMstr();
		String mainTitle = configVo.getMAIN_TITLE();
        String loginImage = webConfigVo.getLOGIN_IMAGE();
        mv.addObject("mainTitle", mainTitle);
        mv.addObject("loginImage", loginImage);
        return mv;
    }
	
	@RequestMapping(value = {"/loginCheck.do"})
    public void loginCheck(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject ret = new JSONObject();
		
		String id = SecureUtils.getParameter(request, "id");
        String password = SecureUtils.getParameter(request, "pwd");
        
        // check login limit and duplicate users
//        try {
        	User verifyUser = authenticationService.selectUserById(id);
        	if (verifyUser == null) {
        		ret.put("error", "사용자 정보가 일치하지 않습니다.");
        	} else {
        		ConfigMasterVO config = authenticationService.getConfigMstr();
            	int limitConnections = Integer.parseInt(config.getLIMIT_CONNECTIONS());
        		int userLockCount = verifyUser.getLOCK_CNT();
        		int loginLockCount = Integer.parseInt(config.getLOGIN_LOCK_CNT());
        		int inactiveLimit = Integer.parseInt(config.getUSE_TERM());
        		Integer userInactiveDays = authenticationService.selectUserInactiveDays(verifyUser);
        		if (loginLockCount > 0 && userLockCount >= loginLockCount) {
        			ret.put("error", "로그인 실패 횟수를 초과하였습니다 ( 실패 횟수 : " + loginLockCount + "번).\n관리자에게 문의하세요.");
        		}
        		else if (userInactiveDays != null && inactiveLimit > 0 && userInactiveDays >= inactiveLimit) {
        			ret.put("error", "미사용 제한 일자를 초과하였습니다 ( 제한일자 : " + inactiveLimit + "일).\n관리자에게 문의하세요.");
        		}
	        	else {
	        		/* DOGFOOT cshan SITENM에 따라 로그인 암호화 일부 적용20200211*/
	        		if(config.getSITE_NM() != null && !config.getSITE_NM().equals("")) {
		    			if(config.getLOGIN_EXT() != null && config.getLOGIN_EXT().equalsIgnoreCase("Y")) {
		    				if(config.getUSE_HASH_YN() != null && config.getUSE_HASH_YN().equalsIgnoreCase("Y")) {
		    					switch(config.getHASH_ALGORITHM()) {
		    					case "1": //MD-5
		    						break;
		    					case "2": //SHA1
		    						MessageDigest md_SHA1 = MessageDigest.getInstance("SHA-1");
				    				byte[] SHA1_hash = md_SHA1.digest(password.getBytes());
				    				StringBuffer SHA1_hexString = new StringBuffer();
				    				for(int i=0;i<SHA1_hash.length;i++) {
				    					String hex = Integer.toHexString(0xff&SHA1_hash[i]);
				    					if(hex.length() == 1) SHA1_hexString.append('0');
				    					SHA1_hexString.append(hex);
				    				}
				    				password = SHA1_hexString.toString();
		    						break;
		    					case "3": //SHA256 - java 7
		    						MessageDigest md_SHA256 = MessageDigest.getInstance("SHA-256");
					    			byte[] SHA256_hash = md_SHA256.digest(password.getBytes());
					    			StringBuffer SHA256_hexString = new StringBuffer();
					    			for(int i=0;i<SHA256_hash.length;i++) {
					    				String hex = Integer.toHexString(0xff&SHA256_hash[i]);
					    				if(hex.length() == 1) SHA256_hexString.append('0');
					    				SHA256_hexString.append(hex);
					    			}
					    			password = SHA256_hexString.toString();
		    						break;
		    					case "4"://SHA512 - java 8 
		    						MessageDigest md_SHA512 = MessageDigest.getInstance("SHA-512");
				    				byte[] SHA512_hash = md_SHA512.digest(password.getBytes());
				    				StringBuffer SHA512_hexString = new StringBuffer();
				    				for(int i=0;i<SHA512_hash.length;i++) {
				    					String hex = Integer.toHexString(0xff&SHA512_hash[i]);
				    					if(hex.length() == 1) SHA512_hexString.append('0');
				    					SHA512_hexString.append(hex);
				    				}
				    				password = SHA512_hexString.toString();
		    						break;
		    					case "5": //모름 추후 알아내서 추가해야함
		    						break;
		    					}
		    				}
		    			}
		    		}
	        		User user = authenticationService.selectLoginUser(id, password);
		        	if(user != null) {
		        		verifyUser.setLOCK_CNT(0);
		        		authenticationService.updateUserLockCount(verifyUser);
		        		ret.put("userId", user.getUSER_ID());
		        		ret.put("user_rel_cd", user.getUSER_REL_CD());
		        		// ADMIN/VIEWER 확
		        		String href = "";
						UserGroupVO runMode = this.authenticationService.selectUserGroupRunMode(user);
						String userId = user.getUSER_ID();
						String userId2 = URLEncoder.encode(userId, "UTF-8");
						boolean grpMode = false;
						if(runMode.getUSER_RUN_MODE() == null || runMode.getUSER_RUN_MODE().equals("")) {
							grpMode = true;
						}
						if (runMode == null) {
							ret.put("error", "사용자 정보가 일치하지 않습니다.");
						/* DOGFOOT ktkang USER RUN MODE 없을 때 오류 수정  20200922 */
						} else if (grpMode && runMode.getGRP_RUN_MODE().equals("ADMIN")) {
							href = "report/edit.do";
						} else if (grpMode  && runMode.getGRP_RUN_MODE().equals("VIEW")) {
							href = "report/viewer.do?USER=" + userId2 + "&assign_name=bWVpcw==";
						} else if (runMode.getUSER_RUN_MODE() != null && runMode.getUSER_RUN_MODE().equals("ADMIN")) {
							href = "report/edit.do";
						} else if (runMode.getUSER_RUN_MODE() != null && runMode.getUSER_RUN_MODE().equals("VIEW")) {
							href = "report/viewer.do?USER=" + userId2 + "&assign_name=bWVpcw==";
						} else {
							href = "report/viewer.do?USER=" + userId2 + "&assign_name=bWVpcw==";
						}
		        		ret.put("href", href);
		        		this.createSession(request, user);
		        	} else {
		        		String lockMsg = "";
		        		if (loginLockCount > 0) {
		        			userLockCount++;
		        			verifyUser.setLOCK_CNT(userLockCount);
		        			authenticationService.updateUserLockCount(verifyUser);
		        			lockMsg = "\n(로그인 실패 횟수 : " + loginLockCount + ", " + (loginLockCount - userLockCount) + " 회 남음)";
		        		}
		        		ret.put("error", "사용자 정보가 일치하지 않습니다." + lockMsg);
		        	}
	            }
        	}
//        } catch (Exception e) {
//        	e.printStackTrace();
//        	ret.put("error", "ERROR 500");
//        }
        
        out.print(ret);
        out.flush();
        out.close();  
    }
	
	/* 개발자용 */
	@RequestMapping(value = {"/sneakyLogin.do"})
    public void bypassLoginCheck(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		response.setCharacterEncoding("utf-8");
		PrintWriter out = response.getWriter();
		JSONObject ret = new JSONObject();
		
		String id = "admin";
        String password = "Wise1012!@#$";
//		String password = "wise1012";
//		String id = "keris";
//		String password = "keris1012";
        
        // check login limit and duplicate users
//        try {
        	User verifyUser = authenticationService.selectUserById(id);
        	if (verifyUser == null) {
        		ret.put("error", "사용자 정보가 일치하지 않습니다.");
        	} else {
        		ConfigMasterVO config = authenticationService.getConfigMstr();
            	int limitConnections = Integer.parseInt(config.getLIMIT_CONNECTIONS());
        		int userLockCount = verifyUser.getLOCK_CNT();
        		int loginLockCount = Integer.parseInt(config.getLOGIN_LOCK_CNT());
        		int inactiveLimit = Integer.parseInt(config.getUSE_TERM());
        		Integer userInactiveDays = authenticationService.selectUserInactiveDays(verifyUser);
        		if (loginLockCount > 0 && userLockCount >= loginLockCount) {
        			ret.put("error", "로그인 실패수 넘었습니다 (" + loginLockCount + ").\n관리자에게 문의하세요.");
        		}
        		else if (userInactiveDays != null && inactiveLimit > 0 && userInactiveDays >= inactiveLimit) {
        			ret.put("error", "미사용 제한 일자 넘었습니다 (" + inactiveLimit + ").\n관리자에게 문의하세요.");
        		}
	        	else {
	        		/* DOGFOOT cshan SITENM에 따라 로그인 암호화 일부 적용20200211*/
	        		if(config.getSITE_NM() != null && !config.getSITE_NM().equals("")) {
		    			if(config.getLOGIN_EXT() != null && config.getLOGIN_EXT().equalsIgnoreCase("Y")) {
		    				if(config.getUSE_HASH_YN() != null && config.getUSE_HASH_YN().equalsIgnoreCase("Y")) {
		    					switch(config.getHASH_ALGORITHM()) {
		    					case "1": //MD-5
		    						break;
		    					case "2": //SHA1
		    						MessageDigest md_SHA1 = MessageDigest.getInstance("SHA-1");
				    				byte[] SHA1_hash = md_SHA1.digest(password.getBytes());
				    				StringBuffer SHA1_hexString = new StringBuffer();
				    				for(int i=0;i<SHA1_hash.length;i++) {
				    					String hex = Integer.toHexString(0xff&SHA1_hash[i]);
				    					if(hex.length() == 1) SHA1_hexString.append('0');
				    					SHA1_hexString.append(hex);
				    				}
				    				password = SHA1_hexString.toString();
		    						break;
		    					case "3": //SHA256 - java 7
	    							MessageDigest md_SHA256 = MessageDigest.getInstance("SHA-256");
				    				byte[] SHA256_hash = md_SHA256.digest(password.getBytes());
				    				StringBuffer SHA256_hexString = new StringBuffer();
				    				for(int i=0;i<SHA256_hash.length;i++) {
				    					String hex = Integer.toHexString(0xff&SHA256_hash[i]);
				    					if(hex.length() == 1) SHA256_hexString.append('0');
				    					SHA256_hexString.append(hex);
				    				}
				    				password = SHA256_hexString.toString();
		    						break;
		    					case "4"://SHA512 - java 8 
		    						MessageDigest md_SHA512 = MessageDigest.getInstance("SHA-512");
				    				byte[] SHA512_hash = md_SHA512.digest(password.getBytes());
				    				StringBuffer SHA512_hexString = new StringBuffer();
				    				for(int i=0;i<SHA512_hash.length;i++) {
				    					String hex = Integer.toHexString(0xff&SHA512_hash[i]);
				    					if(hex.length() == 1) SHA512_hexString.append('0');
				    					SHA512_hexString.append(hex);
				    				}
				    				password = SHA512_hexString.toString();
		    						break;
		    					case "5": //모름 추후 알아내서 추가해야함
		    						break;
		    					}
		    				}
		    			}
		    		}
	        		User user = authenticationService.selectLoginUser(id, password);
		        	if(user != null) {
		        		verifyUser.setLOCK_CNT(0);
		        		authenticationService.updateUserLockCount(verifyUser);
		        		ret.put("userId", user.getUSER_ID());
		        		// ADMIN/VIEWER 확
		        		String href = "";
						UserGroupVO runMode = this.authenticationService.selectUserGroupRunMode(user);
						if (runMode == null) {
							ret.put("error", "사용자 정보가 일치하지 않습니다.");
						} else if ("ADMIN".equals(runMode.getUSER_RUN_MODE()) || "ADMIN".equals(runMode.getGRP_RUN_MODE())) {
							href = "report/edit.do";
						} else {
							href = "report/viewer.do";
						}
		        		ret.put("href", href);
		        		this.createSession(request, user);
		        	} else {
		        		String lockMsg = "";
		        		if (loginLockCount > 0) {
		        			userLockCount++;
		        			verifyUser.setLOCK_CNT(userLockCount);
		        			authenticationService.updateUserLockCount(verifyUser);
		        			lockMsg = "\n(동시접속 제한수: " + loginLockCount + ", " + (loginLockCount - userLockCount) + " 남음)";
		        		}
		        		ret.put("error", "사용자 정보가 일치하지 않습니다." + lockMsg);
		        	}
	            }
        	}
//        } catch (Exception e) {
//        	e.printStackTrace();
//        	ret.put("error", "ERROR 500");
//        }
        
        out.print(ret);
        out.flush();
        out.close();  
    }
	
	@RequestMapping(value = {"/logout.do"})
	public void logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
		/* DOGFOOT ktkang 유저 로그아웃 로그 및 세션 관리 추가  20200923 */
		String id = SecureUtils.getParameter(request, "id");
		
		User verifyUser = authenticationService.selectUserById(id);
		this.removeSession(request, verifyUser);
		response.sendRedirect(request.getContextPath() + "/login.do");
	}
	
	@RequestMapping(value = {"/trackUserSession.do"})
	public void trackUserSession(HttpServletRequest request, HttpServletResponse response) throws Exception {
		while (request.getSession(false) != null) {
			Thread.sleep(60000);
		}
		PrintWriter out = response.getWriter();
    	JSONObject obj = new JSONObject();
    	obj.put("redirectUrl", request.getContextPath() + "/login.do");
    	out.print(obj);
    	out.flush();
    	out.close();
	}

    @RequestMapping(value = {"/sso.do"})
    public ModelAndView sso(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
    	try {
	    	String redirect = "";
	    	String encUserId = request.getParameter("USER_ID");

	    	int keySize = 128;
	    	String ssoKey = "wiseitech_ftc";
	    	
	    	ConfigMasterVO config = authenticationService.getConfigMstr();
	    	if(config.getSITE_NM() != null || !config.getSITE_NM().equals("")) {
	    		switch(config.getSITE_NM()) {
	    		case "FTC" :
					//공정거래위원회
	    			keySize = 128;
	    			ssoKey = "wiseitech_ftc";
	    			break;
	    		}
	    	}
	    	
	    	if(!ssoKey.equals("")) {
		    	String decUserId = AesCrypto.decrypt(keySize, ssoKey, encUserId);
		        User userInfo = (User) authenticationService.selectUserById(decUserId); 
		        
		        if(userInfo!=null) {
			        userInfo.setLOCK_CNT(0);
			        authenticationService.updateUserLockCount(userInfo);
			    	this.createSession(request, userInfo);
			    	
					boolean grpMode = false;
			        UserGroupVO runMode = this.authenticationService.selectUserGroupRunMode(userInfo);
					if(runMode.getUSER_RUN_MODE() == null || "".equals(runMode.getUSER_RUN_MODE())) {
						grpMode = true;
					}
					if(runMode != null && "ADMIN".equals(runMode.getUSER_RUN_MODE())) {
						redirect = "redirect:/report/edit.do";
					} else if(runMode != null && "ADMIN".equals(runMode.getGRP_RUN_MODE()) && grpMode) {
						redirect = "redirect:/report/edit.do";
					} else {
						redirect = "redirect:/report/viewer.do";
					}
		        }
	    	} else {
	    		throw new Exception();
	    	}

	        return new ModelAndView(redirect);
    	} catch(Exception e) {
    		e.printStackTrace();
    		throw e;
    	}
    }

	@Override
	public void request(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		// TODO Auto-generated method stub
		
	}
}
