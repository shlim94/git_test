package com.wise.authn.service.impl;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import jxl.common.Logger;

import org.springframework.stereotype.Service;

import com.wise.context.config.Configurator;
import com.wise.authn.ReportPermission;
import com.wise.authn.User;
import com.wise.authn.UserSessionVO;
import com.wise.authn.WebConfigMasterVO;
import com.wise.authn.cache.ReportPermissionManager;
import com.wise.authn.dao.AuthenticationDAO;
import com.wise.authn.exception.PermissionDeniedReportViewException;
import com.wise.authn.service.AuthenticationService;
import com.wise.authn.ConfigMasterVO;
import com.wise.authn.LoginLogVO;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.UnRegisterdReportException;
import com.wise.authn.UserGroupVO;
import com.wise.ds.repository.dao.ReportDAO;

@Service("authenticationService")
public class AuthenticationServiceImpl implements AuthenticationService {
    private static Logger logger = Logger.getLogger(AuthenticationServiceImpl.class);

    @Resource(name = "authenticationDAO")
    private AuthenticationDAO authenticationDAO;
    
    @Resource(name = "reportDAO")
    private ReportDAO reportDAO;
    
    @Resource(name = "reportAuthenticationManager")
    private ReportPermissionManager reportAuthenticationManager;
    
    @PostConstruct
    public void init() {
        this.reportAuthenticationManager.load();
    }
    
    @Override
    public void authenticate(User sessionUser, int reportId, String reportType) throws UnRegisterdReportException, PermissionDeniedReportViewException {
        ReportPermission permission;
        boolean cached = Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication.cache");
        
        if (cached) {
            permission = this.reportAuthenticationManager.getReportPermission(sessionUser, reportId);
        }
        else {
        	
			ReportMasterVO param = new ReportMasterVO();
			param.setREPORT_ID(String.valueOf(reportId));
			param.setREPORT_TYPE(reportType);
            
			ReportMasterVO report = this.reportDAO.selectReportForLog(param);
			
//			ReportMasterVO report = this.reportDAO.select(param);
            
//			Map<String, Comparable> param = new HashMap<String, Comparable>();
//			param.put("P_PARAM", 0);
//			param.put("REPORT_ID",reportId);
//			param.put("REPORT_TYPE", "DashAny");
//			param.put("FLD_TYPE", "PUBLIC");
//			param.put("FLD_ID", "");
//			param.put("USER_NO", "");
//			ReportMasterVO report = this.reportDAO.select(param);
              
            if (report == null) {
                throw new UnRegisterdReportException();
            }
            
            if (sessionUser.getUSER_NO() == report.getMOD_USER_NO() && "MY".equalsIgnoreCase(report.getFLD_TYPE())) {
                permission = new ReportPermission();
                permission.setPublishYn("Y");
                permission.setViewYn("Y");
                permission.setDataItemYn("Y");
            }
            else {
                permission = this.authenticationDAO.selectUserPermissionByReport(sessionUser.getUSER_NO(), reportId);
                if (permission == null) {
                    permission = this.authenticationDAO.selectUserGroupPermissionByReport(sessionUser.getUSER_NO(), reportId);
                }
            }
        }
        
        if (permission == null) {
            throw new PermissionDeniedReportViewException();
        }
        
        if (!"Y".equalsIgnoreCase(permission.getViewYn())) {
            throw new PermissionDeniedReportViewException();
        }
    }
    
    @Override
    public User getRepositoryUser(String userId) {
        User user;
        String mapperTable = Configurator.getInstance().getConfig("wise.ds.authentication.user.mapper.table");
        
        if ("user_mstr".equals(mapperTable)) {
//            int userNo = Integer.valueOf(userId).intValue();
//            user = this.authenticationDAO.selectRepositoryUserByUserNo(userNo);
            user = this.authenticationDAO.selectRepositoryUserByUserId(userId);
        }
        else {
            user = this.authenticationDAO.selectUserOfMapperTableByUserId(userId);
        }
        
        return user;
    }
    
    @Override
    public ReportPermission selectUserGroupPermissionByReport(int userNo, int reportId) {
    	ReportPermission reportPerm = this.authenticationDAO.selectUserGroupPermissionByReport(userNo, reportId);
    	return reportPerm;
    }
    
    @Override
    public User selectLoginUser(String userId, String password) {
    	User user = this.authenticationDAO.selectLoginUser(userId, password);
    	return user;
    }

	@Override
	public UserSessionVO selectUserSessionLog(User user) {
		return authenticationDAO.selectUserSessionLog(user);
	}

	@Override
	public void insertUserSessionLog(UserSessionVO sessionVo) {
		authenticationDAO.insertUserSessionLog(sessionVo);
	}

	@Override
	public void updateUserSessionLog(UserSessionVO sessionVo) {
		authenticationDAO.updateUserSessionLog(sessionVo);
	}

	@Override
	public ConfigMasterVO getConfigMstr() {
		return authenticationDAO.getConfigMstr();
	}
	
	@Override
	public WebConfigMasterVO getWebConfigMstr() {
		return authenticationDAO.getWebConfigMstr();
	}

	@Override
	public User selectUserById(String id) {
		return authenticationDAO.selectUserById(id);
	}

	@Override
	public User selectUserByNo(int userNo) {
		return authenticationDAO.selectUserByNo(userNo);
	}

	@Override
	public void updateUserLockCount(User user) {
		authenticationDAO.updateUserLockCount(user);
	}

	@Override
	public Integer selectUserInactiveDays(User user) {
		return authenticationDAO.selectUserInactiveDays(user);
	}

	@Override
	public void insertLoginLog(LoginLogVO logVo) {
		authenticationDAO.insertLoginLog(logVo);
	}

	@Override
	public UserGroupVO selectUserGroupRunMode(User user) {
		return authenticationDAO.selectUserGroupRunMode(user);
	}
	
	@Override
	public User getSessionUser(HttpServletRequest request) {
        String SESSINO_USER_PREFIX = Configurator.Constants.SESSION_USER_PREFIX;
        String authnKey = Configurator.getInstance().getConfig("wise.ds.authentication.key", "USER");
        String sessionUserKey = SESSINO_USER_PREFIX + authnKey;
        
        /* DOGFOOT ktkang KERIS 포탈 세션 물고들어오는 부분 제거  20200214 */
        User sessionUser;
        if(request.getSession(false) != null) {
        	sessionUser = (User) request.getSession(false).getAttribute(sessionUserKey);
        } else {
        	sessionUser = null;
        }
        
        return sessionUser;
    }
    
}
