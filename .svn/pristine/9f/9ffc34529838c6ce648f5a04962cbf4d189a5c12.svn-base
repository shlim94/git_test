package com.wise.authn.service;

import com.wise.authn.ReportPermission;
import com.wise.authn.User;
import com.wise.authn.UserSessionVO;
import com.wise.authn.WebConfigMasterVO;
import com.wise.authn.exception.PermissionDeniedReportViewException;
import com.wise.ds.repository.UnRegisterdReportException;
import com.wise.authn.UserGroupVO;

import javax.servlet.http.HttpServletRequest;

import com.wise.authn.ConfigMasterVO;
import com.wise.authn.LoginLogVO;


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

public interface AuthenticationService {
    
    public void authenticate(User sessionUser, int reportId, String reportType) throws UnRegisterdReportException, PermissionDeniedReportViewException;
	
	public User getRepositoryUser(String userId);
	
	public ReportPermission selectUserGroupPermissionByReport(int userNo, int reportId);
	
	public User selectLoginUser(String userId, String password);

	public UserSessionVO selectUserSessionLog(User user);

	public void insertUserSessionLog(UserSessionVO sessionVo);

	public void updateUserSessionLog(UserSessionVO sessionVo);

	public ConfigMasterVO getConfigMstr();
	
	public WebConfigMasterVO getWebConfigMstr();

	public User selectUserById(String id);

	public User selectUserByNo(int userNo);

	public void updateUserLockCount(User user);

	public Integer selectUserInactiveDays(User user);

	public void insertLoginLog(LoginLogVO logVo);
	
	public UserGroupVO selectUserGroupRunMode(User user);
	
	public User getSessionUser(HttpServletRequest request);
}