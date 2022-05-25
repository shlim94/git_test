package com.wise.authn.dao;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Repository;

import com.wise.authn.ReportCache;
import com.wise.authn.ReportDataPermission;
import com.wise.authn.ReportPermission;
import com.wise.authn.User;
import com.wise.authn.UserSessionVO;
import com.wise.authn.WebConfigMasterVO;
import com.wise.common.jdbc.SqlSessionDaoSupport;
import com.wise.context.config.Configurator;
import com.wise.authn.UserGroupVO;
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

@Repository("authenticationDAO")
public class AuthenticationDAO extends SqlSessionDaoSupport {

    public List<ReportCache> selectReportCacheList(String type) {
        List<ReportCache> result = super.getSqlSession().selectList("Report.selectReportCacheList", type);
        return result;
    }
    
    public User selectRepositoryUserByUserNo(int userNo) {
        User result = super.getSqlSession().selectOne("Authn.selectRepositoryUserByUserNo", userNo);
        return result;
    }
    public User selectRepositoryUserByUserId(String userId) {
        User result = super.getSqlSession().selectOne("Authn.selectRepositoryUserByUserId", userId);
        return result;
    }
    
    public User selectUserOfMapperTableByUserId(String userId) {
        String mapperTable = Configurator.getInstance().getConfig("wise.ds.authentication.user.mapper.table");
        String sourceColumn = Configurator.getInstance().getConfig("wise.ds.authentication.user.mapper.column.source", "user_id");
        String targetColumn = Configurator.getInstance().getConfig("wise.ds.authentication.user.mapper.column.target", "user_no");
        
        Map<String,Object> parameter = new HashMap<String,Object>();
        parameter.put("TABLE_NAME", mapperTable.toUpperCase());
        parameter.put("SOURCE_COLUMN", sourceColumn.toUpperCase());
        parameter.put("TARGET_COLUMN", targetColumn.toUpperCase());
        parameter.put("userId", userId);
        
        User result = super.getSqlSession().selectOne("Authn.selectUserOfMapperTable", parameter);
        return result;
    }
    
    public List<ReportPermission> selectUserPermissions() {
        List<ReportPermission> result = super.getSqlSession().selectList("Authn.selectUserPermissions");
        return result;
    }
    
    public List<ReportPermission> selectUserGroupPermissions() {
        List<ReportPermission> result = super.getSqlSession().selectList("Authn.selectUserGroupPermissions");
        return result;
    }
    
    public ReportPermission selectUserPermissionByReport(int userNo, int reportId) {
        Map<String,Integer> parameter = new HashMap<String,Integer>();
        parameter.put("USER_NO", userNo);
        parameter.put("REPORT_ID", Integer.valueOf(reportId));
        
        ReportPermission result = super.getSqlSession().selectOne("Authn.selectUserPermissionByReport", parameter);
        return result;
    }
    
    public ReportPermission selectUserGroupPermissionByReport(int userNo, int reportId) {
        Map<String,Integer> parameter = new HashMap<String,Integer>();
        parameter.put("USER_NO", Integer.valueOf(userNo));
        parameter.put("REPORT_ID", Integer.valueOf(reportId));
        
        ReportPermission result = super.getSqlSession().selectOne("Authn.selectUserGroupPermissionByReport", parameter);
        return result;
    }
    
    public ReportDataPermission selectDataAuthnByUser(int userNo) {
        return super.getSqlSession().selectOne("Authn.selectDataAuthnByUser", userNo);
    }
    public ReportDataPermission selectDataAuthnByUserGroup(int userGroupId) {
        return super.getSqlSession().selectOne("Authn.selectDataAuthnByUserGroup", userGroupId);
    }
    
    public User selectLoginUser(String userId, String password) {
    	Map<String,String> parameter = new HashMap<String,String>();
        parameter.put("USER_ID", userId);
        parameter.put("PASSWORD", password);
    	return super.getSqlSession().selectOne("Authn.selectLoginUser", parameter);
    }

	public UserSessionVO selectUserSessionLog(User user) {
		return super.getSqlSession().selectOne("Authn.selectUserSessionLog", user);
	}

	public void insertUserSessionLog(UserSessionVO sessionVo) {
		super.getSqlSession().insert("Authn.insertUserSessionLog", sessionVo);
	}

	public void updateUserSessionLog(UserSessionVO sessionVo) {
		super.getSqlSession().update("Authn.updateUserSessionLog", sessionVo);
	}

	public ConfigMasterVO getConfigMstr() {
		return super.getSqlSession().selectOne("Authn.UP_CONFIG_MSTR");
	}
	
	public WebConfigMasterVO getWebConfigMstr() {
		return super.getSqlSession().selectOne("Authn.UP_WB_CONFIG_MSTR");
	}

	public User selectUserById(String id) {
		return super.getSqlSession().selectOne("Authn.selectUserById", id);
	}

	public void updateUserLockCount(User user) {
		super.getSqlSession().update("Authn.updateUserLockCount", user);
	}

	public Integer selectUserInactiveDays(User user) {
		return super.getSqlSession().selectOne("Authn.selectUserInactiveDays", user);
	}

	public User selectUserByNo(int userNo) {
		return super.getSqlSession().selectOne("Authn.selectUserByNo", userNo);
	}

	public void insertLoginLog(LoginLogVO logVo) {
		super.getSqlSession().insert("Authn.insertLoginLog", logVo);
	}

	public UserGroupVO selectUserGroupRunMode(User user) {
		return super.getSqlSession().selectOne("Authn.selectUserGroupRunMode", user);
	}
}
