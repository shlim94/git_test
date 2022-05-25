package com.wise.authn.cache;

import java.util.List;

import javax.annotation.Resource;

import jxl.common.Logger;

import org.springframework.stereotype.Service;

import com.wise.authn.ReportCache;
import com.wise.authn.ReportPermission;
import com.wise.authn.User;
import com.wise.authn.dao.AuthenticationDAO;
import com.wise.context.config.Configurator;
import com.wise.ds.repository.UnRegisterdReportException;

@Service("reportAuthenticationManager")
public class ReportPermissionManager {
    private static Logger logger = Logger.getLogger(ReportPermissionManager.class);
    
    private List<ReportPermission> userPermissions;
    private List<ReportPermission> userGroupPermissions;
    private List<ReportCache> reportMasterInfos;
    
//    @Resource(name = "reportDAO")
//    private ReportDAO reportDAO;
    
    @Resource(name = "authenticationDAO")
    private AuthenticationDAO authenticationDAO;
    
    public void setUserPermissions(List<ReportPermission> userPermissions) {
        this.userPermissions = userPermissions;
    }
    public void setUserGroupPermissions(List<ReportPermission> userGroupPermissions) {
        this.userGroupPermissions = userGroupPermissions;
    }
    public void setReportMasterInfos(List<ReportCache> reportMasterInfos) {
        this.reportMasterInfos = reportMasterInfos;
    }
 
    public void clear() {
        this.userPermissions.clear();
        this.userGroupPermissions.clear();
        this.reportMasterInfos.clear();
    }
    
    public void load() {
        boolean cached = Configurator.getInstance().getConfigBooleanValue("wise.ds.authentication.cache");
        if (cached) {
            List<ReportPermission> userPermissionList = this.authenticationDAO.selectUserPermissions();
            this.setUserPermissions(userPermissionList);
            
            List<ReportPermission> userGroupPermissionList = this.authenticationDAO.selectUserGroupPermissions();
            this.setUserGroupPermissions(userGroupPermissionList);
            
            List<ReportCache> reportMasterInfoList = this.authenticationDAO.selectReportCacheList(Configurator.Constants.WISE_REPORT_TYPE);
            this.setReportMasterInfos(reportMasterInfoList);
            
            logger.debug(this.toString());
        }
    }
    
    private ReportCache getReportMasterCache(int reportId) {
        ReportCache cache = null;
        for (ReportCache report : this.reportMasterInfos) {
            if (report.getId() == reportId) {
                cache = report;
                break;
            }
        }
        return cache;
    }
    
    private Object lock = new Object();
    public ReportPermission getReportPermission(User user, int reportId) throws UnRegisterdReportException {
        ReportCache reportMaster;
        
        synchronized(this.lock) {
            reportMaster = this.getReportMasterCache(reportId);
            
            if (reportMaster == null) {
                this.clear();
                this.load();
                
                reportMaster = this.getReportMasterCache(reportId);
                
                if (reportMaster == null) {
                    throw new UnRegisterdReportException("report id>> " + reportId);
                }
            }
        }
        
        ReportPermission permission = null;
        
        if ("PUBLIC".equalsIgnoreCase(reportMaster.getFolderType())) {
            permission = new ReportPermission();
            permission.setPublishYn("Y");
            permission.setViewYn("Y");
            permission.setDataItemYn("Y");
        }
        else if (user.getNo() == reportMaster.getRegUserNo() && "MY".equalsIgnoreCase(reportMaster.getFolderType())) {
            permission = new ReportPermission();
            permission.setPublishYn("Y");
            permission.setViewYn("Y");
            permission.setDataItemYn("Y");
        }
        else {
            for (ReportPermission userPermission : this.userPermissions) {
                if (user.getNo() == userPermission.getId() && userPermission.getFolderId() == reportMaster.getFolderId()) {
                    permission = userPermission;
                    break;
                }
            }
            
            if (permission == null) {
                for (ReportPermission userGroupPermission : this.userGroupPermissions) {
                    if (user.getGid() == userGroupPermission.getId() && userGroupPermission.getFolderId() == reportMaster.getFolderId()) {
                        permission = userGroupPermission;
                        break;
                    }
                }
            }
        }
        
        return permission;
    }

    @Override
    public String toString() {
        return "ReportAuthenticationManager [userAuthns=" + userPermissions + ", userGroupAuthns=" + userGroupPermissions + ", reportMasterInfos="
                + reportMasterInfos + "]";
    }
}
