package com.wise.common.web.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.wise.common.message.WiseMessageSource;
import com.wise.common.secure.SecureUtils;
import com.wise.common.util.BrowserUtils;
import com.wise.context.config.Configurator;

import net.sf.json.JSONObject;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 * 
 *     수정일         수정자               수정내용
 *  --------------    ------------    ---------------------------
 *  2015.06.08        DOGFOOT              최초 생성
 * </pre>
 */

@Controller
@RequestMapping(value = "/js")
public class JavascriptController {
	private Logger logger = Logger.getLogger(this.getClass());
	
	@Resource(name = "wiseMessageSource")
    private WiseMessageSource messageSource;
	
	/*@RequestMapping(value = "/{pid}/WISE.common.js", method = RequestMethod.GET)
    public void common(HttpServletRequest request, HttpServletResponse response, @PathVariable("pid") String pid) throws Exception {*/
	@RequestMapping(value = "/WISE.common.js", method = RequestMethod.GET)
    public void common(HttpServletRequest request, HttpServletResponse response) throws Exception {
	    String encoding = Configurator.getInstance().getConfig("encoding");
        response.setCharacterEncoding(encoding);
        response.setContentType("application/javascript");
        
        String pageId = (String) SecureUtils.getParameter(request, "pid");
//        String pageId = (String) SecureUtils.secure(pid);
             
        String contextPath = request.getSession().getServletContext().getContextPath();
        String script = "WISE.namespace('WISE.Constants');";
        script += "WISE.Constants.conditions = [];";
        script += "WISE.Constants.domain='" + Configurator.getInstance().getFullDomain(request)  + "';";
        script += "WISE.Constants.context='" + contextPath + "';";
        script += "WISE.Constants.browser='" + BrowserUtils.getType(request) + "';";
        script += "WISE.Constants.pid='" + pageId + "';";
        //script += "WISE.Constants.shapeLocation='" + Configurator.Constants.WISE_REPORT_SHAPEFILE_LOCATION + "';";
        
        // UI Config
//        script += "WISE.libs.Dashboard.MessageHandler.showMessage=" + Configurator.getInstance().getConfigBooleanValue("WISE.libs.Dashboard.MessageHandler.showMessage", false) + ";";
//        script += "WISE.libs.Dashboard.MessageHandler.type='" + Configurator.getInstance().getConfig("WISE.libs.Dashboard.MessageHandler.type", "toast") + "';";
        
        Object configValue;
        Set<String> configKeySet = Configurator.getInstance().getConfigKeySet();
        for (String configKey : configKeySet) {
            if (configKey.indexOf("WISE.libs.Dashboard.Config") == 0) {
                configValue = Configurator.getInstance().getConfigObjectValue(configKey);
                
                script += configKey + "=";
                
                if (configValue instanceof List) {
                    script += "[";
                    String listValueScript = "";
                    for (String listValue : (List<String>)configValue) {
                        try {
                            Double.valueOf(listValue);
                            listValueScript += listValue + ",";
                        } catch (NumberFormatException e) {
                            listValueScript += "'" + listValue + "',";
                        }
                    }
                    if (listValueScript.length() > 0) {
                        listValueScript = listValueScript.substring(0, listValueScript.length() - 1);
                    }
                    script += listValueScript;
//                    script += StringUtils.join((List<String>)configValue, ",");
                    script += "]";
                }
                else {
                    try {
                        script += Configurator.getInstance().getConfigIntValue(configKey);
                    } catch(Exception e) {
                        if ("false".equalsIgnoreCase((String)configValue) || "true".equalsIgnoreCase((String)configValue)) {
                            script += Configurator.getInstance().getConfigBooleanValue(configKey);
                        }
                        else {
                            script += "'" + configValue + "'";
                        }
                    }
                }
                
                script += ";";
            }
        }
        
        PrintWriter out = response.getWriter();
        out.write(script);
        
        out.flush();
        out.close();
    }
	
	@RequestMapping(value = "/WISE.i18n.js", method = RequestMethod.GET)
    public void i18n(HttpServletRequest request, HttpServletResponse response) throws Exception {
	    String encoding = Configurator.getInstance().getConfig("encoding");
        response.setCharacterEncoding(encoding);
        response.setContentType("application/javascript");
        
        Properties prop = new Properties();
        InputStream input = null;
        InputStream input2 = null;
     
        try {
            String path = request.getSession().getServletContext().getRealPath("/WEB-INF/config/message");
            File propFile = new File(path, "message-page_ko.properties");
            File propFile2 = new File(path, "message-config_ko.properties");
            
            if (!propFile.exists()) {
                propFile = new File(path, "message-page_ko_KR.properties");
            }
            
            if (!propFile2.exists()) {
                propFile2 = new File(path, "message-config_ko_KR.properties");
            }
            
            input = new FileInputStream(propFile);
            input2 = new FileInputStream(propFile2);
     
            prop.load(input);
            prop.load(input2);
            
        } catch (IOException ex) {
            this.logger.error("JavascriptController#i18n", ex);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (input2 != null) {
                try {
                    input2.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        
        String script = "WISE.namespace('WISE.i18n.message');";
        
        for (Object key : prop.keySet()) {
            script += "WISE.i18n.message['" + key + "'] = '" + this.messageSource.getMessage((String)key) + "';";
        }
        
        this.logger.debug("added i18n - " + script);
        
        PrintWriter out = response.getWriter();
        out.write(script);
        
        out.flush();
        out.close();
    }
	/* dogfoot 
	 * WISE.Common.js , WISE.i18n.js
	 * 스크립트 생성 하지않고 필요 데이터 가져오는 부분 
	 *  shlim 20201124*/
	@RequestMapping(value = {"/getConstants.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getConstantsData(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		String encoding = Configurator.getInstance().getConfig("encoding");
        response.setContentType("application/javascript");
        
        JSONObject returnObj = new JSONObject();
        
//        String pageId = (String) SecureUtils.getParameter(request, "pid");
//        String pageId = (String) SecureUtils.secure(pid);
        
        String contextPath = request.getSession().getServletContext().getContextPath();
        
        returnObj.put("domain", Configurator.getInstance().getFullDomain(request));
        returnObj.put("context", contextPath);
        returnObj.put("browser", BrowserUtils.getType(request));
        
        
        Object configValue;
        Set<String> configKeySet = Configurator.getInstance().getConfigKeySet();
        for (String configKey : configKeySet) {
            if (configKey.indexOf("WISE.libs.Dashboard.Config") == 0) {
                configValue = Configurator.getInstance().getConfigObjectValue(configKey);
                
                if (configValue instanceof List) {
                    String listValueScript = "";
                    for (String listValue : (List<String>)configValue) {
                        try {
                            Double.valueOf(listValue);
                            listValueScript += listValue + ",";
                        } catch (NumberFormatException e) {
                            listValueScript += "'" + listValue + "',";
                        }
                    }
                    if (listValueScript.length() > 0) {
                        listValueScript = listValueScript.substring(0, listValueScript.length() - 1);
                    }
                    
                    returnObj.put(configKey, listValueScript);
                }
                else {
                    try {
                        returnObj.put(configKey, Configurator.getInstance().getConfigIntValue(configKey));
                    } catch(Exception e) {
                        if ("false".equalsIgnoreCase((String)configValue) || "true".equalsIgnoreCase((String)configValue)) {
                            returnObj.put(configKey, Configurator.getInstance().getConfigBooleanValue(configKey));
                        }
                        else {
                            returnObj.put(configKey, configValue);
                        }
                    }
                }
            }
        }
        
        return returnObj;
	}
	
	@RequestMapping(value = {"/getI18n.do"}, method = RequestMethod.POST)
	public @ResponseBody JSONObject getI18nData(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		 String encoding = Configurator.getInstance().getConfig("encoding");
	        response.setCharacterEncoding(encoding);
	        response.setContentType("application/javascript");
	        
	        JSONObject returnObj = new JSONObject();
	        
	        Properties prop = new Properties();
	        InputStream input = null;
	        InputStream input2 = null;
	     
	        try {
	            String path = request.getSession().getServletContext().getRealPath("/WEB-INF/config/message");
	            File propFile = new File(path, "message-page_ko.properties");
	            File propFile2 = new File(path, "message-config_ko.properties");
	            
	            if (!propFile.exists()) {
	                propFile = new File(path, "message-page_ko_KR.properties");
	            }
	            
	            if (!propFile2.exists()) {
	                propFile2 = new File(path, "message-config_ko_KR.properties");
	            }
	            
	            input = new FileInputStream(propFile);
	            input2 = new FileInputStream(propFile2);
	     
	            prop.load(input);
	            prop.load(input2);
	            
	        } catch (IOException ex) {
	            this.logger.error("JavascriptController#i18n", ex);
	        } finally {
	            if (input != null) {
	                try {
	                    input.close();
	                } catch (IOException e) {
	                    e.printStackTrace();
	                }
	            }
	            if (input2 != null) {
	                try {
	                    input2.close();
	                } catch (IOException e) {
	                    e.printStackTrace();
	                }
	            }
	        }
	        
	        for (Object key : prop.keySet()) {
	            returnObj.put(key, this.messageSource.getMessage((String)key));
	        }
        
        return returnObj;
	}
	
}