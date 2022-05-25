package com.wise.context.controller;

import java.io.PrintWriter;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONObject;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.View;

import com.wise.common.secure.SecureUtils;
import com.wise.context.config.Configurator;
//import com.wise.authn.cache.ReportPermissionManager;

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
@RequestMapping(value = "/config")
public class ConfigureController {
	private Logger logger = Logger.getLogger(this.getClass());
	
	@Resource(name = "printWriterView")
    private View printWriterView;
	
	@RequestMapping(value = "/reload.do")
	public void reload(HttpServletRequest request, HttpServletResponse response) throws Exception {
	    response.setCharacterEncoding("utf-8");
	    response.setContentType("text/html");
	    
	    Configurator.getInstance().clear();
	    Configurator.getInstance().load();
	    
	    this.logger.debug("Configurations : " + Configurator.getInstance());
	    this.logger.debug("config reload successfully");
	    
	    PrintWriter out = response.getWriter();
	    out.print("config reload successfully<br/>============================================================================<br/>");
	    out.print("Configurations : " + Configurator.getInstance().toString());
	    out.flush();
	    out.close();
	}
	
	@RequestMapping(value = "/get/json.do")
	public @ResponseBody JSONObject getConfigByJSON(HttpServletRequest request, HttpServletResponse response) throws Exception {
	    String encoding = Configurator.getInstance().getConfig("encoding");
        response.setCharacterEncoding(encoding);
        response.setContentType("application/javascript");
        
	    String configId = SecureUtils.getParameter(request, "cid");
	    Object configure = Configurator.getInstance().getConfigObjectValue(configId);
	    
	    JSONObject json = new JSONObject();
	    json.put(configId, configure);
	    
	    return json;
	}
	
//    // @Scheduled(cron = "* * * * * *")
//    @Scheduled(fixedDelay = 30000)
//    @RequestMapping(value = "/reload.do")
//    public void reload() throws Exception {
//
//        Configurator.getInstance().clear();
//        Configurator.getInstance().load();
//
//        this.logger.debug("Configurations : " + Configurator.getInstance());
//        this.logger.debug("config reload successfully");
//
//        System.out.print("config reload successfully<br>============================================================================");
//        System.out.print("Configurations : " + Configurator.getInstance().toString());
//    }
}