package com.wise.authn.controller;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.View;

import com.wise.authn.cache.ReportPermissionManager;

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
@RequestMapping(value = "/authn")
public class AuthnController {
	private Logger logger = Logger.getLogger(this.getClass());
	
	@Resource(name = "printWriterView")
    private View printWriterView;
	
	@Resource(name = "reportAuthenticationManager")
    private ReportPermissionManager reportAuthenticationManager;

	@RequestMapping(value = "/reload.do")
	public void reload(HttpServletRequest request, HttpServletResponse response) throws Exception {
	    response.setCharacterEncoding("utf-8");
	    
	    this.reportAuthenticationManager.clear();
	    this.reportAuthenticationManager.load();
	    
	}
}