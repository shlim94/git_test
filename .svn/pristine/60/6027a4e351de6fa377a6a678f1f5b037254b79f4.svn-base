package com.wise.common.web.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


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
@RequestMapping(value = "/download")
public class DxGridFileDownloadController {
	private Logger logger = Logger.getLogger(this.getClass());
	
//	@RequestMapping(value = "/grid/excel.do", method = RequestMethod.POST)
//    public void excel(@RequestBody String body) throws Exception {
//        logger.debug("body");
//        logger.debug(body);
//    }
	
	@RequestMapping(value = "/grid/excel.do", method = RequestMethod.POST)
    public void excel(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String contentType = request.getParameter("contentType");
        String fileName = request.getParameter("fileName");
        String data = request.getParameter("data");
        
        logger.debug("contentType: " + contentType);
        logger.debug("fileName: " + fileName);
        logger.debug("data: " + data);
    }
}