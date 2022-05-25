package com.wise.common.web.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 *      <pre>
 * << 개정이력(Modification Information) >>
 * 
 *     수정일         수정자               수정내용
 *  --------------    ------------    ---------------------------
 *  2015.06.08        DOGFOOT              최초 생성
 * </pre>
 */

@Controller
@RequestMapping(value = "/error")
public class ExceptionController {
    private Logger logger = Logger.getLogger(this.getClass());

    @RequestMapping(value = "/404.do")
    public String e404(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return "errors/404";
    }

    @RequestMapping(value = "/500.do")
    public String e500(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return "errors/500";
    }

    @RequestMapping(value = "/session/expired.do")
    public String sessionExpire(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return "errors/sessionExpired";
    }

    @RequestMapping(value = "/invalid/request.do")
    public String invalidRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return "errors/invalidRequest";
    }
    
    @RequestMapping(value = "/invalid/user.do")
    public String invalidUser(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return "errors/invalidUser";
    }
    
    @RequestMapping(value = "/not/found/report.do")
    public String notFoundReport(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return "errors/notFoundReport";
    }
    
    @RequestMapping(value = "/no/permission/report.do")
    public String noViewPermissionReport(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return "errors/reportPermissionDenied";
    }
    
    @RequestMapping(value = "/common.do")
    public String ajax(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return "errors/commonError";
    }
}