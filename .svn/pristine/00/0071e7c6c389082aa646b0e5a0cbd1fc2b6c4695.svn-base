//package com.wise.sso.sample;
//
//import java.io.PrintWriter;
//import java.util.Map;
//
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.RequestMapping;
//
//import com.wise.authn.User;
//import com.wise.context.config.Configurator;
//import com.wise.sso.controller.SsoController;
//
//@Controller
//@RequestMapping(value = "/sso/sample")
//public class SsoSampleController extends SsoController {
//    private static final Logger logger = LoggerFactory.getLogger(SsoSampleController.class);
//    
//    @Override
//    public void request(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
//        SsoSampleAgent ssoAgent = new SsoSampleAgent();
//        ssoAgent.authn(request);
//        
//        PrintWriter out = response.getWriter();
//        out.write("sso authned");
//        out.flush();
//        out.close();
//    }
//
//    @Override
//    public void response(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
//        String encoding = Configurator.getInstance().getConfig("encoding");
//        response.setCharacterEncoding(encoding);
//        response.setContentType("text/html");
//
//        SsoSampleAgent ssoAgent = new SsoSampleAgent();
//        Map<String,String> authnInfo = ssoAgent.getAuthnInfo(request);
//        logger.debug("sso authn info: " + authnInfo);
//        
//        String userid = authnInfo.get("USER_ID");
////        String userid = SecureUtils.getParameter(request, "uid");
//        logger.debug("sso user id>> " + userid);
//        
//        User user = super.authenticationService.getRepositoryUser(userid);
//        logger.debug("User >> " + user);
//        
//        // create session user
//        super.createSession(request, user);
//        
//        logger.debug("created session user >> " + super.getSessionUser(request));
//        
//        PrintWriter out = response.getWriter();
//        out.write(user.toString());
//        out.flush();
//        out.close();
//    }
//}
