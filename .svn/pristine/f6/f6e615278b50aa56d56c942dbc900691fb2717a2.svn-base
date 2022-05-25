package com.wise.context.config;

import java.io.IOException;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

import com.wise.common.util.CoreUtils;

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

public class ApplicationContextListener implements ServletContextListener {
    private Logger logger = Logger.getLogger(this.getClass());
    
    public static boolean CATCH_EXCEPTION = false;
    
	public void contextInitialized(ServletContextEvent event) {
//		try {
		    String applicationContextConfigLocation = (String) event.getServletContext().getInitParameter("applicationContextConfigLocation");
		    
		    if ("".equals(CoreUtils.ifNull(applicationContextConfigLocation))) {
		        applicationContextConfigLocation = Configurator.Constants.APPLICATION_CONFIG_PATH + Configurator.Constants.APPLICATION_CONFIG_XML;
		        this.logger.debug("applicationContextConfigLocation not setted, give it to default(" + applicationContextConfigLocation + ")");
		    }
		    
		    String applicationContextConfigRealLocation = event.getServletContext().getRealPath(applicationContextConfigLocation);
		    String applicationContextRealLocation = event.getServletContext().getRealPath("/");
		    Configurator.getInstance().setApplicationContextRealLocation(applicationContextRealLocation);
		    Configurator.getInstance().setApplicationContextConfigRealLocation(applicationContextConfigRealLocation);
		    this.logger.debug("Application Configuration Real Location : " + Configurator.getInstance().getApplicationContextConfigRealLocation());
		    
			try {
				Configurator.getInstance().load();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ConfigFileNotExistException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SAXException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			this.logger.debug("Application Configurations : " + Configurator.getInstance());
//		} catch (IOException | ConfigFileNotExistException | SAXException e) {
//		    ApplicationContextListener.CATCH_EXCEPTION = true;
//			this.logger.error("exception occur while loading context listener", e);
//		} 
	}
	
	public void contextDestroyed(ServletContextEvent event) {
	}

}
