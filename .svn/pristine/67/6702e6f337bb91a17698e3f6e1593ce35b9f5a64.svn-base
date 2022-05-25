package com.wise.common.util;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

public class BrowserUtils {
    private static Logger logger = Logger.getLogger(BrowserUtils.class);
    
    public static String getType(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent").toLowerCase();
        logger.debug("user agent : " + userAgent);
        
        /*
         * IE Edge : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240
         * IE11 : Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; SMJB; rv:11.0) like Gecko
         * IE10 : Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)
         * IE9 : Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
         * IE8 : Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)
         * IE7 : Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)
         * chrome : Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36
         * chrome(mobile) : mozilla/5.0 (linux; android 4.4.2; shw-m500w build/kot49h) applewebkit/537.36 (khtml, like gecko) chrome/50.0.2661.89 safari/537.36
         * chrome(mobile) : mozilla/5.0 (ipad; cpu os 9_3_1 like mac os x) applewebkit/601.1 (khtml, like gecko) crios/50.0.2661.95 mobile/13e238 safari/601.1.46
         * FF : Mozilla/5.0 (Windows NT 6.3; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0 
         * safari : Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2
         * safari(mobile) : mozilla/5.0 (linux; u; android 4.4.2; ko-kr; shw-m500w build/kot49h) applewebkit/534.30 (khtml, like gecko) version/4.0 safari/534.30 
         * safari(mobile) : mozilla/5.0 (ipad; cpu os 9_3_1 like mac os x) applewebkit/601.1.46 (khtml, like gecko) version/9.0 mobile/13e238 safari/601.1
         * opera : Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36 OPR/34.0.2036.25
         * vivaldi : Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36 Vivaldi/1.0.435.42  
         */
        String browser;
        if (userAgent.indexOf("edge") > -1) {
            browser = "IEEDGE";
        } 
        else if (userAgent.indexOf("rv:11") > -1) {
            browser = "IE11";
        } 
        else if (userAgent.indexOf("msie 10") > -1) {
            browser = "IE10";
        } 
        else if (userAgent.indexOf("msie 9") > -1) {
            browser = "IE9";
        } 
        else if (userAgent.indexOf("msie 8") > -1) {
            browser = "IE8";
        } 
        else if (userAgent.indexOf("msie 7") > -1) {
            browser = "IE7";
        }
        else if (userAgent.indexOf("chrome") > -1) {
            browser = "CHROME";
        }
        else if (userAgent.indexOf("crios") > -1) {
            browser = "CHROME_MOBILE";
        }
        else if (userAgent.indexOf("firefox") > -1) {
            browser = "FIREFOX";
        }
        else if ((userAgent.indexOf("android") > -1 || userAgent.indexOf("mobile") == -1) && userAgent.indexOf("safari") > -1) {
            browser = "SAFARI";
        }
        else if ((userAgent.indexOf("android") > -1 || userAgent.indexOf("mobile") > -1) && userAgent.indexOf("safari") > -1) {
            browser = "SAFARI_MOBILE";
        }
        else if (userAgent.indexOf("opr") > -1) {
            browser = "OPERA";
        }
        else if (userAgent.indexOf("vivaldi") > -1) {
            browser = "VIVALDI";
        }
        else {
            browser = "OTHER";
        }
        
        return browser;
    }
}
