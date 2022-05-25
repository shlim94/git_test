package com.wise.common.util;

import java.util.Random;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

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

final public class CoreUtils {

	public static String ifNull(String value) {
        return CoreUtils.ifNull(value, "");
    }
	
	public static String ifNull(JSONObject json, String key) {
		String value = json.containsKey(key) ? CoreUtils.ifNull(json.getString(key)) : "";
		return value;
	}

    public static String ifNull(String value, String dephault) {
        return value == null || "".equals(value.trim()) || "null".equalsIgnoreCase(value.toLowerCase()) ? dephault : value.trim();
    }

    public static String lpad(String str, int len, String addStr) {
        String result = str;
        int templen = len - result.length();

        for (int i = 0; i < templen; i++) {
            result = addStr + result;
        }

        return result;
    }

    public static String rpad(String str, int len, String addStr) {
        String result = str;
        int templen = len - result.length();

        for (int i = 0; i < templen; i++) {
            result = result + addStr;
        }

        return result;
    }

    public static boolean isRequestMethod(HttpServletRequest request, String method) {
        String m = request.getMethod();
        return m.equalsIgnoreCase(method);
    }

    public static String getRandom(int round) {
        int a1;
        Random random = new Random();
        StringBuffer buff = new StringBuffer();

        for (int i = 0; i < round; i++) {
            a1 = Math.abs(random.nextInt() % 10);
            buff.append(a1);
        }

        return buff.toString();
    }
    
    public static boolean isAjaxRequest(HttpServletRequest request) {
        String ajaxHeader = request.getHeader("x-requested-with");
        return "XMLHttpRequest".equals(ajaxHeader) ? true : false;
    }
    
    public static boolean checkOnlyNumInString(String s) {
        char tmp;
            for (int i =0; i<s.length(); i++){
                tmp = s.charAt(i);
                if(Character.isDigit(tmp)==false){
                    return false;
                }
            }
        return true;
    }
    public static HttpServletRequest getCurrentRequest() {
    	ServletRequestAttributes sra = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
    	HttpServletRequest servletRequest = sra.getRequest();
    	
    	return servletRequest;
    }
}
