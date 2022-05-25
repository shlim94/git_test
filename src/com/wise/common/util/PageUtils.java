package com.wise.common.util;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import javaxt.utils.Base64;

/**
 * reportViewser.jsp 로 파라메터를 보낼경우 reportViewer.js 에서 해당 파라메터를 접근가능하게 해주는 class
 * @author jylee
 *
 */
public class PageUtils {
	public static String arrangeParameters(HttpServletRequest request) throws Exception {
        String key;
        String value;
        String paramValues = "";
        
        @SuppressWarnings("rawtypes") 
        Enumeration en = request.getParameterNames();
        while (en.hasMoreElements()) {
            key = CoreUtils.ifNull((String) en.nextElement());
            String encodekey = key;
            
            if(key.indexOf("@")>-1) {
            	encodekey = URLEncoder.encode(key, "UTF-8");
            }

            if (!encodekey.startsWith("%40"))
                continue;
            
//          2020.01.16 mksong 연결보고서 암호화 수정 dogfoot
            value = URLDecoder.decode(new String(Base64.decode(URLDecoder.decode(request.getParameter(key),"UTF-8"))),"UTF-8");
//            if(value != null) {
//            	value = new String(value.getBytes("ISO-8859-1"), "UTF-8");
//            }
            paramValues += "{key:\"" + URLDecoder.decode(key,"UTF-8") + "\", value: \"" + value + "\"},";
        }

        if (paramValues.length() > 0) {
            paramValues = paramValues.substring(0, paramValues.length() - 1);
        }
        return paramValues;
    }
}
