package com.wise.common.secure;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.web.context.request.AbstractRequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

import com.wise.common.secure.SEED;
import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;

final public class SecureUtils {

    public static Object secure(Object param) {
        if (param == null) {
            param = "";
        } else {
            if (param instanceof String) {
                String paramStr = (String) param;

                paramStr = paramStr.replaceAll("&", "&amp;");
                paramStr = paramStr.replaceAll("\"", "&quot;");
                paramStr = paramStr.replaceAll("<", "&lt;");
                paramStr = paramStr.replaceAll(">", "&gt;");
                paramStr = paramStr.replaceAll("'", "&#39;");
//                paramStr = paramStr.replaceAll("[.][.]/", "");
//                paramStr = paramStr.replaceAll("[.]/", "");
                paramStr = paramStr.replaceAll("%2F", "");

                param = paramStr;
            }
        }

        return param;
    }

    public static String unsecure(String secured) {
        if (secured == null) {
            secured = "";
        } else {
            secured = secured.replaceAll("&lt;", "<");
            secured = secured.replaceAll("&gt;", ">");
            secured = secured.replaceAll("&amp;", "&");
            secured = secured.replaceAll("&quot;", "\"");
            secured = secured.replaceAll("&#39;", "'");
        }
        
        secured = secured.replaceAll("&", "");

        return secured;
    }
    
    public static String sqlsecure(String secured) {
        if (secured == null) {
            secured = "";
        } else {
            secured = secured.replaceAll("-", "");
            secured = secured.replaceAll("'", "");
            secured = secured.replaceAll("/*", "");
            secured = secured.replaceAll("\"", "");
            secured = secured.replaceAll("\\?", "");
            secured = secured.replaceAll("#", "");
            secured = secured.replaceAll("\\(", "");
            secured = secured.replaceAll("\\)", "");
            secured = secured.replaceAll(";", "");
            secured = secured.replaceAll("@", "");
            secured = secured.replaceAll("=", "");
            secured = secured.replaceAll("\\*", "");
            secured = secured.replaceAll("\\+", "");
            secured = secured.replaceAll("union", "");
            secured = secured.replaceAll("select", "");
            secured = secured.replaceAll("drop", "");
            secured = secured.replaceAll("update", "");
            secured = secured.replaceAll("select", "");
            secured = secured.replaceAll("from", "");
            secured = secured.replaceAll("where", "");
            secured = secured.replaceAll("join", "");
            secured = secured.replaceAll("substr", "");
            secured = secured.replaceAll("user_tables", "");
            secured = secured.replaceAll("user_table_columns", "");
            secured = secured.replaceAll("information_schema", "");
            secured = secured.replaceAll("sysobject", "");
            secured = secured.replaceAll("table_schema", "");
            secured = secured.replaceAll("declare", "");
            
        }
        
        secured = secured.replaceAll("&", "");

        return secured;
    }

    public static String getParameter(HttpServletRequest request, String param) {
        return SecureUtils.getParameter(request, param, "1001");
    }

    public static String getParameter(HttpServletRequest request, String param, String dephault) {
        String value;
        Map<String, String[]> securedParams = SecureUtils.getParameters(request);

        if (securedParams.containsKey(param)) {
            value = ((String[]) securedParams.get(param))[0];
            value = value.trim();
            if (dephault == null && "".equals(value)) {
                value = null;
            }
        } else {
            value = dephault;
        }

        return value;
    }

    /**
     * 크로스 사이트 스크립트(XSS) 보안
     * 
     * @param http
     *            request
     * @return 보안된 파라메터를 담은 Map
     */
    public static Map<String, String[]> getParameters(HttpServletRequest request) {
        String key = null;
        String[] values = null;
        Map<String, String[]> securedParamMap = new HashMap<String, String[]>();

        @SuppressWarnings("unchecked")
        Enumeration<String> keyset = request.getParameterNames();

        for (; keyset.hasMoreElements();) {
            key = keyset.nextElement();
            values = request.getParameterValues(key);

            String[] securedParamValues = new String[values.length];

            for (int i = 0; i < securedParamValues.length; i++) {
                securedParamValues[i] = (String) SecureUtils.secure(values[i]);
                // securedParamValues[i] = SecureUtils.secure(((String[]) values)[i]);
            }

            securedParamMap.put(key, securedParamValues);
        }

        return securedParamMap;
    }

    public static JSONObject getJSONObjectParameter(HttpServletRequest request, String paramName) {
    	// 고용정보원09 jhseo param에 적혀있는 sql문 디코딩
    	String paramVal = request.getParameter(paramName);
    	
    	if (!StringUtils.startsWith(StringUtils.trim(paramVal), "{") && paramVal != null) {
    		paramVal = new String(Base64.decode(paramVal));
    	}
        JSONObject json = JSONObject.fromObject(paramVal);

        return SecureUtils.getJSONObjectParameter(json);
    }

    public static JSONObject getJSONObjectParameter(JSONObject json) {
        JSONObject secured = new JSONObject();
        Object[] keys = json.keySet().toArray();

        for (int index = 0; index < keys.length; index++) {
            secured.put(keys[index], SecureUtils.secure(json.get(keys[index])));
            // secured.put(keys[index], SecureUtils.secure((String) json.get(keys[index])));
        }

        return secured;
    }

    public static JSONArray getJSONArrayParameter(HttpServletRequest request, String param) {
        String paramVal = request.getParameter(param);
        JSONArray jsonArray = JSONArray.fromObject(paramVal);

        return SecureUtils.getJSONArrayParameter(jsonArray);
    }

    public static JSONArray getJSONArrayParameter(JSONArray jsonArray) {
        JSONArray secured = new JSONArray();

        for (int index = 0; index < jsonArray.size(); index++) {
            secured.add(index, SecureUtils.getJSONObjectParameter(jsonArray.getJSONObject(index)));
        }

        return secured;
    }

    public static String getHeader(HttpServletRequest request, String headerName) {
        return SecureUtils.getHeader(request, headerName, "");
    }

    public static String getHeader(HttpServletRequest request, String headerName, String dephault) {
        String header = request.getHeader(headerName);
        header = (String) SecureUtils.secure(header);

        if (header == null || "".equals(header)) {
            header = dephault;
        }

        return header;
    }

    public static String encode(String qwer, int round) {
        qwer += CoreUtils.getRandom(3);

        for (int index = 0; index < round; index++) {
            qwer = new String(Base64.encode(qwer.getBytes()));
        }

        String t1 = qwer.substring(0, 4);
        String t2 = qwer.substring(4);

        String[] caret = new String[] { "p", "v", "o", "@", "b", "q", "3", "$", "n", "0" };
        int chip = Integer.valueOf(CoreUtils.getRandom(1));
        if(chip < 0) {
        	return "";
        }
        qwer = t1 + caret[chip] + t2;
        qwer = new String(Base64.encode(qwer.getBytes()));

        return qwer;
    }

    public static String decode(String qwer, int round) {
        qwer = new String(Base64.decode(qwer.getBytes()));

        String t1 = qwer.substring(0, 4);
        String t2 = qwer.substring(5);

        qwer = t1 + t2;

        for (int index = 0; index < round; index++) {
            qwer = new String(Base64.decode(qwer.getBytes()));
        }

        qwer = qwer.substring(0, qwer.length() - 3);

        return qwer;
    }

//    public static String sha256(String plain) throws UnsupportedEncodingException, NoSuchAlgorithmException {
//        String encoding = Configurator.getInstance().getConfig("encoding");
//        
//        MessageDigest digest = MessageDigest.getInstance("SHA-256");
//        byte[] hash = digest.digest(plain.getBytes(encoding));
//
//        return new String(Base64.encode(hash));
//    }
    
    public static String encSeed(String key, String plain) throws UnsupportedEncodingException {
        key = SecureUtils.decode(key, Configurator.Constants.SEED_CBC_ENCRIPTION_KEY_ROUND);
        
        int[] seedKey = SEED.getSeedRoundKey(key);
        String cipher = SEED.getSeedEncrypt(plain, seedKey);
        
        return cipher;
    }
    
    public static String decSeed(String key, String cipher) throws UnsupportedEncodingException {
        key = SecureUtils.decode(key, Configurator.Constants.SEED_CBC_ENCRIPTION_KEY_ROUND);
        
        int[] seedKey = SEED.getSeedRoundKey(key);
        String palin = SEED.getSeedDecrypt(cipher, seedKey);
        
        return palin;
    }
    
//    //CSRF 체크 2021-06-22
//    public static Boolean checkCSRF(HttpServletRequest req, HttpServletResponse res) throws UnsupportedEncodingException{
//        // 쿠키로 전달된 CSRF 토큰 값
//    	String cookieToken = null;
//    	String paramToken = req.getHeader("_csrf");
//    	for(javax.servlet.http.Cookie cookie : req.getCookies()) {
//    		if("CSRF_TOKEN".equals(cookie.getName())) {
//    			cookieToken = URLDecoder.decode(cookie.getValue(), "UTF-8");
//    			//재사용 불가능하도록 쿠키 만료
//    			cookie.setPath("/");
//    			cookie.setValue("");
//    			cookie.setMaxAge(0);
//    			res.addCookie(cookie);
//    			
//    			break;
//    		}
//    	}
//        if(cookieToken.equals(paramToken)) {
//        	return true;
//        }
//        else {
//        	return false;
//        }
//    }
    
}
