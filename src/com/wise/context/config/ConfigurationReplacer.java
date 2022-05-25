package com.wise.context.config;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.wise.common.util.CoreUtils;

public class ConfigurationReplacer {
    
    static String replace(String s, Map<String, Object> config) {
        
        s = CoreUtils.ifNull(s);
        String basket;
        
        Pattern p = Pattern.compile("[$]\\{.*?"+ "\\}");
        Matcher m = p.matcher(s);
        
        StringBuffer sb = new StringBuffer();
        
        while (m.find()) {
            basket = m.group();
            basket = basket.replaceAll("[$]\\{", "");
            basket = basket.replaceAll("\\}", "");
            basket = CoreUtils.ifNull((String) config.get(basket), "CAN_NOT_FIND_REPLACEMENT");
            
            m.appendReplacement(sb, basket);
        }
        
        m.appendTail(sb);
        
        return sb.toString();
    }
}
