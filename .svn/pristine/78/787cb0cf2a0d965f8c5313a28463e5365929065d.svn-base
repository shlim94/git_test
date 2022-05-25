package com.wise.ds.repository.dataset;

import java.util.List;

import org.apache.commons.lang.StringUtils;

import javaxt.utils.Date;

import com.wise.context.config.Configurator;
import com.wise.ds.repository.UndefinedDataTypeForNullValueException;

public class JavaxtUtils {
    public static Object getValue(javaxt.sql.Field field) throws UndefinedDataTypeForNullValueException {
        Object value = null;
        String type = field.getType();
        List<String> stringTypes = Configurator.getInstance().getListConfig("wise.ds.database.data.type.string");
        List<String> integerTypes = Configurator.getInstance().getListConfig("wise.ds.database.data.type.integer");
        
        if (field.getValue().isNull()) {
            for (String string : stringTypes) {
                if (type.equalsIgnoreCase(string)) {
                    value = "";
                    break;
                }
            }
            if (value != null) return value;
            
            for (String integer : integerTypes) {
                if (type.equalsIgnoreCase(integer)) {
                    value = 0;
                    break;
                }
            }
            if (value != null) return value;
            
            if (value == null) {
                String message = "";
                message += "found data type of [" + type + "] for null value";
                message += ", add [" + type + "] type to web-application.xml";
                throw new UndefinedDataTypeForNullValueException(message);
            }
        }
        else {
            if ("datetime".equalsIgnoreCase(type) || "date".equalsIgnoreCase(type) ) {
                Date date = field.getValue().toDate();
                String dateStr = "";
                dateStr += date.getYear() + ".";
                /*DOGFOOT cshan 20200113 - datetime 조회하면 월 값의 +1이 되는 오류 수정*/
//                dateStr += StringUtils.leftPad(String.valueOf(date.getMonth()+1), 2, "0") + ".";
                dateStr += StringUtils.leftPad(String.valueOf(date.getMonth()), 2, "0") + ".";
                dateStr += StringUtils.leftPad(String.valueOf(date.getDay()), 2, "0") + " ";
                dateStr += StringUtils.leftPad(String.valueOf(date.getHour()), 2, "0") + ":";
                dateStr += StringUtils.leftPad(String.valueOf(date.getMinute()), 2, "0") + ":";
                dateStr += StringUtils.leftPad(String.valueOf(date.getSecond()), 2, "0");
                
                value = dateStr;
            }
            else {
                value = field.getValue().toObject();
            }
            
            /* 특수문자 필터링 */
            /*for (String string : stringTypes) {
                if (type.equalsIgnoreCase(string)) {
                    value = ((String)value).replaceAll("\\,"," ");
                    value = ((String)value).replaceAll("\'","-");
                    value = ((String)value).replaceAll("\",","-");
                    value = ((String)value).replaceAll("\\(","[");
                    value = ((String)value).replaceAll("\\)","]");
                    break;
                }
            }*/
            
        }
        
        return value;
    }
}
