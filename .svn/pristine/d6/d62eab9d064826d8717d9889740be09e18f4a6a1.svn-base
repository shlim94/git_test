package com.wise.common.message;

import net.sf.json.JSONObject;

public class AjaxMessageConverter {
    private int code;
    private String message;
    
    public AjaxMessageConverter() {
    }
    
    public AjaxMessageConverter(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        json.put("code", this.getCode());
        json.put("message", this.getMessage());
        return json;
    }

    public String toString() {
        String message = "{code:" + this.getCode() + ", message:\"" + this.getMessage() + "\"}";
        return message;
    }
}
