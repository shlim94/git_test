package com.wise.context.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wise.common.util.CoreUtils;

public class DefaultConfigurationValues {
    private Map<String, String> stringDefaults;
    private Map<String, List<String>> listDefaults;
    
    DefaultConfigurationValues() {
        this.stringDefaults = new HashMap<String, String>();
        this.listDefaults = new HashMap<String, List<String>>();
        
        this.initStringDefaults();
        this.initListDefaults();
    }
    
    private void initStringDefaults() {
        this.stringDefaults.put("encoding", "utf-8");
        this.stringDefaults.put("wise.ds.authentication.user.mapper.table", "user_mstr");
    }
    private void initListDefaults() {
        List<String> defaultDenyBrowser = new ArrayList<String>();
        defaultDenyBrowser.add("IE7");
        defaultDenyBrowser.add("IE8");
        
        this.listDefaults.put("wise.ds.deny.browser", defaultDenyBrowser);
    }
    
    String getStringDefaultValue(String key) {
        return CoreUtils.ifNull(this.stringDefaults.get(key));
    }
    
    List<String> getListDefaultValue(String key) {
        List<String> dephault = this.listDefaults.get(key);
        if (dephault == null) {
            dephault = new ArrayList<String>();
        }
        return dephault;
    }
}
