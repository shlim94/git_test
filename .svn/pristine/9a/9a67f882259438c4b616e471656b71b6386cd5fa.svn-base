package com.wise.context.config;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.digester3.Digester;
import org.apache.commons.lang.StringUtils;
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
 *     수정일                 수정자             수정내용   
 *  ----------    --------    ---------------------------
 *  2015.06.08      DOGFOOT             최초 생성
 * </pre>
 */

public class Configurator {
    private Logger logger = Logger.getLogger(this.getClass());

    private static Configurator instance;

    private String applicationContextConfigRealLocation;
    
    private String applicationContextRealLocation;
    
    private Map<String, Object> configs = new HashMap<String, Object>();

    private Configurator() {
    }

    public static Configurator getInstance() {
        if (Configurator.instance == null) {
            Configurator.instance = new Configurator();
        }

        return Configurator.instance;
    }

    public void load() throws IOException, ConfigFileNotExistException, SAXException {
        /* loading web application configurations */
        Digester digester = new Digester();
        digester.push(this);
        digester.setValidating(false);

        /* String config */
        digester.addObjectCreate("Configurations/config", Configuration.class);
        digester.addSetProperties("Configurations/config", "name", "name");
        digester.addSetProperties("Configurations/config", "value", "value");
        
        digester.addSetNext("Configurations/config", "addConfig");

        /* List config */
        digester.addObjectCreate("Configurations/list", ListConfiguration.class);
        digester.addSetProperties("Configurations/list", "name", "name");
        digester.addCallMethod("Configurations/list/value", "add", 1);
        digester.addCallParam("Configurations/list/value", 0);

        digester.addSetNext("Configurations/list", "addListConfig");

        File configure = new File(this.applicationContextConfigRealLocation);
        
//        this.logger.debug("config file path ->> " + configure.getAbsolutePath());
        
        if (!configure.exists()) {
            throw new ConfigFileNotExistException(configure.getAbsolutePath());
        }
        
        digester.parse(configure);
        
        /* register secure key */ 
        String secureKey = Configurator.getInstance().getConfig("wise.ds.secure.key");
        int secureKeyRound = Configurator.getInstance().getConfigIntValue("wise.ds.secure.key.round");
        
        Configurator.Constants.SEED_CBC_ENCRIPTION_KEY = secureKey;
        Configurator.Constants.SEED_CBC_ENCRIPTION_KEY_ROUND = secureKeyRound;
//        logger.debug("secure.key >> " + secureKey);
//        logger.debug("secure.key.round >> " + secureKeyRound);
    }

    public void clear() {
        this.configs.clear();
    }

    public void addConfig(Configuration configuration) {
        String value = configuration.getValue();
        
        value = ConfigurationReplacer.replace(value, this.configs);
        
        this.configs.put(configuration.getName(), value);
    }

    public void addListConfig(ListConfiguration listConfig) {
        List<String> values = new ArrayList<String>();
        
        for (String value : listConfig.getList()) {
            value = ConfigurationReplacer.replace(value, this.configs);
            values.add(value);
        }
        
        this.configs.put(listConfig.getName(), values);
    }
    
    public Set<String> getConfigKeySet() {
        return this.configs.keySet();
    }
    
    public Object getConfigObjectValue(String key) {
        return this.getConfigObjectValue(key, new Object());
    }
    public Object getConfigObjectValue(String key, Object dephault) {
        Object value;
        if (!this.configs.containsKey(key)) {
//            this.logger.debug("can't find config = " + key + ", return default value: " + dephault);
            value = dephault;
        } else {
            value = this.configs.get(key);
            if (value == null) {
                value = dephault;
            }
        }
        return value;
    }

    public String getConfig(String key) {
        String dephault = new DefaultConfigurationValues().getStringDefaultValue(key);
        return this.getConfig(key, dephault);
    }
    public String getConfig(String key, String dephault) {
        String value;
        if (!this.configs.containsKey(key)) {
//            this.logger.debug("can't find config = " + key + ", return default value: " + dephault);
            value = dephault;
        } else {
            value = ((String) this.configs.get(key)).trim();
            if ("".equals(CoreUtils.ifNull(value))) {
                value = dephault;
            }
        }
        return value;
    }
    
    public int getConfigIntValue(String key) {
        return this.getConfigIntValue(key, 0);
    }
    public int getConfigIntValue(String key, int dephault) {
        int intValue;
        if (!this.configs.containsKey(key)) {
            intValue = dephault;
        } else {
            String value = ((String) this.configs.get(key)).trim();
            try {
            	intValue = Integer.valueOf(value).intValue();
            } catch (NumberFormatException e) {
            	intValue = dephault;
            }
        }
        return intValue;
    }
    
    public boolean getConfigBooleanValue(String key) {
        return this.getConfigBooleanValue(key, false);
    }
    public boolean getConfigBooleanValue(String key, boolean dephault) {
        Boolean boolValue = false;
        if (!this.configs.containsKey(key)) {
//            this.logger.debug("can't find config = " + key + ", return default value: " + dephault);
            boolValue = dephault;
        } else {
            String val = this.getConfig(key);
            boolValue = new Boolean(val).booleanValue();
        }
        return boolValue;
    }

    public List<String> getListConfig(String key) {
        List<String> dephault = new DefaultConfigurationValues().getListDefaultValue(key);
        return this.getListConfig(key, dephault);
    }
    @SuppressWarnings("unchecked")
    public List<String> getListConfig(String key, List<String> dephault) {
        List<String> value;
        if (!this.configs.containsKey(key)) {
//            this.logger.debug("can't find config = " + key + ", return default value: [" + StringUtils.join(dephault, ",") + "]");
            value = dephault;
        } else {
            value = (List<String>) this.configs.get(key);
            if (value == null || value.size() == 0) {
                value = dephault;
            }
        }
        return value;
    }

    public String getFullDomain(HttpServletRequest request) {
        String protocol = request.isSecure() ? "https://" : "http://";
        String domain = request.getServerName();
        int port = request.getServerPort();

        String portStr = port == 80 ? "" : ":" + port;

        return protocol + domain + portStr;
    }
    
    public String getDashboardRepositoryURL() {
        String secure = CoreUtils.ifNull(Configurator.getInstance().getConfig("wise.ds.repository.protocol.secure"));

        String protocol = Boolean.valueOf(secure) ? "https://" : "http://";
        String domain = CoreUtils.ifNull(Configurator.getInstance().getConfig("wise.ds.repository.domain"));
        String port = Boolean.valueOf(secure) ? Configurator.getInstance().getConfig("wise.ds.repository.protocol.secure.port") : Configurator.getInstance().getConfig("wise.ds.repository.protocol.defualt.port");
        port = ("".equals(port) || "80".equals(port)) ? "" : ":" + CoreUtils.ifNull(port);

        String url = protocol + domain + port;

        return url;
    }
    
    public String getDashboardRepositoryXmlURL() {
        String dashboardRepositoryURL = this.getDashboardRepositoryURL();
        String dashboardRepositoryXmlURI = CoreUtils.ifNull(Configurator.getInstance().getConfig("wise.ds.repository.xml.uri"));

        String slash = dashboardRepositoryXmlURI.indexOf("/") == 0 ? "" : "/";
        String url = dashboardRepositoryURL + slash + dashboardRepositoryXmlURI;

        return url;
    }

    public String getApplicationContextConfigRealLocation() {
        return applicationContextConfigRealLocation;
    }

    public void setApplicationContextConfigRealLocation(String ApplicationContextConfigRealLocation) {
        this.applicationContextConfigRealLocation = ApplicationContextConfigRealLocation;
    }
    
    public void setApplicationContextRealLocation(String ApplicationContextRealLocation) {
        this.applicationContextRealLocation = ApplicationContextRealLocation;
    }
    
    public String getApplicationContextRealLocation() {
        return applicationContextRealLocation;
    }

    public String toString() {
        String configStr = "<br/>";
        
        Object[] keyset = this.configs.keySet().toArray();
        for (Object key : keyset) {
            if ("wise.ds.secure.key".equals(key) || "wise.ds.secure.key.round".equals(key)) {
                continue;
            }
            configStr += key + " = " + this.configs.get(key) + "<br/>";
        }
        
        return configStr;
    }

    final public static class Constants {
////        final public static String APPLICATION_CONFIG_PATH = "/WEB-INF/config/";
        final public static String APPLICATION_CONFIG_PATH = File.separator + "WEB-INF" + File.separator + "config" + File.separator;
        final public static String APPLICATION_CONFIG_XML = "web-application.xml";
        
        final public static String SESSION_USER_PREFIX = "SESSION_";
        
        // $6geSIJ+lo!f8-x@
//        final public static String SEED_CBC_ENCRIPTION_KEY = "VmxSS0BNRlV4YkZoVGJrNXFVbTFTVmxsVVRrTldWbXhYWVVaT2JHSkhlREZaYTFacllWWmFWV0pGVmxWV2JFcFVWbGQ0UzFOR1VsbGFSbFpPVmxaVk1WWlZXa1pQVmtKU1VGUXdQUT09";
        // 8074212aa995900a : using kisa SEED
//        final public static String SEED_CBC_ENCRIPTION_KEY = "Vm10UzNRMVV4Um5KTlNHUlBWbFphVlZZd1pHOVVNV3h6Vm0xR2FVMVdSalJXVnpWTFZHeGFWV0pHV2xaV2JXaHlWako0WVZKdFJYcGlSbFpYWVRGVk1WWlZXa1pQVmtKU1VGUXdQUT09";
//        final public static int SEED_CBC_ENCRIPTION_KEY_ROUND = 5;
        public static String SEED_CBC_ENCRIPTION_KEY = null;
        public static int SEED_CBC_ENCRIPTION_KEY_ROUND = -1;
        
        final public static String WISE_REPORT_TYPE = "DashAny";
        
        final public static String WISE_REPORT_SHAPEFILE_LOCATION = "/resources/mapdata/shape/";
    }

}
