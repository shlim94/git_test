package com.wise.common.secure;

import java.io.UnsupportedEncodingException;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.log4j.Logger;

import com.wise.context.config.Configurator;

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

public class SecureBasicDataSource extends BasicDataSource {
    private Logger logger = Logger.getLogger(getClass());
            
    final private String key;
    
    public SecureBasicDataSource() {
        this.key = Configurator.Constants.SEED_CBC_ENCRIPTION_KEY;
    }
    
    @Override
    public synchronized void setUrl(String url) {
        try {
        	String dec = SecureUtils.decSeed(this.key, url);
            super.setUrl(dec);
        } catch (UnsupportedEncodingException e) {
           this.logger.warn("", e);
        }
    }

    @Override
    public void setUsername(String username){
        try {
        	String dec = SecureUtils.decSeed(this.key, username);
            super.setUsername(dec);
        } catch (UnsupportedEncodingException e) {
            this.logger.warn("", e);
        } 
   }
  
    @Override
	public void setPassword(String password) {
		try {
			String dec = SecureUtils.decSeed(this.key, password);
			super.setPassword(dec);
		} catch (UnsupportedEncodingException e) {
			this.logger.warn("", e);
		}
	}
}
