package com.wise.ds.repository;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.encoders.Base64;
import org.json.XML;

import com.wise.common.secure.SecureUtils;
import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class DataSetInfoMasterVO {
	private int FLD_ID;
	private int DATASET_ID;
	private String DATASET_NM;
	private int DATASET_ORDINAL;
	private String DATASET_TYPE;
	private String DATASET_DESC;
	private int PARENT_FLD_ID;
	private int DATASRC_ID;
	private String DATASRC_TYPE;
	private String SQL_XML;
	private String SQL_QUERY;
    private String datasetXml;
    private String paramXml;
	
	public int getFLD_ID() {
        return FLD_ID;
    }

    public void setFLD_ID(int FLD_ID) {
        this.FLD_ID = FLD_ID;
    }
	
	public int getDATASET_ID() {
        return DATASET_ID;
    }

    public void setDATASET_ID(int DATASET_ID) {
        this.DATASET_ID = DATASET_ID;
    }
    
    public String getDATASET_NM() {
        return DATASET_NM;
    }

    public void setDATASET_NM(String DATASET_NM) {
        this.DATASET_NM = DATASET_NM;
    }
    
    public int getDATASET_ORDINAL() {
        return DATASET_ORDINAL;
    }

    public void setDATASET_ORDINAL(int DATASET_ORDINAL) {
        this.DATASET_ORDINAL = DATASET_ORDINAL;
    }
    
    public int getDATASRC_ID() {
        return DATASRC_ID;
    }

    public void setDATASRC_ID(int DATASRC_ID) {
        this.DATASRC_ID = DATASRC_ID;
    }
    
    public String getDATASET_TYPE() {
        return DATASET_TYPE;
    }

    public void setDATASET_TYPE(String DATASET_TYPE) {
        this.DATASET_TYPE = DATASET_TYPE;
    }
    
    public String getDATASET_DESC() {
        return DATASET_DESC;
    }

    public void setDATASET_DESC(String DATASET_DESC) {
        this.DATASET_DESC = DATASET_DESC;
    }
    
    public int getPARENT_FLD_ID() {
        return PARENT_FLD_ID;
    }

    public void setPARENT_FLD_ID(int PARENT_FLD_ID) {
        this.PARENT_FLD_ID = PARENT_FLD_ID;
    }
    
    public String getDATASRC_TYPE() {
        return DATASRC_TYPE;
    }

    public void setDATASRC_TYPE(String DATASRC_TYPE) {
        this.DATASRC_TYPE = DATASRC_TYPE;
    }
    
    public String getSQL_XML() {
        return SQL_XML;
    }

    public void setSQL_XML(String SQL_XML) throws NotFoundReportXmlException, UnsupportedEncodingException {
    	String encoding = Configurator.getInstance().getConfig("encoding");
    	
    	this.SQL_XML = CoreUtils.ifNull(SQL_XML);

    	if ("".equals(this.SQL_XML)) {
    		this.datasetXml = "";
    	}
    	else {
    		this.datasetXml = new String(Base64.decode(this.SQL_XML.getBytes()), encoding);
    	}
    }
    
    public String getDatasetXml() {
        return datasetXml;
    }
    
    public String getParamXml() {
        return paramXml;
    }
    
    public String getSQL_QUERY() {
        return SQL_QUERY;
    }

    public void setSQL_QUERY(String SQL_QUERY) throws NotFoundReportXmlException, UnsupportedEncodingException {
    	this.SQL_QUERY = CoreUtils.ifNull(SQL_QUERY);

    	if ("".equals(this.SQL_QUERY)) {
    		this.SQL_QUERY = "";
    	}
    	else {
    		String encoding = Configurator.getInstance().getConfig("encoding");
    		this.SQL_QUERY = new String(Base64.decode(this.SQL_QUERY.getBytes()), encoding);
    	}
    }
}
