package com.wise.authn;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.bouncycastle.util.encoders.Base64;

import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;

public class ReportDataPermission implements Serializable {
    private static final long serialVersionUID = 6701897706304522045L;

    private int userNo;
    private int userGroupId; // user group id
    private String dataAuthnXmlBase64;
    private String dataAuthnXml;
    private JSONObject dataAuthnJson;

    public int getUserNo() {
        return userNo;
    }

    public void setUserNo(int userNo) {
        this.userNo = userNo;
    }

    public int getUserGroupId() {
        return userGroupId;
    }

    public void setUserGroupId(int userGroupId) {
        this.userGroupId = userGroupId;
    }

    public String getDataAuthnXmlBase64() {
        return dataAuthnXmlBase64;
    }

    public void setDataAuthnXmlBase64(String dataAuthnXmlBase64) throws Exception {
        this.dataAuthnXmlBase64 = CoreUtils.ifNull(dataAuthnXmlBase64);

        if ("".equals(this.dataAuthnXmlBase64)) {
            this.dataAuthnXml = "";
            this.dataAuthnJson = new JSONObject();
        } else {
            String encoding = Configurator.getInstance().getConfig("encoding");
            this.dataAuthnXml = new String(Base64.decode(this.dataAuthnXmlBase64.getBytes()), encoding);
            
            if ("".equals(CoreUtils.ifNull(this.dataAuthnXml))) {
                this.dataAuthnJson = new JSONObject();
            } else {
                org.json.JSONObject CHART_XML = org.json.XML.toJSONObject(this.dataAuthnXml);
                this.dataAuthnJson = JSONObject.fromObject(CHART_XML.toString());
            }
        }
    }

    public String getDataAuthnXml() {
        return dataAuthnXml;
    }

    public JSONObject getDataAuthnJson() {
        return dataAuthnJson;
    }
    
    public List<DataAuthentication> getAuthnMember(int dsViewId) {
        List<DataAuthentication> members = new ArrayList<DataAuthentication>();
        
        JSONObject NewDataSet = this.dataAuthnJson.getJSONObject("NewDataSet");
        Object Auth_Mem = NewDataSet.get("Auth_Mem");
        
        if (Auth_Mem != null) {
            JSONArray temp;
            if (Auth_Mem instanceof JSONObject) {
                temp = new JSONArray();
                temp.add(Auth_Mem);
            }
            else {
            	/* DOGFOOT ktkang 주제영역 오류 수정 갑자기 왜 나는지 모르겠음  20200210 */
                temp =  JSONArray.fromObject(Auth_Mem);
            }
            
            for (Object member : temp.toArray()) {
                DataAuthentication da = new DataAuthentication((JSONObject) member);
                if (dsViewId == da.getDsViewId()) {
                    members.add(da);
                }
            }
        }
        
        return members;
    }
    
    public List<DataAuthentication> getAuthnDim(int dsViewId) {
        List<DataAuthentication> dimensions = new ArrayList<DataAuthentication>();
        
        JSONObject NewDataSet = this.dataAuthnJson.getJSONObject("NewDataSet");
        Object Auth_Dim = NewDataSet.get("Auth_Dim");
        
        if (Auth_Dim != null) {
            JSONArray temp;
            if (Auth_Dim instanceof org.json.JSONObject) {
                temp = new JSONArray();
                temp.add(Auth_Dim);
            }
            else {
            	/* DOGFOOT ktkang 주제영역 오류 수정 갑자기 왜 나는지 모르겠음  20200210 */
                temp = JSONArray.fromObject(Auth_Dim);
            }
            
            for (Object dim : temp.toArray()) {
                DataAuthentication da = new DataAuthentication((JSONObject) dim);
                if (dsViewId == da.getDsViewId()) {
                	dimensions.add(da);
                }
            }
        }
        
        return dimensions;
    }
    
    /* DOGFOOT ktkang 주제영역 권한 추가  20200810 */
    public List<DataAuthentication> getAuthnCubes() {
        List<DataAuthentication> cubes = new ArrayList<DataAuthentication>();
        
        JSONObject NewDataSet = this.dataAuthnJson.getJSONObject("NewDataSet");
        Object Auth_Cubes = NewDataSet.get("Auth_Cubes");
        
        if (Auth_Cubes != null) {
            JSONArray temp;
            if (Auth_Cubes instanceof org.json.JSONObject) {
                temp = new JSONArray();
                temp.add(Auth_Cubes);
            }
            else {
            	/* DOGFOOT ktkang 주제영역 오류 수정 갑자기 왜 나는지 모르겠음  20200210 */
                temp = JSONArray.fromObject(Auth_Cubes);
            }
            
            for (Object cube : temp.toArray()) {
                DataAuthentication da = new DataAuthentication((JSONObject) cube);
                cubes.add(da);
            }
        }
        
        return cubes;
    }

    @Override
    public String toString() {
        return "ReportDataPermission [userNo=" + userNo + ", userGroupId=" + userGroupId + ", dataAuthnXmlBase64=" + dataAuthnXmlBase64
                + ", dataAuthnXml=" + dataAuthnXml + ", dataAuthnJson=" + dataAuthnJson + "]";
    }
}
