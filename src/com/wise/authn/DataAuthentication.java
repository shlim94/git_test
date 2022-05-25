package com.wise.authn;

import net.sf.json.JSONObject;

public class DataAuthentication {
    private int cubeId;
    private int dsViewId;

    private String uniqueName;
    private String logicalTableName;
    private String memberName;

    public DataAuthentication(JSONObject member) {
        if (member.containsKey("CUBE_ID"))
            this.cubeId = member.getInt("CUBE_ID");
        if (member.containsKey("DS_VIEW_ID"))
            this.dsViewId = member.getInt("DS_VIEW_ID");
        if (member.containsKey("HIE_UNI_NM"))
            this.uniqueName = member.getString("HIE_UNI_NM");
        if (member.containsKey("DIM_UNI_NM"))
            this.logicalTableName = member.getString("DIM_UNI_NM");
        if (member.containsKey("MEMBER_NM"))
            this.memberName = member.getString("MEMBER_NM");
    }

    public int getCubeId() {
        return cubeId;
    }

    public void setCubeId(int cubeId) {
        this.cubeId = cubeId;
    }

    public int getDsViewId() {
        return dsViewId;
    }

    public void setDsViewId(int dsViewId) {
        this.dsViewId = dsViewId;
    }

    public String getUniqueName() {
        return uniqueName;
    }

    public void setUniqueName(String uniqueName) {
        this.uniqueName = uniqueName;
    }

    public String getLogicalTablenName() {
        return logicalTableName;
    }

    public void setLogicalTableName(String logicalTableName) {
        this.logicalTableName = logicalTableName;
    }

    public String getMemberName() {
        return memberName;
    }

    public void setMemberName(String memberName) {
        this.memberName = memberName;
    }

    @Override
    public String toString() {
        return "DataAuthentication [cubeId=" + cubeId + ", dsViewId=" + dsViewId + ", uniqueName=" + uniqueName + ", logicalTableName="
                + logicalTableName + ", memberName=" + memberName + "]";
    }
}
