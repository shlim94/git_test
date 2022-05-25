package com.wise.authn;

import java.io.Serializable;

public class User implements Serializable {
    private static final long serialVersionUID = 5059594373633728503L;
    private int USER_NO;
	private int GRP_ID;
	private String USER_ID;
	private String USER_NM;
	private String PASSWD;
	private String E_MAIL1;
	private String E_MAIL2;
	private String DEL_YN;
	private String HP_NO;
	private String TEL_NO;
	private String USER_REL_CD;
	private String USER_DESC;
	private String PW_CHAN_DT;
	private String RUN_MODE;
	private int LOCK_CNT;
	private int PW_MISS_CNT;
	private int LOGIN_DATE_TF;
    // DEPRECATED
    private int no;
    private String id; // target id
    private String name;
    private int gid;
    private String srcId; // source user id of mapper table
    
	public int getUSER_NO() {
		return USER_NO;
	}
	public void setUSER_NO(int uSER_NO) {
		USER_NO = uSER_NO;
	}
	public int getGRP_ID() {
		return GRP_ID;
	}
	public void setGRP_ID(int gRP_ID) {
		GRP_ID = gRP_ID;
	}
	public String getUSER_ID() {
		return USER_ID;
	}
	public void setUSER_ID(String uSER_ID) {
		USER_ID = uSER_ID;
	}
	public String getUSER_NM() {
		return USER_NM;
	}
	public void setUSER_NM(String uSER_NM) {
		USER_NM = uSER_NM;
	}
	public String getPASSWD() {
		return PASSWD;
	}
	public void setPASSWD(String pASSWD) {
		PASSWD = pASSWD;
	}
	public String getE_MAIL1() {
		return E_MAIL1;
	}
	public void setE_MAIL1(String e_MAIL1) {
		E_MAIL1 = e_MAIL1;
	}
	public String getE_MAIL2() {
		return E_MAIL2;
	}
	public void setE_MAIL2(String e_MAIL2) {
		E_MAIL2 = e_MAIL2;
	}
	public String getDEL_YN() {
		return DEL_YN;
	}
	public void setDEL_YN(String dEL_YN) {
		DEL_YN = dEL_YN;
	}
	public String getHP_NO() {
		return HP_NO;
	}
	public void setHP_NO(String hP_NO) {
		HP_NO = hP_NO;
	}
	public String getTEL_NO() {
		return TEL_NO;
	}
	public void setTEL_NO(String tEL_NO) {
		TEL_NO = tEL_NO;
	}
	public String getUSER_REL_CD() {
		return USER_REL_CD;
	}
	public void setUSER_REL_CD(String uSER_REL_CD) {
		USER_REL_CD = uSER_REL_CD;
	}
	public String getUSER_DESC() {
		return USER_DESC;
	}
	public void setUSER_DESC(String uSER_DESC) {
		USER_DESC = uSER_DESC;
	}
	public String getPW_CHAN_DT() {
		return PW_CHAN_DT;
	}
	public void setPW_CHAN_DT(String pW_CHAN_DT) {
		PW_CHAN_DT = pW_CHAN_DT;
	}
	public String getRUN_MODE() {
		return RUN_MODE;
	}
	public void setRUN_MODE(String rUN_MODE) {
		RUN_MODE = rUN_MODE;
	}
	public int getLOCK_CNT() {
		return LOCK_CNT;
	}
	public void setLOCK_CNT(int lOCK_CNT) {
		LOCK_CNT = lOCK_CNT;
	}
	public int getPW_MISS_CNT() {
		return PW_MISS_CNT;
	}
	public void setPW_MISS_CNT(int pW_MISS_CNT) {
		PW_MISS_CNT = pW_MISS_CNT;
	}
	public int getLOGIN_DATE_TF() {
		return LOGIN_DATE_TF;
	}
	public void setLOGIN_DATE_TF(int lOGIN_DATE_TF) {
		LOGIN_DATE_TF = lOGIN_DATE_TF;
	}
    
    @Override
    public String toString() {
    	return "User [no=" + USER_NO + ", id=" + USER_ID + ", name=" + USER_NM + ", gid=" + GRP_ID + "]";
    }
    
    @Override
    public boolean equals(Object o) {
    	if (o == this) {
    		return true;
    	} 	
    	if (!(o instanceof User)) {
    		return false;
    	}
    	User c = (User) o;
    	return Integer.compare(this.getUSER_NO(), c.getUSER_NO()) == 0
    			&& this.getUSER_ID().equals(c.getUSER_ID())
    			&& this.getUSER_NM().equals(c.getUSER_NM());
    }
    
    // DEPRECATED
    public int getNo() {
        return no;
    }

    public void setNo(int no) {
        this.no = no;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSrcId() {
        return srcId;
    }

    public void setSrcId(String srcId) {
        this.srcId = srcId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getGid() {
        return gid;
    }

    public void setGid(int gid) {
        this.gid = gid;
    }
	
}
