package wise.querygen.dto;

public class SelectCubeEtc extends DataTable {

	private String DISTINCT;
	private String SEL_COND;
	private String SEL_NUMBERIC;
	private String CHANGE_COND;
	
	public String getDISTINCT() {
		return DISTINCT;
	}
	public void setDISTINCT(String dISTINCT) {
		DISTINCT = dISTINCT;
	}
	public String getSEL_COND() {
		return SEL_COND;
	}
	public void setSEL_COND(String sEL_COND) {
		SEL_COND = sEL_COND;
	}
	public String getSEL_NUMBERIC() {
		return SEL_NUMBERIC;
	}
	public void setSEL_NUMBERIC(String sEL_NUMBERIC) {
		SEL_NUMBERIC = sEL_NUMBERIC;
	}
	public String getCHANGE_COND() {
		return CHANGE_COND;
	}
	public void setCHANGE_COND(String cHANGE_COND) {
		CHANGE_COND = cHANGE_COND;
	}
	
	
}
