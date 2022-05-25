package wise.querygen.dto;

public enum TopUnit {
	Records(1),
    Percent(2);
	
	private int value;
	
	TopUnit(int value)
    {
    	this.value = value;
    }

	public int getValue() {
		return value;
	}
}
