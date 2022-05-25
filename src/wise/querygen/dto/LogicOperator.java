package wise.querygen.dto;

public enum LogicOperator {
	And(1),
    Or(2);
	
	private int value;
	
	LogicOperator(int value)
    {
    	this.value = value;
    }

	public int getValue() {
		return value;
	}
	
	public static LogicOperator getLogicOperator(String aLogicOperator)
	{
		if(aLogicOperator.equalsIgnoreCase("And"))
			return And;
		if(aLogicOperator.equalsIgnoreCase("Or"))
			return Or;
		
		return And;
	}
}
