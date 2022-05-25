package wise.querygen.dto;

public enum JoinType {
	InnerJoin(1),
    OuterJoin(2),
    LeftJoin(3),
    RightJoin(4);
	private int value;
	
	JoinType(int value)
    {
    	this.value = value;
    }

	public int getValue() {
		return value;
	}
	
	public static JoinType getJoinType(String aJoinType)
	{
		if(aJoinType.equalsIgnoreCase("INNER JOIN"))
			return InnerJoin;
		if(aJoinType.equalsIgnoreCase("OUTER JOIN"))
			return OuterJoin;
		if(aJoinType.equalsIgnoreCase("LEFT JOIN"))
			return LeftJoin;
		if(aJoinType.equalsIgnoreCase("RIGHT JOIN"))
			return RightJoin;
				
		return InnerJoin;
	}
}
