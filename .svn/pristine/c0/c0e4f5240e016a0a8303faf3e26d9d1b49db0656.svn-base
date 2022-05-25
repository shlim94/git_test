package wise.querygen.dto;

public enum Comparison {
	Equals(1) ,
    NotEquals(2),
    GreaterThan(3),
    GreaterOrEquals(4),
    LessThan(5),
    LessOrEquals(6),
    Like(7),
    NotLike(8),
    In(9),
    IsNull(10),
    NotIsNull(11),
    NotIn(12),
    Between(13),
	And(14),
	Or(15);
    private int value;
    
    Comparison(int value)
    {
    	this.value = value;
    }

	public int getValue() {
		return value;
	}

	public static Comparison getComparisonType(String aComparisonType)
	{
		if(aComparisonType.equalsIgnoreCase("Equals") || aComparisonType.equalsIgnoreCase("LIST"))
			return Equals;
		if(aComparisonType.trim().equalsIgnoreCase("NotEquals"))
			return NotEquals;
		if(aComparisonType.equalsIgnoreCase("GreaterThan"))
			return GreaterThan;
		if(aComparisonType.equalsIgnoreCase("GreaterOrEquals"))
			return GreaterOrEquals;
		if(aComparisonType.equalsIgnoreCase("LessThan"))
			return LessThan;
		if(aComparisonType.equalsIgnoreCase("LessOrEquals"))
			return LessOrEquals;
		if(aComparisonType.equalsIgnoreCase("Like"))
			return Like;
		if(aComparisonType.trim().equalsIgnoreCase("NotLike"))
			return NotLike;
		if(aComparisonType.equalsIgnoreCase("In") || aComparisonType.equalsIgnoreCase("INPUT"))
			return In;
		if(aComparisonType.equalsIgnoreCase("IsNull"))
			return IsNull;
		if(aComparisonType.trim().equalsIgnoreCase("NotIsNull"))
			return Like;
		if(aComparisonType.trim().equalsIgnoreCase("NotIn"))
			return NotIn;
		if(aComparisonType.equalsIgnoreCase("Between") || aComparisonType.equalsIgnoreCase("BETWEEN_CAND") || aComparisonType.equalsIgnoreCase("BETWEEN_LIST") || aComparisonType.equalsIgnoreCase("BETWEEN_INPUT"))
			return Between;
		if(aComparisonType.equalsIgnoreCase("And"))
			return And;
		if(aComparisonType.equalsIgnoreCase("Or"))
			return Or;
		
		return Equals;
	}
};
