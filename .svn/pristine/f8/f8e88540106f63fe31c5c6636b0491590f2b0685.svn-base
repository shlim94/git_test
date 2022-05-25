package wise.querygen.clauses;

import wise.querygen.dto.*;

public class JoinClause {

	public JoinType JoinType;
    public String FromTable;
    public String FromColumn;
    public Comparison ComparisonOperator;
    public String ToTable;
    public String ToColumn;
    
    public JoinClause(JoinType join, String toTableName, String toColumnName, Comparison operator, String fromTableName, String fromColumnName)
    {
    	JoinType = join;
        FromTable = fromTableName;
        FromColumn = fromColumnName;
        ComparisonOperator = operator;
        ToTable = toTableName;
        ToColumn = toColumnName;
    }

	public JoinType getJoinType() {
		return JoinType;
	}

	public void setJoinType(JoinType joinType) {
		JoinType = joinType;
	}

	public String getFromTable() {
		return FromTable;
	}

	public void setFromTable(String fromTable) {
		FromTable = fromTable;
	}

	public String getFromColumn() {
		return FromColumn;
	}

	public void setFromColumn(String fromColumn) {
		FromColumn = fromColumn;
	}

	public Comparison getComparisonOperator() {
		return ComparisonOperator;
	}

	public void setComparisonOperator(Comparison comparisonOperator) {
		ComparisonOperator = comparisonOperator;
	}

	public String getToTable() {
		return ToTable;
	}

	public void setToTable(String toTable) {
		ToTable = toTable;
	}

	public String getToColumn() {
		return ToColumn;
	}

	public void setToColumn(String toColumn) {
		ToColumn = toColumn;
	}
    
    
}
