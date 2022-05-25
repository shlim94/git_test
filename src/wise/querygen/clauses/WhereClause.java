package wise.querygen.clauses;

import java.util.ArrayList;

import wise.querygen.dto.*;

public class WhereClause {

	private String m_FieldName;
    private Comparison m_ComparisonOperator;
    private Object m_Value;
    private String m_Value_Type;
    private String m_paramName;

    private LogicOperator m_LogicOperator;

    public ArrayList<SubClause> m_SubClauses;	// Array of SubClause

    public WhereClause(String field, Comparison firstCompareOperator, Object firstCompareValue, String firstvaluetype, String paramName, LogicOperator aLogicOperator)
    {
        m_FieldName = field;
        m_ComparisonOperator = firstCompareOperator;
        m_Value = firstCompareValue;
        m_Value_Type = firstvaluetype;
        m_paramName = paramName;
        
        m_LogicOperator = aLogicOperator;

        m_SubClauses = new ArrayList<SubClause>();
    }
    
    public void AddClause(LogicOperator logic, Comparison compareOperator, Object compareValue, String valuetype, String paramName)
    {
        SubClause NewSubClause = new SubClause(logic, compareOperator, compareValue, valuetype, paramName);
        m_SubClauses.add(NewSubClause);
    }
    
	public String getM_FieldName() {
		return m_FieldName;
	}

	public void setM_FieldName(String m_FieldName) {
		this.m_FieldName = m_FieldName;
	}

	public Comparison getM_ComparisonOperator() {
		return m_ComparisonOperator;
	}

	public void setM_ComparisonOperator(Comparison m_ComparisonOperator) {
		this.m_ComparisonOperator = m_ComparisonOperator;
	}

	public Object getM_Value() {
		return m_Value;
	}

	public void setM_Value(Object m_Value) {
		this.m_Value = m_Value;
	}

	public String getM_Value_Type() {
		return m_Value_Type;
	}

	public void setM_Value_Type(String m_Value_Type) {
		this.m_Value_Type = m_Value_Type;
	}

	public String getM_paramName() {
		return m_paramName;
	}

	public void setM_paramName(String m_paramName) {
		this.m_paramName = m_paramName;
	}

	public LogicOperator getM_LogicOperator() {
		return m_LogicOperator;
	}

	public void setM_LogicOperator(LogicOperator m_LogicOperator) {
		this.m_LogicOperator = m_LogicOperator;
	}

	public ArrayList<SubClause> getM_SubClauses() {
		return m_SubClauses;
	}

	public void setM_SubClauses(ArrayList<SubClause> m_SubClauses) {
		this.m_SubClauses = m_SubClauses;
	}
    
    
    
}
