package wise.querygen.clauses;

import wise.querygen.dto.*;

public class TopClause {

	public int Quantity;
    public TopUnit Unit;
    public TopClause(int nr)
    {
        Quantity = nr;
        Unit = TopUnit.Records;
    }
    public TopClause(int nr, TopUnit aUnit)
    {
        Quantity = nr;
        Unit = aUnit;
    }
	public int getQuantity() {
		return Quantity;
	}
	public void setQuantity(int quantity) {
		Quantity = quantity;
	}
	public TopUnit getUnit() {
		return Unit;
	}
	public void setUnit(TopUnit unit) {
		Unit = unit;
	}
    
    
}
