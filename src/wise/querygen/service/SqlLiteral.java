package wise.querygen.service;

public class SqlLiteral {

	public static String StatementRowsAffected = "SELECT @@ROWCOUNT";

    private String _value;

	public String get_value() {
		return _value;
	}

	public void set_value(String _value) {
		this._value = _value;
	}
    
	 public SqlLiteral(String value)
     {
         _value = value;
     }
}
