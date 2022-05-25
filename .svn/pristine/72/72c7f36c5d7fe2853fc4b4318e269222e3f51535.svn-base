package wise.querysetting.dbms;

public class MSSQLSetting {

	public MSSQLSetting(){}
	public String vbCrLf = "\r\n";
	public String DsDsViewOrderByRandomClause()
	{
		String sOrderBy = "";

		sOrderBy = "ORDER BY NEWID()";

		return sOrderBy;
	}
	
	public String ConvertFileNm(String aFileNm)
	{
		return "[" + aFileNm + "]";
	}
	
	public String FilterQuery(String aTblNm, String aCaptionColNm, String aKeyColNm, String aSortType)
	{
		String sQuery = "";

		sQuery = sQuery + vbCrLf + "SELECT CONVERT(NVARCHAR," + aKeyColNm + ")  KEY_VALUE , CONVERT(NVARCHAR," + aCaptionColNm + ") CAPTION_VALUE";
		sQuery = sQuery + vbCrLf + "FROM   " + aTblNm;
		sQuery = sQuery + vbCrLf + "GROUP BY " + aKeyColNm + "," + aCaptionColNm;
		sQuery = sQuery + vbCrLf + "ORDER BY  KEY_VALUE " + aSortType;

		return sQuery;

	}
	
	public String TblAliasNm(String aDimUniNm)
	{
		String sAliasNm = "";

		sAliasNm = aDimUniNm.replace("[", "").replace("]", "");

		return sAliasNm;

	}
	
	public String ColumnAliasNm(String aColumnNm)
	{
		String sAliasNm = "";

		sAliasNm = "\"" + aColumnNm + "\"";

		return sAliasNm;

	}
	
	public String GetAggregarion(String aAgg)
	{
		String sReturn = aAgg;

		if(sReturn.equalsIgnoreCase("VAR")) 
			sReturn = "VARIANCE";
		

		return sReturn;

	}
}
