package wise.querysetting.dbms;

public class DB2BLUSetting {

	public DB2BLUSetting(){}
	public String vbCrLf = "\r\n";
	public String DsDsViewOrderByRandomClause()
	{
		String sOrderBy = "";

		sOrderBy = "ORDER BY SYS_GUID()";

		return sOrderBy;
	}
	
	public String ConvertFileNm(String aFileNm)
	{
		return "\"" + aFileNm + "\"";
	}
	
	public String FilterQuery(String aTblNm, String aCaptionColNm, String aKeyColNm, String aSortType)
	{
		String sQuery = "";

		sQuery = sQuery + vbCrLf + "SELECT cast(" + aKeyColNm + " as VARCHAR(255)) KEY_VALUE , cast(" + aCaptionColNm + " as VARCHAR(255)) CAPTION_VALUE";
		sQuery = sQuery + vbCrLf + "FROM   " + aTblNm;
		sQuery = sQuery + vbCrLf + "GROUP BY " + aKeyColNm + "," + aCaptionColNm;
		sQuery = sQuery + vbCrLf + "ORDER BY  KEY_VALUE " + aSortType;

		return sQuery;

	}
	
	public String TblAliasNm(String aDimUniNm)
	{
		String sAliasNm = "";

		sAliasNm = aDimUniNm.replace("\"", "").replace("\"", "");

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
