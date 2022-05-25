package com.wise.ds.util;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;

public final class ResultSetMetaDataUtils {

	private ResultSetMetaDataUtils() {
		
	}
	
	public static String[] getColumnNames(final ResultSetMetaData md) throws SQLException {
		final int colCount = md.getColumnCount();
		String[] colNames = new String[colCount];
		for (int i = 1; i <= colCount; i++) {
			colNames[i-1] = md.getColumnName(i);
		}
		return colNames;
	}
}
