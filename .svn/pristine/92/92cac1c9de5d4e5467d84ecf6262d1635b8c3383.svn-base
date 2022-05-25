package com.wise.ds.query.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

import org.apache.commons.lang.StringUtils;

import com.wise.ds.repository.dataset.NotFoundDatabaseConnectorException;

import au.com.bytecode.opencsv.CSVReader;

/**
 * 
 * @author viralpatel.net
 * 
 */
public class CSVLoader {

	private static final 
		String SQL_INSERT = "INSERT INTO ${table}(${keys}) VALUES(${values})";
	private static final String TABLE_REGEX = "\\$\\{table\\}";
	private static final String KEYS_REGEX = "\\$\\{keys\\}";
	private static final String VALUES_REGEX = "\\$\\{values\\}";

	private Connection connection;
	private char seprator;
	private ArrayList<String> header;
	/**
	 * Public constructor to build CSVLoader object with
	 * Connection details. The connection is closed on success
	 * or failure.
	 * @param connection
	 */
	public CSVLoader(Connection connection,char seprator,ArrayList<String> header) {
		this.connection = connection;
		//Set default separator
		this.seprator = seprator;
		this.header = header;
	}
	
	/**
	 * Parse CSV file using OpenCSV library and load in 
	 * given database table. 
	 * @param csvFile Input CSV file
	 * @param tableName Database table name to import data
	 * @param truncateBeforeLoad Truncate the table before inserting 
	 * 			new records.
	 * @throws NotFoundDatabaseConnectorException 
	 * @throws IOException
	 */
	public void loadCSV(String csvFile, String tableName,
			boolean truncateBeforeLoad,ArrayList<HashMap<String, String>> colInfo,String FILE_FIRSTROW_HD,String ckutf) throws IOException, NotFoundDatabaseConnectorException {

		CSVReader csvReader = null;
		if(null == this.connection) {
			throw new NotFoundDatabaseConnectorException("Not a valid connection.");
		}
		try {
			
			String fileEncode = (ckutf.equals("true"))?"UTF8":"EUC-KR"; 
			
			if(csvFile.startsWith("h") || csvFile.startsWith("H")) {
				InputStream in = new URL(csvFile).openStream();
				csvReader = new CSVReader(new InputStreamReader(in, fileEncode));
			} else {
				csvReader = new CSVReader(new InputStreamReader(new FileInputStream(csvFile), fileEncode), this.seprator);
			}

		} catch (IOException e) {
			e.printStackTrace();
		}

		String[] headerRow = header.toArray(new String[header.size()]);

		if (null == headerRow) {
			throw new FileNotFoundException(
					"No columns defined in given CSV file." +
					"Please check the CSV file format.");
		}

		String questionmarks = StringUtils.repeat("?,", headerRow.length);
		questionmarks = (String) questionmarks.subSequence(0, questionmarks
				.length() - 1);

		String query = SQL_INSERT.replaceFirst(TABLE_REGEX, tableName);
		query = query
				.replaceFirst(KEYS_REGEX, StringUtils.join(headerRow, ","));
		query = query.replaceFirst(VALUES_REGEX, questionmarks);

//		System.out.println("Query: " + query);

		String[] nextLine;
		Connection con = null;
		PreparedStatement ps = null;
		try {
			con = this.connection;
			con.setAutoCommit(false);
			ps = con.prepareStatement(query);

			if(truncateBeforeLoad) {
				//delete data from table before loading csv
				con.createStatement().execute("DELETE FROM " + tableName);
			}

			final int batchSize = 1000;
			int count = 0;
			Date date = null;
			while ((nextLine = csvReader.readNext()) != null) {
				if(FILE_FIRSTROW_HD.equals("True"))
				{
					FILE_FIRSTROW_HD = "False";
				}
				else
				{
					if (null != nextLine) {
						int index = 1;
						for (String string : nextLine) {
							date = DateUtil.convertToDate(string);
							if (null != date) {
								ps.setDate(index++, new java.sql.Date(date 
										.getTime()));
							} else {
								
								String coltype = colInfo.get(index-1).get("colType").toUpperCase();
								if(coltype.equals("INT32") || coltype.equalsIgnoreCase("INT") || coltype.equalsIgnoreCase("INTEGER")) {
									if(string.equals("")) {
										ps.setInt(index,0);
									}else {
										ps.setInt(index,Integer.parseInt(string));
									}
								/*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 임시 shlim 20210120*/
								} else if(coltype.equalsIgnoreCase("DOUBLE") || coltype.equalsIgnoreCase("FLOAT")|| coltype.equalsIgnoreCase("DECIMAL")) {
									ps.setDouble(index, Double.parseDouble(string));
								} else {
									ps.setString(index, string);
								}
								
//								System.out.println(index +":"+string+":"+coltype);
								index++;
								/*ps.setString(index++, string);
//								System.out.println(index +":"+string);*/
							}
						}
						ps.addBatch();
					}
				}
				
				if (++count % batchSize == 0) {
					ps.executeBatch();
				}
			}
			ps.executeBatch(); // insert remaining records
			con.commit();
		} catch (SQLException e) {
			e.printStackTrace();
			if (con != null) {
				try {
					con.rollback();
				} catch (SQLException se) {
					se.printStackTrace();
				}
			}
		} finally {
			if (null != ps) {
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			csvReader.close();
		}
	}

	public String loadCSVCpCust(String csvFile, String tableName) throws IOException, NotFoundDatabaseConnectorException {

		CSVReader csvReader = null;
		SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
		String today= formatter.format(new java.util.Date());
		
		if(null == this.connection) {
			throw new NotFoundDatabaseConnectorException("Not a valid connection.");
		}
		try {
			
			csvReader = new CSVReader(new InputStreamReader(new FileInputStream(csvFile), "EUC-KR"), this.seprator);

		} catch (IOException e) {
			e.printStackTrace();
		}
		
		ArrayList <String> header = new ArrayList<String>();
		
		header.add("UP_ID");
		header.add("CUST_NO");
		header.add("REG_DT");
		
		String[] headerRow = header.toArray(new String[header.size()]);

		if (null == headerRow) {
			throw new FileNotFoundException(
					"No columns defined in given CSV file." +
					"Please check the CSV file format.");
		}

		String questionmarks = StringUtils.repeat("?,", headerRow.length);
		questionmarks = (String) questionmarks.subSequence(0, questionmarks
				.length() - 1);

		String query = SQL_INSERT.replaceFirst(TABLE_REGEX, tableName);
		query = query
				.replaceFirst(KEYS_REGEX, StringUtils.join(headerRow, ","));
		query = query.replaceFirst(VALUES_REGEX, questionmarks);

//		System.out.println("Query: " + query);

		String[] nextLine;
		Connection con = null;
		PreparedStatement ps = null;
		try {
			con = this.connection;
			con.setAutoCommit(false);
			ps = con.prepareStatement(query);
			
			

			

			final int batchSize = 1000;
			int count = 0;
			Date date = null;
			while ((nextLine = csvReader.readNext()) != null) {
	
				if (null != nextLine) {
					for (String string : nextLine) {

							ps.setString(1, "cpupload_" + today);
							ps.setString(2, string);
							ps.setString(3, today);
						
					}
					ps.addBatch();
				}
				
				if (++count % batchSize == 0) {
					ps.executeBatch();
				}
			}
			ps.executeBatch(); // insert remaining records
			con.commit();
		} catch (SQLException e) {
			e.printStackTrace();
			if (con != null) {
				try {
					con.rollback();
				} catch (SQLException se) {
					se.printStackTrace();
				}
			}
		} finally {
			if (null != ps) {
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			csvReader.close();
		}
		
		return "cpupload_" + today;
	}
	
	public char getSeprator() {
		return seprator;
	}

	public void setSeprator(char seprator) {
		this.seprator = seprator;
	}

}
