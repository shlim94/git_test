package com.wise.ds.query.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;

import org.apache.commons.lang.StringUtils;
import org.apache.poi.hssf.usermodel.HSSFCell;
import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

public class ExcelLoader {

	private static final String SQL_INSERT = "INSERT INTO ${table}(${keys}) VALUES(${values})";
	private static final String TABLE_REGEX = "\\$\\{table\\}";
	private static final String KEYS_REGEX = "\\$\\{keys\\}";
	private static final String VALUES_REGEX = "\\$\\{values\\}";

	private Connection connection;
	private String seprator;
	private ArrayList<String> header;
	
	public ExcelLoader(Connection connection,String seprator,ArrayList<String> header) {
		this.connection = connection;
		//Set default separator
		this.seprator = seprator;
		this.header = header;
	}
	
	public void loadExcel(String csvFile, String tableName,
			boolean truncateBeforeLoad,ArrayList<HashMap<String, String>> colInfo,String FILE_FIRSTROW_HD) throws IOException {
		
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
		
		Connection con = null;
		PreparedStatement ps = null;
		
		String ext = "";
		int index = csvFile.lastIndexOf(".");
		try 
		{
			con = this.connection;
			String databaseName = con.getMetaData().getDatabaseProductName();
			con.setAutoCommit(false);
			ps = con.prepareStatement(query);
			
			if (index != -1) {
				ext = csvFile.substring(index + 1);
			}
			if(ext.equalsIgnoreCase("xls")) {
				FileInputStream fis=new FileInputStream(csvFile);
				HSSFWorkbook workbook=new HSSFWorkbook(fis);
				fis.close();
				int rowindex=0;
				int columnindex=0;
				//시트 수 (첫번째에만 존재하므로 0을 준다)
				//만약 각 시트를 읽기위해서는 FOR문을 한번더 돌려준다
				HSSFSheet sheet = workbook.getSheetAt(0);
				//행의 수
				final int batchSize = 1000;
				int rows=sheet.getPhysicalNumberOfRows();
				int hdChk = 0;
				if (FILE_FIRSTROW_HD.equals("True"))
	            {
					hdChk = 1;
	            }
				HSSFRow rowheader=sheet.getRow(0);
				int cells=rowheader.getPhysicalNumberOfCells();
				for(rowindex=hdChk;rowindex<rows;rowindex++){
				    //행을읽는다
				    HSSFRow row=sheet.getRow(rowindex);
				    if(row !=null){
				        //셀의 수
				        
				        for(columnindex=0;columnindex<cells;columnindex++){
				            //셀값을 읽는다
				            HSSFCell cell=row.getCell(columnindex);
				            String value="";
				            /*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 임시 shlim 20210120*/
				            String coltype = colInfo.get(columnindex).get("COL_DATA_TYPE");	
				            //셀이 빈값일경우를 위한 널체크
				            if(cell==null){
//				                continue;
				            	 value="";
				            }else{
				                //타입별로 내용 읽기
				                switch (cell.getCellTypeEnum()){
				                case FORMULA:
				                    value=cell.getCellFormula();
				                    break;
				                case NUMERIC:
				                	/*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 임시 shlim 20210120*/
				                	if(coltype.equalsIgnoreCase("decimal") || coltype.equalsIgnoreCase("float") ) {
				                		value= cell.getNumericCellValue()+"";
				                	}else {
				                		value= (int)cell.getNumericCellValue()+"";
				                	}
				                    break;
				                case STRING:
				                    value=cell.getStringCellValue()+"";
				                    break;
				                case BLANK:
				                    value=cell.getBooleanCellValue()+"";
				                    break;
				                case ERROR:
				                    value=cell.getErrorCellValue()+"";
				                    break;
				                }
				            }
				            /*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 임시 shlim 20210120*/
				            //String coltype = colInfo.get(columnindex).get("COL_DATA_TYPE");
							if(coltype == "int")
							{
								ps.setInt(columnindex,Integer.parseInt(value));
							}
							else if(coltype.equalsIgnoreCase("decimal") || coltype.equalsIgnoreCase("float") ) {
								
								ps.setDouble(columnindex + 1, Double.parseDouble(value));
							}
							else
							{
								if(databaseName.equals("Impala") && value.equals("")) {
									ps.setString(columnindex+1, null);
								} else {
									ps.setString(columnindex+1, value);
								}
							}
							
				        }
				        ps.addBatch();
				   }
				    if (rowindex % batchSize == 0) {
						ps.executeBatch();
					}
					
				}
				
				ps.executeBatch(); // insert remaining records
				con.commit();
			}else {
				FileInputStream fis=new FileInputStream(csvFile);
				XSSFWorkbook workbook=new XSSFWorkbook(fis);
				fis.close();
				int rowindex=0;
				int columnindex=0;
				//시트 수 (첫번째에만 존재하므로 0을 준다)
				//만약 각 시트를 읽기위해서는 FOR문을 한번더 돌려준다
				XSSFSheet sheet=workbook.getSheetAt(0);
				//행의 수
				final int batchSize = 1000;
				int rows=sheet.getPhysicalNumberOfRows();
				int hdChk = 0;
				if (FILE_FIRSTROW_HD.equals("True"))
	            {
					hdChk = 1;
	            }
				XSSFRow rowheaders=sheet.getRow(rowindex);
				int cells=rowheaders.getPhysicalNumberOfCells();
				for(rowindex=hdChk;rowindex<rows;rowindex++){
				    //행을읽는다
				    XSSFRow row=sheet.getRow(rowindex);
				    if(row !=null){
				        //셀의 수
				        
				        for(columnindex=0;columnindex<cells;columnindex++){
				            //셀값을 읽는다
				            XSSFCell cell=row.getCell(columnindex);
				            String value="";
				            /*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 임시 shlim 20210120*/
				            String coltype = colInfo.get(columnindex).get("colType");	
				            //셀이 빈값일경우를 위한 널체크
				            if(cell==null){
//				                continue;
				            	value="";
				            }else{
				                //타입별로 내용 읽기
				                switch (cell.getCellTypeEnum()){
				                case FORMULA:
				                    value=cell.getCellFormula();
				                    break;
				                case NUMERIC:
				                	/*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 임시 shlim 20210120*/
				                	if(coltype.equalsIgnoreCase("decimal") || coltype.equalsIgnoreCase("float") ) {
				                		value= cell.getNumericCellValue()+"";
				                	}else {
				                		value= (int)cell.getNumericCellValue()+"";
				                	}
				                    
				                    break;
				                case STRING:
				                    value=cell.getStringCellValue()+"";
				                    break;
				                case BLANK:
				                    //value=cell.getBooleanCellValue()+"";
				                	value="";
				                    break;
				                case ERROR:
				                    value=cell.getErrorCellValue()+"";
				                    break;
				                }
				            }
				            /*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 임시 shlim 20210120*/
				            //String coltype = colInfo.get(columnindex).get("colType");
							if(coltype.equalsIgnoreCase("int"))
							{
								if(value.equals(""))
									ps.setNull(columnindex + 1, java.sql.Types.INTEGER);
								else
									ps.setInt(columnindex + 1, Integer.parseInt(value));
							}
							/*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 임시 shlim 20210120*/
							else if(coltype.equalsIgnoreCase("decimal") || coltype.equalsIgnoreCase("float") ) {
								if(value.equals(""))
									ps.setNull(columnindex + 1, java.sql.Types.INTEGER);
								else
									ps.setDouble(columnindex + 1, Double.parseDouble(value));
							}
							else
							{
								if(databaseName.equals("Impala") && value.equals("")) {
									ps.setString(columnindex+1, null);
								} else {
									ps.setString(columnindex+1, value);
								}
							}
							
				        }
				        ps.addBatch();
				   }
				    if (rowindex % batchSize == 0) {
						ps.executeBatch();
					}
					
				}
				
				ps.executeBatch(); // insert remaining records
				con.commit();
			}
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
		}
		
	}	
}
