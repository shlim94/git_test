package com.wise.comp.pivotgrid.util;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.commons.lang3.StringUtils;
import org.apache.poi.ss.SpreadsheetVersion;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.DataConsolidateFunction;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.util.AreaReference;
import org.apache.poi.ss.util.CellReference;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFPivotTable;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.openxmlformats.schemas.spreadsheetml.x2006.main.CTPivotField;

import com.wise.common.util.WINumberUtils;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/*
 피벗그리드용 다운로드 Util Class 
 */
public final class PivotGridDownloadUtils {
	
	/*
	  피벗그리드용 sql like Excel Download
	 */
	public static void sqlLikeExcel(final JSONObject content, final JSONArray list
			, final String downloadFilter, final JSONArray paramJsonArray,  final XSSFWorkbook wb) {
		/* 2020.12.18 mksong 주택금융공사 정렬컬럼 피벗테이블 제외 dogfoot */
		int sortColumnCount = content.getInt("sortColumnCount");
			
		JSONArray cols = null;
		JSONArray rows = null;
		JSONObject totalView = null;
		JSONObject dataItems = null;
		JSONArray mea = null;
		JSONArray dim = null;
		
		XSSFSheet pivotSheet = null;
		Boolean isSameName = false;
		int sameIndex = 0;
		
		for(int j = 0; j < wb.getNumberOfSheets(); j++) {
			if(wb.getSheetName(j).equals(content.getString("item"))){
				isSameName = true;
				sameIndex++;
			}
		}
		
		Sheet sh;
		if (isSameName) {
			pivotSheet = wb.createSheet(content.getString("item") + "_" + sameIndex);
			sh = wb.createSheet(content.getString("item") + "data" + sameIndex);
		}
		else {
			pivotSheet = wb.createSheet(content.getString("item"));
			sh = wb.createSheet(content.getString("item") + "data");
		}
			
		// 행열변경 처리
		Boolean colRowSwitch = content.get("colRowSwitch") == null ? false : content.getBoolean("colRowSwitch");
		if (colRowSwitch) {
			cols = content.getJSONArray("rows");
			rows = content.getJSONArray("cols");
		}
		else {
			cols = content.getJSONArray("cols");
			rows = content.getJSONArray("rows");
		}
		
		totalView = content.getJSONObject("totalView");
		dataItems = content.getJSONObject("dataItems");
		mea = dataItems.getJSONArray("Measure");
		String memoText = content.getString("memoText");
		
		int headerNo = 1;
		int addRowNum = 0;			// yyb 2021-04-01 엑셀 로우 시작 넘버
		/* 2020.11.23 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
		
		if (downloadFilter.equals("Y")) {
			if(paramJsonArray.size() != 0) {
				headerNo = paramJsonArray.size() + 2;
				pivotSheet.createRow(0).createCell(0).setCellValue("필터 차원");
				pivotSheet.getRow(0).createCell(1).setCellValue("조건 값");
				for(int j = 0; j < paramJsonArray.size(); j++) {
					pivotSheet.createRow(j+1).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
					if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
						pivotSheet.getRow(j+1).createCell(1).setCellValue("전체");
					}else {
						String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
						paramValue = paramValue.replace("]", "");
						pivotSheet.getRow(j+1).createCell(1).setCellValue(paramValue);
					}
				}
			}
		}
		
		Row heading;

		ArrayList<String> columns = null;
		if (list.size() > 0) {
			columns = new ArrayList<String>();
			JSONObject jobj =  new JSONObject();
			
			// yyb 2021-04-14 순서를 다시 정렬한 list가 있으면 해당 순서대로 컬럼 리스트를 만든다.
			if (content.has("dataItems2")) {
				JSONArray arr = content.getJSONArray("dataItems2");
				for (int i = 0; i < arr.size(); i++) {
					JSONObject obj = arr.getJSONObject(i);
					String key = obj.getString("dataField");
					jobj.put(key, key);
				}
			}
			else {
				jobj = list.getJSONObject(0);
			}
				
			// 행열변환으로 인해 컬럼 순서 다시 지정
			if (colRowSwitch) {
				for (Object item : cols) {
					String column = ((JSONObject)item).get("name").toString();
					columns.add(column);
				}
				for (Object item : rows) {
					String column = ((JSONObject)item).get("name").toString();
					columns.add(column);
				}
			}
			
			Iterator<?> keys = jobj.keys();
			while (keys.hasNext()) {
				Object key = keys.next();
				
				// columns에 속하지 않을때만 추가해줌
				if (columns.stream().filter(f -> f.equals(key.toString())).count() == 0) {
					columns.add(key.toString());
				}
			}
				
			/* 2021-03-23 yyb 텍스트라벨 */
			if (StringUtils.isNotBlank(memoText)) {
				pivotSheet.createRow(headerNo - 1).createCell(columns.size() - 1, CellType.STRING).setCellValue(memoText);
				headerNo++;
			}

			/* 타이틀 */
			heading = sh.createRow(addRowNum);
			for (int i = 0; i < columns.size() - sortColumnCount; i++) {
				Cell cell = heading.createCell(i);
				cell.setCellValue(columns.get(i).toString());
			}
				
			for (int j = 0; j < list.size(); j++) {
				Row row = sh.createRow(j + 1);
				JSONObject item = list.getJSONObject(j);
				for (int i = 0; i < columns.size() - sortColumnCount; i++) {
					// 2021-06-15 yyb 정도표시 오류로 수정
					String colValue = item.getString(columns.get(i));
					if(i >= cols.size() + rows.size()) {
						Cell cell = row.createCell(i);
						/* Number 형식인지 체크 */
						if (WINumberUtils.isNumber(colValue)) {
							BigDecimal b = new BigDecimal(colValue);
							// 소숫점 판별
							if (colValue.contains(".")) {
								cell.setCellValue(b.doubleValue()); 	// longValue가 아닌 doubleValue 사용
							}
							else {
								cell.setCellValue(b.longValue());
							}
						}
						else {
							cell.setCellValue(colValue);
						}
						
					} else {
						row.createCell(i).setCellValue(colValue);
					}
				}
			}
		} 

		XSSFCellStyle style = wb.createCellStyle();
		style.setBorderTop(BorderStyle.THIN);
		style.setBorderBottom(BorderStyle.THIN);
		style.setBorderLeft(BorderStyle.THIN);
		style.setBorderRight(BorderStyle.THIN);
		
		String columnLetter = CellReference.convertNumToColString(columns.size()- sortColumnCount-1);
		int nSize = list.size() + 1;		// yyb 2021-04-01 사이즈 잘리는 오류 수정
		String pivotString = "A1:" + columnLetter + nSize;

		AreaReference areaReference = new AreaReference(pivotString, SpreadsheetVersion.EXCEL2007);
		/* 2020.12.18 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
		XSSFPivotTable pivotTable = pivotSheet.createPivotTable(areaReference, new CellReference("A" + headerNo), sh);
		
		for(int i = 0; i < cols.size(); i++) {
			pivotTable.addColLabel(i);
		}

		for(int i = cols.size(); i < rows.size() + cols.size(); i++) {
			pivotTable.addRowLabel(i);
		}

		for(int i = cols.size() + rows.size(); i < columns.size() - sortColumnCount; i++) {
			boolean IncludeGroupSeparator = false;
			int Precision = 0;
			for(int k = 0; k < mea.size(); k++) {
				JSONObject meaK = mea.getJSONObject(k);
				if(columns.get(i).equals(meaK.getString("Name"))) {
					JSONObject numFormat = meaK.getJSONObject("NumericFormat");
					if(numFormat.has("IncludeGroupSeparator")) {
						// 2021-04-21 yyb NumericFormat의 IncludeGroupSeparator는 Y/N으로 저장되고 있음
						IncludeGroupSeparator = numFormat.getString("IncludeGroupSeparator") == "Y" ? true : false;
					}
					if(numFormat.has("Precision")) {
						Precision = numFormat.getInt("Precision");
					}
				}
			}

			String format = "0";
			if(IncludeGroupSeparator) {
				format = "#,##0";
				if(Precision > 0) {
					format = format + ".";
					for(int k = 0; k < Precision; k++) {
						format = format + "0";
					}
				}
			} else if(Precision > 0) {
				format = "0.";
				for(int k = 0; k < Precision; k++) {
					format = format + "0";
				}
			}
			/* 2020.12.18 mksong 주택금융공사 정렬컬럼 피벗테이블 제외 dogfoot */
			if(i < (columns.size()-sortColumnCount)) {
				pivotTable.addColumnLabel(DataConsolidateFunction.SUM, i, columns.get(i), format);
			}
		}
//				pivotTable.addDataColumn(2, false);
//				pivotTable.addDataColumn(3, false); 
//				pivotTable.getColLabelColumns().remove(columns.size()-1); 						
		if(totalView.getBoolean("ShowColumnGrandTotals") == false) {
			pivotTable.getCTPivotTableDefinition().setColGrandTotals(false);
		}

		if(totalView.getBoolean("ShowRowGrandTotals") == false) {
			pivotTable.getCTPivotTableDefinition().setRowGrandTotals(false);
		}
		
		pivotTable.getCTPivotTableDefinition().setSubtotalHiddenItems(false);
		
		// 텍스트라벨 일단보류
//				if (StringUtils.isNotBlank(memoText)) {
//					int nMemoNum = pivotTable.getCTPivotTableDefinition().getPivotFields().getPivotFieldList().size();
//					pivotSheet.getRow(headerNo - 2).createCell(nMemoNum, CellType.STRING).setCellValue(memoText);
//					
//				}
		
		for (CTPivotField ctPivotField : pivotTable.getCTPivotTableDefinition().getPivotFields().getPivotFieldList()) {
			ctPivotField.setAutoShow(false);
			ctPivotField.setOutline(false);
//					ctPivotField.setSumSubtotal(false);
//					ctPivotField.setProductSubtotal(false);
//					ctPivotField.setDefaultSubtotal(false);
//					ctPivotField.setSubtotalTop(false);
		}
		
		wb.setSheetHidden(wb.getNumberOfSheets() - 1, true);
	}
}
