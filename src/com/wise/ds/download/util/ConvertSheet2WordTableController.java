package com.wise.ds.download.util;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xwpf.usermodel.ParagraphAlignment;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFParagraph;
import org.apache.poi.xwpf.usermodel.XWPFRun;
import org.apache.poi.xwpf.usermodel.XWPFTable;
import org.apache.poi.xwpf.usermodel.XWPFTableCell;
import org.apache.poi.xwpf.usermodel.XWPFTableRow;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTTblWidth;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTTcPr;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTVMerge;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.STMerge;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.STTblWidth;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class ConvertSheet2WordTableController {
	public static void tableSetting(XWPFTable table, int maxRowNum, int maxColumnNum) throws Exception {
		// create CTTblGrid for this table with widths of the 5 columns.
		// necessary for Libreoffice/Openoffice to accept the column widths.
		// values are in unit twentieths of a point (1/1440 of an inch)
		// first column = 1 inches width
		table.getCTTbl().addNewTblGrid().addNewGridCol().setW(BigInteger.valueOf(1 * 140));
		// other columns (2 in this case) also each 1 inches width
		for (int col = 1; col < maxColumnNum; col++) {
			table.getCTTbl().getTblGrid().addNewGridCol().setW(BigInteger.valueOf(1 * 140));
		}
		
		// create and set column widths for all columns in all rows
		// most examples don't set the type of the CTTblWidth but this
		// is necessary for working in all office versions
		for (int col = 0; col < maxColumnNum; col++) {
			CTTblWidth tblWidth = CTTblWidth.Factory.newInstance();
			tblWidth.setW(BigInteger.valueOf(1 * 1440));
//			tblWidth.setType(STTblWidth.DXA);
			tblWidth.setType(STTblWidth.AUTO);
			for (int row = 0; row < maxRowNum; row++) {
				CTTcPr tcPr = table.getRow(row).getCell(col).getCTTc().getTcPr();
				if (tcPr != null) {
					tcPr.setTcW(tblWidth);
				} else {
					tcPr = CTTcPr.Factory.newInstance();
					tcPr.setTcW(tblWidth);
					table.getRow(row).getCell(col).getCTTc().setTcPr(tcPr);
				}
			}
		}
	}
	
	private static JSONObject findLastRowAndColumn(XSSFSheet sheet) throws Exception {
		JSONObject obj = new JSONObject();
		obj.put("maxRow", sheet.getLastRowNum());
		obj.put("maxCol", sheet.getRow(sheet.getLastRowNum()).getLastCellNum());
		return obj;
	}
	
	public static void convertXSSF2XWPF(XWPFTable newTable, XSSFSheet sheet) throws Exception {
		int maxColumnNum = 0;
		Map<Integer, XSSFCellStyle> styleMap = new HashMap<>();
		// manage a list of merged zone in order to not insert two times a merged zone
		Set<CellRangeAddressWrapper> mergedRegions = new TreeSet<>();
		List<CellRangeAddress> sheetMergedRegions = sheet.getMergedRegions();
		JSONObject rowAndCol = findLastRowAndColumn(sheet);
		
		for (int i = sheet.getFirstRowNum(); i <= rowAndCol.getInt("maxRow"); i++) {
			XSSFRow srcRow = sheet.getRow(i);
			XWPFTableRow destRow = null;
			if(newTable.getRow(i) == null) {
				for(int k = 0; k <= i; k++) {
					if(newTable.getRow(k) == null) {
						newTable.createRow();
					}
				}
				destRow = newTable.getRow(i);
			}else {
				destRow = newTable.getRow(i);	
			}
			
			if (srcRow != null) {
				if (rowAndCol.getInt("maxCol") > maxColumnNum) {
					maxColumnNum = rowAndCol.getInt("maxCol");
				}
				
				for(int j = 0; j < maxColumnNum; j++) {
					destRow.createCell();
				}
				convertXSSFRow2XWPFRow(newTable, srcRow, destRow, styleMap);
			}
		}
		int maxRowNum = rowAndCol.getInt("maxRow");
		tableSetting(newTable, maxRowNum, maxColumnNum);
		JSONObject controller = mergeDo(newTable, sheetMergedRegions, mergedRegions, maxRowNum,  maxColumnNum);
		JSONArray mergeList = controller.getJSONArray("mergeList");
		int basicCount = controller.getInt("basic");
		for (int i = 0; i <= newTable.getNumberOfRows(); i++) {
			XWPFTableRow row = newTable.getRow(i);
			if(row != null) {
				boolean rowSynchronized = true;
				while(rowSynchronized) {
					int rowLength = row.getTableCells().size();
					if(rowLength > basicCount) {
						if(row.getCell(basicCount) != null) {
							row.getCtRow().removeTc(basicCount);
							row.removeCell(basicCount);	
						}else {
							rowSynchronized = false;
						}
					}else if(rowLength < basicCount){
						row.addNewTableCell();
					}else {
						rowSynchronized = false;
					}
				}
			}
		}
	
		if(mergeList.size() > 0) {
			int cellSize = 0;
			JSONObject obj2 = mergeList.getJSONObject(0);
			int rowNum = obj2.getInt("row");
			JSONArray mergeArray = new JSONArray();
			for (int i = 0; i < mergeList.size(); i++) {
				JSONObject obj = mergeList.getJSONObject(i);
				if(rowNum != obj.getInt("row")) {
					JSONObject mergeObj = new JSONObject();
					mergeObj.put("row", rowNum);
					mergeObj.put("count", cellSize);
					mergeArray.add(mergeObj);
					cellSize = obj.getInt("count");
					rowNum = obj.getInt("row");
				} else {
					cellSize = cellSize + obj.getInt("count");
				}
				
				if(i == (mergeList.size()-1)) {
					if(rowNum == obj.getInt("row")) {
						JSONObject mergeObj = new JSONObject();
						mergeObj.put("row", rowNum);
						mergeObj.put("count", cellSize);
						mergeArray.add(mergeObj);
					}
				}
			}
			
			int complicatedCellMergedCheck = 0;
			boolean removeFirstRowLastCell = false;
			for (int i = 0; i < mergeArray.size(); i++) {
				JSONObject obj = mergeArray.getJSONObject(i);
				XWPFTableRow row = newTable.getRow(obj.getInt("row"));
				if(obj.getInt("row") == 0) {
					if(complicatedCellMergedCheck != 0) {
						removeFirstRowLastCell = true;
					}
					complicatedCellMergedCheck++;
				}
				int mergeCount = obj.getInt("count");
				if(obj.getInt("row") == 0 && removeFirstRowLastCell) {
					mergeCount++;
				}
				
				for(int k = 0; k <= mergeCount; k++) {
					if(row.getCell(basicCount-k) != null) {
						row.getCell(basicCount-k).removeParagraph(0);
						row.getCtRow().removeTc(basicCount - k);
						row.removeCell(basicCount - k);	
					}
				}
			}
		}

	}

	public static void convertXSSFRow2XWPFRow(XWPFTable destTable, XSSFRow srcRow, XWPFTableRow destRow, Map<Integer, XSSFCellStyle> styleMap) throws Exception {
		destRow.setHeight(srcRow.getHeight());
		// pour chaque row
		for (int j = srcRow.getFirstCellNum(); j <= srcRow.getLastCellNum(); j++) {
			XSSFCell oldCell = srcRow.getCell(j); // ancienne cell
			XWPFTableCell newCell = destRow.getCell(j); // new cell
			if (oldCell != null) {
				if (newCell == null) {
					newCell = destRow.createCell();
				}
				convertXSSFCell2XWPFTableCell(oldCell, newCell, styleMap);
			}
		}
	}
	
	private static JSONObject mergeDo (XWPFTable destTable, List<CellRangeAddress> sheetMergedRegions, Set<CellRangeAddressWrapper> mergedRegions, int maxRowNum, int maxColumnNum) throws Exception {
		JSONObject control = new JSONObject();
		JSONArray mergeList = new JSONArray();
		int tempMain = maxColumnNum;
		for (CellRangeAddress mergedRegion : sheetMergedRegions) {
			JSONObject mergeobj = new JSONObject();
			int temp = 0;
			if (mergedRegion != null) {
				CellRangeAddress newMergedRegion = new CellRangeAddress(mergedRegion.getFirstRow(),	mergedRegion.getLastRow(), mergedRegion.getFirstColumn(), mergedRegion.getLastColumn());
				CellRangeAddressWrapper wrapper = new CellRangeAddressWrapper(newMergedRegion);
				if (isNewMergedRegion(wrapper, mergedRegions)) {
					mergedRegions.add(wrapper);
					JSONObject obj = convertMergeRegion(wrapper);
					if(obj.get("orientation").equals("horizontal")) {
						temp = mergeCellHorizontally(destTable, Integer.parseInt(obj.get("row").toString()), Integer.parseInt(obj.get("from").toString()), Integer.parseInt(obj.get("to").toString()), maxColumnNum);
						mergeobj.put("row", Integer.parseInt(obj.get("row").toString()));
						mergeobj.put("count", temp);
						
//						System.out.println(mergeobj);
						mergeList.add(mergeobj);
					}else if(obj.get("orientation").equals("vertical")) {
//						System.out.println("col : "+obj.get("col").toString() + "\t from :" + obj.get("from").toString() + "\t to : " + obj.get("to").toString());
						mergeCellVertically(destTable, Integer.parseInt(obj.get("col").toString()), Integer.parseInt(obj.get("from").toString()), Integer.parseInt(obj.get("to").toString()));
					}else {
						for(int i = 0; i < obj.getJSONArray("array").size(); i++) {
							JSONObject object = (JSONObject) obj.getJSONArray("array").get(i);
							
							if(object.get("orientation").equals("vertical")) {
//								System.out.println("col : "+object.get("col").toString() + "\t from :" + object.get("from").toString() + "\t to : " + object.get("to").toString());
								mergeCellVertically(destTable, Integer.parseInt(object.get("col").toString()), Integer.parseInt(object.get("from").toString()), Integer.parseInt(object.get("to").toString()));	
							}else {
//								System.out.println("row : "+object.get("row").toString() + "\t from :" + object.get("from").toString() + "\t to : " + object.get("to").toString());
								temp = mergeCellHorizontally(destTable, Integer.parseInt(object.get("row").toString()), Integer.parseInt(object.get("from").toString()), Integer.parseInt(object.get("to").toString()), maxColumnNum);
								mergeobj.put("row", Integer.parseInt(object.get("row").toString()));
								mergeobj.put("count", temp);
								mergeList.add(mergeobj);
							}
						}
					}
				}
				if(maxColumnNum < temp) {
					tempMain = temp;
				}
			}
		}
		
		control.put("basic", tempMain);
		control.put("mergeList", mergeList);
		
		return control;
	}

	private static JSONObject convertMergeRegion(CellRangeAddressWrapper wrapper) throws Exception {
		JSONObject obj = new JSONObject();
//		System.out.println(wrapper.range.formatAsString());
		
		if(wrapper.range.getFirstRow() == wrapper.range.getLastRow() && wrapper.range.getFirstColumn() != wrapper.range.getLastColumn()) {
			obj.put("orientation", "horizontal");
			obj.put("row", wrapper.range.getFirstRow());
			obj.put("from", wrapper.range.getFirstColumn());
			obj.put("to", wrapper.range.getLastColumn());
		}else if (wrapper.range.getFirstRow() != wrapper.range.getLastRow() && wrapper.range.getFirstColumn() == wrapper.range.getLastColumn()) {
			obj.put("orientation", "vertical");
			obj.put("col", wrapper.range.getFirstColumn());
			obj.put("from", wrapper.range.getFirstRow());
			obj.put("to", wrapper.range.getLastRow());
		}else if(wrapper.range.getFirstRow() != wrapper.range.getLastRow() && wrapper.range.getFirstColumn() != wrapper.range.getLastColumn()) {
			JSONArray array = new JSONArray();
			JSONObject tempVertical = new JSONObject();

			for(int i = 0; i <= (wrapper.range.getLastRow() - wrapper.range.getFirstRow()) ; i++) {
				JSONObject tempHorizontal = new JSONObject();
				tempHorizontal.put("orientation", "horizontal");
				tempHorizontal.put("row", wrapper.range.getFirstRow()+i);
				tempHorizontal.put("from", wrapper.range.getFirstColumn());
				tempHorizontal.put("to", wrapper.range.getLastColumn());
				array.add(tempHorizontal);
			}
			
			tempVertical.put("orientation", "vertical");
			tempVertical.put("col", wrapper.range.getFirstColumn());
			tempVertical.put("from", wrapper.range.getFirstRow());
			tempVertical.put("to", wrapper.range.getLastRow());
			array.add(tempVertical);
			
			obj.put("orientation", "both");
			obj.put("array", array);
		}
		
		return obj;
	}
	
	private static boolean isNewMergedRegion(CellRangeAddressWrapper newMergedRegion, Set<CellRangeAddressWrapper> mergedRegions) throws Exception {
		boolean check = false;
		for (CellRangeAddressWrapper s : mergedRegions) {
			if (s.range.formatAsString().equals(newMergedRegion.range.formatAsString())) {
				check = true;
			}
		}
		return !check;
	}

	public static void convertXSSFCell2XWPFTableCell(XSSFCell oldCell, XWPFTableCell newCell, Map<Integer, XSSFCellStyle> styleMap) throws Exception {
		String text = "";
		XWPFParagraph newCellPara = newCell.getParagraphArray(0);
		XWPFRun r = newCellPara.createRun();
		switch (oldCell.getCellType()) {
		case STRING:
			newCellPara.setAlignment(ParagraphAlignment.LEFT);
			text = oldCell.getStringCellValue();
			r.setText(text);
			break;
		case NUMERIC:
			newCellPara.setAlignment(ParagraphAlignment.RIGHT);
			text = oldCell.getRawValue();
			r.setText(text);
			break;
		// case BLANK:
		// newCell.setCellType(CellType.BLANK);
		// break;
		// case BOOLEAN:
		// newCell.setCellValue(oldCell.getBooleanCellValue());
		// break;
		// case ERROR:
		// newCell.setCellErrorValue(oldCell.getErrorCellValue());
		// break;
		// case FORMULA:
		// newCell.setCellFormula(oldCell.getCellFormula());
		// break;
		default:
			newCellPara.setAlignment(ParagraphAlignment.RIGHT);
			text = oldCell.getStringCellValue();
			r.setText(text);
			break;
		}
		
		
		
	}

	public static void mergeCellVertically(XWPFTable table, int col, int fromRow, int toRow) throws Exception {
		for (int rowIndex = fromRow; rowIndex <= toRow; rowIndex++) {
			if(table.getRow(rowIndex) == null) {
				boolean check = true;
				while(check) {
					if(table.getRow(rowIndex) == null) {
						table.createRow();	
					}else {
						check = false;
					}
				}
			}
			
			if(table.getRow(rowIndex).getCell(col) == null) {
				boolean check2 = true;
				while(check2) {
					if(table.getRow(rowIndex).getCell(col) == null) {
						table.getRow(rowIndex).createCell();	
					}else {
						check2 = false;
					}
					
				}
			}
			
			XWPFTableCell cell = table.getRow(rowIndex).getCell(col);
			CTVMerge vmerge = CTVMerge.Factory.newInstance();
			if (rowIndex == fromRow) {
				// The first merged cell is set with RESTART merge value
				vmerge.setVal(STMerge.RESTART);
			} else {
				// Cells which join (merge) the first one, are set with CONTINUE
				vmerge.setVal(STMerge.CONTINUE);
				// and the content should be removed
				for (int i = cell.getParagraphs().size(); i > 0; i--) {
					cell.removeParagraph(0);
				}
				if(cell.getParagraphs().size() == 0) {
					cell.addParagraph();
				}else {
					cell.removeParagraph(0);
				}
			}
			// Try getting the TcPr. Not simply setting an new one every time.
			CTTcPr tcPr = cell.getCTTc().getTcPr();
			if (tcPr == null)
				tcPr = cell.getCTTc().addNewTcPr();
			tcPr.setVMerge(vmerge);
		}
	}

	public static int mergeCellHorizontally(XWPFTable table, int row, int fromCol, int toCol, int maxColumnNum) throws Exception {
		int checkNull = 0;
		int mergeCount = toCol - fromCol;
		for(int i = 0; i <= maxColumnNum; i++) {
			if(table.getRow(row).getCell(i) == null) {
				checkNull++;
			}
		}
		
		fromCol -= checkNull;
		toCol -= checkNull;
		
		XWPFTableCell cell = table.getRow(row).getCell(fromCol);
		// Try getting the TcPr. Not simply setting an new one every time.
		CTTcPr tcPr = cell.getCTTc().getTcPr();
		if (tcPr == null)
			tcPr = cell.getCTTc().addNewTcPr();
		// The first merged cell has grid span property set
		if (tcPr.isSetGridSpan()) {
			tcPr.getGridSpan().setVal(BigInteger.valueOf(toCol - fromCol + 1));
		} else {
			tcPr.addNewGridSpan().setVal(BigInteger.valueOf(toCol - fromCol + 1));
		}
		// Cells which join (merge) the first one, must be removed
		for (int colIndex = toCol; colIndex > fromCol; colIndex--) {
			table.getRow(row).getCtRow().removeTc(colIndex);
			table.getRow(row).removeCell(colIndex);
		}
		return mergeCount;
	}

	public static int getImageFormat(String imgFileName) throws Exception {
		int format;
		if (imgFileName.endsWith(".emf"))
			format = XWPFDocument.PICTURE_TYPE_EMF;
		else if (imgFileName.endsWith(".wmf"))
			format = XWPFDocument.PICTURE_TYPE_WMF;
		else if (imgFileName.endsWith(".pict"))
			format = XWPFDocument.PICTURE_TYPE_PICT;
		else if (imgFileName.endsWith(".jpeg") || imgFileName.endsWith(".jpg"))
			format = XWPFDocument.PICTURE_TYPE_JPEG;
		else if (imgFileName.endsWith(".png"))
			format = XWPFDocument.PICTURE_TYPE_PNG;
		else if (imgFileName.endsWith(".dib"))
			format = XWPFDocument.PICTURE_TYPE_DIB;
		else if (imgFileName.endsWith(".gif"))
			format = XWPFDocument.PICTURE_TYPE_GIF;
		else if (imgFileName.endsWith(".tiff"))
			format = XWPFDocument.PICTURE_TYPE_TIFF;
		else if (imgFileName.endsWith(".eps"))
			format = XWPFDocument.PICTURE_TYPE_EPS;
		else if (imgFileName.endsWith(".bmp"))
			format = XWPFDocument.PICTURE_TYPE_BMP;
		else if (imgFileName.endsWith(".wpg"))
			format = XWPFDocument.PICTURE_TYPE_WPG;
		else {
			return 0;
		}
		return format;
	}
}
