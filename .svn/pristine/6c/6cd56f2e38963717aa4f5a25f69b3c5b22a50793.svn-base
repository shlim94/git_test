package com.wise.ds.download.util;

import java.awt.Color;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.poi.sl.usermodel.TableCell.BorderEdge;
import org.apache.poi.sl.usermodel.TextParagraph.TextAlign;
import org.apache.poi.sl.usermodel.TextShape.TextAutofit;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xslf.usermodel.XSLFTable;
import org.apache.poi.xslf.usermodel.XSLFTableCell;
import org.apache.poi.xslf.usermodel.XSLFTableRow;
import org.apache.poi.xslf.usermodel.XSLFTextParagraph;
import org.apache.poi.xslf.usermodel.XSLFTextRun;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xwpf.usermodel.ParagraphAlignment;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFTable;
import org.apache.poi.xwpf.usermodel.XWPFTableCell;
import org.apache.poi.xwpf.usermodel.XWPFTableRow;
import org.openxmlformats.schemas.drawingml.x2006.main.CTTableCell;
import org.openxmlformats.schemas.drawingml.x2006.main.CTTableRow;
import org.openxmlformats.schemas.drawingml.x2006.main.STPenAlignment;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTHMerge;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTTblWidth;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTTcPr;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTVMerge;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.STMerge;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.STTblWidth;

//import io.keikai.client.api.Alignment;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class ConvertSheet2PptTableController {
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
			// tblWidth.setType(STTblWidth.DXA);
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
		// System.out.println("First-Row : " + sheet.getFirstRowNum() + " First-Column :
		// " + sheet.getRow(sheet.getFirstRowNum()).getFirstCellNum() + " Last-Row : " +
		// sheet.getLastRowNum() + " Last-Row : " +
		// sheet.getRow(sheet.getLastRowNum()).getLastCellNum());
		// for(int i = 0; i < sheet.getLastRowNum();i++) {
		// for(int j = 0; j < sheet.getRow(i).getLastCellNum(); j++) {
		// if(sheet.getRow(i).getCell(j).getCellType() != CellType.BLANK) {
		// maxRow = i;
		// maxCol = j;
		// }
		// }
		// }

		obj.put("maxRow", sheet.getLastRowNum());
		obj.put("maxCol", sheet.getRow(sheet.getLastRowNum()).getLastCellNum());
		return obj;
	}

	public static void convertXSSF2XSLF(XSLFTable newTable, XSSFSheet sheet) throws Exception {
		int maxColumnNum = 0;
		Map<Integer, XSSFCellStyle> styleMap = new HashMap<>();
		// manage a list of merged zone in order to not insert two times a merged zone
		Set<CellRangeAddressWrapper> mergedRegions = new TreeSet<>();
		List<CellRangeAddress> sheetMergedRegions = sheet.getMergedRegions();
		JSONObject rowAndCol = findLastRowAndColumn(sheet);

		for (int i = sheet.getFirstRowNum(); i <= rowAndCol.getInt("maxRow"); i++) {
			XSSFRow srcRow = sheet.getRow(i);
			XSLFTableRow destRow = null; 
			if (newTable.getNumberOfRows() < i) {
				boolean isAddingRow = true;
				while (isAddingRow) {
					newTable.addRow();
					if (i == newTable.getNumberOfRows()) {
						destRow = newTable.addRow();
						isAddingRow = false;
					}
				}
			} else {
				destRow = newTable.addRow();
			}

			if (srcRow != null) {
				if (rowAndCol.getInt("maxCol") > maxColumnNum) {
					maxColumnNum = rowAndCol.getInt("maxCol");
				}

				for (int j = 0; j < maxColumnNum; j++) {
					destRow.addCell();
				}
				convertXSSFRow2XWPFRow(newTable, srcRow, destRow, styleMap);
			}
		}
		int maxRowNum = rowAndCol.getInt("maxRow");
//		tableSetting(newTable, maxRowNum, maxColumnNum);
		JSONObject controller = mergeDo(newTable, sheetMergedRegions, mergedRegions, maxRowNum, maxColumnNum);
		JSONArray mergeList = controller.getJSONArray("mergeList");
		int basicCount = controller.getInt("basic");
		// System.out.println("maxColumnNum :" + maxColumnNum + "\t GETNUMBEROFROWS : "
		// +newTable.getNumberOfRows());
//		for (int i = 0; i <= newTable.getNumberOfRows(); i++) {
//			XSLFTableRow row = newTable.getRows().get(i);
//			if (row != null) {
//
//				for (int j = 0; j < maxColumnNum; j++) {
//					int temp = 0;
//					if (row.getCells().get(j + maxColumnNum) != null) {
//						temp = j + maxColumnNum;
//						// System.out.println("삭제한 행 :" + i + " 삭제한 열: " + temp);
//						row.getCells().remove(j + maxColumnNum);
//					} else {
//						temp = j + maxColumnNum;
//						// System.out.println("ROW: " + i + " null : " + temp);
//					}
//					// tempMain = temp;
//				}
//
//				for (int k = 0; k <= basicCount; k++) {
//					if (row.getCells().get(maxColumnNum) != null) {
//						row.getCells().remove(maxColumnNum);
//					}
//				}
//			}
//		}
//
//		for (int i = 0; i < mergeList.size(); i++) {
//			JSONObject obj = mergeList.getJSONObject(i);
//			XSLFTableRow row = newTable.getRows().get(obj.getInt("row"));
//			// System.out.println("i : " + i + "\t mergeList : " + mergeList.size() + "count
//			// : " + obj.getInt("count"));
//
//			for (int k = 0; k <= obj.getInt("count"); k++) {
//				if (row.getCells().get(maxColumnNum - k) != null) {
//					row.getCells().remove(maxColumnNum - k);
//				}
//			}
//		}

	}

	public static void convertXSSFRow2XWPFRow(XSLFTable destTable, XSSFRow srcRow, XSLFTableRow destRow,
			Map<Integer, XSSFCellStyle> styleMap) throws Exception {
		destRow.setHeight(srcRow.getHeight());
		// pour chaque row
		destRow.setHeight(13.);
		for (int j = srcRow.getFirstCellNum(); j <= srcRow.getLastCellNum(); j++) {
			XSSFCell oldCell = srcRow.getCell(j); // ancienne cell
			XSLFTableCell newCell = null;
			if (oldCell != null) {
				if (destRow.getCells().size() < j) {
					boolean isAddingCell = true;
					while (isAddingCell) {
						destRow.addCell();
						if (destRow.getCells().size() == j) {
							newCell = destRow.getCells().get(j);
							isAddingCell = false;
						}
					}
				}else {
					newCell = destRow.getCells().get(j);
				}
				convertXSSFCell2XSLFTableCell(oldCell, newCell, styleMap);
				newCell.setBorderWidth(BorderEdge.bottom, 1);
				newCell.setBorderColor(BorderEdge.bottom,Color.BLACK);
				newCell.setBorderWidth(BorderEdge.top, 1);
				newCell.setBorderColor(BorderEdge.top,Color.BLACK);
				newCell.setBorderWidth(BorderEdge.left, 1);
				newCell.setBorderColor(BorderEdge.left,Color.BLACK);
				newCell.setBorderWidth(BorderEdge.right, 1);
				newCell.setBorderColor(BorderEdge.right,Color.BLACK);
				newCell.setTextAutofit(TextAutofit.SHAPE);
			}
		}
	}

	private static JSONObject mergeDo(XSLFTable destTable, List<CellRangeAddress> sheetMergedRegions,
			Set<CellRangeAddressWrapper> mergedRegions, int maxRowNum, int maxColumnNum) throws Exception {
		JSONObject control = new JSONObject();
		JSONArray mergeList = new JSONArray();
		int tempMain = maxColumnNum;
		for (CellRangeAddress mergedRegion : sheetMergedRegions) {
			JSONObject mergeobj = new JSONObject();
			int temp = 0;
			if (mergedRegion != null) {
				CellRangeAddress newMergedRegion = new CellRangeAddress(mergedRegion.getFirstRow(),
						mergedRegion.getLastRow(), mergedRegion.getFirstColumn(), mergedRegion.getLastColumn());
				CellRangeAddressWrapper wrapper = new CellRangeAddressWrapper(newMergedRegion);
				if (isNewMergedRegion(wrapper, mergedRegions)) {
					mergedRegions.add(wrapper);
//					System.out.println(wrapper.range.formatAsString());
					destTable.mergeCells(wrapper.range.getFirstRow(), wrapper.range.getLastRow(), wrapper.range.getFirstColumn(), wrapper.range.getLastColumn()); 
//					JSONObject obj = convertMergeRegion(wrapper);
//					if (obj.get("orientation").equals("horizontal")) {
//						// System.out.println("row : "+obj.get("row").toString() + "\t from :" +
//						// obj.get("from").toString() + "\t to : " + obj.get("to").toString());
//						temp = mergeCellHorizontally(destTable, Integer.parseInt(obj.get("row").toString()),
//								Integer.parseInt(obj.get("from").toString()),
//								Integer.parseInt(obj.get("to").toString()), maxColumnNum);
//						mergeobj.put("row", Integer.parseInt(obj.get("row").toString()));
//						mergeobj.put("count", temp);
//						mergeList.add(mergeobj);
//					} else if (obj.get("orientation").equals("vertical")) {
//						// System.out.println("col : "+obj.get("col").toString() + "\t from :" +
//						// obj.get("from").toString() + "\t to : " + obj.get("to").toString());
//						mergeCellVertically(destTable, Integer.parseInt(obj.get("col").toString()),
//								Integer.parseInt(obj.get("from").toString()),
//								Integer.parseInt(obj.get("to").toString()));
//					} else {
//						for (int i = 0; i < obj.getJSONArray("array").size(); i++) {
//							JSONObject object = (JSONObject) obj.getJSONArray("array").get(i);
//
//							if (object.get("orientation").equals("vertical")) {
//								// System.out.println("col : "+object.get("col").toString() + "\t from :" +
//								// object.get("from").toString() + "\t to : " + object.get("to").toString());
//								mergeCellVertically(destTable, Integer.parseInt(object.get("col").toString()),
//										Integer.parseInt(object.get("from").toString()),
//										Integer.parseInt(object.get("to").toString()));
//							} else {
//								System.out.println("row : " + object.get("row").toString() + "\t from :"
//										+ object.get("from").toString() + "\t to : " + object.get("to").toString());
//								temp = mergeCellHorizontally(destTable, Integer.parseInt(object.get("row").toString()),
//										Integer.parseInt(object.get("from").toString()),
//										Integer.parseInt(object.get("to").toString()), maxColumnNum);
//								mergeobj.put("row", Integer.parseInt(object.get("row").toString()));
//								mergeobj.put("count", temp);
//								mergeList.add(mergeobj);
//							}
//						}
//					}
				}
				if (maxColumnNum < temp) {
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
		// System.out.println(wrapper.range.formatAsString());

		if (wrapper.range.getFirstRow() == wrapper.range.getLastRow()
				&& wrapper.range.getFirstColumn() != wrapper.range.getLastColumn()) {
			obj.put("orientation", "horizontal");
			obj.put("row", wrapper.range.getFirstRow());
			obj.put("from", wrapper.range.getFirstColumn());
			obj.put("to", wrapper.range.getLastColumn());
		} else if (wrapper.range.getFirstRow() != wrapper.range.getLastRow()
				&& wrapper.range.getFirstColumn() == wrapper.range.getLastColumn()) {
			obj.put("orientation", "vertical");
			obj.put("col", wrapper.range.getFirstColumn());
			obj.put("from", wrapper.range.getFirstRow());
			obj.put("to", wrapper.range.getLastRow());
		} else if (wrapper.range.getFirstRow() != wrapper.range.getLastRow()
				&& wrapper.range.getFirstColumn() != wrapper.range.getLastColumn()) {
			JSONArray array = new JSONArray();
			JSONObject tempVertical = new JSONObject();
			JSONObject tempHorizontal = new JSONObject();

			tempVertical.put("orientation", "vertical");
			tempVertical.put("col", wrapper.range.getFirstColumn());
			tempVertical.put("from", wrapper.range.getFirstRow());
			tempVertical.put("to", wrapper.range.getLastRow());
			array.add(tempVertical);
			tempHorizontal.put("orientation", "horizontal");
			tempHorizontal.put("row", wrapper.range.getFirstRow());
			tempHorizontal.put("from", wrapper.range.getFirstColumn());
			tempHorizontal.put("to", wrapper.range.getLastColumn());
			array.add(tempHorizontal);
			obj.put("orientation", "both");
			obj.put("array", array);
		}

		return obj;
	}

	private static boolean isNewMergedRegion(CellRangeAddressWrapper newMergedRegion,
			Set<CellRangeAddressWrapper> mergedRegions) throws Exception {
		boolean check = false;
		for (CellRangeAddressWrapper s : mergedRegions) {
			if (s.range.formatAsString().equals(newMergedRegion.range.formatAsString())) {
				check = true;
			}
		}
		return !check;
	}

	public static void convertXSSFCell2XSLFTableCell(XSSFCell oldCell, XSLFTableCell newCell,
			Map<Integer, XSSFCellStyle> styleMap) throws Exception {
		String text = "";
		XSLFTextParagraph textparagraph = newCell.addNewTextParagraph();
		XSLFTextRun textrun = textparagraph.addNewTextRun();
		switch (oldCell.getCellTypeEnum()) {
		case STRING:
			textparagraph.setTextAlign(TextAlign.LEFT);
			text = oldCell.getStringCellValue();
			break;
		case NUMERIC:
			textparagraph.setTextAlign(TextAlign.RIGHT);
			text = oldCell.getRawValue();
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
			textparagraph.setTextAlign(TextAlign.LEFT);
			text = oldCell.getStringCellValue();
			break;
		}
		textrun.setFontSize(10.0);
		textrun.setText(text);

	}

	public static void mergeCellVertically(XWPFTable table, int col, int fromRow, int toRow) throws Exception {
		for (int rowIndex = fromRow; rowIndex <= toRow; rowIndex++) {
			if (table.getRow(rowIndex) == null) {
				boolean check = true;
				while (check) {
					if (table.getRow(rowIndex) == null) {
						table.createRow();
					} else {
						check = false;
					}
				}
			}

			if (table.getRow(rowIndex).getCell(col) == null) {
				boolean check2 = true;
				while (check2) {
					if (table.getRow(rowIndex).getCell(col) == null) {
						table.getRow(rowIndex).createCell();
					} else {
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
				cell.addParagraph();
			}
			// Try getting the TcPr. Not simply setting an new one every time.
			CTTcPr tcPr = cell.getCTTc().getTcPr();
			if (tcPr == null)
				tcPr = cell.getCTTc().addNewTcPr();
			tcPr.setVMerge(vmerge);
		}
	}

//	public static int mergeCellHorizontally(XSLFTable table, int row, int fromCol, int toCol, int maxColumnNum)
//			throws Exception {
//		int checkNull = 0;
//		int mergeCount = toCol - fromCol;
//		for (int i = 0; i <= maxColumnNum; i++) {
//			if (table.getRows().get(row).getCells().get(i) == null) {
//				checkNull++;
//			}
//		}
//
//		fromCol -= checkNull;
//		toCol -= checkNull;
//		
//		XSLFTableCell cell = table.getRows().get(row).getCells().get(fromCol);
//		// Try getting the TcPr. Not simply setting an new one every time.
//		CTTcPr tcPr = cell.getCTTc().getTcPr();
//		if (tcPr == null)
//			tcPr = cell.getCTTc().addNewTcPr();
//		// The first merged cell has grid span property set
//		if (tcPr.isSetGridSpan()) {
//			tcPr.getGridSpan().setVal(BigInteger.valueOf(toCol - fromCol + 1));
//		} else {
//			tcPr.addNewGridSpan().setVal(BigInteger.valueOf(toCol - fromCol + 1));
//		}
//		// Cells which join (merge) the first one, must be removed
//		for (int colIndex = toCol; colIndex > fromCol; colIndex--) {
//			table.getRow(row).getCtRow().removeTc(colIndex);
//			table.getRow(row).removeCell(colIndex);
//		}
//		return mergeCount;
//	}

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
