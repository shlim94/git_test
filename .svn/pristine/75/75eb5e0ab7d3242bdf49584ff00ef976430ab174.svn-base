package com.wise.ds.download.util;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.poi.hssf.usermodel.HSSFCell;
import org.apache.poi.hssf.usermodel.HSSFCellStyle;
import org.apache.poi.hssf.usermodel.HSSFClientAnchor;
import org.apache.poi.hssf.usermodel.HSSFPatriarch;
import org.apache.poi.hssf.usermodel.HSSFPicture;
import org.apache.poi.hssf.usermodel.HSSFPictureData;
import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFShape;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.ClientAnchor;
import org.apache.poi.ss.usermodel.CreationHelper;
import org.apache.poi.ss.usermodel.Drawing;
import org.apache.poi.ss.usermodel.Footer;
import org.apache.poi.ss.usermodel.Header;
import org.apache.poi.ss.usermodel.Name;
import org.apache.poi.ss.usermodel.PrintSetup;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.ss.util.CellReference;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFClientAnchor;
import org.apache.poi.xssf.usermodel.XSSFDrawing;
import org.apache.poi.xssf.usermodel.XSSFName;
import org.apache.poi.xssf.usermodel.XSSFPicture;
import org.apache.poi.xssf.usermodel.XSSFPictureData;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFShape;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.openxmlformats.schemas.drawingml.x2006.spreadsheetDrawing.CTTwoCellAnchor;

import com.ibm.icu.text.NumberFormat;
import com.wise.context.config.Configurator;

public final class MoveSheetController {
	public static void copyXSSFSheets(XSSFWorkbook sourceWB, XSSFWorkbook destinationWB) {
        for (Iterator<Sheet> it = sourceWB.sheetIterator(); it.hasNext(); ) {
            XSSFSheet sheet = (XSSFSheet) it.next();
            String sheetName = sheet.getSheetName();
            if (destinationWB.getSheetIndex(sheetName) != -1) {
                int index = 1;
                while (destinationWB.getSheetIndex(sheetName + "(" + index + ")") != -1) {
                    index++;
                }
                sheetName += "(" + index + ")";
            }
            XSSFSheet newSheet = destinationWB.createSheet(sheetName);
            copySheetSettings(newSheet, sheet);
            copyXSSFSheet(newSheet, sheet);
            copyPictures(newSheet, sheet);
        }
    }
 
    public static void copyXSSFSheet(XSSFSheet newSheet, XSSFSheet sheet) {
        int maxColumnNum = 0;
        Map<Integer, XSSFCellStyle> styleMap = new HashMap<>();
        // manage a list of merged zone in order to not insert two times a merged zone
        Set<CellRangeAddressWrapper> mergedRegions = new TreeSet<>();
        List<CellRangeAddress> sheetMergedRegions = sheet.getMergedRegions();
        for (int i = sheet.getFirstRowNum(); i <= sheet.getLastRowNum(); i++) {
            XSSFRow srcRow = sheet.getRow(i);
            XSSFRow destRow = newSheet.createRow(i);
            if (srcRow != null) {
                copyXSSFRow(newSheet, srcRow, destRow, styleMap, sheetMergedRegions, mergedRegions);
                if (srcRow.getLastCellNum() > maxColumnNum) {
                    maxColumnNum = srcRow.getLastCellNum();
                }
            }
        }
        for (int i = 0; i <= maxColumnNum; i++) {
            newSheet.setColumnWidth(i, sheet.getColumnWidth(i));
        }
    }
 
    public static void copyXSSFRow(XSSFSheet destSheet, XSSFRow srcRow, XSSFRow destRow, Map<Integer, XSSFCellStyle> styleMap, List<CellRangeAddress> sheetMergedRegions, Set<CellRangeAddressWrapper> mergedRegions) {
        destRow.setHeight(srcRow.getHeight());
        // pour chaque row
        for (int j = srcRow.getFirstCellNum(); j <= srcRow.getLastCellNum(); j++) {
            XSSFCell oldCell = srcRow.getCell(j);   // ancienne cell
            XSSFCell newCell = destRow.getCell(j);  // new cell
            if (oldCell != null) {
                if (newCell == null) {
                    newCell = destRow.createCell(j);
                }
                // copy chaque cell
                copyXSSFCell(oldCell, newCell, styleMap);
                
                // copy les informations de fusion entre les cellules
                
                for(CellRangeAddress mergedRegion : sheetMergedRegions) {
                	if (mergedRegion != null) {
                        CellRangeAddress newMergedRegion = new CellRangeAddress(mergedRegion.getFirstRow(), mergedRegion.getLastRow(), mergedRegion.getFirstColumn(), mergedRegion.getLastColumn());
                        CellRangeAddressWrapper wrapper = new CellRangeAddressWrapper(newMergedRegion);
                        if (isNewMergedRegion(wrapper, mergedRegions)) {
                            mergedRegions.add(wrapper);
                            destSheet.addMergedRegion(wrapper.range);
                        }
                    }	
                }
//                CellRangeAddress mergedRegion = getMergedRegion(sheetMergedRegions, srcRow.getRowNum(), (short) oldCell.getColumnIndex());
            }
        }
 
    }
    
//    private static CellRangeAddress getMergedRegion(XSSFSheet sheet, int rowNum, short cellNum) {
//    	CellRangeAddress merged = null;
//    	for (int i = 0; i < sheet.getNumMergedRegions(); i++) {
//            merged = sheet.getMergedRegion(i);
// 
//            if (merged.isInRange(rowNum, cellNum)) {
//                return merged;
//            }
//        }
//        return merged;
//    }
    
    private static boolean isNewMergedRegion(CellRangeAddressWrapper newMergedRegion,Set<CellRangeAddressWrapper> mergedRegions) {
    	boolean check = false;
    	for(CellRangeAddressWrapper s : mergedRegions) {
    		if(s.range.formatAsString().equals(newMergedRegion.range.formatAsString())) {
    			check = true;	
    		}
    	}
    	return !check;
	}
    
    /*dogfoot shlim 20210308
     * 문자열 데이터 숫자로만 이루어져 있는지 체크 하는 함수 
     * 사용자 정의 데이터 컬럼명 숫자로 되어있을때 테이블 생성 오류 수정
     * */
    public static boolean checkOnlyNumInString(String s) {
        char tmp;
            for (int i =0; i<s.length(); i++){
                tmp = s.charAt(i);
                
                if(Character.toString(s.charAt(i)) == ".") {
                	
                } else if(Character.isDigit(tmp)==false){
                    return false;
                }
            }
        return true;
    }
    
    public static void copyXSSFCell(XSSFCell oldCell, XSSFCell newCell, Map<Integer, XSSFCellStyle> styleMap) {
    	String companyname = Configurator.getInstance().getConfig("wise.ds.solution.companyname");
        if (styleMap != null) {
            if (oldCell.getSheet().getWorkbook() == newCell.getSheet().getWorkbook()) {
                newCell.setCellStyle(oldCell.getCellStyle());
            } else {
                int stHashCode = oldCell.getCellStyle().hashCode();
                XSSFCellStyle newCellStyle = styleMap.get(stHashCode);
                if (newCellStyle == null) {
                    newCellStyle = newCell.getSheet().getWorkbook().createCellStyle();
                    newCellStyle.cloneStyleFrom(oldCell.getCellStyle());
                    styleMap.put(stHashCode, newCellStyle);
                }
                newCell.setCellStyle(newCellStyle);
            }
        }
        switch (oldCell.getCellType()) {
            case STRING:
                newCell.setCellValue(oldCell.getStringCellValue());
                break;
            case NUMERIC:
            	/*dogfoot 그리드 PDF 다운로드 오류 수정 shlim 20200618*/
            	/*dogfoot PDF 다운로드 오류 수정 shlim 20210430*/
            	oldCell.setCellType(CellType.STRING);
            	
            	if(companyname.equals("고용정보원")) {
            		if(checkOnlyNumInString(oldCell.getStringCellValue().replaceAll(",", ""))) {
                		double num = Double.parseDouble(oldCell.getStringCellValue().replaceAll(",", ""));
//                    	newCell.setCellValue(f.format(num) + "");
                    	newCell.setCellValue(num + "");
                	}else {
                		//double num = Double.parseDouble(oldCell.getStringCellValue().replaceAll(",", ""));
//                    	newCell.setCellValue(f.format(num) + "");
                    	newCell.setCellValue(oldCell.getStringCellValue() + "");
                	}
            	}else {
            		NumberFormat f = NumberFormat.getInstance();
                	f.setGroupingUsed(false);
            		if(checkOnlyNumInString(oldCell.getStringCellValue().replaceAll(",", ""))) {
                		double num = Double.parseDouble(oldCell.getStringCellValue().replaceAll(",", ""));
                    	newCell.setCellValue(f.format(num) + "");
//                    	newCell.setCellValue(num + "");
                	}else {
                		//double num = Double.parseDouble(oldCell.getStringCellValue().replaceAll(",", ""));
//                    	newCell.setCellValue(f.format(num) + "");
                    	newCell.setCellValue(oldCell.getStringCellValue() + "");
                	}
            		
            	}
//            	oldCell.setCellType(CellType.STRING);
//            	newCell.setCellValue(Double.parseDouble(oldCell.getStringCellValue().replaceAll(",", "")));            	
//            	/* DOGFOOT hsshim 1216
//            	 	 * 측정값의 숫자 형식 적용된 보고서가 다운로드 안되는 오류 수정
//            	 */
////        		newCell.setCellValue(Double.parseDouble(oldCell.getStringCellValue().replaceAll(",", "")));
//            	newCell.setCellValue(oldCell.getStringCellValue().replaceAll(",", ""));
//        		newCell.setCellType(CellType.NUMERIC);
                break;
            case BLANK:
                newCell.setCellType(CellType.BLANK);
                break;
            case BOOLEAN:
                newCell.setCellValue(oldCell.getBooleanCellValue());
                break;
            case ERROR:
                newCell.setCellErrorValue(oldCell.getErrorCellValue());
                break;
            case FORMULA:
                newCell.setCellFormula(oldCell.getCellFormula());
                break;
            default:
                break;
        }
 
    }
    
    public static void copySheetSettings(Sheet newSheet, Sheet sheetToCopy) {
    	 
        newSheet.setAutobreaks(sheetToCopy.getAutobreaks());
        newSheet.setDefaultColumnWidth(sheetToCopy.getDefaultColumnWidth());
        newSheet.setDefaultRowHeight(sheetToCopy.getDefaultRowHeight());
        newSheet.setDefaultRowHeightInPoints(sheetToCopy.getDefaultRowHeightInPoints());
        newSheet.setDisplayGuts(sheetToCopy.getDisplayGuts());
        newSheet.setFitToPage(sheetToCopy.getFitToPage());
 
        newSheet.setForceFormulaRecalculation(sheetToCopy.getForceFormulaRecalculation());
 
        PrintSetup sheetToCopyPrintSetup = sheetToCopy.getPrintSetup();
        PrintSetup newSheetPrintSetup = newSheet.getPrintSetup();
 
        newSheetPrintSetup.setPaperSize(sheetToCopyPrintSetup.getPaperSize());
        newSheetPrintSetup.setScale(sheetToCopyPrintSetup.getScale());
        newSheetPrintSetup.setPageStart(sheetToCopyPrintSetup.getPageStart());
        newSheetPrintSetup.setFitWidth(sheetToCopyPrintSetup.getFitWidth());
        newSheetPrintSetup.setFitHeight(sheetToCopyPrintSetup.getFitHeight());
        newSheetPrintSetup.setLeftToRight(sheetToCopyPrintSetup.getLeftToRight());
        newSheetPrintSetup.setLandscape(sheetToCopyPrintSetup.getLandscape());
        newSheetPrintSetup.setValidSettings(sheetToCopyPrintSetup.getValidSettings());
        newSheetPrintSetup.setNoColor(sheetToCopyPrintSetup.getNoColor());
        newSheetPrintSetup.setDraft(sheetToCopyPrintSetup.getDraft());
        newSheetPrintSetup.setNotes(sheetToCopyPrintSetup.getNotes());
        newSheetPrintSetup.setNoOrientation(sheetToCopyPrintSetup.getNoOrientation());
        newSheetPrintSetup.setUsePage(sheetToCopyPrintSetup.getUsePage());
        newSheetPrintSetup.setHResolution(sheetToCopyPrintSetup.getHResolution());
        newSheetPrintSetup.setVResolution(sheetToCopyPrintSetup.getVResolution());
        newSheetPrintSetup.setHeaderMargin(sheetToCopyPrintSetup.getHeaderMargin());
        newSheetPrintSetup.setFooterMargin(sheetToCopyPrintSetup.getFooterMargin());
        newSheetPrintSetup.setCopies(sheetToCopyPrintSetup.getCopies());
 
        Header sheetToCopyHeader = sheetToCopy.getHeader();
        Header newSheetHeader = newSheet.getHeader();
        newSheetHeader.setCenter(sheetToCopyHeader.getCenter());
        newSheetHeader.setLeft(sheetToCopyHeader.getLeft());
        newSheetHeader.setRight(sheetToCopyHeader.getRight());
 
        Footer sheetToCopyFooter = sheetToCopy.getFooter();
        Footer newSheetFooter = newSheet.getFooter();
        newSheetFooter.setCenter(sheetToCopyFooter.getCenter());
        newSheetFooter.setLeft(sheetToCopyFooter.getLeft());
        newSheetFooter.setRight(sheetToCopyFooter.getRight());
 
        newSheet.setHorizontallyCenter(sheetToCopy.getHorizontallyCenter());
        newSheet.setMargin(Sheet.LeftMargin, sheetToCopy.getMargin(Sheet.LeftMargin));
        newSheet.setMargin(Sheet.RightMargin, sheetToCopy.getMargin(Sheet.RightMargin));
        newSheet.setMargin(Sheet.TopMargin, sheetToCopy.getMargin(Sheet.TopMargin));
        newSheet.setMargin(Sheet.BottomMargin, sheetToCopy.getMargin(Sheet.BottomMargin));
 
        newSheet.setPrintGridlines(sheetToCopy.isPrintGridlines());
        newSheet.setRowSumsBelow(sheetToCopy.getRowSumsBelow());
        newSheet.setRowSumsRight(sheetToCopy.getRowSumsRight());
        newSheet.setVerticallyCenter(sheetToCopy.getVerticallyCenter());
        newSheet.setDisplayFormulas(sheetToCopy.isDisplayFormulas());
        newSheet.setDisplayGridlines(sheetToCopy.isDisplayGridlines());
        newSheet.setDisplayRowColHeadings(sheetToCopy.isDisplayRowColHeadings());
        newSheet.setDisplayZeros(sheetToCopy.isDisplayZeros());
        newSheet.setPrintGridlines(sheetToCopy.isPrintGridlines());
        newSheet.setRightToLeft(sheetToCopy.isRightToLeft());
//        newSheet.setZoom(0);
        copyPrintTitle(newSheet, sheetToCopy);
    }
    
    private static void copyPrintTitle(Sheet newSheet, Sheet sheetToCopy) {
        int nbNames = sheetToCopy.getWorkbook().getNumberOfNames();
        Name name = null;
        String formula = null;
 
        String part1S = null;
        String part2S = null;
        String formS = null;
        String formF = null;
        String part1F = null;
        String part2F = null;
        int rowB = -1;
        int rowE = -1;
        int colB = -1;
        int colE = -1;
 
        for (int i = 0; i < nbNames; i++) {
        	/* DOGFOOT ktkang API보안 취약점 20191218 */
//          name = sheetToCopy.getWorkbook().getNameAt(i);
        	name = sheetToCopy.getWorkbook().getAllNames().get(i);
            if (name.getSheetIndex() == sheetToCopy.getWorkbook().getSheetIndex(sheetToCopy)) {
                if (name.getNameName().equals("Print_Titles")
                        || name.getNameName().equals(XSSFName.BUILTIN_PRINT_TITLE)) {
                    formula = name.getRefersToFormula();
                    int indexComma = formula.indexOf(",");
                    if (indexComma == -1) {
                        indexComma = formula.indexOf(";");
                    }
                    String firstPart = null;
                    ;
                    String secondPart = null;
                    if (indexComma == -1) {
                        firstPart = formula;
                    } else {
                        firstPart = formula.substring(0, indexComma);
                        secondPart = formula.substring(indexComma + 1);
                    }
 
                    formF = firstPart.substring(firstPart.indexOf("!") + 1);
                    part1F = formF.substring(0, formF.indexOf(":"));
                    part2F = formF.substring(formF.indexOf(":") + 1);
 
                    if (secondPart != null) {
                        formS = secondPart.substring(secondPart.indexOf("!") + 1);
                        part1S = formS.substring(0, formS.indexOf(":"));
                        part2S = formS.substring(formS.indexOf(":") + 1);
                    }
 
                    rowB = -1;
                    rowE = -1;
                    colB = -1;
                    colE = -1;
                    String rowBs, rowEs, colBs, colEs;
                    if (part1F.lastIndexOf("$") != part1F.indexOf("$")) {
                        rowBs = part1F.substring(part1F.lastIndexOf("$") + 1, part1F.length());
                        rowEs = part2F.substring(part2F.lastIndexOf("$") + 1, part2F.length());
                        rowB = Integer.parseInt(rowBs);
                        rowE = Integer.parseInt(rowEs);
                        if (secondPart != null) {
                            colBs = part1S.substring(part1S.lastIndexOf("$") + 1, part1S.length());
                            colEs = part2S.substring(part2S.lastIndexOf("$") + 1, part2S.length());
                            colB = CellReference.convertColStringToIndex(colBs);// CExportExcelHelperPoi.convertColumnLetterToInt(colBs);
                            colE = CellReference.convertColStringToIndex(colEs);// CExportExcelHelperPoi.convertColumnLetterToInt(colEs);
                        }
                    } else {
                        colBs = part1F.substring(part1F.lastIndexOf("$") + 1, part1F.length());
                        colEs = part2F.substring(part2F.lastIndexOf("$") + 1, part2F.length());
                        colB = CellReference.convertColStringToIndex(colBs);// CExportExcelHelperPoi.convertColumnLetterToInt(colBs);
                        colE = CellReference.convertColStringToIndex(colEs);// CExportExcelHelperPoi.convertColumnLetterToInt(colEs);
 
                        if (secondPart != null) {
                            rowBs = part1S.substring(part1S.lastIndexOf("$") + 1, part1S.length());
                            rowEs = part2S.substring(part2S.lastIndexOf("$") + 1, part2S.length());
                            rowB = Integer.parseInt(rowBs);
                            rowE = Integer.parseInt(rowEs);
                        }
                    }
 
//                    newSheet.getWorkbook().setRepeatingRowsAndColumns(newSheet.getWorkbook().getSheetIndex(newSheet),
//                            colB, colE, rowB - 1, rowE - 1);
                }
            }
        }
    }
    
    private static void copyPictures(Sheet newSheet, Sheet sheet) {
        Drawing drawingOld = sheet.createDrawingPatriarch();
        Drawing drawingNew = newSheet.createDrawingPatriarch();
        CreationHelper helper = newSheet.getWorkbook().getCreationHelper();
 
        // if (drawingNew instanceof HSSFPatriarch) {
        if (drawingOld instanceof HSSFPatriarch) {
            List<HSSFShape> shapes = ((HSSFPatriarch) drawingOld).getChildren();
            for (int i = 0; i < shapes.size(); i++) {
//                System.out.println(shapes.size());
                if (shapes.get(i) instanceof HSSFPicture) {
                    HSSFPicture pic = (HSSFPicture) shapes.get(i);
                    HSSFPictureData picdata = pic.getPictureData();
                    int pictureIndex = newSheet.getWorkbook().addPicture(picdata.getData(), picdata.getFormat());
                    ClientAnchor anchor = null;
                    if (pic.getAnchor() != null) {
                        anchor = helper.createClientAnchor();
                        anchor.setDx1(((HSSFClientAnchor) pic.getAnchor()).getDx1());
                        anchor.setDx2(((HSSFClientAnchor) pic.getAnchor()).getDx2());
                        anchor.setDy1(((HSSFClientAnchor) pic.getAnchor()).getDy1());
                        anchor.setDy2(((HSSFClientAnchor) pic.getAnchor()).getDy2());
                        anchor.setCol1(((HSSFClientAnchor) pic.getAnchor()).getCol1());
                        anchor.setCol2(((HSSFClientAnchor) pic.getAnchor()).getCol2());
                        anchor.setRow1(((HSSFClientAnchor) pic.getAnchor()).getRow1());
                        anchor.setRow2(((HSSFClientAnchor) pic.getAnchor()).getRow2());
                        anchor.setAnchorType(((HSSFClientAnchor) pic.getAnchor()).getAnchorType());
                    }
                    drawingNew.createPicture(anchor, pictureIndex);
                }
            }
        } else {
            if (drawingNew instanceof XSSFDrawing) {
                List<XSSFShape> shapes = ((XSSFDrawing) drawingOld).getShapes();
                for (int i = 0; i < shapes.size(); i++) {
                    if (shapes.get(i) instanceof XSSFPicture) {
                        XSSFPicture pic = (XSSFPicture) shapes.get(i);
                        XSSFPictureData picdata = pic.getPictureData();
                        int pictureIndex = newSheet.getWorkbook().addPicture(picdata.getData(),
                                picdata.getPictureType());
                        XSSFClientAnchor anchor = null;
                        CTTwoCellAnchor oldAnchor = ((XSSFDrawing) drawingOld).getCTDrawing().getTwoCellAnchorArray(i);
                        if (oldAnchor != null) {
                            anchor = (XSSFClientAnchor) helper.createClientAnchor();
//                            CTMarker markerFrom = oldAnchor.getFrom();
//                            CTMarker markerTo = oldAnchor.getTo();
//                            anchor.setDx1((int) markerFrom.getColOff());
//                            anchor.setDx2((int) markerTo.getColOff());
//                            anchor.setDy1((int) markerFrom.getRowOff());
//                            anchor.setDy2((int) markerTo.getRowOff());
//                            anchor.setCol1(markerFrom.getCol());
//                            anchor.setCol2(markerTo.getCol());
//                            anchor.setRow1(markerFrom.getRow());
//                            anchor.setRow2(markerTo.getRow());
                        }
                        drawingNew.createPicture(anchor, pictureIndex);
                    }
                }
            }
        }
    }

	public void copyXSSFSheet(HSSFSheet newSheet, XSSFSheet sheet) {
		int maxColumnNum = 0;
        Map<Integer, HSSFCellStyle> styleMap = new HashMap<>();
        // manage a list of merged zone in order to not insert two times a merged zone
        Set<CellRangeAddressWrapper> mergedRegions = new TreeSet<>();
        List<CellRangeAddress> sheetMergedRegions = sheet.getMergedRegions();
        for (int i = sheet.getFirstRowNum(); i <= sheet.getLastRowNum(); i++) {
            XSSFRow srcRow = sheet.getRow(i);
            HSSFRow destRow = newSheet.createRow(i);
            if (srcRow != null) {
                copyXSSFRow(newSheet, srcRow, destRow, styleMap, sheetMergedRegions, mergedRegions);
                if (srcRow.getLastCellNum() > maxColumnNum) {
                    maxColumnNum = srcRow.getLastCellNum();
                }
            }
        }
        for (int i = 0; i <= maxColumnNum; i++) {
            newSheet.setColumnWidth(i, sheet.getColumnWidth(i));
        }
		
	}

	private void copyXSSFRow(HSSFSheet destSheet, XSSFRow srcRow, HSSFRow destRow, Map<Integer, HSSFCellStyle> styleMap, List<CellRangeAddress> sheetMergedRegions, Set<CellRangeAddressWrapper> mergedRegions) {
		destRow.setHeight(srcRow.getHeight());
        // pour chaque row
        for (int j = srcRow.getFirstCellNum(); j <= srcRow.getLastCellNum(); j++) {
            XSSFCell oldCell = srcRow.getCell(j);   // ancienne cell
            HSSFCell newCell = destRow.getCell(j);  // new cell
            if (oldCell != null) {
                if (newCell == null) {
                    newCell = destRow.createCell(j);
                }
                // copy chaque cell
                copyXSSFCell(oldCell, newCell, styleMap);
                
                // copy les informations de fusion entre les cellules
                
                for(CellRangeAddress mergedRegion : sheetMergedRegions) {
                	if (mergedRegion != null) {
                        CellRangeAddress newMergedRegion = new CellRangeAddress(mergedRegion.getFirstRow(), mergedRegion.getLastRow(), mergedRegion.getFirstColumn(), mergedRegion.getLastColumn());
                        CellRangeAddressWrapper wrapper = new CellRangeAddressWrapper(newMergedRegion);
                        if (isNewMergedRegion(wrapper, mergedRegions)) {
                            mergedRegions.add(wrapper);
                            destSheet.addMergedRegion(wrapper.range);
                        }
                    }	
                }
//                CellRangeAddress mergedRegion = getMergedRegion(sheetMergedRegions, srcRow.getRowNum(), (short) oldCell.getColumnIndex());
            }
        }
		
	}

	public static void copyXSSFCell(XSSFCell oldCell, HSSFCell newCell, Map<Integer, HSSFCellStyle> styleMap) {
        if (styleMap != null) {
            int stHashCode = oldCell.getCellStyle().hashCode();
            HSSFCellStyle newCellStyle = styleMap.get(stHashCode);
            if (newCellStyle == null) {
                newCellStyle = newCell.getSheet().getWorkbook().createCellStyle();
//                newCellStyle.cloneStyleFrom(oldCell.getCellStyle());
                styleMap.put(stHashCode, newCellStyle);
            }
            newCell.setCellStyle(newCellStyle);
        }
//        switch (oldCell.getCellTypeEnum()) {
        switch (oldCell.getCellType()) {
            case STRING:
                newCell.setCellValue(oldCell.getStringCellValue());
                break;
            case NUMERIC:
                newCell.setCellValue(oldCell.getNumericCellValue());
                break;
            case BLANK:
                newCell.setCellType(CellType.BLANK);
                break;
            case BOOLEAN:
                newCell.setCellValue(oldCell.getBooleanCellValue());
                break;
            case ERROR:
                newCell.setCellErrorValue(oldCell.getErrorCellValue());
                break;
            case FORMULA:
                newCell.setCellFormula(oldCell.getCellFormula());
                break;
            default:
                break;
        }
 
    }
}
