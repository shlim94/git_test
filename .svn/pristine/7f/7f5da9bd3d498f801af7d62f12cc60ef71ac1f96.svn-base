package com.wise.ds.repository.controller;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.management.ManagementFactory;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.annotation.Resource;
import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.PNGTranscoder;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.util.ZipSecureFile;
import org.apache.poi.sl.usermodel.PictureData.PictureType;
import org.apache.poi.ss.SpreadsheetVersion;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.DataConsolidateFunction;
import org.apache.poi.ss.usermodel.DataFormat;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.HorizontalAlignment;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.VerticalAlignment;
import org.apache.poi.ss.util.AreaReference;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.ss.util.CellReference;
import org.apache.poi.ss.util.RegionUtil;
import org.apache.poi.util.Units;
import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.apache.poi.xslf.usermodel.XSLFPictureData;
import org.apache.poi.xslf.usermodel.XSLFPictureShape;
import org.apache.poi.xslf.usermodel.XSLFSlide;
import org.apache.poi.xslf.usermodel.XSLFTable;
import org.apache.poi.xssf.streaming.SXSSFSheet;
import org.apache.poi.xssf.streaming.SXSSFWorkbook;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFClientAnchor;
import org.apache.poi.xssf.usermodel.XSSFColor;
import org.apache.poi.xssf.usermodel.XSSFCreationHelper;
import org.apache.poi.xssf.usermodel.XSSFDataFormat;
import org.apache.poi.xssf.usermodel.XSSFDrawing;
import org.apache.poi.xssf.usermodel.XSSFPicture;
import org.apache.poi.xssf.usermodel.XSSFPivotTable;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.xwpf.usermodel.Borders;
import org.apache.poi.xwpf.usermodel.BreakType;
import org.apache.poi.xwpf.usermodel.ParagraphAlignment;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFParagraph;
import org.apache.poi.xwpf.usermodel.XWPFRun;
import org.apache.poi.xwpf.usermodel.XWPFTable;
import org.bouncycastle.util.encoders.Base64;
import org.openxmlformats.schemas.spreadsheetml.x2006.main.CTDataField;
import org.openxmlformats.schemas.spreadsheetml.x2006.main.CTDataFields;
import org.openxmlformats.schemas.spreadsheetml.x2006.main.CTFormat;
import org.openxmlformats.schemas.spreadsheetml.x2006.main.CTFormats;
import org.openxmlformats.schemas.spreadsheetml.x2006.main.CTPivotField;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTBody;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTPageSz;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.CTSectPr;
import org.openxmlformats.schemas.wordprocessingml.x2006.main.STPageOrientation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ibm.db2.jcc.am.s;
import com.keypoint.PngEncoder;
import com.wise.authn.User;
import com.wise.authn.service.AuthenticationService;
import com.wise.common.secure.SecureUtils;
import com.wise.common.util.CloseableList;
import com.wise.common.util.FileBackedJSONObjectList;
import com.wise.common.util.QueryExecutor;
import com.wise.common.util.Timer;
import com.wise.comp.model.SummaryValue;
import com.wise.comp.pivotgrid.aggregator.ExpressionEngine;
import com.wise.comp.pivotgrid.param.GroupParam;
import com.wise.comp.pivotgrid.param.PagingParam;
import com.wise.comp.pivotgrid.param.SummaryParam;
import com.wise.comp.pivotgrid.param.UdfGroupParam;
import com.wise.comp.pivotgrid.util.ParamUtils;
import com.wise.comp.pivotmatrix.SummaryCell;
import com.wise.comp.pivotmatrix.SummaryDimension;
import com.wise.comp.pivotmatrix.SummaryDimensionUtils;
import com.wise.comp.pivotmatrix.SummaryMatrix;
import com.wise.comp.pivotmatrix.SummaryMatrixProvider;
import com.wise.common.util.WINumberUtils;
import com.wise.context.config.Configurator;
import com.wise.ds.download.util.ConvertHtml2PdfConverter;
import com.wise.ds.download.util.ConvertSheet2HtmlConverter;
import com.wise.ds.download.util.ConvertSheet2HtmlConverterForPdf;
import com.wise.ds.download.util.ConvertSheet2HwpConverter;
import com.wise.ds.download.util.ConvertSheet2PptTableController;
//import com.wise.ds.download.util.ConvertSheet2PptTableController;
import com.wise.ds.download.util.ConvertSheet2WordTableController;
import com.wise.ds.download.util.MoveSheetController;
import com.wise.ds.download.util.MoveSheetControllerForXlsx;
import com.wise.ds.repository.service.DataSetService;
import com.wise.ds.util.WebFileUtils;

import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;

@Controller
@RequestMapping(value = "/download")
public class ReportDownLoadController {
	//2020.03.05 MKSONG 로그 추가 DOGFOOT
	private static final Logger logger = LoggerFactory.getLogger(ReportDownLoadController.class);
	
	private final int EXCEL_DOWN_SIZE = 1048576;
	
	@Resource(name = "dataSetService")
    private DataSetService dataSetServiceImpl;
	
	@Resource(name = "authenticationService")
    private AuthenticationService authenticationService;
	
	@Autowired
    private ObjectMapper objectMapper;
	
	@Autowired
    private ExpressionEngine expressionEngine;

	@Autowired
	private SummaryMatrixProvider summaryMatrixProvider;
	
	//2020.03.05 MKSONG 엑셀파일 하나에 시트별 복사하는 방식 DOGFOOT 
	@RequestMapping(value = "/xlsx.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject exeReportDownLoad(HttpServletRequest request, HttpServletResponse response) throws FileNotFoundException {
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");

		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
		//2020.07.22 MKSONG 다운로드 필터조건 포함 DOGFOOT
		JSONArray paramJsonArray = SecureUtils.getJSONArrayParameter(request, "params");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String tempType = SecureUtils.getParameter(request, "tempType");
		String downloadType = SecureUtils.getParameter(request, "downloadType");
		String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");
		/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
		String downloadFilter = SecureUtils.getParameter(request, "downloadFilter");
		String userName = SecureUtils.getParameter(request, "userName");
		String userId = SecureUtils.getParameter(request, "userId");
		
		String reportOriName = "";
		String contentN = reportName.substring(reportName.length()-1);
		if(NumberUtils.isNumber(contentN)) {
			contentN = reportName.substring(reportName.length()-2);
			if(NumberUtils.isNumber(contentN)) {
				reportOriName = reportName.substring(0, reportName.length()-2);
			} else {
				reportOriName = reportName.substring(0, reportName.length()-1);
			}
		} else {
			reportOriName = reportName;
		}
		
		int sqlTimeout = Integer.parseInt(SecureUtils.getParameter(request, "sqlTimeout"));
		JSONObject params = SecureUtils.getJSONObjectParameter(request, "paramObj");
		
		User user = this.authenticationService.getRepositoryUser(userId);
		
		String iscd = "yyyy";
		Map<String, String> relCodeMap = new HashMap<String, String>();
		if(user.getUSER_REL_CD() != null && !user.getUSER_REL_CD().equals("1001") && !user.getUSER_REL_CD().equals("")) {
			String[] relCode = user.getUSER_REL_CD().split(",");
			if(!relCode[0].equals("N")) {
				iscd = relCode[0];
			}
		}
//		String sosok = this.dataSetServiceImpl.selectGoyongUserSosok(iscd);
//		if(sosok == null || sosok.equals("1001") || sosok.equals("")) {
//			sosok = "";
//		} else {
//			sosok = sosok + " ";
//		}
		
		JSONObject returnobj = new JSONObject();
		String path = "";
		String slash = "";
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

		
		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "\\";
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "/";
		}
		// 1차로 workbook을 생성
		XSSFWorkbook workbook = new XSSFWorkbook();
		new File(path + tempType + slash).mkdirs();
		// FileOutputStream fileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + downloadType);

		CellStyle bodyStyle = workbook.createCellStyle();
		bodyStyle.setBorderTop(BorderStyle.THIN);
		bodyStyle.setBorderBottom(BorderStyle.THIN);
		bodyStyle.setBorderLeft(BorderStyle.THIN);
		bodyStyle.setBorderRight(BorderStyle.THIN);
		String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(System.currentTimeMillis()));
		FileOutputStream fileoutputstream = null;
		try {
			fileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + downloadType);
			// 2020.01.07 mksong 엑셀 다운로드 시트 내용 변경 dogfoot
			MoveSheetControllerForXlsx movesheet = new MoveSheetControllerForXlsx();
			
			/* 2020.12.18 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
			// 2019.12.20 mksong 시트 이름 중복 오류 수정 dogfoot
			int sameIndex = 0;
			int addRowNum = 0;
			for (int i = 0; i < contentList.size(); i++) {
				JSONObject content = (JSONObject) contentList.get(i);
				boolean isSameName = false;
				
				/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
				String memoText = "";
				if(content.has("memoText")) {
					memoText = content.getString("memoText");
				}
				
				// 2차는 sheet생성
				switch (content.getString("itemtype")) {
				case "PIVOT_GRID":
					addRowNum = 0;
					isSameName = false;
					
					String query = new String(Base64.decode(content.getString("query")));
					List<JSONObject> list = this.dataSetServiceImpl.querySqlLike(content.getInt("dsid"), content.getString("dstype"), query, params, sqlTimeout, null, content.getJSONObject("sqlConfig"), content.getJSONObject("nullDimension"), "");
					
					System.out.println("아이템 : 피벗 그리드 그리기 시작");
					
					int sortColumnCount = content.getInt("sortColumnCount");
						
 					JSONArray cols = null;
 					JSONArray rows = null;
 					JSONObject totalView = null;
 					JSONObject dataItems = null;
 					JSONArray mea = null;
 					JSONArray dim = null;
 					
 					XSSFSheet pivotSheet = null;
 					
 					int headerNo = 1;
 					Sheet sh;
 					
 					for(int j = 0; j < workbook.getNumberOfSheets(); j++) {
						if(workbook.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
 					
 					if(isSameName) {
						pivotSheet = workbook.createSheet((String) content.getString("item")+"_"+sameIndex);
						sh = workbook.createSheet(content.getString("item") + "data"+sameIndex);
					}
					else {
						pivotSheet = workbook.createSheet((String) content.getString("item"));
						sh = workbook.createSheet(content.getString("item") + "data");
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
					/* goyong ktkang 차원 측정값이 하나씩 밖에 없을때 다운로드 오류 수정  20210603 */
					mea = dataItems.getJSONArray("Measure");
					//dim = dataItems.getJSONArray("Dimension");

					if(userId.equals("okeis")) {
						pivotSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
						pivotSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
						pivotSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
						pivotSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime);
						pivotSheet.createRow(2);
						pivotSheet.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
						pivotSheet.createRow(4);
						addRowNum = 5;
						headerNo = 5;
					} else {
						pivotSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
						pivotSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("산림청");
						pivotSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
						pivotSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(userName);
						pivotSheet.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
						pivotSheet.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime);
						pivotSheet.createRow(3);
						pivotSheet.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
						pivotSheet.createRow(5);
						addRowNum = 6;
						headerNo = 6;
					}
					
					if(downloadFilter.equals("Y")) {
						if(paramJsonArray.size() != 0) {
							// headerNo = headerNo + paramJsonArray.size() + 2;
							pivotSheet.createRow(addRowNum).createCell(0).setCellValue("필터 차원");
							pivotSheet.getRow(addRowNum).createCell(1).setCellValue("조건 값");
							for(int j = 0; j < paramJsonArray.size(); j++) {
								String key = paramJsonArray.getJSONObject(j).getString("key");
								Boolean bKeyChk = StringUtils.startsWithAny(key, "H_", "S_") ? false : true;
								
								if(bKeyChk) {
									addRowNum++;
									pivotSheet.createRow(addRowNum).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
									if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
										pivotSheet.getRow(addRowNum).createCell(1).setCellValue("전체");
									}else {
										String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
										paramValue = paramValue.replace("]", "");
										pivotSheet.getRow(addRowNum).createCell(1).setCellValue(paramValue);
									}
								}
							}
						}
						addRowNum++;
						pivotSheet.createRow(addRowNum);
 					}
 					
					Row heading = sh.createRow(0);

 					ArrayList<String> columns = null;
 					if(list.size()>0) {
 						columns = new ArrayList<String>();
 						JSONObject jobj = list.iterator().next();
 						
 						// 행열변환으로 인해 컬럼 순서 다시 지정
 						if (colRowSwitch) {
 							for (Object item : cols) {
 								columns.add(((JSONObject)item).get("name").toString());
 							}
 							for (Object item : rows) {
 								columns.add(((JSONObject)item).get("name").toString());
 							}
 						}
 						
 						Iterator<?> keys = jobj.keys();
 						while (keys.hasNext()) {
 							Object key = keys.next();
 							// H_, S_ 제외
 							Boolean bKeyChk = StringUtils.startsWithAny(key.toString(), "H_", "S_") ? false : true;
 							if (bKeyChk) {
 								
 								// new에서는 lamda가 되지 않음
 								// columns에 속하지 않을때만 추가해줌 
// 	 							if (columns.stream().filter(f -> f.equals(key.toString())).count() == 0) {
// 	 								columns.add(key.toString());
// 	 							}
 								Boolean bChk = true;
 								for (int k = 0; k < columns.size(); k++) {
 	 								if (key.toString().equals(columns.get(k))) {
 	 									bChk = false;
 	 									break;
 	 								}
 	 							}
 								
 								if (bChk) {
 									columns.add(key.toString());
 								}
 							}
 						}

 						for (int k = 0; k < columns.size(); k++) {
 							Cell cell = heading.createCell(k);
 							cell.setCellValue(columns.get(k).toString());
 						}

 						int j = 0;
						for (Iterator<JSONObject> it = list.iterator(); it.hasNext(); j++) {
							
							if (j >= EXCEL_DOWN_SIZE - 1) {
								break;
							}
							
							Row row = sh.createRow(j + 1);
							JSONObject item = it.next();
							for (int k = 0; k < columns.size(); k++) {
								if(k >= cols.size() + rows.size()) {
									Cell cell = row.createCell(k);
									String strColVal = item.getString(columns.get(k));
									if (WINumberUtils.isNumber(strColVal)) {
										cell.setCellValue(item.getDouble(columns.get(k)));
									}
									else {
										cell.setCellValue(item.getString(columns.get(k)));
									}
									
								} else {
									row.createCell(k).setCellValue(item.getString(columns.get(k)));
								}
							}
						}
 					}
 					
					XSSFCellStyle style = workbook.createCellStyle();
					style.setBorderTop(BorderStyle.THIN);
					style.setBorderBottom(BorderStyle.THIN);
					style.setBorderLeft(BorderStyle.THIN);
					style.setBorderRight(BorderStyle.THIN);
					
					String columnLetter = CellReference.convertNumToColString(columns.size()-1);
					int nSize = list.size() + 1;
					String pivotString = "A1:" + columnLetter + nSize;

					AreaReference areaReference = new AreaReference(pivotString, SpreadsheetVersion.EXCEL2007);
					/* 2020.12.18 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
					headerNo = addRowNum + 1;
					XSSFPivotTable pivotTable = pivotSheet.createPivotTable(areaReference, new CellReference("A" + headerNo), sh);
					
					for(int k = 0; k < cols.size(); k++) {
						pivotTable.addColLabel(k);
					}

					for(int k = cols.size(); k < rows.size() + cols.size(); k++) {
						pivotTable.addRowLabel(k);
					}

					for(int j = cols.size() + rows.size(); j < columns.size(); j++) {
						boolean IncludeGroupSeparator = false;
						int Precision = 0;
						for(int k = 0; k < mea.size(); k++) {
							JSONObject meaK = mea.getJSONObject(k);
							if(columns.get(j).equals(meaK.getString("Name"))) {
								JSONObject numFormat = meaK.getJSONObject("NumericFormat");
								if(numFormat.has("IncludeGroupSeparator")) {
									IncludeGroupSeparator = numFormat.getBoolean("IncludeGroupSeparator");
								}
								if(numFormat.has("Precision")) {
									Precision = numFormat.getInt("Precision");
								}
							}
						}

						String format = "0";
						//if(IncludeGroupSeparator) {
							format = "#,##0";
							if(Precision > 0) {
								format = format + ".";
								for(int k = 0; k < Precision; k++) {
									format = format + "0";
								}
							}
						//}
						if(Precision > 0) {
							format = "0.";
							for(int k = 0; k < Precision; k++) {
								format = format + "0";
							}
						}
						/* 2020.12.18 mksong 주택금융공사 정렬컬럼 피벗테이블 제외 dogfoot */
						//if(j < (columns.size()-sortColumnCount)) {
							pivotTable.addColumnLabel(DataConsolidateFunction.SUM, j, columns.get(j), format);
						//}
					}
// 						pivotTable.addDataColumn(2, false);
// 						pivotTable.addDataColumn(3, false); 
// 						pivotTable.getColLabelColumns().remove(columns.size()-1); 						
					if(totalView.getBoolean("ShowColumnGrandTotals") == false) {
						pivotTable.getCTPivotTableDefinition().setColGrandTotals(false);
					}

					if(totalView.getBoolean("ShowRowGrandTotals") == false) {
						pivotTable.getCTPivotTableDefinition().setRowGrandTotals(false);
					}
					
					// 빈셀표시 여부
					pivotTable.getCTPivotTableDefinition().setShowEmptyCol(true);
					
					pivotTable.getCTPivotTableDefinition().setSubtotalHiddenItems(false);
					for (CTPivotField ctPivotField : pivotTable.getCTPivotTableDefinition().getPivotFields().getPivotFieldList()) {
						ctPivotField.setSubtotalTop(true);			// 서브토탈 위에 표시여부 처리
						ctPivotField.setAutoShow(false);
						ctPivotField.setOutline(false);
// 							ctPivotField.setSumSubtotal(false);
// 							ctPivotField.setProductSubtotal(false);
// 							ctPivotField.setDefaultSubtotal(false);
// 							ctPivotField.setSubtotalTop(false);
					}
					
					workbook.setSheetHidden(workbook.getNumberOfSheets() - 1, true);
 					
 					System.out.println("아이템 : 피벗 그리드  그리기 끝");
					
					break;
				case "DATA_GRID":
				// 2020.02.21 mksong textbox 다운로드 추가 dogfoot
				case "TEXTBOX":
					addRowNum = 0;
					isSameName = false;
					
					OPCPackage opcPackage = OPCPackage.open(new FileInputStream((String) content.get("uploadPath")));
					XSSFWorkbook wb = new XSSFWorkbook(opcPackage);
					XSSFSheet movingSheet = (wb.getSheetAt(0));
					
					for(int j = 0; j < workbook.getNumberOfSheets(); j++) {
						if(workbook.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
					XSSFSheet positionSheet;
					
					if(isSameName) {
						positionSheet = workbook.createSheet((String) content.getString("item")+"_"+sameIndex);	
					}else {
						positionSheet = workbook.createSheet((String) content.getString("item"));
					}
					
					/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
//					if(userId.equals("okeis")) {
//						positionSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
//						positionSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
//						positionSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
//						positionSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime);
//						positionSheet.createRow(2);
//						positionSheet.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
//						positionSheet.createRow(4);
//						addRowNum = 5;
//					} else {
//						positionSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
//						positionSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("고용정보통합분석시스템(EIS)");
//						positionSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
//						positionSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(sosok + userName);
//						positionSheet.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
//						positionSheet.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime);
//						positionSheet.createRow(3);
//						positionSheet.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
//						positionSheet.createRow(5);
//						addRowNum = 6;
//					}
					
//						String unitFilter = "";
					/* 2020.11.23 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
					/* 2021-03-23 yyb 추가된 로우 index 계산 */
//					if(downloadFilter.equals("Y")) {
//						if(paramJsonArray.size() != 0) {
//							positionSheet.createRow(addRowNum).createCell(0).setCellValue("필터 차원");
//							positionSheet.getRow(addRowNum).createCell(1).setCellValue("조건 값");
//							for(int j = 0; j < paramJsonArray.size(); j++) {
//								String key = paramJsonArray.getJSONObject(j).getString("key");
//								Boolean bKeyChk = StringUtils.startsWithAny(key, "H_", "S_") ? false : true;
//								
//								if(bKeyChk) {
//									addRowNum++;
//									positionSheet.createRow(addRowNum).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
//									if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
//										positionSheet.getRow(addRowNum).createCell(1).setCellValue("전체");
//									}else {
//										String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
//										paramValue = paramValue.replace("]", "");
//										positionSheet.getRow(addRowNum).createCell(1).setCellValue(paramValue);
//									}									
//								}
//							}
//							
//							addRowNum++;
//							positionSheet.createRow(addRowNum);
//						}
//					}
//					
//					/* 2021-03-23 yyb 텍스트라벨이 필터와 겹치지 않게 로우 추가 */
//					if (StringUtils.isNotBlank(memoText)) {
//						addRowNum++;
//						positionSheet.createRow(addRowNum);
//					}
					
//						if(content.getString("itemtype").equals("PIVOT_GRID")) {
//							addRowNum++;
//							JSONArray rows = content.getJSONArray("rows");
//							JSONArray cols = content.getJSONArray("cols");
//							
//							if(rows != null && rows.size() > 0) {
//								positionSheet.createRow(addRowNum).createCell(0).setCellValue("행");
//								for(int j = 0; j < rows.size(); j++) {
//									JSONObject row = rows.getJSONObject(j);
//									String rowName = "";
//									if(row.has("wiseUniqueName")) {
//										rowName = row.getString("wiseUniqueName");
//									} else if(row.has("caption")) {
//										rowName = row.getString("caption");
//									}
//									positionSheet.getRow(addRowNum).createCell(j+1, CellType.STRING).setCellValue(rowName);
//								}
//								addRowNum++;
//							}
//							
//							if(cols != null && cols.size() > 0) {
//								positionSheet.createRow(addRowNum).createCell(0).setCellValue("열");
//								for(int j = 0; j < cols.size(); j++) {
//									JSONObject col = cols.getJSONObject(j);
//									String colName = "";
//									if(col.has("wiseUniqueName")) {
//										colName = col.getString("wiseUniqueName");
//									} else if(col.has("caption")) {
//										colName = col.getString("caption");
//									}
//									positionSheet.getRow(addRowNum).createCell(j+1, CellType.STRING).setCellValue(colName);
//								}
//								addRowNum++;
//							}
//						}
					
					movesheet.copySheetSettings(positionSheet, movingSheet);
					
					if (content.getString("itemtype").equals("DATA_GRID")) {
//						// 데이터 그리드일때만 엑셀 바디로우의 셀병합시 머지 처리를 위한 계산로직
//						if (content.has("isGrdCellMerge") && (Boolean)content.get("isGrdCellMerge")) {
//							JSONArray mergeJson = (JSONArray)content.get("mergeRange");
//							for (int _i=0; _i<mergeJson.size(); _i++) {
//								JSONObject obj = mergeJson.getJSONObject(_i);
//								int bodyStartNum = content.getInt("hdRowCnt");
//								bodyStartNum = bodyStartNum + obj.getInt("row");
//								int colIdx = obj.getInt("col");
//								int range = obj.getInt("range");
//								
//								CellRangeAddress rangeAddr;
////								if(obj.getInt("row") > 0) {
////									rangeAddr = new CellRangeAddress(bodyStartNum - 1, bodyStartNum + range - 2, colIdx, colIdx);
////								} else {
//									rangeAddr = new CellRangeAddress(bodyStartNum, bodyStartNum + range - 1, colIdx, colIdx);
////								}
//								
//								movingSheet.addMergedRegion(rangeAddr);
//							}
//						}
					
						System.out.println("아이템 : 데이터그리드 복사 시작");
						movesheet.allCopyXSSFSheet(positionSheet, movingSheet);
						System.out.println("아이템 : 데이터그리드 복사 끝");
					}
					
					wb.close();
					opcPackage.close();
					break;

				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
				case "SIMPLE_CHART":
				case "CHOROPLETH_MAP":
				case "PIE_CHART":
				case "TREEMAP" :
				case "STAR_CHART" :
				/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
				case "CARD_CHART":
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case "KAKAO_MAP":
				case "KAKAO_MAP2":
				case "HISTOGRAM_CHART":
				case "DIVERGING_CHART":
			    case "SCATTER_PLOT":
			    case "HISTORY_TIMELINE":
			    case "ARC_DIAGRAM":
			    case "RADIAL_TIDY_TREE":
			    case "SCATTER_PLOT_MATRIX":
			    case "SCATTER_PLOT2":
				case "BOX_PLOT":
				case "DEPENDENCY_WHEEL":
				case "SEQUENCES_SUNBURST":
				case "LIQUID_FILL_GAUGE":
				case "WATERFALL_CHART":
				case "BIPARTITE_CHART":
				case "SANKEY_CHART":
				case "PARALLEL_COORDINATE":
				case "BUBBLE_PACK_CHART":
				case "WORD_CLOUD_V2":
				case "DENDROGRAM_BAR_CHART":
				case "COLLAPSIBLE_TREE_CHART":
				case "CALENDAR_VIEW_CHART":
				case "CALENDAR_VIEW2_CHART":
				case "CALENDAR_VIEW3_CHART":
				case "HEATMAP":
				case "HEATMAP2":
				case "COORDINATE_DOT":
				case "COORDINATE_LINE":
                case "SYNCHRONIZED_CHARTS":
				case "RECTANGULAR_ARAREA_CHART":
				case "WORD_CLOUD":
				case "BUBBLE_D3":
				case "FORCEDIRECT":
				case "FORCEDIRECTEXPAND":
				case "HIERARCHICAL_EDGE":
				case "FUNNEL_CHART":
				case "PYRAMID_CHART":
					for(int j = 0; j < workbook.getNumberOfSheets(); j++) {
						if(workbook.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
					XSSFSheet sheet1;

					/* 2020.12.18 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
					addRowNum = 0;
					if(isSameName) {
						sheet1 = workbook.createSheet((String) content.getString("item")+"_"+sameIndex);	
					}else {
						sheet1 = workbook.createSheet((String) content.getString("item"));
					}
					try {
						/* 2020.12.18 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
						String keyTime2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(System.currentTimeMillis()));
						
//						if(userId.equals("okeis")) {
//							sheet1.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
//							sheet1.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
//							sheet1.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
//							sheet1.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime2);
//							sheet1.createRow(2);
//							sheet1.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
//							sheet1.createRow(4);
//							addRowNum = 5;
//						} else {
//							sheet1.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
//							sheet1.getRow(0).createCell(1, CellType.STRING).setCellValue("고용정보통합분석시스템(EIS)");
//							sheet1.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
//							sheet1.getRow(1).createCell(1, CellType.STRING).setCellValue(userName);
//							sheet1.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
//							sheet1.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime2);
//							sheet1.createRow(3);
//							sheet1.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
//							sheet1.createRow(5);
//							addRowNum = 6;
//						}
						
						/* 2020.11.23 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
						if(downloadFilter.equals("Y")) {
							if(paramJsonArray.size() != 0) {
								sheet1.createRow(addRowNum).createCell(0).setCellValue("필터 차원");
								sheet1.getRow(addRowNum).createCell(1).setCellValue("조건 값");
								for(int j = 0; j < paramJsonArray.size(); j++) {
									String key = paramJsonArray.getJSONObject(j).getString("key");
									Boolean bKeyChk = StringUtils.startsWithAny(key, "H_", "S_") ? false : true;
									if(bKeyChk) {
										addRowNum++;
										sheet1.createRow(addRowNum).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
										if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
											sheet1.getRow(addRowNum).createCell(1).setCellValue("전체");
										}else {
											String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
											paramValue = paramValue.replace("]", "");
											sheet1.getRow(addRowNum).createCell(1).setCellValue(paramValue);
										}									
									}
								}
								
								addRowNum++;
								sheet1.createRow(addRowNum);
							}
						}
						
						for (int j = 0; j < 12; j++) {
							if(sheet1.getRow(addRowNum)== null) {
								sheet1.createRow(addRowNum);
							}
							
							if(sheet1.getRow(addRowNum).getCell(j) == null) {
								sheet1.getRow(addRowNum).createCell(j);
							}
							
						}
						
//						sheet1.getRow(paramJsonArray.size()+1 + unitFilterCount).getCell(0).setCellValue(reportName);
						/* 2021-03-23 yyb 텍스트라벨이 이미지와 겹치지 않게 로우 추가 */
						if (StringUtils.isNotBlank(memoText)) {
							sheet1.getRow(addRowNum).getCell(11).setCellValue(memoText);  // 얘는 같은 로우에 있어야함
							addRowNum++;
						}
						
						// 이미지 파일 로드
						InputStream inputStream = new FileInputStream((String) content.getString("uploadPath"));
						byte[] bytes = IOUtils.toByteArray(inputStream);
						int pictureIdx = workbook.addPicture(bytes, XSSFWorkbook.PICTURE_TYPE_PNG);
						inputStream.close();

						XSSFCreationHelper helper = workbook.getCreationHelper();
						XSSFDrawing drawing = sheet1.createDrawingPatriarch();
						XSSFClientAnchor anchor = helper.createClientAnchor();

						anchor.setCol1(0);
						anchor.setRow1(addRowNum);
						
						// 이미지 그리기
						XSSFPicture pict = drawing.createPicture(anchor, pictureIdx);

						// 이미지 사이즈 비율 설정
						pict.resize();
					} catch (Exception e) {
						e.printStackTrace();
					}

					break;
				}
				
				// 피벗그리드일때 임시파일 삭제하지 않음(생성하지 않았음)
				if (!content.getString("itemtype").equals("PIVOT_GRID")) {
					Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
					logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));	
				}
			}
			
			/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
			SXSSFWorkbook wb = new SXSSFWorkbook(workbook); 
	        wb.setCompressTempFiles(true);

	        SXSSFSheet sh = (SXSSFSheet) wb.getSheetAt(0);
	        sh.setRandomAccessWindowSize(1000);
	        
//			workbook.write(fileoutputstream);
	        wb.write(fileoutputstream);
//			System.out.println(path + tempType + slash + reportName + "." + downloadType);

			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", path + tempType + slash + reportName + "." + downloadType);
			wb.dispose();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		} finally {
			// 필수로 닫아주어야함
			if (fileoutputstream != null) {
				try {
					fileoutputstream.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
			
			if (workbook != null) {
				try {
					workbook.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
		}
		
		return returnobj;
	}
	
	//dogfoot 지도 불러오기 리스트 가져오기 syjin 20210513
	@RequestMapping(value = "/getListSHP.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject getListSHP(HttpServletRequest request, HttpServletResponse response,@RequestBody String paramData) throws Exception {
		JSONObject paramMeta = JSONObject.fromObject(paramData);
		String path = "";
		String name =  paramMeta.getString("name");
		logger.debug(name);

		File folder = WebFileUtils.getWebFolder(request, false, "UploadFiles", "geojson", name);
		JSONObject obj = new JSONObject();
		
		if(!folder.isDirectory()) {
			obj.put("file", "noData");		
		}else {
			File[] fileList = folder.listFiles();
			
			for(int i=1; i<=fileList.length; i++) {
				obj.put("file"+i, fileList[i-1].getName());
			}
		}
		
		return obj;
	}
	
	@RequestMapping(value = "/xlsxPivot.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject exeReportDownLoadPivot(HttpServletRequest request, HttpServletResponse response, @RequestParam Map<String, Object> allParameters) throws FileNotFoundException {
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");

		JSONArray contentList = JSONArray.fromObject(allParameters.get("contentList"));
		//2020.07.22 MKSONG 다운로드 필터조건 포함 DOGFOOT
		JSONArray paramJsonArray = JSONArray.fromObject(allParameters.get("params"));
		String reportName = allParameters.get("reportName").toString();
		String tempType = allParameters.get("tempType").toString();
		String downloadType = allParameters.get("downloadType").toString();
		String downloadFilter = allParameters.get("downloadFilter").toString();
		String userName = allParameters.get("userName").toString();
		String userId = allParameters.get("userId").toString();
		
		String reportOriName = "";
		String contentN = reportName.substring(reportName.length()-1);
		if(NumberUtils.isNumber(contentN)) {
			contentN = reportName.substring(reportName.length()-2);
			if(NumberUtils.isNumber(contentN)) {
				reportOriName = reportName.substring(0, reportName.length()-2);
			} else {
				reportOriName = reportName.substring(0, reportName.length()-1);
			}
		} else {
			reportOriName = reportName;
		}
		
		int sqlTimeout = 0;
		if(allParameters.get("sqlTimeout") != null) {
			sqlTimeout = Integer.parseInt(allParameters.get("sqlTimeout").toString());
		}
		
		JSONObject params = null;
		if(allParameters.get("paramObj") != null) {
			params = JSONObject.fromObject(allParameters.get("paramObj").toString());
		}
		
		String sqlLikeOption;
		if(allParameters.containsKey("sqlLikeOption")) {
			sqlLikeOption= allParameters.get("sqlLikeOption").toString();
		}
		
		User user = this.authenticationService.getRepositoryUser(userId);
		
		String iscd = "yyyy";
		Map<String, String> relCodeMap = new HashMap<String, String>();
		if(user.getUSER_REL_CD() != null && !user.getUSER_REL_CD().equals("1001") && !user.getUSER_REL_CD().equals("")) {
			String[] relCode = user.getUSER_REL_CD().split(",");
			if(!relCode[0].equals("N")) {
				iscd = relCode[0];
			}
		}
//		String sosok = this.dataSetServiceImpl.selectGoyongUserSosok(iscd);
//		if(sosok == null || sosok.equals("1001") || sosok.equals("")) {
//			sosok = "";
//		} else {
//			sosok = sosok + " ";
//		}
		
		JSONObject returnobj = new JSONObject();
		String path = "";
		String slash = "";
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

		
		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "\\";
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "/";
		}
		// 1차로 workbook을 생성
		XSSFWorkbook workbook = new XSSFWorkbook();
		new File(path + tempType + slash).mkdirs();
		// FileOutputStream fileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + downloadType);

		
		String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(System.currentTimeMillis()));
		FileOutputStream fileoutputstream = null;
		try {
			HashMap<String, XSSFCellStyle> styleMap = new HashMap<String, XSSFCellStyle>();
			
			XSSFCellStyle borderStyle = workbook.createCellStyle();
			borderStyle.setBorderTop(BorderStyle.THIN);
			borderStyle.setBorderBottom(BorderStyle.THIN);
			borderStyle.setBorderLeft(BorderStyle.THIN);
			borderStyle.setBorderRight(BorderStyle.THIN);
			styleMap.put("border", borderStyle);
			
			XSSFCellStyle alignCenterStyle = workbook.createCellStyle();
			alignCenterStyle.setBorderTop(BorderStyle.THIN);
			alignCenterStyle.setBorderBottom(BorderStyle.THIN);
			alignCenterStyle.setBorderLeft(BorderStyle.THIN);
			alignCenterStyle.setBorderRight(BorderStyle.THIN);
			alignCenterStyle.setAlignment(HorizontalAlignment.CENTER);
			alignCenterStyle.setVerticalAlignment(VerticalAlignment.CENTER);
			styleMap.put("alignCenter", alignCenterStyle);
			
			short white = IndexedColors.WHITE.getIndex();
			XSSFCellStyle topStyle = workbook.createCellStyle();
			topStyle.setBorderTop(BorderStyle.THIN);
			topStyle.setBorderLeft(BorderStyle.THIN);
			topStyle.setBorderRight(BorderStyle.THIN);
			topStyle.setFillForegroundColor(white);
			topStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
			styleMap.put("top", topStyle);
			
			XSSFCellStyle leftRightStyle = workbook.createCellStyle();
			leftRightStyle.setBorderLeft(BorderStyle.THIN);
			leftRightStyle.setBorderRight(BorderStyle.THIN);
			leftRightStyle.setFillForegroundColor(white);
			leftRightStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
			styleMap.put("leftRight", leftRightStyle);
			
			XSSFCellStyle bottomStyle = workbook.createCellStyle();
			bottomStyle.setBorderLeft(BorderStyle.THIN);
			bottomStyle.setBorderRight(BorderStyle.THIN);
			bottomStyle.setBorderBottom(BorderStyle.THIN);
			bottomStyle.setFillForegroundColor(white);
			bottomStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
			styleMap.put("bottom", bottomStyle);
			
			XSSFCellStyle leftStyle = workbook.createCellStyle();
			leftStyle.setBorderLeft(BorderStyle.THIN);
			leftStyle.setBorderTop(BorderStyle.THIN);
			leftStyle.setBorderBottom(BorderStyle.THIN);
			leftStyle.setFillForegroundColor(white);
			leftStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
			styleMap.put("left", leftStyle);
			
			XSSFCellStyle rightStyle = workbook.createCellStyle();
			rightStyle.setBorderRight(BorderStyle.THIN);
			rightStyle.setBorderTop(BorderStyle.THIN);
			rightStyle.setBorderBottom(BorderStyle.THIN);
			rightStyle.setFillForegroundColor(white);
			rightStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
			styleMap.put("right", rightStyle);
			
			XSSFCellStyle topBottomStyle = workbook.createCellStyle();
			topBottomStyle.setBorderTop(BorderStyle.THIN);
			topBottomStyle.setBorderBottom(BorderStyle.THIN);
			topBottomStyle.setFillForegroundColor(white);
			topBottomStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
			styleMap.put("topBottom", topBottomStyle);
			
			fileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + downloadType);
			// 2020.01.07 mksong 엑셀 다운로드 시트 내용 변경 dogfoot
			MoveSheetControllerForXlsx movesheet = new MoveSheetControllerForXlsx();
			
			/* 2020.12.18 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
			// 2019.12.20 mksong 시트 이름 중복 오류 수정 dogfoot
			int sameIndex = 0;
			int addRowNum = 0;
			for (int i = 0; i < contentList.size(); i++) {
				JSONObject content = (JSONObject) contentList.get(i);
				boolean isSameName = false;
				
				/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
				String memoText = "";
				if(content.has("memoText")) {
					memoText = content.getString("memoText");
				}
				
				// 2차는 sheet생성
				switch (content.getString("itemtype")) {
				case "PIVOT_GRID":
					addRowNum = 0;
					isSameName = false;
					
//					final String cacheKey = "bd229aa4b689ec6f66cd11b5935a60c2ff9626c15648344985dba77307c66aae";
//					final SummaryMatrix matrix = summaryMatrixProvider.getPivotSummaryMatrixFromCache(cacheKey);
					JSONObject downloadParams = (JSONObject) content.get("downloadParams");
					final String pagingParamValue = downloadParams.get("paging").toString();
		            final ObjectNode pagingParamNode = StringUtils.isNotBlank(pagingParamValue)
		                    ? (ObjectNode) objectMapper.readTree(pagingParamValue) : null;
		            final PagingParam pagingParam = ParamUtils.toPagingParam(objectMapper, pagingParamNode);
		            pagingParam.setLimit(Integer.MAX_VALUE);
		            
					SummaryMatrix matrix = (SummaryMatrix) summaryMatrixProvider.getPivotSummaryMatrix(request, downloadParams, pagingParam, new QueryExecutor() {
						@Override
			         	   public CloseableList<JSONObject> execute(String sqlLikeOption, boolean useWithQuery) throws Exception {
			         		   return dataSetServiceImpl.executeSqlLike(sqlLikeOption, useWithQuery, request);
			         	   }
			            }).get();
					
//					testTraverseSummaryMatrix(matrix);
					
 					JSONArray cols = null;
 					JSONArray rows = null;
 					JSONArray deltaItems = new JSONArray();
 					JSONArray formatDataItems = new JSONArray();
 					JSONObject totalView = null;
 					JSONObject dataItems = null;
 					JSONArray mea = null;
 					JSONArray dim = null;
 					JSONObject reportLayout = (JSONObject) downloadParams.get("reportLayout");
 					String datafieldPosition = null;
 					
 					XSSFSheet pivotSheet = null;
 					
 					int headerNo = 1;
 					Sheet sh;
 					
 					for(int j = 0; j < workbook.getNumberOfSheets(); j++) {
						if(workbook.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
 					
 					if(isSameName) {
						pivotSheet = workbook.createSheet((String) content.getString("item")+"_"+sameIndex);
					}
					else {
						pivotSheet = workbook.createSheet((String) content.getString("item"));
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
					if(content.has("delta")) {
						deltaItems = content.getJSONArray("delta");
					}
					if(content.has("datafieldPosition")) {
						datafieldPosition = content.getString("datafieldPosition");
					}
					
					if(downloadParams.has("formatFieldArray")) {
						formatDataItems = downloadParams.getJSONArray("formatFieldArray");
					}
					
					/* goyong ktkang 차원 측정값이 하나씩 밖에 없을때 다운로드 오류 수정  20210603 */
					mea = dataItems.getJSONArray("Measure");
					//dim = dataItems.getJSONArray("Dimension");
					
					for(int k = 0; k < mea.size(); k++) {
						JSONObject measure = (JSONObject) mea.getJSONObject(k);
						JSONObject numericFormat = (JSONObject) measure.get("NumericFormat");
						
						XSSFCellStyle meaStyle = workbook.createCellStyle();
						XSSFDataFormat newDataFormat = workbook.createDataFormat();
						meaStyle.setBorderTop(BorderStyle.THIN);
						meaStyle.setBorderBottom(BorderStyle.THIN);
						meaStyle.setBorderLeft(BorderStyle.THIN);
						meaStyle.setBorderRight(BorderStyle.THIN);
						
						if(numericFormat != null) {
							String format = "0";
							if(numericFormat.getString("FormatType").equals("Percent")) {
								if(numericFormat.getBoolean("IncludeGroupSeparator")) {
									format = "#,##0";
								}
								
								if(numericFormat.getInt("Precision") > 0) {
									format += ".";
									for(int j = 0; j < numericFormat.getInt("Precision"); j++) {
										format += "0";
									}
								}
								format += "%";
								
								meaStyle.setDataFormat(newDataFormat.getFormat(format));
								styleMap.put(measure.getString("Name"), meaStyle);
								styleMap.put(measure.getString("DataMember"), meaStyle);
							} else if(numericFormat.getString("FormatType").equals("Number")) {
								if(numericFormat.getBoolean("IncludeGroupSeparator")) {
									format = "#,##0";
								}
								
								if(numericFormat.getInt("Precision") > 0) {
									format += ".";
									for(int j = 0; j < numericFormat.getInt("Precision"); j++) {
										format += "0";
									}
								}
								
								meaStyle.setDataFormat(newDataFormat.getFormat(format));
								styleMap.put(measure.getString("Name"), meaStyle);
								styleMap.put(measure.getString("DataMember"), meaStyle);
							}
						} else {
							styleMap.put(measure.getString("Name"), meaStyle);
							styleMap.put(measure.getString("DataMember"), meaStyle);
						}
					}
					
					for(int l = 0; l < deltaItems.size(); l++) {
						JSONObject deltaItem = (JSONObject) deltaItems.getJSONObject(l);
						JSONObject numericFormat = new JSONObject();
						for(int m = 0; m < formatDataItems.size(); m++) {
							JSONObject formatDataItem = (JSONObject) formatDataItems.getJSONObject(m);
							if(formatDataItem.has("deltaFieldName")) {
								if(deltaItem.get("FLD_NM").equals(formatDataItem.getString("deltaFieldName"))) {
									numericFormat = (JSONObject) formatDataItem.get("format");
								}
							}
						}
						
						
						XSSFCellStyle deltaStyle = workbook.createCellStyle();
						XSSFDataFormat newDataFormat = workbook.createDataFormat();
						deltaStyle.setBorderTop(BorderStyle.THIN);
						deltaStyle.setBorderBottom(BorderStyle.THIN);
						deltaStyle.setBorderLeft(BorderStyle.THIN);
						deltaStyle.setBorderRight(BorderStyle.THIN);
						
						if(numericFormat != null) {
							String format = "0";
							String defaultValueType = "";
							
							if(deltaItem.has("DELTA_VALUE_TYPE")) {
								defaultValueType = deltaItem.get("DELTA_VALUE_TYPE").toString();
							}
							
							if(numericFormat.getString("FormatType").equals("Percent")) {
								if(numericFormat.getBoolean("IncludeGroupSeparator")) {
									format = "#,##0";
								}
								
								if(numericFormat.getInt("Precision") > 0) {
									format += ".";
									for(int j = 0; j < numericFormat.getInt("Precision"); j++) {
										format += "0";
									}
								}
								format += "%";
								deltaItem.put("Precision",numericFormat.getInt("Precision")); 
								deltaStyle.setDataFormat(newDataFormat.getFormat(format));
								styleMap.put(deltaItem.getString("FLD_NM"), deltaStyle);
							} else if(numericFormat.getString("FormatType").equals("Number")) {
								if(numericFormat.getBoolean("IncludeGroupSeparator")) {
									format = "#,##0";
								}
								
								if(numericFormat.getInt("Precision") > 0) {
									format += ".";
									for(int j = 0; j < numericFormat.getInt("Precision"); j++) {
										format += "0";
									}
								}
								
								if(defaultValueType.indexOf("Percent") > -1) {
									format += "%";
								}
								
								deltaItem.put("Precision",numericFormat.getInt("Precision")); 
								deltaStyle.setDataFormat(newDataFormat.getFormat(format));
								styleMap.put(deltaItem.getString("FLD_NM"), deltaStyle);
							}
							
						} else {
							styleMap.put(deltaItem.getString("FLD_NM"), deltaStyle);
						}
					}
					
					XSSFCellStyle percentStyle = workbook.createCellStyle();
					XSSFDataFormat newDataFormat = workbook.createDataFormat();
					percentStyle.setBorderTop(BorderStyle.THIN);
					percentStyle.setBorderBottom(BorderStyle.THIN);
					percentStyle.setBorderLeft(BorderStyle.THIN);
					percentStyle.setBorderRight(BorderStyle.THIN);
					percentStyle.setDataFormat(newDataFormat.getFormat("0.##%"));
					styleMap.put("percent", percentStyle);
					
					XSSFCellStyle zeroStyle = workbook.createCellStyle();
					XSSFDataFormat newDataFormat2 = workbook.createDataFormat();
					zeroStyle.setBorderTop(BorderStyle.THIN);
					zeroStyle.setBorderBottom(BorderStyle.THIN);
					zeroStyle.setBorderLeft(BorderStyle.THIN);
					zeroStyle.setBorderRight(BorderStyle.THIN);
					zeroStyle.setDataFormat(newDataFormat2.getFormat("0"));
					styleMap.put("zero", zeroStyle);
					
					XSSFCellStyle commaStyle = workbook.createCellStyle();
					XSSFDataFormat newDataFormat3 = workbook.createDataFormat();
					commaStyle.setBorderTop(BorderStyle.THIN);
					commaStyle.setBorderBottom(BorderStyle.THIN);
					commaStyle.setBorderLeft(BorderStyle.THIN);
					commaStyle.setBorderRight(BorderStyle.THIN);
					commaStyle.setDataFormat(newDataFormat3.getFormat("#,##0"));
					styleMap.put("comma", commaStyle);
//					
//					if(userId.equals("okeis")) {
//						pivotSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
//						pivotSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
//						pivotSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
//						pivotSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime);
//						pivotSheet.createRow(2);
//						pivotSheet.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
//						pivotSheet.createRow(4);
//						addRowNum = 5;
//						headerNo = 5;
//					} else {
//						pivotSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
//						pivotSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("고용정보통합분석시스템(EIS)");
//						pivotSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
//						pivotSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(sosok + userName);
//						pivotSheet.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
//						pivotSheet.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime);
//						pivotSheet.createRow(3);
//						pivotSheet.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
//						pivotSheet.createRow(5);
//						addRowNum = 6;
//						headerNo = 6;
//					}
					
					if(userId.equals("okeis")) {
						pivotSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
						pivotSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
						pivotSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
						pivotSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime);
						pivotSheet.createRow(2);
						pivotSheet.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
						pivotSheet.createRow(4);
						addRowNum = 5;
						headerNo = 5;
					} else {
						pivotSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
						pivotSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("산림청");
						pivotSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
						pivotSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(userName);
						pivotSheet.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
						pivotSheet.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime);
						pivotSheet.createRow(3);
						pivotSheet.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
						pivotSheet.createRow(5);
						addRowNum = 6;
						headerNo = 6;
					}
					

					if(downloadFilter.equals("Y")) {
						if(paramJsonArray.size() != 0) {
							// headerNo = headerNo + paramJsonArray.size() + 2;
							pivotSheet.createRow(addRowNum).createCell(0).setCellValue("필터 차원");
							pivotSheet.getRow(addRowNum).getCell(0).setCellStyle(borderStyle);
							pivotSheet.getRow(addRowNum).createCell(1).setCellValue("조건 값");
							pivotSheet.getRow(addRowNum).getCell(1).setCellStyle(borderStyle);
							for(int j = 0; j < paramJsonArray.size(); j++) {
								String key = paramJsonArray.getJSONObject(j).getString("key");
								Boolean bKeyChk = StringUtils.startsWithAny(key, "H_", "S_") ? false : true;
								
								if(bKeyChk) {
									addRowNum++;
									pivotSheet.createRow(addRowNum).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
									pivotSheet.getRow(addRowNum).getCell(0).setCellStyle(borderStyle);
									if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
										pivotSheet.getRow(addRowNum).createCell(1).setCellValue("전체");
										pivotSheet.getRow(addRowNum).getCell(1).setCellStyle(borderStyle);
									}else {
										String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
										paramValue = paramValue.replace("]", "");
										pivotSheet.getRow(addRowNum).createCell(1).setCellValue(paramValue);
										pivotSheet.getRow(addRowNum).getCell(1).setCellStyle(borderStyle);
									}
								}
							}
						}
						addRowNum++;
						pivotSheet.createRow(addRowNum);
 					}
 					
					
//					if(content.getString("itemtype").equals("PIVOT_GRID")) {
//						addRowNum++;
//						if(rows != null && rows.size() > 0) {
//							pivotSheet.createRow(addRowNum).createCell(0).setCellValue("행");
//							pivotSheet.getRow(addRowNum).getCell(0).setCellStyle(borderStyle);
//							addRowNum++;
//							pivotSheet.createRow(addRowNum);
//							for(int j = 0; j < rows.size(); j++) {
//								JSONObject row = rows.getJSONObject(j);
//								String rowName = "";
//								if(row.has("wiseUniqueName")) {
//									rowName = row.getString("wiseUniqueName");
//								} else if(row.has("caption")) {
//									rowName = row.getString("caption");
//								}
//								pivotSheet.getRow(addRowNum-1).createCell(j+1, CellType.STRING).setCellValue(rowName);
//								pivotSheet.getRow(addRowNum-1).getCell(j+1).setCellStyle(borderStyle);
//								
//							}
//							addRowNum++;
//						}
//						
//						if(cols != null && cols.size() > 0) {
//							pivotSheet.createRow(addRowNum).createCell(0).setCellValue("열");
//							pivotSheet.getRow(addRowNum).getCell(0).setCellStyle(borderStyle);
//							addRowNum++;
//							pivotSheet.createRow(addRowNum);
//							for(int j = 0; j < cols.size(); j++) {
//								JSONObject col = cols.getJSONObject(j);
//								String colName = "";
//								if(col.has("wiseUniqueName")) {
//									colName = col.getString("wiseUniqueName");
//								} else if(col.has("caption")) {
//									colName = col.getString("caption");
//								}
//								pivotSheet.getRow(addRowNum-1).createCell(j+1, CellType.STRING).setCellValue(colName);
//								pivotSheet.getRow(addRowNum-1).getCell(j+1).setCellStyle(borderStyle);
//							}
//							addRowNum++;
//						}
//					}
						
					
					
					
					final List<GroupParam> rowGroupParams = matrix.getRowGroupParams();
			        int maxRowGroupDepth = rowGroupParams.size();
			        final List<GroupParam> colGroupParams = matrix.getColGroupParams();
			        final int maxColGroupDepth = colGroupParams.size();
			        
			        Map<String, Integer> deltaBaseMeasure = new HashMap<String, Integer>(); // 변동측정값 기준 측정값 위치
			        List<SummaryParam> summaryParams = new LinkedList<SummaryParam>();
			        List<String> meaString = new ArrayList<String>();
			        HashMap<String, String> meaCaptionNmMapper = new HashMap<String, String>();
			        HashMap<String, String> headerCaptionNmMapper = new HashMap<String, String>();
			        for(int s = 0; s < matrix.getSummaryParams().size(); s++) {
			        	SummaryParam sp = matrix.getSummaryParams().get(s);
						if(!StringUtils.startsWithAny(sp.getSelector(), "H_", "S_")) {
							if(mea != null && mea.size() > 0) {
								for(int m = 0; m < mea.size(); m++) {
									if((mea.getJSONObject(m).getString("Name").equals(sp.getSelector()) || mea.getJSONObject(m).getString("DataMember").equals(sp.getSelector())) && !summaryParams.contains(sp)) {
										summaryParams.add(sp);
										meaString.add(sp.getSelector());
										if(!meaCaptionNmMapper.containsKey(sp.getSelector())){
											meaCaptionNmMapper.put(sp.getSelector(), mea.getJSONObject(m).getString("Name"));
										}
									}
								}
							} else {
								summaryParams.add(sp);
								meaString.add(sp.getSelector());
							}
						}
						if(deltaItems != null) {
							for(int d = 0; d < deltaItems.size(); d++) {
					        	if(sp.getSelector().equals(deltaItems.getJSONObject(d).getString("BASE_UNI_NM"))) {
					        		deltaBaseMeasure.put(deltaItems.getJSONObject(d).getString("CAPTION"), s);
					        		meaString.add(deltaItems.getJSONObject(d).getString("CAPTION"));
					        	}
					        }
						}
						
			        }
			        int summaryValueCount = summaryParams.size();
			        final SummaryDimension[] rowFlattenedSummaryDimensions = matrix.getRowFlattendSummaryDimensions();
			        final SummaryDimension[] colFlattenedSummaryDimensions = matrix.getColFlattendSummaryDimensions();
			        int rowsNum = matrix.getRows();
			        int colsNum = matrix.getCols();
			        final SummaryCell[][] summaryCells = matrix.getSummaryCells();
			        if(summaryCells.length > 1) {
			        	int deltaVariationCount = 0;
				        final int deltaItemsCount = deltaItems.size();
				        for(int d = 0; d < deltaItemsCount; d++) {
				        	if(deltaItems.getJSONObject(d).getString("DELTA_VALUE_TYPE").contains("Variation")) {
				        		deltaVariationCount++;
				        	}
				        }
				        
				        if(deltaItemsCount > 0) {
				        	summaryValueCount = summaryValueCount + deltaItemsCount;
				        }
				        addRowNum = addRowNum+1;
				        
				        if(cols != null && cols.size() > 0) {
							pivotSheet.createRow(addRowNum + 1);
							for(int j = 0; j < cols.size(); j++) {
								JSONObject col = cols.getJSONObject(j);
								String colName = "";
								if(col.has("wiseUniqueName")) {
									colName = col.getString("wiseUniqueName");
								} else if(col.has("caption")) {
									colName = col.getString("caption");
								}
								if(datafieldPosition == null || datafieldPosition.equals("column")) {
									pivotSheet.getRow(addRowNum+1).createCell(j+maxRowGroupDepth, CellType.STRING).setCellValue(colName);
									pivotSheet.getRow(addRowNum+1).getCell(j+maxRowGroupDepth).setCellStyle(borderStyle);
								}else {
									pivotSheet.getRow(addRowNum+1).createCell(j+1+maxRowGroupDepth, CellType.STRING).setCellValue(colName);
									pivotSheet.getRow(addRowNum+1).getCell(j+1+maxRowGroupDepth).setCellStyle(borderStyle);
								}
							}
						}
				        
				        
				        int createRowNum = addRowNum+2;
				        
				        List<Integer> subtotalRow = new ArrayList<Integer>();
				        List<Integer> subtotalCol = new ArrayList<Integer>();
				        
				        if(datafieldPosition == null || datafieldPosition.equals("column")) {
				        	// Column 부분
				        	int[] createColtoDepth = new int[maxColGroupDepth];
				        	for(int k = 0; k < maxColGroupDepth; k++) {
				        		createColtoDepth[k] = maxRowGroupDepth;
				        	}
				        	int afterDepth = 0;
				        	int startRowtoColumnDraw = createRowNum;
				        	int startRowColumList = createRowNum;
				        	for (int r = 0; r <= maxColGroupDepth; r++) {
				        		pivotSheet.createRow(createRowNum + r);
				        		startRowColumList = createRowNum + r;
				        	}
				        	
				        	if(rows != null && rows.size() > 0) {
								for(int j = 0; j < rows.size(); j++) {
									JSONObject row = rows.getJSONObject(j);
									String rowName = "";
									if(row.has("wiseUniqueName")) {
										rowName = row.getString("wiseUniqueName");
									} else if(row.has("caption")) {
										rowName = row.getString("caption");
									}
									pivotSheet.getRow(startRowColumList).createCell(j, CellType.STRING).setCellValue(rowName);
									pivotSheet.getRow(startRowColumList).getCell(j).setCellStyle(borderStyle);
								}
							}
				        	int removeColCount = 0;
				        	int grandTotalCheck = 1;
				        	
				        	if(cols.size() > 1) {
				        		grandTotalCheck = 2;
				        	}

				        	
				        	int controlCol = maxColGroupDepth;
				        	if (totalView.getBoolean("ShowColumnGrandTotals") == true) {
			        			int colspan = maxRowGroupDepth;
			        			final int rowspan = maxColGroupDepth;
			        			int lastColspan = colspan + (summaryValueCount - deltaVariationCount) - 1;
			        			controlCol = colspan;
			        			if(maxRowGroupDepth == 0) {
			        				colspan++;
			        				lastColspan--;
			        			}

//			        			if(colspan - 1 > 0 || rowspan > 0) {
//			        				CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + rowspan, 0, colspan - 1);
//			        				pivotSheet.addMergedRegion(mergedRegion);
//			        				addBorderRegion(mergedRegion, pivotSheet);
//			        			}

			        			pivotSheet.getRow(createRowNum).createCell(colspan).setCellValue("총계");
			        			pivotSheet.getRow(createRowNum).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
			        			if(rowspan - 1 >= 0 && lastColspan >= colspan) {
			        				CellRangeAddress mergedRegion2 = new CellRangeAddress(createRowNum, createRowNum + rowspan - 1, colspan, lastColspan);
			        				mergedRegion(pivotSheet, mergedRegion2);
			        				addBorderRegion(mergedRegion2, pivotSheet);
			        			}
			        			
			        			for(int k = 0; k < maxColGroupDepth; k++) {
	        						createColtoDepth[k] = createColtoDepth[k] + (summaryValueCount - deltaVariationCount);
	        					}
			        		}
				        	HashMap<String, Integer> columTotalMap = new HashMap<String,Integer>();
				        	if(maxColGroupDepth > 0 && colGroupParams.get(0).getSelector() != null) {
				        		for(int col = 0; col < colFlattenedSummaryDimensions.length; col++) {
				        			SummaryDimension colDimension = colFlattenedSummaryDimensions[col];
				        			if(colDimension.getDepth() != 0) {
				        				int depth = colDimension.getDepth() - 1;
				        				createRowNum = startRowtoColumnDraw + depth;
				        				int columnNum = createColtoDepth[depth];
				        				if(colDimension.getDepth() < maxColGroupDepth) {
				        					if((afterDepth == 0 || afterDepth != colDimension.getDepth()) && totalView.getBoolean("ShowColumnTotals") == true && cols.size() > 1) {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(colDimension.getKey() + " 전체");
				        						pivotSheet.getRow(createRowNum).getCell(columnNum).setCellStyle(styleMap.get("alignCenter"));
				        						
				        						if(depth < maxColGroupDepth - 1) {
				        							if(col <= grandTotalCheck) {
				        								CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + (maxColGroupDepth - depth) - 1, columnNum, columnNum + summaryValueCount - deltaVariationCount -1);
					        							mergedRegion(pivotSheet, mergedRegion);
					        							addBorderRegion(mergedRegion, pivotSheet);
					        						}else {
					        							CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + (maxColGroupDepth - depth) - 1, columnNum, columnNum + summaryValueCount -1);
					        							mergedRegion(pivotSheet, mergedRegion);
					        							addBorderRegion(mergedRegion, pivotSheet);
					        						}
				        							
				        						}	
				        						columTotalMap.put("전체"+col,col);
				        						
				        						if(col <= grandTotalCheck) {
				        							columnNum = columnNum + summaryValueCount - deltaVariationCount;
				        						}else {
				        							columnNum = columnNum + summaryValueCount;
				        						}
				        						for(int k = 0; k < maxColGroupDepth; k++) {
				        							if(depth < k) {
				        								createColtoDepth[k] = columnNum;
				        							}
				        						}
				        					} else if((afterDepth == 0 || afterDepth != colDimension.getDepth()) && (totalView.getBoolean("ShowColumnTotals") == false || cols.size() <= 1)) {
				        						subtotalCol.add(columnNum + (summaryValueCount * removeColCount));
				        						removeColCount++;
				        						columTotalMap.put("전체"+col,col);
				        					}else {
				        						columTotalMap.put("전체"+col,col);
				        					}

				        					int colspan = 0;
				        					int valueCount = 0;
				        				
				        					
				        					valueCount = summaryValueCount;
				        					
				        					
				        					if(totalView.getBoolean("ShowColumnTotals") == true && cols.size() > 1) {
				        						colspan = SummaryDimensionUtils.getDescendantCount(colDimension) * valueCount;
				        					} else {
				        						colspan = SummaryDimensionUtils.getLeafDescendantCount(colDimension) * valueCount;
				        					}
				        					int colCheck = columnNum - summaryValueCount < 0 ? col-1 : columnNum - summaryValueCount;
				        					
				        					if(col <= grandTotalCheck) {
				        						colspan = colspan - deltaVariationCount;
				        					}
			        						
				        					if("null".equals(colDimension.getKey())) {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(" ");
				        					}else {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(colDimension.getKey());
				        					}
				        					if(colspan > 1) {
				        						for(int span = 0; span < colspan; span++) {
				        							if(span == 0) {
				        								pivotSheet.getRow(createRowNum).getCell(columnNum + span).setCellStyle(styleMap.get("left"));
				        							} else if(span == colspan - 1) {
				        								pivotSheet.getRow(createRowNum).createCell(columnNum + span).setCellStyle(styleMap.get("right"));
				        							} else {
				        								pivotSheet.getRow(createRowNum).createCell(columnNum + span).setCellStyle(styleMap.get("topBottom"));
				        							}
				        						}
				        					}
				        					columnNum = columnNum + colspan;
				        				} else if(colDimension.getDepth() == maxColGroupDepth){
				        					int valueCount = 0;
				        					
				        					valueCount = summaryValueCount;
				        					
				        					int variation = 0;
			        						if(cols.size() < 2 && col <= grandTotalCheck) {
			        							variation = deltaVariationCount;
			        						}
			        						
				        					int colCheck = col-1;
				        					if("null".equals(colDimension.getKey())) {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(" ");
				        					}else {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(colDimension.getKey());
				        					}
				        					if(valueCount == 1) {
				        						pivotSheet.getRow(createRowNum).getCell(columnNum).setCellStyle(styleMap.get("border"));
				        					} else {
				        						
				        						if(columTotalMap.containsKey("전체"+colCheck)) {
					        						for(int span = 0; span < valueCount - deltaVariationCount; span++) {
						        						if(span == 0) {
						        							pivotSheet.getRow(createRowNum).getCell(columnNum + span).setCellStyle(styleMap.get("left"));
						        						} else if(span == valueCount - 1) {
						        							pivotSheet.getRow(createRowNum).createCell(columnNum + span).setCellStyle(styleMap.get("right"));
						        						} else {
						        							pivotSheet.getRow(createRowNum).createCell(columnNum + span).setCellStyle(styleMap.get("topBottom"));
						        						}
						        					}
					        					} else {
					        						
					        						
					        						for(int span = 0; span < valueCount - variation; span++) {
						        						if(span == 0) {
						        							pivotSheet.getRow(createRowNum).getCell(columnNum + span).setCellStyle(styleMap.get("left"));
						        						} else if(span == valueCount - 1) {
						        							pivotSheet.getRow(createRowNum).createCell(columnNum + span).setCellStyle(styleMap.get("right"));
						        						} else {
						        							pivotSheet.getRow(createRowNum).createCell(columnNum + span).setCellStyle(styleMap.get("topBottom"));
						        						}
						        					}
					        					}
				        						
				        					}
				        					if(columTotalMap.containsKey("전체"+colCheck)) {
				        						for (int s = 0; s < valueCount - deltaItemsCount; s++) {
					        						final SummaryParam summaryParam = summaryParams.get(s);
					        						if(meaCaptionNmMapper.containsKey(summaryParam.getSelector())){
								        				pivotSheet.getRow(createRowNum + 1).createCell(columnNum).setCellValue(meaCaptionNmMapper.get(summaryParam.getSelector()));
													}else {
														pivotSheet.getRow(createRowNum + 1).createCell(columnNum).setCellValue(summaryParam.getSelector());
													}
					        						pivotSheet.getRow(createRowNum + 1).getCell(columnNum).setCellStyle(styleMap.get("alignCenter"));
					        						columnNum++;
					        					}
					        					if(deltaItems.size() > 0) {
					        						for (int s = 0; s < deltaItems.size(); s++) {
					        							if(!deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").contains("Variation")) {
					        								pivotSheet.getRow(createRowNum + 1).createCell(columnNum).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
						        							pivotSheet.getRow(createRowNum + 1).getCell(columnNum).setCellStyle(styleMap.get("alignCenter"));
						        							columnNum++;
					        							}
					        						}
					        					}
				        					}else {
				        						for (int s = 0; s < valueCount - deltaItemsCount; s++) {
					        						final SummaryParam summaryParam = summaryParams.get(s);
					        						if(meaCaptionNmMapper.containsKey(summaryParam.getSelector())){
								        				pivotSheet.getRow(createRowNum + 1).createCell(columnNum).setCellValue(meaCaptionNmMapper.get(summaryParam.getSelector()));
													}else {
														pivotSheet.getRow(createRowNum + 1).createCell(columnNum).setCellValue(summaryParam.getSelector());
													}
					        						pivotSheet.getRow(createRowNum + 1).getCell(columnNum).setCellStyle(styleMap.get("alignCenter"));
					        						columnNum++;
					        					}
					        					if(deltaItems.size() > 0) {
					        						for (int s = 0; s < deltaItems.size(); s++) {
					        							if(cols.size() < 2 && col <= grandTotalCheck) {
					        								if(!deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").contains("Variation")) {
						        								pivotSheet.getRow(createRowNum + 1).createCell(columnNum).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
							        							pivotSheet.getRow(createRowNum + 1).getCell(columnNum).setCellStyle(styleMap.get("alignCenter"));
							        							columnNum++;
						        							}
					        							}else {
					        								pivotSheet.getRow(createRowNum + 1).createCell(columnNum).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
						        							pivotSheet.getRow(createRowNum + 1).getCell(columnNum).setCellStyle(styleMap.get("alignCenter"));
						        							columnNum++;
					        							}
					        						}
					        					}
				        					}
				        					
				        				}
				        				afterDepth = colDimension.getDepth();
				        				createColtoDepth[depth] = columnNum;
				        			}
				        		}
				        	}
				        	
				        	
				        	if (totalView.getBoolean("ShowColumnGrandTotals") == false) {
				        		createRowNum = createRowNum + 1;
				        		//pivotSheet.createRow(createRowNum);
				        	} else {
				        		createRowNum = createRowNum + 1;
				        	}

				        	int totalTF = 0;
				        	if (totalView.getBoolean("ShowColumnGrandTotals") == false) {
				        		totalTF++;
				        	}
				        	if(maxRowGroupDepth == 0) {
				        		maxRowGroupDepth++;
				        	}
				        	int colSpanStartNum = maxRowGroupDepth;
				        	removeColCount = 0;
				        	for (int c = totalTF; c < colsNum; c++) {
				        		if(totalView.getBoolean("ShowColumnTotals") == false || cols.size() <= 1) {
				        			if(subtotalCol.contains(colSpanStartNum + (summaryValueCount * removeColCount))) {
				        				removeColCount++;
				        				continue;
				        			}
				        		}
				        		int colCheck = c-1;
				        		for (int s = 0; s < summaryValueCount - deltaItemsCount; s++) {
				        			final SummaryParam summaryParam = summaryParams.get(s);
				        			if(meaCaptionNmMapper.containsKey(summaryParam.getSelector())){
				        				pivotSheet.getRow(createRowNum).createCell(colSpanStartNum).setCellValue(meaCaptionNmMapper.get(summaryParam.getSelector()));
									}else {
										pivotSheet.getRow(createRowNum).createCell(colSpanStartNum).setCellValue(summaryParam.getSelector());
									}
				        			pivotSheet.getRow(createRowNum).getCell(colSpanStartNum).setCellStyle(styleMap.get("alignCenter"));
				        			colSpanStartNum++;
				        		}
				        		if(deltaItems.size() > 0) {
				        			for (int s = 0; s < deltaItems.size(); s++) {
				        				if(c <= grandTotalCheck) {
				        					if(!deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").contains("Variation")) {
				        						pivotSheet.getRow(createRowNum).createCell(colSpanStartNum).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
				        						pivotSheet.getRow(createRowNum).getCell(colSpanStartNum).setCellStyle(styleMap.get("alignCenter"));
				        						colSpanStartNum++;
				        					}
				        				} else {
				        					if(columTotalMap.containsKey("전체"+colCheck)) {
				        						if(!deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").contains("Variation")) {
				        							pivotSheet.getRow(createRowNum).createCell(colSpanStartNum).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
						        					pivotSheet.getRow(createRowNum).getCell(colSpanStartNum).setCellStyle(styleMap.get("alignCenter"));
						        					colSpanStartNum++;
				        						}
				        					}else {
				        						pivotSheet.getRow(createRowNum).createCell(colSpanStartNum).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
					        					pivotSheet.getRow(createRowNum).getCell(colSpanStartNum).setCellStyle(styleMap.get("alignCenter"));
					        					colSpanStartNum++;
				        					}
				        				}
				        			}
				        		}
				        	}
				        	//열 끝

				        	grandTotalCheck = 1;
				        	if(cols.size() > 1) {
				        		if(totalView.getBoolean("ShowColumnTotals") == true) {
				        			grandTotalCheck = 2;
				        		}
				        	}else {
				        		if(totalView.getBoolean("ShowColumnGrandTotals") == true) {
				        			grandTotalCheck = 2;
				        		}
				        	}
				        	createRowNum = createRowNum + 1;
				        	int dataCellNum = 0;
				        	int startRowNum = createRowNum; // 총계 라인 +1
				        	int rowControl = 0;
				        	if (totalView.getBoolean("ShowRowGrandTotals") == true) {
				        		startRowNum++;
				        		rowControl = 0;
				        	}else {
				        		startRowNum++;
				        		rowControl = 1;
				        	}
				        	
				        	for (int r = 0; r < rowsNum; r++) {
				        		pivotSheet.createRow(createRowNum + r);
				        	}
				        	
				        	int[] createRowtoDepth = new int[maxRowGroupDepth];
				        	for(int k = 0; k < maxRowGroupDepth; k++) {
				        		createRowtoDepth[k] = startRowNum;
				        	}
				        	int afterDepthRow = 0;
				        	int removeRowCount = 0;
				        	HashMap<String, Integer> rowTotalMap = new HashMap<String,Integer>();
				        	for(int row = 0; row < rowFlattenedSummaryDimensions.length; row++) {
				        		SummaryDimension rowDimension = rowFlattenedSummaryDimensions[row];
				        		if(rowDimension.getDepth() != 0) {
				        			int depth = rowDimension.getDepth() - 1;
				        			createRowNum = createRowtoDepth[depth];
				        			if(rowDimension.getDepth() < maxRowGroupDepth) {
				        				if((afterDepthRow == 0 || afterDepthRow != rowDimension.getDepth()) && totalView.getBoolean("ShowRowTotals") == true && rows.size() > 1) {
				        					pivotSheet.getRow(createRowNum - rowControl).createCell(depth).setCellValue(rowDimension.getKey() + " 전체");
				        					//pivotSheet.getRow(createRowNum).getCell(depth).setCellStyle(styleMap.get("alignCenter"));
				        					if(depth < maxRowGroupDepth - 1) {
				        						for(int span = 0; span < maxRowGroupDepth - depth; span++) {
				        							if(span == 0) {
				        								pivotSheet.getRow(createRowNum- rowControl).getCell(depth + span).setCellStyle(styleMap.get("left"));
				        							} else if(span == maxRowGroupDepth - depth - 1) {
				        								pivotSheet.getRow(createRowNum- rowControl).createCell(depth + span).setCellStyle(styleMap.get("right"));
				        							} else {
				        								pivotSheet.getRow(createRowNum- rowControl).createCell(depth + span).setCellStyle(styleMap.get("topBottom"));
				        							}
				        						}
				        						/*CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum, depth, maxRowGroupDepth - 1);
				        					pivotSheet.addMergedRegion(mergedRegion);
				        					addBorderRegion(mergedRegion, pivotSheet);*/
				        					}
				        					rowTotalMap.put("전체"+(createRowNum- rowControl),(createRowNum- rowControl));
				        					createRowNum = createRowNum + 1;
				        					for(int k = 0; k < maxRowGroupDepth; k++) {
				        						if(depth < k) {
				        							createRowtoDepth[k] = createRowtoDepth[k] + 1;
				        						}
				        					}
				        				} else if(afterDepthRow == 0 || afterDepthRow != rowDimension.getDepth()){
				        					subtotalRow.add(createRowNum + removeRowCount);
				        					removeRowCount++;
				        					rowTotalMap.put("전체"+(createRowNum- rowControl),(createRowNum- rowControl));
				        				}

				        				int rowspan = 0;
				        				
				        				if(totalView.getBoolean("ShowRowTotals") == true) {
				        					rowspan = SummaryDimensionUtils.getDescendantCount(rowDimension);
				        				} else {
				        					rowspan = SummaryDimensionUtils.getLeafDescendantCount(rowDimension);
				        				}
			        					
				        				if("null".equals(rowDimension.getKey())) {
				        					pivotSheet.getRow(createRowNum - rowControl).createCell(depth).setCellValue(" ");
			        					}else {
			        						pivotSheet.getRow(createRowNum - rowControl).createCell(depth).setCellValue(rowDimension.getKey());
			        					}
				        				//pivotSheet.getRow(createRowNum).getCell(depth).setCellStyle(styleMap.get("alignCenter"));
				        				if(rowspan > 1) {
				        					for(int span = 0; span < rowspan; span++) {
				        						if(span == 0) {
				        							pivotSheet.getRow(createRowNum + span - rowControl).getCell(depth).setCellStyle(styleMap.get("top"));
				        						} else if(span == rowspan - 1) {
				        							pivotSheet.getRow(createRowNum + span - rowControl).createCell(depth).setCellStyle(styleMap.get("bottom"));
				        						} else {
				        							pivotSheet.getRow(createRowNum + span - rowControl).createCell(depth).setCellStyle(styleMap.get("leftRight"));
				        						}
				        					}
				        					/*CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + rowspan - 1, depth, depth);
				        				pivotSheet.addMergedRegion(mergedRegion);
				        				addBorderRegion(mergedRegion, pivotSheet);*/
				        				} else {
				        					pivotSheet.getRow(createRowNum - rowControl).getCell(depth).setCellStyle(styleMap.get("border"));
				        				}
				        				createRowNum = createRowNum + rowspan;
				        			} else if(rowDimension.getDepth() == maxRowGroupDepth){
				        				if("null".equals(rowDimension.getKey())) {
				        					pivotSheet.getRow(createRowNum - rowControl).createCell(depth).setCellValue(" ");
			        					}else {
			        						pivotSheet.getRow(createRowNum - rowControl).createCell(depth).setCellValue(rowDimension.getKey());
			        					}
				        				pivotSheet.getRow(createRowNum - rowControl).getCell(depth).setCellStyle(styleMap.get("alignCenter"));
				        				createRowNum++;
				        			}
				        			afterDepthRow = rowDimension.getDepth();
				        			createRowtoDepth[depth] = createRowNum;
				        		}
				        	}
				        	
				        	int controlRow = 0;
				        	createRowNum = startRowNum - 1;
				        	removeRowCount = 0;
				        	removeColCount = 0;
				        	for (int r = 0; r < rowsNum; r++) {
				        		final SummaryCell colGrandTortalCell = summaryCells[r][0];
				        		
				        		if (r== 0 && totalView.getBoolean("ShowRowGrandTotals") == true) {
				        			final int colspan = maxRowGroupDepth - 1;
				        			pivotSheet.getRow(createRowNum).createCell(0).setCellValue("총계");
				        			pivotSheet.getRow(createRowNum).getCell(0).setCellStyle(styleMap.get("alignCenter"));
				        			controlRow = createRowNum + 1;
				        			if(colspan > 0) {
				        				CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum, 0, colspan);
				        				mergedRegion(pivotSheet, mergedRegion);
				        				addBorderRegion(mergedRegion, pivotSheet);
				        			}
				        		} else if(r== 0 && totalView.getBoolean("ShowRowGrandTotals") == false){
				        			continue;
				        		}
				        		
				        		if(totalView.getBoolean("ShowRowTotals") == false || rows.size() <= 1) {
				        			if(subtotalRow.contains(createRowNum + removeRowCount + rowControl)) {
				        				removeRowCount++;
				        				continue;
				        			}
				        		}
				        		dataCellNum = maxRowGroupDepth;
				        		removeColCount = 0;
				        		// 총계 부분
				        		
				        		SummaryCell precolumnTortalCell = summaryCells[r][1];
				        		SummaryCell nowcolumnTortalCell = summaryCells[r][1];
				        		if(cols.size() <= 1) {
				        			precolumnTortalCell = summaryCells[r][0];
				        			nowcolumnTortalCell = summaryCells[r][0];
			        			}
				        		int columnCount=0;
				        		int columnStartCell = 0;
				        		for (int c = totalTF; c < colsNum; c++) {
				        			columnStartCell =  dataCellNum;
				        			final SummaryCell rowGrandTortalCell = summaryCells[0][c];
				        			SummaryCell rowTortalCell = summaryCells[1][c];
				        			if(rows.size() <= 1) {
				        				rowTortalCell = summaryCells[0][c];
				        			}
				        			if(totalView.getBoolean("ShowColumnTotals") == false || cols.size() <= 1) {
				        				if(columTotalMap.containsKey("전체"+c)) {
				        					if(c > 0) {
				        						precolumnTortalCell = nowcolumnTortalCell;
				        						nowcolumnTortalCell = summaryCells[r][c-1];
				        						columnCount=0;
				        					}
										}
					        			if(subtotalCol.contains(dataCellNum + (summaryValueCount * removeColCount))) {
					        				removeColCount++;
					        				continue;
					        			}
					        		}else {
					        			if(columTotalMap.containsKey("전체"+c)) {
					        				if(c > 0) {
					        					precolumnTortalCell = nowcolumnTortalCell;
					        					nowcolumnTortalCell = summaryCells[r][c];
					        					columnCount=0;
				        					}
										}
					        			
					        		}			        			
				        			if(totalView.getBoolean("ShowRowTotals") == false || rows.size() <= 1) {
				        				if(rowTotalMap.containsKey("전체"+c)) {
				        					if(r > 0) {
				        						rowTortalCell = summaryCells[r-1][c];
				        					}
										}
					        		}else {
					        			if(rowTotalMap.containsKey("전체"+c)) {
					        				rowTortalCell = summaryCells[r][c];
										}
					        		}
				        			
				        			final SummaryCell cell = summaryCells[r][c];
				        			final List<SummaryValue> summaryValues = cell.getSummaryValues();
				        			for(int sc = 0 ; sc < meaString.size(); sc++) {
		        						for (SummaryValue summaryValue : summaryValues) {
					        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && meaString.get(sc).equals(summaryValue.getFieldName())) {
					        					pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellType(CellType.NUMERIC);
					        					BigDecimal value = getExcelCellValue(summaryValue);
					        					pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellValue(value.doubleValue());
					        					
					        					
					        					if(value.toString().equals("0")) {
					        						if(meaCaptionNmMapper.containsKey(summaryValue.getFieldName())){
								        				pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(meaCaptionNmMapper.get(summaryValue.getFieldName())));
													}else {
														pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
													}
					        					} else {
					        						if(meaCaptionNmMapper.containsKey(summaryValue.getFieldName())){
								        				pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(meaCaptionNmMapper.get(summaryValue.getFieldName())));
													}else {
														pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(summaryValue.getFieldName()));
													}
					        					}

					        					dataCellNum++;
					        					break;
					        				}
					        			}
		        					}

				        			if(cell.getSummaryValues().size() == 0) {
				        				for(int s = 0; s < summaryParams.size(); s++) {
				        					pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellValue(0);
				        					pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
				        					pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
				        					dataCellNum++;
				        				}
				        			}

				        			if(deltaItems.size() > 0) {
				        				for (int s = 0; s < deltaItems.size(); s++) {
				        					if(c < 1  || (deltaVariationCount > 0 && c == 1)) {
				        						if(!deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").contains("Variation")) {
				        							if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of GrandTotal")) {
				        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        								
				        								baseMea = baseMea + maxRowGroupDepth;
				        								String colName = CellReference.convertNumToColString(baseMea);
				        								pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName + controlRow + " = 0, 0, ROUND(" + colName + (createRowNum + 1) + "/" + colName + controlRow + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        								dataCellNum++;
				        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column GrandTotal")) {
				        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));

				        								String colName2 = CellReference.convertNumToColString(columnStartCell + baseMea);
				        								
			        				        			final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			
			        				        			pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        								dataCellNum++;
				        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column")) {
				        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));

//				        								String colName2 = CellReference.convertNumToColString(dataCellNum - s - (summaryValueCount - deltaItemsCount - deltaVariationCount) + baseMea);
				        								String colName2 = CellReference.convertNumToColString(columnStartCell + baseMea);
					        							
				        								if( r<1 && totalView.getBoolean("ShowRowGrandTotals") == true) {
		        											final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
			        										pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        										}else if(rowTotalMap.containsKey("전체"+(createRowNum)) && totalView.getBoolean("ShowRowTotals") == true) {
				        				        			final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
			        										pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        									}else {
			        										final List<SummaryValue> rowTortalsummaryValues = rowTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : rowTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
				        				        			pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        									}
			        				        			
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        								dataCellNum++;
				        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row")){
				        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        								int standardCol = baseMea + maxRowGroupDepth;
				        								
				        								String colName = CellReference.convertNumToColString(standardCol);	
				        								String colName2 = CellReference.convertNumToColString(columnStartCell + baseMea);
				        								
				        								if( c<1 && totalView.getBoolean("ShowColumnGrandTotals") == true) {
		        											final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
			        										pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        										}else if(columnCount == 0 && totalView.getBoolean("ShowColumnTotals") == true) {
				        				        			final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
			        										pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        									}else {
			        										final List<SummaryValue> colTortalsummaryValues = nowcolumnTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : colTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
				        				        			pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        									}

					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							dataCellNum++;
				        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row GrandTotal")){
				        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        								int standardCol = baseMea + maxRowGroupDepth;
				        								
				        								String colName = CellReference.convertNumToColString(standardCol);
				        								String colName2 = CellReference.convertNumToColString(columnStartCell + baseMea);
				        								if(totalView.getBoolean("ShowColumnGrandTotals") == true) {
				        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName + (createRowNum + 1) + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + colName + (createRowNum + 1) + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
				        								}else {
				        				        			final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
				        				        			
				        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
				        								}
				        								
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        								dataCellNum++;
				        							} else {
				        								pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellValue("");
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
				        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("alignCenter"));
				        								dataCellNum++;
				        							}
				        						}
				        					} else {
				        						if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of GrandTotal")) {
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							
				        							String colName = CellReference.convertNumToColString(baseMea+maxRowGroupDepth);
				        							
				        							if(totalTF == 0) {
				        								baseMea = baseMea + (summaryValueCount * c) + maxRowGroupDepth - deltaVariationCount;
				        							} else {
				        								baseMea = baseMea + (summaryValueCount * (c - 1)) + maxRowGroupDepth - deltaVariationCount;
				        							}
				        							
				        							String colName2 = CellReference.convertNumToColString(baseMea);
				        							pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName + controlRow + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + colName + controlRow + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        							dataCellNum++;
			        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column GrandTotal")) {
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							String colName2 = CellReference.convertNumToColString(columnStartCell + baseMea);
				        							
		        				        			final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
		        				        			BigDecimal value = BigDecimal.valueOf(0);
		        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
		        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
		        				        					value = getExcelCellValue(summaryValue);
		        				        					break;
		        				        				}
		        				        			}
		        				        			
		        				        			pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        								
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        							dataCellNum++;
				        						} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column")) {
			        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
			        								String colName2 = CellReference.convertNumToColString(columnStartCell + baseMea);
				        							
			        								
			        								if( r<1 && totalView.getBoolean("ShowRowGrandTotals") == true) {
	        											final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
		        										pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
	        										}else if(rowTotalMap.containsKey("전체"+(createRowNum)) && totalView.getBoolean("ShowRowTotals") == true) {
			        				        			final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
		        										pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        									}else {
		        										final List<SummaryValue> rowTortalsummaryValues = rowTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : rowTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        									}
		        				        			
			        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//			        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
			        								pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
			        								dataCellNum++;
			        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Absolute Variation")){
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							
				        							String colName1 = null;

				        							String colName2 = null;
				        							
				        							
//				        							if(totalView.getBoolean("ShowColumnTotals") == true) {
				        								if(columnCount < grandTotalCheck) {
		        											if(columTotalMap.containsKey("전체"+(c)) && c > 2) {
		        												
		        												final List<SummaryValue> precolTortalsummaryValues = precolumnTortalCell.getSummaryValues();
		        												final List<SummaryValue> nowcolTortalsummaryValues = nowcolumnTortalCell.getSummaryValues();
		    		        				        			BigDecimal value = BigDecimal.valueOf(0);
		    		        				        			BigDecimal value2 = BigDecimal.valueOf(0);
		    		        				        			for (SummaryValue summaryValue : precolTortalsummaryValues) {
		    		        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
		    		        				        					value = getExcelCellValue(summaryValue);
		    		        				        					break;
		    		        				        				}
		    		        				        			}
		    		        				        			
		    		        				        			for (SummaryValue summaryValue : nowcolTortalsummaryValues) {
		    		        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
		    		        				        					value2 = getExcelCellValue(summaryValue);
		    		        				        					break;
		    		        				        				}
		    		        				        			}
		    		        				        			
					        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula(value2 + "-" + value);
					        									pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//								        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("comma"));
							        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
							        							dataCellNum++;
			        										}	
				        								}else if(columnCount == grandTotalCheck) {
				        									colName1 = CellReference.convertNumToColString(columnStartCell + baseMea);
				        									colName2 = CellReference.convertNumToColString(columnStartCell - (summaryValueCount - deltaVariationCount) + baseMea);
				        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula(colName1 + (createRowNum + 1) + "-" + colName2 + (createRowNum + 1));
				        									pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//						        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("comma"));
						        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
						        							dataCellNum++;
				        								}else {
				        									colName1 = CellReference.convertNumToColString(columnStartCell + baseMea);
				        									colName2 = CellReference.convertNumToColString(columnStartCell - summaryValueCount + baseMea);
				        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula(colName1 + (createRowNum + 1) + "-" + colName2 + (createRowNum + 1));
				        									pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//						        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("comma"));
						        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
						        							dataCellNum++;
				        								}
//		        									}
				        							
				        							
				        						} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Variation")){
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							
				        							String colName1 = null;

				        							String colName2 = null;
				        							
				        							if(columnCount < grandTotalCheck) {
	        											if(columTotalMap.containsKey("전체"+(c)) && c > 2) {
	        												
	        												final List<SummaryValue> precolTortalsummaryValues = precolumnTortalCell.getSummaryValues();
	        												final List<SummaryValue> nowcolTortalsummaryValues = nowcolumnTortalCell.getSummaryValues();
	    		        				        			BigDecimal value = BigDecimal.valueOf(0);
	    		        				        			BigDecimal value2 = BigDecimal.valueOf(0);
	    		        				        			for (SummaryValue summaryValue : precolTortalsummaryValues) {
	    		        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
	    		        				        					value = getExcelCellValue(summaryValue);
	    		        				        					break;
	    		        				        				}
	    		        				        			}
	    		        				        			
	    		        				        			for (SummaryValue summaryValue : nowcolTortalsummaryValues) {
	    		        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
	    		        				        					value2 = getExcelCellValue(summaryValue);
	    		        				        					break;
	    		        				        				}
	    		        				        			}
	    		        				        			
				        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, (" + value2 + "-" + value + ")/" + value + ")");
						        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//							        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
						        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
						        							dataCellNum++;
		        										}	
			        								}else if(columnCount == grandTotalCheck) {
			        									colName1 = CellReference.convertNumToColString(columnStartCell + baseMea);
			        									colName2 = CellReference.convertNumToColString(columnStartCell - (summaryValueCount - deltaVariationCount)  + baseMea);
			        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName2 + (createRowNum + 1) + " = 0, 0, (" + colName1 + (createRowNum + 1) + "-" + colName2 + (createRowNum + 1) + ")/" + colName2 + (createRowNum + 1) + ")");
					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							dataCellNum++;
			        								}else {
			        									colName1 = CellReference.convertNumToColString(columnStartCell + baseMea);
			        									colName2 = CellReference.convertNumToColString(columnStartCell - summaryValueCount + baseMea);
			        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName2 + (createRowNum + 1) + " = 0, 0, (" + colName1 + (createRowNum + 1) + "-" + colName2 + (createRowNum + 1) + ")/" + colName2 + (createRowNum + 1) + ")");
					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
					        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							dataCellNum++;
			        								}
				        							
				        						} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row")){
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
			        								int standardCol = baseMea + maxRowGroupDepth;
			        								
			        								String colName = CellReference.convertNumToColString(standardCol);
			        								String colName2 = CellReference.convertNumToColString(columnStartCell + baseMea);
			        								
			        								
	        										if( c<1 && totalView.getBoolean("ShowColumnGrandTotals") == true) {
	        											final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
		        										pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
	        										}else if(columnCount == 0 && totalView.getBoolean("ShowColumnTotals") == true) {
			        				        			final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
		        										pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        									}else {
		        										final List<SummaryValue> colTortalsummaryValues = nowcolumnTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : colTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        									}

				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        							dataCellNum++;
			        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row GrandTotal")){
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
			        								int standardCol = baseMea + maxRowGroupDepth;
			        								
			        								String colName = CellReference.convertNumToColString(standardCol);
			        								String colName2 = CellReference.convertNumToColString(columnStartCell + baseMea);
				        							
			        								
			        								if(totalView.getBoolean("ShowColumnGrandTotals") == true) {
			        									pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName + (createRowNum + 1) + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + colName + (createRowNum + 1) + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        								}else {
			        				        			final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			
			        				        			pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName2 + (createRowNum + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        								}
			        								
			        								
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        							dataCellNum++;
			        							} else {
				        							pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellValue("");
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
				        							pivotSheet.getRow(createRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("alignCenter"));
				        							dataCellNum++;
				        						}
				        					}
				        				}
				        			}
				        			columnCount++;
				        		}
				        		createRowNum++;
				        	}
				        	
				        	for(int c = 0; c < colSpanStartNum; c++) {
				        		pivotSheet.autoSizeColumn(c);
				        	}
				        } else {
					        if(maxRowGroupDepth == 0) {
					        	maxRowGroupDepth = 1;
					        }
//				        	int colSpanStartNum = maxRowGroupDepth + 1;
//				        	for (int r = 0; r < maxColGroupDepth; r++) {
//				        		createRowNum = createRowNum + r;
//				        		pivotSheet.createRow(createRowNum);
//				        		if (r == 0 && totalView.getBoolean("ShowColumnGrandTotals") == true) {
//				        			int colspan = maxRowGroupDepth;
//				        			final int rowspan = maxColGroupDepth - 1;
	//
//				        			if(rowGroupParams.size() != 0) {
//				        				colspan++;
//				        			}
	//
//				        			if(colspan - 1 > 0 || rowspan > 0) {
//				        				CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + rowspan, 0, colspan - 1);
//				        				mergedRegion(pivotSheet, mergedRegion);
//				        				addBorderRegion(mergedRegion, pivotSheet);
//				        			}
	//
//				        			pivotSheet.getRow(createRowNum).createCell(colspan).setCellValue("총계");
//				        			pivotSheet.getRow(createRowNum).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
//				        			if(rowspan - 1 > 0) {
//				        				CellRangeAddress mergedRegion2 = new CellRangeAddress(createRowNum, createRowNum + rowspan - 1, colspan, colspan);
//				        				mergedRegion(pivotSheet, mergedRegion2);
//				        				addBorderRegion(mergedRegion2, pivotSheet);
//				        			}
//				        			colSpanStartNum++;
//				        		}
	//
//				        		// 측정값 개수 +
//				        		int colSpanInterval = 0;
//				        		for (int c = 1; c < colsNum; c++) {
//				        			final SummaryDimension colDimension = colFlattenedSummaryDimensions[c];
//				        			final int colDepth = colDimension.getDepth();
//				        			if (r < maxColGroupDepth - 1) {
//				        				if (colDepth == r + 1) {
//				        					final AtomicInteger spanSizeCounter = new AtomicInteger();
//				        					countSummaryDimensionSpanningSize(spanSizeCounter, colDimension);
//				        					int colspan = spanSizeCounter.intValue();
	//
//				        					if(colSpanInterval != 0){
//				        						colSpanStartNum += colSpanInterval + 1;
//				        					}
//				        					if(maxColGroupDepth > 1) {
//				        						if(colDepth < maxColGroupDepth) {
//				        							colspan = colspan - 1;
//				        						}
//				        					}
//				        					colSpanInterval = colspan;
	//
//				        					if(colDimension.getKey() != null && !colDimension.getKey().equals("null") && !colDimension.getKey().equals("")) {
//				        						pivotSheet.getRow(createRowNum).createCell(colSpanStartNum).setCellValue(colDimension.getKey());
//				        						pivotSheet.getRow(createRowNum).getCell(colSpanStartNum).setCellStyle(styleMap.get("alignCenter"));
//				        						if(colspan > 0) {
//				        							CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum, colSpanStartNum, colSpanStartNum + colspan);
//				        							mergedRegion(pivotSheet, mergedRegion);
//				        							addBorderRegion(mergedRegion, pivotSheet);
//				        						}
//				        					}
//				        				}
//				        			}
//				        			else {
//				        				if (colDepth < r + 1 && totalView.getBoolean("ShowColumnTotals") == true && maxColGroupDepth > 1) {
//				        					pivotSheet.getRow(createRowNum).createCell(colSpanStartNum).setCellValue("전체");
//				        					pivotSheet.getRow(createRowNum).getCell(colSpanStartNum).setCellStyle(styleMap.get("alignCenter"));
//				        					colSpanStartNum++;
//				        				}
//				        				else {
//				        					pivotSheet.getRow(createRowNum).createCell(colSpanStartNum).setCellValue(colDimension.getKey());
//				        					pivotSheet.getRow(createRowNum).getCell(colSpanStartNum).setCellStyle(styleMap.get("alignCenter"));
//				        					colSpanStartNum++;
//				        				}
//				        			}
//				        		}
//				        	}
					        int[] createColtoDepth = new int[maxColGroupDepth];
				        	for(int k = 0; k < maxColGroupDepth; k++) {
				        		createColtoDepth[k] = maxRowGroupDepth + 1;
				        	}
				        	int afterDepth = 0;
				        	int startRowtoColumnDraw = createRowNum;
				        	int startRowColumList = createRowNum;
				        	for (int r = 0; r <= maxColGroupDepth; r++) {
				        		pivotSheet.createRow(createRowNum + r);
				        		startRowColumList = createRowNum + r;
				        	}
				        	int controlColumn = maxRowGroupDepth;
				        	int removeColCount = 0;
				        	if (totalView.getBoolean("ShowColumnGrandTotals") == true) {
			        			int colspan = maxRowGroupDepth + 1;
			        			final int rowspan = maxColGroupDepth;
			        			controlColumn = colspan;
//			        			if(rowspan - 1 > 0 && colspan - 1 > 0) {
//			        				CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + rowspan - 1, 0, colspan - 1);
//			        				mergedRegion(pivotSheet, mergedRegion);
//			        				addBorderRegion(mergedRegion, pivotSheet);
//			        			}

			        			pivotSheet.getRow(createRowNum).createCell(colspan).setCellValue("총계");
			        			pivotSheet.getRow(createRowNum).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
			        			if(rowspan - 1 > 0) {
			        				CellRangeAddress mergedRegion2 = new CellRangeAddress(createRowNum, createRowNum + rowspan - 1, colspan, colspan);
				        			mergedRegion(pivotSheet, mergedRegion2);
				        			addBorderRegion(mergedRegion2, pivotSheet);
			        			}
			        			for(int k = 0; k < maxColGroupDepth; k++) {
					        		createColtoDepth[k] = createColtoDepth[k] + 1;
					        	}
			        		} else {	
			        			int colspan = maxRowGroupDepth + 1;
			        			final int rowspan = maxColGroupDepth;
			        			
			        			if(rowspan - 1 > 0) {
			        				CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + rowspan - 1, 0, colspan);
			        				mergedRegion(pivotSheet, mergedRegion);
			        				addBorderRegion(mergedRegion, pivotSheet);
			        			}
			        		}
				        	HashMap<String, Integer> columTotalMap = new HashMap<String,Integer>();
				        	if(maxColGroupDepth > 0) {
				        		for(int col = 0; col < colFlattenedSummaryDimensions.length; col++) {
				        			SummaryDimension colDimension = colFlattenedSummaryDimensions[col];
				        			if(colDimension.getDepth() != 0) {
				        				int depth = colDimension.getDepth() - 1;
				        				createRowNum = startRowtoColumnDraw + depth;
				        				int columnNum = createColtoDepth[depth];
				        				if(colDimension.getDepth() < maxColGroupDepth) {
				        					if((afterDepth == 0 || afterDepth != colDimension.getDepth()) && totalView.getBoolean("ShowColumnTotals") == true && cols.size() > 1) {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(colDimension.getKey() + " 전체");
				        						pivotSheet.getRow(createRowNum).getCell(columnNum).setCellStyle(styleMap.get("alignCenter"));
				        						if(depth < maxColGroupDepth - 1) {
				        							CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + (maxColGroupDepth - depth) - 1, columnNum, columnNum);
				        							mergedRegion(pivotSheet, mergedRegion);
				        							addBorderRegion(mergedRegion, pivotSheet);
				        						}
				        						columTotalMap.put("전체"+columnNum,columnNum);
				        						columnNum = columnNum + 1;
				        						for(int k = 0; k < maxColGroupDepth; k++) {
				        							if(depth < k) {
				        								createColtoDepth[k] = columnNum;
				        							}
				        						}
				        					} else if((afterDepth == 0 || afterDepth != colDimension.getDepth()) && (totalView.getBoolean("ShowColumnTotals") == false || cols.size() <= 1)) {
				        						subtotalCol.add(columnNum + removeColCount);
				        						removeColCount++;
				        						columTotalMap.put("전체"+columnNum,columnNum);
				        					}

				        					int colspan = 0;
				        					if(totalView.getBoolean("ShowColumnTotals") == true && cols.size() > 1) {
				        						colspan = SummaryDimensionUtils.getDescendantCount(colDimension);
				        					} else {
				        						colspan = SummaryDimensionUtils.getLeafDescendantCount(colDimension);
				        					}

				        					
				        					if("null".equals(colDimension.getKey())) {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(" ");
					        				}else {
					        					pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(colDimension.getKey());
					        				}
				        					if(colspan > 1) {
				        						for(int span = 0; span < colspan; span++) {
				        							if(span == 0) {
				        								pivotSheet.getRow(createRowNum).getCell(columnNum + span).setCellStyle(styleMap.get("left"));
				        							} else if(span == colspan - 1) {
				        								pivotSheet.getRow(createRowNum).createCell(columnNum + span).setCellStyle(styleMap.get("right"));
				        							} else {
				        								pivotSheet.getRow(createRowNum).createCell(columnNum + span).setCellStyle(styleMap.get("topBottom"));
				        							}
				        						}
				        					}
				        					columnNum = columnNum + colspan;
				        				} else if(colDimension.getDepth() == maxColGroupDepth){
				        					if("null".equals(colDimension.getKey())) {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(" ");
					        					pivotSheet.getRow(createRowNum).getCell(columnNum).setCellStyle(styleMap.get("border"));
				        					}else {
				        						pivotSheet.getRow(createRowNum).createCell(columnNum).setCellValue(colDimension.getKey());
					        					pivotSheet.getRow(createRowNum).getCell(columnNum).setCellStyle(styleMap.get("border"));
				        					}
				        					columnNum++;
				        				}
				        				afterDepth = colDimension.getDepth();
				        				createColtoDepth[depth] = columnNum;
				        			}
				        		}
				        	}

				        	int totalTF = 0;
				        	if (totalView.getBoolean("ShowColumnGrandTotals") == false) {
				        		totalTF++;
				        	}

				        	
				        	createRowNum = createRowNum + 1;
				        	int dataRowNum = 0;
				        	int startRowNum = createRowNum;
				        	int firstRowNum = createRowNum;
				        	if (totalView.getBoolean("ShowRowGrandTotals") == true) {
				        		startRowNum += summaryValueCount;
				        	}
				        	int[] createRowtoDepth = new int[maxRowGroupDepth];
				        	for(int k = 0; k < maxRowGroupDepth; k++) {
				        		createRowtoDepth[k] = startRowNum;
				        	}
				        	afterDepth = 0;
				        	int removeRowCount = 0;
				        	for (int r = 0; r < (rowsNum + 10) * summaryValueCount; r++) {
				        		pivotSheet.createRow(createRowNum + r);
				        	}
				        	if(rows != null && rows.size() > 0) {
								for(int j = 0; j < rows.size(); j++) {
									JSONObject row = rows.getJSONObject(j);
									String rowName = "";
									if(row.has("wiseUniqueName")) {
										rowName = row.getString("wiseUniqueName");
									} else if(row.has("caption")) {
										rowName = row.getString("caption");
									}
									pivotSheet.getRow(startRowColumList-1).createCell(j, CellType.STRING).setCellValue(rowName);
									pivotSheet.getRow(startRowColumList-1).getCell(j).setCellStyle(borderStyle);
								}
							}
				        	HashMap<String, Integer> rowTotalMap = new HashMap<String,Integer>();
				        	for(int row = 0; row < rowFlattenedSummaryDimensions.length; row++) {
				        		SummaryDimension rowDimension = rowFlattenedSummaryDimensions[row];
				        		if(rowDimension.getDepth() != 0) {
				        			int depth = rowDimension.getDepth() - 1;
				        			createRowNum = createRowtoDepth[depth];
				        			dataRowNum = createRowNum;
				        			if(rowDimension.getDepth() < maxRowGroupDepth) {
				        				if(afterDepth == 0 || afterDepth != rowDimension.getDepth()) {
				        					pivotSheet.getRow(createRowNum).createCell(depth).setCellValue(rowDimension.getKey() + " 전체");
				        					pivotSheet.getRow(createRowNum).getCell(depth).setCellStyle(styleMap.get("alignCenter"));
				        					if(depth < maxRowGroupDepth - 1) {
				        						/*for(int span = 0; span < maxRowGroupDepth - depth + 2; span++) {
				        							if(span == 0) {
				        								pivotSheet.getRow(createRowNum).getCell(depth + span).setCellStyle(styleMap.get("left"));
				        							} else if(span == maxRowGroupDepth - depth) {
				        								pivotSheet.getRow(createRowNum).createCell(depth + span).setCellStyle(styleMap.get("right"));
				        							} else {
				        								pivotSheet.getRow(createRowNum).createCell(depth + span).setCellStyle(styleMap.get("topBottom"));
				        							}
				        						}*/
				        						CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + summaryValueCount -1, depth, maxRowGroupDepth -1);
				        						mergedRegion(pivotSheet, mergedRegion);
				        						addBorderRegion(mergedRegion, pivotSheet);
				        					}
				        					rowTotalMap.put("전체"+(createRowNum),(createRowNum));
				        					int colspan = maxRowGroupDepth;
						        			for (int s = 0; s < summaryValueCount - deltaItemsCount; s++) {
							        			final SummaryParam summaryParam = summaryParams.get(s);
							        			if(meaCaptionNmMapper.containsKey(summaryParam.getSelector())){
							        				pivotSheet.getRow(dataRowNum).createCell(colspan).setCellValue(meaCaptionNmMapper.get(summaryParam.getSelector()));
												}else {
													pivotSheet.getRow(dataRowNum).createCell(colspan).setCellValue(summaryParam.getSelector());
												}
							        			pivotSheet.getRow(dataRowNum).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
							        			dataRowNum++;
							        		}
							        		if(deltaItems.size() > 0) {
							        			for (int s = 0; s < deltaItems.size(); s++) {
							        				pivotSheet.getRow(dataRowNum).createCell(colspan).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
							        				pivotSheet.getRow(dataRowNum).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
							        				dataRowNum++;
							        			}
							        		}
				        					createRowNum = createRowNum + summaryValueCount;
				        					subtotalRow.add(createRowNum - 1);
				        					for(int k = 0; k < maxRowGroupDepth; k++) {
				        						if(depth < k) {
				        							createRowtoDepth[k] = createRowtoDepth[k] + summaryValueCount;
				        						}
				        					}
				        				} else if(afterDepth == 0 || afterDepth != rowDimension.getDepth()){
				        					subtotalRow.add(createRowNum + removeRowCount);
				        					removeRowCount++;
				        					rowTotalMap.put("전체"+(createRowNum),(depth));
				        				}

				        				int rowspan = SummaryDimensionUtils.getDescendantCount(rowDimension) * summaryValueCount;

				        				
				        				if("null".equals(rowDimension.getKey())) {
				        					pivotSheet.getRow(createRowNum).createCell(depth).setCellValue(" ");
				        				}else {
				        					pivotSheet.getRow(createRowNum).createCell(depth).setCellValue(rowDimension.getKey());
				        				}
				        				
				        				//pivotSheet.getRow(createRowNum).getCell(depth).setCellStyle(styleMap.get("alignCenter"));
				        				if(rowspan > 1) {
				        					for(int span = 0; span < rowspan; span++) {
				        						if(span == 0) {
				        							pivotSheet.getRow(createRowNum + span).getCell(depth).setCellStyle(styleMap.get("top"));
				        						} else if(span == rowspan - 1) {
				        							pivotSheet.getRow(createRowNum + span).createCell(depth).setCellStyle(styleMap.get("bottom"));
				        						} else {
				        							pivotSheet.getRow(createRowNum + span).createCell(depth).setCellStyle(styleMap.get("leftRight"));
				        						}
				        					}
				        					/*CellRangeAddress mergedRegion = new CellRangeAddress(createRowNum, createRowNum + rowspan - 1, depth, depth);
				        				pivotSheet.addMergedRegion(mergedRegion);
				        				addBorderRegion(mergedRegion, pivotSheet);*/
				        				}
				        				createRowNum = createRowNum + rowspan;
				        			} else if(rowDimension.getDepth() == maxRowGroupDepth){
				        				if("null".equals(rowDimension.getKey())) {
				        					pivotSheet.getRow(createRowNum).createCell(depth).setCellValue(" ");
				        				}else {
				        					pivotSheet.getRow(createRowNum).createCell(depth).setCellValue(rowDimension.getKey());
				        				}
				        				for(int span = 0; span < summaryValueCount; span++) {
			        						if(span == 0) {
			        							pivotSheet.getRow(createRowNum + span).getCell(depth).setCellStyle(styleMap.get("top"));
			        						} else if(span == summaryValueCount - 1) {
			        							pivotSheet.getRow(createRowNum + span).createCell(depth).setCellStyle(styleMap.get("bottom"));
			        						} else {
			        							pivotSheet.getRow(createRowNum + span).createCell(depth).setCellStyle(styleMap.get("leftRight"));
			        						}
			        					}
				        				int colspan = maxRowGroupDepth;
					        			for (int s = 0; s < summaryValueCount - deltaItemsCount; s++) {
						        			final SummaryParam summaryParam = summaryParams.get(s);
						        			if(meaCaptionNmMapper.containsKey(summaryParam.getSelector())){
						        				pivotSheet.getRow(dataRowNum).createCell(colspan).setCellValue(meaCaptionNmMapper.get(summaryParam.getSelector()));
											}else {
												pivotSheet.getRow(dataRowNum).createCell(colspan).setCellValue(summaryParam.getSelector());
											}
						        			pivotSheet.getRow(dataRowNum).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
						        			dataRowNum++;
						        		}
						        		if(deltaItems.size() > 0) {
						        			for (int s = 0; s < deltaItems.size(); s++) {
						        				pivotSheet.getRow(dataRowNum).createCell(colspan).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
						        				pivotSheet.getRow(dataRowNum).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
						        				dataRowNum++;
						        			}
						        		}
				        				createRowNum = createRowNum + summaryValueCount;
				        			}
				        			afterDepth = rowDimension.getDepth();
				        			createRowtoDepth[depth] = createRowNum;
				        		} else if(maxRowGroupDepth == 1 && (rowDimension.getKey() != null && rowDimension.getKey().equals("null"))) {
				        			dataRowNum = startRowNum;
				        			/* ktkang 1004번 오류 수정  */
				        			/*CellRangeAddress mergedRegion = new CellRangeAddress(dataRowNum, dataRowNum + summaryValueCount -1, 0, 0);
				        			mergedRegion(pivotSheet, mergedRegion);
				        			addBorderRegion(mergedRegion, pivotSheet);*/

			        				for (int s = 0; s < summaryValueCount - deltaItemsCount; s++) {
					        			final SummaryParam summaryParam = summaryParams.get(s);
					        			if(meaCaptionNmMapper.containsKey(summaryParam.getSelector())){
					        				pivotSheet.getRow(dataRowNum).createCell(1).setCellValue(meaCaptionNmMapper.get(summaryParam.getSelector()));
										}else {
											pivotSheet.getRow(dataRowNum).createCell(1).setCellValue(summaryParam.getSelector());
										}
					        			pivotSheet.getRow(dataRowNum).getCell(1).setCellStyle(styleMap.get("alignCenter"));
					        			dataRowNum++;
					        		}
			        				if(deltaItems.size() > 0) {
					        			for (int s = 0; s < deltaItems.size(); s++) {
					        				pivotSheet.getRow(dataRowNum).createCell(1).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
					        				pivotSheet.getRow(dataRowNum).getCell(1).setCellStyle(styleMap.get("alignCenter"));
					        				dataRowNum++;
					        			}
					        		}
			        			} else if(maxRowGroupDepth == 1 && rowDimension.getKey() == null) {
			        				dataRowNum = startRowNum;
			        				/* ktkang 1004번 오류 수정  */
			        				/*CellRangeAddress mergedRegion = new CellRangeAddress(dataRowNum, dataRowNum + summaryValueCount -1, 0, 0);
			        				mergedRegion(pivotSheet, mergedRegion);
			        				addBorderRegion(mergedRegion, pivotSheet);*/
			        				
			        				for (int s = 0; s < summaryValueCount - deltaItemsCount; s++) {
					        			final SummaryParam summaryParam = summaryParams.get(s);
					        			if(meaCaptionNmMapper.containsKey(summaryParam.getSelector())){
					        				pivotSheet.getRow(dataRowNum).createCell(1).setCellValue(meaCaptionNmMapper.get(summaryParam.getSelector()));
										}else {
											pivotSheet.getRow(dataRowNum).createCell(1).setCellValue(summaryParam.getSelector());
										}
					        			pivotSheet.getRow(dataRowNum).getCell(1).setCellStyle(styleMap.get("alignCenter"));
					        			dataRowNum++;
					        		}
			        				if(deltaItems.size() > 0) {
					        			for (int s = 0; s < deltaItems.size(); s++) {
					        				pivotSheet.getRow(dataRowNum).createCell(1).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
					        				pivotSheet.getRow(dataRowNum).getCell(1).setCellStyle(styleMap.get("alignCenter"));
					        				dataRowNum++;
					        			}
					        		}
			        			}
				        	}

				        	int dataCellNum = 0;
				        	removeColCount = 0;
				        	removeRowCount = 0;
				        	int controlRow = 0;
				        	
				        	for (int r = 0; r < rowsNum; r++) {
				        		// 총계 부분
				        		final SummaryCell colGrandTortalCell = summaryCells[r][0];
				        		if (r== 0 && totalView.getBoolean("ShowRowGrandTotals") == true) {
				        			int colspan = maxRowGroupDepth - 1;
				        			int totalRow = firstRowNum;
				        			pivotSheet.getRow(totalRow).createCell(0).setCellValue("총계");
				        			pivotSheet.getRow(totalRow).getCell(0).setCellStyle(styleMap.get("alignCenter"));
				        			controlRow = totalRow + 1;
				        			if(!(colspan <= 0 && summaryValueCount < 2)) {
				        				CellRangeAddress mergedRegion = new CellRangeAddress(totalRow, totalRow + summaryValueCount - 1, 0, colspan);
				        				mergedRegion(pivotSheet, mergedRegion);
				        				addBorderRegion(mergedRegion, pivotSheet);
				        			}
				        			
				        			colspan = colspan + 1;
				        			for (int s = 0; s < summaryValueCount - deltaItemsCount; s++) {
					        			final SummaryParam summaryParam = summaryParams.get(s);
					        			if(meaCaptionNmMapper.containsKey(summaryParam.getSelector())){
					        				pivotSheet.getRow(totalRow).createCell(colspan).setCellValue(meaCaptionNmMapper.get(summaryParam.getSelector()));
										}else {
											pivotSheet.getRow(totalRow).createCell(colspan).setCellValue(summaryParam.getSelector());
										}
					        			pivotSheet.getRow(totalRow).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
					        			totalRow++;
					        		}
					        		if(deltaItems.size() > 0) {
					        			for (int s = 0; s < deltaItems.size(); s++) {
					        				pivotSheet.getRow(totalRow).createCell(colspan).setCellValue(deltaItems.getJSONObject(s).getString("CAPTION"));
					        				pivotSheet.getRow(totalRow).getCell(colspan).setCellStyle(styleMap.get("alignCenter"));
					        				totalRow++;
					        			}
					        		}
				        		}else if (r== 0 && totalView.getBoolean("ShowRowGrandTotals") == false){
				        			continue;
				        		}
				        		
				        		removeColCount = 0;
				        		if(totalView.getBoolean("ShowRowTotals") == false || rows.size() <= 1) {
				        			if(subtotalRow.contains(firstRowNum + removeRowCount)) {
				        				removeRowCount++;
				        				continue;
				        			}
				        		}
				        		
				        		dataCellNum = maxRowGroupDepth + 1;
				        		dataRowNum = firstRowNum;
				        		SummaryCell columnTortalCell = summaryCells[r][1];
				        		for (int c = totalTF; c < colsNum; c++) {
				        			final SummaryCell rowGrandTortalCell = summaryCells[0][c];
				        			SummaryCell rowTortalCell = summaryCells[1][c];
				        			if(totalView.getBoolean("ShowColumnTotals") == false || cols.size() <= 1) {
				        				if(columTotalMap.containsKey("전체"+dataCellNum)) {
				        					if(c > 0) {
				        						columnTortalCell = summaryCells[r][c-1];
				        					}
										}
					        			if(subtotalCol.contains(dataCellNum + removeColCount)) {
					        				removeColCount++;
					        				continue;
					        			}
					        		}else {
					        			if(columTotalMap.containsKey("전체"+dataCellNum)) {
					        				columnTortalCell = summaryCells[r][c];
										}
					        		}
				        			
				        			
				        			if(totalView.getBoolean("ShowRowTotals") == false || rows.size() <= 1) {
				        				if(rowTotalMap.containsKey("전체"+dataRowNum)) {
				        					if(r > 0) {
				        						rowTortalCell = summaryCells[r-1][c];
				        					}
										}
					        		}else {
					        			if(rowTotalMap.containsKey("전체"+dataRowNum)) {
					        				rowTortalCell = summaryCells[r][c];
										}
					        		}
				        			
				        			final SummaryCell cell = summaryCells[r][c];
				        			final List<SummaryValue> summaryValues = cell.getSummaryValues();
				        			
				        			dataRowNum = firstRowNum;
				        			HashMap<String, Integer> meaRowLocation = new HashMap<String, Integer>();
		        					for(int sc = 0 ; sc < meaString.size(); sc++) {
		        						for (SummaryValue summaryValue : summaryValues) {
					        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && meaString.get(sc).equals(summaryValue.getFieldName())) {
					        					pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellType(CellType.NUMERIC);
					        					BigDecimal value = getExcelCellValue(summaryValue);
					        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellValue(value.doubleValue());
					        					if(value.toString().equals("0")) {
					        						if(meaCaptionNmMapper.containsKey(summaryValue.getFieldName())){
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(meaCaptionNmMapper.get(summaryValue.getFieldName())));
													}else {
														pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
													}
					        					} else {
					        						if(meaCaptionNmMapper.containsKey(summaryValue.getFieldName())){
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(meaCaptionNmMapper.get(summaryValue.getFieldName())));
													}else {
														pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(summaryValue.getFieldName()));
													}
					        					}
					        					meaRowLocation.put(summaryValue.getFieldName(), dataRowNum);
					        					dataRowNum++;
					        					break;
					        				}
					        			}
		        					}

				        			if(cell.getSummaryValues().size() == 0) {
				        				for(int s = 0; s < summaryParams.size(); s++) {
				        					pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellValue(0);
				        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
				        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
				        					dataRowNum++;
				        				}
				        			}

				        			if(deltaItems.size() > 0) {
				        				for (int s = 0; s < deltaItems.size(); s++) {
				        					if(c == 1 && deltaVariationCount > 0 && !deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column GrandTotal") 
				        											&& !deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row GrandTotal") && deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row")
				        											&& deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column")) {
				        						if(!deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").contains("Variation")) {
				        							if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of GrandTotal")) {
				        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
					        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
//					        							if(totalTF == 0) {
//					        								baseMea = baseMea + (summaryValueCount * c) - deltaItems.size() + maxRowGroupDepth - deltaVariationCount;
//					        							} else {
//					        								baseMea = baseMea + (summaryValueCount * (c - 1)) + maxRowGroupDepth - deltaVariationCount;
//					        							}
					        							String colName = CellReference.convertNumToColString(dataCellNum);
					        							String colName2 = CellReference.convertNumToColString(1 + maxColGroupDepth);
					        							pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("ROUND(" + colName + (baseMeaRow+1) + "/" + colName2 + (controlRow+baseMea) + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+")");
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							
				        							}else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column GrandTotal")) {
				        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
					        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
//					        							if(totalTF == 0) {
//					        								baseMea = baseMea + (summaryValueCount * c) - deltaItems.size() + maxRowGroupDepth - deltaVariationCount;
//					        							} else {
//					        								baseMea = baseMea + (summaryValueCount * (c - 1)) + maxRowGroupDepth - deltaVariationCount;
//					        							}
					        							String colName = CellReference.convertNumToColString(dataCellNum);
					        							pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("ROUND(" + colName + (baseMeaRow+1) + "/" + colName + (controlRow+baseMea) + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+")");
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							dataRowNum++;
				        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row")){
					        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
				        								
				        								String colName1 = CellReference.convertNumToColString(dataCellNum);
					        							String colName2 = CellReference.convertNumToColString(controlColumn);
					        							if( c<1 && totalView.getBoolean("ShowColumnGrandTotals") == true) {
		        											final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
			        										
			        										pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        										}else if(columTotalMap.containsKey("전체"+(dataCellNum)) && totalView.getBoolean("ShowColumnTotals") == true) {
				        				        			final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
				        				        			pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        									}else {
			        										final List<SummaryValue> colTortalsummaryValues = columnTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : colTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
				        				        			pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        									}
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							dataRowNum++;
				        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row GrandTotal")){
					        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
				        								
				        								String colName1 = CellReference.convertNumToColString(dataCellNum);
					        							String colName2 = CellReference.convertNumToColString(controlColumn);
				        								
				        								
				        								if(totalView.getBoolean("ShowColumnGrandTotals") == true) {
				        									pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName2 + (baseMeaRow + 1) + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + colName2 + (baseMeaRow + 1) + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
				        								}else {
				        				        			final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
				        				        			BigDecimal value = BigDecimal.valueOf(0);
				        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
				        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
				        				        					value = getExcelCellValue(summaryValue);
				        				        					break;
				        				        				}
				        				        			}
				        				        			
				        				        			pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
				        								}
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							dataRowNum++;
				        							} else {
				        								pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellValue(0);
							        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
							        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
							        					dataRowNum++;
				        							}
				        						}else {
				        							pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellValue(0);
						        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
						        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
						        					dataRowNum++;
			        							}
				        					} else if(meaRowLocation.size() > 0){
				        						if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of GrandTotal")) {
			        								int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
//				        							if(totalTF == 0) {
//				        								baseMea = baseMea + (summaryValueCount * c) - deltaItems.size() + maxRowGroupDepth - deltaVariationCount;
//				        							} else {
//				        								baseMea = baseMea + (summaryValueCount * (c - 1)) + maxRowGroupDepth - deltaVariationCount;
//				        							}
				        							String colName = CellReference.convertNumToColString(dataCellNum);
				        							String colName2 = CellReference.convertNumToColString(maxRowGroupDepth+1);
				        							pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("ROUND(" + colName + (baseMeaRow+1) + "/" + colName2 + (controlRow+baseMea) + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+")");
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
			        							}else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column GrandTotal")) {
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
//				        							if(totalTF == 0) {
//				        								baseMea = baseMea + (summaryValueCount * c) - deltaItems.size() + maxRowGroupDepth - deltaVariationCount;
//				        							} else {
//				        								baseMea = baseMea + (summaryValueCount * (c - 1)) + maxRowGroupDepth - deltaVariationCount;
//				        							}
				        							String colName = CellReference.convertNumToColString(dataCellNum);
				        							pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("ROUND(" + colName + (baseMeaRow+1) + "/" + colName + (controlRow+baseMea) + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+")");
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        							dataRowNum++;
				        						} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Column")) {
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
//				        							if(totalTF == 0) {
//				        								baseMea = baseMea + (summaryValueCount * c) - deltaItems.size() + maxRowGroupDepth - deltaVariationCount;
//				        							} else {
//				        								baseMea = baseMea + (summaryValueCount * (c - 1)) + maxRowGroupDepth - deltaVariationCount;
//				        							}
			        								String colName1 = CellReference.convertNumToColString(dataCellNum);
				        							String colName2 = CellReference.convertNumToColString(controlColumn);
				        							if( r<1 && totalView.getBoolean("ShowRowGrandTotals") == true) {
		    											final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
		        										
		        										pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		    										}else if(rowTotalMap.containsKey("전체"+(dataRowNum - summaryValueCount +1)) && totalView.getBoolean("ShowRowTotals") == true) {
			        				        			final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        									}else {
		        										final List<SummaryValue> rowTortalsummaryValues = rowTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : rowTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        									}
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        							dataRowNum++;
				        						} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Absolute Variation")){
				        							int subtotalTF = 1;
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
				        							if(totalView.getBoolean("ShowColumnTotals") == true && cols.size() > 1) {
				        								subtotalTF += 1;
				        							}
				        							if(dataCellNum == maxRowGroupDepth + subtotalTF) {
				        								pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellValue(0);
							        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
							        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
							        					dataRowNum++;
				        							} else {
				        								String colName1 = CellReference.convertNumToColString(dataCellNum);
					        							String colName2 = CellReference.convertNumToColString(dataCellNum -1);
					        							
//					        							pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula(colName1 + (dataRowNum + 1 - (summaryValueCount - deltaItems.size()) + "-" + colName2 + (dataRowNum + 1 - (summaryValueCount - deltaItems.size()))));
					        							pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula(colName1 + (baseMeaRow+1) + "-" + colName2 + (baseMeaRow+1));
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("comma"));
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							dataRowNum++;
				        							}
				        						} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Variation")){
				        							int subtotalTF = 1;
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
				        							if(totalView.getBoolean("ShowColumnTotals") == true && cols.size() > 1) {
				        								subtotalTF += 1;
				        							}
				        							if(dataCellNum == maxRowGroupDepth + subtotalTF) {
				        								pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellValue(0);
							        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
							        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
							        					dataRowNum++;
				        							} else {
				        								String colName1 = CellReference.convertNumToColString(dataCellNum);
					        							String colName2 = CellReference.convertNumToColString(dataCellNum -1);
					        							
//					        							pivotSheet.getRow(createRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName2 + (createRowNum + 1) + " = 0, 0, (" + colName1 + (createRowNum + 1) + "-" + colName2 + (createRowNum + 1) + ")/" + colName2 + (createRowNum + 1) + ")");
					        							pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName2 + (baseMeaRow+1) + " = 0, 0, (" + colName1 + (baseMeaRow+1) + "-" + colName2 + (baseMeaRow+1) + ")/" + colName2 + (baseMeaRow+1) + ")");
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
					        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
					        							dataRowNum++;
				        							}
				        							
				        							
				        						} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row")){
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
			        								
			        								String colName1 = CellReference.convertNumToColString(dataCellNum);
				        							String colName2 = CellReference.convertNumToColString(controlColumn);
				        							
				        							if( c<1 && totalView.getBoolean("ShowColumnGrandTotals") == true) {
	        											final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
		        										
		        										pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
	        										}else if(columTotalMap.containsKey("전체"+(dataCellNum)) && totalView.getBoolean("ShowColumnTotals") == true) {
			        				        			final List<SummaryValue> colGrandTortalsummaryValues = colGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : colGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        									}else {
		        										final List<SummaryValue> colTortalsummaryValues = columnTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : colTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
		        									}
				        							
			        								
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        							dataRowNum++;
				        							
			        								
			        							} else if(deltaItems.getJSONObject(s).getString("DELTA_VALUE_TYPE").equals("Percent Of Row GrandTotal")){
			        								
				        							int baseMea = deltaBaseMeasure.get(deltaItems.getJSONObject(s).getString("CAPTION"));
				        							int baseMeaRow = meaRowLocation.get(deltaItems.getJSONObject(s).getString("BASE_FLD_NM"));
			        								
			        								String colName1 = CellReference.convertNumToColString(dataCellNum);
				        							String colName2 = CellReference.convertNumToColString(controlColumn);
				        							if(totalView.getBoolean("ShowColumnGrandTotals") == true) {
			        									pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + colName2 + (baseMeaRow + 1) + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + colName2 + (baseMeaRow + 1) + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        								}else {
			        				        			final List<SummaryValue> rowGrandTortalsummaryValues = rowGrandTortalCell.getSummaryValues();
			        				        			BigDecimal value = BigDecimal.valueOf(0);
			        				        			for (SummaryValue summaryValue : rowGrandTortalsummaryValues) {
			        				        				if(!StringUtils.startsWithAny(summaryValue.getFieldName(), "H_", "S_") && deltaItems.getJSONObject(s).getString("BASE_FLD_NM").equals(summaryValue.getFieldName())) {
			        				        					value = getExcelCellValue(summaryValue);
			        				        					break;
			        				        				}
			        				        			}
			        				        			
			        				        			pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellFormula("IF(" + value + " = 0, 0, ROUND(" + colName1 + (baseMeaRow + 1) + "/" + value + ", "+(Integer)deltaItems.getJSONObject(s).get("Precision")+2+"))");
			        								}
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.FORMULA);
//				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("percent"));
				        							pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get(deltaItems.getJSONObject(s).getString("FLD_NM")));
				        							dataRowNum++;
			        							} else {
			        								pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellValue(0);
						        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
						        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
				        							dataRowNum++;
				        						}
				        					}else {
				        						pivotSheet.getRow(dataRowNum).createCell(dataCellNum).setCellValue(0);
					        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellType(CellType.NUMERIC);
					        					pivotSheet.getRow(dataRowNum).getCell(dataCellNum).setCellStyle(styleMap.get("zero"));
			        							dataRowNum++;
				        					}
				        				}
				        			}
				        			dataCellNum++;
				        		}

				        		firstRowNum = firstRowNum + summaryValueCount;
				        	}


				        	//행 시작
				        	if(totalView.getBoolean("ShowRowTotals") == false || rows.size() <= 1) {
				        		for(int r = 0; r < subtotalRow.size(); r++) {
				        			removeRow(pivotSheet, subtotalRow.get(r) - (summaryValueCount * r), summaryValueCount * -1);
				        		}
				        	}

//				        	for(int c = 0; c < colSpanStartNum; c++) {
//				        		pivotSheet.autoSizeColumn(c);
//				        	}
				        }
			        }else {
			        	pivotSheet.createRow(addRowNum + 1);
						pivotSheet.getRow(addRowNum+1).createCell(0, CellType.STRING).setCellValue("조회된 데이터가 없습니다.");
						pivotSheet.getRow(addRowNum+1).getCell(0).setCellStyle(borderStyle);
			        }
			        
			        
					break;
				case "DATA_GRID":
				// 2020.02.21 mksong textbox 다운로드 추가 dogfoot
				case "TEXTBOX":
					addRowNum = 0;
					isSameName = false;
					
					OPCPackage opcPackage = OPCPackage.open(new FileInputStream((String) content.get("uploadPath")));
					XSSFWorkbook wb = new XSSFWorkbook(opcPackage);
					XSSFSheet movingSheet = (wb.getSheetAt(0));
					
					for(int j = 0; j < workbook.getNumberOfSheets(); j++) {
						if(workbook.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
					XSSFSheet positionSheet;
					
					if(isSameName) {
						positionSheet = workbook.createSheet((String) content.getString("item")+"_"+sameIndex);	
					}else {
						positionSheet = workbook.createSheet((String) content.getString("item"));
					}
					
					movesheet.copySheetSettings(positionSheet, movingSheet);
					
					if (content.getString("itemtype").equals("DATA_GRID")) {
						movesheet.allCopyXSSFSheet(positionSheet, movingSheet);
					}
					
					wb.close();
					opcPackage.close();
					break;

				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
				case "SIMPLE_CHART":
				case "CHOROPLETH_MAP":
				case "PIE_CHART":
				case "TREEMAP" :
				case "STAR_CHART" :
				/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
				case "CARD_CHART":
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case "KAKAO_MAP":
				case "KAKAO_MAP2":
				case "HISTOGRAM_CHART":
				case "DIVERGING_CHART":
			    case "SCATTER_PLOT":
			    case "HISTORY_TIMELINE":
			    case "ARC_DIAGRAM":
			    case "RADIAL_TIDY_TREE":
			    case "SCATTER_PLOT_MATRIX":
			    case "SCATTER_PLOT2":
				case "BOX_PLOT":
				case "DEPENDENCY_WHEEL":
				case "SEQUENCES_SUNBURST":
				case "LIQUID_FILL_GAUGE":
				case "WATERFALL_CHART":
				case "BIPARTITE_CHART":
				case "SANKEY_CHART":
				case "PARALLEL_COORDINATE":
				case "BUBBLE_PACK_CHART":
				case "WORD_CLOUD_V2":
				case "DENDROGRAM_BAR_CHART":
				case "COLLAPSIBLE_TREE_CHART":
				case "CALENDAR_VIEW_CHART":
				case "CALENDAR_VIEW2_CHART":
				case "CALENDAR_VIEW3_CHART":
				case "HEATMAP":
				case "HEATMAP2":
				case "COORDINATE_DOT":
				case "COORDINATE_LINE":
                case "SYNCHRONIZED_CHARTS":
				case "RECTANGULAR_ARAREA_CHART":
				case "WORD_CLOUD":
				case "BUBBLE_D3":
				case "FORCEDIRECT":
				case "FORCEDIRECTEXPAND":
				case "HIERARCHICAL_EDGE":
				case "FUNNEL_CHART":
				case "PYRAMID_CHART":
					for(int j = 0; j < workbook.getNumberOfSheets(); j++) {
						if(workbook.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
					XSSFSheet sheet1;

					addRowNum = 0;
					if(isSameName) {
						sheet1 = workbook.createSheet((String) content.getString("item")+"_"+sameIndex);	
					}else {
						sheet1 = workbook.createSheet((String) content.getString("item"));
					}
					try {
						String keyTime2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(System.currentTimeMillis()));
						
//						if(userId.equals("okeis")) {
//							sheet1.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
//							sheet1.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
//							sheet1.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
//							sheet1.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime2);
//							sheet1.createRow(2);
//							sheet1.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
//							sheet1.createRow(4);
//							addRowNum = 5;
//						} else {
//							sheet1.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
//							sheet1.getRow(0).createCell(1, CellType.STRING).setCellValue("고용정보통합분석시스템(EIS)");
//							sheet1.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
//							sheet1.getRow(1).createCell(1, CellType.STRING).setCellValue(userName);
//							sheet1.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
//							sheet1.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime2);
//							sheet1.createRow(3);
//							sheet1.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
//							sheet1.createRow(5);
//							addRowNum = 6;
//						}
						
						if(downloadFilter.equals("Y")) {
							if(paramJsonArray.size() != 0) {
								sheet1.createRow(addRowNum).createCell(0).setCellValue("필터 차원");
								sheet1.getRow(addRowNum).createCell(1).setCellValue("조건 값");
								for(int j = 0; j < paramJsonArray.size(); j++) {
									String key = paramJsonArray.getJSONObject(j).getString("key");
									Boolean bKeyChk = StringUtils.startsWithAny(key, "H_", "S_") ? false : true;
									if(bKeyChk) {
										addRowNum++;
										sheet1.createRow(addRowNum).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
										if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
											sheet1.getRow(addRowNum).createCell(1).setCellValue("전체");
										}else {
											String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
											paramValue = paramValue.replace("]", "");
											sheet1.getRow(addRowNum).createCell(1).setCellValue(paramValue);
										}									
									}
								}
								
								addRowNum++;
								//sheet1.createRow(addRowNum);
							}
						}
						
						sheet1.createRow(addRowNum);
						
						for (int j = 0; j < 12; j++) {
							if(sheet1.getRow(addRowNum)== null) {
								sheet1.createRow(addRowNum);
							}
							
							if(sheet1.getRow(addRowNum).getCell(j) == null) {
								sheet1.getRow(addRowNum).createCell(j);
							}
							
						}
						
						if (StringUtils.isNotBlank(memoText)) {
							sheet1.getRow(addRowNum).getCell(11).setCellValue(memoText);  // 얘는 같은 로우에 있어야함
							addRowNum++;
						}
						
						InputStream inputStream = new FileInputStream((String) content.getString("uploadPath"));
						byte[] bytes = IOUtils.toByteArray(inputStream);
						int pictureIdx = workbook.addPicture(bytes, XSSFWorkbook.PICTURE_TYPE_PNG);
						inputStream.close();

						XSSFCreationHelper helper = workbook.getCreationHelper();
						XSSFDrawing drawing = sheet1.createDrawingPatriarch();
						XSSFClientAnchor anchor = helper.createClientAnchor();

						anchor.setCol1(0);
						anchor.setRow1(addRowNum);
						
						XSSFPicture pict = drawing.createPicture(anchor, pictureIdx);

						pict.resize();
					} catch (Exception e) {
						e.printStackTrace();
					}

					break;
				}
				
				// 피벗그리드일때 임시파일 삭제하지 않음(생성하지 않았음)
				if (!content.getString("itemtype").equals("PIVOT_GRID")) {
					Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
					logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));	
				}
			}
			
			/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
			SXSSFWorkbook wb = new SXSSFWorkbook(workbook); 
	        wb.setCompressTempFiles(true);

	        SXSSFSheet sh = (SXSSFSheet) wb.getSheetAt(0);
	        sh.setRandomAccessWindowSize(1000);
	        
//			workbook.write(fileoutputstream);
	        wb.write(fileoutputstream);
//			System.out.println(path + tempType + slash + reportName + "." + downloadType);

			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", path + tempType + slash + reportName + "." + downloadType);
			wb.dispose();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		} finally {
			// 필수로 닫아주어야함
			if (fileoutputstream != null) {
				try {
					fileoutputstream.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
			
			if (workbook != null) {
				try {
					workbook.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
		}
		
		return returnobj;
	}
	
	@RequestMapping(value = "/adhocXlsx.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject adhocXlsx(HttpServletRequest request, HttpServletResponse response) throws InvalidFormatException, IOException {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");

		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
		//2020.07.22 MKSONG 다운로드 필터조건 포함 DOGFOOT
		JSONArray paramJsonArray = SecureUtils.getJSONArrayParameter(request, "params");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String tempType = SecureUtils.getParameter(request, "tempType");
		String downloadType = SecureUtils.getParameter(request, "downloadType");
		String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");
		/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
		String downloadFilter = SecureUtils.getParameter(request, "downloadFilter");
		String userName = SecureUtils.getParameter(request, "userName");
		String userId = SecureUtils.getParameter(request, "userId");
		
		User user = this.authenticationService.getRepositoryUser(userId);
		
		String reportOriName = "";
		String contentN = reportName.substring(reportName.length()-1);
		if(NumberUtils.isNumber(contentN)) {
			contentN = reportName.substring(reportName.length()-2);
			if(NumberUtils.isNumber(contentN)) {
				reportOriName = reportName.substring(0, reportName.length()-2);
			} else {
				reportOriName = reportName.substring(0, reportName.length()-1);
			}
		} else {
			reportOriName = reportName;
		}
		
		String iscd = "yyyy";
		Map<String, String> relCodeMap = new HashMap<String, String>();
		if(user.getUSER_REL_CD() != null && !user.getUSER_REL_CD().equals("1001") && !user.getUSER_REL_CD().equals("")) {
			String[] relCode = user.getUSER_REL_CD().split(",");
			if(!relCode[0].equals("N")) {
				iscd = relCode[0];
			}
		}
//		String sosok = this.dataSetServiceImpl.selectGoyongUserSosok(iscd);
//		if(sosok == null || sosok.equals("1001") || sosok.equals("")) {
//			sosok = "";
//		} else {
//			sosok = sosok + " ";
//		}
		
		JSONObject returnobj = new JSONObject();
		String path = "";
		String slash = "";
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

		
		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "\\";
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "/";
		}
		JSONObject content = (JSONObject) contentList.get(0);
		
		OPCPackage opcPackage = OPCPackage.open(new FileInputStream((String) content.get("uploadPath")));
		XSSFWorkbook wb = new XSSFWorkbook(opcPackage);
		FileOutputStream fout = null;

		CellStyle bodyStyle = wb.createCellStyle();
		bodyStyle.setBorderTop(BorderStyle.THIN);
		bodyStyle.setBorderBottom(BorderStyle.THIN);
		bodyStyle.setBorderLeft(BorderStyle.THIN);
		bodyStyle.setBorderRight(BorderStyle.THIN);

		try {
			int addRowNum = 0;

			String memoText = "";
			if(content.has("memoText")) {
				memoText = content.getString("memoText");
			}

			wb.setSheetName(0, (String) content.getString("item"));
			XSSFSheet positionSheet = wb.createSheet("정보");	
			wb.setSheetOrder((String) content.getString("item"), 1);
			wb.setSheetOrder("정보", 0);
			
			XSSFSheet dataSheet = wb.getSheet(content.getString("item"));
			
			int rowFreeze = 0;
			int colFreeze = 0;
			
			if (dataSheet.getPaneInformation() != null) {
				rowFreeze = dataSheet.getPaneInformation().getHorizontalSplitPosition();
				colFreeze = dataSheet.getPaneInformation().getVerticalSplitPosition();
			}
			
			dataSheet.createFreezePane(0, 0);
			dataSheet.shiftRows(0, dataSheet.getLastRowNum(), 2);
			
			if(content.getString("itemtype").equals("PIVOT_GRID")) {
				JSONArray rows = content.getJSONArray("rows");

				if(rows != null && rows.size() > 0) {
					dataSheet.createRow(0).createCell(0).setCellValue("행");
					dataSheet.createRow(1);
					for(int j = 0; j < rows.size(); j++) {
						JSONObject row = rows.getJSONObject(j);
						String rowName = "";
						if(row.has("wiseUniqueName")) {
							rowName = row.getString("wiseUniqueName");
						} else if(row.has("caption")) {
							rowName = row.getString("caption");
						}
						dataSheet.getRow(1).createCell(j, CellType.STRING).setCellValue(rowName);
					}
				}
			}
			
			Iterator<Row> iterRow = dataSheet.iterator();
			CellStyle newCellStyle2 = null;
			while(iterRow.hasNext()) {
				Row curRow = iterRow.next();
				
				if(curRow.getRowNum() >= rowFreeze + 2) {
					Iterator<Cell> iterCell = curRow.cellIterator();
					while(iterCell.hasNext()) {
						Cell curCell = iterCell.next();
						if(curCell.getColumnIndex() >= colFreeze) {
							curCell.setCellType(CellType.STRING);
							String value = curCell.getStringCellValue();
							curCell.setCellType(CellType.NUMERIC);
							if(value.length() > 0 && value.substring(value.length() - 1).equals("%")) {
								String preString = value.substring(0, value.length() - 1).replaceAll(",", "");
								String preFormat = "";
								if(preString.lastIndexOf(".") > -1) {
									int precision = preString.trim().length() - preString.lastIndexOf(".") -1;
									if(preString.indexOf("0") == 0) {
										preFormat = "0.";
									} else {
										preFormat = "#.";
									}
									for(int i = 0; i < precision; i++) {
										preFormat += "#";
									}
									preFormat += "%";
								} else {
									preFormat = "0%";
								}
								double preDouble = Double.parseDouble(preString) / 100;
								DataFormat newDataFormat = curCell.getSheet().getWorkbook().createDataFormat();
								if(newCellStyle2 == null) {
									newCellStyle2 = curCell.getSheet().getWorkbook().createCellStyle();
									newCellStyle2.setDataFormat(newDataFormat.getFormat(preFormat));
								} else if(newDataFormat.getFormat(preFormat) == newCellStyle2.getDataFormat()) {
								} else {
									newCellStyle2 = curCell.getSheet().getWorkbook().createCellStyle();
									newCellStyle2.setDataFormat(newDataFormat.getFormat(preFormat));
								}
								
								curCell.setCellStyle(newCellStyle2);
								curCell.setCellValue(preDouble);
							} else if(value.length() > 0 && !value.contains(",")) {
								String preString = value;
								String preFormat = "";
								if(preString.lastIndexOf(".") > -1) {
									int point = 0;
									String preData = preString.substring(preString.lastIndexOf(".") + 1).trim();
									for(int i = 0; i < preData.length(); i++) {
										if(preData.charAt(i) == '0') {
											point++;
										}
									}
									if(point == preData.length()) {
										preFormat = "0";
									} else {
										int precision = preString.trim().length() - preString.lastIndexOf(".") -1;
										if(preString.indexOf("0") == 0) {
											preFormat = "0.";
										} else {
											preFormat = "#.";
										}
										for(int i = 0; i < precision; i++) {
											preFormat += "#";
										}
									}
								} else {
									preFormat = "0";
								}
								double preDouble = Double.parseDouble(preString);
								DataFormat newDataFormat = curCell.getSheet().getWorkbook().createDataFormat();
								if(newCellStyle2 == null) {
									newCellStyle2 = curCell.getSheet().getWorkbook().createCellStyle();
									newCellStyle2.setDataFormat(newDataFormat.getFormat(preFormat));
								} else if(newDataFormat.getFormat(preFormat) == newCellStyle2.getDataFormat()) {
								} else {
									newCellStyle2 = curCell.getSheet().getWorkbook().createCellStyle();
									newCellStyle2.setDataFormat(newDataFormat.getFormat(preFormat));
								}
								curCell.setCellStyle(newCellStyle2);
								curCell.setCellValue(preDouble);
							} else if(value.length() > 0 && value.contains(",")) {
								String preString = value.replaceAll(",", "");
								String preFormat = "";
								if(preString.lastIndexOf(".") > -1) {
									int point = 0;
									String preData = preString.substring(preString.lastIndexOf(".") + 1).trim();
									for(int i = 0; i < preData.length(); i++) {
										if(preData.charAt(i) == '0') {
											point++;
										}
									}
									if(point == preData.length()) {
										preFormat = "#,##0";
									} else {
										int precision = preString.trim().length() - preString.lastIndexOf(".") -1;
										preFormat = "#,###.";
										if(preString.indexOf("0") == 0) {
											preFormat = "0.";
										} else {
											preFormat = "#.";
										}
										for(int i = 0; i < precision; i++) {
											preFormat += "#";
										}
									}
								} else {
									preFormat = "#,##0";
								}
								double preDouble = Double.parseDouble(preString);
								DataFormat newDataFormat = curCell.getSheet().getWorkbook().createDataFormat();
								if(newCellStyle2 == null) {
									newCellStyle2 = curCell.getSheet().getWorkbook().createCellStyle();
									newCellStyle2.setDataFormat(newDataFormat.getFormat(preFormat));
								} else if(newDataFormat.getFormat(preFormat) == newCellStyle2.getDataFormat()) {
								} else {
									newCellStyle2 = curCell.getSheet().getWorkbook().createCellStyle();
									newCellStyle2.setDataFormat(newDataFormat.getFormat(preFormat));
								}
								curCell.setCellStyle(newCellStyle2);
								curCell.setCellValue(preDouble);
							} else {
								curCell.setCellType(CellType.STRING);
								curCell.setCellValue(value);
							}
						}
					}
				}
			}
			
			String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(System.currentTimeMillis()));

			/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
			if(userId.equals("okeis")) {
				positionSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
				positionSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
				positionSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
				positionSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime);
				positionSheet.createRow(2);
				positionSheet.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
				positionSheet.createRow(4);
				addRowNum = 5;
			} else {
				positionSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
				positionSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("산림청");
				positionSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
				positionSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(userName);
				positionSheet.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
				positionSheet.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime);
				positionSheet.createRow(3);
				positionSheet.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
				positionSheet.createRow(5);
				addRowNum = 6;
			}

			//					String unitFilter = "";
			/* 2020.11.23 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
			/* 2021-03-23 yyb 추가된 로우 index 계산 */
			if(downloadFilter.equals("Y")) {
				if(paramJsonArray.size() != 0) {
					positionSheet.createRow(addRowNum).createCell(0).setCellValue("필터 차원");
					positionSheet.getRow(addRowNum).createCell(1).setCellValue("조건 값");
					for(int j = 0; j < paramJsonArray.size(); j++) {
						String key = paramJsonArray.getJSONObject(j).getString("key");
						Boolean bKeyChk = StringUtils.startsWithAny(key, "H_", "S_") ? false : true;
						if(bKeyChk) {
							addRowNum++;
							positionSheet.createRow(addRowNum).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
							if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
								positionSheet.getRow(addRowNum).createCell(1).setCellValue("전체");
							}else {
								String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
								paramValue = paramValue.replace("]", "");
								positionSheet.getRow(addRowNum).createCell(1).setCellValue(paramValue);
							}									
						}
					}

					addRowNum++;
					positionSheet.createRow(addRowNum);
				}
			}

			/* 2021-03-23 yyb 텍스트라벨이 필터와 겹치지 않게 로우 추가 */
			if (StringUtils.isNotBlank(memoText)) {
				addRowNum++;
				positionSheet.createRow(addRowNum);
			}

//			if(content.getString("itemtype").equals("PIVOT_GRID")) {
//				addRowNum++;
//				JSONArray rows = content.getJSONArray("rows");
//				JSONArray cols = content.getJSONArray("cols");
//
//				if(rows != null && rows.size() > 0) {
//					positionSheet.createRow(addRowNum).createCell(0).setCellValue("행");
//					for(int j = 0; j < rows.size(); j++) {
//						JSONObject row = rows.getJSONObject(j);
//						String rowName = "";
//						if(row.has("wiseUniqueName")) {
//							rowName = row.getString("wiseUniqueName");
//						} else if(row.has("caption")) {
//							rowName = row.getString("caption");
//						}
//						positionSheet.getRow(addRowNum).createCell(j+1, CellType.STRING).setCellValue(rowName);
//					}
//					addRowNum++;
//				}
//
//				if(cols != null && cols.size() > 0) {
//					positionSheet.createRow(addRowNum).createCell(0).setCellValue("열");
//					for(int j = 0; j < cols.size(); j++) {
//						JSONObject col = cols.getJSONObject(j);
//						String colName = "";
//						if(col.has("wiseUniqueName")) {
//							colName = col.getString("wiseUniqueName");
//						} else if(col.has("caption")) {
//							colName = col.getString("caption");
//						}
//						positionSheet.getRow(addRowNum).createCell(j+1, CellType.STRING).setCellValue(colName);
//					}
//					addRowNum++;
//				}
//			}

			SXSSFWorkbook wb2 = new SXSSFWorkbook(wb); 
	        wb2.setCompressTempFiles(true);

	        SXSSFSheet sh2 = (SXSSFSheet) wb2.getSheetAt(1);
	        sh2.setRandomAccessWindowSize(1000);
			fout = new FileOutputStream((String) content.get("uploadPath"));
			wb.write(fout);

			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", content.get("uploadPath"));
			wb2.dispose();
			wb2.close();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		} finally {
			if (fout != null) {
				try {
					fout.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
			if (wb != null) {
				try {
					wb.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
			if (opcPackage != null) {
				try {
					opcPackage.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
		}
		
		return returnobj;
	}
	
	//2020.03.05 MKSONG 엑셀파일 하나에 시트별 복사하는 방식 DOGFOOT 
	@RequestMapping(value = "/csv.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject pivotCsvDownLoad(HttpServletRequest request, HttpServletResponse response) throws FileNotFoundException {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");

		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
		String paramStr = SecureUtils.getParameter(request, "params");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String tempType = SecureUtils.getParameter(request, "tempType");
		String downloadType = SecureUtils.getParameter(request, "downloadType");
		String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");

		JSONObject returnobj = new JSONObject();
		String path = "";
		String slash = "";
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

		
		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "\\";
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "/";
		}
		// 1차로 workbook을 생성
		XSSFWorkbook workbook = new XSSFWorkbook();
		new File(path + tempType + slash).mkdirs();
		FileOutputStream fileoutputstream = null;
		OutputStreamWriter outputstreamwriter = null;
		BufferedWriter bufferedwriter = null;
		try {
			fileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + downloadType);
			outputstreamwriter = new OutputStreamWriter(fileoutputstream, "MS949");
			bufferedwriter = new BufferedWriter(outputstreamwriter);
		}catch(Exception e) {
			e.printStackTrace();
		}

		
		CellStyle bodyStyle = workbook.createCellStyle();
		bodyStyle.setBorderTop(BorderStyle.THIN);
		bodyStyle.setBorderBottom(BorderStyle.THIN);
		bodyStyle.setBorderLeft(BorderStyle.THIN);
		bodyStyle.setBorderRight(BorderStyle.THIN);

		try {
			// 2020.01.07 mksong 엑셀 다운로드 시트 내용 변경 dogfoot
			MoveSheetControllerForXlsx movesheet = new MoveSheetControllerForXlsx();
			// 2019.12.20 mksong 시트 이름 중복 오류 수정 dogfoot
			int sameIndex = 0;
			JSONObject content = (JSONObject) contentList.get(0);
			boolean isSameName = false;
			
			XSSFWorkbook wb = new XSSFWorkbook(new FileInputStream((String) content.get("uploadPath")));
			XSSFSheet movingSheet = (wb.getSheetAt(0));
			
			StringBuilder data = new StringBuilder();
			
			if (wb != null) {
	            XSSFSheet sheet = movingSheet;
	            Iterator<Row> rowIterator = sheet.rowIterator();
	            while (rowIterator.hasNext()) {               
	                Row row = rowIterator.next();
	                Iterator<Cell> cellIterator = row.cellIterator();
	                while (cellIterator.hasNext()) {
	                    Cell cell = cellIterator.next();
	                    CellType type = cell.getCellTypeEnum();
	                    if(downloadType.equals("csv")) {
	                    	if (type == CellType.BOOLEAN) {
		                        data.append(cell.getBooleanCellValue());
		                    } else if (type == CellType.NUMERIC) {
		                        data.append(cell.getNumericCellValue());
		                    } else if (type == CellType.STRING) {
		                    	if(cell.getStringCellValue().contains(","))
		                    		data.append("\"");
		                        data.append(cell.getStringCellValue());
		                        if(cell.getStringCellValue().contains(","))
		                    		data.append("\"");
		                    } else if (type == CellType.BLANK) {
		                    } else {
		                        data.append(cell + "");
		                    }
	                    	data.append(",");
	                    }else {
	                    	if (type == CellType.BOOLEAN) {
		                        data.append(cell.getBooleanCellValue());
		                    } else if (type == CellType.NUMERIC) {
		                        data.append(cell.getNumericCellValue());
		                    } else if (type == CellType.STRING) {
		                        data.append(cell.getStringCellValue());
		                    } else if (type == CellType.BLANK) {
		                    } else {
		                        data.append(cell + "");
		                    }
	                    	data.append("\t");
	                    }
	                    
	                    
	                }
	                data.append('\n');
	            }
	            System.out.println(data.toString());
	            System.out.println(downloadType.equals("csv"));

	        }
			
			try {
				bufferedwriter.write(data.toString());
			}
			catch(Exception e) {
				System.out.print(e.toString());
			}


			// 파일을 쓴다
//			workbook.write(fileoutputstream);
//			System.out.println(path + tempType + slash + reportName + "." + downloadType);
			


			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", path + tempType + slash + reportName + "." + downloadType);
			
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		} finally {
			// 필수로 닫아주어야함
			if (fileoutputstream != null) {
				try {
					bufferedwriter.close();
					outputstreamwriter.close();
					fileoutputstream.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
			if (workbook != null) {
				try {
					workbook.close();
				} catch (Exception ie) {
					ie.printStackTrace();
				}
			}
		}
		
		return returnobj;
	}
	
	
	//2020.03.05 MKSONG zip으로 묶는 방식 DOGFOOT
//	@RequestMapping(value = "/xlsx.do", method = RequestMethod.POST)
//	public @ResponseBody JSONObject exeReportDownLoad(HttpServletRequest request, HttpServletResponse response) throws Exception {
//		response.setContentType("text/html;charset=UTF-8");
//		response.setCharacterEncoding("UTF-8");
//
//		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
//		String paramStr = SecureUtils.getParameter(request, "params");
//		String reportName = SecureUtils.getParameter(request, "reportName");
//		//2020.03.07 MKSONG 다운로드 파일명 /포함 오류 수정 DOGFOOT
//		reportName = reportName.replaceAll("/", "_");
//		String tempType = SecureUtils.getParameter(request, "tempType");
//		String downloadType = SecureUtils.getParameter(request, "downloadType");
//		//2020.03.03 mksong KERIS 출처 내용에 포함 dogfoot
//		String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");
//
//		JSONObject returnobj = new JSONObject();
//		String path = "";
//		String slash = "";
//		
//		FileOutputStream zipfileoutputstream = null;
//		ZipOutputStream zipout = null;
//		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
//		
//		if(osBean.getName().indexOf("Windows") != -1) {
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
//			slash = "\\";
//		}else {
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
//			slash = "/";
//		}
//		
//		//2020.03.08 mksong 폴더 생성 순서변경 dogfoot
//		new File(path + tempType + slash).mkdirs();
//		
//		try {
//			zipfileoutputstream = new FileOutputStream(path + tempType + slash + reportName + ".zip");
//			zipout = new ZipOutputStream(zipfileoutputstream);
//			
//			byte[] buf = new byte[102400];
//			
//			// 2020.01.07 mksong 엑셀 다운로드 시트 내용 변경 dogfoot
//			MoveSheetControllerForXlsx movesheet = new MoveSheetControllerForXlsx();
//			// 2019.12.20 mksong 시트 이름 중복 오류 수정 dogfoot
//			int sameIndex = 0;
//			for (int i = 0; i < contentList.size(); i++) {
//				JSONObject content = (JSONObject) contentList.get(i);
//				boolean isSameName = false;
//				InputStream inputStream = new FileInputStream((String) content.getString("uploadPath"));
//				String fileName = "";
//				if(!srcFolderNm.equals("")) {
//					fileName = reportName +"_"+ (String) content.getString("item") + "(" + srcFolderNm + ")." + downloadType; 
//				}else {
//					fileName = reportName +"_"+ (String) content.getString("item") + "." + downloadType;
//				}
//				
//				ZipEntry ze;
//				int len = 0;
//				
//				// 2차는 sheet생성
//				switch (content.getString("itemtype")) {
//				case "PIVOT_GRID":
//				case "DATA_GRID":
//				// 2020.02.21 mksong textbox 다운로드 추가 dogfoot
//				case "TEXTBOX":
//					ze = new ZipEntry(fileName);
//					zipout.putNextEntry(ze);
//					
//					while((len = inputStream.read(buf)) > 0) {
//						zipout.write(buf, 0, len);
//					}
//					
//					zipout.closeEntry();
//					inputStream.close();
//					break;
//
//				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
//				case "SIMPLE_CHART":
//				case "PIE_CHART":
//				case "TREEMAP" :
//				case "STAR_CHART" :
//					// 1차로 workbook을 생성
//					XSSFWorkbook workbook = new XSSFWorkbook();
//					//2020.03.05 MKSONG 엑셀 파일 생성 DOGFOOT
//					String filepath = path + tempType + slash + System.currentTimeMillis()+(String) content.getString("item") + "." + downloadType;
//					FileOutputStream fileoutputstream = new FileOutputStream(filepath);
//
//					CellStyle bodyStyle = workbook.createCellStyle();
//					bodyStyle.setBorderTop(BorderStyle.THIN);
//					bodyStyle.setBorderBottom(BorderStyle.THIN);
//					bodyStyle.setBorderLeft(BorderStyle.THIN);
//					bodyStyle.setBorderRight(BorderStyle.THIN);
//					
//					for(int j = 0; j < workbook.getNumberOfSheets(); j++) {
//						if(workbook.getSheetName(j).equals((String) content.getString("item"))){
//							isSameName = true;
//							sameIndex++;
//						}
//					}
//					XSSFSheet sheet1;
//					
//					if(isSameName) {
//						sheet1 = workbook.createSheet((String) content.getString("item")+"_"+sameIndex);	
//					}else {
//						sheet1 = workbook.createSheet((String) content.getString("item"));
//					}
//					try {
//						// 이미지 파일 로드
//						byte[] bytes = IOUtils.toByteArray(inputStream);
//						int pictureIdx = workbook.addPicture(bytes, XSSFWorkbook.PICTURE_TYPE_PNG);
//						inputStream.close();
//
//						XSSFCreationHelper helper = workbook.getCreationHelper();
//						XSSFDrawing drawing = sheet1.createDrawingPatriarch();
//						XSSFClientAnchor anchor = helper.createClientAnchor();
//
//						// 이미지를 출력할 CELL 위치 선정
//						anchor.setCol1(0);
//						anchor.setRow1(0);
//
//						// 이미지 그리기
//						XSSFPicture pict = drawing.createPicture(anchor, pictureIdx);
//
//						// 이미지 사이즈 비율 설정
//						pict.resize();
//						
//						workbook.write(fileoutputstream);
//					} catch (Exception e) {
//						e.printStackTrace();
//						throw e;
//					}finally {
//						workbook.close();
//						fileoutputstream.close();
//					}
//					
//					ze = new ZipEntry(fileName);
//					zipout.putNextEntry(ze);
//					
//					inputStream = new FileInputStream(filepath);
//					
//					while((len = inputStream.read(buf)) > 0) {
//						zipout.write(buf, 0, len);
//					}
//					
//					zipout.closeEntry();
//					inputStream.close();
//					break;
//					
//				}
//				//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
//				Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
//				logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));
//			}
//			
//		} catch (Exception e) {
//			// TODO: handle exception
//			e.printStackTrace();
//			throw e;
//		} finally {
//			zipout.close();
//			zipfileoutputstream.close();
//			
//			returnobj.put("fileName", reportName + ".zip");
//			returnobj.put("filePath", path + tempType + slash + reportName + ".zip");
//		}
//		
//		return returnobj;
//	}

	// 2020.02.21 mksong textbox 다운로드 추가 dogfoot
	@RequestMapping(value = "/saveXLSXForTextBox.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject saveXLSXForTextBox(MultipartHttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		
		JSONObject obj = new JSONObject();
		String textBox_HTML = SecureUtils.getParameter(request, "textbox_html");
		String fileName = SecureUtils.getParameter(request, "itemName");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String path = UtilFile.getSaveLocation(request,reportName);
		XSSFWorkbook wb = new XSSFWorkbook();
		XSSFSheet createSheet = wb.createSheet(fileName);
		textBox_HTML = textBox_HTML.replaceAll("&lt;", "<");
		textBox_HTML = textBox_HTML.replaceAll("&gt;", ">");
		textBox_HTML = textBox_HTML.replaceAll("&#39;", "'");
		textBox_HTML = textBox_HTML.replaceAll("&#34;", "\"");
		textBox_HTML = textBox_HTML.replaceAll("&quot;", "\"");
		textBox_HTML = textBox_HTML.replaceAll("&#60;", "<");
		textBox_HTML = textBox_HTML.replaceAll("&lt;", "<");
		textBox_HTML = textBox_HTML.replaceAll("&#61;", "=");
		textBox_HTML = textBox_HTML.replaceAll("&#62;", ">");
		textBox_HTML = textBox_HTML.replaceAll("&gt;", ">");
		//2020.03.05 MKSONG 특수문자 HTML 변환 추가 DOGFOOT
		textBox_HTML = textBox_HTML.replaceAll("&amp;", "&");
		textBox_HTML = textBox_HTML.replaceAll("&Hat;", "^");
		textBox_HTML = textBox_HTML.replaceAll("&apos;", "'");
		textBox_HTML = textBox_HTML.replaceAll("&semi;", ";");
		textBox_HTML = textBox_HTML.replaceAll("&num;", "#");
		textBox_HTML = textBox_HTML.replaceAll("&nbsp;", " ");
		
		String [] textBoxHtmlList= textBox_HTML.split("</p>");
		for(int i = 0; i < textBoxHtmlList.length; i++) {
			if(textBoxHtmlList[i].contains("<br>")) {
				createSheet.createRow(i).createCell(0);
			}else if(textBoxHtmlList[i].contains("<span")) {
				String text = textBoxHtmlList[i].replaceAll("<p>", "");
				text = text.replaceAll("</p>", "");								
				text = text.substring(text.indexOf(">")+1, text.lastIndexOf("</span>"));
				text = text.replaceAll("&lt;", "<");
				text = text.replaceAll("&gt;", ">");
				createSheet.createRow(i).createCell(0).setCellValue(text);
			//2020.03.05 MKSONG SPAN 없는 경우 추가 DOGFOOT
			}else {
				String text = textBoxHtmlList[i].replaceAll("<p>", "");
				text = text.replaceAll("</p>", "");
				text = text.substring(text.indexOf(">")+1, text.length());
				text = text.replaceAll("&lt;", "<");
				text = text.replaceAll("&gt;", ">");
				createSheet.createRow(i).createCell(0).setCellValue(text);
			}
		}
	
		//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 DOGFOOT
		FileOutputStream fileoutputstream = null;
		try {
			File file = new File(path);

			// 파일명이 중복으로 존재할 경우
			if (fileName != null && !fileName.equals("")) {
				if (file.exists()) {
					// 파일명 앞에 업로드 시간 초단위로 붙여 파일명 중복을 방지
					fileName = System.currentTimeMillis() + "_" + fileName;
				}
			}
			
			//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
			fileoutputstream = new FileOutputStream(path + fileName + ".xlsx");
			wb.write(fileoutputstream);
//			System.out.println(path + tempType + slash + reportName + "." + downloadType);

			obj.put("checkValue", true);
			obj.put("uploadPath", path + fileName + ".xlsx");
		//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//		}catch (IOException e) {			
		}catch (Exception e) {
			e.printStackTrace();
			obj.put("checkValue", false);
			throw e;
		}finally {
			wb.close();
			//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
			fileoutputstream.close();
		}
		
		return obj;
	}
	
	@RequestMapping(value = "/saveXLSX.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject saveXLSX(@RequestParam("exceldata") MultipartFile uploadFile,
			MultipartHttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		// UtilFile 객체 생성
		UtilFile utilFile = new UtilFile();

		// 파일 업로드 결과값을 path로 받아온다(이미 fileUpload() 메소드에서 해당 경로에 업로드는 끝났음)
		JSONObject obj = utilFile.fileUpload(request, uploadFile, ".xlsx");
		return obj;
	}
	
	@RequestMapping(value = "/saveImage.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject saveImage(@RequestParam("imagedata") MultipartFile uploadFile,
			MultipartHttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		// UtilFile 객체 생성
		UtilFile utilFile = new UtilFile();

		// 파일 업로드 결과값을 path로 받아온다(이미 fileUpload() 메소드에서 해당 경로에 업로드는 끝났음)
		JSONObject obj = utilFile.fileUpload(request, uploadFile, ".png");
		return obj;
	}

	@RequestMapping(value = "/mergeImage.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject mergeImage(HttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");

		String[] pictureList = request.getParameterValues("pictureList");

		BufferedImage mergedImage;
		int mergedImageWidth = 0;
		int mergedImageHeight = 0;

		ArrayList<BufferedImage> imgList = new ArrayList<>();
		// 파일 업로드 결과값을 path로 받아온다(이미 fileUpload() 메소드에서 해당 경로에 업로드는 끝났음)
		JSONObject obj = new JSONObject();
		
		String slash = "";
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();

		if(osBean.getName().indexOf("Windows") != -1) {
			slash = "\\";
		}else {
			slash = "/";
		}
		
		try {
			if (pictureList != null) {
				for (String pictureLocation : pictureList) {
					imgList.add(ImageIO.read(new File(pictureLocation)));
				}

				for (int i = 0; i < imgList.size(); i++) {
					BufferedImage bi;
					if (i > 0) {
						bi = imgList.get(i);
						mergedImageHeight = Math.max(bi.getHeight(), imgList.get(i - 1).getHeight());
					} else {
						bi = imgList.get(i);
						mergedImageHeight = bi.getHeight();
					}

					mergedImageWidth += bi.getWidth();
				}

				mergedImage = new BufferedImage(mergedImageWidth, mergedImageHeight, BufferedImage.TYPE_INT_RGB);
				Graphics2D graphics = (Graphics2D) mergedImage.getGraphics();
				graphics.setBackground(Color.WHITE);
				int x = 0;
				for (int i = 0; i < imgList.size(); i++) {
					if (i == 0) {
						graphics.drawImage(imgList.get(i), 0, 0, null);
						x += imgList.get(i).getWidth();
					} else {
						graphics.drawImage(imgList.get(i), x, 0, null);
						x += imgList.get(i).getWidth();
					}
				}

//				System.out.println("사진저장위치 : " + pictureList[0].substring(0, pictureList[0].lastIndexOf(slash)));
				long timemill = System.currentTimeMillis();
				String finalFileName = pictureList[0].substring(pictureList[0].lastIndexOf("_") + 1, pictureList[0].lastIndexOf("."));
				ImageIO.write(mergedImage, "png",
						new File(pictureList[0].substring(0, pictureList[0].lastIndexOf(slash)) + slash + timemill + "_" + finalFileName + ".png"));
				obj.put("checkValue", true);
				obj.put("uploadPath", pictureList[0].substring(0, pictureList[0].lastIndexOf(slash)) + slash + timemill + "_" + finalFileName + ".png");
			} else {
				obj.put("checkValue", false);
			}
		//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//		}catch (IOException e) {			
		}catch (Exception e) {
			obj.put("checkValue", false);
			e.printStackTrace();
			throw e;
		}

		return obj;
	}
	/*dogfoot 이미지 전체 다운로드 추가 shlim 20200828*/
	@RequestMapping(value = "/mergeImageAll.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject mergeImageAll(HttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");

		String[] pictureList = request.getParameterValues("pictureList");
		JSONArray itemLocationList = SecureUtils.getJSONArrayParameter(request, "itemLocationList");
		String clientWidth = SecureUtils.getParameter(request, "clientWidth");
		String clientHeight = SecureUtils.getParameter(request, "clientHeight");
		BufferedImage mergedImage;
		int mergedImageWidth =  (int)Double.parseDouble(clientWidth);
		int mergedImageHeight = (int)Double.parseDouble(clientHeight);

		ArrayList<BufferedImage> imgList = new ArrayList<>();
		JSONObject obj = new JSONObject();
		
		String slash = "";
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();

		if(osBean.getName().indexOf("Windows") != -1) {
			slash = "\\";
		}else {
			slash = "/";
		}
		
		try {
			if (pictureList != null) {
				for (String pictureLocation : pictureList) {
					imgList.add(ImageIO.read(new File(pictureLocation)));
				}
				mergedImage = new BufferedImage(mergedImageWidth, mergedImageHeight, BufferedImage.TYPE_INT_ARGB);
				Graphics2D graphics = (Graphics2D) mergedImage.getGraphics();
				graphics.setBackground(Color.WHITE);
				for (int i = 0; i < itemLocationList.size(); i++) {
					JSONObject itemLocation = (JSONObject) itemLocationList.get(i);
					int y = Integer.parseInt(itemLocation.getString("itemTop"));
					int x = Integer.parseInt(itemLocation.getString("itemLeft"));
					int itemWidth = Integer.parseInt(itemLocation.getString("itemWidth"));
					int itemHeight = Integer.parseInt(itemLocation.getString("itemHeight"));
					graphics.drawImage(ImageIO.read(new File((String) itemLocation.get("itemPath"))), x, y, itemWidth,itemHeight,Color.WHITE,null);
					System.out.println("사진저장위치 : " +itemLocation);
				}

				long timemill = System.currentTimeMillis();
				String finalFileName = pictureList[0].substring(pictureList[0].lastIndexOf("_") + 1, pictureList[0].lastIndexOf("."));
				String finalFileType = pictureList[0].substring(pictureList[0].lastIndexOf(".")+1,pictureList[0].length());
				ImageIO.write(mergedImage, "png",
						new File(pictureList[0].substring(0, pictureList[0].lastIndexOf(slash)) + slash + timemill + "_" + finalFileName + ".png"));
				obj.put("checkValue", true);
				obj.put("uploadPath", pictureList[0].substring(0, pictureList[0].lastIndexOf(slash)) + slash + timemill + "_" + finalFileName + ".png");
			} else {
				obj.put("checkValue", false);
			}
		}catch (Exception e) {
			obj.put("checkValue", false);
			e.printStackTrace();
			throw e;
		}

		return obj;
	}
	
	// 2020.02.21 mksong static으로 변경 dogfoot
	public static class UtilFile {
		String fileName = "";

		// 프로젝트 내 지정된 경로에 파일을 저장하는 메소드
		// DB에는 업로드된 전체 경로명으로만 지정되기 때문에(업로드한 파일 자체는 경로에 저장됨)
		// fileUpload() 메소드에서 전체 경로를 리턴받아 DB에 경로 그대로 저장
		public JSONObject fileUpload(MultipartHttpServletRequest request, MultipartFile uploadFile, String extension) {
			String path = "";
			/* DOGFOOT ktkang 파일 이름 js에서 encode하고 java에서는 decode 없던 오류 수정  20200727 */
			String fileName = new String(Base64.decode(SecureUtils.getParameter(request, "itemName")));
			String reportName = SecureUtils.getParameter(request, "reportName");
			OutputStream out = null;
			OutputStream outPng = null;
			PrintWriter printWriter = null;

			JSONObject obj = new JSONObject();
			try {
				if(SecureUtils.getParameter(request, "imageType").equals("D3Png")) {
//					String svgXmlbase64 = SecureUtils.getParameter(request, "svgXml");
//					String svgXml = new String(Base64.decode(svgXmlbase64));
					String svgXml = SecureUtils.getParameter(request, "svgXml");
					svgXml = svgXml.replaceAll("&lt;", "<");
					svgXml = svgXml.replaceAll("&gt;", ">");
					svgXml = svgXml.replaceAll("&#39;", "'");
					svgXml = svgXml.replaceAll("&#34;", "\"");
					svgXml = svgXml.replaceAll("&quot;", "\"");
					svgXml = svgXml.replaceAll("&#60;", "<");
					svgXml = svgXml.replaceAll("&lt;", "<");
					svgXml = svgXml.replaceAll("&#61;", "=");
					svgXml = svgXml.replaceAll("&#62;", ">");
					svgXml = svgXml.replaceAll("&gt;", ">");
					//2020.03.05 MKSONG 특수문자 HTML 변환 추가 DOGFOOT
					svgXml = svgXml.replaceAll("&amp;", "&");
					svgXml = svgXml.replaceAll("&Hat;", "^");
					svgXml = svgXml.replaceAll("&apos;", "'");
					svgXml = svgXml.replaceAll("&semi;", ";");
					svgXml = svgXml.replaceAll("&num;", "#");
					svgXml = svgXml.replaceAll("&nbsp;", " ");
					
					byte[] imageByte = svgXml.getBytes();
					path = getSaveLocation(request, reportName);
					OutputStream svgOutput = new FileOutputStream(path + fileName + ".svg");
		            svgOutput.write(imageByte);
		            svgOutput.close();
		            
		            
		            @SuppressWarnings("deprecation")
					String svgURI = new File(path + fileName + ".svg").toURL().toString();
		            TranscoderInput input_svg_image = new TranscoderInput(svgURI);
		            
//		            TranscoderInput input_svg_image = new TranscoderInput("file:"+path + fileName + ".svg");
		            // 스텝 2:OutputStream이미지를 정의하고 TranscoderOutput에 연결합니다.
		           
		            
		            if (fileName != null && !fileName.equals("")) {
							// 파일명 앞에 업로드 시간 초단위로 붙여 파일명 중복을 방지
						fileName = System.currentTimeMillis() + "_" + fileName;
						
					}
		            OutputStream png_ostream = new FileOutputStream(path + fileName + ".png");
		            TranscoderOutput output_png_image = new TranscoderOutput(png_ostream);
		            
//		            OutputStream jpg_ostream = new FileOutputStream(path + fileName + ".jpg");
//		            TranscoderOutput output_jpg_image = new TranscoderOutput(jpg_ostream);
		            
		            // 스텝 3:P/CGT구축/암호화 및 필요한 경우 힌트를 정의합니다.
		            PNGTranscoder converter_png = new PNGTranscoder();
		            
//		            JPEGTranscoder converter_jpg = new JPEGTranscoder();
//		            converter_jpg.addTranscodingHint(JPEGTranscoder.KEY_QUALITY, new Float(.8));
		            
		            // 스텝 4:출력 및 쓰기 출력
		           
		            try {
//		            	converter_jpg.transcode(input_svg_image, output_jpg_image);
		            	 converter_png.transcode(input_svg_image, output_png_image);
		            }catch (Exception e) {
//						e.printStackTrace();
						
					}
		            
		            obj.put("checkValue", true);
//					obj.put("uploadPath",path + fileName + ".jpg");	
					obj.put("uploadPath",path + fileName + ".png");	
		            // 5단계- 닫힘/플러시 출력 스트림
		            
		            //jpg_ostream.flush();
		            //jpg_ostream.close();
		            
				}else {
					
				
					// fileName = uploadFile.getOriginalFilename();
					byte[] bytes = uploadFile.getBytes();
	
					path = getSaveLocation(request, reportName);
	//				System.out.println("UtilFile fileUpload fileName : " + fileName);
	//				System.out.println("UtilFile fileUpload uploadPath : " + path);
	
					File file = new File(path);
	
					// 파일명이 중복으로 존재할 경우
					if (fileName != null && !fileName.equals("")) {
						if (file.exists()) {
							// 파일명 앞에 업로드 시간 초단위로 붙여 파일명 중복을 방지
							fileName = System.currentTimeMillis() + "_" + fileName;
							file = new File(path + fileName + extension);
						}
					}
	
	//				System.out.println("UtilFile fileUpload final fileName : " + fileName);
	//				Sstem.out.println("UtilFile fileUpload file : " + file);
					out = new FileOutputStream(file);
	//				System.out.println("UtilFile fileUpload out : " + out);
	
					out.write(bytes);
					obj.put("checkValue", true);
					obj.put("uploadPath", file.getPath());	
				}
				
				
			//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//			}catch (IOException e) {			
			}catch (Exception e) {
				e.printStackTrace();
				obj.put("checkValue", false);
			} finally {
				try {
					if (out != null) {
						out.close();
					}
					if (printWriter != null) {
						printWriter.close();
					}
				//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//				}catch (IOException e) {			
				}catch (Exception e) {
					e.printStackTrace();
				}
			}

			return obj;
		}

		// 업로드 파일 저장 경로 얻는 메소드
		// 업로드한 파일의 경로가 도메인 별로 달라야 했기 때문에 도메인의 형을 비교하여 파일 저장 정로를 다르게 지정함
		// 2020.02.21 mksong static으로 변경 dogfoot
		//2020.03.05 MKSONG 파일위치 TEMP로 일원화 DOGFOOT
		private static String getSaveLocation(MultipartHttpServletRequest request, String reportName) {
			String uploadPath = "";
			java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
			boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");
			
			if(osBean.getName().indexOf("Windows") != -1) {
				if(weblogicPath) {
					/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
					uploadPath = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\temp\\";
				}else {
					uploadPath = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\temp\\";
				}
//				uploadPath = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\temp\\";
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				
			}else {
				if(weblogicPath) {
					/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
					uploadPath = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/temp/";
				}else {
					uploadPath = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/temp/";
				}
//				uploadPath = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/temp/";
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				
			}
			new File(uploadPath).mkdirs();
			return uploadPath;
		}
	}

	@RequestMapping(value = "/docx.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject wordDownLoader(HttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");

		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
		String paramStr = SecureUtils.getParameter(request, "params");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String tempType = SecureUtils.getParameter(request, "tempType");
		String downloadType = SecureUtils.getParameter(request, "downloadType");
		//2020.03.03 mksong KERIS 출처 내용에 포함 dogfoot
		String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");
		
		String path = "";
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\docx\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\docx\\";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\docx\\";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/docx/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/docx/";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/docx/";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
		}
		
		JSONObject returnobj = new JSONObject();
		FileOutputStream fileoutputstream = null;
		
		// Blank Document
		XWPFDocument document = new XWPFDocument();
		ConvertSheet2WordTableController converter = new ConvertSheet2WordTableController();
		
		CTBody body = document.getDocument().getBody();
		if (!body.isSetSectPr()) {
			body.addNewSectPr();
		}

		CTSectPr section = body.getSectPr();
		if (!section.isSetPgSz()) {
			section.addNewPgSz();
		}

		CTPageSz pageSize = section.getPgSz();
		pageSize.setOrient(STPageOrientation.LANDSCAPE);
		// A4 = 595x842 / multiply 20 since BigInteger represents 1/20 Point
		pageSize.setW(BigInteger.valueOf(16840));
		pageSize.setH(BigInteger.valueOf(11900));
		
		try {
			// Write the Document in file system
			new File(path).mkdirs();
			fileoutputstream = new FileOutputStream(
					path + reportName + "." + downloadType);
			
			// 2020.01.07 mksong 워드 다운로드 내용 변경 dogfoot
			XWPFParagraph basicParagraph = document.createParagraph();
			XWPFRun basicRun = basicParagraph.createRun();
			basicParagraph.setAlignment(ParagraphAlignment.CENTER);
			basicParagraph.setBorderBottom(Borders.BASIC_WIDE_INLINE);
			basicRun.setFontSize(14);
			basicRun.setBold(true);
			basicRun.setText(reportName);

			// 2020.01.07 mksong 워드 다운로드 시트 내용 변경 dogfoot
			for (int i = 0; i < contentList.size(); i++) {
				XWPFParagraph paragraph = document.createParagraph();
				JSONObject content = (JSONObject) contentList.get(i);
				//2020.03.03 mksong 파일 업로드 통일 dogfoot
				InputStream file = null;
				// 2차는 sheet생성
				switch (content.getString("itemtype")) {
				case "PIVOT_GRID":
				case "DATA_GRID":
				case "TEXTBOX":
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					file = new FileInputStream((String) content.get("uploadPath"));
					XWPFParagraph para = document.getLastParagraph();
					XWPFRun run = para.createRun();
					if(i != 0) {
						run.addBreak(BreakType.PAGE);
					}
					// 2020.01.07 mksong 엑셀 다운로드 시트 내용 변경 dogfoot
					para.setAlignment(ParagraphAlignment.LEFT);
					run.setBold(true);
					run.setText((String) content.getString("item").trim());
					/* DOGFOOT ktkang 아이템 이름 중복되어 나오는 부분 삭제  20200924 */
//					para = document.createParagraph();
//					run = para.createRun();
//					para.setAlignment(ParagraphAlignment.RIGHT);
//					run.setText((String) content.getString("originItemName"));
					//2020.03.03 mksong KERIS 출처 내용에 포함 dogfoot
					if(!srcFolderNm.equals("")) {
						run.addBreak();
						run.setText(srcFolderNm);	
					}
//					run.addCarriageReturn();
					XWPFTable positionSheet = document.createTable();
//					System.out.println("엑셀 경로 : " + (String) content.get("uploadPath"));
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					XSSFWorkbook wb = new XSSFWorkbook(file);
					XSSFSheet movingSheet = (wb.getSheetAt(0));
					
					converter.convertXSSF2XWPF(positionSheet, movingSheet);
					
					wb.close();
					file.close();
					break;
				
				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
				case "SIMPLE_CHART":
				case "CHOROPLETH_MAP":
				case "FUNNEL_CHART":
				case "PYRAMID_CHART":
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case "KAKAO_MAP":
				case "KAKAO_MAP2":
				case "TREEMAP" :
				case "STAR_CHART" :
				case "PIE_CHART":
					/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
				case "CARD_CHART":
				case "HISTOGRAM_CHART":
				case "DIVERGING_CHART":
				case "SCATTER_PLOT":
				case "SCATTER_PLOT2":
				case "HISTORY_TIMELINE":
				case "ARC_DIAGRAM":
				case "RADIAL_TIDY_TREE":
				case "SCATTER_PLOT_MATRIX":
				case "BOX_PLOT":
				case "DEPENDENCY_WHEEL":
				case "SEQUENCES_SUNBURST":
				case "LIQUID_FILL_GAUGE":
				case "WATERFALL_CHART":
				case "BIPARTITE_CHART":
				case "SANKEY_CHART":
				case "PARALLEL_COORDINATE":
				case "BUBBLE_PACK_CHART":
				case "WORD_CLOUD_V2":
				case "DENDROGRAM_BAR_CHART":
				case "COLLAPSIBLE_TREE_CHART":
				case "CALENDAR_VIEW_CHART":
				case "CALENDAR_VIEW2_CHART":
				case "CALENDAR_VIEW3_CHART":
				case "HEATMAP":
				case "HEATMAP2":
				case "COORDINATE_DOT":
				case "COORDINATE_LINE":
                case "SYNCHRONIZED_CHARTS":
				case "RECTANGULAR_ARAREA_CHART":
				case "WORD_CLOUD":
				case "BUBBLE_D3":
				case "FORCEDIRECT":
				case "FORCEDIRECTEXPAND":
				case "HIERARCHICAL_EDGE":
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					FileInputStream file2 = null;
					try {
						XWPFParagraph para2 = document.getLastParagraph();
						XWPFRun run2 = para2.createRun();
						if(i != 0) {
							run2.addBreak(BreakType.PAGE);
						}

						run2.setText((String) content.getString("item").trim());
						run2.addCarriageReturn();
						//2020.03.03 mksong 파일 업로드 통일 dogfoot
						file = new FileInputStream((String) content.getString("uploadPath"));
						// 이미지 파일 로드
						BufferedImage img = ImageIO.read(file);
						int width = img.getWidth();
						int height = img.getHeight();
						String imgFileName = (String) content.getString("item") + ".png";
						// System.out.println("width : " + width +"\n height: " + height + "\n img : " +
						// img + "\n imgname : " + imgFileName);

						int imgFormat = converter.getImageFormat(imgFileName);
						//2020.03.03 mksong 파일 업로드 통일 dogfoot
						file2 = new FileInputStream((String) content.getString("uploadPath"));
						run2.addPicture(file2, imgFormat, imgFileName, Units.toEMU(730), Units.toEMU(250));
						//run2.addPicture(file2, imgFormat, imgFileName, Units.toEMU(width), Units.toEMU(height));
					//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//					}catch (IOException e) {			
					}catch (Exception e) {
						e.printStackTrace();
						throw e;
					//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT	
					}finally {
						file.close();
						file2.close();
					}

					break;
				}
				//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
				Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
				logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));
			}
			
			document.write(fileoutputstream);

//			System.out.println(path + reportName + "." + downloadType);
			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", path + reportName + "." + downloadType);

			//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//		}catch (IOException e) {			
		}catch (Exception e) {
			e.printStackTrace();
			throw e;
		} finally {
			document.close();
			fileoutputstream.close();
		}

		return returnobj;

	}
	
	@RequestMapping(value = "/hwp.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject downloadHwp(HttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		
		ConvertSheet2HwpConverter converter = new ConvertSheet2HwpConverter();
		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
		String paramStr = SecureUtils.getParameter(request, "params");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String tempType = "xlsx";
		String downloadType = SecureUtils.getParameter(request, "downloadType");
		JSONObject returnobj = new JSONObject();
		String path = "";
		String slash = "";
		
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "\\";
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "/";
		}
		XSSFWorkbook workbook = new XSSFWorkbook();
		new File(path + tempType + slash).mkdirs();
		//2020.03.03 mksong 파일 업로드 통일 dogfoot
		FileOutputStream xlsxfileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + tempType);

		CellStyle bodyStyle = workbook.createCellStyle();
		bodyStyle.setBorderTop(BorderStyle.THIN);
		bodyStyle.setBorderBottom(BorderStyle.THIN);
		bodyStyle.setBorderLeft(BorderStyle.THIN);
		bodyStyle.setBorderRight(BorderStyle.THIN);
		try {
			MoveSheetController movesheet = new MoveSheetController();
			HashMap<String, String> imageMap = new HashMap<String, String>();
			JSONObject contentPath = (JSONObject) contentList.get(0);
			String pathString = (String) contentPath.get("uploadPath");
			pathString = pathString.replace("\\", "/");
			imageMap.put("contextPath", request.getRequestURL().substring(0, request.getRequestURL().indexOf("download")) + pathString.substring(pathString.lastIndexOf("UploadFiles"), pathString.lastIndexOf("/")));

			for (int i = 0; i < contentList.size(); i++) {
				JSONObject content = (JSONObject) contentList.get(i);
				//2020.03.03 mksong 파일 업로드 통일 dogfoot
				InputStream inputStream = new FileInputStream((String) content.getString("uploadPath"));
				// 2차는 sheet생성
				switch (content.getString("itemtype")) {
				case "PIVOT_GRID":
				case "DATA_GRID":
				case "TEXTBOX":
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					XSSFWorkbook wb = new XSSFWorkbook(inputStream);
					XSSFSheet movingSheet = (wb.getSheetAt(0));
					XSSFSheet positionSheet = workbook.createSheet((String) content.getString("item"));
					movesheet.copySheetSettings(positionSheet, movingSheet);
					movesheet.copyXSSFSheet(positionSheet, movingSheet);
					wb.close();
					inputStream.close();
					break;
				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
				case "SIMPLE_CHART":
				case "CHOROPLETH_MAP":
				case "FUNNEL_CHART":
				case "PYRAMID_CHART":
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case "KAKAO_MAP":
				case "KAKAO_MAP2":
				case "TREEMAP" :
				case "STAR_CHART" :
				case "PIE_CHART":
				/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
				case "CARD_CHART":
				case "HISTOGRAM_CHART":
				case "DIVERGING_CHART":
				case "SCATTER_PLOT":
				case "HISTORY_TIMELINE":
				case "ARC_DIAGRAM":
				case "RADIAL_TIDY_TREE":
				case "SCATTER_PLOT_MATRIX":
				case "SCATTER_PLOT2":
				case "BOX_PLOT":
				case "DEPENDENCY_WHEEL":
				case "SEQUENCES_SUNBURST":
				case "LIQUID_FILL_GAUGE":
				case "WATERFALL_CHART":
				case "BIPARTITE_CHART":
				case "SANKEY_CHART":
				case "PARALLEL_COORDINATE":
				case "BUBBLE_PACK_CHART":
				case "WORD_CLOUD_V2":
				case "DENDROGRAM_BAR_CHART":
				case "COLLAPSIBLE_TREE_CHART":
				case "CALENDAR_VIEW_CHART":
				case "CALENDAR_VIEW2_CHART":
				case "CALENDAR_VIEW3_CHART":
				case "HEATMAP":
				case "HEATMAP2":
				case "COORDINATE_DOT":
				case "COORDINATE_LINE":
                case "SYNCHRONIZED_CHARTS":
				case "RECTANGULAR_ARAREA_CHART":
				case "WORD_CLOUD":
				case "BUBBLE_D3":
				case "FORCEDIRECT":
				case "FORCEDIRECTEXPAND":
				case "HIERARCHICAL_EDGE":
					imageMap.put(content.getString("item"), content.getString("uploadPath").substring(content.getString("uploadPath").lastIndexOf(slash) + 1, content.getString("uploadPath").length()));
//					System.out.println((String) content.getString("item"));
					XSSFSheet sheet1 = workbook.createSheet((String) content.getString("item"));
					try {
						
						byte[] bytes = IOUtils.toByteArray(inputStream);
						int pictureIdx = workbook.addPicture(bytes, XSSFWorkbook.PICTURE_TYPE_PNG);

						XSSFCreationHelper helper = workbook.getCreationHelper();
						XSSFDrawing drawing = sheet1.createDrawingPatriarch();
						XSSFClientAnchor anchor = helper.createClientAnchor();

						// 이미지를 출력할 CELL 위치 선정
						anchor.setCol1(0);
						anchor.setRow1(0);

						// 이미지 그리기
						XSSFPicture pict = drawing.createPicture(anchor, pictureIdx);

						// 이미지 사이즈 비율 설정
						pict.resize();
					//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//					}catch (IOException e) {			
					}catch (Exception e) {
						e.printStackTrace();
						throw e;
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					}finally {
						inputStream.close();
					}

					break;
				}
				//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
				//Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
				//logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));
			}
			// 파일을 쓴다
			workbook.write(xlsxfileoutputstream);
	        String s [] = {path + tempType + slash + reportName + "." + tempType, path + tempType + slash + reportName + "." + downloadType};
            // BufferedWriter 와 FileWriter를 조합하여 사용 (속도 향상)
			
//	        ToHtml.main(s);
	        converter.main(s, imageMap);
//	        converter.setCompleteHTML(true);
//	        converter.printPage();
	        
//	        System.out.println(path + tempType + slash + reportName + "." + downloadType);
	        
			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", path + tempType + slash + reportName + "." + downloadType);
		
		//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//		}catch (IOException e) {			
		}catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			throw e;
		} finally {
			// 필수로 닫아주어야함
			xlsxfileoutputstream.close();
			workbook.close();
		}
		
		return returnobj;
	}
	
	@RequestMapping(value = "/pptx.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject pptDownloader(HttpServletRequest request, HttpServletResponse response)	throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");

		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
		String paramStr = SecureUtils.getParameter(request, "params");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String tempType = SecureUtils.getParameter(request, "tempType");
		String downloadType = SecureUtils.getParameter(request, "downloadType");
		String path = request.getSession(false).getServletContext().getRealPath("/");
		JSONObject returnobj = new JSONObject();
		FileOutputStream fileoutputstream = null;
		
		XMLSlideShow powerpoint = new XMLSlideShow();
		
		ConvertSheet2PptTableController converter = new ConvertSheet2PptTableController();
		try {
			// Write the Document in file system
			String slash = "";
			java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
			boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

			
			if(osBean.getName().indexOf("Windows") != -1) {
				if(weblogicPath) {
					/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
					path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
				}else {
					path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
				}
//				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				
				slash = "\\";
			}else {
				if(weblogicPath) {
					/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
					path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
				}else {
					path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
				}
//				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				
				slash = "/";
			}
			
			new File(path + tempType + slash).mkdirs();
			fileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + downloadType);

			for (int i = 0; i < contentList.size(); i++) {
				JSONObject content = (JSONObject) contentList.get(i);
				//2020.03.03 mksong 파일 업로드 통일 dogfoot
				FileInputStream file = new FileInputStream((String) content.get("uploadPath"));
				XSLFSlide slide = powerpoint.createSlide();
//				XSLFSimpleShape rect = slide.createAutoShape();
//				rect.setShapeType(ShapeType.RECT);
//		        rect.setAnchor(new Rectangle(100, 100, 100, 100));
//				XSLFTextBox textBox = slide.createTextBox();
//				XSLFTextParagraph paragraph = textBox.addNewTextParagraph();
//			    XSLFTextRun run = paragraph.addNewTextRun();
				// 2차는 sheet생성
				switch (content.getString("itemtype")) {
				case "PIVOT_GRID":
				case "DATA_GRID":
				//2020.03.03 mksong 텍스트박스 추가 dogfoot
				case "TEXTBOX":
//					paragraph.setTextAlign(TextAlign.CENTER);
//					run.setText((String) content.getString("item"));
				    
//					System.out.println((String) content.getString("item"));
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					XSSFWorkbook wb = new XSSFWorkbook(file);
					XSSFSheet movingSheet = (wb.getSheetAt(0));
					XSLFTable positionTable = slide.createTable();
					positionTable.setAnchor(new Rectangle(10, 10, 10, 10));
//					XSLFTableRow tableRow = positionTable.addRow();
//				    XSLFTableCell cell = tableRow.addCell();
//				    XSLFTextParagraph textparagraph = cell.addNewTextParagraph();
//				    XSLFTextRun textrun = textparagraph.addNewTextRun();
//				    textrun.setText("Any Text");
//				    textrun.setFontColor(Color.BLUE);
//				    textparagraph.setTextAlign(TextAlign.CENTER);
//				    tableRow.addCell();
//				    tableRow.addCell();
//				    tableRow.mergeCells(0, 1);
					
					converter.convertXSSF2XSLF(positionTable, movingSheet);
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					file.close();
					break;
				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
				case "SIMPLE_CHART":
				case "CHOROPLETH_MAP":
				case "FUNNEL_CHART":
				case "PYRAMID_CHART":
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case "KAKAO_MAP":
				case "KAKAO_MAP2":
				case "PIE_CHART":
				case "TREEMAP" :
				case "STAR_CHART" :
				/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
				case "CARD_CHART":
				case "HISTOGRAM_CHART":
				case "DIVERGING_CHART":
				case "SCATTER_PLOT":
				case "SCATTER_PLOT2":
				case "HISTORY_TIMELINE":
				case "ARC_DIAGRAM":
				case "RADIAL_TIDY_TREE":
				case "SCATTER_PLOT_MATRIX":
				case "BOX_PLOT":
				case "DEPENDENCY_WHEEL":
				case "SEQUENCES_SUNBURST":
				case "LIQUID_FILL_GAUGE":
				case "WATERFALL_CHART":
				case "BIPARTITE_CHART":
				case "SANKEY_CHART":
				case "PARALLEL_COORDINATE":
				case "BUBBLE_PACK_CHART":
				case "WORD_CLOUD_V2":
				case "DENDROGRAM_BAR_CHART":
				case "COLLAPSIBLE_TREE_CHART":
				case "CALENDAR_VIEW_CHART":
				case "CALENDAR_VIEW2_CHART":
				case "CALENDAR_VIEW3_CHART":
				case "HEATMAP":
				case "HEATMAP2":
				case "COORDINATE_DOT":
				case "COORDINATE_LINE":
                case "SYNCHRONIZED_CHARTS":
				case "RECTANGULAR_ARAREA_CHART":
				case "WORD_CLOUD":
				case "BUBBLE_D3":
				case "FORCEDIRECT":
				case "FORCEDIRECTEXPAND":
				case "HIERARCHICAL_EDGE":
					try {
//						paragraph.setTextAlign(TextAlign.CENTER);
//						run.setText((String) content.getString("item"));
//						FileInputStream file = new FileInputStream((String) content.getString("uploadPath"));
						// 이미지 파일 로드
//						BufferedImage img = ImageIO.read(file);
//						int width = img.getWidth();
//						int height = img.getHeight();
//						String imgFileName = (String) content.getString("item") + ".png";
						// System.out.println("width : " + width +"\n height: " + height + "\n img : " +
						// img + "\n imgname : " + imgFileName);
						//2020.03.03 mksong 파일 업로드 통일 dogfoot
						byte[] picture = IOUtils.toByteArray(file);
//						int imgFormat = converter.getImageFormat(imgFileName);
						XSLFPictureData pictureData = powerpoint.addPicture(picture, PictureType.PNG);
						XSLFPictureShape pictureShape = slide.createPicture(pictureData);
					//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//					}catch (IOException e) {			
					}catch (Exception e) {
						e.printStackTrace();
						throw e;
					}finally {
						file.close();
					}

					break;
//				case "PIE_CHART":
//					try {
//						System.out.println((String) content.getString("item"));
//						run.setText((String) content.getString("item") + "\t \n");
//						run.addBreak();
//						run.addBreak();
//						FileInputStream file = new FileInputStream((String) content.getString("uploadPath"));
//						// 이미지 파일 로드
//						BufferedImage img = ImageIO.read(file);
//						int width = img.getWidth();
//						int height = img.getHeight();
//						String imgFileName = (String) content.getString("item") + ".png";
//						// System.out.println("width : " + width +"\n height: " + height + "\n img : " +
//						// img + "\n imgname : " + imgFileName);
//
//						int imgFormat = converter.getImageFormat(imgFileName);
//						run.addBreak();
//						run.addPicture(new FileInputStream((String) content.getString("uploadPath")), imgFormat, imgFileName, Units.toEMU(width), Units.toEMU(height));
//						run.addBreak();
//						run.addBreak(BreakType.PAGE);
//					} catch (IOException e) {
//						e.printStackTrace();
//					}
//
//					break;
				}
				//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
//				Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
//				logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));
			}
			
			powerpoint.write(fileoutputstream);
			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", path + tempType + slash + reportName + "." + downloadType);

		//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//		}catch (IOException e) {			
		}catch (Exception e) {
			e.printStackTrace();
			throw e;
		} finally {
			powerpoint.close();
			fileoutputstream.close();
		}

		return returnobj;

	}
	
	@RequestMapping(value = "/saveItemCSV.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject saveItemCSV(@RequestParam("exceldata") MultipartFile uploadFile,
			MultipartHttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		// UtilFile 객체 생성
		UtilFile utilFile = new UtilFile();

		// 파일 업로드 결과값을 path로 받아온다(이미 fileUpload() 메소드에서 해당 경로에 업로드는 끝났음)
		JSONObject obj = utilFile.fileUpload(request, uploadFile, ".xlsx");
		//2020.03.03 mksong 파일 업로드 통일 dogfoot
		FileInputStream file = new FileInputStream((String) obj.get("uploadPath"));
		XSSFWorkbook wb = new XSSFWorkbook(file);
		XSSFSheet convertSheet = (wb.getSheetAt(0));
    	ArrayList<String> rowList = echoAsCSV(convertSheet);
    	obj.put("rowList", rowList);
		wb.close();
		//2020.03.03 mksong 파일 업로드 통일 dogfoot
		file.close();
		//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
		Boolean checkDelete = new File((String) obj.get("uploadPath")).delete();
		System.out.println("임시파일 삭제여부 : " + checkDelete + "\n 임시파일 : " + (String) obj.get("uploadPath"));
		return obj;
	}
	
	public static ArrayList echoAsCSV(XSSFSheet sheet) {
		ArrayList<String> rowList = new ArrayList<>();
        XSSFRow row = null;
        for (int i = 0; i < sheet.getLastRowNum() + 1 ; i++) {
        	String r = "";
            row = sheet.getRow(i);
            for (int j = 0; j < row.getLastCellNum(); j++) {
            	switch(row.getCell(j).getCellType()) {
            		case  STRING:
            			String value = row.getCell(j).getStringCellValue().replaceAll("\n", "");
            			value.replaceAll(",", "_");
            			r += value + ",";
            			break;
            		case NUMERIC:
            			r += row.getCell(j).getNumericCellValue() + ",";
                        break;
            		case BLANK:
            			r += ",";
                        break;
            	}
            }
            rowList.add(r+"\n");
        }
        return rowList;
    }
	
	@RequestMapping(value = "/saveItemTXT.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject saveItemTXT(@RequestParam("exceldata") MultipartFile uploadFile,
			MultipartHttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		// UtilFile 객체 생성
		UtilFile utilFile = new UtilFile();

		// 파일 업로드 결과값을 path로 받아온다(이미 fileUpload() 메소드에서 해당 경로에 업로드는 끝났음)
		JSONObject obj = utilFile.fileUpload(request, uploadFile, ".xlsx");
		XSSFWorkbook wb = new XSSFWorkbook(new FileInputStream((String) obj.get("uploadPath")));
		XSSFSheet convertSheet = (wb.getSheetAt(0));
    	ArrayList<String> rowList = echoAsTXT(convertSheet);
    	obj.put("rowList", rowList);
		wb.close();
		return obj;
	}
	
	public static ArrayList echoAsTXT(XSSFSheet sheet) {
		ArrayList<String> rowList = new ArrayList<>();
        XSSFRow row = null;
        for (int i = 0; i < sheet.getLastRowNum() + 1 ; i++) {
        	String r = "";
            row = sheet.getRow(i);
            for (int j = 0; j < row.getLastCellNum(); j++) {
            	switch(row.getCell(j).getCellType()) {
            		case  STRING:
            			String value = row.getCell(j).getStringCellValue().replaceAll("\n", "");
            			r += value + "\t";
            			break;
            		case NUMERIC:
            			r += row.getCell(j).getNumericCellValue() + "\t";
                        break;
            		case BLANK:
            			r += "\t";
                        break;
            	}
            }
            rowList.add(r+"\n");
        }
        return rowList;
    }
	
	@RequestMapping(value = "/html.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject downloadHtml(HttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		
		ConvertSheet2HtmlConverter converter = new ConvertSheet2HtmlConverter();
		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
		String paramStr = SecureUtils.getParameter(request, "params");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String tempType = SecureUtils.getParameter(request, "tempType");
		String downloadType = SecureUtils.getParameter(request, "downloadType");
		JSONObject returnobj = new JSONObject();
		String path = "";
		String slash = "";
		BufferedWriter fw = null;
		/*dogfoot 캡션숨긴 아이템 캡션명 삭제 shlim 20200625*/
		ArrayList<String> captionHideList = new ArrayList<>();
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");
		
		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "\\";
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "/";
		}
		XSSFWorkbook workbook = new XSSFWorkbook();
		new File(path + tempType + slash).mkdirs();
		FileOutputStream fileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + tempType);

		CellStyle bodyStyle = workbook.createCellStyle();
		bodyStyle.setBorderTop(BorderStyle.THIN);
		bodyStyle.setBorderBottom(BorderStyle.THIN);
		bodyStyle.setBorderLeft(BorderStyle.THIN);
		bodyStyle.setBorderRight(BorderStyle.THIN);
		try {
			MoveSheetController movesheet = new MoveSheetController();
			HashMap<String, String> imageMap = new HashMap<String, String>();
			JSONObject contentPath = (JSONObject) contentList.get(0);
			String pathString = (String) contentPath.get("uploadPath");
			pathString = pathString.replace("\\", "/");
			imageMap.put("contextPath", request.getRequestURL().substring(0, request.getRequestURL().indexOf("download")) + pathString.substring(pathString.lastIndexOf("UploadFiles"), pathString.lastIndexOf("/")));

			for (int i = 0; i < contentList.size(); i++) {
				JSONObject content = (JSONObject) contentList.get(i);
				//2020.03.03 mksong 파일 업로드 통일 dogfoot
				InputStream inputStream = new FileInputStream((String) content.getString("uploadPath"));
				/*dogfoot 캡션숨긴 아이템 캡션명 삭제 shlim 20200625*/
				if(content.has("hidecaption")) {
					captionHideList.add(content.getString("hidecaption"));
				}
				// 2차는 sheet생성
				switch (content.getString("itemtype")) {
				case "PIVOT_GRID":
				case "DATA_GRID":
				//2020.03.03 mksong 텍스트박스 추가 dogfoot
				case "TEXTBOX":
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					XSSFWorkbook wb = new XSSFWorkbook(inputStream);
					XSSFSheet movingSheet = (wb.getSheetAt(0));
					XSSFSheet positionSheet = workbook.createSheet((String) content.getString("item"));
					movesheet.copySheetSettings(positionSheet, movingSheet);
					movesheet.copyXSSFSheet(positionSheet, movingSheet);
					wb.close();
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					inputStream.close();
					break;
				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
				case "SIMPLE_CHART":
				case "CHOROPLETH_MAP":
				case "FUNNEL_CHART":
				case "PYRAMID_CHART":
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case "KAKAO_MAP":
				case "KAKAO_MAP2":
				case "PIE_CHART":
				case "TREEMAP" :
				case "STAR_CHART" :
				/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
				case "CARD_CHART":
				case "HISTOGRAM_CHART":
				case "DIVERGING_CHART":
				case "SCATTER_PLOT":
				case "SCATTER_PLOT2":
				case "HISTORY_TIMELINE":
				case "RADIAL_TIDY_TREE":
				case "SCATTER_PLOT_MATRIX":
				case "BOX_PLOT":
				case "DEPENDENCY_WHEEL":
				case "SEQUENCES_SUNBURST":
				case "LIQUID_FILL_GAUGE":
				case "WATERFALL_CHART":
				case "BIPARTITE_CHART":
				case "SANKEY_CHART":
				case "PARALLEL_COORDINATE":
				case "BUBBLE_PACK_CHART":
				case "WORD_CLOUD_V2":
				case "DENDROGRAM_BAR_CHART":
				case "COLLAPSIBLE_TREE_CHART":
				case "CALENDAR_VIEW_CHART":
				case "CALENDAR_VIEW2_CHART":
				case "CALENDAR_VIEW3_CHART":
				case "HEATMAP":
				case "HEATMAP2":
				case "COORDINATE_DOT":
				case "COORDINATE_LINE":
                case "SYNCHRONIZED_CHARTS":
				case "RECTANGULAR_ARAREA_CHART":
				case "WORD_CLOUD":
				case "BUBBLE_D3":
				case "FORCEDIRECT":
				case "FORCEDIRECTEXPAND":
				case "HIERARCHICAL_EDGE":
					imageMap.put(content.getString("item"), content.getString("uploadPath").substring(content.getString("uploadPath").lastIndexOf(slash) + 1, content.getString("uploadPath").length()));
//					System.out.println((String) content.getString("item"));
					XSSFSheet sheet1 = workbook.createSheet((String) content.getString("item"));
					try {
						// 이미지 파일 로드
						byte[] bytes = IOUtils.toByteArray(inputStream);
						int pictureIdx = workbook.addPicture(bytes, XSSFWorkbook.PICTURE_TYPE_PNG);

						XSSFCreationHelper helper = workbook.getCreationHelper();
						XSSFDrawing drawing = sheet1.createDrawingPatriarch();
						XSSFClientAnchor anchor = helper.createClientAnchor();

						// 이미지를 출력할 CELL 위치 선정
						anchor.setCol1(0);
						anchor.setRow1(0);

						// 이미지 그리기
						XSSFPicture pict = drawing.createPicture(anchor, pictureIdx);

						// 이미지 사이즈 비율 설정
						pict.resize();
					//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//					}catch (IOException e) {			
					}catch (Exception e) {
						e.printStackTrace();
						throw e;
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					}finally {
						inputStream.close();
					}

					break;
				}
				//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
//				Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
//				logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));
			}
			// 파일을 쓴다
			workbook.write(fileoutputstream);
	        String s [] = {path + tempType + slash + reportName + "." + tempType, path + tempType + slash + reportName + "." + downloadType};
            // BufferedWriter 와 FileWriter를 조합하여 사용 (속도 향상)
			
//	        ToHtml.main(s);
	        /*dogfoot 캡션숨긴 아이템 캡션명 삭제 shlim 20200625*/
	        converter.main(s, imageMap,captionHideList);
//	        converter.setCompleteHTML(true);
//	        converter.printPage();
	        
//	        System.out.println(path + tempType + slash + reportName + "." + downloadType);
	        
			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", path + tempType + slash + reportName + "." + downloadType);
			
		//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//		}catch (IOException e) {			
		}catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			throw e;
		} finally {
			// 필수로 닫아주어야함
			fileoutputstream.close();
			workbook.close();
		}
		
		
		return returnobj;
	}
	
	@RequestMapping(value = "/pdf.do", method = RequestMethod.POST)
	public @ResponseBody JSONObject pdfDownLoader(HttpServletRequest request, HttpServletResponse response) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		
		ConvertSheet2HtmlConverterForPdf converter = new ConvertSheet2HtmlConverterForPdf();
		JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
		String paramStr = SecureUtils.getParameter(request, "params");
		String reportName = SecureUtils.getParameter(request, "reportName");
		String tempType = "xlsx";
		String downloadType = SecureUtils.getParameter(request, "downloadType");
		JSONObject returnobj = new JSONObject();
		String path = "";
		String slash = "";
		String imgpath = "";
		/*dogfoot 캡션숨긴 아이템 캡션명 삭제 shlim 20200625*/
		ArrayList<String> captionHideList = new ArrayList<>();
		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");
		
		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "\\";
		}else {
			if(weblogicPath) {
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
			}else {
				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			}
//			path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
			/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
			
			slash = "/";
		}
		XSSFWorkbook workbook = new XSSFWorkbook();
		new File(path + tempType + slash).mkdirs();
		FileOutputStream fileoutputstream = new FileOutputStream(path + tempType + slash + reportName + "." + tempType);
		
		CellStyle bodyStyle = workbook.createCellStyle();
		bodyStyle.setBorderTop(BorderStyle.THIN);
		bodyStyle.setBorderBottom(BorderStyle.THIN);
		bodyStyle.setBorderLeft(BorderStyle.THIN);
		bodyStyle.setBorderRight(BorderStyle.THIN);
		try {
			MoveSheetController movesheet = new MoveSheetController();
			HashMap<String, String> imageMap = new HashMap<String, String>();
			JSONObject contentPath = (JSONObject) contentList.get(0);
			String pathString = (String) contentPath.get("uploadPath");
			pathString = pathString.replace("\\", "/");
			imageMap.put("contextPath", request.getRequestURL().substring(0, request.getRequestURL().indexOf("download")) + pathString.substring(pathString.lastIndexOf("UploadFiles"), pathString.lastIndexOf("/")));

			for (int i = 0; i < contentList.size(); i++) {
				JSONObject content = (JSONObject) contentList.get(i);
				//2020.03.03 mksong 파일 업로드 통일 dogfoot
				InputStream inputStream = new FileInputStream((String) content.getString("uploadPath"));
				/*dogfoot 캡션숨긴 아이템 캡션명 삭제 shlim 20200625*/
				if(content.has("hidecaption")) {
					captionHideList.add(content.getString("hidecaption"));
				}
				// 2차는 sheet생성
				switch (content.getString("itemtype")) {
				case "PIVOT_GRID":
				case "DATA_GRID":
					XSSFWorkbook wb = new XSSFWorkbook(new FileInputStream((String) content.get("uploadPath")));
					XSSFSheet movingSheet = (wb.getSheetAt(0));
					XSSFSheet positionSheet = workbook.createSheet((String) content.getString("item"));
					movesheet.copySheetSettings(positionSheet, movingSheet);
					movesheet.copyXSSFSheet(positionSheet, movingSheet);
					wb.close();
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					inputStream.close();
					break;
				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
				case "SIMPLE_CHART":
				case "CHOROPLETH_MAP":
				case "FUNNEL_CHART":
				case "PYRAMID_CHART":
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case "KAKAO_MAP":
				case "KAKAO_MAP2":
				case "PIE_CHART":
				case "TREEMAP" :
				case "STAR_CHART" :
				/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
				case "CARD_CHART":
				case "HISTOGRAM_CHART":
				case "DIVERGING_CHART":
				case "SCATTER_PLOT":
				case "SCATTER_PLOT2":
				case "HISTORY_TIMELINE":
				case "ARC_DIAGRAM":
				case "RADIAL_TIDY_TREE":
				case "SCATTER_PLOT_MATRIX":
				case "BOX_PLOT":
				case "DEPENDENCY_WHEEL":
				case "SEQUENCES_SUNBURST":
				case "LIQUID_FILL_GAUGE":
				case "WATERFALL_CHART":
				case "BIPARTITE_CHART":
				case "SANKEY_CHART":
				case "PARALLEL_COORDINATE":
				case "BUBBLE_PACK_CHART":
				case "WORD_CLOUD_V2":
				case "DENDROGRAM_BAR_CHART":
				case "COLLAPSIBLE_TREE_CHART":
				case "CALENDAR_VIEW_CHART":
				case "CALENDAR_VIEW2_CHART":
				case "CALENDAR_VIEW3_CHART":
				case "HEATMAP":
				case "HEATMAP2":
				case "COORDINATE_DOT":
				case "COORDINATE_LINE":
                case "SYNCHRONIZED_CHARTS":
				case "RECTANGULAR_ARAREA_CHART":
				case "WORD_CLOUD":
				case "BUBBLE_D3":
				case "FORCEDIRECT":
				case "FORCEDIRECTEXPAND":
				case "HIERARCHICAL_EDGE":
					imageMap.put(content.getString("item"), content.getString("uploadPath").substring(content.getString("uploadPath").lastIndexOf(slash) + 1, content.getString("uploadPath").length()));
					XSSFSheet sheet1 = workbook.createSheet((String) content.getString("item"));
					try {
						// 이미지 파일 로드
						imgpath = content.getString("uploadPath").substring(0, content.getString("uploadPath").lastIndexOf(slash)+1);
						
						byte[] bytes = IOUtils.toByteArray(inputStream);
						int pictureIdx = workbook.addPicture(bytes, XSSFWorkbook.PICTURE_TYPE_PNG);
						inputStream.close();

						XSSFCreationHelper helper = workbook.getCreationHelper();
						XSSFDrawing drawing = sheet1.createDrawingPatriarch();
						XSSFClientAnchor anchor = helper.createClientAnchor();

						// 이미지를 출력할 CELL 위치 선정
						anchor.setCol1(0);
						anchor.setRow1(0);

						// 이미지 그리기
						XSSFPicture pict = drawing.createPicture(anchor, pictureIdx);

						// 이미지 사이즈 비율 설정
						pict.resize();
					//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//					}catch (IOException e) {			
					}catch (Exception e) {
						e.printStackTrace();
						throw e;
					//2020.03.03 mksong 파일 업로드 통일 dogfoot
					}finally {
						inputStream.close();
					}

					break;
				}
				//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
//				Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
//				logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));
			}
			// 파일을 쓴다
			workbook.write(fileoutputstream);
	        String s [] = {path + tempType + slash + reportName + "." + tempType, path + tempType + slash + reportName + ".html"};
            // BufferedWriter 와 FileWriter를 조합하여 사용 (속도 향상)
			
//	        ToHtml.main(s);
	        converter.main(s, imageMap, imgpath);
//	        converter.setCompleteHTML(true);
//	        converter.printPage();
	        
//	        System.out.println(path + tempType + slash + reportName + "." + downloadType);
			ConvertHtml2PdfConverter html2pdf = new ConvertHtml2PdfConverter();

			BufferedReader br = null;
	        String htmlStr = ""; // 테스트용 변수
	         try {
	            br = new BufferedReader(new FileReader(path + tempType + slash + reportName + ".html"));
	            String line = null;
	            
	            while ((line = br.readLine()) != null) {
	                //System.out.println(line);
	            	htmlStr += (line);
	            }
	            /*dogfoot 캡션숨긴 아이템 캡션명 삭제 shlim 20200625*/
	            for (String captionHideValue : captionHideList) {
                    if (captionHideValue == null || captionHideValue.length() == 0) {
                    	break;
                    }
                    htmlStr = htmlStr.replaceAll(captionHideValue, "");
	            }
	 
	        //2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//			}catch (IOException e) {			
			}catch (Exception e) {
	        	e.printStackTrace();
	        	throw e;
	        } finally {
	        	if (br != null) { 
                    try { 
                        br.close();
                    //2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//        			}catch (IOException e) {			
        			}catch (Exception e) {
    	            	e.printStackTrace();
    	            	br = null;
    	            	throw e;
    	            }
                }
	        }
//	        System.out.println(path + tempType + slash + reportName + ".html");
//	        HtmlConverter.convertToPdf(htmlStr, outputstream);
			String filePath = html2pdf.createPdf(path + tempType + slash + reportName + "." + downloadType, htmlStr, request);
			
			returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", filePath);
		//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//		}catch (IOException e) {			
		}catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			throw e;
		} finally {
			// 필수로 닫아주어야함
			fileoutputstream.close();
			workbook.close();
		}
		
		
		return returnobj;

	}
	
	@RequestMapping( value = "/downloadFile.do")
	public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws Exception {
		try {
		String displayFileName = SecureUtils.getParameter(request, "fileName");
		String encodedFilename = "";
		String filePath = SecureUtils.getParameter(request, "filePath");
		
		File file = new File(filePath);

//		System.out.println(displayFileName);
//		System.out.println(filePath);
		
		response.setContentType( "application/octet-stream" );
		response.setContentLength( (int) file.length() );

		String header = request.getHeader( "User-Agent" );

		if ( header.indexOf( "MSIE" ) > -1 || (header.indexOf("Mozilla") > -1 && header.indexOf("Edg") > -1)) {
			encodedFilename = URLEncoder.encode( displayFileName, "UTF-8" ).replaceAll( "\\+", "%20" );
		}
		else if ( header.indexOf( "Trident" ) > -1 ) { 
			encodedFilename = URLEncoder.encode( displayFileName, "UTF-8" ).replaceAll( "\\+", "%20" );
		}
		else if ( header.indexOf( "Chrome" ) > -1 ) {
			StringBuffer sb = new StringBuffer();

			for ( int i = 0; i < displayFileName.length(); i++ ) {
				char c = displayFileName.charAt( i );
				if ( c > '~' ) {
					sb.append( URLEncoder.encode( "" + c, "UTF-8" ) );
				}
				else {
					sb.append( c );
				}

			}
			encodedFilename = sb.toString();
		}
		else if ( header.indexOf( "Opera" ) > -1 ) {
			encodedFilename = "\"" + new String( displayFileName.getBytes( "UTF-8" ), "8859_1" ) + "\"";
		}
		else if ( header.indexOf( "Safari" ) > -1 ) {
			encodedFilename = "\"" + new String( displayFileName.getBytes( "UTF-8" ), "8859_1" ) + "\"";
			encodedFilename = URLDecoder.decode(encodedFilename, "UTF-8");
		}else{
			encodedFilename = "\"" + new String( displayFileName.getBytes( "UTF-8" ), "8859_1" ) + "\"";
			encodedFilename = URLDecoder.decode(encodedFilename, "UTF-8");
		}

		response.setHeader( "Content-Disposition", "attachment; filename=\"" + encodedFilename + "\";" );
		response.flushBuffer();
		
		OutputStream out = response.getOutputStream();

		try (FileInputStream fis = new FileInputStream( file );
				BufferedInputStream bis = new BufferedInputStream(fis)){

			FileCopyUtils.copy( bis, out );
		//2020.03.05 KERIS MKSONG 오류 내용 확인 위해 임시로 Exception 변경 DOGFOOT
//		}catch (IOException e) {			
		}catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
		finally {
			//2020.03.05 MKSONG 다운로드 파일 서버에서 삭제 위해 수정 DOGFOOT
			Boolean checkDelete = new File(filePath).delete();
			System.out.println("최종 파일 삭제여부 : " + checkDelete + "\n파일 : " + filePath);
		}

		out.flush();
		} catch(IOException e) {
			e.printStackTrace();
			throw e;
		}
	}
	
	/*dogfoot shlim 20210308
     * 문자열 데이터 숫자로만 이루어져 있는지 체크 하는 함수 
     * */
    public boolean checkOnlyNumInString(String s) {
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
	/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
	@RequestMapping(value = {"/sqlLikeExcel.do"}, method = RequestMethod.POST)
    public @ResponseBody JSONObject sqllikeexcel(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
 		FileOutputStream outByteStream = null;
		XSSFWorkbook wb = null;
		SXSSFWorkbook workbook = null;
		JSONObject returnobj = new JSONObject();
		
			
 		try {
 			request.setCharacterEncoding("utf-8");

 			JSONArray contentList = SecureUtils.getJSONArrayParameter(request, "contentList");
 			Timer timer = new Timer();

 			int sqlTimeout = Integer.parseInt(SecureUtils.getParameter(request, "sqlTimeout"));
 			String status = "50";
 			JSONObject params = SecureUtils.getJSONObjectParameter(request, "params");
 			
 			JSONArray paramJsonArray = SecureUtils.getJSONArrayParameter(request, "paramJsonArray");
 			/* 2020.12.18 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
 			String downloadFilter = SecureUtils.getParameter(request, "downloadFilter");

 			/*
 			String userId = SecureUtils.getParameter(request, "userId");
 			String reportType = SecureUtils.getParameter(request, "reportType");
 			String reportName = SecureUtils.getParameter(request, "reportName");
 			원래 있던거*/
 			
 			String userId = SecureUtils.getParameter(request, "userId");
 			String userName = SecureUtils.getParameter(request, "userName");
 			String srcFolderNm = SecureUtils.getParameter(request, "srcFolderNm");
 			String reportType = SecureUtils.getParameter(request, "reportType");
 			String reportName = SecureUtils.getParameter(request, "reportName");
 			String downloadType = SecureUtils.getParameter(request, "downloadType");
 			
 			
 			String reportOriName = "";
 			String contentN = reportName.substring(reportName.length()-1);
 			if(NumberUtils.isNumber(contentN)) {
 				contentN = reportName.substring(reportName.length()-2);
 				if(NumberUtils.isNumber(contentN)) {
 					reportOriName = reportName.substring(0, reportName.length()-2);
 				} else {
 					reportOriName = reportName.substring(0, reportName.length()-1);
 				}
 			} else {
 				reportOriName = reportName;
 			}
			
 			int sortColumnCount = 0;

 			timer.start();

 			status = "60";
 			
 			//2020.09.11 mksong 타이머 위치 오류 수정 dogfoot
 			
 			List<JSONObject> list = null;
 			MoveSheetControllerForXlsx movesheet = new MoveSheetControllerForXlsx();
			
			//2020.07.22 MKSONG 다운로드 필터조건 포함 DOGFOOT
			
			// 2019.12.20 mksong 시트 이름 중복 오류 수정 dogfoot
			int sameIndex = 0;

			ObjectMapper mapper = new ObjectMapper();

			String path = "";
			String slash = "";
			java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
			boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

			if(osBean.getName().indexOf("Windows") != -1) {
				if(weblogicPath) {
					/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
					path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
				}else {
					path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
				}
//				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				
				slash = "\\";
			}else {
				if(weblogicPath) {
					/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
					path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
				}else {
					path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
				}
//				path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
				/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				
				slash = "/";
			}
			new File(path + "excel" + slash).mkdirs();
			outByteStream = new FileOutputStream(path + "excel" + slash + reportName + "." + downloadType);
			// 			outByteStream = new ByteArrayOutputStream();

			// xlsx파일은 xml이 포함되어 있으므로 많은데이터를 변환할 경우 Apache Poi에서 Zip bomb 에러를 발생시킴
			// workbook 생성 전에 반드시 호출할것
			ZipSecureFile.setMinInflateRatio(0);
			wb = new XSSFWorkbook();

			CellStyle bodyStyle = wb.createCellStyle();
			bodyStyle.setBorderTop(BorderStyle.THIN);
			bodyStyle.setBorderBottom(BorderStyle.THIN);
			bodyStyle.setBorderLeft(BorderStyle.THIN);
			bodyStyle.setBorderRight(BorderStyle.THIN);
			
//			if(paramJsonArray.size() != 0) {
//				XSSFSheet infoSheet =  wb.createSheet("조건");
//				infoSheet.createRow(0).createCell(0).setCellValue("필터 차원");
//				infoSheet.getRow(0).createCell(1).setCellValue("조건 값");
//				for(int j = 0; j < paramJsonArray.size(); j++) {
//					infoSheet.createRow(j+1).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
//					infoSheet.getRow(j+1).createCell(1).setCellValue(paramJsonArray.getJSONObject(j).getString("value"));
//				}
//			}
			
 			for(int con = 0; con < contentList.size(); con++) {
 				JSONObject content = contentList.getJSONObject(con);
 				boolean isSameName = false;
 				String itemType = content.getString("itemtype");
 				
 				switch (itemType) {
				case "TEXTBOX":
					OPCPackage opcPackage = OPCPackage.open(new FileInputStream((String) content.get("uploadPath")));
					XSSFWorkbook subWb = new XSSFWorkbook(opcPackage);
					XSSFSheet movingSheet = (subWb.getSheetAt(0));
					
					for(int j = 0; j < wb.getNumberOfSheets(); j++) {
						if(wb.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
					XSSFSheet positionSheet;
					
					if(isSameName) {
						positionSheet = wb.createSheet((String) content.getString("item")+"_"+sameIndex);	
					}else {
						positionSheet = wb.createSheet((String) content.getString("item"));
					}
					
					opcPackage.close();
					Boolean checkDelete = new File((String) content.get("uploadPath")).delete();
					logger.debug("임시파일 삭제여부 : " + checkDelete + "\t 임시파일 : " + (String) content.get("uploadPath"));
					break;
				// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
				case "SIMPLE_CHART":
				case "CHOROPLETH_MAP":
				case "PIE_CHART":
				case "TREEMAP" :
				case "STAR_CHART" :
				/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
				case "CARD_CHART":
				case "HISTOGRAM_CHART":
				case "DIVERGING_CHART":
				case "SCATTER_PLOT":
				case "SCATTER_PLOT2":
				case "HISTORY_TIMELINE":
				case "ARC_DIAGRAM":
				case "RADIAL_TIDY_TREE":
				case "SCATTER_PLOT_MATRIX":
				case "BOX_PLOT":
				case "DEPENDENCY_WHEEL":
				case "SEQUENCES_SUNBURST":
				case "LIQUID_FILL_GAUGE":
				case "WATERFALL_CHART":
				case "BIPARTITE_CHART":
				case "SANKEY_CHART":
				case "PARALLEL_COORDINATE":
				case "BUBBLE_PACK_CHART":
				case "WORD_CLOUD_V2":
				case "DENDROGRAM_BAR_CHART":
				case "COLLAPSIBLE_TREE_CHART":
				case "CALENDAR_VIEW_CHART":
				case "CALENDAR_VIEW2_CHART":
				case "CALENDAR_VIEW3_CHART":
				case "HEATMAP":
				case "HEATMAP2":
				case "COORDINATE_DOT":
				case "COORDINATE_LINE":
                case "SYNCHRONIZED_CHARTS":
				case "RECTANGULAR_ARAREA_CHART":
				case "WORD_CLOUD":
				case "BUBBLE_D3":
				case "FORCEDIRECT":
				case "FORCEDIRECTEXPAND":
				case "HIERARCHICAL_EDGE":
				case "FUNNEL_CHART":
				case "PYRAMID_CHART":
					for(int j = 0; j < wb.getNumberOfSheets(); j++) {
						if(wb.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
					XSSFSheet sheet1;
					
					if(isSameName) {
						sheet1 = wb.createSheet((String) content.getString("item")+"_"+sameIndex);	
					}else {
						sheet1 = wb.createSheet((String) content.getString("item"));
					}
					try {
						/* 2020.11.23 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
						if(downloadFilter.equals("Y")) {
							if(paramJsonArray.size() != 0) {
								sheet1.createRow(0).createCell(0).setCellValue("필터 차원");
								sheet1.getRow(0).createCell(1).setCellValue("조건 값");
								for(int j = 0; j < paramJsonArray.size(); j++) {
									sheet1.createRow(j+1).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
									
									if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
										sheet1.getRow(j+1).createCell(1).setCellValue("전체");
									}else if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_EMPTY_VALUE_\"]")){
										sheet1.getRow(j+1).createCell(1).setCellValue("");
									}else {
										String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
										paramValue = paramValue.replace("]", "");
										sheet1.getRow(j+1).createCell(1).setCellValue(paramValue);
									}
								}
							}
						}
						
						// 이미지 파일 로드
						InputStream inputStream = new FileInputStream((String) content.getString("uploadPath"));
						byte[] bytes = IOUtils.toByteArray(inputStream);
						int pictureIdx = wb.addPicture(bytes, XSSFWorkbook.PICTURE_TYPE_PNG);
						inputStream.close();

						XSSFCreationHelper helper = wb.getCreationHelper();
						XSSFDrawing drawing = sheet1.createDrawingPatriarch();
						XSSFClientAnchor anchor = helper.createClientAnchor();

						// 이미지를 출력할 CELL 위치 선정
//						anchor.setCol1(0);
//						anchor.setRow1(0);
						/* 2020.11.23 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
						if(downloadFilter.equals("Y") && paramJsonArray.size() != 0) {
							anchor.setCol1(0);
							anchor.setRow1(paramJsonArray.size() + 2);
						}else {
							anchor.setCol1(0);
							anchor.setRow1(0);
						}

						// 이미지 그리기
						XSSFPicture pict = drawing.createPicture(anchor, pictureIdx);

						// 이미지 사이즈 비율 설정
						pict.resize();
					} catch (Exception e) {
						e.printStackTrace();
					}

					Boolean checkDelete2 = new File((String) content.get("uploadPath")).delete();
					logger.debug("임시파일 삭제여부 : " + checkDelete2 + "\t 임시파일 : " + (String) content.get("uploadPath"));
					break;
 				case "DATA_GRID":
 				case "PIVOT_GRID":
 					int addRowNum = 0;
 					isSameName = false;

 					User user = this.authenticationService.getRepositoryUser(userId);
 					
 					String iscd = "yyyy";
 					Map<String, String> relCodeMap = new HashMap<String, String>();
 					if(user.getUSER_REL_CD() != null && !user.getUSER_REL_CD().equals("1001") && !user.getUSER_REL_CD().equals("")) {
 						String[] relCode = user.getUSER_REL_CD().split(",");
 						if(!relCode[0].equals("N")) {
 							iscd = relCode[0];
 						}
 					}
// 					String sosok = this.dataSetServiceImpl.selectGoyongUserSosok(iscd);
// 					if(sosok == null || sosok.equals("1001") || sosok.equals("")) {
// 						sosok = "";
// 					} else {
// 						sosok = sosok + " ";
// 					}
 					
 					String memoText = "";
 					if(content.has("memoText")) {
 						memoText = content.getString("memoText");
 					}
 					
 					String query = new String(Base64.decode(content.getString("query")));
					/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
 					list = this.dataSetServiceImpl.querySqlLike(content.getInt("dsid"), content.getString("dstype"), query, params, sqlTimeout, null, content.getJSONObject("sqlConfig"), content.getJSONObject("nullDimension"), "");
 					
 					//사용자데이터 컬럼 추가 시작 1029
 					if(content.has("udfGroups")) {
 						final String udfGroups = content.getString("udfGroups");
 						
 						final ArrayNode udfGroupParamsNode = StringUtils.isNotBlank(udfGroups)
 								? (ArrayNode) objectMapper.readTree(udfGroups)
 								: null;
 						final List<UdfGroupParam> udfGroupParams = ParamUtils.toUdfGroupParams(objectMapper, udfGroupParamsNode);
 						
 						for(int i = 0; i < udfGroupParams.size(); i++) {
 							for(int j = 0; j < list.size(); j++) {
 	 							JSONObject row = list.get(j);
 	 							UdfGroupParam udfGroupParam = udfGroupParams.get(i);
 	 							
 	 							final String name = udfGroupParam.getName();
 	 			                final String expression = udfGroupParam.getExpression();

 	 			                if (StringUtils.isBlank(name) || StringUtils.isBlank(expression)) {
 	 			                	break;
 	 			                }

	 	 			            Map<String, Object> context = null;
	
	 	 		                context = new HashMap<>();
	
	 	 		                Iterator iterator = row.keySet().iterator();
	 	 		                
	 	 		                while(iterator.hasNext()) {
	 	 		                	String key = (String)iterator.next();
	 	 		                	context.put(key, row.get(key));
	 	 		                }
 	 		                	
 	 		                		final Object ret = expressionEngine.evaluate(context, expression, null);
 		 	 		                BigDecimal numValue = null;
 		
 		 	 		                if (ret instanceof BigDecimal) {
 		 	 		                    numValue = (BigDecimal) ret;
 		 	 		                }
 		 	 		                else if (ret instanceof Number) {
 		 	 		                    numValue = new BigDecimal(ret.toString());
 		 	 		                }
 		 	 		                
 		 	 		                if(numValue == null) {
 		 	 		                	numValue = new BigDecimal(0);
 		 	 		                }
 		 	 		                
 		 	 		                row.put("sum_"+name, numValue);
 	 		                	
 	 						}
 						}
 					}   
 					//사용자데이터 컬럼 추가 끝 1029
 					/* 2020.12.18 mksong 주택금융공사 정렬컬럼 피벗테이블 제외 dogfoot */
 					sortColumnCount = content.getInt("sortColumnCount");
 							
 					JSONArray cols = null;
 					JSONArray rows = null;
 					JSONObject totalView = null;
 					JSONObject dataItems = null;
 					JSONArray mea = null;
 					JSONArray dim = null;
 					
 					XSSFSheet pivotSheet = null;
 					
 					int headerNo = 1;
 					String keyTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(System.currentTimeMillis()));
 					Sheet sh;
 					
 					for(int j = 0; j < wb.getNumberOfSheets(); j++) {
						if(wb.getSheetName(j).equals((String) content.getString("item"))){
							isSameName = true;
							sameIndex++;
						}
					}
 					
 					// 행열변경 처리 값
 					Boolean colRowSwitch = content.get("colRowSwitch") == null ? false : content.getBoolean("colRowSwitch");
 					if(itemType.equals("PIVOT_GRID")) {
 						if(isSameName) {
 							pivotSheet = wb.createSheet((String) content.getString("item")+"_"+sameIndex);
 							sh = wb.createSheet(content.getString("item") + "data"+sameIndex);
 						}
 						else {
 							pivotSheet = wb.createSheet((String) content.getString("item"));
 							sh = wb.createSheet(content.getString("item") + "data");
 						}
 						
 						// 행열변경 처리
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
						/* goyong ktkang 차원 측정값이 하나씩 밖에 없을때 다운로드 오류 수정  20210603 */
						mea = dataItems.getJSONArray("Measure");
						//dim = dataItems.getJSONArray("Dimension");
						
						if(userId.equals("okeis")) {
							pivotSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
							pivotSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
							pivotSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
							pivotSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime);
							pivotSheet.createRow(2);
							pivotSheet.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
							pivotSheet.createRow(4);
							addRowNum = 5;
							headerNo = 5;
						} else {
							pivotSheet.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
							pivotSheet.getRow(0).createCell(1, CellType.STRING).setCellValue("산림청");
							pivotSheet.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
							pivotSheet.getRow(1).createCell(1, CellType.STRING).setCellValue(userName);
							pivotSheet.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
							pivotSheet.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime);
							pivotSheet.createRow(3);
							pivotSheet.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
							pivotSheet.createRow(5);
							addRowNum = 6;
							headerNo = 6;
						}
 					}
 					
 					else {
 						dataItems = content.getJSONObject("dataItems");
						mea = dataItems.getJSONArray("Measure");
						
 						if(isSameName) {
 		 					sh = wb.createSheet(content.getString("item") + "data"+sameIndex);
 	 					}
 	 					else {
 	 						sh = wb.createSheet(content.getString("item"));
 	 					}
 	 					
 						if(userId.equals("okeis")) {
 							sh.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
 							sh.getRow(0).createCell(1, CellType.STRING).setCellValue("한국고용정보원 고용행정통계");
 							sh.createRow(1).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
 							sh.getRow(1).createCell(1, CellType.STRING).setCellValue(keyTime);
 							sh.getRow(1).getCell(1).setCellStyle(bodyStyle);
 							sh.createRow(2);
 							sh.createRow(3).createCell(0, CellType.STRING).setCellValue(reportName);
 							sh.createRow(4);
 							addRowNum = 5;
 						} else {
 							sh.createRow(0).createCell(0, CellType.STRING).setCellValue("출처");
 							sh.getRow(0).createCell(1, CellType.STRING).setCellValue("산림청");
 							sh.createRow(1).createCell(0, CellType.STRING).setCellValue("사용자");
 							sh.getRow(1).createCell(1, CellType.STRING).setCellValue(userName);
 							sh.createRow(2).createCell(0, CellType.STRING).setCellValue("다운로드 시간");
 							sh.getRow(2).createCell(1, CellType.STRING).setCellValue(keyTime);
 							sh.createRow(3);
 							sh.createRow(4).createCell(0, CellType.STRING).setCellValue(reportName);
 							sh.createRow(5);
 							addRowNum = 6;
 						}
 					}
 					
 					/* 2020.11.23 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
 					if(downloadFilter.equals("Y")) {
 						if(itemType.equals("PIVOT_GRID")) {
 							if(paramJsonArray.size() != 0) {
 								// headerNo = headerNo + paramJsonArray.size() + 2;
 								pivotSheet.createRow(addRowNum).createCell(0).setCellValue("필터 차원");
 								pivotSheet.getRow(addRowNum).getCell(0).setCellStyle(bodyStyle);
 								pivotSheet.getRow(addRowNum).createCell(1).setCellValue("조건 값");
 								pivotSheet.getRow(addRowNum).getCell(1).setCellStyle(bodyStyle);
 								for(int j = 0; j < paramJsonArray.size(); j++) {
 									String key = paramJsonArray.getJSONObject(j).getString("key");
 									Boolean bKeyChk = StringUtils.startsWithAny(key, "H_", "S_") ? false : true;
 									if(bKeyChk) {
 										addRowNum++;
 										pivotSheet.createRow(addRowNum).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
 										pivotSheet.getRow(addRowNum).getCell(0).setCellStyle(bodyStyle);
 										if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
 											pivotSheet.getRow(addRowNum).createCell(1).setCellValue("전체");
 											pivotSheet.getRow(addRowNum).getCell(1).setCellStyle(bodyStyle);
 										}else {
 											String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
 											paramValue = paramValue.replace("]", "");
 											pivotSheet.getRow(addRowNum).createCell(1).setCellValue(paramValue);
 											pivotSheet.getRow(addRowNum).getCell(1).setCellStyle(bodyStyle);
 										}
 									}
 								}
 							}
 							addRowNum++;
 							pivotSheet.createRow(addRowNum);
 						}
 						else {
 							if(paramJsonArray.size() != 0) {
 								sh.createRow(addRowNum).createCell(0).setCellValue("필터 차원");
 								sh.getRow(addRowNum).getCell(0).setCellStyle(bodyStyle);
 								sh.getRow(addRowNum).createCell(1).setCellValue("조건 값");
 								sh.getRow(addRowNum).getCell(1).setCellStyle(bodyStyle);
 								for(int j = 0; j < paramJsonArray.size(); j++) {
 									
 									String key = paramJsonArray.getJSONObject(j).getString("key");
 									Boolean bKeyChk = StringUtils.startsWithAny(key, "H_", "S_") ? false : true;
 									
 									if(bKeyChk) {
 										addRowNum++;
 										sh.createRow(addRowNum).createCell(0).setCellValue(paramJsonArray.getJSONObject(j).getString("key"));
 										sh.getRow(addRowNum).getCell(0).setCellStyle(bodyStyle);
 										if(paramJsonArray.getJSONObject(j).getString("value").equals("[\"_ALL_VALUE_\"]")) {
 											sh.getRow(addRowNum).createCell(1).setCellValue("전체");
 											sh.getRow(addRowNum).getCell(1).setCellStyle(bodyStyle);
 										}else {
 											String paramValue = paramJsonArray.getJSONObject(j).getString("value").replace("[", "");
 											paramValue = paramValue.replace("]", "");
 											sh.getRow(addRowNum).createCell(1).setCellValue(paramValue);
 											sh.getRow(addRowNum).getCell(1).setCellStyle(bodyStyle);
 										}
 									}
 								}
 							}
 							addRowNum++;
 							sh.createRow(addRowNum);
 						}
 					}
 					
 					Row heading;
 					if(itemType.equals("PIVOT_GRID")) {
 						heading = sh.createRow(0);
 					}
 					else {
 						addRowNum++;
 						heading = sh.createRow(addRowNum);
 					}
 					
 					ArrayList<String> columns = null;
 					JSONArray dataItems2 = null;
 					if(list.size() > 0) {
 						columns = new ArrayList<String>();
 						JSONObject jobj = list.iterator().next();
 						
 						// 행열변환으로 인해 컬럼 순서 다시 지정
 						if (colRowSwitch) {
 							for (Object item : cols) {
 								columns.add(((JSONObject)item).get("name").toString());
 							}
 							for (Object item : rows) {
 								columns.add(((JSONObject)item).get("name").toString());
 							}
 						}
 						
 						Iterator<?> keys = jobj.keys();
 						int sortCount = 0;
 						HashMap<String, Number> sortIndexArray = new HashMap<String, Number>();
 						HashMap<String, String> columnCaptionList = new HashMap<String, String>();
 						if(itemType.equals("PIVOT_GRID")) {
 							while (keys.hasNext()) {
 	 							Object key = keys.next();
 	 							// H_, S_ 제외
 	 							Boolean bKeyChk = StringUtils.startsWithAny(key.toString(), "H_", "S_", "min_S_","min_") ? false : true;
 	 							if (bKeyChk) {
 	 								
 	 								// new에서는 lamda가 되지 않음
 	 								// columns에 속하지 않을때만 추가해줌 
// 	 	 							if (columns.stream().filter(f -> f.equals(key.toString())).count() == 0) {
// 	 	 								columns.add(key.toString());
// 	 	 							}
 	 								Boolean bChk = true;
 	 								if (columns.size() > 0) {
 	 									for (int i = 0; i < columns.size(); i++) {
 	 	 									if (key.toString().equals(columns.get(i))) {
 	 	 										bChk = false;
 	 	 										break;
 	 	 									}
 	 	 								}
 	 								}
 	 								
 	 								if (bChk) {
 	 									columns.add(key.toString());
 	 								}
 	 							}else {
 	 								sortIndexArray.put(key.toString(), sortCount);
 	 							}
 	 							sortCount++;
 	 						}
 						}else {
 							JSONArray dataItemsForDataGrid = content.getJSONArray("dataItems2");
 							if(dataItemsForDataGrid.size() > 0) {
								for (int i = 0; i < dataItemsForDataGrid.size(); i++) {
									JSONObject dataItemForDataGridObject = (JSONObject) content.getJSONArray("dataItems2").get(i);
									columns.add(dataItemForDataGridObject.get("dataField").toString());
 								}
							}
 							while (keys.hasNext()) {
 	 							Object key = keys.next();
 	 							// H_, S_ 제외
 	 							Boolean bKeyChk = StringUtils.startsWithAny(key.toString(), "H_", "S_", "min_S_","min_") ? false : true;
 	 							if (bKeyChk) {
 	 								
 	 								// new에서는 lamda가 되지 않음
 	 								// columns에 속하지 않을때만 추가해줌 
// 	 	 							if (columns.stream().filter(f -> f.equals(key.toString())).count() == 0) {
// 	 	 								columns.add(key.toString());
// 	 	 							}
 	 								Boolean bChk = true;
 	 								if (columns.size() > 0) {
 	 									for (int i = 0; i < columns.size(); i++) {
 	 	 									if (key.toString().equals(columns.get(i))) {
 	 	 										bChk = false;
 	 	 										break;
 	 	 									}
 	 	 								}
 	 								}
 	 								
 	 								if (bChk) {
 	 									columns.add(key.toString());
 	 								}
 	 								
 	 								if(dataItemsForDataGrid.size() > 0) {
 	 									for (int i = 0; i < dataItemsForDataGrid.size(); i++) {
 	 										JSONObject dataItemForDataGridObject = (JSONObject) content.getJSONArray("dataItems2").get(i);
 	 												
 	 	 									if (key.toString().equals(dataItemForDataGridObject.get("dataField"))) {
 	 	 										columnCaptionList.put(key.toString(), dataItemForDataGridObject.get("caption").toString());
 	 	 										break;
 	 	 									}
 	 	 								}
 	 								}
 	 							}else {
 	 								sortIndexArray.put(key.toString(), sortCount);
 	 							}
 	 							sortCount++;
 	 						}
 						}
 						
 						
 	 					
 						if(content.has("headerList")) {
 	 						JSONObject headerList = content.getJSONObject("headerList");
 	 						
 	 						ArrayList<ArrayList<String>> tempHeaderList = new ArrayList<ArrayList<String>>();

 							HashMap<String, String> headerNmMapper = new HashMap<String, String>();
 							
 							HashMap<String, String> headerCaptionNmMapper = new HashMap<String, String>();
 							
 							int maxLength = 0;
 							int headerHeight = 0;
 							for (int i = 0; i < content.getJSONArray("dataItems2").size(); i++) {
 								if(!sortIndexArray.containsKey(columns.get(i).toString())) {
 									int headerCount = 0;
 	 								ArrayList<String> tempHeaderArr = new ArrayList<String> ();
 	 								
 	 								String column = columns.get(i).toString();
 	 								tempHeaderArr.add(column);
 	 								
 	 								Iterator<?> iter = headerList.keySet().iterator();
 	 								boolean isComplete = false;
 	 								while(iter.hasNext() && !isComplete) {
 	 									String key = (String)iter.next();
 	 									JSONObject headerInfo = headerList.getJSONObject(key);
 	 									
 	 									if(headerInfo.getString("HEADER_YN").equals("N")) continue;
 	 									
// 	 									if(i == 0) {
 	 										headerNmMapper.put(headerInfo.getString("HEADER_CODE"), headerInfo.getString("HEADER_NAME"));
// 	 									}
 	 									
 	 									if(headerInfo.getJSONArray("COLUMN_LIST").size()> 0) {
 	 										JSONArray colList= headerInfo.getJSONArray("COLUMN_LIST");
 	 										for(int j = 0; j < colList.size(); j++) {
 	 											if(colList.getJSONObject(j).getString("dataField").equals(column)) {
 	 												
 	 												tempHeaderArr.add(0, headerInfo.getString("HEADER_CODE"));
 	 												if(!headerNmMapper.containsKey(column)){
 	 													headerCaptionNmMapper.put(column, colList.getJSONObject(j).getString("caption"));
 	 												}
// 	 												tempHeaderArr.set(tempHeaderArr.indexOf(column), colList.getJSONObject(j).getString("caption"));
 	 												isComplete = true;
 	 												while(!headerInfo.isEmpty() && headerInfo.has("HEADER_UPPER") && !headerInfo.getString("HEADER_UPPER").equals("NonHeader")) {
 	 													headerInfo = headerList.getJSONObject(headerInfo.getString("HEADER_UPPER"));
 	 													if(!headerInfo.isEmpty() && headerInfo.has("HEADER_CODE")) {
 	 														tempHeaderArr.add(0, headerInfo.getString("HEADER_CODE"));
 	 													}
 	 													headerCount++;
 	 												}
 	 												if(tempHeaderArr.size() > maxLength) {
 	 													maxLength = tempHeaderArr.size();
 	 												}
 	 												break;
 	 											}
 	 										}
 	 									}
 	 								}
 	 								if(headerHeight < headerCount) {
 	 									headerHeight = headerCount;
 	 								}
 	 								
 	 								tempHeaderList.add(tempHeaderArr);
 								}
 							}
 							
// 							for(int j = 0; j < maxLength; j++) {
// 								String prevHeader = "WISE_START_HEADER";
// 								for(int i = 0; i < tempHeaderList.size(); i++) {
// 									String currentHeader = "WISE_NULL_HEADER";
// 									
// 									if(tempHeaderList.get(i).size() > j) {
// 										currentHeader = tempHeaderList.get(i).get(j);
// 									}
// 									if(prevHeader.equals("WISE_START_HEADER")) {
// 										if(tempHeaderList.get(i).size() <= j) {
// 											prevHeader = "WISE_NULL_HEADER";
// 										}else {
// 											prevHeader = tempHeaderList.get(i).get(j);
// 										}
// 									}else {
// 										if(prevHeader.equals(currentHeader)) {
// 											continue;
// 										}else {
// 											if(j != 0) {
// 												String tempStr1 = "WISE_NULL_HEADER";
// 												String tempStr2 = "WISE_NULL_HEADER";
// 												
// 												if(tempHeaderList.get(i).size() > j - 1) {
// 													tempStr1 = tempHeaderList.get(i).get(j-1);
// 												}
// 												if(tempHeaderList.get(i-1).size() > j - 1) {
// 													tempStr1 = tempHeaderList.get(i-1).get(j-1);
// 												}
// 												if(tempStr1.equals(tempStr2)) {
// 													prevHeader = currentHeader;
// 													continue;
// 												}
// 											}
// 											
// 											boolean headerCheck = false;
// 											for (int k = i; k < tempHeaderList.size(); k++) {
// 												String tempHeader = "WISE_NULL_HEADER";
// 												if(tempHeaderList.get(k).size() > j) {
// 													tempHeader = tempHeaderList.get(k).get(j);
// 												}
// 												
// 												if(prevHeader.equals(tempHeader)) {
// 													headerCheck = true;
// 													break;
// 												}
// 											}
// 											
// 											if(headerCheck) {
// 												tempHeaderList.add(tempHeaderList.get(i));
// 												tempHeaderList.remove(i);
// 												
// 												columns.add(columns.get(i));
// 												columns.remove(i);
// 												i--;
// 											} else {
// 												prevHeader = currentHeader;
// 											}
// 										}
// 									}
// 								}
// 							}
 							
 							if(maxLength > 0) {
 								for(int j = 0; j< maxLength; j++) {
 									heading = sh.createRow(addRowNum);
 									int startMerge = 0;
 									int endMerge = 0;
 									for (int i = 0; i < tempHeaderList.size(); i++) {
 										Cell cell = heading.createCell(i);
 										cell.setCellStyle(bodyStyle);
 										if(tempHeaderList.get(i).size() > j) {
 											if(headerNmMapper.containsKey(tempHeaderList.get(i).get(j).toString())){
 												cell.setCellValue(headerNmMapper.get(tempHeaderList.get(i).get(j).toString()));
 											} else{
 												if(tempHeaderList.get(i).size() < maxLength) {
 													if(columnCaptionList.containsKey(tempHeaderList.get(i).get(j).toString())) {
 														cell.setCellValue(columnCaptionList.get(tempHeaderList.get(i).get(j).toString()));
 													}else {
 														cell.setCellValue(tempHeaderList.get(i).get(j).toString());	
 													}
 													CellStyle alignCenterStyle = sh.getWorkbook().createCellStyle();
 													alignCenterStyle.setAlignment(HorizontalAlignment.CENTER);
 													alignCenterStyle.setVerticalAlignment(VerticalAlignment.CENTER);
 													cell.setCellStyle(alignCenterStyle);
 													final CellRangeAddress rangeAddr = new CellRangeAddress(addRowNum, addRowNum + maxLength - 1 - j, i, i);
 					 	 							sh.addMergedRegion(rangeAddr);
 					 	 							RegionUtil.setBorderTop(BorderStyle.THIN, rangeAddr, sh);
 					 	 					        RegionUtil.setBorderBottom(BorderStyle.THIN, rangeAddr, sh);
 					 	 					        RegionUtil.setBorderLeft(BorderStyle.THIN, rangeAddr, sh);
 					 	 					        RegionUtil.setBorderRight(BorderStyle.THIN, rangeAddr, sh);
 												} else {
 													cell.setCellValue(tempHeaderList.get(i).get(j).toString());
 												}
 											}
 										}
 										
 										if(i != 0) {
 											String tempStr1 = "WISE_NULL_HEADER";
 											String tempStr2 = "WISE_NULL_HEADER";
 											
 											if(tempHeaderList.get(i).size() > j) {
 												tempStr1 = tempHeaderList.get(i).get(j);
 											}
 											if(tempHeaderList.get(i-1).size() > j) {
 												tempStr2 = tempHeaderList.get(i - 1).get(j);
 											}
 											
 											if(!tempStr1.equals(tempStr2)) {
 												startMerge = i;
 											}
 											
 											if(tempHeaderList.get(i).size() > j) {
 												tempStr1= tempHeaderList.get(i).get(j);
 											}
 											if(tempHeaderList.size() != i + 1) {
 												if(tempHeaderList.get(i + 1).size() > j) {
 													tempStr2 = tempHeaderList.get(i + 1).get(j);
 												} else {
 													tempStr2 = "WISE_NULL_HEADER";
 												}
 											} else {
 												endMerge = i;
 											}
 											
 											if(!tempStr1.equals("WISE_NULL_HEADER") && (!tempStr1.equals(tempStr2) || endMerge == i)) {
 												endMerge = i;
 												if(endMerge != startMerge) {
 	 												sh.addMergedRegion(new CellRangeAddress(cell.getAddress().getRow(), cell.getAddress().getRow(), cell.getAddress().getColumn() - (endMerge - startMerge), cell.getAddress().getColumn()));
 												}
 											}
 										}
 										
 										if(tempHeaderList.get(i).size() > j) {
 											if(columnCaptionList.containsKey(tempHeaderList.get(i).get(j).toString())) {
												cell.setCellValue(columnCaptionList.get(tempHeaderList.get(i).get(j).toString()));
											}else if(headerCaptionNmMapper.containsKey(tempHeaderList.get(i).get(j).toString())){
 												cell.setCellValue(headerCaptionNmMapper.get(tempHeaderList.get(i).get(j).toString()));
 											}
										}
 									}
 									addRowNum ++;
 								}
 								addRowNum --;
 								dataItems2 = content.getJSONArray("dataItems2");
 							} else {
 								for (int i = 0; i < columns.size(); i++) {
 		 							
 		 							if (content.get("dataItems2") != null && itemType.equals("DATA_GRID")) {
 		 	 							dataItems2 = content.getJSONArray("dataItems2");
 		 	 							for (int k = 0; k < dataItems2.size(); k++) {	
 		 	 								JSONObject headJson = (JSONObject)dataItems2.get(k);
 		 	 								if (StringUtils.equals(columns.get(i).toString(), headJson.getString("dataField"))) {
 		 	 									Cell cell = heading.createCell(i);
 		 	 									cell.setCellStyle(bodyStyle);
 		 	 		 	 						cell.setCellValue(headJson.getString("caption"));
 		 	 									break;
 		 	 								}
 		 								}
 		 	 						}
 		 							else {
 		 								Cell cell = heading.createCell(i);
 		 								cell.setCellStyle(bodyStyle);
 		 	 	 						cell.setCellValue(columns.get(i).toString());
 		 							}
 		 	 						
 		 						}
 							}
 							
 	 					} else {
 	 						for (int i = 0; i < columns.size(); i++) {
 	 							
 	 							if (content.get("dataItems2") != null && itemType.equals("DATA_GRID")) {
 	 	 							dataItems2 = content.getJSONArray("dataItems2");
 	 	 							for (int k = 0; k < dataItems2.size(); k++) {	
 	 	 								JSONObject headJson = (JSONObject)dataItems2.get(k);
 	 	 								if (StringUtils.equals(columns.get(i).toString(), headJson.getString("dataField"))) {
 	 	 									Cell cell = heading.createCell(i);
 	 	 									cell.setCellStyle(bodyStyle);
 	 	 		 	 						cell.setCellValue(headJson.getString("caption"));
 	 	 									break;
 	 	 								}
 	 								}
 	 	 						}
 	 							else {
 	 								Cell cell = heading.createCell(i);
 	 								cell.setCellStyle(bodyStyle);
 	 	 	 						cell.setCellValue(columns.get(i).toString());
 	 							}
 	 	 						
 	 						}
 	 					}
 						

 						if(itemType.equals("PIVOT_GRID")) {
 							int j = 0;
 							for (Iterator<JSONObject> it = list.iterator(); it.hasNext(); j++) {
 								if (j >= EXCEL_DOWN_SIZE - 1) {
 									break;
 								}
 								Row row = sh.createRow(j + 1);
 								JSONObject item = it.next();
 								for (int i = 0; i < columns.size(); i++) {
 									if(i >= cols.size() + rows.size()) {
 										Cell cell = row.createCell(i);
 										cell.setCellStyle(bodyStyle);
 										String strColVal = item.getString(columns.get(i));
 										if (WINumberUtils.isNumber(strColVal)) {
 											cell.setCellValue(item.getDouble(columns.get(i)));
 										}
 										else {
 											cell.setCellValue(strColVal);
 										}
 										
 									} else {
 										row.createCell(i).setCellValue(item.getString(columns.get(i)));
 									}
 								}
 							}
 						} else {
 							ArrayList<Integer> tempList = new ArrayList<Integer>();
 							Row row = null;
 							JSONObject item = null;
 							JSONObject prevItem = null;
 							String strVal = "";
 							String prevVal = "";
 							CellStyle newCellStyle = null;
 							JSONArray measure = null;
 							int mergeColIdx = -1;
 							if (content.get("dataItems") != null) {
 								dataItems = content.getJSONObject("dataItems");
 								if(dataItems.has("Measure")) {
 									try {
 										measure = dataItems.getJSONArray("Measure");
 									} catch(JSONException e) {
 										JSONArray meaArray = new JSONArray();
 										meaArray.add(dataItems.getJSONObject("Measure"));
 										measure = meaArray;
 									}
 								}
 	 						}
 							
							for (int j = 0; j < dataItems2.size(); j++) {
								JSONObject dataItem2Object = (JSONObject) dataItems2.get(j);
								String colNm = "";
								String dataType = "";
								String dataformat = "";
								if(itemType.equals("PIVOT_GRID")) {
									colNm = columns.get(j);
								}else {
									if(columns.contains(dataItem2Object.get("dataField"))) {
										colNm = dataItem2Object.get("dataField").toString();
										dataType = dataItem2Object.get("dataType").toString();
										dataformat = dataItem2Object.get("format").toString();
									}
									 
								}
								if("".contains(colNm)) {
									break;
								}
								int i = 0;
								for (Iterator<JSONObject> it = list.iterator(); it.hasNext(); i++) {
	 								int nRowIdx = i + 1 + addRowNum;
	 								
	 								if (i == 0) {
	 									strVal = "";
	 		 							prevVal = "";
	 		 							prevItem = null;
	 								}
	 								
	 								if (j == 0)  {
	 									row = sh.createRow(nRowIdx);
	 								}
	 								else {
	 									row = sh.getRow(nRowIdx);
	 								}
	 								
	 								item = it.next();
	 								
	 								strVal = item.getString(colNm);
									if (i > 0) {
 										prevVal = prevItem.getString(colNm);
// 										if (i == 3 && j == 3) {
// 											String tempppp = "";
// 										}
 										if (!StringUtils.equals(strVal, prevVal)) {
 											//tempList.add(nRowIdx - 1 + "," + i);
 											final int tmpSize = tempList.size();
 											if (tmpSize > 0) {
 												//merge
												Integer nStart = Collections.min(tempList);
												//if (tmpSize == 1) {
													nStart = nStart - 1;
												//}
												//else {
												//	nStart = nStart - 2;		// merge에 사용하는 인덱스는 0부터 시작 이전로우(merge 시작 로우)는 -2임
												//}
												
												Integer nEnd = Collections.max(tempList);
					 							
 						 						// merge 정보 세팅
												final CellRangeAddress rangeAddr = new CellRangeAddress(nStart, nEnd, mergeColIdx, mergeColIdx);
				 	 							sh.addMergedRegion(rangeAddr);
				 	 							RegionUtil.setBorderTop(BorderStyle.THIN, rangeAddr, sh);
				 	 					        RegionUtil.setBorderBottom(BorderStyle.THIN, rangeAddr, sh);
				 	 					        RegionUtil.setBorderLeft(BorderStyle.THIN, rangeAddr, sh);
				 	 					        RegionUtil.setBorderRight(BorderStyle.THIN, rangeAddr, sh);
				 	 							tempList.clear();
				 	 							mergeColIdx = -1;
 						 					}
 										}
 										else {
 											if (StringUtils.isNotBlank(strVal) && "string".equals(dataType) && "".equals(dataformat)) {
// 												if (2401 == nRowIdx) {
// 													String sss = "";   // 이상함
// 												}
 												tempList.add(nRowIdx);
 												if (mergeColIdx == -1) {
 													mergeColIdx = j;
 												}
 											}
 										}
 									}
 									
 									if (WINumberUtils.isNumber(strVal) && !"string".equals(dataType) && !"".equals(dataformat)) {
 										if (measure != null) {
 											final int meaSize = measure.size();
 											final int headSize = dataItems2.size();
 											String format = getNumberFormatByMeasure(colNm, meaSize, measure, headSize, dataItems2);
 											Cell curCell = row.createCell(j);
 											
 											if (StringUtils.isNotBlank(format)) {
 												newCellStyle = curCell.getSheet().getWorkbook().createCellStyle();
 												newCellStyle.setBorderTop(BorderStyle.THIN);
 												newCellStyle.setBorderBottom(BorderStyle.THIN);
 												newCellStyle.setBorderLeft(BorderStyle.THIN);
 												newCellStyle.setBorderRight(BorderStyle.THIN);
 	 											DataFormat newDataFormat = curCell.getSheet().getWorkbook().createDataFormat();
 	 											newCellStyle.setDataFormat(newDataFormat.getFormat(format));
 	 											
 	 											// curCell.setCellType(CellType.NUMERIC);
 	 											curCell.setCellStyle(newCellStyle);
 	 										}

 											curCell.setCellValue(item.getDouble(colNm));
 											
 										}
 										else {
 											row.createCell(j).setCellValue(item.getDouble(colNm));
 											newCellStyle = row.getCell(j).getSheet().getWorkbook().createCellStyle();
 											newCellStyle.setBorderTop(BorderStyle.THIN);
 											newCellStyle.setBorderBottom(BorderStyle.THIN);
 											newCellStyle.setBorderLeft(BorderStyle.THIN);
 											newCellStyle.setBorderRight(BorderStyle.THIN);
 											row.getCell(j).setCellStyle(newCellStyle);
 										}
 										
 									}
 									else {
 										if(WINumberUtils.isNumber(strVal)) {
 											row.createCell(j).setCellValue(item.getDouble(colNm));
										}else {
											if("null".equals(strVal) && !"string".equals(dataType) && !"".equals(dataformat)) {
												final int meaSize = measure.size();
	 											final int headSize = dataItems2.size();
	 											String format = getNumberFormatByMeasure(colNm, meaSize, measure, headSize, dataItems2);
	 											Cell curCell = row.createCell(j);
	 											
	 											if (StringUtils.isNotBlank(format)) {
	 												newCellStyle = curCell.getSheet().getWorkbook().createCellStyle();
	 												newCellStyle.setBorderTop(BorderStyle.THIN);
	 												newCellStyle.setBorderBottom(BorderStyle.THIN);
	 												newCellStyle.setBorderLeft(BorderStyle.THIN);
	 												newCellStyle.setBorderRight(BorderStyle.THIN);
	 	 											DataFormat newDataFormat = curCell.getSheet().getWorkbook().createDataFormat();
	 	 											newCellStyle.setDataFormat(newDataFormat.getFormat(format));
	 	 											
	 	 											// curCell.setCellType(CellType.NUMERIC);
	 	 											curCell.setCellStyle(newCellStyle);
	 	 										}

	 											curCell.setCellValue(0);
											}else {
												row.createCell(j).setCellValue(strVal);
											}
											
										}
 										newCellStyle = row.getCell(j).getSheet().getWorkbook().createCellStyle();
 										newCellStyle.setBorderTop(BorderStyle.THIN);
 										newCellStyle.setBorderBottom(BorderStyle.THIN);
 										newCellStyle.setBorderLeft(BorderStyle.THIN);
 										newCellStyle.setBorderRight(BorderStyle.THIN);
 										row.getCell(j).setCellStyle(newCellStyle);
 									}
 									
 									if (!it.hasNext()) {
										//tempList.add(nRowIdx - 1 + "," + i);
										final int tmpSize = tempList.size();
										if (tmpSize > 0) {
											//merge
										Integer nStart = Collections.min(tempList);
										//if (tmpSize == 1) {
											nStart = nStart - 1;
										//}
										//else {
										//	nStart = nStart - 2;		// merge에 사용하는 인덱스는 0부터 시작 이전로우(merge 시작 로우)는 -2임
										//}
										
										Integer nEnd = Collections.max(tempList);
			 							
					 						// merge 정보 세팅
										final CellRangeAddress rangeAddr = new CellRangeAddress(nStart, nEnd, mergeColIdx, mergeColIdx);
		 	 							sh.addMergedRegion(rangeAddr);
		 	 							RegionUtil.setBorderTop(BorderStyle.THIN, rangeAddr, sh);
		 	 					        RegionUtil.setBorderBottom(BorderStyle.THIN, rangeAddr, sh);
		 	 					        RegionUtil.setBorderLeft(BorderStyle.THIN, rangeAddr, sh);
		 	 					        RegionUtil.setBorderRight(BorderStyle.THIN, rangeAddr, sh);
		 	 							tempList.clear();
		 	 							mergeColIdx = -1;
					 					}
									}

 									prevItem = item;
	 							}
							}
							
							sh.setFitToPage(true);
 						}
 					}

 					if(itemType.equals("PIVOT_GRID")) {
 						XSSFCellStyle style = wb.createCellStyle();
 						style.setBorderTop(BorderStyle.THIN);
 						style.setBorderBottom(BorderStyle.THIN);
 						style.setBorderLeft(BorderStyle.THIN);
 						style.setBorderRight(BorderStyle.THIN);
 						
 						String columnLetter = CellReference.convertNumToColString(columns.size()-1);
 						int nSize = list.size() + 1;
 						String pivotString = "A1:" + columnLetter + nSize;

 						AreaReference areaReference = new AreaReference(pivotString, SpreadsheetVersion.EXCEL2007);
 						/* 2020.12.18 mksong 주택금융공사 필터 조건 시트별 포함 dogfoot */
 						headerNo = addRowNum + 1;
 						XSSFPivotTable pivotTable = pivotSheet.createPivotTable(areaReference, new CellReference("A" + headerNo), sh);
 						
// 						int nLabelNum = 0;
// 						for(int i = 0; i < cols.size(); i++) {
// 							String lblCol = cols.getJSONObject(i).getString("name");
// 							if (!StringUtils.startsWithAny(lblCol, "H_", "S_")) {
// 								pivotTable.addColLabel(nLabelNum);
// 								nLabelNum++;
// 							}
// 						}
//
// 						nLabelNum = cols.size();
// 						for(int i = cols.size(); i < rows.size() + cols.size(); i++) {
// 							pivotTable.addRowLabel(i);
// 						}
 						
 						for(int i = 0; i < cols.size(); i++) {
 							pivotTable.addColLabel(i);
 						}

 						for(int i = cols.size(); i < rows.size() + cols.size(); i++) {
 							pivotTable.addRowLabel(i);
 						}

 						for(int i = cols.size() + rows.size(); i < columns.size(); i++) {
 							boolean IncludeGroupSeparator = false;
 							int Precision = 0;
 							for(int k = 0; k < mea.size(); k++) {
 								JSONObject meaK = mea.getJSONObject(k);
 								if(columns.get(i).equals(meaK.getString("Name"))) {
 									JSONObject numFormat = meaK.getJSONObject("NumericFormat");
 									if(numFormat.has("IncludeGroupSeparator")) {
 										IncludeGroupSeparator = numFormat.getBoolean("IncludeGroupSeparator");
 									}
 									if(numFormat.has("Precision")) {
 										Precision = numFormat.getInt("Precision");
 									}
 								}
 							}

 							String format = "0";
 							//if(IncludeGroupSeparator) {
 								format = "#,##0";
 								if(Precision > 0) {
 									format = format + ".";
 									for(int k = 0; k < Precision; k++) {
 										format = format + "0";
 									}
 								}
 							//}
 							if(Precision > 0) {
 								format = "0.";
 								for(int k = 0; k < Precision; k++) {
 									format = format + "0";
 								}
 							}
 							/* 2020.12.18 mksong 주택금융공사 정렬컬럼 피벗테이블 제외 dogfoot */
 							//if(i < (columns.size()-sortColumnCount)) {
 								pivotTable.addColumnLabel(DataConsolidateFunction.SUM, i, columns.get(i), format);
 							//}
 						}
// 						pivotTable.addDataColumn(2, false);
// 						pivotTable.addDataColumn(3, false); 
// 						pivotTable.getColLabelColumns().remove(columns.size()-1); 						
 						if(totalView.getBoolean("ShowColumnGrandTotals") == false) {
 							pivotTable.getCTPivotTableDefinition().setColGrandTotals(false);
 						}

 						if(totalView.getBoolean("ShowRowGrandTotals") == false) {
 							pivotTable.getCTPivotTableDefinition().setRowGrandTotals(false);
 						}
 						
 						// 빈셀표시 여부
 						pivotTable.getCTPivotTableDefinition().setShowEmptyCol(true);
 						
 						pivotTable.getCTPivotTableDefinition().setSubtotalHiddenItems(false);
 						for (CTPivotField ctPivotField : pivotTable.getCTPivotTableDefinition().getPivotFields().getPivotFieldList()) {
 							ctPivotField.setSubtotalTop(true);			// 서브토탈 위에 표시여부 처리
 							ctPivotField.setAutoShow(false);
 							ctPivotField.setOutline(false);
// 							ctPivotField.setSumSubtotal(false);
// 							ctPivotField.setProductSubtotal(false);
// 							ctPivotField.setDefaultSubtotal(false);
// 							ctPivotField.setSubtotalTop(false);
 						}
 						wb.setSheetHidden(wb.getNumberOfSheets() - 1, true);
 					}
 					break;
 				}
 			}
            workbook = new SXSSFWorkbook(wb); 
            workbook.setCompressTempFiles(true);
            
	        workbook.write(outByteStream);
            OutputStream os = response.getOutputStream();
            
            //2020.09.11 mksong 타이머 위치 오류 수정 dogfoot
            timer.stop();

 			Timestamp queryStartTimestamp = Timer.formatTime(timer.getStartTime());
 			Timestamp queryFinishTimestamp = Timer.formatTime(timer.getFinishTime());

 			logger.debug("sqlLike query start time: " + queryStartTimestamp + "(" + timer.getStartTime() + ")");
 			logger.debug("sqlLike query finish time: " + queryFinishTimestamp + "(" + timer.getFinishTime() + ")");
 			logger.debug("sqlLike query elapse time: " + timer.getInterval());
            
            returnobj.put("fileName", reportName + "." + downloadType);
			returnobj.put("filePath", path + "excel" + slash + reportName + "." + downloadType);
			
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (outByteStream != null) {
            	outByteStream.flush(); outByteStream.close();
            }
            if (wb != null) {
            	wb.close();
            }
            if (workbook != null) {
            	workbook.dispose(); workbook.close();
            }
        }       	
       	
 		return returnobj;
    }
	
	// 측정값에 설정된 포맷 가져오기
	private String getNumberFormatByMeasure(final String colNm, final int meaSize, final JSONArray measure, final int headSize, final JSONArray headInfo) {
		String retVal = "0";
		
		try {
			boolean includeGroupSeparator = false;
			int precision = 0;
			String meaNmUnique = "";
			String meaNmCaption = "";
			String formatType = "";
			for (int k = 0; k < headSize; k++) {
				JSONObject headJson = headInfo.getJSONObject(k);
				
				if(colNm.equals(headJson.getString("dataField"))) {
					meaNmUnique = headJson.getString("uniqueName");
					meaNmCaption = headJson.getString("caption");
					break;
				}
			}
			if (StringUtils.isNotBlank(meaNmCaption)) {
				for (int j = 0; j < meaSize; j++) {
					JSONObject meaJson = measure.getJSONObject(j);
					String uniqueName = meaJson.getString("UniqueName");
					String caption = meaJson.getString("Name");
					if (StringUtils.equals(meaNmUnique, uniqueName) && StringUtils.equals(meaNmCaption, caption)) {
						JSONObject numFormat = meaJson.getJSONObject("NumericFormat");
						if(numFormat.has("IncludeGroupSeparator")) {
							includeGroupSeparator = numFormat.getBoolean("IncludeGroupSeparator");
						}
						if(numFormat.has("Precision")) {
							precision = numFormat.getInt("Precision");
						}
						if (numFormat.has("FormatType")) {
							formatType = numFormat.getString("FormatType");
						}
						
						break;
					}
				}
			}
			
			if(includeGroupSeparator) {
				retVal = "#,##0";
				if(precision > 0) {
					retVal = retVal + ".";
					for(int k = 0; k < precision; k++) {
						retVal = retVal + "0";
					}
				}
			}
			if(precision > 0) {
				retVal = "0.";
				for(int k = 0; k < precision; k++) {
					retVal = retVal + "0";
				}
			}
			
			if (StringUtils.equals("Percent", formatType)) {
				retVal = retVal + "%";
			}
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
		return retVal;
	}
	
	public void testTraverseSummaryMatrix(SummaryMatrix matrix) throws Exception {
        final List<GroupParam> rowGroupParams = matrix.getRowGroupParams();
        final int maxRowGroupDepth = rowGroupParams.size();
        final List<GroupParam> colGroupParams = matrix.getColGroupParams();
        final int maxColGroupDepth = colGroupParams.size();
        final List<SummaryParam> summaryParams = matrix.getSummaryParams();
        final int summaryValueCount = summaryParams.size();
        final SummaryDimension[] rowFlattenedSummaryDimensions = matrix.getRowFlattendSummaryDimensions();
        final SummaryDimension[] colFlattenedSummaryDimensions = matrix.getColFlattendSummaryDimensions();
        final int rows = matrix.getRows();
        final int cols = matrix.getCols();
        final SummaryCell[][] summaryCells = matrix.getSummaryCells();

        StringWriter sw = new StringWriter(1024);
        PrintWriter out = new PrintWriter(sw);

        out.println("<HTML>");
        out.println("<HEAD>");
        out.println("<STYLE>");
        out.println("TD { text-align: right; }");
        out.println("</STYLE>");
        out.println("</HEAD>");
        out.println("<BODY>");
        out.println();

        out.println("<TABLE BORDER='1'>");

        out.println("  <THEAD>");

        for (int r = 0; r < maxColGroupDepth; r++) {
            out.println("    <TR>");

            if (r == 0) {
                final int colspan = maxRowGroupDepth;
                final int rowspan = maxColGroupDepth;

                out.print("      <TH");
                if (rowspan > 1) {
                    out.print(" rowspan='" + (rowspan + 1) + "'");
                }
                if (colspan > 1) {
                    out.print(" colspan='" + colspan + "'");
                }
                out.println("></TH>");

                out.print("      <TH");
                if (rowspan > 1) {
                    out.print(" rowspan='" + rowspan + "'");
                }
                out.println(">(TOTAL)</TH>");
            }

            for (int c = 1; c < cols; c++) {
                final SummaryDimension colDimension = colFlattenedSummaryDimensions[c];
                final int colDepth = colDimension.getDepth();

                if (r < maxColGroupDepth - 1) {
                    if (colDepth == r + 1) {
                        final AtomicInteger spanSizeCounter = new AtomicInteger();
                        countSummaryDimensionSpanningSize(spanSizeCounter, colDimension);
                        final int colspan = spanSizeCounter.intValue() * summaryValueCount;
                        out.print("      <TH");
                        if (colspan > 1) {
                            out.print(" colspan='" + colspan + "'");
                        }
                        out.print(">");
                        out.print(colDimension.getKey());
                        out.println("</TH>");
                    }
                }
                else {
                    out.print("      <TH>");
                    if (colDepth < r + 1) {
                        out.print("(TOTAL)");
                    }
                    else {
                        out.print(colDimension.getKey());
                    }
                    out.println("</TH>");
                }
            }

            out.println("    </TR>");
        }

        out.println("    <TR>");

        for (int c = 0; c < cols; c++) {
            final SummaryDimension colDimension = colFlattenedSummaryDimensions[c];
            for (int s = 0; s < summaryValueCount; s++) {
                final SummaryParam summaryParam = summaryParams.get(s);
                out.print("      <TH>");
                out.print(summaryParam.getSelector());
                out.println("</TH>");
            }
        }

        out.println("    </TR>");

        out.println("  </THEAD>");

        out.println("  <TBODY>");

        final Map<Integer, AtomicInteger> colRowSpanMap = new HashMap<>();
        for (int c = 0; c < maxRowGroupDepth; c++) {
            colRowSpanMap.put(c, new AtomicInteger());
        }

        for (int r = 0; r < rows; r++) {
            final SummaryDimension rowDimension = rowFlattenedSummaryDimensions[r];
            final int rowDepth = rowDimension.getDepth();

            out.println("    <TR>");

            if (r == 0) {
                final int colspan = maxRowGroupDepth;
                out.print("      <TH");
                out.print(" colspan='" + colspan + "'");
                out.println(">(TOTAL)</TH>");
            }
            else {
                for (int c = 0; c < maxRowGroupDepth; c++) {
                    if (c < maxRowGroupDepth - 1) {
                        final AtomicInteger preColRowSpan = colRowSpanMap.get(c);

                        if (preColRowSpan != null && preColRowSpan.get() > 1) {
                            preColRowSpan.decrementAndGet();
                        }
                        else {
                            final AtomicInteger colRowSpan = colRowSpanMap.get(c);
                            colRowSpan.set(0);
                            countSummaryDimensionSpanningSize(colRowSpan, rowDimension);
                            colRowSpanMap.put(c, colRowSpan);
                            final int rowspan = colRowSpan.intValue();
                            out.print("      <TH");
                            if (rowspan > 1) {
                                out.print(" rowspan='" + rowspan + "'");
                            }
                            out.print(">");
                            out.print(rowDimension.getKey());
                            out.println("</TH>");
                        }
                    }
                    else {
                        out.print("      <TH>");
                        if (rowDepth < c + 1) {
                            out.print("(TOTAL)");
                        }
                        else {
                            out.print(rowDimension.getKey());
                        }
                        out.println("</TH>");
                    }
                }
            }

            for (int c = 0; c < cols; c++) {
                final SummaryCell cell = summaryCells[r][c];
                final List<SummaryValue> summaryValues = cell.getSummaryValues();
                for (SummaryValue summaryValue : summaryValues) {
                    out.print("      <TD>");
                    out.print(summaryValue.getRepresentingValue());
                    out.println("</TD>");
                }
            }

            out.println("    </TR>");
        }

        out.println("  </TBODY>");

        out.println("</TABLE>");

        out.println();
        out.println("</BODY>");
        out.println("</HTML>");

        logger.debug("html table: \n{}", sw);
    }

    private static void countSummaryDimensionSpanningSize(final AtomicInteger counter, final SummaryDimension dimension) {
        if (dimension.hasChild()) {
            counter.addAndGet(dimension.getChildCount() + 1);

            for (SummaryDimension childDimension : dimension.getChildren()) {
                countSummaryDimensionSpanningSize(counter, childDimension);
            }
        }
    }
    
    private static void countSummaryDimensionChildWithoutLastDepth(final AtomicInteger counter, final SummaryDimension dimension, final int maxDepth) {
        if (dimension.hasChild() && dimension.getDepth() < maxDepth - 1) {
            counter.addAndGet(dimension.getChildCount());

            for (SummaryDimension childDimension : dimension.getChildren()) {
            	countSummaryDimensionChildWithoutLastDepth(counter, childDimension, maxDepth);
            }
        }
    }
    
    private void addBorderRegion(CellRangeAddress mergedRegion, XSSFSheet sheet) {
    	RegionUtil.setBorderTop(BorderStyle.THIN, mergedRegion, sheet);
        RegionUtil.setBorderBottom(BorderStyle.THIN, mergedRegion, sheet);
        RegionUtil.setBorderLeft(BorderStyle.THIN, mergedRegion, sheet);
        RegionUtil.setBorderRight(BorderStyle.THIN, mergedRegion, sheet);
    }
    
    private BigDecimal getExcelCellValue(SummaryValue summaryValue) {
        switch (summaryValue.getSummaryType()) {
        case COUNT:
            return BigDecimal.valueOf(summaryValue.getCount());
        case COUNTDISTINCT:
            return summaryValue.getDistinctValues() != null ? BigDecimal.valueOf(summaryValue.getDistinctValues().size()) : BigDecimal.valueOf(0);
        case SUM:
        case CUSTOM:
            return summaryValue.getSum() != null ? summaryValue.getSum() : BigDecimal.valueOf(0);
        case AVG:
        	return summaryValue.getValue() != null ? summaryValue.getValue() : summaryValue.getSum() != null ? summaryValue.getSum() : BigDecimal.valueOf(0);
        case MIN:
		case MAX:
			if(summaryValue.getValue().toString().equals("9223372036854776000")){
				return BigDecimal.valueOf(0);
		    }else {
		    	return summaryValue.getValue();
		    }
        default:
        	BigDecimal result = summaryValue.getValue() != null ? summaryValue.getValue() : BigDecimal.valueOf(0);
        	if(result.equals(0)) {
        		result = summaryValue.getSum() != null ? summaryValue.getSum() : BigDecimal.valueOf(0);
        	}
        	return result;
        }
    }
    
    private void removeRow(Sheet sheet, final int rowIndex, final int shiftCount) {
    	final int lastRowNum = sheet.getLastRowNum();
    	if(rowIndex >= 0 && rowIndex < lastRowNum) {
    		sheet.shiftRows(rowIndex + 1, lastRowNum, shiftCount);
    	}
    }
    
    private void mergedRegion(Sheet sheet, final CellRangeAddress mergedRegion) {
    	final int firstCol = mergedRegion.getFirstColumn();
    	final int lastCol = mergedRegion.getLastColumn();
    	final int firstRow = mergedRegion.getFirstRow();
    	final int lastRow = mergedRegion.getLastRow();
    	
    	try {
    		sheet.addMergedRegion(mergedRegion);
    	} catch(Exception e) {
    		logger.debug("셀 병합 실패 : 열 : " + firstCol + " ~ " + lastCol + ", 행 : " + firstRow + " ~ " + lastRow);
    	}
    }
    
}
