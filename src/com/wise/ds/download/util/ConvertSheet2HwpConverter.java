package com.wise.ds.download.util;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Formatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.examples.html.HSSFHtmlHelper;
import org.apache.poi.ss.examples.html.HtmlHelper;
import org.apache.poi.ss.examples.html.XSSFHtmlHelper;
import org.apache.poi.ss.format.CellFormat;
import org.apache.poi.ss.format.CellFormatResult;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.HorizontalAlignment;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.VerticalAlignment;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.apache.poi.util.IOUtils;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

/**
 * This example shows how to display a spreadsheet in HTML using the classes for
 * spreadsheet display.
 */
public class ConvertSheet2HwpConverter {
	private Workbook wb;
	private Appendable output;
	private boolean completeHTML;
	private Formatter out;
	private boolean gotBounds;
	private int firstColumn;
	private int endColumn;
	private HtmlHelper helper;
	
	private HashMap<String, String> imageMap = new HashMap<String, String>();

	private static final String DEFAULTS_CLASS = "excelDefaults";
	private static final String COL_HEAD_CLASS = "colHeader";
	private static final String ROW_HEAD_CLASS = "rowHeader";

	private static final Map<HorizontalAlignment, String> HALIGN = mapFor(HorizontalAlignment.LEFT, "left",
			HorizontalAlignment.CENTER, "center", HorizontalAlignment.RIGHT, "right", HorizontalAlignment.FILL, "left",
			HorizontalAlignment.JUSTIFY, "left", HorizontalAlignment.CENTER_SELECTION, "center");

	private static final Map<VerticalAlignment, String> VALIGN = mapFor(VerticalAlignment.BOTTOM, "bottom",
			VerticalAlignment.CENTER, "middle", VerticalAlignment.TOP, "top");

	private static final Map<BorderStyle, String> BORDER = mapFor(BorderStyle.DASH_DOT, "dashed 1pt",
			BorderStyle.DASH_DOT_DOT, "dashed 1pt", BorderStyle.DASHED, "dashed 1pt", BorderStyle.DOTTED, "dotted 1pt",
			BorderStyle.DOUBLE, "double 3pt", BorderStyle.HAIR, "solid 1px", BorderStyle.MEDIUM, "solid 2pt",
			BorderStyle.MEDIUM_DASH_DOT, "dashed 2pt", BorderStyle.MEDIUM_DASH_DOT_DOT, "dashed 2pt",
			BorderStyle.MEDIUM_DASHED, "dashed 2pt", BorderStyle.NONE, "none", BorderStyle.SLANTED_DASH_DOT,
			"dashed 2pt", BorderStyle.THICK, "solid 3pt", BorderStyle.THIN, "dashed 1pt");

	private static final int IDX_TABLE_WIDTH = -2;
	private static final int IDX_HEADER_COL_WIDTH = -1;

	@SuppressWarnings({ "unchecked" })
	private static <K, V> Map<K, V> mapFor(Object... mapping) {
		Map<K, V> map = new HashMap<>();
		for (int i = 0; i < mapping.length; i += 2) {
			map.put((K) mapping[i], (V) mapping[i + 1]);
		}
		return map;
	}

	/**
	 * Creates a new examples to HTML for the given workbook.
	 *
	 * @param wb
	 *            The workbook.
	 * @param output
	 *            Where the HTML output will be written.
	 *
	 * @return An object for converting the workbook to HTML.
	 */
	public void create(Workbook wb, Appendable output) {
		ToHtml(wb, output);
	}

	/**
	 * Creates a new examples to HTML for the given workbook. If the path ends with
	 * "<tt>.xlsx</tt>" an {@link XSSFWorkbook} will be used; otherwise this will
	 * use an {@link HSSFWorkbook}.
	 *
	 * @param path
	 *            The file that has the workbook.
	 * @param output
	 *            Where the HTML output will be written.
	 *
	 * @return An object for converting the workbook to HTML.
	 */
	public void create(String path, Appendable output) throws IOException {
		create(new FileInputStream(path), output);
	}

	/**
	 * Creates a new examples to HTML for the given workbook. This attempts to
	 * detect whether the input is XML (so it should create an {@link XSSFWorkbook}
	 * or not (so it should create an {@link HSSFWorkbook}).
	 *
	 * @param in
	 *            The input stream that has the workbook.
	 * @param output
	 *            Where the HTML output will be written.
	 *
	 * @return An object for converting the workbook to HTML.
	 */
	public void create(InputStream in, Appendable output) throws IOException {
		Workbook wb = WorkbookFactory.create(in);
		create(wb, output);
	}

	private void ToHtml(Workbook workbook, Appendable outputAppendable) {
	        if (workbook == null) {
	            throw new NullPointerException("wb");
	        }
	        if (outputAppendable == null) {
	            throw new NullPointerException("output");
	        }
	       this.wb = workbook;
	       this.output = outputAppendable;
	       setupColorMap();
	    }

	private void setupColorMap() {
		if (wb instanceof HSSFWorkbook) {
			helper = new HSSFHtmlHelper((HSSFWorkbook) wb);
		} else if (wb instanceof XSSFWorkbook) {
			helper = new XSSFHtmlHelper();
		} else {
			throw new IllegalArgumentException("unknown workbook type: " + wb.getClass().getSimpleName());
		}
	}

	/**
	 * Run this class as a program
	 *
	 * @param args
	 *            The command line arguments.
	 *
	 * @throws Exception
	 *             Exception we don't recover from.
	 */
	public void main(String[] args, HashMap<String, String> imageMap) {
		if (args.length < 2) {
//			System.err.println("usage: ToHtml inputWorkbook outputHtmlFile");
			return;
		}

		try (FileWriter fw = new FileWriter(args[1]); PrintWriter pw = new PrintWriter(fw)) {
			create(args[0], pw);
			this.setCompleteHTML(true);
			this.imageMap = new HashMap<>(imageMap);
			this.printPage();
		}catch (IOException e) {			
			e.printStackTrace();
			System.out.println("연결 예외 발생");
		}
	}

	public void setCompleteHTML(boolean completeHTML) {
		this.completeHTML = completeHTML;
	}

	public void printPage() throws IOException {
		try {
			ensureOut();
			if (completeHTML) {
				this.out.format("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>%n");
				this.out.format("<html>%n");
				this.out.format("<head>%n");
				this.out.format("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />%n");
				this.out.format("<meta charset=\"UTF-8\"/>%n");
				this.out.format("</head>%n");
				this.out.format("<body>%n");
			}

			print();

			if (completeHTML) {
				this.out.format("</body>%n");
				this.out.format("</html>%n");
			}
		} finally {
			IOUtils.closeQuietly(out);
			if (this.out instanceof Closeable) {
				IOUtils.closeQuietly((Closeable) output);
			}
		}
	}

	public void print() {
		printInlineStyle();
		printSheets();
	}

	private void printInlineStyle() {
//		this.out.format("<link href=\"excelStyle.css\" rel=\"stylesheet\" type=\"text/css\" />%n");
		this.out.format("<style type=\"text/css\">%n");
//		String style = ".colHeader{\r\n" + 
//				"			display : none;\r\n" + 
//				"		}\r\n" + 
//				"		.rowHeader{\r\n" + 
//				"			display : none;\r\n" + 
//				"		}\r\n" + 
//				"		td {\r\n" + 
//				"			border: solid 1px #e7e7e7 !important;\r\n" + 
//				"			padding: 0px;\r\n" + 
//				"		    background-image: linear-gradient(to bottom, #fafafa, #ececed);\r\n" + 
//				"		 }\r\n";
//		this.out.format(style);		
//		printStyles();
		this.out.format("</style>%n");
	}

	private void ensureOut() {
		if (this.out == null) {
			this.out = new Formatter(output);
		}
	}

	public void printStyles() {
		ensureOut();

		// First, copy the base css
//		try (BufferedReader in = new BufferedReader(
//				new InputStreamReader(getClass().getResourceAsStream("excelStyle.css")))) {
//			String line;
//			while ((line = in.readLine()) != null) {
//				out.format("%s%n", line);
//			}
//		} catch (IOException e) {
//			throw new IllegalStateException("Reading standard css", e);
//		}

		// now add css for each used style
		Set<CellStyle> seen = new HashSet<>();
		for (int i = 0; i < wb.getNumberOfSheets(); i++) {
			Sheet sheet = wb.getSheetAt(i);
			Iterator<Row> rows = sheet.rowIterator();
			while (rows.hasNext()) {
				Row row = rows.next();
				for (Cell cell : row) {
					CellStyle style = cell.getCellStyle();
					if (!seen.contains(style)) {
						printStyle(style);
						seen.add(style);
					}
				}
			}
		}
	}

	private void printStyle(CellStyle style) {
		this.out.format(".%s .%s {%n", DEFAULTS_CLASS, styleName(style));
		styleContents(style);
		this.out.format("}%n");
	}

	private void styleContents(CellStyle style) {
		styleOut("text-align", style.getAlignment(), HALIGN);
		styleOut("vertical-align", style.getVerticalAlignment(), VALIGN);
		fontStyle(style);
		borderStyles(style);
		helper.colorStyles(style, this.out);
	}

	private void borderStyles(CellStyle style) {
		styleOut("border-left", style.getBorderLeft(), BORDER);
		styleOut("border-right", style.getBorderRight(), BORDER);
		styleOut("border-top", style.getBorderTop(), BORDER);
		styleOut("border-bottom", style.getBorderBottom(), BORDER);
	}

	private void fontStyle(CellStyle style) {
		Font font = wb.getFontAt(style.getFontIndexAsInt());

		if (font.getBold()) {
			this.out.format("  font-weight: bold;%n");
		}
		if (font.getItalic()) {
			this.out.format("  font-style: italic;%n");
		}

		int fontheight = font.getFontHeightInPoints();
		if (fontheight == 9) {
			// fix for stupid ol Windows
			fontheight = 10;
		}
		this.out.format("  font-size: %dpt;%n", fontheight);

		// Font color is handled with the other colors
	}

	private String styleName(CellStyle style) {
		if (style == null) {
			style = wb.getCellStyleAt((short) 0);
		}
		StringBuilder sb = new StringBuilder();
		try (Formatter fmt = new Formatter(sb)) {
			fmt.format("style_%02x", style.getIndex());
			return fmt.toString();
		}
	}

	private <K> void styleOut(String attr, K key, Map<K, String> mapping) {
		String value = mapping.get(key);
		if (value != null) {
			this.out.format("  %s: %s;%n", attr, value);
		}
	}

	private static CellType ultimateCellType(Cell c) {
		CellType type = c.getCellType();
		if (type == CellType.FORMULA) {
			type = c.getCachedFormulaResultType();
		}
		return type;
	}

	private void printSheets() {
		ensureOut();
		for (int i = 0; i < wb.getNumberOfSheets(); i++) {
			Sheet sheet = wb.getSheetAt(i);
			printSheet(sheet);
			this.out.format("<br/><br/>");
		}
		
	}

	public void printSheet(Sheet sheet) {
		ensureOut();
//		System.out.println(sheet.getSheetName());
		Map<Integer, Integer> widths = computeWidths(sheet);
		this.out.format("<p style=\"width:100%%; font-size: 20px;\">" + sheet.getSheetName() + "</p>%n");
		int k = 0;
		Set set = this.imageMap.entrySet();
		Iterator iterator = set.iterator();

		try {
			while(iterator.hasNext()){
				Map.Entry entry = (Map.Entry)iterator.next();
				String key = (String)entry.getKey();
				String value = (String)entry.getValue();

				if(key.equals(sheet.getSheetName())) {
					k = 1;
					String uriEnc = this.imageMap.get("contextPath") + "/" + URLEncoder.encode(value, "UTF-8");
//					String uriEnc = this.imageMap.get("contextPath") + "/" + value;
					uriEnc = uriEnc.replaceAll("\\+", "%20");
//									uriEnc.replace("%", "%%");
					this.out.format("<img src=\"%s\" alt=\"\" />%n", uriEnc);
					break;
				}
			}
		} catch(UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		if(k == 0) {
			int tableWidth = widths.get(IDX_TABLE_WIDTH);
			this.out.format("<table class=%s style=\"width:%dpx;\">%n", DEFAULTS_CLASS, tableWidth);
			printCols(widths);
			printSheetContent(sheet);
			this.out.format("</table>%n");
		}
	}

	/**
	 * computes the column widths, defined by the sheet.
	 *
	 * @param sheet
	 *            The sheet for which to compute widths
	 * @return Map with key: column index; value: column width in pixels <br>
	 * 		special keys: <br>
	 * 		{@link #IDX_HEADER_COL_WIDTH} - width of the header column <br>
	 * 		{@link #IDX_TABLE_WIDTH} - width of the entire table
	 */
	private Map<Integer, Integer> computeWidths(Sheet sheet) {
		Map<Integer, Integer> ret = new TreeMap<>();
		int tableWidth = 0;
		gotBounds = false;
		ensureColumnBounds(sheet);

		// compute width of the header column
		int lastRowNum = sheet.getLastRowNum();
		int headerCharCount = String.valueOf(lastRowNum).length();
		int headerColWidth = widthToPixels((headerCharCount + 1) * 256.0) +10;
		ret.put(IDX_HEADER_COL_WIDTH, headerColWidth);
		tableWidth += headerColWidth;

		for (int i = firstColumn; i < endColumn; i++) {
			int colWidth = widthToPixels(sheet.getColumnWidth(i)) + 10;
			ret.put(i, colWidth);
			tableWidth += colWidth;
		}

		ret.put(IDX_TABLE_WIDTH, tableWidth);
		return ret;
	}

	/**
	 * Probably platform-specific, but appears to be a close approximation on some
	 * systems
	 * 
	 * @param widthUnits
	 *            POI's native width unit (twips)
	 * @return the approximate number of pixels for a typical display
	 */
	protected int widthToPixels(final double widthUnits) {
		return (int) (Math.round(widthUnits * 9 / 256));
	}

	private void printCols(Map<Integer, Integer> widths) {
//		int headerColWidth = widths.get(IDX_HEADER_COL_WIDTH);
//		this.out.format("<col style=\"width:%dpx;\"></col>%n", headerColWidth);
		for (int i = firstColumn; i < endColumn; i++) {
			int colWidth = widths.get(i);
			this.out.format("<col style=\"width:%dpx;\"></col>%n", colWidth);
		}
	}

	private void ensureColumnBounds(Sheet sheet) {
		if (gotBounds) {
			return;
		}

		Iterator<Row> iter = sheet.rowIterator();
		firstColumn = (iter.hasNext() ? Integer.MAX_VALUE : 0);
		endColumn = 0;
		while (iter.hasNext()) {
			Row row = iter.next();
			short firstCell = row.getFirstCellNum();
			if (firstCell >= 0) {
				firstColumn = Math.min(firstColumn, firstCell);
				endColumn = Math.max(endColumn, row.getLastCellNum());
			}
		}
		gotBounds = true;
	}

	private void printColumnHeads() {
		this.out.format("<thead>%n");
		this.out.format("  <tr class=%s>%n", COL_HEAD_CLASS);
		this.out.format("    <th class=%s>&#x25CA;</th>%n", COL_HEAD_CLASS);
		// noinspection UnusedDeclaration
//		StringBuilder colName = new StringBuilder();
//		for (int i = firstColumn; i < endColumn; i++) {
//			colName.setLength(0);
//			int cnum = i;
//			do {
//				colName.insert(0, (char) ('A' + cnum % 26));
//				cnum /= 26;
//			} while (cnum > 0);
//			this.out.format("    <th class=%s>%s</th>%n", COL_HEAD_CLASS, colName);
//		}
		this.out.format("  </tr>%n");
		this.out.format("</thead>%n");
	}

	private void printSheetContent(Sheet sheet) {
		printColumnHeads();

		this.out.format("<tbody>%n");
		Iterator<Row> rows = sheet.rowIterator();
		while (rows.hasNext()) {
			Row row = rows.next();
			
			short firstCell = row.getFirstCellNum();
			if (firstCell >= 0) {
				firstColumn = Math.min(firstColumn, firstCell);
				endColumn = Math.max(endColumn, row.getLastCellNum());
			}
			
			this.out.format("  <tr>%n");
			this.out.format("    <td class=%s style=\"border:solid 1px #333;\">%d</td>%n", ROW_HEAD_CLASS, row.getRowNum() + 1);
			for (int i = firstColumn; i < endColumn; i++) {
				String content = "&nbsp;";
				String attrs = "";
				CellStyle style = null;
				if (i >= row.getFirstCellNum() && i < row.getLastCellNum()) {
					Cell cell = row.getCell(i);
					if (cell != null) {
						style = cell.getCellStyle();
						attrs = tagStyle(cell, style);
						// Set the value that is rendered for the cell
						// also applies the format
						CellFormat cf = CellFormat.getInstance(style.getDataFormatString());
						CellFormatResult result = cf.apply(cell);
						content = result.text; // never null
						if (content.isEmpty()) {
							content = "&nbsp;";
						}
					}
				}
				this.out.format("    <td class=%s %s style=\"border:solid 1px #333; border-collapse:collapse;\">%s</td>%n", styleName(style), attrs, content);
			}
			this.out.format("  </tr>%n");
		}
		this.out.format("</tbody>%n");
	}

	private String tagStyle(Cell cell, CellStyle style) {
		if (style.getAlignment() == HorizontalAlignment.GENERAL) {
			switch (ultimateCellType(cell)) {
			case STRING:
				return "style=\"text-align: left;\"";
			case BOOLEAN:
			case ERROR:
				return "style=\"text-align: center;\"";
			case NUMERIC:
			default:
				// "right" is the default
				break;
			}
		}
		return "";
	}
}
