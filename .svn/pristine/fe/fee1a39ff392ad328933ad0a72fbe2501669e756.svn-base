package com.wise.ds.download.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.lang.management.ManagementFactory;
import java.nio.charset.Charset;

import javax.servlet.http.HttpServletRequest;

import com.itextpdf.layout.element.Cell;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.PageSize;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.tool.xml.ElementList;
import com.itextpdf.tool.xml.XMLWorker;
import com.itextpdf.tool.xml.XMLWorkerFontProvider;
import com.itextpdf.tool.xml.XMLWorkerHelper;
import com.itextpdf.tool.xml.css.CssFile;
import com.itextpdf.tool.xml.css.StyleAttrCSSResolver;
import com.itextpdf.tool.xml.html.CssAppliers;
import com.itextpdf.tool.xml.html.CssAppliersImpl;
import com.itextpdf.tool.xml.html.Tags;
import com.itextpdf.tool.xml.parser.XMLParser;
import com.itextpdf.tool.xml.pipeline.css.CSSResolver;
import com.itextpdf.tool.xml.pipeline.css.CssResolverPipeline;
import com.itextpdf.tool.xml.pipeline.end.ElementHandlerPipeline;
import com.itextpdf.tool.xml.pipeline.html.HtmlPipeline;
import com.itextpdf.tool.xml.pipeline.html.HtmlPipelineContext;
import com.wise.context.config.Configurator;


public class ConvertHtml2PdfConverter {
	public String createPdf(String filename, String htmlStr, HttpServletRequest request) throws DocumentException, IOException {

		java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
		String path = "";
		String slash = "";
		 // HTML, 폰트 설정
        XMLWorkerFontProvider fontProvider = new XMLWorkerFontProvider(XMLWorkerFontProvider.DONTLOOKFORFONTS);
        boolean weblogicPath = Configurator.getInstance().getConfigBooleanValue("wise.ds.was.weblogic");

       
		if(osBean.getName().indexOf("Windows") != -1) {
			if(weblogicPath) {
	        	/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				 path = request.getSession(false).getServletContext().getRealPath("/")+"\\UploadFiles\\";
				 fontProvider.register(request.getSession(false).getServletContext().getRealPath("/")+"\\resources\\main\\fonts\\NanumSquareOTFRegular.ttf", "NanumSquare");
	        }else {
	        	path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles\\";
	        	fontProvider.register(request.getSession(false).getServletContext().getRealPath("/")+"resources\\main\\fonts\\NanumSquareOTFRegular.ttf", "NanumSquare");
	        }
			
			slash = "\\";
			
		}else {
			if(weblogicPath) {
	        	/*dogfoot shlim weblogic 클러스터 배포 시 아래 path 사용 해야함 (임시 작업) 20210203*/
				path = request.getSession(false).getServletContext().getRealPath("/")+"/UploadFiles/";
				fontProvider.register(request.getSession(false).getServletContext().getRealPath("/")+"/resources/main/fonts/NanumSquareOTFRegular.ttf", "NanumSquare");
	        }else {
	        	path = request.getSession(false).getServletContext().getRealPath("/")+"UploadFiles/";
	        	fontProvider.register(request.getSession(false).getServletContext().getRealPath("/")+"resources/main/fonts/NanumSquareOTFRegular.ttf", "NanumSquare");
	        }
			
			slash = "/";
			
		}
		
		String storePathString = path;

		// 서버 내 파일 주소
		String serverPath = path + "pdf"+slash;

		File saveFolder = new File(storePathString);

		// 경로가 없으면 생성한다.
		if (!saveFolder.exists() || saveFolder.isFile()) {
			saveFolder.mkdirs();
		}

//		// 용지 설정이 가능하다. 생략해도 무관
		Document document = new Document(PageSize.A4.rotate(), 0, 0, 20, 10);
		OutputStream outputstream = new FileOutputStream(filename);
//		Document document = new Document();
//
//		// 파일 확장자는 pdf
//		String realName = filename;
//
//		File pdfFile = new File(realName);
//
//		// 파일이 있으면 삭제(같은 이름으로 만들 때마다 새로 쓰기 위해서)
//		if (pdfFile.isFile()) {
//			pdfFile.delete();
//		}
//
//		// pdf를 만들기 시작한다.
//		PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(realName));
//
//		document.open();
//
//		XMLWorkerHelper helper = XMLWorkerHelper.getInstance();
//
//		// css파일
//		CSSResolver cssResolver = new StyleAttrCSSResolver();
//		CssFile cssFile = XMLWorkerHelper.getCSS(new FileInputStream(serverPath + "pdfdefault.css"));
//		cssResolver.addCss(cssFile);
//
//		XMLWorkerFontProvider fontProvider = new XMLWorkerFontProvider(XMLWorkerFontProvider.DONTLOOKFORFONTS);
//
//		// 매우매우 중요!!
//		// 반드시 해당 폰트가 경로내에 있어야한다.
//		// (폰트 존재하지 않을 시 pdf 생성 후 열리지 않는 에러 발생)
////		fontProvider.register(serverPath + "malgun.ttf", "MalgunGothic"); // MalgunGothic은 font-family용 alias
//		CssAppliers cssAppliers = new CssAppliersImpl(fontProvider);
//
//		HtmlPipelineContext htmlContext = new HtmlPipelineContext(cssAppliers);
//		htmlContext.setTagFactory(Tags.getHtmlTagProcessorFactory());
//
//		// html을 pdf로 변환시작
//		PdfWriterPipeline pdf = new PdfWriterPipeline(document, writer);
//		HtmlPipeline html = new HtmlPipeline(htmlContext, pdf);
//		CssResolverPipeline css = new CssResolverPipeline(cssResolver, html);
//
//		XMLWorker worker = new XMLWorker(css, true);
//		// 캐릭터 셋 설정
//		XMLParser xmlParser = new XMLParser(worker, Charset.forName("UTF-8"));
//
//		StringReader strReader = new StringReader(htmlStr);
//		xmlParser.parse(strReader);
//
//		document.close();
//		writer.close();
//
		// version 5
        // PdfWriter 생성
        PdfWriter.getInstance(document, outputstream);
         
        // Document 오픈
        document.open();
        
        // CSS
        CSSResolver cssResolver = new StyleAttrCSSResolver();
//        CssFile cssFile = XMLWorkerHelper.getInstance().getCSS(new FileInputStream(serverPath + "pdfdefault.css"));
//        cssResolver.addCss(cssFile);
             
        CssAppliers cssAppliers = new CssAppliersImpl(fontProvider);
         
        HtmlPipelineContext htmlContext = new HtmlPipelineContext(cssAppliers);
        htmlContext.setTagFactory(Tags.getHtmlTagProcessorFactory());
         
        // Pipelines
        ElementList elements = new ElementList();
        ElementHandlerPipeline end = new ElementHandlerPipeline(elements, null);
        HtmlPipeline html = new HtmlPipeline(htmlContext, end);
        CssResolverPipeline css = new CssResolverPipeline(cssResolver, html);
        
        XMLWorker worker = new XMLWorker(css, true);
        XMLParser xmlParser = new XMLParser(worker, Charset.forName("UTF-8"));
        
//        for (int i =0 ; i <= 1 ; i++) {
            // 폰트 설정에서 별칭으로 줬던 "MalgunGothic"을 html 안에 폰트로 지정한다.
            StringReader strReader;
            
            strReader = new StringReader(htmlStr);
            xmlParser.parse(strReader);
            PdfPTable table = new PdfPTable(1);
            PdfPCell cell = new PdfPCell();
            
            for (Element element : elements) {           	
                
                table.setSplitLate(true);
                table.setSplitRows(true);
                cell.addElement(element);
                
            }
            table.addCell(cell);
            document.add(table);
            document.newPage();
//        }
        
        document.close();
		
		return filename;
		
	}
}
