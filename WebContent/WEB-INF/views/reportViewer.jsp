<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.wise.context.config.Configurator"%>
<%@ page import="com.wise.common.util.BrowserUtils"%>
<%@ page import="com.wise.common.util.CoreUtils"%>
<%@ page import="com.wise.common.util.PageUtils"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%
	response.setHeader("Cache-Control","no-store"); 
	response.setHeader("Cache-Control", "no-cache"); 
    response.setHeader("Pragma", "no-cache");
    response.setHeader("P3P","CP='CAO PSA CONi OTR OUR DEM ONL'");
    response.setDateHeader("Expires", 0);
	String agent = BrowserUtils.getType(request);
	String dxVer = (agent.equals("IE10"))?Configurator.getInstance().getConfig("devextreme.ver.IE10"):Configurator.getInstance().getConfig("devextreme.ver");
	String resourceDebug = (Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.debug"))?".debug":"";
	String devVersion[] = dxVer.split("\\.");
	boolean dxTwety = (Integer.parseInt(devVersion[0])>=20);
	boolean minFile = Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.scriptcompress");
	boolean checkstatic = Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.staticwebscript");
%>
<c:set var="domain" value="<%=Configurator.getInstance().getFullDomain(request)%>" />
<c:set var="useShapeFile" value="<%=Configurator.getInstance().getConfigBooleanValue(\"WISE.libs.Dashboard.Config.widget.map.useShapeFile\")%>" />
<c:set var="visibleTitle" value="<%=Configurator.getInstance().getConfigBooleanValue(\"WISE.libs.Dashboard.report.title.visible\")%>" />
<c:choose>
	<c:when test="${visibleTitle}"><c:set var="visibleTitleStyle" value="" /></c:when>
	<c:otherwise><c:set var="visibleTitleStyle" value="remove-title" /></c:otherwise>
</c:choose>
<c:set var="globalizeVer" value="<%=Configurator.getInstance().getConfig(\"globalize.ver\")%>" />
<c:set var="dxVer" value="<%=dxVer%>" />
<c:set var="resourceDebug" value="<%=resourceDebug%>" />
<!doctype html>
<html lang="ko">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
		<meta http-equiv="Content-Script-Type" content="text/javascript">
		<meta http-equiv="Content-Style-Type" content="text/css">
		<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
		<meta name="apple-mobile-web-app-title" content="${mainTitle}" />
		<meta name="keywords" content="BIportal">
		<meta name="description" content="BIportal">
		<meta http-equiv="Expires" content="-1"> 
		<meta http-equiv="Pragma" content="no-cache"> 
		<meta http-equiv="Cache-Control" content="No-Cache"> 
		<sec:csrfMetaTags />
		<title>${mainTitle}</title>

		<link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
		
		 <%if(minFile){%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/style.min.css"/>
		
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.min.css" />
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.min.css" />
        <%if(dxTwety){%>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx-diagram.min.css" />
        <%}%>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/jquery/apprise-v2.css"/>    
        
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.dx.light-hack.min.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.progressbar.min.css"/>
		
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/scheduler.min.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-base.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-dark-theme.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-light-theme.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/viewstyle.min.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/spread.min.css" />
		<!-- DOGFOOT syjin customOverlay 스타일 추가  20200914 -->
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/customOverlay.min.css" />
		<%} else {%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/style.css"/>
		
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" />
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" />
        <%if(dxTwety){%>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx-diagram.min.css" />
        <%}%>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/jquery/apprise-v2.css"/>
        
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.dx.light-hack.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.progressbar.css"/>
		
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/scheduler.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-base.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-dark-theme.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-light-theme.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/viewstyle.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/spread.css" />
		<!-- DOGFOOT syjin customOverlay 스타일 추가  20200914 -->
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/customOverlay.css" />	
		<%}%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/x2js/xml2json.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-3.4.1.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.json-2.4.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.number.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.simplemodal.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.watermark.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/apprise-v2.js"></script>
		<!-- DOGFOOT syjin jquery resize 추가  20201119 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.resize.js"></script>
		<!-- DOGFOOT syjin 2020-11-27 geojson 파일 스크립트로 처리 -->
		<%-- <script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/sido.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/sigungu.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/eupmyeondong.js"></script> --%>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/cldr.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/event.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/supplemental.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/unresolved.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/globalize.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/message.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/number.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/date.min.js"></script> <!-- 반드시 number.min.js 이후에 로드 -->
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/currency.min.js"></script> <!-- 반드시 number.min.js 이후에 로드 -->
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/globalize.culture.ko.js"></script>    	
    
       <%--  <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/0.1.1/globalize.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/0.1.1/globalize.culture.ko.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/0.1.1/localization.ko.js"></script> --%>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/sqlike/SQLike.1.0.21.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/jszip/jszip.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/moment/moment.js"></script>
        
<%--         <script type="text/javascript" src="${pageContext.request.contextPath}/resources/underscore/underscore-1.8.3.js"></script> --%>
        
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/lodash/lodash.min.js"></script>
        
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/rgbcolor.js"></script> 
    	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/StackBlur.js"></script>
    	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/canvg.js"></script>
    	
		<%-- 이미지 다운로드 분기 처리 --%>
		<%if(agent.indexOf("IE")>-1){%>
    	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/html2canvas/html2canvas.js"></script>
    	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/html2canvas/html2canvas.svg.js"></script>
		<%} else {%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/html2canvas/html2canvas.1.0.0.rc5.js"></script>
		<%}%>
    	
    	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/Blob.js"></script>
    	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/canvas-toBlob.js"></script>
    	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/FileSaver.min.js"></script>
        
        <%if(dxTwety){%>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx-diagram.min.js"></script>
        <%}%>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx.all${resourceDebug}.js"></script>
        
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/es6-promise/es6-promise.auto.js"></script>        
        <!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
        <%if(minFile){%>
         <script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/menuConfig.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/fontConfig.min.js"></script>
        <!-- Core JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.js"></script>
		<!--	dogfoot web 서버 용 정적 파일 처리 shlim 20201124  -->
		<%if(checkstatic){%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.common.test.js?pid=${pid}"></script>
		<script>
			$.ajax({
				type : 'POST',
				async : false,
				url : '${pageContext.request.contextPath}/js/getConstants.do',
				contentType: false,
				processData: false,
				success : function(_data) {
					WISE.Constants.browser = _data.browser;
					WISE.Constants.context = _data.context;
					WISE.Constants.domain = _data.domain;
					WISE.Constants.pid = "${pid}"
				}
			});
		</script>
	
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.i18n.test.js"></script>
		<script>
			$.ajax({
				type : 'POST',
				async : false,
				url : '${pageContext.request.contextPath}/js/getI18n.do',
				contentType: false,
				processData: false,
				success : function(_data) {
					if(Object.keys(_data).length > 0){
						$.each(Object.keys(_data),function(_i,_key){
							WISE.i18n.message[_key] = _data[_key];
						})
					}
				}
			});
		</script>
		<%}else{%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.common.js?pid=${pid}"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.i18n.js"></script>	
		<%}%>

		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceFactory.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.DataSourceManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.QueryHandler.min.js"></script>
		
		<!-- Util JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.lang.message.js"></script>
	
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.prototype.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.Util.Array.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.Util.Number.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.Util.Object.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.Util.String.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.libs.Progressbar.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.Util.MessageHandler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.Util.SqlLikeQuery.min.js"></script>		
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.dx.ko.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.GoldenLayout.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.LayoutManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Download.min.js"></script>
		
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Utility.min.js"></script>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/backup_WISE.widget.DataSourceVariable.Related.min.js"></script> --%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.DataSourceVariable.Related.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.CalculatedField.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Conditions.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.DataGrid.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.PivotGrid.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Chart.min.js"></script>
		
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Chart.160224.01.js"></script> --%>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/tableExport.js"></script> --%>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/jquery.base64.js"></script> --%>
		
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/sprintf.js"></script> --%>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/jspdf.min.js"></script> --%>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/base64.js"></script> --%>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/html2pdf.js"></script> --%>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/png.js"></script> --%>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/zlib.js"></script> --%>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Pie.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Gauge.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Card.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.BubbleChart.min.js"></script>		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Map.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Map.GeoPoint.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Map.Choropleth.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Image.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Card.$.plugin.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.TreeView.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.ListBox.min.js"></script>
<%--  	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.RangeFilter.min.js"></script> --%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.ComboBox.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.TextBox.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.FieldFilter.min.js"></script>
<%-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.TreeMap.min.js"></script> --%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.HeatMap.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.HeatMap2.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CoordinateDot.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.SynchronizedChart.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.WordCloud.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Scheduler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.CustomFieldManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.CustomParameterHandler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.RectangularAreaChart.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.HistogramChart.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.WaterfallChart.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.BubbleD3.min.js"></script>
		
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Spreadsheet.min.js"></script>

		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetMaster.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetDesigner.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetDesignerSelector.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasourceSelector.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetNameEditor.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetQueryDesigner.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetTableDesigner.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetQueryTester.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetErdDesigner.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DatasetParameterEditor.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.TableColumnPicker.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.ParameterBar.min.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/create/WISE.widget.DataSet.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/create/WISE.widget.InsertItem.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/create/WISE.widget.ChangeReportType.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/create/WISE.widget.ReportUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Scheduler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Preferences.min.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/WISE.widget.custom.global.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/WISE.widget.custom.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/reportViewer.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/reportDesigner.min.js"></script>
		<%} else {%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/menuConfig.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/js/config/fontConfig.js"></script>
        <!-- Core JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.js"></script>
		<!--	dogfoot web 서버 용 정적 파일 처리 shlim 20201124  -->
		<%if(checkstatic){%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.common.test.js?pid=${pid}"></script>
		<script>
			$.ajax({
				type : 'POST',
				async : false,
				url : '${pageContext.request.contextPath}/js/getConstants.do',
				contentType: false,
				processData: false,
				success : function(_data) {
					WISE.Constants.browser = _data.browser;
					WISE.Constants.context = _data.context;
					WISE.Constants.domain = _data.domain;
					WISE.Constants.pid = "${pid}"
				}
			});
		</script>
	
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.i18n.test.js"></script>
		<script>
			$.ajax({
				type : 'POST',
				async : false,
				url : '${pageContext.request.contextPath}/js/getI18n.do',
				contentType: false,
				processData: false,
				success : function(_data) {
					if(Object.keys(_data).length > 0){
						$.each(Object.keys(_data),function(_i,_key){
							WISE.i18n.message[_key] = _data[_key];
						})
					}
				}
			});
		</script>
		<%}else{%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.common.js?pid=${pid}"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.i18n.js"></script>	
		<%}%>

		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceFactory.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.QueryHandler.js"></script>
		
		<!-- Util JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.lang.message.js"></script>
	
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.prototype.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.Util.Array.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.Util.Number.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.Util.Object.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.Util.String.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/util/WISE.libs.Progressbar.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.Util.MessageHandler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.Util.SqlLikeQuery.js"></script>		
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.dx.ko.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.GoldenLayout.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.LayoutManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Download.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.PivotUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Utility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/backup_WISE.widget.DataSourceVariable.Related.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.DataSourceVariable.Related.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.CalculatedField.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Conditions.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.DataGrid.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.PivotGrid.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Chart.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Chart.160224.01.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/tableExport.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/jquery.base64.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/sprintf.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/jspdf.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/base64.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/html2pdf.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/png.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/export/zlib.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Pie.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Gauge.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Card.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CoordinateLine.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.BubbleChart.js"></script>		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Map.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Map.GeoPoint.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Map.Choropleth.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Image.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Card.$.plugin.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.TreeView.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.ListBox.js"></script>
 		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.RangeFilter.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.ComboBox.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.TextBox.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.FieldFilter.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.TreeMap.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.HeatMap.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.HeatMap2.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CoordinateDot.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.SynchronizedChart.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.WordCloud.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Scheduler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.CustomFieldManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.CustomParameterHandler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.RectangularAreaChart.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.HistogramChart.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.WaterfallChart.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.BubbleD3.js"></script>
		
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Spreadsheet.js"></script>

		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetMaster.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetDesigner.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetDesignerSelector.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasourceSelector.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetNameEditor.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetQueryDesigner.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetTableDesigner.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetQueryTester.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetErdDesigner.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DatasetParameterEditor.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.TableColumnPicker.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.ParameterBar.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/create/WISE.widget.DataSet.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/create/WISE.widget.InsertItem.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/create/WISE.widget.ChangeReportType.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/create/WISE.widget.ReportUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Scheduler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Preferences.js"></script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.global.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/reportViewer.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/reportDesigner.js"></script>
		<%}%>
		
<%-- 	<c:if test="${useShapeFile == true}"> --%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-utils/dx.vectormaputils.js"></script>
<%-- 	</c:if> --%>
<%-- DOGFOOT ktkang KERIS 캐시 사용을 위해 timestamp 및 사용안하는 라이브러리 제거  20200205 --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/mapdata/south.korea.js"></script> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/base64/base64.js"></script> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/mapdata/TL_SCCO_CTPRVN.js"></script> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-data/world.js"></script> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-data/usa.js"></script> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-data/europe.js"></script> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-data/eurasia.js"></script> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-data/canada.js"></script> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-data/africa.js"></script> --%>
 		
 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/bootstrap-3.3.7-dist/js/bootstrap.min.js"></script>
 		<!-- 개발 hsshim 1209 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/goldenlayout/js/goldenlayout-custom.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/scripts.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/loadAnimation.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/math/math.min.js"></script>
		
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/d3.min.js" type="text/javascript"charset="utf-8"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/crossfilter.v1.min.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/d3.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/d3.geom.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/d3.layout.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/packages.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/d3.v3.min.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/json2.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/three.min.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/tween.min.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/highlight.min.js" type="text/javascript"charset="utf-8"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/TrackballControls.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/CSS3DRenderer.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/box.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/cubism.v1.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/bullet.js" type="text/javascript"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/d3.parsets.js" type="text/javascript"charset="utf-8"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/d3.v4.js" type="text/javascript"charset="utf-8"></script> --%>
<%-- 		<script src="${pageContext.request.contextPath}/resources/visual/d3.scale.chromatic.js" type="text/javascript"charset="utf-8"></script> --%>
 		
 		<script src="${pageContext.request.contextPath}/resources/visual/paletteValArea.js" type="text/javascript"></script>
 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.calender.js"></script>
 		
 		<script>
		  d3vCal = d3;
		  window.d3 = null;
		</script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.v3.js" charset="utf-8"></script>
		<script>
		  d3v3 = d3;
		  window.d3 = null;
		</script>
		
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.v5.min.js" charset="utf-8"></script>
		<script>
		  d3min = d3;
		  window.d3 = null;
		</script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.v3.min.js" charset="utf-8"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.v4.js" charset="utf-8"></script> 
 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.v4.min.js" charset="utf-8"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.scale.chromatic.js" charset="utf-8"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.layout.cloud.js" charset="utf-8"></script>
		<!-- 20201201 shlim 이분법 차트 오류 수정 DOGFOOT -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.3.0.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3-legend.min.js"></script>
		
		<!-- dxHtmlEdit -->
		<script src="${pageContext.request.contextPath}/resources/quill/1.3.6/quill.min.js" type="text/javascript" charset="utf-8"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/webtoolkit/webtoolkit.base64.js"></script>
		
	</head>

	<body class="body_bg">
    	<!-- top 시작 -->
    	<div class="cont_top ${visibleTitleStyle}">
        	<div id="report-title" class="cont_top_tit"></div>
        	<ul class="cont_top_bt">
            	<%-- <li><a href="#"><img src="${pageContext.request.contextPath}/images/top_bt_down.png" onMouseOver="this.src='${pageContext.request.contextPath}/images/top_bt_down_.png'" onMouseOut="this.src='${pageContext.request.contextPath}/images/top_bt_down.png'" alt="내려받기" title="내려받기"></a></li> 
                <li><a id="btn_print" href="#"><img src="${pageContext.request.contextPath}/images/top_bt_print.png" onMouseOver="this.src='${pageContext.request.contextPath}/images/top_bt_print_.png'" onMouseOut="this.src='${pageContext.request.contextPath}/images/top_bt_print.png'" alt="출력하기" title="출력하기"></a></li>--%>
                <%-- <li><a href="#"><img src="${pageContext.request.contextPath}/images/top_bt_linkdocu.png" onMouseOver="this.src='${pageContext.request.contextPath}/images/top_bt_linkdocu_.png'" onMouseOut="this.src='${pageContext.request.contextPath}/images/top_bt_linkdocu.png'" alt="연결보고서" title="연결보고서"></a></li>
                <li><a href="#"><img src="${pageContext.request.contextPath}/images/top_bt_discuss.png" onMouseOver="this.src='${pageContext.request.contextPath}/images/top_bt_discuss_.png'" onMouseOut="this.src='${pageContext.request.contextPath}/images/top_bt_discuss.png'" alt="토론" title="토론"></a></li> --%>
            </ul>
        </div>
        <!-- top 끝 -->
        
        <div class="cont_query"></div>
        <div id="cont_popup" class="cont_popup"></div>
		<article id="contentContainer" class="${visibleTitleStyle}">
		</article>
		
			<!-- 워터 마크 테스트 <div id="background">
			  <p id="bg-text">군사III급비밀</p>
			</div> -->
			
		<script>
			WISE.Constants.conditions = [<%= PageUtils.arrangeParameters(request)%>];
		</script>
		<script>
			var userObject = '${returnArr}';
			var userJsonObject = JSON.parse(userObject);
			var reportType = 'Viewer';
			var userAuthMode = '${userAuthMode}';
		</script>
	</body>
</html>
