<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.wise.context.config.Configurator"%>
<%@ page import="com.wise.common.util.BrowserUtils"%>
<%@ page import="com.wise.common.util.CoreUtils"%>
<%@ page import="com.wise.common.util.PageUtils"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="s" uri="http://www.springframework.org/security/tags"%>
<%
	response.setHeader("Set-Cookie", "Test1=TestCookieValue1; Secure; SameSite=None");
	response.addHeader("Set-Cookie", "Test2=TestCookieValue2; Secure; SameSite=None");
	response.setHeader("Set-Cookie", "Test3=TestCookieValue3; Secure; SameSite=None");
	response.setHeader("Cache-Control","no-store"); 
	response.setHeader("Cache-Control", "no-cache"); 
    response.setHeader("Pragma", "no-cache");
    response.setHeader("P3P","CP='CAO PSA CONi OTR OUR DEM ONL'");
    response.setDateHeader("Expires", 0);
	String agent = BrowserUtils.getType(request);
	String dxVer = (agent.equals("IE10"))?Configurator.getInstance().getConfig("devextreme.ver.IE10"):Configurator.getInstance().getConfig("devextreme.ver");
	String resourceDebug = (Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.debug"))?".debug":"";
	String companyname = Configurator.getInstance().getConfig("wise.ds.solution.companyname") != null ? Configurator.getInstance().getConfig("wise.ds.solution.companyname"):"";
	String devVersion[] = dxVer.split("\\.");
	boolean dxTwety = (Integer.parseInt(devVersion[0])>=20);
	boolean minFile = Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.scriptcompress");
	//2020.11.04 mksong 로컬에서는  item js 정적 import 하도록 수정 dogfoot
	boolean dynamicImportCheck = Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.dynamicimport");
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
<c:set var="companyname" value="<%=companyname%>" />
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
		<s:csrfMetaTags/>
		
		<title>${mainTitle}</title>
		
		<link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
				<%-- DOGFOOT ktkang KERIS 캐시 사용을 위해 timestamp 및 사용안하는 라이브러리 제거  20200205 --%>
		<%if(minFile){%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/style.min.css"/>
		<%-- DOGFOOT hsshim 2020-01-15 디자인 수정사항 반영위해 alert.js 이용 --%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.min.css" />
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.min.css" />
        <%if(dxTwety){%>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx-diagram.min.css" />
        <%}%>
        
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.dx.light-hack.min.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.progressbar.min.css"/>
		
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/scheduler.min.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-base.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-dark-theme.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-light-theme.css" />
		<!-- 2019.12.16 수정자 : mksong 뷰어 spectrum 추가 dogfoot -->
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/spectrum/spectrum.min.css" />
		
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/viewstyle.min.css" />
<%-- 		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/spread.css" /> --%>
		<!-- DOGFOOT syjin customOverlay 스타일 추가  20200914 -->
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/customOverlay.min.css" />
		<%} else {%>
				<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/style.css"/>
		<%-- DOGFOOT hsshim 2020-01-15 디자인 수정사항 반영위해 alert.js 이용 --%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" />
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" />
        <%if(dxTwety){%>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx-diagram.min.css" />
        <%}%>
        
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.dx.light-hack.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.progressbar.css"/>
		
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/scheduler.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-base.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-dark-theme.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-light-theme.css" />
		<!-- 2019.12.16 수정자 : mksong 뷰어 spectrum 추가 dogfoot -->
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/spectrum/spectrum.min.css" />
		
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/viewstyle.css" />
<%-- 		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.css" /> --%>
<%-- 		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/spread.css" /> --%>
		<!-- DOGFOOT syjin customOverlay 스타일 추가  20200914 -->
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/customOverlay.css" />
		<%}%>
		

		
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/x2js/xml2json.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-3.4.1.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-ui.min.js"></script>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/jquery.scrollbar.js"></script>
 --%>		
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.json-2.4.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.number.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.ui.touch-punch.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.simplemodal.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.watermark.js"></script>
		<!-- DOGFOOT syjin jquery resize 추가  20201119 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.resize.js"></script>
		
		<%-- DOGFOOT hsshim 2020-01-15 디자인 수정사항 반영위해 alert.js 이용 --%>
		<!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
		<%if(minFile){%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/alert.min.js"></script>
		<%} else {%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/alert.js"></script>
		<%}%>		
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
        <!-- DOGFOOT hsshim 2020-02-06 마스터 필터 속도 개선 -->
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/crossfilter-1.4.8/crossfilter.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/jszip/jszip.min.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/moment/moment.js"></script>
        
        <!-- 2020.11.10 mksong 동적로딩 d3 다운로드 오류 수정 -->
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/Blob.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/canvas-toBlob.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/FileSaver.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvas2image/canvas2image.min.js"></script>
		
        <!-- 2020.11.10 mksong 동적로딩 d3 다운로드 오류 수정 -->
		<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/rgbcolor.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/StackBlur.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/canvg.min.js"></script> -->
        
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/underscore/underscore-1.8.3.js"></script>
        
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/lodash/lodash.min.js"></script>
        
        <%if(dxTwety){%>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx-diagram.min.js"></script>
        <%}%>
        <script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx.all${resourceDebug}.js"></script>
        
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/es6-promise/es6-promise.auto.min.js"></script>        
        
        <!-- DOGFOOT MKSONG 200219 panelResizer위해 추가 -->
        <!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
         <%if(minFile){%>
        <!-- Core JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.min.js"></script>
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
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.resources.dx.js"></script>
	
		<!-- Core libs JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.ConditionItem.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DummyDxItem.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceFactory.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.DataSourceManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.QueryHandler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.FieldFilter.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.GoldenLayoutManager.min.js"></script>
		<!-- dogfoot shlim 보고서 레이아웃 파일 추가 20200820 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.ReportLayoutManager.min.js"></script>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.ParameterHandler.min.js"></script> --%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.ParameterQueryHandler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.util.WindowSet.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.FontManager.min.js"></script>
		
		<!-- Core libs util JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.item.ChartUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.item.DataCubeUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.item.DataGridUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.item.DatasetUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.item.DataUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.item.ItemUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.item.PieChartUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.util.PanelResizer.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/util/WISE.libs.Dashboard.util.QueryUtility.min.js"></script>
		
		<!-- Core widget JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/widget/WISE.widget.main.js"></script>
		
		<!-- Core widget condition JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/widget/condition/WISE.widget.Condition.Validator.js"></script>
		
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
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.dx.ko.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.LayoutManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Download.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.CalculatedField.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.CustomFieldManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.CustomParameterHandler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Scheduler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Preferences.min.js"></script>
			
		<!-- Item JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.ItemManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.ItemColorManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.InsertItem.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.ItemFactory.min.js"></script>
		
		<!-- DOGFOOT mksong 2020-08-10 D3MANAGER 추가 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.D3Manager.min.js"></script>
		
		
		<!-- Item FieldChooser JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/fieldchooser/WISE.widget.DragNDropController.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/fieldchooser/WISE.widget.FieldChooserController.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/fieldchooser/WISE.widget.FieldChooserManager.js"></script>
		
		<!-- Item Util JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/util/WISE.widget.Util.FunctionButton.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/util/WISE.widget.Util.FunctionButtonDivider.js"></script>
		
		<!-- DataSet JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.DataSet.min.js"></script>
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
				
		<!-- Report JS -->	
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/report/WISE.widget.ChangeReportType.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/report/WISE.libs.Dashboard.item.ReportUtility.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/report/WISE.libs.Dashboard.item.AdHocReportUtility.min.js"></script>			
			
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/menuConfig.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/fontConfig.min.js"></script>
<!-- 
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.FieldFilter.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.CustomFieldManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Preferences.min.js"></script>
-->		

		<!-- DOGFOOT hsshim 200103 뷰어 스프레드 기능 적용 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Spreadsheet.min.js"></script>
	
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.global.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/WISE.widget.custom.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/reportViewer.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/resize.min.js"></script>
		
		<!-- 2020.11.04 mksong 로컬에서는  item js 정적 import 하도록 수정 dogfoot -->
	<% if(!dynamicImportCheck){%>
		<!-- Item Detail JS -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.DataGrid.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.PivotGrid.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Chart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Pie.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Gauge.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Card.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CoordinateLine.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Map.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Map.GeoPoint.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Map.Choropleth.min.js"></script>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/paletteValArea.js"></script>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.calender.js"></script>
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
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.layout.cloud.js" charset="utf-8"></script> -->
	
<!-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-selection.v1.min.js" charset="utf-8"></script> -->
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-collection.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-array.v2.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-path.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-shape.v1.min.js" charset="utf-8"></script> -->
<!-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-tip.js" charset="utf-8"></script> -->
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-sankey.js" charset="utf-8"></script>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.css" />
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/saveSvgAsPng.js" charset="utf-8"></script>

	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.3.0.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3-legend.min.js"></script> -->

	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Image.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Card.$.plugin.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.TreeView.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ListBox.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ComboBox.min.js"></script> 
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.TextBox.min.js"></script>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.TreeMap.min.js"></script>-->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.StarChart.min.js"></script>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.HeatMap.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.HeatMap2.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CoordinateDot.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.SynchronizedChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.WordCloud.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ParallelCoordinate.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.RectangularAreaChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.HistogramChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.WaterfallChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.BubbleD3.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.BubbleChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.BipartiteChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.FunnelChart.min.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.PyramidChart.min.js"></script>		
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.SankeyChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.DivergingChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.DependencyWheel.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.SequencesSunburst.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.BoxPlot.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ScatterPlot.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ScatterPlot2.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.RadialTidyTree.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ScatterPlotMatrix.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.HistoryTimeline.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ArcDiagram.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.LiquidFillGauge.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ForceDirect.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ForceDirectExpand.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.HierarchicalEdge.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.RangeBar.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.RangeAreaChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.TimeLineChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.BubblePackChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CalendarView.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CalendarView2.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CalendarView3.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CollapsibleTree.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.DendrogramBarChart.min.js"></script> -->
	
	<%} %>
     	<%} else {%>
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
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.resources.dx.js"></script>
	
		<!-- Core libs JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.ConditionItem.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DummyDxItem.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceFactory.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.QueryHandler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.FieldFilter.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.GoldenLayoutManager.js"></script>
		<!-- dogfoot shlim 보고서 레이아웃 파일 추가 20200820 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.ReportLayoutManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.ParameterHandler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.ParameterQueryHandler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.util.WindowSet.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.FontManager.js"></script>
		
		<!-- Core libs util JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.ChartUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.PivotUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.DataCubeUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.DataGridUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.DatasetUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.DataUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.ItemUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.item.PieChartUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.util.PanelResizer.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/util/WISE.libs.Dashboard.util.QueryUtility.js"></script>
		
		<!-- Core widget JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/widget/WISE.widget.main.js"></script>
		
		<!-- Core widget condition JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/widget/condition/WISE.widget.Condition.Validator.js"></script>
		
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
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.LayoutManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Download.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.CalculatedField.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.CustomFieldManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.CustomParameterHandler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Scheduler.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Preferences.js"></script>
			
		<!-- Item JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/WISE.widget.ItemManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/WISE.widget.ItemColorManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/WISE.widget.InsertItem.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/WISE.widget.ItemFactory.js"></script>
		
		<!-- DOGFOOT mksong 2020-08-10 D3MANAGER 추가 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/WISE.widget.D3Manager.js"></script>
		
		
		<!-- Item FieldChooser JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/fieldchooser/WISE.widget.DragNDropController.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/fieldchooser/WISE.widget.FieldChooserController.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/fieldchooser/WISE.widget.FieldChooserManager.js"></script>
		
		<!-- Item Util JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/util/WISE.widget.Util.FunctionButton.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/util/WISE.widget.Util.FunctionButtonDivider.js"></script>
		
		<!-- DataSet JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.DataSet.js"></script>
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
				
		<!-- Report JS -->	
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/report/WISE.widget.ChangeReportType.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/report/WISE.libs.Dashboard.item.ReportUtility.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/report/WISE.libs.Dashboard.item.AdHocReportUtility.js"></script>			
			
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/menuConfig.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/fontConfig.js"></script>
 		<!--
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.FieldFilter.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.CustomFieldManager.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Preferences.js"></script>
		-->
	

		<!-- DOGFOOT hsshim 200103 뷰어 스프레드 기능 적용 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Spreadsheet.js"></script>
	
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.global.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/reportViewer.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/resize.js"></script>
		
		<!-- 2020.11.04 mksong 로컬에서는  item js 정적 import 하도록 수정 dogfoot -->
	<% if(!dynamicImportCheck){%>
		<!-- Item Detail JS -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.DataGrid.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.PivotGrid.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Chart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Pie.js"></script>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Gauge.js"></script> -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Card.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CoordinateLine.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Map.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Map.GeoPoint.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Map.Choropleth.js"></script>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/paletteValArea.js"></script>
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
	
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-collection.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-array.v2.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-path.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-shape.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-sankey.js" charset="utf-8"></script>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.css" />
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.js" charset="utf-8"></script> -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/saveSvgAsPng.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.3.0.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3-legend.min.js"></script>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Image.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Card.$.plugin.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.TreeView.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ListBox.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ComboBox.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.TextBox.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.TreeMap.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.StarChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.HeatMap.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.HeatMap2.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CoordinateDot.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.SynchronizedChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.WordCloud.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ParallelCoordinate.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.RectangularAreaChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.HistogramChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.WaterfallChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.BubbleD3.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.BubbleChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.BipartiteChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ScatterPlot2.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.LiquidFillGauge.js"></script>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.FunnelChart.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.PyramidChart.js"></script>		
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.SankeyChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.DivergingChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.DependencyWheel.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.SequencesSunburst.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.BoxPlot.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ScatterPlot.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ScatterPlot2.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.RadialTidyTree.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ScatterPlotMatrix.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.HistoryTimeline.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ArcDiagram.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.LiquidFillGauge.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ForceDirect.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ForceDirectExpand.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.HierarchicalEdge.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.RangeBar.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.RangeAreaChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.TimeLineChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.BubblePackChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CalendarView.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CalendarView2.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CalendarView3.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CollapsibleTree.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.DendrogramBarChart.js"></script> -->
	
	<%} %>
		<%}%>
		
<%-- 	<c:if test="${useShapeFile == true}"> --%>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-utils/dx.vectormaputils.js"></script> --%>
<%-- 	</c:if> --%>
<%--  		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/mapdata/south.korea.js"></script> --%>
 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/base64/base64.js"></script>
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
		
		<!-- 2019.12.16 수정자 : mksong 뷰어 spectrum 추가 dogfoot -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/spectrum/spectrum.js"></script>
		
		<!-- dxHtmlEdit -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/quill/1.3.6/quill.min.js" charset="utf-8"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/webtoolkit/webtoolkit.base64.min.js"></script>
	
		<!-- DOGFOOT mksong 2020-12-11 kakaoMapApi 라이센스 없는 경우 연동 x -->
		<%--<c:if test="${kakaoMapApi ne null and kakaoMapApi != '' }">
 			<script type="text/javascript" src="//dapi.kakao.com/v2/maps/sdk.js?appkey=${kakaoMapApi}&libraries=services,clusterer,drawing"></script> 
		</c:if>--%>
		<!-- DOGFOOT syjin 2020-11-27 geojson 파일 스크립트로 처리 -->
		<%-- <script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/sido.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/sigungu.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/eupmyeondong.js"></script> --%>
		<ul id="singleView_layout" class="more-link left-type" style="left: 10px; z-index:1501;">
			<li><a id="changeLayoutC" class="changeLayout" >차트만 보기</a></li>
			<li><a id="changeLayoutG" class="changeLayout" >그리드만 보기</a></li>
			<li><a id="changeLayoutCG" class="changeLayout" >차트와 그리드 동시에 보기</a></li>
		</ul>
	</head>

	<body class="body_bg" oncontextmenu="return false;">
		<form action="${pageContext.request.contextPath}/download/downloadFile.do" id="downForm" method="post">
        	<input type="hidden" id="downFileName" name="fileName" value="">
        	<input type="hidden" id="downFilePath" name="filePath" value="">
        	<s:csrfInput/>
	    </form>
	    <form action="${pageContext.request.contextPath}/report/excelEdit.do" target="_blank" id="excelForm" method="post">
        	<input type="hidden" id="reportId_excel" name="pid" value="">
        	<s:csrfInput/>
    	</form>
    	<!-- 20200217 MKSONG KERIS 뷰어에서 디자이너로 레포트 이동 DOGFOOT -->
    	 <form action="${pageContext.request.contextPath}/report/edit.do" target="_blank" id="editForm" method="post">
        	<input type="hidden" id="reportId" name="reportId" value="">
        	<!-- 20200219 MKSONG KERIS CUBEID 전송 추가 DOGFOOT -->
        	<input type="hidden" id="cubeId" name="cubeId" value="">
        	<s:csrfInput/>
    	</form>
	    <input type='hidden' id='linkParam' value='${linkParam}'/>
	
    	<!-- top 시작 -->
    	<div id="wrap" class="viewer">
			<header>
			    <div class="header-container"></div>
			</header>
	
		    <div id="cont_popup"></div>
		    <div id="export_popover"></div>
    		<!-- 2019.12.16 수정자 : mksong 뷰어 popup, popover 추가 dogfoot -->
		    <div id="editPopup"></div>
		    <div id="editPopover"></div>
		    <div id="editPopup2"></div>
		    <div id="editPopover2"></div>
		    <div id="seriesOptions"></div>
		    <div id="dl_popover" style="display: none;"></div>
		</div>
	<div id="container">
		<div class="container-inner">
			<section class="content">
				<div class="panel-tab">
					<!-- 1203 뷰어 UI변경에 따른 마크업 변경 -->
					<div class="viewr-ui-option">
						<a href="#" class="tree-view on">트리 목록 보기</a>
						<!-- 2019.12.24 수정자 : mksong 뷰어 데이터뷰 비정형일 때만 보이도록 수정 dogfoot -->
						<a href="#" class="data-view" style="display: none;" title="데이터 속성 목록 보기">데이터 속성 목록
							보기 </a>
					</div>
					<!-- 2019.12.26 mksong 트리 높이 수정 dogfoot -->
					<div id="treeopen" class="tree-area" style="height: 96%;z-index:5;">
						<div class="reportListArea on">
							<div class="panel tree active viewer1">
							<!-- DOGFOOT ajkim 리스트 너비 변경 버튼 추가  20200508  -->
								<button id="splitter3" class="btn-drag" type="button">Drag</button>
							<!-- DOGFOOT ktkang 개인보고서 추가  20200107  -->
								<div class="tab-title rowColumn">
									<ul class="col-2">
										<li rel="panelReportA-1"><a href="#">공용보고서</a></li>
										<li rel="panelReportA-2"><a href="#">개인보고서</a></li>
									</ul>
								</div>
								<div class="filter-gui">
									<div class="filter-col ui">
										<!-- DOGFOOT ktkang 보고서 새로고침 위치 수정  20200130 -->
										<div id="refreshFolderList" style="position: absolute; top: -38px">
											<a href="#" class="gui refresh" title="검색창 초기화">refresh</a>
										</div>
									</div>
								</div>
								<div class="panel-inner"
									style="overflow-y: visible !important">
									<!-- 2020.01.16 수정자 : mksong 보고서 목록 높이 수정 dogfoot -->
									<div id="panelReportA" class="tab-component" style="height:100%;">
										<div class="panelReportA-1 tab-content" style="height:100%">
											<div id="reportList"></div>
										</div>
										<div class="panelReportA-2 tab-content" style="display: none;">
											<div id="userReportList"></div>
										</div>
									</div>
								</div>
							</div>
						</div>
						<!-- 						2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT -->
						<div class="dataAttrArea"></div>
						<!-- 						수정 끝 -->
					</div>
					<!-- DOGFOOT ktkang 뷰어에서 주제영역 필터 추가 가능하도록 수정 20200705 -->
					<div id="filter-bar" class="filter-bar viewer">
						<div id="filter-row" class="filter-row">
							<div class="filter-gui">
								<div class="filter-col ui">
									<a class="filter-more" title="필터표시">필터펼치기</a>
								</div>
							</div>
						</div>
						<div id="calcParamButton" style="display: none;top: 0px;position: absolute;right: 50px;"></div>
						<span title="조회"><a id="btn_query" class="global-lookup search" title="조회">lookup</a></span>
<!-- 						<ul id="singleView_layout" class="more-link left-type" style="left: 10px; z-index:1501;"> -->
<!-- 						<li><a id="changeLayoutC" class="changeLayout" href="#">차트만 보기</a></li> -->
<!-- 						<li><a id="changeLayoutG" class="changeLayout" href="#">그리드만 보기</a></li> -->
<!-- 						<li><a id="changeLayoutCG" class="changeLayout" href="#">차트와 그리드 동시에 보기</a></li> -->
<!-- 						</ul> -->
					<!-- 	<a id="viewerDownload" class="btn_query_custom other-menu-ico util-gui global-lookup download viewerDownload" style="display: none; right: 54px;" title="다운로드"></a>
						<a id="viewerAdhoc" class="arrow btn_query_custom other-menu-ico util-gui atypical-layout global-lookup viewerAdhoc" style="display: none; right: 89px;" title="비정형 레이아웃"></a> -->
						<!--행안부자원봉사조회이미지-->
						<!--<a id="btn_query" href="#" style="width: 75px;height: 25px;position: absolute;right: 20px;top: 0;bottom: 0;margin: auto;"><img src="${pageContext.request.contextPath}/images/search.png"></a>-->
					</div>
					<div id="reportContainer" class="tab-component"></div>
					<!-- 2019.12.16 수정자 : mksong 뷰어 spectrum 추가 dogfoot -->
				</div>
			</section>
		</div>
	</div>

	<!--     	<div id="contentContainer"></div> -->
		<script>
			//2020.11.03 mksong 카카오맵 동적 import 추가 dogfoot
			//2020.11.03 mksong 동적 import 압축파일 구분 dogfoot
			WISE.Constants.minFile = <%= minFile %>;
			WISE.Constants.kakaoApi = '${kakaoMapApi}';
			WISE.Constants.conditions = [
		<%=PageUtils.arrangeParameters(request)%>
			];
			WISE.Constants.editmode = 'viewer';
			// 			2019.12.26 mksong 뷰어 골든레이아웃 또는 기존 레이아웃 구분 SwitchLayout dogfoot 
			WISE.Constants.layoutType = 'goldenlayout';
			if('${companyname}' != undefined && '${companyname}' != ""){
				WISE.Constants.companyname = '${companyname}';
			}
			// 			WISE.Constants.layoutType = 'standard';
		</script>
		<script>
			var userObject = '${returnArr}';
			var userJsonObject = JSON.parse(userObject);
			
			//20210723 AJKIM 자산공사 필터 바 샋상 변경 dogfoot
			if(userJsonObject.siteNm == "KAMKO"){
				$('.filter-bar').addClass("kamko");
			}
			
			//dogfoot 자산관리공사 뷰어조회 버튼 변경 syjin 20210830	
			if(userJsonObject.siteNm == 'KAMKO'){
				$("#btn_query").removeClass('global-lookup');
				$("#btn_query").removeClass('search');
				
				$("#btn_query").addClass('btn');
				$("#btn_query").addClass('crud');
				//$("#btn_query").addClass('positive');
				
 				$("#btn_query").attr('style','border-radius:0px; background-color:#1b8466; position:absolute; right:20px; top:8px; color:white;')
				$("#btn_query").text('조회');
			}
			
			var reportType = 'ListViewer';
			//2020.03.03 mksong KERIS 출처 내용에 포함 dogfoot
			var srcFolderNm = '${srcFolderNm}';
			var spreadJsLicense = '${spreadJsLicense}';
		</script>
	</body>
</html>
