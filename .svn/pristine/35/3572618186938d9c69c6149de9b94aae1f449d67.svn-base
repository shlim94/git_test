<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.wise.context.config.Configurator"%>
<%@ page import="com.wise.common.util.BrowserUtils"%>
<%@ page import="com.wise.common.util.CoreUtils"%>
<%@ page import="com.wise.common.util.PageUtils"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags"%>
<%
	request.setCharacterEncoding("utf-8");
	response.setHeader("P3P","CP='CAO PSA CONi OTR OUR DEM ONL'");
	response.setHeader("Expires", "Sat, 6 May 1995 12:00:00 GMT"); 
	response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
	response.addHeader("Cache-Control", "post-check=0, pre-check=0"); 
	response.setHeader("Pragma", "no-cache");
	String linkParam = request.getParameter("linkParam");
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
<c:set var="visibleTitle" value="<%=Configurator.getInstance().getConfigBooleanValue(\"WISE.libs.Dashboard.report.title.visible\")%>" />
<c:choose>
	<c:when test="${visibleTitle}">
		<c:set var="visibleTitleStyle" value="" />
	</c:when>
	<c:otherwise>
		<c:set var="visibleTitleStyle" value="remove-title" />
	</c:otherwise>
</c:choose>
<c:set var="globalizeVer" value="<%=Configurator.getInstance().getConfig(\"globalize.ver\")%>" />
<c:set var="dxChartIntegrated" value="<%=Configurator.getInstance().getConfigBooleanValue(\"devextreme.chart.integrated\")%>" />
<c:set var="dxVer" value="<%=dxVer%>" />
<c:set var="companyname" value="<%=companyname%>" />
<c:set var="resourceDebug" value="<%=resourceDebug%>" />
<!DOCTYPE html>
<html lang="ko">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
	<meta http-equiv="Content-Script-Type" content="text/javascript">
	<meta http-equiv="Content-Style-Type" content="text/css">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="apple-mobile-web-app-title"	content="${mainTitle}" />
	<meta name="keywords" content="BIportal">
	<meta name="description" content="BIportal">
	<meta http-equiv="Expires" content="-1">
	<meta http-equiv="Pragma" content="no-cache">
	<meta http-equiv="Cache-Control" content="No-Cache">

	<sec:csrfMetaTags />
	
	<title>${mainTitle}</title>
	
	<link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
	<!-- 	circos shlim -->
	<!-- CSS 파일 -->
	<!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
	 <%if(minFile){%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/style.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.min.css" />
	<%if(dxTwety){%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx-diagram.min.css" />
	<%}%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/jquery/apprise-v2.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.dx.light-hack.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.progressbar.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-base.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-dark-theme.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-light-theme.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/spectrum/spectrum.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/scheduler.min.css" />
	<!-- DOGFOOT syjin customOverlay 스타일 추가  20200914 -->
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/customOverlay.min.css" />
	<%} else {%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/style.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" />
	<%if(dxTwety){%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx-diagram.min.css" />
	<%}%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/jquery/apprise-v2.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.dx.light-hack.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.progressbar.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-base.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-dark-theme.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/goldenlayout/css/goldenlayout-light-theme.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/spectrum/spectrum.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/scheduler.css" />
	<!-- DOGFOOT syjin customOverlay 스타일 추가  20200914 -->
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/customOverlay.css" />
	<%}%>
	
<%-- 	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.css.map" /> --%>
<!-- CSS 파일 -->
</head>
<body>
<!-- hidden element -->
	<form action="${pageContext.request.contextPath}/download/downloadFile.do" id="downForm" method="post">
	    <input type="hidden" id="downFileName" name="fileName" value="">
	    <input type="hidden" id="downFilePath" name="filePath" value="">
	    <sec:csrfInput/>
	</form>
	<!-- DOGFOOT ktkang 비정형 메인 화면 새창 열기 기능  20200120 -->
	<form name="mainAdhocName" id="adhocForm" method="post">
	    <input type="hidden" id="mainAdhoc" name="mainAdhoc" value="mainAdhoc">
	    <sec:csrfInput/>
	</form>
	<!-- 통계분석 -->
	<form name="staticAnalysis" id="staticAnalysisForm" method="post">
	    <input type="hidden" id="staticAnalysis" name="staticAnalysis" value="staticAnalysis">
	    <input type="hidden" id="staticAnalysisType" name="staticAnalysisType" value="">
	    <sec:csrfInput/>
	</form>
	<!-- R분석 -->
	<form name="rAnalysis" id="rAnalysisForm" method="post">
	    <input type="hidden" id="rAnalysis" name="rAnalysis" value="rAnalysis">
	    <input type="hidden" id="rAnalysisType" name="rAnalysisType" value="">
	    <sec:csrfInput/>
	</form>
	<!-- 데이터 집합 뷰어 -->
	<form name="dataSetViewer" id="dataSetViewerForm" method="post">
	    <input type="hidden" id="dataSetViewer" name="dataSetViewer" value="dataSetViewer">
	    <sec:csrfInput/>
	</form>
	<!-- DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 -->
	<form action="${pageContext.request.contextPath}/report/edit.do" target="_blank" id="reportHisForm" method="post">
        	<input type="hidden" id="reportId" name="reportId" value="">
        	<input type="hidden" id="reportSeq" name="reportSeq" value="">
        	<input type="hidden" id="reportType" name="reportType" value="">
        	<sec:csrfInput/>
    </form>
	<input type='hidden' id='linkParam' value='${linkParam}'/>
	<div id="cont_popup" class="cont_popup"></div>
	<div id="sql_popup" class="sql_popup"></div>
	<div id="data_popup" class="data_popup"></div>
	<div id="ds_popup" class="ds_popup"></div>
	<div id='savePopup'></div>
	<div id="Filter_Popup" class="Filter_Popup"></div>
	<div id="columnType_popup"></div>
	<div id="dataList_popup"></div>
<!-- hidden element -->
	
<!-- main body element -->
	<div id="wrapper">
		<header>
		    <div class="header-container"></div>
		</header>
		<!-- header e -->
	
	<!-- global loading -->
<!-- 	<div class="data-load"> -->
<%-- 		<img class="load-out" src="${pageContext.request.contextPath}/resources/main/images/load_img_out.png" alt=""> --%>
<%-- 		<img class="load-in" src="${pageContext.request.contextPath}/resources/main/images/load_img_inner.png" alt=""> --%>
<!-- 	</div> -->

		<div id="container">
			<%-- 2020.02.04 mksong KERIS 디자인 최적화 수정 dogfoot --%>
			<c:choose>
				<c:when test="${empty userJsonObject.selectCubeId}">
					<nav id="gnb">
					    <div class="gnb-container"></div>
					</nav>
				</c:when>
			</c:choose>
			
			<!-- #gnb e -->
			<div class="container-inner">
				<nav id="lnb" class="active"></nav>
				<section class="content">
				</section>
			</div>
			<div id="cont_popup"></div>
			<div id="export_popover"></div>
			<div id="newDataset_popover"></div>
			<div id="TBLList_popup"></div>
		</div>
	<!-- 2020.03.03 mksong div 마감태그 누락 부분 수정 dogfoot -->
	</div>
<!-- 	<script src="//d3js.org/d3.v3.min.js"></script> -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/data.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/circos.min.js"></script>
	
	<div id='chart'></div>
<!-- main body element -->
	
<!-- JavaScript 파일 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/x2js/xml2json.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-3.4.1.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-ui.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.json-2.4.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.number.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.ui.touch-punch.min.js"></script>
	<%-- 2020.01.07 mksong 디자인 수정사항 반영위해 alert.js 이용 dogfoot --%>
	<%-- <script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/apprise-v2.js"></script> --%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/hashtable.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.numberformatter.js"></script>
	<!-- DOGFOOT syjin jquery resize 추가  20201119 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.resize.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/cldr.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/event.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/supplemental.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/unresolved.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/globalize.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/message.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/number.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/date.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/currency.min.js"></script> <!-- 반드시 number.min.js 이후에 로드 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/globalize.culture.ko.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/sqlike/SQLike.1.0.21.js"></script>
	<!-- DOGFOOT hsshim 2020-02-06 마스터 필터 속도 개선 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/ace-1.4.8/ace.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/crossfilter-1.4.8/crossfilter.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jszip/jszip.min.js"></script>
<%-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/underscore/underscore-1.8.3.js"></script> --%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/lodash/lodash.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/moment/moment.js"></script>

	<!-- 2020.11.10 mksong 동적로딩 d3 다운로드 오류 수정 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/Blob.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/canvas-toBlob.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/filesaver/FileSaver.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvas2image/canvas2image.min.js"></script>

	<!-- 2020.11.10 mksong 동적로딩 d3 다운로드 오류 수정 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/rgbcolor.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/StackBlur.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/canvg.min.js"></script>

	<!-- DOGFOOT ktkang 오타 수정  20200212 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/quill/1.3.6/quill.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/webtoolkit/webtoolkit.base64.min.js"></script>
	
<!-- 	<script src="https://cdnjs.cloudflare.com/ajax/libs/babel-polyfill/7.10.1/polyfill.js"></script> -->
<!-- 	<script src="https://cdnjs.cloudflare.com/ajax/libs/exceljs/3.8.0/exceljs.js"></script> -->
	<!-- dogfoot dev exceljs 추가 shlim 20210319 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/excelJs/exceljs.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/excelJs/jspdf.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/excelJs/jspdf.plugin.autotable.min.js"></script>
<!-- 	<script src="https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.2/FileSaver.min.js"></script> -->

	<%if(dxTwety){%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx-diagram.min.js"></script>
	<%}%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx.all${resourceDebug}.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-utils/dx.vectormaputils.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/math/math.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/spectrum/spectrum.js"></script>	

<script type="text/javascript" src="${pageContext.request.contextPath}/resources/es6-promise/es6-promise.auto.min.js"></script>

<%-- <script type="text/javascript" src="${pageContext.request.contextPath}/js/reportViewer.js"></script> --%>
	<!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
	 <%if(minFile){%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/polyfill_custom.min.js"></script>
	
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
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.resources.dx.min.js"></script>

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
<%-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.ParameterHandler.min.js"></script> --%>
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
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.D3Manager.min.js"></script> -->
	
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
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/WISE.widget.custom.global.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/WISE.widget.custom.min.js"></script>
	<!-- 2020.11.03 mksong resource Import 동적 테스트 dogfoot -->
    <script type="text/javascript" src="${pageContext.request.contextPath}/js.min/reportViewer.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/resize.min.js"></script>
	<%-- 2020.01.07 mksong 디자인 수정사항 반영위해 alert.min.js 이용 dogfoot --%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/alert.min.js"></script>
	
	<!-- 2020.11.04 mksong 로컬에서는  item js 정적 import 하도록 수정 dogfoot -->
	<% if(!dynamicImportCheck){%>
		<!-- Item Detail JS -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.DataGrid.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.PivotGrid.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Chart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Pie.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CoordinateLine.min.js"></script>ISE.widget.Card.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CoordinateLine.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Map.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Map.GeoPoint.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Map.Choropleth.min.js"></script>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.calender.js"></script>
	<!-- 20201201 shlim 이분법 차트 오류 수정 DOGFOOT -->
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.3.0.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3-legend.min.js"></script>-->
	
	<!--<script>
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
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3.layout.cloud.js" charset="utf-8"></script>-->
	
<%-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-selection.v1.min.js" charset="utf-8"></script> --%>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-collection.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-array.v2.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-path.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-shape.v1.min.js" charset="utf-8"></script> -->
<%-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-tip.js" charset="utf-8"></script> --%>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-sankey.js" charset="utf-8"></script>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.css" />
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.js" charset="utf-8"></script> -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/saveSvgAsPng.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/paletteValArea.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3-legend.min.js"></script>
	<%--<%if(dxTwety){%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Map.KakaoMap2.min.js"></script>
	<%}else{%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Map.KakaoMap.min.js"></script>
	<%}%>--%>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Image.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.Card.$.plugin.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.TreeView.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ListBox.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ComboBox.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.TextBox.min.js"></script>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.TreeMap.min.js"></script> -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.StarChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.HeatMap.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.HeatMap2.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.CoordinateDot.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.SynchronizedChart.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.WordCloud.min.js"></script>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/detail/WISE.widget.ParallelCoordinate.min.js"></script>
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
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/polyfill_custom.js"></script>
	
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
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.global.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/reportViewer.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/resize.js"></script>
	<!-- 2020.01.07 mksong 디자인 수정사항 반영위해 alert.js 이용 dogfoot -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/alert.js"></script>
	
	<!-- 2020.11.04 mksong 로컬에서는  item js 정적 import 하도록 수정 dogfoot -->
	<% if(!dynamicImportCheck){%>
		<!-- Item Detail JS -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.DataGrid.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.PivotGrid.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Chart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Pie.js"></script>
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Gauge.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Card.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.CoordinateLine.js"></script> -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Map.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Map.GeoPoint.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Map.Choropleth.js"></script>
	
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
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-selection.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-collection.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-array.v2.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-path.v1.min.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-shape.v1.min.js" charset="utf-8"></script>
<%--  	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-tip.js" charset="utf-8"></script>  --%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/d3-sankey.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.js" charset="utf-8"></script>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/visual/sankey/sk.d3.css" />
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/saveSvgAsPng.js" charset="utf-8"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/d3-legend.min.js"></script> 
	<!-- 20201112 AJKIM 이분법 차트 오류 수정 DOGFOOT -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.3.0.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/viz.v1.js"></script>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/visual/paletteValArea.js"></script>-
	<%--<%if(dxTwety){%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Map.KakaoMap2.js"></script>
	<%}else{%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Map.KakaoMap.js"></script>
	<%}%>--%>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Image.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.Card.$.plugin.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.TreeView.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ListBox.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ComboBox.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.TextBox.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.ScatterPlot2.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.LiquidFillGauge.js"></script>
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
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.BipartiteChart.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/detail/WISE.widget.FunnelChart.js"></script>	
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
	
	
	
	<!--<script type="text/javascript" src="${pageContext.request.contextPath}/resources/shp2geojson/stream.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/shp2geojson/shapefile_noThread.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/shp2geojson/dbf_noThread.js"></script> -->
	
	<!-- KERIS 수정 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/goldenlayout/js/goldenlayout-custom.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/loadAnimation.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/scripts.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/sampleData.js"></script>
	<!-- DOGFOOT mksong 2020-12-11 kakaoMapApi 라이센스 없는 경우 연동 x -->
	<c:if test="${kakaoMapApi ne null and kakaoMapApi != '' }">
		<!-- DOGFOOT syjin 2020-11-27 geojson 파일 스크립트로 처리 -->
	<%-- <script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/sido.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/sigungu.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/geoJson/eupmyeondong.js"></script> --%>
	</c:if>	
	        
	<!-- 0508 추가 스크롤디자인 라이브러리 -->
<%-- 	 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/jquery.scrollbar.js"></script> --%>
	<!-- 2020.02.04 mksong 스크롤 라이브러리 추가 dogfoot -->
<%-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/jquery.mCustomScrollbar.concat.min.js"></script> --%>
 		
 	<!-- 2020.04.02 ajkim 설정파일 추가 -->
 	<!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
 	 <%if(minFile){%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/menuConfig.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/fontConfig.min.js"></script>
	<%} else {%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/menuConfig.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/fontConfig.js"></script>
	<%}%>
	<script>
			var userObject = '${returnArr}';
			var userJsonObject = JSON.parse(userObject);
			var reportType = 'Editor';
	</script>
<!-- JavaScript 파일 -->

<!-- constants -->
	<script type="text/javascript">
		//2020.11.03 mksong 카카오맵 동적 import 추가 dogfoot
			//2020.11.03 mksong 동적 import 압축파일 구분 dogfoot
		WISE.Constants.minFile = <%= minFile %>;
		WISE.Constants.kakaoApi = '${kakaoMapApi}';
		WISE.Constants.dx = { chartIntegrated: ${dxChartIntegrated} };
		WISE.Constants.conditions = [<%=PageUtils.arrangeParameters(request)%>];
		WISE.Constants.editmode = 'designer';
		if('${companyname}' != undefined && '${companyname}' != ""){
			WISE.Constants.companyname = '${companyname}';
		}
		var userJsonObject = JSON.parse('${returnArr}');
		var reportType = 'Editor';
		//2020.03.03 mksong KERIS 출처 내용에 포함 dogfoot
		var srcFolderNm = '${srcFolderNm}';
		
		var csrfToken = $("meta[name='_csrf']").attr("content");
		var csrfHeader = $("meta[name='_csrf_header']").attr("content");
		
	</script> 
<!-- constants -->
</body>
</html>
