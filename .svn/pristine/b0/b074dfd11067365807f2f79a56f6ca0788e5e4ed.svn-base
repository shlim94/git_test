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
	response.setHeader("Cache-Control", "no-store");
	response.setHeader("Cache-Control", "no-cache");
	response.setHeader("Pragma", "no-cache");
	response.setDateHeader("Expires", 0);
	String linkParam = request.getParameter("linkParam");
	String agent = BrowserUtils.getType(request);
	String dxVer = (agent.equals("IE10"))?Configurator.getInstance().getConfig("devextreme.ver.IE10"):Configurator.getInstance().getConfig("devextreme.ver");
	String resourceDebug = (Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.debug"))?".debug":"";
	String devVersion[] = dxVer.split("\\.");
	boolean dxTwety = (Integer.parseInt(devVersion[0])>=20);
	boolean minFile = Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.scriptcompress");
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
<c:set var="resourceDebug" value="<%=resourceDebug%>" />
<!DOCTYPE html>
<html lang="ko" style="font-size: 14px;">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>
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
	
		<!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
		<link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
		 <%if(minFile){%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/style.min.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.min.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.min.css" />
		<%if(dxTwety){%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx-diagram.min.css" />
		<%}%>
		<%-- DOGFOOT hsshim 2020-01-13 디자인 수정사항 반영위해 alert.js 이용 --%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.dx.light-hack.min.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.progressbar.min.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.min.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/spread.min.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/spreadJS/css/gc.spread.sheets.13.0.5.css" />

		<%} else {%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/style.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" />
		<%if(dxTwety){%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx-diagram.min.css" />
		<%}%>
		<%-- DOGFOOT hsshim 2020-01-13 디자인 수정사항 반영위해 alert.js 이용 --%>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.dx.light-hack.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.progressbar.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/spread.css" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/spreadJS/css/gc.spread.sheets.13.0.5.css" />
		
		<%}%>
		
		<style>
		  .spreadsheet-cont canvas{
		    float:left;
		  }
		</style>

	</head>
	<body>
	<form name="mainAdhocName" id="adhocForm" method="post">
	    <input type="hidden" id="mainAdhoc" name="mainAdhoc" value="mainAdhoc">
	    <sec:csrfInput/>
	</form>
		<div id="cont_popup" class="cont_popup"></div>
		<div id="sql_popup" class="sql_popup"></div>
		<div id="data_popup" class="data_popup"></div>
		<div id="ds_popup" class="ds_popup"></div>
		<!-- DOGFOOT ktkang 스프레드 시트 단일테이블 오류 수정  20200716 -->
		<div id="columnType_popup"></div>
    	<div id="wrap">
			<header>
			    <div class="header-container"></div>
			</header>
			<div id="container">
				<nav id="gnb">
				    <div class="gnb-container"></div>
				</nav>
				<div class="container-inner">
					<nav id="lnb" class="active"></nav>
					<div id="cont_popup"></div>
					<div id="export_popover"></div>
					<div id="newDataset_popover"></div>
					<div id="TBLList_popup"></div>
					<section class="content spreadsheet-editor">
						<div class="panel-tab">	
							<div class="panel tree active"></div>
							<div class="filter-bar">
							</div>
							<div  class="spreadsheet-cont">
								<iframe id="ss" style="width:100%; height:100%;" src="${pageContext.request.contextPath}/resources/spreadJS/designer_sourceV13/index/index.html"></iframe>
							</div>
						</div>
					</section>
				</div>
		    </div>
		</div>

		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-3.4.1.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-ui.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.json-2.4.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.number.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.ui.touch-punch.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/x2js/xml2json.js"></script>
		<%-- DOGFOOT hsshim 2020-01-13 디자인 수정사항 반영위해 alert.js 이용 --%>
		<!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
		<%if(minFile){%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/alert.min.js"></script>
		<%} else {%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/alert.js"></script>
		<%}%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/hashtable.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.numberformatter.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/cldr.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/event.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/supplemental.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/unresolved.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/globalize.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/message.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/number.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/date.min.js"></script>
		<!-- 반드시 number.min.js 이후에 로드 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/currency.min.js"></script>
		<!-- 반드시 number.min.js 이후에 로드 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/globalize.culture.ko.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/sqlike/SQLike.1.0.21.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/ace-1.4.8/ace.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/crossfilter-1.4.8/crossfilter.min.js"></script>		
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jszip/jszip.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/underscore/underscore-1.8.3.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/lodash/lodash.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/rgbcolor.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/StackBlur.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/canvg/canvg.js"></script>
		<%if(agent.indexOf("IE")>-1){%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/html2canvas/html2canvas.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/html2canvas/html2canvas.svg.js"></script>
		<%}else{%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/html2canvas/html2canvas.1.0.0.rc5.js"></script>
		<%}%>
		
		<%if(dxTwety){%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx-diagram.min.js"></script>
		<%}%>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx.all${resourceDebug}.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/vectormap-utils/dx.vectormaputils.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/math/math.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/bootstrap-3.3.7-dist/js/bootstrap.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/webtoolkit/webtoolkit.base64.js"></script>
		
		<!-- 개발 hsshim 1209 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/goldenlayout/js/goldenlayout-custom.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/loadAnimation.js"></script>
		<!-- DOGFOOT ktkang 스프레드 시트 필터 오류 수정  20200703 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/moment/moment.js"></script>
<%-- 		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/jquery.scrollbar.js"></script>
 --%>		
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
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/sampleData.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.ParameterHandler.min.js"></script>
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
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Scheduler.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Preferences.min.js"></script>
		
		<!-- Item JS -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.ItemManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.ItemColorManager.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.InsertItem.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.ItemFactory.min.js"></script>
		
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
			
		<!-- DOGFOOT hsshim 200103 SpreadManager 클래스 추가 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Spreadsheet.min.js"></script>

		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/WISE.widget.custom.global.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/WISE.widget.custom.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/reportViewer.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/resize.min.js"></script>
		<!-- DOGFOOT ajkim 0402 임시로 설정파일 불러옴 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/menuConfig.min.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/fontConfig.min.js"></script>
		
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
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/sampleData.js"></script>
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
			
		<!-- DOGFOOT hsshim 200103 SpreadManager 클래스 추가 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Spreadsheet.js"></script>

		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.global.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/WISE.widget.custom.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/reportViewer.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/resize.js"></script>
		<!-- DOGFOOT ajkim 0402 임시로 설정파일 불러옴 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/menuConfig.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/fontConfig.js"></script>
		<%}%>
		<!-- DOGFOOT hsshim 1216 WISE.js 다움에 scripts.js를 추가 필수 -->
		<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/scripts.js"></script>		
		
		<script>
			WISE.Constants.editmode = 'spreadsheet';
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
			
			var reportType = 'Spread';
			var spreadJsLicense = '${spreadJsLicense}';
		</script>
	</body>
	
</html> 
