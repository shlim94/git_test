<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.wise.context.config.Configurator"%>
<%@ page import="com.wise.common.util.BrowserUtils"%>
<%@ page import="com.wise.common.util.CoreUtils"%>
<%@ page import="com.wise.common.util.PageUtils"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="s" uri="http://www.springframework.org/security/tags"%>
<%
	request.setCharacterEncoding("utf-8");
	response.setHeader("Cache-Control", "no-store");
	response.setHeader("Cache-Control", "no-cache");
	response.setHeader("Pragma", "no-cache");
	response.setHeader("P3P","CP='CAO PSA CONi OTR OUR DEM ONL'");
	response.setDateHeader("Expires", 0);
	String linkParam = request.getParameter("linkParam");
	String agent = BrowserUtils.getType(request);
	String dxVer = (agent.equals("IE10"))?Configurator.getInstance().getConfig("devextreme.ver.IE10"):Configurator.getInstance().getConfig("devextreme.ver");
	String resourceDebug = (Configurator.getInstance().getConfigBooleanValue("wise.ds.js.resource.debug"))?".debug":"";
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
<c:set var="dxVer" value="<%=dxVer%>" />
<c:set var="resourceDebug" value="<%=resourceDebug%>" />
<!DOCTYPE html>
<html lang="ko">
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
	<s:csrfMetaTags />
	
	<title>${mainTitle}</title>
	
	<link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
	 <!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
	<%if(minFile){%>
	<%-- DOGFOOT ktkang KERIS 캐시 사용을 위해 timestamp 제거  20200205 --%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/style.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.progressbar.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.dx.light-hack.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css" />
		<%-- DOGFOOT hsshim 2020-01-15 디자인 수정사항 반영위해 alert.js 이용 --%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/config.min.css"/>
	
	<%} else {%>
	<%-- DOGFOOT ktkang KERIS 캐시 사용을 위해 timestamp 제거  20200205 --%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/style.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.progressbar.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.dx.light-hack.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css" />
	<%-- DOGFOOT hsshim 2020-01-15 디자인 수정사항 반영위해 alert.js 이용 --%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/config.css"/>
	<%}%>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-3.4.1.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-ui.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.json-2.4.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.number.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.ui.touch-punch.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jszip/jszip.min.js"></script>
	<%-- DOGFOOT hsshim 2020-01-15 디자인 수정사항 반영위해 alert.js 이용 --%>
	<!-- DOGFOOT ajkim 2020-10-20 js 및 css 압축파일 적용 -->
	 <%if(minFile){%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/alert.min.js"></script>
	<%} else {%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/alert.js"></script>
	<%}%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/hashtable.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.numberformatter.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/base64/base64.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/cldr.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/event.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/supplemental.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/cldr/unresolved.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/globalize.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/message.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/number.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/globalize/${globalizeVer}/date.min.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx.all${resourceDebug}.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/moment/moment.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/underscore/underscore-1.8.3.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/es6-promise/es6-promise.auto.js"></script>
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
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceFactory.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.DataSourceManager.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.QueryHandler.min.js"></script>
	
	<!-- Core widget JS -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/widget/WISE.widget.main.js"></script>

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
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/WISE.widget.Preferences.min.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/configMaster.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/userGroup.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/monitor.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/authenticate.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/WISE.widget.GeneralConfig.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/WISE.widget.Session.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/log.min.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/reportFolder.min.js"></script>
	<!-- 2020.04.02 ajkim 설정파일 추가 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/menuConfig.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/fontConfig.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.FontManager.min.js"></script>
	<!-- dogfoot shlim 보고서 레이아웃 파일 추가 20200820 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.ReportLayoutManager.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.ParameterHandler.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/dataset/WISE.widget.ParameterBar.min.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/item/WISE.widget.InsertItem.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/loadDataSetList.min.js"></script>
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
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceFactory.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.DataSourceManager.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.QueryHandler.js"></script>
	
	<!-- Core widget JS -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/widget/WISE.widget.main.js"></script>

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
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/WISE.widget.Preferences.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/configMaster.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/userGroup.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/monitor.js"></script>
	<!-- 2020.12.21 syjin 환경 설정 원본 추가 layout 추가 -->	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/dataSource.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/authenticate.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/WISE.widget.GeneralConfig.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/WISE.widget.Session.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/log.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/reportFolder.js"></script>
	<!-- 2020.04.02 ajkim 설정파일 추가 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/menuConfig.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/fontConfig.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.FontManager.js"></script>
	<!-- dogfoot shlim 보고서 레이아웃 파일 추가 20200820 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.ReportLayoutManager.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.ParameterHandler.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/dataset/WISE.widget.ParameterBar.js"></script>	
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/item/WISE.widget.InsertItem.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/loadDataSetList.js"></script>
	<%}%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/sampleData.js"></script>
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/scripts.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/loadAnimation.js"></script>
<%-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/jquery.scrollbar.js"></script>
 --%>	
</head>

<body>
	<div id="wrap">
		<header>
		    <div class="header-container"></div>
		</header>
		<div id="container" class="pf">
			<nav id="gnb">
		  	  <div class="gnb-container"></div>
			</nav>
			<div class="container-inner">
				<nav id="lnb" class="active"></nav>
				<div class="config-container">
					<section class="content"></section>
				</div>
			</div>
    	</div>
   	</div>
   	<div id="ds_popup"></div>
	<script>
		var userObject = '${returnArr}';
		var userJsonObject = JSON.parse(userObject);
		WISE.Constants.editmode = 'config';
	</script>
</body>

</html>