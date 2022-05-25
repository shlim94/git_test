<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.wise.context.config.Configurator"%>
<%@ page import="com.wise.common.util.BrowserUtils"%>
<%@ page import="com.wise.common.util.CoreUtils"%>
<%@ page import="com.wise.common.util.PageUtils"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
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
%>
<c:set var="domain"	value="<%=Configurator.getInstance().getFullDomain(request)%>" />
<c:set var="dxVer" value="<%=dxVer%>" />
<c:set var="resourceDebug" value="<%=resourceDebug%>" />
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport"
	content="width=device-width, initial-scale=1, maximum-scale=1" />
<meta http-equiv="Content-Script-Type" content="text/javascript">
<meta http-equiv="Content-Style-Type" content="text/css">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="apple-mobile-web-app-title"	content="${mainTitle}" />
<meta name="keywords" content="BIportal">
<meta name="description" content="BIportal">
<meta http-equiv="Expires" content="-1">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Cache-Control" content="No-Cache">

<title>${mainTitle}</title>

<link rel="shortcut icon" href="${pageContext.request.contextPath}/wise_ds.ico" />
<link rel="stylesheet" type="text/css" href="${domain}${pageContext.request.contextPath}/css/style.css" />
<link rel="stylesheet" type="text/css" href="${domain}${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" />
<link rel="stylesheet" type="text/css" href="${domain}${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" />
<link rel="stylesheet" type="text/css" href="${domain}${pageContext.request.contextPath}/resources/jquery/apprise-v2.css" />

<link rel="stylesheet" type="text/css" href="${domain}${pageContext.request.contextPath}/css/WISE.dx.light-hack.css" />

<link rel="stylesheet" type="text/css" href="${domain}${pageContext.request.contextPath}/css/WISE.custom.css" />
<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-3.4.1.min.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx.all${resourceDebug}.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/js/execToss.js"></script>
</head>
<body>
	<div style='font-size:2em;text-align:center'>배치실행</div>
	<div style='text-align:center'>
		<div id='executor' style='float:left'></div>
		<div id='tableInput' style='float:left'></div>
		<div id='executeBatch' style='float:left'></div>
	</div>
	<br>
	<br>
	<br>
	<div id="resultArea" style="font-size : 1.5em"></div>
</body>
</html>