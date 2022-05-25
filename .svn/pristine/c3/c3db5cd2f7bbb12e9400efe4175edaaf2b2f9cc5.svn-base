<%@ page language="java" contentType="text/html; charset=utf-8"
	pageEncoding="utf-8"%>
<%@ page import="com.wise.context.config.Configurator"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<%
	response.setHeader("Cache-Control", "no-cache");
	response.setHeader("Pragma", "no-cache");
	response.setDateHeader("Expires", 0);
%>

<c:set var="domain"
	value="<%=Configurator.getInstance().getFullDomain(request)%>" />
<c:set var="timestamp" value="<%=System.nanoTime()%>" />


<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Script-Type" content="text/javascript">
<meta http-equiv="Content-Style-Type" content="text/css">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="apple-mobile-web-app-title" content="WISE BI Portal" />
<meta name="keywords" content="BIportal">
<meta name="description" content="BIportal">
<title><spring:message code="page.common.title"></spring:message></title>
<link rel="shortcut icon"
	href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
<link rel="stylesheet" type="text/css"
	href="${pageContext.request.contextPath}/css/style.css" />
<link rel="stylesheet" type="text/css"
	href="${pageContext.request.contextPath}/resources/main/css/style.css" />
</head>

<body>
	<div id="wrap">
		<div class="errorPage-container pageValid">
			<a href="#" class="wi-logo">WI</a>
			<div class="inner">
				<div class="txt-cont">
<%-- 					<strong><spring:message code="page.error.invalid.user.m2"></spring:message></strong> --%>
<%-- 					<p><spring:message code="page.error.invalid.user.m1"></spring:message></p> --%>
					<strong>허가되지 않은 사용자 요청</strong>
					<p>유효하지 않은 사용자 요청입니다.</p>
						<!-- 2020.02.13 mksong keris 메인으로 이동 버튼 삭제 DOGFOOT -->
<!-- 					<div class="row center"> -->
<%-- 						<a class="btn positive" href="${pageContext.request.contextPath}/report/edit.do">메인으로 가기 </a> --%>
<!-- 					</div> -->
				</div>
			</div>
		</div>
	</div>
</body>
</html>
