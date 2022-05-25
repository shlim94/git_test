<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="com.wise.context.config.Configurator"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<%
    response.setHeader("Cache-Control", "no-cache");
    response.setHeader("Pragma", "no-cache");
    response.setDateHeader("Expires", 0);
%>

<c:set var="domain" value="<%=Configurator.getInstance().getFullDomain(request)%>" />
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
<link rel="stylesheet" type="text/css" href="${domain}${pageContext.request.contextPath}/css/style.css"/>
</head>

<body class="body_bg">
    
    <div class="error_page">
    	<div class="error_img"><img src="${pageContext.request.contextPath}/images/error_img_02.png" alt=""></div>
        <div class="error_txt">
            <div class="error_txt01">
                <spring:message code="page.error.no.view.permission.report.m2"></spring:message>
            </div>
            <div class="error_txt02">
                <spring:message code="page.error.no.view.permission.report.m1"></spring:message>
            </div>
<!--             <div class="error_bt"><a href="#">메인페이지 바로가기</a></div> -->
        </div>
    </div>

</body>
</html>
