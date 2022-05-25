<%@ page language="java" contentType="text/html; charset=utf-8"
	pageEncoding="utf-8"%>
<%@ page isErrorPage="true" %>
<%@ page import="com.wise.context.config.Configurator"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<%
	response.setHeader("Cache-Control", "no-cache");
	response.setHeader("Pragma", "no-cache");
	response.setDateHeader("Expires", 0);
	//System Exception 표시
	if(Configurator.getInstance().getConfigBooleanValue("wise.ds.error.display.system")) exception.printStackTrace();
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
<link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/style.css" />
<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" />
</head>

<body>
	<div id="wrap">
		<div class="errorPage-container pageSystem">
			<a href="#" class="wi-logo">WI</a>
			<div class="inner">
				<div class="txt-cont">
					<strong> 시스템 사용중 입니다. </strong>
					<p>
						에러가 발생하였습니다. <br> 시스템 관리자에게 문의 하세요.
					</p>
						<!-- 2020.02.13 mksong keris 메인으로 이동 버튼 삭제 DOGFOOT -->
<!-- 					<div class="row center"> -->
<%-- 						<a class="btn positive" href="${pageContext.request.contextPath}/report/edit.do"> 메인으로 가기 </a> --%>
<!-- 					</div> -->
				</div>
			</div>
		</div>
	</div>
<%-- AJAX오류 표기 --%>
<error_message style="display:none;"><%
if(Configurator.getInstance().getConfigBooleanValue("wise.ds.error.display.ajax")) out.println(exception.toString());
%></error_message> 
</body>
</html>
