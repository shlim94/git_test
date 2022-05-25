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
<html lang="ko">
<head>
    <title>${mainTitle}</title>

    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=1.0, maximum-scale=1.0">
    <meta name="title" content="Wise Intelligence" />
	<s:csrfMetaTags/>
	
    <link rel="icon" href="favicon.ico" type="image/x-icon" />
	
	<!-- DOGFOOT ktkang 라이브러리 변경  20200221 -->
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-3.4.1.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.cookie.js"></script>
    <script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx.all${resourceDebug}.js"></script>
    <script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/loadAnimation.js"></script>
    <!-- DOGFOOT MKSONG editmode undefined 오류 수정 20200805 -->
<%--     <script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/scripts.js"></script> --%>
<%-- 	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/jquery.scrollbar.js"></script>
 --%>
	<link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
<%-- 	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" /> --%>
<%-- 	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" /> --%>
<%--     <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" /> --%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" />
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" />
    
</head>

<body>

<div id="wrap">
	<form id="mainForm" method="POST">
		<input type="hidden" name="USER" id="USER"/>
		<s:csrfInput/>
	</form>
    <div class="log-container">
        <div class="deco-wrap">
            <span class="bg-deco1"></span>
            <span class="bg-deco2"></span>
            <span class="bg-deco3"></span>
        </div>

        <div class="log-inner">
            <div class="log-cont visual">
                <div class="visual-inner">
                    <img id="loginImage" src="${pageContext.request.contextPath}/resources/main/images/custom/${loginImage}?v=1234">
                </div>
            </div>

            <script>
                // 로그인창 활성/비활성 애니메이션 이벤트 UI
                $(document).ready(function(){
                    loginEffect();
                });
                
                function loginEffect(){
                	var token = $("meta[name='_csrf']").attr("content");
                	var header = $("meta[name='_csrf_header']").attr("content");
                	
                    $('.form-group input').focus(function(){
                        $(this).parent('.form-group').addClass('on');
                    });
                    $('.form-group input').focusout(function(){
                        $(this).parent('.form-group').removeClass('on');
                    });

                    $('.form-cont').css({'display':'none'});
                    $('.form-cont.login').addClass('active');

                    $('.findpwd').on("click", function(){
                        $('.form-cont.forget').addClass('active').siblings().removeClass('active');
                    });
                    $('.signUp').on("click", function(){
                        $('.form-cont.sign-up').addClass('active').siblings().removeClass('active');
                    });
                    $('.reload').on("click", function(){
                        location.reload();
                    });

                    $('.certiFi').on("click", function(){
                        $('.form-cont.certification').addClass('active').siblings().removeClass('active');
                    });
                    
                    $('#loginButton').on("click", function(){
                    	var id = $('#id').val();
                    	var pwd = $('#pwd').val();
                    	
                    	if (id == '' || pwd == '') {
                    		if (id == '')
                    			$('#id').focus();
                    		else
                    			$('#pwd').focus();
                    		alert('사용자 정보가 일치하지 않습니다.');
                    		return false;
                    	}
                    	
                    	$.ajax({
                    		method : 'POST',
                    		url : './loginCheck.do',
                    		data : {
                    			id : id,
                    			pwd : pwd
                    		},
                    		beforeSend: function(xhr, settings) {
                    			xhr.setRequestHeader(header, token);
                    		},
                    		error : function(e)
                    		{
                    			alert('사용자 정보가 일치하지 않습니다.');
                    		},
                    		success : function(data) {
                    			data = $.parseJSON(data);
                    			if (data.error) {
                    				alert(data.error);
                    			} else {
	                    			userId = data["userId"];
	                    			var href = data["href"];
	                    			
	                    			if(userId != null) {
	                    				$('#USER').val(userId);
	                    				$('#mainForm').attr('action', href);
	                    				$('#mainForm').submit();
	                    			} else {
	                    				alert('사용자 정보가 일치하지 않습니다.');
	                    			}
	                    			
	                            	if($("input[name=remember]").is(":checked")) {
	                            		$.cookie('wi_id', userId, { expires: 30 });
	                            	} else {
	                            		$.removeCookie('wi_id');
	                            	}	
                    			}
                    		}
                    	});
                    });
                    
                    $('#pwd').on('keydown', function(e) {
                    	if (e.keyCode === 13)
                    		$('#loginButton').click();
                    });
                    
                    $('.log-logo').on('dblclick', function() {
						$.ajax({
							url: './sneakyLogin.do',
							beforeSend: function(xhr, settings) {
								xhr.setRequestHeader(header, token);
                    		},
							success : function(data) {
                    			data = $.parseJSON(data);
                    			if (data.error) {
                    				alert(data.error);
                    			} else {
	                    			userId = data["userId"];
	                    			var href = data["href"];
	                    			
	                    			if(userId != null) {
	                    				$('#USER').val(userId);
	                    				$('#mainForm').attr('action', href);
	                    				$('#mainForm').submit();
	                    			} else {
	                    				alert('사용자 정보가 일치하지 않습니다.');
	                    			}
	                    			
	                            	if($("input[name=remember]").is(":checked")) {
	                            		$.cookie('wi_id', userId, { expires: 30 });
	                            	} else {
	                            		$.removeCookie('wi_id');
	                            	}
                    			}
                    		}
						});
						
                    });
                    
                   	if($.cookie('wi_id')!=undefined) {
                   		$('#id').val($.cookie('wi_id'));
                   	}
                }
            </script>
            <div class="log-cont">
                <h1 class="log-logo">logo</h1>

                <div class="form-cont login">
                    <form id="loginForm">
                        <div class="form-group">
                            <input type="text" id="id" class="wise-text-input" placeholder="ID" name="email">
                        </div>
                        <div class="form-group">
                            <input type="password" id="pwd" class="wise-text-input" placeholder="Password" name="password">
                        </div>
                        <div class="form-sub">
                            <div class="form-sub-left">
		                        <input class="check" id="remember" type="checkbox" name="remember" checked>
                                <label for="remember">ID Remember</label>
                            </div>
                            <!-- <div class="form-sub-right">
                                <a href="#" class="findpwd forget-pwd">Find password</a>
                            </div> -->
                        </div>
                        <div class="form-btn">
                            <a id="loginButton" class="btn positive" href="#">
                                Login
                            </a>
                            <!-- <a class="signUp btn point" href="#">
                                Sign Up
                            </a> -->
                        </div>
                    </form>
                </div>
                <!-- .login e -->


                <div class="form-cont sign-up">
                    <form action="">
                        <div class="form-group">
                            <input type="text" placeholder="Company" name="company">
                        </div>
                        <div class="form-group">
                            <input type="text" placeholder="Name" name="name">
                        </div>
                        <div class="form-group">
                            <input type="text" placeholder="Email address" name="email">
                        </div>
                        <div class="form-group">
                            <input type="password" placeholder="Password" name="password">
                        </div>
                        <div class="form-group">
                            <input type="password" placeholder="Password check" name="password">
                        </div>
                        <div class="form-btn">
                            <a class="certiFi btn positive" href="#">
                                Next
                            </a>
                            <a class="reload btn neutral" href="#">
                                Cancel
                            </a>
                        </div>
                    </form>
                </div>
                <!-- .sign-up e -->


                <div class="form-cont forget">
                    <form action="">
                        <div class="form-group">
                            <input type="text" placeholder="Email address" name="email">
                        </div>
                        <div class="form-btn">
                            <a class="btn positive" href="#">
                                Request
                            </a>
                            <a class="reload btn neutral" href="#">
                                Cancel
                            </a>
                        </div>
                    </form>
                </div>
                <!-- .forget e -->

                <div class="form-cont certification">
                    <form action="">
                        <div class="form-group">
                            <input type="text" placeholder="Certification Number" name="Certification Number">
                        </div>
                        <div class="form-btn">
                            <a class="btn positive" href="#">
                                Sign Up
                            </a>
                            <a class="signUp btn neutral" href="#">
                                Cancel
                            </a>
                        </div>
                    </form>
                </div>
                <!-- .forget e -->

            </div>

        </div>
    </div>
    <!-- .log-container e -->

	<footer>
	    <small>2019 &copy; Intelligence by wise</small>
	</footer>
	
</div>
<!-- #wrap e -->
</body>
</html>
