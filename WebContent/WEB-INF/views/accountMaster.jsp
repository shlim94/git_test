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

	<sec:csrfMetaTags />
	
	<title>${mainTitle}</title>
	
	<link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/main/images/logo.png" />
	<!-- DOGFOOT ajkim 2020-10-20 속도 개선 위해 min 파일로 대체 -->
	<%if(minFile){%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/style.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/config.min.css"/>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.progressbar.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css.min/WISE.dx.light-hack.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css" />
	<%-- DOGFOOT hsshim 2020-01-13 디자인 수정사항 반영위해 alert.js 이용 --%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.min.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.min.css" />
	<%} else {%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/style.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/config.css"/>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.progressbar.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.dx.light-hack.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/WISE.custom.css" />
	<%-- DOGFOOT hsshim 2020-01-13 디자인 수정사항 반영위해 alert.js 이용 --%>
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/main/css/style.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.common.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/resources/dx/${dxVer}/css/dx.light.css" />
	<%}%>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-3.4.1.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery-ui.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.json-2.4.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.number.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/jquery/jquery.ui.touch-punch.min.js"></script>
	<%-- DOGFOOT hsshim 2020-01-13 디자인 수정사항 반영위해 alert.js 이용 --%>
	<!-- DOGFOOT ajkim 2020-10-20 속도 개선 위해 min 파일로 대체 -->
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
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/dx/${dxVer}/dx.all${resourceDebug}.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/moment/moment.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/es6-promise/es6-promise.auto.js"></script>
	
	<!-- DOGFOOT ajkim 2020-10-20 속도 개선 위해 min 파일로 대체 -->
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
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/core/libs/WISE.libs.Dashboard.FontManager.min.js"></script>
	
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
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/accountMaster.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/menuConfig.min.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js.min/config/fontConfig.min.js"></script>
	<%} else {%>
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
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/core/libs/WISE.libs.Dashboard.FontManager.js"></script>
	
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
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/accountMaster.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/menuConfig.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/js/config/fontConfig.js"></script> 
	<%}%>
	
	
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/scripts.js"></script>
	<script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/loadAnimation.js"></script>
	<%-- <script type="text/javascript" src="${pageContext.request.contextPath}/resources/main/js/lib/jquery.scrollbar.js"></script> --%>
	
</head>

<body style="overflow: hidden;">
	<div id="accountPopup"></div>
	<!-- DOGFOOT ktkang 개인보고서 추가  20200107  -->
	<div id="deleteReportPopup"></div>
	<div id="folderNamePopup"></div>
	<div id="deleteFolderPopup"></div>
	<div id="wrap">
		<header>
		    <div class="header-container"></div>
		</header>
		<div id="container" class="acc">
			<div class="account-container-inner">
				<nav id="lnb" class="active"></nav>
				<div class="account-container">
					<section class="content">
						<div class="account-content">
							<div class="account-settings-container" id="editFolderReport">
								<h4 class="tit-level3 account-tit">개인 보고서 및 폴더 관리</h4>
								<div class="account-settings-category">
									<div class="category-body">
										<div class="panel active" style="overflow:hidden">
											<div class="tab-title rowColumn">
												<ul class="col-2">
													<li rel="panelReportA-1"><a href="#">폴더</a></li>
													<li rel="panelReportA-2"><a href="#">보고서</a></li>
												</ul>
											</div>
											<div class="panel-inner scrollbar"
												style="overflow-y: visible !important">
												<div id="panelReportA" class="tab-component">
													<div class="panelReportA-1 tab-content" style="">
														<div class="out-row">
															<div class="out-column"
																style="width: 30%; height: 100%; border-right: 1px solid #e7e7e7;">
																<h4 class="tit-level3 pre">폴더</h4>
																<div id="folderList"></div>
															</div>
														</div>
														<div class="out-column" style="width: 70%; height: 100%;">
															<div class="row horizen col-2" style="height: 100%;">
															</div>
														</div>
														<div class="account-settings-button left2" id="newUserFolder">
															<p>새로만들기</p>
														</div>
														<div class="account-settings-button center" id="editUserFolder">
															<p>편집</p>
														</div>
														<div class="account-settings-button right2" id="deleteUserFolder">
															<p>삭제</p>
														</div>
													</div>
													<div class="panelReportA-2 tab-content"
														style="display: none;">
														<div class="out-row" style="margin: 10px">
															<div class="out-column"
																style="width: 30%; height: 100%; border-right: 1px solid #e7e7e7;">
																<h4 class="tit-level3 pre">보고서</h4>
																<div id="reportList"></div>
															</div>
															<div class="out-column" style="width: 70%; height: 100%;">
																<div class="row horizen col-2" style="height: 100%;">
																	<div style="height: 50%; border-bottom: 1px solid #e7e7e7;">
																		<h4 class="tit-level3 pre">보고서 정보</h4>
																		<div id="reportInfo"
																			class="tbl data-form preferences-tbl">
																			<table>
																				<colgroup>
																					<col style="width: 140px">
																					<col style="width: auto">
																				</colgroup>
																				<tbody>
																					<tr>
																						<th class="left">보고서 ID</th>
																						<td class="ipt">
																							<div class="relative-cell">
																								<span id="reportId" class="txt"></span> <input
																									id="reportDataLoad" type="checkbox"
																									name="option1"> <label
																									for="reportDataLoad">데이터 불러오기</label>
																							</div>
																						</td>
																					</tr>
																					<tr>
																						<th class="left">보고서 명</th>
																						<td class="ipt"><input
																							class="wise-text-input" id="reportTitle"
																							type="text" style="width: 100%;"></td>
																					</tr>
																					<tr>
																						<th class="left">보고서 부제목</th>
																						<td class="ipt"><input
																							class="wise-text-input" id="reportSubtitle"
																							type="text" style="width: 100%;"></td>
																					</tr>
																					<tr>
																						<th class="left">보고서 유형</th>
																						<td class="ipt"><select id="reportType">
																								<option value="" selected="selected"
																									style="display: none;"></option>
																								<option value="AdHoc">비정형</option>
																								<option value="DashAny">대시보드</option>
																								<option value="Excel">엑셀</option>
																						</select></td>
																					</tr>
																					<tr>
																						<th class="left">게시자</th>
																						<td id="publisherName" class="left"></td>
																					</tr>
																					<tr>
																						<th class="left">게시일자</th>
																						<td id="publishedDate" class="left"></td>
																					</tr>
																					<tr>
																						<th class="left">주석</th>
																						<td class="ipt"><input
																							class="wise-text-input" id="reportTag"
																							type="text" style="width: 100%;"></td>
																					</tr>
																					<tr>
																						<th class="left">순서</th>
																						<td class="ipt"><input
																							class="wise-text-input" id="reportOrder"
																							type="text" style="width: 100%;"></td>
																					</tr>
																					<tr>
																						<th class="left">설명</th>
																						<td class="ipt"><textarea
																								class="wise-text-input" id="reportDesc" style="height: 60px;"
																								name="name" rows="5" cols="80"></textarea></td>
																					</tr>
																				</tbody>
																			</table>
																		</div>
																	</div>
																	<div style="height: 50%;">
																		<div class="row" style="height: 100%;">
																			<div style="width: 100%;">
																				<h4 class="tit-level3 pre">수행 쿼리</h4>
																					<textarea name="name" rows="8" cols="80"
																						class="querry-full" id="reportQuerySql" readonly></textarea>
																			</div>
																		</div>
																	</div>
																</div>
															</div>
														</div>
														<div class="account-settings-button left" id="saveUserReport">
															<p>저장</p>
														</div>
														<div class="account-settings-button right" id="deleteUserReport">
															<p>삭제</p>
														</div>
													</div>
												</div>
											</div>
										</div>
									</div>
								</div>
							</div>
						</div>
					</section>
				</div>
			</div>
    	</div>
   	</div>
	<script>
		var userObject = '${returnArr}';
		var userJsonObject = JSON.parse(userObject);
		WISE.Constants.editmode = 'account';
		
		var csrfToken = $("meta[name='_csrf']").attr("content");
		var csrfHeader = $("meta[name='_csrf_header']").attr("content");
	</script>
</body>

</html>