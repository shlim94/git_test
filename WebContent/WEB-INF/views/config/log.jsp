<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<div id="logPage">
	<div class="tab-container" id="logUserTab">
		<div id="logUserList"></div>
	</div>
	<div class="tab-container" id="logReportTab">
		<div id="logReportList"></div>
	</div>
	<div class="tab-container" id="logExportTab">
		<div id="logExportList"></div>
	</div>
	<div class="tab-container" id="logQueryTab">
		<div class="out-column" style="width:100%;height:100%;">
			<div class="row horizen col-2" style="height:100%;">
				<div class="column" style="height:50%;border-bottom:1px solid #e7e7e7;">
					<div id="logQueryList"></div>
				</div>
				<div class="column" style="height:50%;border-bottom:1px solid #e7e7e7;">
					<h4 class="tit-level3 pre">수행 쿼리</h4>
					<textarea rows="20" cols="80" class="sql-display" id="logQuerySql" readonly></textarea>
			   	</div>
			</div>
		</div>
	</div>
<!-- 	<div class="tab-container" id="logAnalysisTab"> -->
<!-- 		<div id="logAnalysisList"></div> -->
<!-- 	</div> -->
</div>