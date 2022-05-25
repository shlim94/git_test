<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<div id="popup"></div>
<div id="monitoringPage">
	<!-- DOGFOOT ktkang 모니터링에서 시스템 부분 주석처리  20200924 -->
	<!-- <div class="tab-container" id="overviewTab">
		<div class="row horizen col-2" style="height:100%;">
			<div class="column" style="height:50%;border-bottom:1px solid #e7e7e7;">
				<div class="row" style="height:100%;">
					<div class="column responsive-border" style="width:50%;border-right:1px solid #e7e7e7;">
						<h4 class="tit-level3 pre">Disk 사용량</h4>
						<div class="system-chart-container" style="float:left;">
							<div id="diskGauge"></div>
						</div>
						<div class="system-chart-container scrollable" style="float:right;">
							<div id="systemInfo"></div>
						</div>
					</div>
					<div class="column" style="width:50%;">
					    <h4 class="tit-level3 pre">CPU 사용량</h4>
						<div class="system-chart-container" style="float:left;">
							<div id="cpuGauge"></div>
						</div>
						<div class="system-chart-container" style="float:right;">
							<div id="cpuChart"></div>
							<div id="cpuButton"></div>
						</div>
					</div>
				</div>
			</div>
			<div class="column" style="height:50%;">
				<div class="row" style="height:100%;">
					<div class="column responsive-border" style="width:50%;border-right:1px solid #e7e7e7;">
						<h4 class="tit-level3 pre">Memory 사용량</h4>
						<div class="system-chart-container" style="float:left;">
							<div id="memGauge"></div>
						</div>
						<div class="system-chart-container" style="float:right;">
							<div id="memChart"></div>
							<div id="memButton"></div>
						</div>
					</div>
					<div class="column" style="width:50%;">
					   	<h4 class="tit-level3 pre">IO Read/Write</h4>
						<div class="system-chart-full-container">
							<div id="diskChart"></div>
							<div id="diskButton"></div>						
						</div>
					</div>
				</div>
			</div>
		</div>
	</div> -->
	<div class="tab-container" id="processesTab">
<!-- 		<h4 id="jobDescription" class="tit-level3 pre"></h4>  -->
		<div id ="jobInfoList"></div>
	</div>
	<div class="tab-container" id="activeUsersTab">
<!-- 		<h4 id="sametimeUser" class="tit-level3 pre"></h4>  -->
		<div id ="activeUserList"></div>
	</div>
</div>