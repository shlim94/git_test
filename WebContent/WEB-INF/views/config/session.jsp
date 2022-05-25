<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<div id="sessionPage">
	<!-- 일반 설정 탭 -->
	<div class="tab-container" id="sessionJobTab">
		<div class="row col-2" style="height:100%;">
			<div class="column" style="width:25%;height:100%;border-bottom:1px solid #e7e7e7;">
				<div class="row" style="height:30%;">
					<div class="column responsive-border" style="width:100%;">
						<h4 class="tit-level3" style="margin-bottom:0px;">데이터 소스 정보</h4>
						<div style="height:calc(100% - 40px);margin: 5px;">
							<div id="datasourceForm"></div>
						</div>
					</div>
				</div>
				<div class="row" style="height:70%;">
					<div class="column responsive-border" style="width:100%;">
						<h4 class="tit-level3" style="margin-bottom:0px;border-top:1px solid #e7e7e7;">데이터 소스 목록</h4>
						<div style="height:calc(100% - 40px);">
							<div id="datasourceGrid"></div>
						</div>
					</div>
				</div>
			</div>
			<div class="column" style="width:75%;height:100%;">
				<div class="row" style="height:50%;">
					<div class="column responsive-border" style="width:100%;">
						<h4 class="tit-level3" style="margin-bottom:0px;">실행 중인 프로세스 목록</h4>
						<div style="height:calc(100% - 40px);">
					 		<div id="sessionGrid" style="width:100%;"></div>
						</div>
					</div>
				</div>
				<div class="row" style="height:50%;">
					<div class="column responsive-border" style="width:100%;">
						<h4 class="tit-level3" style="margin-bottom:0px;border-top:1px solid #e7e7e7;">수행쿼리 정보</h4>
						<div style="height:calc(100% - 40px);">
							<div id="sessionQuery"></div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
	<div class="tab-container" id="sessionUserTab">
		<div id="logoutPopup"></div>
 		<div id="userGrid"></div>
	</div>
	<div class="tab-container" id="sessionInactiveUserTab">
 		<div id="inactiveUserGrid"></div>
	</div>
	<div class="tab-container" id="sessionLockedUserTab">
 		<div id="lockedUserGrid"></div>
	</div>
</div>