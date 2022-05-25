<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<div id="reportFolderPage">
	<div id="reportManagerTab" class="tab-container">
		<div id="deleteReportPopup"></div>
		<div class="out-row">
			<div class="out-column" style="width:30%;height:100%;border-right:1px solid #e7e7e7;">
				<h4 class="tit-level3 pre">보고서</h4>
				<div id="reportList"></div>
			</div>
			<div class="out-column" style="width:70%;height:100%;">
				<div class="row horizen col-2" style="height:100%;">
					<!-- DOGFOOT ktkang KERIS 보고서 폴더 보기에서 쿼리때문에 너무 느려서 뺌  20200130 -->
					<div class="column" style="height:100%;border-bottom:1px solid #e7e7e7;">
						<h4 class="tit-level3 pre">보고서 정보</h4>
						<div id="reportInfo" class="tbl data-form preferences-tbl">
							<table>
								<colgroup>
									<col style="width:140px">
									<col style="width:auto">
								</colgroup>
								<tbody>
									<tr>
										<th class="left">보고서 ID</th>
										<td class="ipt">
											<div class="relative-cell">
												<span id="reportId" class="txt"></span>
												<input id="reportDataLoad" type="checkbox" name="option1">
												<label for="reportDataLoad">데이터 불러오기</label>
											</div>
										</td>
									</tr>
									<tr>
										<th class="left">보고서 명</th>
										<td class="ipt">
											<input class="wise-text-input" id="reportTitle" type="text" style="width:100%;">
										</td>
									</tr>
									<tr>
										<th class="left">보고서 부제목</th>
										<td class="ipt">
											<input class="wise-text-input" id="reportSubtitle" type="text" style="width:100%;">
										</td>
									</tr>
									<tr>
										<th class="left">보고서 유형</th>
										<td id="reportType" class="left"></td>
									</tr>
									<tr>
									<!-- dogfoot 보고서 관리 폴더 저장 기능 추가 shlim 20201117 -->
										<th class="left">폴더 관리</th>
										<td  class="left">
											<div>
												<input class="wise-text-input" id="reportFolder" type="text" style="width:70%;" readonly="readonly">
												<div id="findFolder"></div>
											</div>
											<div id='save_box' style="text-align: center;"></div>
										</td>
										
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
										<td class="ipt">
											<input class="wise-text-input" id="reportTag" type="text" style="width:100%;">
										</td>
									</tr>
									<tr>
										<th class="left">순서</th>
										<td class="ipt">
											<input class="wise-text-input" id="reportOrder" type="text" style="width:100%;">
										</td>
									</tr>
									<tr>
										<th class="left">설명</th>
										<td class="ipt">
											<textarea class="wise-text-input" id="reportDesc" name="name" rows="8" cols="80"></textarea>
										</td>
									</tr>
								</tbody>
							</table>
						</div>
					</div>
					<!-- DOGFOOT ktkang KERIS 보고서 폴더 보기에서 쿼리때문에 너무 느려서 뺌  20200130 -->
<!-- 					<div class="column" style="height:50%;"> -->
<!-- 						<div class="row" style="height:100%;"> -->
<!-- 							<div class="column" style="width:100%;"> -->
<!-- 								<h4 class="tit-level3 pre">수행 쿼리</h4> -->
<!-- 							   	<div class="panel-inner scrollbar"> -->
<!-- 									<textarea name="name" rows="8" cols="80" class="querry-full" id="reportQuerySql" readonly></textarea> -->
<!-- 							   	</div> -->
<!-- 							</div> -->
<!-- 						</div> -->
<!-- 					</div> -->
				</div>
			</div>
		</div>
	</div>
	<div id="folderManagerTab" class="tab-container">
		<div id="folderNamePopup"></div>
		<div id="deleteFolderPopup"></div>
		<div class="out-row">
			<div class="out-column" style="width:30%;height:100%;border-right:1px solid #e7e7e7;">
			<!-- 2019.12.20 mksong 오타수정 dogfoot-->
				<h4 class="tit-level3 pre">폴더</h4>
				<div id="folderList"></div>
			</div>
		</div>
	</div>
</div>