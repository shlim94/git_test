<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<div id="dataSourcePage">
	<div class="tab-container" id="dataSourceTab">
		<div id="pwPopup"></div>
		<div class="out-row">
			<div class="out-column" style="width:50%;height:100%;border-right:1px solid #e7e7e7;">
				<h4 class="tit-level3 pre" id="dataSourceCount"></h4>
				<div id="dataSourceList" style="height: calc(100% - 65px);"></div>
			</div>
			<div class="out-column" style="width:50%;height:100%;">
				<h4 class="tit-level3 pre">데이터 원본 정보</h4>
				<div class="panel-inner scrollbar">
					<div id="dataSourceDetailInfo" class="tbl data-form preferences-tbl">
						<table>
							<colgroup>
								<col style="width: 150px">
								<col style="width: 150px">
								<col style="width: 100px">
								<col style="width: auto">
							</colgroup>
							<tbody>
								<tr title="">
									<th>데이터원본 명</th>
									<td colspan="3" class="ipt"><input class="wise-text-input dataSource-id"
										type="text"></td>
								</tr>
								<tr title="">
									<th>서버 주소(명)</th>
									<td colspan="3" class="ipt"><input class="wise-text-input dataSource-name"
										type="text"></td>
								</tr>
								<tr title="데이터베이스 명을 지정해주세요.">
									<th>DB명</th>
									<td colspan="3" class="ipt"><input class="wise-text-input dataSource-dbName"
										type="text"></td>
								</tr>
								<tr title="DB 유형을 선택해주세요.">
									<th>DB 유형</th>
									<td class="ipt">
										<!-- 2021.02.09 syjin DB 유형 수정 -->
										<select class="group-name dataSource-type">
											<option value="" selected="selected" style="">DB 유형</option>
											<option value="MS-SQL" style="">MS-SQL</option>
											<!--  <option value="MS-SQL ExpressEdition" style="">MS-SQL ExpressEdition</option> -->
											<!--  <option value="MS Analysis Service" style="">MS Analysis Service</option> -->
											<option value="ORACLE" style="">ORACLE</option>
											<option value="TIBERO" style="">TIBERO (DBMS)</option>
											<!--  <option value="TIBERO (DBMS)" style="">TIBERO (DBMS)</option> -->
											<!--  <option value="TIBERO (Infini Data)" style="">TIBERO (Infini Data)</option> -->
											<option value="VERTICA" style="">VERTICA</option>
											<option value="MSPDW" style="">MSPDW</option>
											<option value="MySql" style="">MySql</option>
											<option value="Maria" style="">Maria</option>
											<!--  <option value="Infini DB" style="">Infini DB</option> -->
											<option value="DB2BLU" style="">DB2BLU</option>
											<!--  <option value="PetaSQL" style="">PetaSQL</option> -->
											<option value="POSTGRES" style="">POSTGRES</option>
											<option value="NETEZZA" style="">NETEZZA</option>
											<option value="SAPIQ" style="">SAPIQ</option>
											<!--  <option value="SAPASE" style="">SAPASE</option> -->
											<option value="CUBRID" style="">CUBRID</option>
											<option value="ALTIBASE" style="">ALTIBASE</option>
											<!--  <option value="GOLDILOCKS" style="">GOLDILOCKS</option> -->
											<option value="TERADATA" style="">TERADATA</option>
											<option value="IMPALA" style="">IMPALA</option>
										</select>
									</td>
									<th><span style="display:none;" id="span_connect1">접속 유형</span></th>
									<td class="ipt">
										<span style="display:none;" id="span_connect2">
											<select class="group-name connect-type" style="width:150px;">
												<option value="" selected="selected" style="">접속 유형</option>
												<option value="SID" style="">SID</option>
												<option value="SERVICE NAME" style="">ServiceName</option>
											</select>
										</span>
									</td>
								</tr>
								<tr title="DB 소유자를 입력해주세요.">
									<th>소유자</th>
									<td colspan="3" class="ipt"><input class="wise-text-input dataSource-owner"
										type="text"></td>
								</tr>
								<tr title="port 번호를 입력해주세요.">
									<th>Port</th>
									<td colspan="3" class="ipt"><input
										class="wise-text-input dataSource-port" type="text"></td>
								</tr>
								<tr>
									<th>접속 id</th>
									<td colspan="3" class="ipt"><input
										class="wise-text-input dataSource-accessId" type="text"></td>
								</tr>
								<tr>
									<th>접속 암호</th>
									<td colspan="3" class="ipt"><input
										class="wise-text-input dataSource-accessPw" type="password"></td>
								</tr>
<!-- 								<tr>
									<th>설명</th>
									<td class="ipt"><textarea class="wise-text-input datasource-desc"
											rows="4"></textarea></td>
								</tr> -->

								<tr>
									<!-- DOGFOOT syjin 연결 테스트 UI 버튼 추가  20210113 -->
									<td colspan="4"><div style="margin-left:31%;" id="accessTestBtn"></div></td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>