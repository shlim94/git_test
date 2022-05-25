<%@ page language="java" contentType="text/html; charset=utf-8"
	pageEncoding="utf-8"%>
<div id="userGroupPage">
	<!-- USER TAB -->
	<div class="tab-container" id="userManagerTab">
		<div id="pwPopup"></div>
		<div class="out-row">
			<div class="out-column" style="width:30%;height:100%;border-right:1px solid #e7e7e7;">
				<h4 class="tit-level3 pre" id="userCount"></h4>
				<div id="userList"></div>
			</div>
			<div class="out-column" style="width:70%;height:100%;">
				<h4 class="tit-level3 pre">사용자 정보</h4>
				<div class="panel-inner scrollbar">
					<div id="userDetailedInfo" class="tbl data-form preferences-tbl">
						<table>
							<colgroup>
								<col style="width: 150px">
								<col style="width: auto">
							</colgroup>
							<tbody>
								<tr title="빈값이나 정복이름은 가능하지 않습니다.">
									<th>사용자 ID*</th>
									<td class="ipt"><input class="wise-text-input user-id"
										type="text"></td>
								</tr>
								<tr title="빈값은 가능하지 않습니다.">
									<th>사용자 명*</th>
									<td class="ipt"><input class="wise-text-input user-name"
										type="text"></td>
								</tr>
								<tr>
									<th>그룹 명*</th>
									<td class="ipt"><select class="group-name">
											<option value="" selected="selected" style="display: none;"></option>
									</select></td>
								</tr>
								<tr>
									<th>사용자 실행모드</th>
									<td class="ipt"><select class="user-run-mode">
											<option value="" selected="selected" style="display: none;"></option>
											<option value="ADMIN">Admin</option>
											<option value="VIEW">View</option>
											<option value=""></option>
									</select></td>
								</tr>
								<tr>
									<th>그룹 실행모드</th>
									<td class="ipt"><select class="group-run-mode" disabled>
											<option value="" selected="selected" style="display: none;"></option>
											<option value="ADMIN">Admin</option>
											<option value="VIEW">View</option>
									</select></td>
								</tr>
								<tr>
									<th>참조코드</th>
									<td class="ipt"><input class="wise-text-input user-ref-no"
										type="text"></td>
								</tr>
								<tr>
									<th>설명</th>
									<td class="ipt"><textarea class="wise-text-input user-desc"
											rows="4"></textarea></td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</div>
	<!-- GROUP TAB -->
	<div class="tab-container" id="groupManagerTab">
		<div class="out-row">
			<div class="out-column" style="width:30%;height:100%;border-right:1px solid #e7e7e7;">
				<h4 class="tit-level3 pre" id="groupCount"></h4>
				<div id="groupList"></div>
			</div>
			<div class="out-column" style="width:70%;height:100%;">
				<div class="row horizen col-2" style="height:100%;">
					<div class="column" style="height:50%;border-bottom:1px solid #e7e7e7;">
						<h4 class="tit-level3 pre">그룹 정보</h4>
						<div id="groupDetailedInfo" class="tbl data-form preferences-tbl">
							<table>
								<colgroup>
									<col style="width: 150px">
									<col style="width: auto">
								</colgroup>
								<tbody>
									<tr>
										<th>그룹 명*</th>
										<td class="ipt">
											<input class="wise-text-input grp-name" type="text">
										</td>
									</tr>
									<tr>
										<th>설명</th>
										<td class="ipt">
											<textarea class="wise-text-input grp-desc"rows="4"></textarea>
										</td>
									</tr>
									<tr>
										<th>그룹 실행모드</th>
										<td class="ipt">
											<select class="grp-run-mode">
												<option value="" selected="selected" style="display: none;"></option>
												<option value="ADMIN">Admin</option>
												<option value="VIEW">View</option>
											</select>
										</td>
									</tr>
									<tr>
										<th>참조코드</th>
										<td class="ipt">
											<input class="wise-text-input grp-rel-cd" type="text">
										</td>
									</tr>
								</tbody>
							</table>
						</div>
					</div>
					<div class="column" style="height:50%;">
						<div class="row multi-table" style="height:100%;">
							<div class="column" style="width:50%;border-right:1px solid #e7e7e7;">
								<h4 class="tit-level3 pre">그룹소속사용자</h4>
								<div id="usersInGroup"></div>
			                    <button class="btn-move-left" type="button">move left</button>
			                    <button class="btn-move-right" type="button">move right</button>
							</div>
							<div class="column" style="width:50%;">
								<h4 class="tit-level3 pre">사용자목록</h4>
								<div id="usersNotInGroup"></div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>