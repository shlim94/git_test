var userGroupManager = (function() {
	var users;
	var groups;
	/**
	 * Initialize functions for user page.
	 */
	function initUserLayout() {
		// user count indicator
		$('#userCount').text('사용자 (' + users.length + ' 명)');
		$('#groupCount').text('그룹 (' + groups.length + ' 개)');
		// group select list
		$.each(groups, function(i, group) {
			$('select.group-name').append('<option value="' + group.id + '">' + group.name + '</option>');
		});
		// user list
		$('#userList').dxDataGrid({
			dataSource: users,
			columns: [
				{
					dataField: "사용자 NO",
					visible: false, 
				},
				{
					dataField: "사용자 ID"
				},
				{
					dataField: "사용자 명"
				},
				{
					dataField: "그룹 명"
				}
			],
			keyExpr: "사용자 ID",
			visible: true,
			showColumnLines: true,
			showRowLines: true,
			rowAlternationEnabled: true,
			showBorders: true,
			/* goyong ktkang 환경설정 유저 부분 페이징 추가  20210527 */
			paging: {
				enabled: true
			},
			searchPanel: {
				visible: true
			},
			onInitialized: function(e) {
				$('.panel-head').on('click', function() {
					if ($(this).find('.select-category').data('category') === 'usrgrp-user') {
						e.component.updateDimensions();
					}
				});
			},
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForList('userList');
			},
			onSelectionChanged: function(e) {
				var selectedField = e.selectedRowsData[0];
				if (selectedField) {
					$('.ipt .user-id').val(selectedField['사용자 ID']).removeClass('error').addClass('success');
					$('.ipt .user-name').val(selectedField['사용자 명']).removeClass('error').addClass('success');
					$('.ipt .group-name').val(selectedField['그룹 ID']).removeClass('error').addClass('success');
					$('.ipt .user-run-mode').val(selectedField['사용자 실행모드']);
					$('.ipt .group-run-mode').val(selectedField['그룹 실행모드']);
					$('.ipt .user-ref-no').val(selectedField['참조코드']);
					$('.ipt .user-desc').val(selectedField['설명']);
				} else {
					$('.ipt .user-id').val('').removeClass('success').addClass('error');
					$('.ipt .user-name').val('').removeClass('success').addClass('error');
					$('.ipt .group-name').val('').removeClass('success').addClass('error');
					$('.ipt .user-run-mode').val('');
					$('.ipt .group-run-mode').val('');
					$('.ipt .user-ref-no').val('');
					$('.ipt .user-desc').val('');
				}
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			}
		});
		// group change event
		$('.ipt .group-name').on('change', function() {
			var grpId = $(this).val();
			for (var i = 0; i < groups.length; i++) {
				if (groups[i].id === parseInt(grpId)) {
					$('.ipt .group-run-mode').val(groups[i].runMode);
					break;
				}
			}
		});
		// fields are invalid by default
		$('.ipt .user-id').addClass('error');
		$('.ipt .user-name').addClass('error');
		/* DOGFOOT ktkang 그룹명 사용자 싱행 모드 필수 정보로 입력하도록 수정  20200629 */
		$('.ipt .group-name').addClass('error');
//		$('.ipt .user-run-mode').addClass('error');

		initUserInputValidation();
	}

	/**
	 * Initialize textbox input validation for user fields.
	 */
	function initUserInputValidation() {
		$('.ipt .user-id').on('input propertychange', function() {
			var userId = $(this).val();
			var selected = $('#userList').dxDataGrid('instance').getSelectedRowKeys()[0];
			var exists = false;
			$.each($('#userList').dxDataGrid('instance').option('dataSource'), function(i, user) {
				if (user['사용자 ID'] === userId) {
					exists = true;
					return false;
				}
			});

			if (userId.length > 0 && (userId === selected || !exists)) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
		$('.ipt .user-name').on('input propertychange', function() {
			var userName = $(this).val();
			if (userName.length > 0) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
		$('.ipt .group-name').on('input propertychange', function() {
			var groupName = $(this).val();
			if (groupName.length > 0) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
		
//		$('.ipt .user-run-mode').on('input propertychange', function() {
//			var userRunName = $(this).val();
//			if (userRunName.length > 0) {
//				$(this).removeClass('error').addClass('success');
//			} else {
//				$(this).removeClass('success').addClass('error');
//			}
//		});
	}

	/**
	 * Initialize functions for group page.
	 */
	function initGroupLayout() {
		$('#groupList').dxDataGrid({
			dataSource: groups,
			columns: [
				{
					caption: "그룹 명",
					dataField: "name"
				},
				{
					caption: "설명",
					dataField: "desc"
				}
			],
			keyExpr: "id",
			visible: true,
			showColumnLines: true,
			showRowLines: true,
			rowAlternationEnabled: true,
			showBorders: true,
			paging: {
				enabled: false
			},
			onInitialized: function(e) {
				$('.panel-head').on('click', function() {
					if ($(this).find('.select-category').data('category') === 'usrgrp-group') {
						e.component.updateDimensions();
					}
				});
			},
			onSelectionChanged: function(e) {
				var selectedField = e.selectedRowsData[0];
				if (selectedField) {
					$('.ipt .grp-name').val(selectedField.name).removeClass('error').addClass('success');
					$('.ipt .grp-desc').val(selectedField.desc);
					/* DOGFOOT ktkang 그룹명 사용자 싱행 모드 필수 정보로 입력하도록 수정  20200629 */
					$('.ipt .grp-run-mode').val(selectedField.runMode);
					$('.ipt .grp-rel-cd').val(selectedField.relCd);
					var usersInGroup = [];
					var usersNotInGroup = [];
					var selectedGroupId = selectedField.id;
					users.forEach(function(user) {
						if (user['그룹 ID'] === selectedGroupId) {
							usersInGroup.push(user);
						} else {
							usersNotInGroup.push(user);
						}
					});
					$('#usersInGroup').dxDataGrid('instance').option('dataSource', usersInGroup);
					$('#usersNotInGroup').dxDataGrid('instance').option('dataSource', usersNotInGroup);
				} else {
					$('.ipt .grp-name').val('').removeClass('success').addClass('error');
					$('.ipt .grp-desc').val('');
					/* DOGFOOT ktkang 그룹명 사용자 싱행 모드 필수 정보로 입력하도록 수정  20200629 */
					$('.ipt .grp-run-mode').val('');
					$('.ipt .grp-rel-cd').val('');
					$('#usersInGroup').dxDataGrid('instance').option('dataSource', []);
					$('#usersNotInGroup').dxDataGrid('instance').option('dataSource', users);
				}
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			},
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForList('groupList');
				gProgressbar.hide();
			}
		});

		$('#usersInGroup').dxDataGrid({
			columns: [
				{
					dataField: "사용자 NO",
					visible: false,
				},
				{
					dataField: '사용자 ID'
				},
				{
					dataField: '사용자 명'
				}
			],
			dataSource: [],
			keyExpr: "사용자 ID",
			visible: true,
			showColumnLines: true,
			columnAutoWidth: true,
			showRowLines: true,
			rowAlternationEnabled: true,
			showBorders: true,
			selection: {
				mode: 'multiple',
				showCheckBoxesMode: 'always'
			},
			/* goyong ktkang 환경설정 유저 부분 페이징 추가  20210527 */
			paging: {
				enabled: true
			},
			searchPanel: {
				visible: true
			},
			onInitialized: function(e) {
				$('.panel-head').on('click', function() {
					if ($(this).find('.select-category').data('category') === 'usrgrp-group') {
						e.component.updateDimensions();
					}
				});
			},
			onContentReady: function(e) {
				gDashboard.fontManager.setFontConfigForList('usersInGroup')
			}
		});

		$('#usersNotInGroup').dxDataGrid({
			columns: [
				{
					dataField: "사용자 NO",
					visible: false,
				},
				{
					dataField: '사용자 ID'
				},
				{
					dataField: '사용자 명'
				}
			],
			dataSource: users,
			keyExpr: "사용자 ID",
			visible: true,
			showColumnLines: true,
			columnAutoWidth: true,
			showRowLines: true,
			rowAlternationEnabled: true,
			showBorders: true,
			selection: {
				mode: 'multiple',
				showCheckBoxesMode: 'always'
			},
			paging: {
				enabled: false
			},
			onInitialized: function(e) {
				$('.panel-head').on('click', function() {
					if ($(this).find('.select-category').data('category') === 'usrgrp-group') {
						e.component.updateDimensions();
					}
				});
			},
			onContentReady: function(e) {
				gDashboard.fontManager.setFontConfigForList('usersNotInGroup')
			}
			
		});

		$('.btn-move-left').off('click').on('click', function() {
			var usersToSwitch = $('#usersNotInGroup').dxDataGrid('instance').getSelectedRowsData();
			var usersInGroup = $('#usersInGroup').dxDataGrid('instance').option('dataSource');
			var usersNotInGroup = $('#usersNotInGroup').dxDataGrid('instance').option('dataSource');
			$.each(usersToSwitch, function(i, user) {
				usersInGroup.push(user);
				for (var j = 0; j < usersNotInGroup.length; j++) {
					if (usersNotInGroup[j]['사용자 ID'] === user['사용자 ID']) {
						usersNotInGroup.splice(j, 1);
						break;
					}
				}
			});
			$('#usersInGroup').dxDataGrid('instance').option('dataSource', usersInGroup);
			$('#usersNotInGroup').dxDataGrid('instance').option('dataSource', usersNotInGroup);
		});

		$('.btn-move-right').off('click').on('click', function() {
			var usersToSwitch = $('#usersInGroup').dxDataGrid('instance').getSelectedRowsData();
			var usersInGroup = $('#usersInGroup').dxDataGrid('instance').option('dataSource');
			var usersNotInGroup = $('#usersNotInGroup').dxDataGrid('instance').option('dataSource');
			$.each(usersToSwitch, function(i, user) {
				usersNotInGroup.push(user);
				for (var j = 0; j < usersInGroup.length; j++) {
					if (usersInGroup[j]['사용자 ID'] === user['사용자 ID']) {
						usersInGroup.splice(j, 1);
						break;
					}
				}
			});
			$('#usersInGroup').dxDataGrid('instance').option('dataSource', usersInGroup);
			$('#usersNotInGroup').dxDataGrid('instance').option('dataSource', usersNotInGroup);
		});
		// fields are invalid by default
		$('.ipt .grp-name').addClass('error');
		initGroupInputValidation();
	}

	/**
	 * Initialize textbox input validation for group fields.
	 */
	function initGroupInputValidation() {
		$('.ipt .grp-name').on('input propertychange', function() {
			var grpName = $(this).val();
			var selected = $('#groupList').dxDataGrid('instance').getSelectedRowKeys()[0];
			var exists = false;
			$.each($('#groupList').dxDataGrid('instance').option('dataSource'), function(i, group) {
				if (group.name === grpName) {
					exists = true;
					return false;
				}
			});

			if (grpName.length > 0 && (grpName === selected || !exists)) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
	}

	/**
	 * Helper function. Update all widgets that contain users.
	 * @param {Object[]} users list of users
	 */
	function updateUsers() {
		$('#userList').dxDataGrid('instance').option('dataSource', users);
		$('#userList').dxDataGrid('instance').refresh();
		var selectedUserID = $('#userList').dxDataGrid('instance').getSelectedRowKeys()[0];
		if (selectedUserID) {
			for (var i = 0; i < users.length; i++) {
				if (users[i]['사용자 ID'] === selectedUserID) {
					$('.ipt .user-id').val(users[i]['사용자 ID']).removeClass('error').addClass('success');
					$('.ipt .user-name').val(users[i]['사용자 명']).removeClass('error').addClass('success');
					/* DOGFOOT ktkang 그룹명 사용자 싱행 모드 필수 정보로 입력하도록 수정  20200629 */
					$('.ipt .group-name').val(users[i]['그룹 ID']).removeClass('error').addClass('success');
					$('.ipt .user-run-mode').val(users[i]['사용자 실행모드']);
					$('.ipt .group-run-mode').val(users[i]['그룹 실행모드']);
					$('.ipt .user-ref-no').val(users[i]['참조코드']);
					$('.ipt .user-desc').val(users[i]['설명']);
					break;
				}
			}
		}
		var selectedGroupID = $('#groupList').dxDataGrid('instance').getSelectedRowKeys()[0];
		if (selectedGroupID) {
			var usersInGroup = [];
			var usersNotInGroup = [];
			$.each(users, function(i, user) {
				if (user['그룹 ID'] === selectedGroupID) {
					usersInGroup.push(user);
				} else {
					usersNotInGroup.push(user);
				}
			});
			$('#usersInGroup').dxDataGrid('instance').option('dataSource', usersInGroup);
			$('#usersNotInGroup').dxDataGrid('instance').option('dataSource', usersNotInGroup);
		} else {
			$('#usersInGroup').dxDataGrid('instance').option('dataSource', []);
			$('#usersNotInGroup').dxDataGrid('instance').option('dataSource', users);
		}
	}

	/**
	 * Helper function. Update all widgets that contain groups.
	 */
	function updateGroupsAndUsers() {
		$('#groupList').dxDataGrid('instance').option('dataSource', groups);
		$('#groupList').dxDataGrid('instance').refresh();
		var selectedGroupID = $('#groupList').dxDataGrid('instance').getSelectedRowKeys()[0];
		if (selectedGroupID) {
			for (var i = 0; i < groups.length; i++) {
				if (groups[i].name === selectedGroupID) {
					$('.ipt .grp-name').val(groups[i].name).removeClass('error').addClass('success');
					$('.ipt .grp-desc').val(groups[i].desc);
					$('.ipt .grp-run-mode').val(groups[i].runMode);
					$('.ipt .grp-rel-cd').val(groups[i].relCd);
					break;
				}
			}
		}
		$('select.group-name').empty();
		$.each(groups, function(i, group) {
			$('select.group-name').append('<option value="' + group.id + '">' + group.name + '</option>');
		});
		$.ajax({
			url: WISE.Constants.context + '/report/getUserList.do',
			async: false,
			success: function(data) {
				users = JSON.parse(data).users;
				updateUsers();
			}
		});
	}

	/* private methods */
	return {
		/**
		 * Main.
		 */
		initUserGroup: function() {
			$.ajax({
				url: WISE.Constants.context + '/report/getUserList.do',
				async: false,
				success: function(data) {
					users = JSON.parse(data).users;
				}
			});
			$.ajax({
				url: WISE.Constants.context + '/report/getGroupList.do',
				async: false,
				success: function(data) {
					groups = JSON.parse(data).groups;
				}
			});

			initUserLayout();
			initGroupLayout();
		},

		/**
		 * Refresh user/group page.
		 * @listens click
		 */
		handleUserGroupRefresh: function() {
			gProgressbar.show();
			updateGroupsAndUsers();
		},

		/**
		 * Clear user info fields.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handleUserCreate: function(event) {
			event.preventDefault();
			$('#userList').dxDataGrid('instance').clearSelection();
			$('.ipt .user-id').val('').removeClass('success').addClass('error');
			$('.ipt .user-name').val('').removeClass('success').addClass('error');
			/* DOGFOOT ktkang 그룹명 사용자 싱행 모드 필수 정보로 입력하도록 수정  20200629 */
			$('.ipt .group-name').val('').removeClass('success').addClass('error');
			$('.ipt .user-run-mode').val('');
			$('.ipt .group-run-mode').val('');
			$('.ipt .user-ref-no').val('');
			$('.ipt .user-desc').val('');
		},

		/**
		 * Save user info fields to new user. If user in user list is selected, save info to selected user.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handleUserSave: function(event) {
			event.preventDefault();
			var selectedUser = $('#userList').dxDataGrid('instance').option('selectedRowKeys')[0];
			var invalidFieldCount = $('#userDetailedInfo input.error').length;
			if (invalidFieldCount === 0) {
				if (!selectedUser) {
					$('#pwPopup').dxPopup({
						title: '비밀번호 만들기',
						/* DOGFOOT ktkang 창 크기 조절  20200629 */
						 height: 'auto',
						 width: 'auto',
						contentTemplate: function(e) {
							var html = 	'<div class="tbl data-form">' +
											'<table>' +
												'<colgroup class="pw-form-col">' +
													'<col style="width: 150px;">' +
												'</colgroup>' +
												'<tbody>' +
													'<tr>' +
														'<th>비밀번호</th>' +
														'<td class="ipt">' +
															'<input class="wise-text-input new-user-pw" type="password" autocomplete="false">' +
														'</td>' +
													'</tr>' +
													'<tr>' +
														'<th>비밀번호 확인</th>' +
														'<td class="ipt">' +
															'<input class="wise-text-input new-user-pw-confirm" type="password" autocomplete="false">' +
														'</td>' +
													'</tr>' +
												'</tbody>' +
											'</table>' +
										'</div>' +
										'<div class="row center popup-footer pw-maker-confirm">' +
											'<a href="#" class="btn positive pw-maker-ok">확인</a>' +
											'<a href="#" class="btn neutral pw-maker-cancel">취소</a>' +
										'</div>';
							e.append(html);
						},
						onContentReady: function(e) {
							$('.btn.pw-maker-ok').on('click', function() {
								var pw = $('.new-user-pw').val();
								var pwConfirm = $('.new-user-pw-confirm').val();
								if (pw.length > 0 && pw === pwConfirm) {
									$.ajax({
										url: WISE.Constants.context + '/report/insertUserInfo.do',
										async: false,
										method: 'POST',
										data: {
											newUserId: $('.ipt .user-id').val(),
											newUserName: $('.ipt .user-name').val(),
											newUserPw: pw,
											newGroupId: $('.ipt .group-name').val(),
											newUserRunMode: $('.ipt .user-run-mode').val(),
											newUserRefNo: $('.ipt .user-ref-no').val(),
											newUserDesc: $('.ipt .user-desc').val()
										},
										success: function(newData) {
											var error = JSON.parse(newData).error;
											if (error) {
												//2020.01.21 mksong 경고창 타입 지정 dogfoot
												WISE.alert(error,'error');
											} else {
												users = JSON.parse(newData).users;
												updateUsers();
												e.component.hide();
												//2020.01.21 mksong 경고창 타입 지정 dogfoot
												WISE.alert(gMessage.get('config.user.create.success'),'success');
											}
										},
										error: function() {
											//2020.01.21 mksong 경고창 타입 지정 dogfoot
											WISE.alert(gMessage.get('config.save.failed'),'error');
										}
									});
								} else {
									//2020.01.21 mksong 경고창 타입 지정 dogfoot
									WISE.alert(gMessage.get('config.password.incorrect'),'error');
								}
							});
							$('.btn.pw-maker-cancel').on('click', function() {
								$('.new-user-pw').val('');
								$('.new-user-pw-confirm').val('');
								e.component.hide();
							});
						}
					}).dxPopup('instance').show();
				} else {
					$.ajax({
						url: WISE.Constants.context + '/report/updateUserInfo.do',
						async: false,
						method: 'POST',
						data: {
							selectedUser: selectedUser,
							newUserId: $('.ipt .user-id').val(),
							newUserName: $('.ipt .user-name').val(),
							newGroupId: $('.ipt .group-name').val(),
							newUserRunMode: $('.ipt .user-run-mode').val(),
							newUserRefNo: $('.ipt .user-ref-no').val(),
							newUserDesc: $('.ipt .user-desc').val()
						},
						success: function(newData) {
							var error = JSON.parse(newData).error;
							if (error) {
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(error,'error');
							} else {
								users = JSON.parse(newData).users;
								updateUsers();
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.save.success'),'success');
							}
						},
						error: function() {
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.save.failed'),'error');
						}
					});
				}
			} else {
				WISE.alert(gMessage.get('config.critical.items'));
			}
		},

		/**
		 * Deletes selected user in user list.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handleUserDelete: function(event) {
			event.preventDefault();
			var selectedUser = $('#userList').dxDataGrid('instance').option('selectedRowKeys')[0];
			if (selectedUser) {
				$('#pwPopup').dxPopup({
					title: '사용자 삭제',
					/* DOGFOOT ktkang 창 크기 조절  20200629 */
					 height: 'auto',
					 width: 'auto',
					contentTemplate: function(e) {
						var html = 	'<p>사용자 "' + selectedUser + '"를 삭제 하시겠습니까?</p>' +
									'<div class="row center popup-footer user-delete-confirmation">' +
										'<a href="#" class="btn positive user-delete-confirm">확인</a>' +
										'<a href="#" class="btn neutral user-delete-cancel">취소</a>' +
									'</div>';
						e.append(html);
					},
					onContentReady: function(e) {
						$('.user-delete-confirm').on('click', function() {
							$.ajax({
								url: WISE.Constants.context + '/report/deleteUserInfo.do',
								method: 'POST',
								data: {
									user: selectedUser,
								},
								async: false,
								success: function(newData) {
									users = JSON.parse(newData).users;
									updateUsers();
									//2020.01.21 mksong 경고창 타입 지정 dogfoot
									WISE.alert(gMessage.get('config.delete.success'),'success');
									e.component.hide();
								},
								error: function() {
									//2020.01.21 mksong 경고창 타입 지정 dogfoot
									WISE.alert(gMessage.get('config.delete.failed'),'error');
								}
							});
						});
						$('.user-delete-cancel').on('click', function() {
							e.component.hide();
						});
					}
				}).dxPopup('instance').show();
			}
		},
		/**
		 * Change a user's password to a new one.
		 * @param {MouseEvent} event
		 * @listens click
		 */
		handleUserChangePassword: function(event) {
			event.preventDefault();
			var selectedUser = $('#userList').dxDataGrid('instance').option('selectedRowKeys')[0];
			if (selectedUser) {
				$('#pwPopup').dxPopup({
					title: '비밀번호 변경',
					/* DOGFOOT ktkang 창 크기 조절  20200629 */
					 height: 'auto',
					 width: 'auto',
					contentTemplate: function(e) {
						var html = 	'<div class="tbl data-form">' +
										'<table>' +
											'<colgroup class="pw-form-col">' +
												'<col style="width: 150px;">' +
											'</colgroup>' +
											'<tbody>' +
												'<tr>' +
													'<th>현제 비밀번호</th>' +
													'<td class="ipt">' +
														'<input class="wise-text-input change-user-pw-old" type="password" autocomplete="false">' +
													'</td>' +
												'</tr>' +
												'<tr>' +
													'<th>새 비밀번호</th>' +
													'<td class="ipt">' +
														'<input class="wise-text-input change-user-pw-new" type="password" autocomplete="false">' +
													'</td>' +
												'</tr>' +
												'<tr>' +
													'<th>비밀번호 확인</th>' +
													'<td class="ipt">' +
														'<input class="wise-text-input change-user-pw-confirm" type="password" autocomplete="false">' +
													'</td>' +
												'</tr>' +
											'</tbody>' +
										'</table>' +
									'</div>' +
									'<div class="row center popup-footer pw-checker-confirm">' +
										'<a href="#" class="btn positive pw-changer-ok">확인</a>' +
										'<a href="#" class="btn neutral pw-changer-cancel">취소</a>' +
									'</div>';
						e.append(html);
					},
					onContentReady: function(e) {
						$('.btn.pw-changer-ok').on('click', function() {
							var oldPw = $('.change-user-pw-old').val();
							var newPw = $('.change-user-pw-new').val();
							var confirmPw = $('.change-user-pw-confirm').val();
							if (newPw.length > 0 && newPw === confirmPw) {
								$.ajax({
									url: WISE.Constants.context + '/report/changePassword.do',
									method: 'POST',
									data: {
										user: selectedUser,
										oldPw: oldPw,
										newPw: newPw,
									},
									async: false,
									success: function(status) {
										var error = JSON.parse(status).error;
										if (error) {
											//2020.01.21 mksong 경고창 타입 지정 dogfoot
											WISE.alert(error,'error');
										} else {
											//2020.01.21 mksong 경고창 타입 지정 dogfoot
											WISE.alert(gMessage.get('config.password.change.success'),'success');
											e.component.hide();
										}
									},
									error: function() {
										//2020.01.21 mksong 경고창 타입 지정 dogfoot
										WISE.alert(gMessage.get('config.password.change.failed'),'error');
									}
								});
							} else {
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.password.incorrect'),'error');
							}
						});
						$('.btn.pw-changer-cancel').on('click', function() {
							$('.change-user-pw-old').val('');
							$('.change-user-pw-new').val('');
							$('.change-user-pw-confirm').val('');
							e.component.hide();
						});
					}
				}).dxPopup('instance').show();
			}
		},

		/**
		 * Clear group info fields.
		 * @param {MouseEvent} event
		 * @listens click
		 */
		handleGroupCreate: function(event) {
			event.preventDefault();
			$('#groupList').dxDataGrid('instance').clearSelection();
			$('.ipt .grp-name').val('').removeClass('success').addClass('error');
			$('.ipt .grp-desc').val('');
			$('.ipt .grp-run-mode').val('');
			$('.ipt .grp-rel-cd').val('');
		},

		/**
		 * Save user info fields to new user. If user in user list is selected, save info to selected user.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handleGroupSave: function(event) {
			event.preventDefault();
			var selectedGroup = $('#groupList').dxDataGrid('instance').getSelectedRowsData()[0];
			var invalidFieldCount = $('#groupDetailedInfo input.error').length;
			var usersInGroup = $('#usersInGroup').dxDataGrid('instance').option('dataSource');
			var selectedUsers = [];
			$.each(usersInGroup, function(i, user) {
				selectedUsers.push(user['사용자 NO']);
			});
			if (invalidFieldCount === 0) {
				if (!selectedGroup) {
					$.ajax({
						url: WISE.Constants.context + '/report/insertGroupInfo.do',
						async: false,
						method: 'POST',
						data: {
							newGroupName: $('.ipt .grp-name').val(),
							newGroupRunMode: $('.ipt .grp-run-mode').val(),
							newGroupRelCd: $('.ipt .grp-rel-cd').val(),
							newGroupDesc: $('.ipt .grp-desc').val(),
							selectedUsers: selectedUsers
						},
						success: function(newData) {
							var error = JSON.parse(newData).error;
							if (error) {
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(error,'error');
							} else {
								groups = JSON.parse(newData).groups;
								updateGroupsAndUsers();
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.save.success'),'success');
							}
						},
						error: function() {
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.save.failed'),'error');
						}
					});
				} else {
					$.ajax({
						url: WISE.Constants.context + '/report/updateGroupInfo.do',
						async: false,
						method: 'POST',
						data: {
							selectedGroup: selectedGroup.id,
							selectedGroupName: selectedGroup.name,
							newGroupName: $('.ipt .grp-name').val(),
							newGroupRunMode: $('.ipt .grp-run-mode').val(),
							newGroupRelCd: $('.ipt .grp-rel-cd').val(),
							newGroupDesc: $('.ipt .grp-desc').val(),
							selectedUsers: selectedUsers
						},
						success: function(newData) {
							var error = JSON.parse(newData).error;
							if (error) {
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(error,'error');
							} else {
								groups = JSON.parse(newData).groups;
								updateGroupsAndUsers();
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.save.success'),'success');
							}
						},
						error: function() {
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.save.failed'),'error');
						}
					});
				}
			} else {
				WISE.alert(gMessage.get('config.critical.items'));
			}
		},

		/**
		 * Delete selected group from group list.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handleGroupDelete: function(event) {
			event.preventDefault();
			var confirmOk
			WISE.confirm(
				'선택하신 그룹을 삭제하시겠습니까?', 
				{
					buttons: {
						confirm: {
							id: 'confirm',
							className: 'green',
							text: '확인',
							action: function() {
								$AlertPopup.hide();
								var selectedGroup = $('#groupList').dxDataGrid('instance').getSelectedRowsData()[0];
								if (selectedGroup) {
									$.ajax({
										url: WISE.Constants.context + '/report/deleteGroupInfo.do',
										method: 'POST',
										data: {
											groupId: selectedGroup.id,
										},
										async: false,
										success: function(newData) {
											var error = JSON.parse(newData).error;
											if (error) {
												//2020.01.21 mksong 경고창 타입 지정 dogfoot
												WISE.alert(error,'error');
											} else {
												groups = JSON.parse(newData).groups;
												updateGroupsAndUsers();
												$('#groupList').dxDataGrid('instance').clearSelection();
												//2020.01.21 mksong 경고창 타입 지정 dogfoot
												WISE.alert(gMessage.get('config.delete.success'),'success');
											}
										},
										error: function() {
											//2020.01.21 mksong 경고창 타입 지정 dogfoot
											WISE.alert(gMessage.get('config.delete.failed'),'error');
										}
									});
								}
							}
						},
						cancel: {
							id: 'cancel',
							className: 'negative',
							text: '취소',
							action: function() {confirmOk = false; $AlertPopup.hide(); }
						}
					}
				}
			);
		}
	}
})();