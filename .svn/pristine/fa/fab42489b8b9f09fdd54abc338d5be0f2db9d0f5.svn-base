var sessionManager = (function() {
	/* private variables */
	var processList = [];
	var selectedPID;

	var initCurrentSql = function() {	
		var datasourceForm = $('#datasourceForm').dxForm({
            width: "100%",
            height: "100%",
            readOnly: true,
            formData: {},
            items: [{
                dataField: 'DS_NM',
                label: {
                    text: "데이터 원본 명",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'IP',
                label: {
                    text: "서버 주소(명)",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'DB_NM',
                label: {
                    text: "DB 명",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'DBMS_TYPE',
                label: {
                    text: "DB 유형",
                },
                editorOptions: {
                    readOnly: true
                }
            }],			
		}).dxForm('instance');
		
		var sessionQuery = $('#sessionQuery').dxTextArea({
			height: "100%",
			readOnly: true
		}).dxTextArea('instance');		

		var sessionGrid = $('#sessionGrid').dxDataGrid({
			columns:[
				{
					dataField: 'RUNTIME',
					label: {
                    	text: "진행 시간"
					},
					width: "15%",
					sortOrder: 'desc'
				},
				{
					dataField: 'SESSION_ID',
					label: {
                    	text: "세션 ID"
					},
					width: "15%"
				},
				{
					dataField: 'SQL_TEXT',
					label: {
                    	text: "진행 중인 작업"
					},
					width: "50%"
				},
				{
					dataField: 'WAIT_INFO',
					label: {
                    	text: "상태"
					},
					width: "20%"
				}
			],
			visible:true,
			showColumnLines: true,
			showRowLines: true,
			rowAlternationEnabled: true,
			showBorders: true,
			columnAutoWidth: true,
			loadPanel: {
				enabled: false
			},
			editing: {
				mode: 'row',
				allowDeleting: true,
				useIcons: true,
				texts: {
					confirmDeleteMessage: ''
				}
			},
            selection: {
                mode:'single'
            },			
            onSelectionChanged: function (selectedItems) {
				if(!$.isEmptyObject(selectedItems.selectedRowsData[0])) {
                	sessionQuery.option("value", selectedItems.selectedRowsData[0].SQL_TEXT);
				}
            },
			onRowRemoving: function(e) {
				e.component.selectRowsByIndexes(e.rowIndex);
				selectedPID = e.data['SESSION_ID'];
				stopProcess();
				sessionQuery.option("value", "");
			},
			paging: {
				enabled: true
			},
			onInitialized: function(e) {
				$('.panel-head').on('click', function() {
					if ($(this).find('.select-category').data('category') === 'session-job') {
						e.component.updateDimensions();
					}
				});
			},
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForList('sessionGrid');
				gProgressbar.hide();
			}
		}).dxDataGrid('instance');
		
		var datasourceGrid = $('#datasourceGrid').dxDataGrid({
            width: "100%",
            height: "100%",
            showBorders: true,
            paging: {
                pageSize: 20
            },
            visible : true,
            columnAutoWidth: true,
            allowColumnResizing: true,
            selection: {
                mode:'single'
            },
            onSelectionChanged: function (selectedItems) {
                datasourceForm.option("formData", selectedItems.selectedRowsData[0]);
				sessionQuery.option("value", "");
				sessionManager.handleCurrentSqlRefresh();
            },
            columns: [{
                dataField: 'DS_NM',
                caption: '데이터 원본 명', 
                width: '40%',
            }, {
                dataField: 'IP',
                caption: '서버 주소(명)',
                width: '25%',
            }, {
                dataField: 'OWNER_NM',
                caption: '소유자',
                width: '15%',
            }, {
                dataField: 'DBMS_TYPE',
                caption: 'DB 유형',
                width: '10%',
            }],
            onContentReady: function(e){
				e.component.selectRowsByIndexes([0]);
            },
		}).dxDataGrid('instance');
		
        $.ajax({
            method: 'GET',
            url: WISE.Constants.context + '/report/datasourceList.do',
            data: {
                userNo: userJsonObject.userNo
            },
            beforeSend: function() {
                gProgressbar.show();
            },
            complete: function() {
                gProgressbar.hide();
            },
            success: function(result) {
                if (result.status === 200) {
                    datasourceGrid.option('dataSource', result.data);
                } else {
                    WISE.alert(result.status);
                }
            },
            error: function() {
                WISE.alert(gMessage.get('WISE.message.page.500.m1'));
            }
        });
		
		var stopProcess = function() {
			var selected = $('#datasourceGrid').dxDataGrid('instance').getSelectedRowsData()[0];
			if(selected) {			
				$.ajax({
					url: './stopProcess.do',
					async: false,
					data: {SESSION_ID: selectedPID, DS_ID: selected.DS_ID},
					success: function(_data) {
						//2020.01.21 mksong 경고창 타입 지정 dogfoot
						WISE.alert(gMessage.get('config.stop.process.success'),'success');
						sessionManager.handleCurrentSqlRefresh();
					},
					error: function() {
						//2020.01.21 mksong 경고창 타입 지정 dogfoot
						WISE.alert(gMessage.get('config.stop.process.failed'),'error');
					}
				});
			}
		};
		sessionManager.handleCurrentSqlRefresh();
	}

	function initUserSession() {
		var columnOrder = [
			{
				dataField: '사용자 ID'
			},
			{
				dataField: '사용자 No'
			},
			{
				dataField: '로그 유형'
			},
			{
				dataField: '접속 IP'
			},
			{
				dataField: '일시'
			},
			{
				dataField: '수정자 ID'
			},
			{
				dataField: '사용자 세션 키'
			}
		];
		$('#userGrid').dxDataGrid({
			columns: columnOrder,
			visible: true,
			showColumnLines: true,
			showRowLines: true,
			rowAlternationEnabled: true,
			showBorders: true,
			columnAutoWidth: true,
			keyExpr: '사용자 No',
			loadPanel: {
				enabled: false
			},
			selectionMode: {
				mode: 'single'
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			},
			paging: {
				enabled: true
			},
			onInitialized: function(e) {
				$('.panel-head').on('click', function() {
					if ($(this).find('.select-category').data('category') === 'session-users') {
						e.component.updateDimensions();
					}
				});
			},
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForList('userGrid');
				gProgressbar.hide();
			}
		});
		$('#logoutPopup').dxPopup({
			title: '로그아웃 확인',
			width: 500,
			height: 'auto',
			contentTemplate: function(e) {
				var html = 	'<p id="logoutConfirmText"></p>' +
							'<div class="row center popup-footer">' +
								'<a href="#" class="btn positive logout-ok">확인</a>' +
								'<a href="#" class="btn neutral logout-cancel">취소</a>' +
							'</div>';
				e.append(html);
			},
			onContentReady: function(e) {
				$('.logout-ok').on('click', function() {
					e.component.hide();
				});
				$('.logout-cancel').on('click', function() {
					e.component.hide();
				});
			}
		});
		sessionManager.handleUserRefresh();
	}

	function initInactiveUserSession() {
		var columnOrder = [
			{
				dataField: '사용자 ID'
			},
			{
				dataField: '사용자 No'
			},
			{
				dataField: '로그 유형'
			},
			{
				dataField: '접속 IP'
			},
			{
				dataField: '일시'
			},
			{
				dataField: '수정자 ID'
			},
			{
				dataField: '사용자 세션 키'
			},
			{
				dataField: '미사용 기간'
			}
		];
		$('#inactiveUserGrid').dxDataGrid({
			columns: columnOrder,
			visible: true,
			showColumnLines: true,
			showRowLines: true,
			rowAlternationEnabled: true,
			showBorders: true,
			columnAutoWidth: true,
			keyExpr: '사용자 No',
			loadPanel: {
				enabled: false
			},
			selectionMode: {
				mode: 'single'
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			},
			paging: {
				enabled: true
			},
			onInitialized: function(e) {
				$('.panel-head').on('click', function() {
					if ($(this).find('.select-category').data('category') === 'session-inactive-users') {
						e.component.updateDimensions();
					}
				});
			},
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForList('inactiveUserGrid');
				gProgressbar.hide();
			}
		});
		sessionManager.handleInactiveUserRefresh();
	}

	function initLockedUserSession() {
		var columnOrder = [
			{
				dataField: '사용자 No'
			},
			{
				dataField: '사용자 ID'
			},
			{
				dataField: '사용자 명'
			},
			{
				dataField: '그룹 명'
			},
			{
				dataField: '실행 타입'
			}
		];
		$('#lockedUserGrid').dxDataGrid({
			columns: columnOrder,
			visible: true,
			showColumnLines: true,
			showRowLines: true,
			rowAlternationEnabled: true,
			showBorders: true,
			columnAutoWidth: true,
			keyExpr: '사용자 No',
			loadPanel: {
				enabled: false
			},
			selectionMode: {
				mode: 'single'
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			},
			paging: {
				enabled: true
			},
			onInitialized: function(e) {
				$('.panel-head').on('click', function() {
					if ($(this).find('.select-category').data('category') === 'session-locked-users') {
						e.component.updateDimensions();
					}
				});
			},
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForList('lockedUserGrid');
				gProgressbar.hide();
			}
		});
		sessionManager.handleLockedUserRefresh();
	}

	return {
		/**
		 * Main.
		 */
		initSession: function() {
			initCurrentSql();
			initUserSession();
			initInactiveUserSession();
			initLockedUserSession();
		},

		/**
		 * Initialize login/logout session filters.
		 */
		initSessionLoginFilter: function() {
			$('#filterContainer').append(
				'<div id="startDate"></div>' +
				'<h1 class="tit-config date-tilde">~</h1>' +
				'<div id="endDate"></div>' +
				'<div id="logStatus"></div>'
			).show();
			/* DOGFOOT HSSHIM 200107 환경설정 필터바 UI 수정 */
			$('#filterContainer').css('width', 'calc(100% - 154px)');
			$('#startDate').dxDateBox({
				value: new Date(),
				displayFormat: "yyyy/MM/dd"
			});
			$('#endDate').dxDateBox({
				value: new Date(),
				displayFormat: "yyyy/MM/dd"
			});
			$('#logStatus').dxSelectBox({
				items: ['All', 'LOGIN', 'LOGOUT'],
				value: 'All'
			});
		},

		/**
		 * Initialize user name/ID session filters.
		 */
		initSessionUserFilter: function() {
			$('#filterContainer').append(
				'<div id="idNo"></div>' +
				'<div id="idNoFilter"></div>'
			).show();
			/* DOGFOOT HSSHIM 200107 환경설정 필터바 UI 수정 */
			$('#filterContainer').css('width', 'calc(100% - 154px)');
			$('#idNo').dxSelectBox({
				items: ['USER_ID', 'USER_NO'],
				value: 'USER_ID'
			});
			$('#idNoFilter').dxTextBox({
				value: ''
			});
		},

		handleCurrentSqlRefresh: function() {
			var selected = $('#datasourceGrid').dxDataGrid('instance').getSelectedRowsData()[0];
			if(selected) {
				$.ajax({
					url: WISE.Constants.context + '/report/getCurrentProcesses.do?ds_id='+selected.DS_ID,
					beforeSend: function() {
						gProgressbar.show();
					},
					success: function(_data){
						processList = JSON.parse(_data)['sqlResult'];
						$('#sessionGrid').dxDataGrid('instance').option('dataSource', processList);
					},
					error: function() {
						//2020.01.21 mksong 경고창 타입 지정 dogfoot
						WISE.alert(gMessage.get('config.refresh.failed'),'error');
					}
				});
			}
		},

		handleUserRefresh: function() {
			var startDate, endDate, logStatus;
			if ($('#sessionUserTab').css('display') !== 'none' && $('#filterContainer').children().length > 0) {
				startDate = moment($('#startDate').dxDateBox('instance').option('value')).format('YYYYMMDD');
				endDate = moment($('#endDate').dxDateBox('instance').option('value')).format('YYYYMMDD');
				logStatus = $('#logStatus').dxSelectBox('instance').option('value');
			} else {
				startDate = moment().format('YYYYMMDD');
				endDate = moment().format('YYYYMMDD');
				logStatus = 'All';
			}
			$.ajax({
				url: WISE.Constants.context + '/report/getUserSession.do',
				data: {
					startdate: startDate,
					enddate: endDate,
					logstatus: logStatus
				},
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(data) {
					var sessions = JSON.parse(data).sessions;
					$('#userGrid').dxDataGrid('instance').option('dataSource', sessions);
				},
				error: function() {
					//2020.01.21 mksong 경고창 타입 지정 dogfoot
					WISE.alert(gMessage.get('config.refresh.failed'),'error');
				}
			});
		},

		// handleUserDownload: function(event) {
		// 	event.preventDefault();
		// },

		handleUserLogout: function(event) {
			event.preventDefault();
			var selected = $('#userGrid').dxDataGrid('instance').getSelectedRowsData()[0];
			if (selected) {
				$('#logoutPopup').dxPopup('instance').show();
				if (selected['사용자 No'] === userJsonObject.userNo) {
					$('#logoutConfirmText').text('선택하신 사용자가 현재 사용자 입니다. 로그아웃  하시겠습니까?');
					$('.logout-ok').off('click').on('click', function() {
						$.ajax({
							url: WISE.Constants.context + '/logout.do',
							/* DOGFOOT ktkang 유저 로그아웃 로그 및 세션 관리 추가  20200923 */
							data: {
								id : userJsonObject.userId
							},
							success: function() {
								window.location.href = WISE.Constants.context;
								/* DOGFOOT ktkang 세션 로그아웃 후 리프레시  20200701 */
								sessionManager.handleUserRefresh();
							}
						});
					});
				} else {
					$('#logoutConfirmText').text('이 사용자를 로그아웃  하시겠습니까?');
					$('.logout-ok').off('click').on('click', function() {
//						$.ajax({
//							url: WISE.Constants.context + '/report/endUserSession.do',
//							method: 'POST',
//							data: { sessionId: selected['사용자 세션 키']},
//							success: function(msg) {
//								if (msg) {
//									WISE.alert(msg);
//								} else {
//									sessionManager.handleUserRefresh();
//									//2020.01.21 mksong 경고창 타입 지정 dogfoot
//									WISE.alert('로그아웃 되었습니다.','success');
//									$('#logoutPopup').dxPopup('instance').hide();
//								}
//							},
//							error: function() {
//								//2020.01.21 mksong 경고창 타입 지정 dogfoot
//								WISE.alert(gMessage.get('config.refresh.failed'),'error');
//							}
//						});
					});
				}
			}
		},

		handleInactiveUserRefresh: function() {
			var idNo, idNoFilter;
			if ($('#sessionInactiveUserTab').css('display') !== 'none' && $('#filterContainer').children().length > 0) {
				idNo = $('#idNo').dxSelectBox('instance').option('value');
				idNoFilter = $('#idNoFilter').dxTextBox('instance').option('value');
			} else {
				idNo = 'USER_ID';
				idNoFilter = '';
			}
			$.ajax({
				url: WISE.Constants.context + '/report/getInactiveUserSession.do',
				data: {
					idno: idNo,
					idnofilter: idNoFilter
				},
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(data) {
					var sessions = JSON.parse(data).sessions;
					$('#inactiveUserGrid').dxDataGrid('instance').option('dataSource', sessions);
				},
				error: function() {
					//2020.01.21 mksong 경고창 타입 지정 dogfoot
					WISE.alert(gMessage.get('config.refresh.failed'),'error');
				}
			});
		},

		// handleInactiveUserDownload: function(event) {
		// 	event.preventDefault();
		// },

		handleInactiveUserUnlock: function(event) {
			event.preventDefault();
			var selected = $('#inactiveUserGrid').dxDataGrid('instance').getSelectedRowsData()[0];
			if (selected) {
				$.ajax({
					url: WISE.Constants.context + '/report/updateUserSession.do',
					method: 'POST',
					data: { 
						userId: selected['사용자 ID'],
						userNo: selected['사용자 No']
					},
					success: function(msg) {
						if (msg) {
							WISE.alert(msg);
						} else {
							sessionManager.handleInactiveUserRefresh();
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.user.unlock'),'success');
						}
					},
					error: function() {
						//2020.01.21 mksong 경고창 타입 지정 dogfoot
						WISE.alert(gMessage.get('config.refresh.failed'),'error');
					}
				});
			}
		},

		handleLockedUserRefresh: function() {
			$.ajax({
				url: WISE.Constants.context + '/report/getLockedUserSession.do',
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(data) {
					var sessions = JSON.parse(data).sessions;
					$('#lockedUserGrid').dxDataGrid('instance').option('dataSource', sessions);
				},
				error: function() {
					//2020.01.21 mksong 경고창 타입 지정 dogfoot
					WISE.alert(gMessage.get('config.refresh.failed'),'error');
				}
			});
		},

		handleLockedUserUnlock: function(event) {
			event.preventDefault();
			var selected = $('#lockedUserGrid').dxDataGrid('instance').getSelectedRowsData()[0];
			if (selected) {
				$.ajax({
					url: WISE.Constants.context + '/report/unlockUserSession.do',
					method: 'POST',
					data: { 
						userNo: selected['사용자 No']
					},
					success: function(msg) {
						if (msg) {
							WISE.alert(msg);
						} else {
							sessionManager.handleLockedUserRefresh();
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.user.unlock'),'success');
						}
					},
					error: function() {
						//2020.01.21 mksong 경고창 타입 지정 dogfoot
						WISE.alert(gMessage.get('config.refresh.failed'),'error');
					}
				});
			}
		}
	}
})();