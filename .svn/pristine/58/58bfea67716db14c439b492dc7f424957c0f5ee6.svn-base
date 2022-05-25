var dataSourceManager = (function(){
	var datasources;
	var dsId;

	function initDsControl(field) {
		if (!isNull(field)) {
			$(".ipt .dataSource-id").val(field['데이터원본 명']);
			$(".ipt .dataSource-name").val(field['서버주소 명']);
			$(".ipt .dataSource-dbName").val(field['DB 명']);
			$(".ipt .dataSource-type").val(field['DB 유형']);
			$(".ipt .dataSource-owner").val(field['소유자']);
			$(".ipt .dataSource-port").val(field['Port']);
			$(".ipt .dataSource-accessId").val(field['접속 id']);
			$(".ipt .dataSource-accessPw").val(field['접속 암호']);
			$(".ipt .connect-type").val(field['접속 유형']);

			var dbType = field['DB 유형'];
			if (dbType == 'ORACLE') {
				$("#span_connect1").attr("style", "display:block;");
				$("#span_connect2").attr("style", "display:block;");
			}
			else {
				$("#span_connect1").attr("style", "display:none;");
				$("#span_connect2").attr("style", "display:none;");
			}
		}
		else {
			$(".ipt .dataSource-id").val('');
			$(".ipt .dataSource-name").val('');
			$(".ipt .dataSource-dbName").val('');
			$(".ipt .dataSource-type").val('');
			$(".ipt .dataSource-owner").val('');
			$(".ipt .dataSource-port").val('');
			$(".ipt .dataSource-accessId").val('');
			$(".ipt .dataSource-accessPw").val('');
			$(".ipt .connect-type").val('');

			$("#span_connect1").attr("style", "display:none;");
			$("#span_connect2").attr("style", "display:none;");
		}
	}

	function initDataSourceLayout(){

		$('#dataSourceCount').text('데이터 원본 목록');

		$("#dataSourceList").dxDataGrid({
			dataSource : datasources,
			columns : [
				{
					dataField: "데이터 ID",
					visible: false
				},
				{
					dataField: "USER NO",
					visible: false
				},
				{
					dataField: "데이터원본 명",
					width: "40%"
				},
				{
					caption: "서버 주소(명)",
					dataField: "서버주소 명"
				},
				{
					dataField: "소유자"
				},
				{
					dataField: "DB 유형"
				},
				{
					dataField: "접속 유형",
					visible: false
				},
				{
					dataField: "DATA"
				}
			],
			visible: true,
			rowAlternationEnabled: true,
			scrolling: {
	            columnRenderingMode: "virtual"
	        },
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForList('dataSourceList');

				$(".ipt .dataSource-type").off('change').on('change', function() {
					var dbType = $(".ipt .dataSource-type").val();
					if (dbType == 'ORACLE') {
						$(".ipt .connect-type").val('SID');
						$("#span_connect1").attr("style", "display:block;");
						$("#span_connect2").attr("style", "display:block;");
					}
					else {
						$(".ipt .connect-type").val('');
						$("#span_connect1").attr("style", "display:none;");
						$("#span_connect2").attr("style", "display:none;");
					}
				});

			},
			onSelectionChanged: function(e) {
				var selectedField = e.selectedRowsData[0];
				if (selectedField) {
					initDsControl(selectedField);
				}
				else {
					initDsControl();
				}
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			}

		})

	}

	function updateDatasources(){
		$('#dataSourceList').dxDataGrid('instance').option('dataSource', datasources);
		$('#dataSourceList').dxDataGrid('instance').refresh();

		var selectedDsID = $('#dataSourceList').dxDataGrid('instance').getSelectedRowKeys()[0];

		if (selectedDsID) {
			var selDs = datasources.filter(function(ds) {
				return ds['데이터 ID'] == selectedDsID['데이터 ID'];
			});

			initDsControl(selDs);
		}
		else {
			initDsControl();
		}
	}

	return{
		initDataSource : function(){
			$.ajax({
				url: WISE.Constants.context + '/report/getDataSourceList.do',
				async: false,
				success: function(data) {
					datasources = JSON.parse(data).datasources;
				}
			})

			initDataSourceLayout();
		},
		handleDataSourceNew: function(event){
			$('#dataSourceList').dxDataGrid('instance').deselectAll();

			initDsControl();
		},

		handleDataSourceSave : function(event){
			event.preventDefault();
			var selectedUser = $('#dataSourceList').dxDataGrid('instance').option('selectedRowKeys')[0];
			var invalidFieldCount = true;

            $("#dataSourceList").find("input[type=text]").each(function(index, item){
                if ($(this).val().trim() == '') {
                    invalidFieldCount = false;
                    return false;
                }
            });

			if (invalidFieldCount) {
				var dbmsType = $('.ipt .dataSource-type').val();
				if (isNull(dbmsType)) {
					WISE.alert('DB 유형을 입력 해주십시오.');
					$('.ipt .dataSource-type').focus();
					return false;
				}
				else {
					if (dbmsType == 'ORACLE') {
						if (isNull($(".ipt .connect-type").val())) {
							WISE.alert('접속 유형을 입력 해주십시오.');
							$('.ipt .connect-type').focus();
							return false;
						}
					}
				}

				if (!selectedUser) {
					$.ajax({
						url: WISE.Constants.context + '/report/insertDatasourceInfo.do',
						async: false,
						method: 'POST',
						data: {
							newDsNm: $('.ipt .dataSource-id').val(),
							newDbNm: $('.ipt .dataSource-dbName').val(),
							newIp: $('.ipt .dataSource-name').val(),
							newUserId: $('.ipt .dataSource-accessId').val(),
							newPasswd: $('.ipt .dataSource-accessPw').val(),
							newPort: $('.ipt .dataSource-port').val(),
							newDbmsType: $('.ipt .dataSource-type').val(),
							newOwnerNm: $('.ipt .dataSource-owner').val(),
							newDsDesc: '',
							newDsConnstr: '',
							newRegDt: '',
							newRegUserNo:'',
							newUpdDt: '',
							newUpdUserNo: '',
							newRacip: '',
							newRacport: '',
							newWfyn: 'N',
							newUserAreaYn: 'N',
							newConnType: $(".ipt .connect-type").val(),
							newHashYn: ''
						},
						success: function(newData) {
							var error = JSON.parse(newData).error;
							if (error) {

								WISE.alert(error,'error');
							} else {
								datasources = JSON.parse(newData).datasources;
								updateDatasources();


								WISE.alert(gMessage.get('config.datasource.create.success'),'success');
							}
						},
						error: function() {

							WISE.alert(gMessage.get('config.save.failed'),'error');
						}
					});
				}
				else {
					$.ajax({
						url: WISE.Constants.context + '/report/updateDatasourceInfo.do',
						async: false,
						method: 'POST',
						data: {
							newDsId: selectedUser['데이터 ID'],
							newDsNm: $('.ipt .dataSource-id').val(),
							newDbNm: $('.ipt .dataSource-dbName').val(),
							newIp: $('.ipt .dataSource-name').val(),
							newUserId: $('.ipt .dataSource-accessId').val(),
							newPasswd: $('.ipt .dataSource-accessPw').val(),
							newPort: $('.ipt .dataSource-port').val(),
							newDbmsType: $('.ipt .dataSource-type').val(),
							newOwnerNm: $('.ipt .dataSource-owner').val(),
							newDsDesc: '',
							newDsConnstr: '',
							newRegDt: '',
							newRegUserNo:'',
							newUpdDt: '',
							newUpdUserNo: '',
							newRacip: '',
							newRacport: '',
							newWfyn: 'N',
							newUserAreaYn: 'N',
							newConnType: $(".ipt .connect-type").val(),
							newHashYn: ''
						},
						success: function(newData) {
							var error = JSON.parse(newData).error;
							if (error) {

								WISE.alert(error,'error');
							} else {
								datasources = JSON.parse(newData).datasources;
								updateDatasources();

								WISE.alert(gMessage.get('config.save.success'),'success');
							}
						},
						error: function() {

							WISE.alert(gMessage.get('config.save.failed'),'error');
						}
					});
				}
			}else {
				WISE.alert(gMessage.get('config.critical.items'));
			}
		},

		handleDatasourceDelete : function(event){
			event.preventDefault();
			var selectedDatasource = $('#dataSourceList').dxDataGrid('instance').option('selectedRowKeys')[0];
			if (selectedDatasource) {
				$('#pwPopup').dxPopup({
					title: '데이터 원본 삭제',

					 height: 'auto',
					 width: 'auto',
					contentTemplate: function(e) {
						var html = 	'<p>데이터 원본 "' + selectedDatasource['데이터원본 명'] + '"를 삭제 하시겠습니까?</p>' +
									'<div class="row center popup-footer datasource-delete-confirmation">' +
										'<a href="#" class="btn positive datasource-delete-confirm">확인</a>' +
										'<a href="#" class="btn neutral datasource-delete-cancel">취소</a>' +
									'</div>';
						e.append(html);
					},
					onContentReady: function(e) {
						$('.datasource-delete-confirm').on('click', function() {
							$.ajax({
								url: WISE.Constants.context + '/report/deleteDatasourceInfo.do',
								method: 'POST',
								data: {
									datasource: selectedDatasource['데이터 ID'],
								},
								async: false,
								success: function(newData) {
									datasources = JSON.parse(newData).datasources;
									updateDatasources();

									WISE.alert(gMessage.get('config.delete.success'),'success');
									e.component.hide();

									initDsControl();
								},
								error: function() {

									WISE.alert(gMessage.get('config.delete.failed'),'error');
								}
							});
						});
						$('.datasource-delete-cancel').on('click', function() {
							e.component.hide();
						});
					}
				}).dxPopup('instance').show();
			}
		},

		/* DOGFOOT syjin 연결 테스트 기능 추가  20210113 */
		initAccessButton : function(){
			$("#accessTestBtn").dxButton({
				text: "연결 테스트",
        		onClick:function(){
        			gProgressbar.show();
        			var selectedDsID = $('#dataSourceList').dxDataGrid('instance').getSelectedRowKeys()[0];
        			if (selectedDsID) {
						var _dbType = selectedDsID["DB 유형"];
						var dbType = _dbType.toUpperCase();
						switch(_dbType.toUpperCase()) {
							case "TIBERO(DBMS)":
								dbType = "TIBERO";
								break;
							//case "MSPDW":
//								break;
							//case "SAPIQ":
//								break;					// 알아내야함
						}
						/* 2021-07-14 본사소스 적용(jhseo)*/
						// 2021-04-02 yyb 연결테스트 진행하기 전 변경된 정보가 있으면 저장 후 진행하라고 유도
						var nChkCnt = 0;
						var chkMsg = '변경된 정보가 있습니다. 연결테스트를 진행하시려면 변경된 정보를 저장 후 진행해주십시오.';
						if (selectedDsID["서버주소 명"] != $('.ipt .dataSource-name').val()) {
							nChkCnt++;
						}
						
						if (selectedDsID["접속 id"] != $('.ipt .dataSource-accessId').val()) {
							nChkCnt++;
						}
						
						if (selectedDsID["접속 암호"] != $('.ipt .dataSource-accessPw').val()) {
							nChkCnt++;
						}
						
						if (selectedDsID["Port"] != $('.ipt .dataSource-port').val()) {
							nChkCnt++;
						}
						
						if (selectedDsID["소유자"] != $('.ipt .dataSource-owner').val()) {
							nChkCnt++;
						}
						
						if (nChkCnt > 0){
							WISE.alert(chkMsg);
							gProgressbar.hide();
							return false;
						}
						
        				$.ajax({
                            method: 'POST',
                            url: WISE.Constants.context + '/report/vldQry.do',
                            data: {
                                id: selectedDsID['데이터 ID'],
                                type: "DS_SQL",
								dbType: dbType,
                                params: []
                            },
                            success: function(data){
                            	if(data.length > 0){
                            		WISE.alert(gMessage.get('config.dataaccess.success'),'success');
                            	}else{
                            		WISE.alert(gMessage.get('config.dataaccess.failed'),'error');
                            	}
                            }
                        });
        			}
					else {
						WISE.alert('저장후 진행해주십시오.');
        			}
        			gProgressbar.hide();
        		}
			})
		}
	}
})();