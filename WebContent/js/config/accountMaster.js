/**
 * Global variables
 */
var gConsole, gProgressbar, gMessage, gDashboard;

/**
 * Class for running "/account.do" page.
 */
var accountMaster = (function() {
	/*
	 * Local variables
	 */
	var userId;
	var	userImage; 
	var	userDatasetId; 
	var	userDatasetNm; 
	var	userReportId;
	var	userReportNm; 
	var	userReportType; 
	var	userItem; 
	var	userPalette; 
	var	userViewerReportId; 
	var	userViewerReportNm; 
	var	userViewerReportType;
	var emailFormat;
	var telNoFormat;
	var mobileNoFormat;
	var userFontConfig;

	/**
	 * Constructor
	 */
	function init() {
		userId = userJsonObject.userId;
		userImage = userJsonObject.userImage;
		userDatasetId = userJsonObject.userDatasetId;
		userDatasetNm = userJsonObject.userDatasetNm;
		userReportId = userJsonObject.userReportId;
		userReportNm = userJsonObject.userReportNm;
		userReportType = userJsonObject.userReportType;
		userItem = userJsonObject.userItemType;
		userPalette = userJsonObject.userPalette;
		userViewerReport = userJsonObject.userViewerReport;
		userViewerReportNm = userJsonObject.userViewerReportNm;
		userViewerReportType = userJsonObject.userViewerReportType;
		userFontConfig = userJsonObject.fontConfig;
		emailFormat = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
		telNoFormat = /^\d{2,3}-\d{4}-\d{4}$/;
		mobileNoFormat = /^\d{3}-\d{4}-\d{4}$/;
	}

	/**
	 * Initialize layout for account settings page.
	 */
	function initLayout() {
		if (userJsonObject.userAuth === 'admin') {
			$('#editDesignerInfo').show();
		} else {
			$('#editDesignerInfo').remove();
		}
	}

	/**
	 * Initialize user info components.
	 */
	function initUserInfo() {
		if (typeof userJsonObject !== 'undefined') {
			$.ajax({
				url: WISE.Constants.context + '/report/getUserInfo.do',
				method: 'POST',
				data: { userNo: userJsonObject.userNo },
				success: function(userJson) {
					var userInfo = JSON.parse(userJson);
					$('input.user-id').val(userInfo.userId);
					$('input.user-name').val(userInfo.userName);
					$('input.user-email1').val(userInfo.email1);
					$('input.user-email2').val(userInfo.email2);
					$('input.user-tel-no').val(userInfo.telNo);
					$('input.user-mobile-no').val(userInfo.mobileNo);
					if (userInfo.userImage) {
						$('#userProfile').attr('src', WISE.Constants.context + '/images/users/' + userJsonObject.userNo + '/' + userInfo.userImage);
					} else {
						$('#userProfile').attr('src', WISE.Constants.context + '/resources/main/images/ico_namEdit.png');
					}
//					var fontConfigJson = JSON.parse(userInfo.fontConfig);
					if (userInfo.fontConfig) {
						if(userInfo.fontConfig.FONT_SIZE){
							$('#fontFamily').val(userInfo.fontConfig.FONT_FAMILY);
							$('#fontSize').val(userInfo.fontConfig.FONT_SIZE);
							$('#FONT_COVERAGE-Menu').prop("checked", userInfo.fontConfig.FONT_COVERAGE.Menu);
							$('#FONT_COVERAGE-Item').prop("checked", userInfo.fontConfig.FONT_COVERAGE.Item);
						}
					}
					
					$('#userProfileUpload').dxFileUploader({
						accept: 'image/*',
						multiple: false,
						selectButtonText: '프로필 사진 바꾸기',
						labelText: '드래그 위치',
						readyToUploadMessage: '',
						uploadedMessage: '',
						uploadFailedMessage: '업로드 실패 했습니다.',
						showFileList: false,
						uploadMethod: 'POST',
						uploadUrl: WISE.Constants.context + '/report/uploadUserImage.do',
						onUploaded: function(e) {
							userImage = e.request.responseText;
							$('#userProfile').attr('src', WISE.Constants.context + '/images/users/' + userJsonObject.userNo + '/' + userImage);
							e.component.reset();
						}
					});
					$('#saveUserInfo').on('click', function() {
						$.ajax({
							url: WISE.Constants.context + '/report/saveAccountProfile.do',
							method: 'POST',
							data: {
								userName: $('input.user-name').val(),
								email1: $('input.user-email1').val(),
								email2: $('input.user-email2').val(),
								telNo: $('input.user-tel-no').val(),
								mobileNo: $('input.user-mobile-no').val(),
								image: userImage
							},
							success: function(result) {
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert(result, 'success');
							},
							error: function() {
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
							}
						});
					});
					$('#changePassword').on('click', function() {
						var popup = $('#accountPopup').dxPopup({
							showCloseButton: false,
							title: '비밀번호 변경',
							visible: true,
							height: "auto",
							width: "600px",
							position: {  
						         my: 'center',  
						         at: 'center',  
						         of: 'body'  
						    },
							onContentReady: function() {
								gDashboard.fontManager.setFontConfigForOption('accountPopup');
							},
							contentTemplate: function(e) {
								var html = 	'<div class="tbl data-form">' +
												'<table>' +
													'<colgroup class="pw-form-col">' +
														'<col style="width: 150px;">' +
														'<col style="width: auto;">' +
													'</colgroup>' +
													'<tbody>' +
														'<tr>' +
															'<th>현 비밀번호</th>' +
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

								$('.btn.pw-changer-ok').on('click', function() {
									var oldPw = $('.change-user-pw-old').val();
									var newPw = $('.change-user-pw-new').val();
									var confirmPw = $('.change-user-pw-confirm').val();
									if (newPw.length > 0 && newPw === confirmPw) {
										$.ajax({
											url: WISE.Constants.context + '/report/changePassword.do',
											method: 'POST',
											data: {
												user: userId,
												oldPw: oldPw,
												newPw: newPw,
											},
											async: false,
											success: function(status) {
												var error = JSON.parse(status).error;
												if (error) {
													// 2020.01.07 mksong 경고창 UI 변경 dogfoot
													WISE.alert(error, 'error');
												} else {
													// 2020.01.07 mksong 경고창 UI 변경 dogfoot
													WISE.alert(gMessage.get('config.password.change.success'),'success');
													popup.hide();
												}
											},
											error: function() {
												// 2020.01.07 mksong 경고창 UI 변경 dogfoot
												WISE.alert(gMessage.get('config.password.change.failed'),'error');
											}
										});
									} else {
										// 2020.01.07 mksong 경고창 UI 변경 dogfoot
										WISE.alert(gMessage.get('config.password.incorrect'),'error');
									}
								});
								$('.btn.pw-changer-cancel').on('click', function() {
									$('.change-user-pw-old').val('');
									$('.change-user-pw-new').val('');
									$('.change-user-pw-confirm').val('');
									popup.hide();
								});
							}
						}).dxPopup('instance');
					});
					
					// 폰트 설정
					$('#resetFontInfo').on('click', function() {
						$.ajax({
							url: WISE.Constants.context + '/report/saveAccountFontConfig.do',
							method: 'POST',
							data: {
								fontConfig: "{}"
							},
							success: function() {
								$('#fontFamily').val('Basic');
								$('#fontSize').val('');
								$('#FONT_COVERAGE-Menu').prop("checked", false);
								$('#FONT_COVERAGE-Item').prop("checked", false);
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('초기화 되었습니다.','success');
							},
							error: function() {
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
							}
						});
					});
					
					$('#saveFontUserInfo').on('click', function() {
						var fontUserConfig = {
							'FONT_FAMILY': $('#fontFamily').val(),
							'FONT_SIZE': $('#fontSize').val() !== ""? $('#fontSize').val() : 0,
							'FONT_COVERAGE': {
								'Menu': $('#FONT_COVERAGE-Menu').prop('checked'),
								'Item': $('#FONT_COVERAGE-Item').prop('checked')
							}
						}
						
						$.ajax({
							url: WISE.Constants.context + '/report/saveAccountFontConfig.do',
							method: 'POST',
							data: {
								fontConfig: JSON.stringify(fontUserConfig)
							},
							success: function() {
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('저장 되었습니다.','success');
							},
							error: function() {
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
							}
						});
					});
				}
			});
		}
	}

	/**
	 * Initialize textbox input validation for user fields.
	 */
	function initUserInputValidation() {
		$('input.user-name').on('input propertychange', function() {
			var userName = $(this).val();
			if (userName.length > 0) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
		$('input.user-email1').on('input propertychange', function() {
			var userEmail1 = $(this).val();
			if (userEmail1.length === 0) {
				$(this).removeClass('success error');
			} else if (emailFormat.test(userEmail1)) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
		$('input.user-email2').on('input propertychange', function() {
			var userEmail2 = $(this).val();
			if (userEmail2.length === 0) {
				$(this).removeClass('success error');
			} else if (emailFormat.test(userEmail2)) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
		$('input.user-tel-no').on('input propertychange', function() {
			var userTelNo = $(this).val();
			if (userTelNo.length === 0) {
				$(this).removeClass('success error');
			} else if (telNoFormat.test(userTelNo)) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
		$('input.user-mobile-no').on('input propertychange', function() {
			var userMobileNo = $(this).val();
			if (userMobileNo.length === 0) {
				$(this).removeClass('success error');
			} else if (mobileNoFormat.test(userMobileNo)) {
				$(this).removeClass('error').addClass('success');
			} else {
				$(this).removeClass('success').addClass('error');
			}
		});
	}

	/**
	 * Initialize user editor configuration components.
	 */
	function initUserEditorSettings() {
		// 기본 데이터 집합
		$('#setDataset').on('click', function() {
			var popup = $("#accountPopup").dxPopup({
				showCloseButton: false,
				title: "데이터 집합 즐겨 찾기",
				height: "800px",
				width: "600px",
				position: {  
			         my: 'center',  
			         at: 'center',  
			         of: 'body'  
			    },
				visible: true,
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForListPopup('accountPopup')
				},
				contentTemplate: function(contentElement) {
					var html = 	'<div class="popup-body">' +
									'<div class="modal-article">' + 
										'<div class="modal-tit">' + 
											'<span>데이터집합 목록</span>' + 
										'</div>' + 
										'<div id="data_list" class="data_list"></div>' +
									'</div>' + 
								'</div>' + 
								'<div class="modal-footer">' + 
									'<div class="row center">' + 
										'<a href="#" class="btn positive dataset-select-ok">확인</a>' + 
										'<a href="#" class="btn neutral dataset-select-cancel">취소</a>' + 
									'</div>' + 
								'</div>';
					contentElement.append(html);

					$.ajax({
						url : WISE.Constants.context + '/report/dataSetList.do',
						method: 'POST',
						data:{
							userId: userId
						},
						beforeSend:function() {
							gProgressbar.show();
						},
						complete:function() {
							gProgressbar.hide();
						},
						success: function(data) {
							var DATASET_ID;
							var DATASET_NM;
							var ITEM_TYPE;

							data = JSON.parse(data);

							var dataSetFolders = data["dataSetFolders"];

							$("#data_list").dxTreeView({ 
								dataSource: dataSetFolders,
								dataStructure: "plain",
								parentIdExpr: "PARENT_FLD_ID",
								keyExpr: "FLD_ID",
								displayExpr: "FLD_NM",
								width: '100%',
								height: 550,
								onContentReady: function(){
									gDashboard.fontManager.setFontConfigForListPopup('data_list');
								},
								onInitialized:function(_e){
									$.each(_e.component.option('dataSource'),function(_i,_items){
										if(typeof _items['PARENT_FLD_ID'] == 'undefined') {
											_items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
										} else {
											_items['icon']= WISE.Constants.context + '/resources/main/images/ico_dataset.png';
										}
									});
								},
								onItemClick: function(e) {
									DATASET_ID = e.itemData['DATASET_ID'];
									DATASET_NM = e.itemData['FLD_NM'];
									ITEM_TYPE = typeof e.itemData['PARENT_FLD_ID'] !== 'undefined' ? 'REPORT' : 'FOLDER';
								}
							});

							$(".dataset-select-ok").on('click', function() {
								if (DATASET_ID && ITEM_TYPE === 'REPORT') {
									$.ajax({
										url: WISE.Constants.context + '/report/saveAccountDatasetId.do',
										method: 'POST',
										data: {
											datasetId: DATASET_ID
										},
										success: function() {
											userDatasetId = DATASET_ID;
											userDatasetNm = DATASET_NM;
											showSelectedOptions();
											// 2020.01.07 mksong 경고창 UI 변경 dogfoot
											WISE.alert('저장 되었습니다.','success');
											popup.hide();
										},
										error: function() {
											// 2020.01.07 mksong 경고창 UI 변경 dogfoot
											WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
										}
									});
								}
							});

							$(".dataset-select-cancel").on('click', function() {
								popup.hide();
							});
						}
					});
				}
			}).dxPopup('instance');
		});

		$('#resetDataset').on('click', function() {
			$.ajax({
				url: WISE.Constants.context + '/report/saveAccountDatasetId.do',
				method: 'POST',
				data: {
					datasetId: 0
				},
				success: function() {
					userDatasetId = undefined;
					userDatasetNm = undefined;
					showSelectedOptions();
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('초기화 되었습니다.','success');
				},
				error: function() {
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
				}
			});
		});

		// 기본 보고서
		$('#setReport').on('click', function() {
			var popup = $('#accountPopup').dxPopup({
				title:'보고서 즐겨 찾기',
				height: "800px",
				width: "600px",
				position: {  
			         my: 'center',  
			         at: 'center',  
			         of: 'body'  
			    },
				visible:true,
				showCloseButton: false,
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForListPopup('accountPopup')
				},
				contentTemplate: function(contentElement) {
					var html = 	'<div class="popup-body">' +
									'<div class="modal-article">' + 
										'<div class="modal-tit">' + 
											'<span>보고서 목록</span>' + 
										'</div>' + 
										'<div id="folder_tree"></div>' +
									'</div>' + 
								'</div>' + 
								'<div class="modal-footer">' + 
									'<div class="row center">' + 
										'<a href="#" class="btn positive report-select-ok">확인</a>' + 
										'<a href="#" class="btn neutral report-select-cancel">취소</a>' + 
									'</div>' + 
								'</div>';
					contentElement.append(html);

					$.ajax({
						url: WISE.Constants.context + '/report/getReportList.do',
						method: 'POST',
						data: {
							fld_type: 'PUBLIC',
							user_id: userId,
							report_type: 'ALL'
						},
						success: function(result) {
							result = result.data;
							/* DOGFOOT hsshim 200103
							 * json 포맷 오류 수정
							 */
							// result = JSON.parse(result);
							var report_id, report_nm, report_type, item_type;
							$('#folder_tree').dxTreeView({
								dataSource:result,
								dataStructure:'plain',
								keyExpr: "uniqueKey",
								parentIdExpr: "upperKey",
								rootValue: "F_0",
								displayExpr: "TEXT",
								// mksong 2019.12.20 보고서 검색 추가 dogfoot
								searchEnabled: true,
								searchMode : "contains",
								searchTimeout:undefined,
								searchValue:"",
								// 2019.12.20 mksong nodata 텍스트 수정 dogfoot
								noDataText:"조회된 보고서가 없습니다.",
								width: '100%',
								height: 550,
								showCloseButton: false,
								onContentReady: function(){
									gDashboard.fontManager.setFontConfigForListPopup('folder_tree')
								},
								onInitialized:function(_e){
									$.each(_e.component.option('dataSource'),function(_i,_items){
										switch(_items.TYPE){
										case 'REPORT':
											if(_items.REPORT_TYPE == 'DashAny'){
												_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
											}else if(_items.REPORT_TYPE == 'AdHoc'){
												_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';		            						
			            					}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
			            						_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';		            						
											}
											break;
										case 'FOLDER':
											_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
											break;
										}
									});
								},
								onItemClick:function(_e){
									report_id = _e.itemData['ID'];
									report_nm = _e.itemData['TEXT'];
									report_type = _e.itemData['REPORT_TYPE'];
									item_type = _e.itemData['TYPE'];
								}
							});
							$('.report-select-ok').on('click', function() {
								if (report_id && item_type === 'REPORT') {
									$.ajax({
										url: WISE.Constants.context + '/report/saveAccountReportInfo.do',
										method: 'POST',
										data: {
											reportId: report_id
										},
										success: function() {
											userReportId = report_id;
											userReportNm = report_nm;
											userReportType = report_type;
											showSelectedOptions();
											// 2020.01.07 mksong 경고창 UI 변경 dogfoot
											WISE.alert('저장 되었습니다.','success');
											popup.hide();
										},
										error: function() {
											// 2020.01.07 mksong 경고창 UI 변경 dogfoot
											WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
										}
									});
								}
							});
							$('.report-select-cancel').on('click', function() {
								popup.hide();
							});
						}
					});
				}
			}).dxPopup('instance');
		});

		$('#resetReport').on('click', function() {
			$.ajax({
				url: WISE.Constants.context + '/report/saveAccountReportInfo.do',
				method: 'POST',
				data: {
					reportId: 0
				},
				success: function() {
					userReportId = undefined;
					userReportNm = undefined;
					userReportType = undefined;
					showSelectedOptions();
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('초기화 되었습니다.','success');
				},
				error: function() {
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
				}
			});
		});

		// 기본 아이템
		$('#setItem').on('click', function() {
			var popup = $('#accountPopup').dxPopup({
				title:'아이템 선택',
				visible:true,
				height: "auto",
				width: "600px",
				position: {  
			         my: 'center',  
			         at: 'center',  
			         of: 'body'  
			    },
				showCloseButton: false,
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForListPopup('accountPopup')
				},
				contentTemplate: function(contentElement) {
					var html = 	'<div class="popup-body">' +
									'<div class="modal-article">' + 
										'<div class="modal-tit">' + 
											'<span>아이템</span>' + 
										'</div>' + 
										'<div id="item_list"></div>' +
									'</div>' + 
								'</div>' + 
								'<div class="modal-footer">' + 
									'<div class="row center">' + 
										'<a href="#" class="btn positive item-select-ok">확인</a>' + 
										'<a href="#" class="btn neutral item-select-cancel">취소</a>' + 
									'</div>' + 
								'</div>';
					contentElement.append(html);
					//20200720 ajkim 유저 아이템 설정 한글화 dogfoot
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
					var itemCollection = ['None', 'AdHoc', 'Bar', 'StackedBar', 'FullStackedBar', 'Point', 'Line', 'StackedLine', 'FullStackedLine', 
								'StepLine', 'Spline', 'Area', 'StackedArea', 'FullStackedArea', 'StepArea', 'SplineArea', 
								'StackedSplineArea', 'FullStackedSplineArea', 'Bubble', 'PivotGrid', 'DataGrid', 'PieChart', 'Card', 
								'ChoroplethMap', 'ParallelCoordinate', 'Waterfallchart', 'HistogramChart', 'BubbleD3', 
								'RectangularAreaChart', 'TreeMap', 'StarChart', 'HeatMap','WordCloud', 'HierarchicalEdge',
								'FunnelChart', 'PyramidChart', 'RangeBarChart','RangeAreaChart','TimeLineChart'
								,'BubblePackChart','WordCloudV2','DendrogramBarChart','CalendarViewChart', 'KakaoMap', 'KakaoMap2'
								,'CalendarView2Chart','CalendarView3Chart','CollapsibleTreeChart'];
					
					var itemCollection2 = ["없음", "비정형", "막대 차트", "스택 막대 차트", "풀스택 막대 차트", "점 차트", "선 차트", "스택 선 차트", "풀스택 선 차트",
								"계단 차트", "곡선 차트", "영역 차트", "스택 영역 차트", "풀스택 영역 차트", "계단 영역 차트", "곡선 영역 차트",
								"스택 곡선 영역 차트", "풀스택 곡선 영역 차트", "버블 차트2", "피봇 그리드", "일반 그리드", "파이 차트", "카드",
								"코로플레스", "평행좌표계", "폭포수 차트", "히스토그램 차트", "버블 차트",
								"네모 영역", "트리맵", "스타 차트", "히트맵", "워드클라우드", "계층 차트", '레인지 바 차트', "레인지 영역 차트", "퍼널 차트", '피라미드 차트','타임라인 차트', '카카오 지도', '카카오 지도2'];
					
					var itemObject = {
							'None':'없음',
							'AdHoc':'비정형',
							'Bar':'막대 차트',
							'StackedBar':'스택 막대 차트',
							'FullStackedBar':'풀스택 막대 차트',
							'Point':'점 차트',
							'Line':'선 차트',
							'StackedLine':'스택 선 차트',
							'FullStackedLine':'풀스택 선 차트',
							'StepLine':'계단 차트',
							'Spline':'곡선 차트',
							'Area':'영역 차트',
							'StackedArea':'스택 영역 차트',
							'FullStackedArea':'풀스택 영역 차트',
							'StepArea':'계단 영역 차트',
							'SplineArea':'곡선 영역 차트',
							'StackedSplineArea':'스택 곡선 영역 차트',
							'FullStackedSplineArea':'풀스택 곡선 영역 차트',
							'Bubble':'버블 차트2',
							'PivotGrid':'피봇 그리드',
							'DataGrid':'일반 그리드',
							'PieChart':'파이 차트',
							'Card':'카드',
							'ChoroplethMap':'코로플레스',
							'ParallelCoordinate':'평행좌표계',
							'BubblePackChart':'버블 팩',
							'WordCloudV2':'워드클라우드2',
							'DendrogramBarChart':'신경망바차트',
							'CalendarViewChart':'캘린더뷰',
							'CalendarView2Chart':'캘린더2 뷰',
							'CalendarView3Chart':'캘린더3 뷰',
							'CollapsibleTreeChart':'신경망 트리',
							'Waterfallchart':'폭포수 차트',
							'HistogramChart':'히스토그램 차트',
							'BubbleD3':'버블 차트',
							'RectangularAreaChart':'네모 영역',
							'TreeMap':'트리맵',
							'StarChart':'스타 차트',
							'HeatMap':'히트맵',
							'WordCloud':'워드클라우드',
							'HierarchicalEdge':'계층 차트',
							'RangeBarChart':'레인지 바 차트',
							'RangeAreaChart':'레인지 영역 차트',
							'TimeLineChart':'타임라인 차트',
							/* DOGFOOT syjin 카카오 지도 추가  20200820 */
							'KakaoMap' : '카카오 지도',
							'KakaoMap2' : '카카오 지도2'
						};
					
					var itemObejct2 = {
							"계단 영역 차트": "StepArea",
							"계단 차트": "StepLine",
							"계층 차트": "HierarchicalEdge",
							"곡선 영역 차트": "SplineArea",
							"곡선 차트": "Spline",
							"네모 영역": "RectangularAreaChart",
							"막대 차트": "Bar",
							"버블 차트": "BubbleD3",
							"버블 차트2": "Bubble",
							"비정형": "AdHoc",
							"선 차트": "Line",
							"스타 차트": "StarChart",
							"스택 곡선 영역 차트": "StackedSplineArea",
							"스택 막대 차트": "StackedBar",
							"스택 선 차트": "StackedLine",
							"스택 영역 차트": "StackedArea",
							"없음": "None",
							"영역 차트": "Area",
							"워드클라우드": "WordCloud",
							"일반 그리드": "DataGrid",
							"점 차트": "Point",
							"카드": "Card",
							"코로플레스": "ChoroplethMap",
							"트리맵": "TreeMap",
							"파이 차트": "PieChart",
							"평행좌표계": "ParallelCoordinate",
							"버블 팩 차트": "BubblePackChart",
							"워드클라우드2": "WordCloudV2",
							"신경망바차트": "DendrogramBarChart",
							"캘린더뷰차트": "CalendarViewChart",
							"캘린더뷰2차트": "CalendarView2Chart",
							"캘린더뷰3차트": "CalendarView3Chart",
							"신경망트리차트": "CollapsibleTreeChart",
							"폭포수 차트": "Waterfallchart",
							"풀스택 곡선 영역 차트": "FullStackedSplineArea",
							"풀스택 막대 차트": "FullStackedBar",
							"풀스택 선 차트": "FullStackedLine",
							"풀스택 영역 차트": "FullStackedArea",
							"피봇 그리드": "PivotGrid",
							"히스토그램 차트": "HistogramChart",
							"히트맵": "HeatMap",
							"레인지 바 차트":"RangeBarChart",
							"레인지 영역 차트":"RangeAreaChart",
							"타임라인 차트":"TimeLineChart",
							/* DOGFOOT syjin 카카오 지도 추가  20200820 */
							"카카오 지도":"KakaoMap",
							"카카오 지도2":"KakaoMap2"
						};
					//임성현 주임 히스토그램 변수명 변경
					var itemList = $('#item_list').dxSelectBox({
						items: itemCollection2,
						value: itemObject[userItem] || 'None'
					}).dxSelectBox('instance');
					$('.item-select-ok').on('click', function() {
						$.ajax({
							url: WISE.Constants.context + '/report/saveAccountItem.do',
							method: 'POST',
							data: {
								item: itemObejct2[itemList.option('value')]
							},
							success: function() {
								userItem = itemObejct2[itemList.option('value')];
								showSelectedOptions();
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('저장 되었습니다.','success');
								popup.hide();
							},
							error: function() {
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
							}
						});
					});
					$('.item-select-cancel').on('click', function() {
						popup.hide();
					});
				}
			}).dxPopup('instance');
		});

		$('#resetItem').on('click', function() {
			$.ajax({
				url: WISE.Constants.context + '/report/saveAccountItem.do',
				method: 'POST',
				data: {
					item: 'None'
				},
				success: function() {
					userItem = undefined;
					showSelectedOptions();
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('초기화 되었습니다.','success');
				},
				error: function() {
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
				}
			});
		});
		
		// 기본 아이템
		$('#setPalette').on('click', function() {
			var popup = $('#accountPopup').dxPopup({
				title:'색상 선택',
				visible:true,
				showCloseButton: false,
				height: "auto",
				width: "600px",
				position: {  
			         my: 'center',  
			         at: 'center',  
			         of: 'body'  
			    },
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForListPopup('accountPopup')
				},
				contentTemplate: function(contentElement) {
					var html = 	'<div class="popup-body">' +
									'<div class="modal-article">' + 
										'<div class="modal-tit">' + 
											'<span>색상</span>' + 
										'</div>' + 
										'<div id="palette_list"></div>' +
									'</div>' + 
								'</div>' + 
								'<div class="modal-footer">' + 
									'<div class="row center">' + 
										'<a href="#" class="btn positive palette-select-ok">확인</a>' + 
										'<a href="#" class="btn neutral palette-select-cancel">취소</a>' + 
									'</div>' + 
								'</div>';
					contentElement.append(html);
					
					//20200720 ajkim 유저 팔레트 설정 한글화 dogfoot
					var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
						'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office'];
					//2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 DOGFOOT
					var paletteCollection2 = ['밝음', '발광체', '바다', '파스텔', '부드러움', '연한 파스텔', '나무', '포도', 
						'단색', '우주', '진보라', '안개숲', '연파랑', '기본값', '사무실 테마'];
					var paletteObject = {
							'Bright':'밝음',
							'Harmony Light':'발광체',
							'Ocean':'바다',
							'Pastel':'파스텔',
							'Soft':'부드러움',
							'Soft Pastel':'연한 파스텔',
							'Vintage':'나무',
							'Violet':'포도',
							'Carmine':'단색',
							'Dark Moon':'우주',
							'Dark Violet':'진보라',
							'Green Mist':'안개숲',
							'Soft Blue':'연파랑',
							'Material':'기본값',
							'Office':'사무실 테마',
							'Custom':'사용자 정의 테마',
						};
					var paletteObject2 = {
						'밝음':'Bright',
						'발광체':'Harmony Light',
						'바다':'Ocean',
						'파스텔':'Pastel',
						'부드러움':'Soft',
						'연한 파스텔':'Soft Pastel',
						'나무':'Vintage',
						'포도':'Violet',
						'단색':'Carmine',
						'우주':'Dark Moon',
						'진보라':'Dark Violet',
						'안개숲':'Green Mist',
						'연파랑':'Soft Blue',
						'기본값':'Material',
						'사무실 테마':'Office',
						'사용자 정의 테마':'Custom',
					};
					
					var paletteList = $('#palette_list').dxSelectBox({
						items: paletteCollection2,
						itemTemplate: function(data) {
							var html = $('<div />');
							$('<p />').text(data).css({
								display: 'inline-block',
								float: 'left'
							}).appendTo(html);
							var itemPalette = DevExpress.viz.getPalette(paletteObject2[data]).simpleSet;
							if (data !== 'None') {
								for (var i = 5; i >= 0; i--) {
									$('<div />').css({
										backgroundColor: itemPalette[i],
										height: 30,
										width: 30,
										display: 'inline-block',
										float: 'right'
									}).appendTo(html);
								}
							}
							return html;
						},
						value: paletteObject[userPalette] || 'None'
					}).dxSelectBox('instance');
					$('.palette-select-ok').on('click', function() {
						$.ajax({
							url: WISE.Constants.context + '/report/saveAccountPalette.do',
							method: 'POST',
							data: {
								palette: paletteObject2[paletteList.option('value')]
							},
							success: function() {
								userPalette = paletteObject2[paletteList.option('value')];
								showSelectedOptions();
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('저장 되었습니다.','success');
								popup.hide();
							},
							error: function() {
								// 2020.01.07 mksong 경고창 UI 변경 dogfoot
								WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
							}
						});
					});
					$('.palette-select-cancel').on('click', function() {
						popup.hide();
					});
				}
			}).dxPopup('instance');
		});

		$('#resetPalette').on('click', function() {
			$.ajax({
				url: WISE.Constants.context + '/report/saveAccountPalette.do',
				method: 'POST',
				data: {
					palette: 'None'
				},
				success: function() {
					userPalette = undefined;
					showSelectedOptions();
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('초기화 되었습니다.','success');
				},
				error: function() {
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
				}
			});
		});
	}

	/**
	 * Initialize user viewer configuration components.
	 */
	function initUserViewerSettings() {
		// 기본 보고서
		$('#setViewerReport').on('click', function() {
			var popup = $('#accountPopup').dxPopup({
				title:'뷰어 보고서 즐겨 찾기',
				visible:true,
				height: "800px",
				width: "600px",
				position: {  
			         my: 'center',  
			         at: 'center',  
			         of: 'body'  
			    },
				showCloseButton: false,
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForListPopup('accountPopup')
				},
				contentTemplate: function(contentElement) {
					var html = 	'<div class="popup-body">' +
									'<div class="modal-article">' + 
										'<div class="modal-tit">' + 
											'<span>보고서 목록</span>' + 
										'</div>' + 
										'<div id="viewer_folder_tree"></div>' +
									'</div>' + 
								'</div>' + 
								'<div class="modal-footer">' + 
									'<div class="row center">' + 
										'<a href="#" class="btn positive viewer-report-select-ok">확인</a>' + 
										'<a href="#" class="btn neutral viewer-report-select-cancel">취소</a>' + 
									'</div>' + 
								'</div>';
					contentElement.append(html);

					$.ajax({
						url: WISE.Constants.context + '/report/getReportList.do',
						method: 'POST',
						data: {
							fld_type: 'PUBLIC',
							user_id: userId,
							report_type: 'ALL'
						},
						success: function(result) {
							result = result.data;
							/* DOGFOOT hsshim 200103
							 * json 포맷 오류 수정
							 */
							// result = JSON.parse(result);
							var report_id, report_nm, report_type, item_type;
							$('#viewer_folder_tree').dxTreeView({
								dataSource:result,
								dataStructure:'plain',
								keyExpr: "uniqueKey",
								parentIdExpr: "upperKey",
								rootValue: "F_0",
								displayExpr: "TEXT",
								// mksong 2019.12.20 보고서 검색 추가 dogfoot
								searchEnabled: true,
								searchMode : "contains",
								searchTimeout:undefined,
								searchValue:"",
								width: '100%',
								height: 550,
								showCloseButton: false,
								onContentReady: function(){
									gDashboard.fontManager.setFontConfigForListPopup('viewer_folder_tree')
								},
								onInitialized:function(_e){
									$.each(_e.component.option('dataSource'),function(_i,_items){
										switch(_items.TYPE){
										case 'REPORT':
											if(_items.REPORT_TYPE == 'DashAny'){
												_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
											}else if(_items.REPORT_TYPE == 'AdHoc'){
												_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';		            						
			            					}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
			            						_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';		            						
											}
											break;
										case 'FOLDER':
											_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
											break;
										}
									});
								},
								onItemClick:function(_e){
									report_id = _e.itemData['ID'];
									report_nm = _e.itemData['TEXT'];
									report_type = _e.itemData['REPORT_TYPE'];
									item_type = _e.itemData['TYPE'];
								}
							});
							$('.viewer-report-select-ok').on('click', function() {
								if (report_id && item_type === 'REPORT') {
									$.ajax({
										url: WISE.Constants.context + '/report/saveAccountViewerReportInfo.do',
										method: 'POST',
										data: {
											reportId: report_id
										},
										success: function() {
											userViewerReportId = report_id;
											userViewerReportNm = report_nm;
											userViewerReportType = report_type;
											showSelectedOptions();
											// 2020.01.07 mksong 경고창 UI 변경 dogfoot
											WISE.alert('저장 되었습니다.','success');
											popup.hide();
										},
										error: function() {
											// 2020.01.07 mksong 경고창 UI 변경 dogfoot
											WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
										}
									});
								}
							});
							$('.viewer-report-select-cancel').on('click', function() {
								popup.hide();
							});
						}
					});
				}
			}).dxPopup('instance');
		});

		$('#resetViewerReport').on('click', function() {
			$.ajax({
				url: WISE.Constants.context + '/report/saveAccountViewerReportInfo.do',
				method: 'POST',
				data: {
					reportId: 0
				},
				success: function() {
					userViewerReportId = undefined;
					userViewerReportNm = undefined;
					userViewerReportType = undefined;
					showSelectedOptions();
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('초기화 되었습니다.','success');
				},
				error: function() {
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('실패 했습니다. 관리자에게 문의 하세요.','error');
				}
			});
		});
	}
	
	/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	function initUserFolderSettings() {
		selectedUserFolderNode = undefined;
		$.ajax({
			url: WISE.Constants.context + '/report/getUserFolderList.do',
			method: 'POST',
			data: {user_no : userJsonObject.userNo},
			async: false,
			dataType: "json",
			success: function(result) {
				$.each(result, function(_i,_items) {
					_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
				});
				$('#folderList').dxTreeView({
					dataSource: result,
					dataStructure: 'plain',
					keyExpr: "FLD_ID",
					parentIdExpr: "PARENT_FLD_ID",
					displayExpr: "FLD_NM",
					// mksong 2019.12.20 보고서 검색 추가 dogfoot
					searchEnabled: true,
					searchMode : "contains",
					searchTimeout:undefined,
					searchValue:"",
					showCloseButton: false,
					/* DOGFOOT ktkang 고용정보원10 문구 수정 */
					noDataText:"조회된 폴더가 없습니다.",
					selectionMode: 'single',
					selectNodesRecursive: false,
					focusStateEnabled: false,
					onItemClick:function(_e) {
						var node = _e.node;
						if (node.selected) {
							_e.component.unselectItem(node.key);
							selectedUserFolderNode = undefined;
						} else {
							_e.component.selectItem(node.key);
							selectedUserFolderNode = node;
						}
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('folderList')
						gProgressbar.hide();
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'repfol-folder') {
								e.component.updateDimensions();
							}
						});
					}
				});
			}
		});
		$('#folderNamePopup').dxPopup({
			title: '이름 편집',
			width: 500,
			height: 'auto',
			contentTemplate: function(e) {
				var html = 	'<div class="tbl data-form">' +
				'<table>' +
				'<colgroup class="folder-name-col">' +
				'<col style="width: auto">' +
				'</colgroup>' +
				'<tbody>' +
				'<tr>' +
				'<th>폴더 이름</th>' +
				'<td class="ipt">' +
				'<input class="wise-text-input folder-name-edit" type="text">' +
				'</td>' +
				'</tr>' +
				'</tbody>' +
				'</table>' +
				'</div>' +
				'<div class="row center popup-footer">' +
				'<a href="#" class="btn positive folder-edit-ok">확인</a>' +
				'<a href="#" class="btn neutral folder-edit-cancel">취소</a>' +
				'</div>';
				e.append(html);
			},
			onContentReady: function(e) {
				$('.folder-edit-ok').on('click', function() {
					e.component.hide();
				});
				$('.folder-edit-cancel').on('click', function() {
					e.component.hide();
				});
				gDashboard.fontManager.setFontConfigForOption('folderNamePopup')
			}
		});
		$('#deleteFolderPopup').dxPopup({
			title: '폴더 삭제',
			width: 500,
			height: 'auto',
			contentTemplate: function(e) {
				var html = 	'<p id="deleteConfirmText"></p>' +
				'<div class="row center popup-footer">' +
				'<a href="#" class="btn positive folder-delete-ok">확인</a>' +
				'<a href="#" class="btn neutral folder-delete-cancel">취소</a>' +
				'</div>';
				e.append(html);
			},
			onContentReady: function(e) {
				$('.folder-delete-ok').on('click', function() {
					e.component.hide();
				});
				$('.folder-delete-cancel').on('click', function() {
					e.component.hide();
				});
			}
		});
		
		$('#newUserFolder').on('click', function() {
			$('#folderNamePopup').dxPopup('instance').show();
			$('.folder-name-edit').val('');
			$('.folder-edit-ok').off('click').on('click', function() {
				var folderName = $('.folder-name-edit').val();
				if (folderName.length > 0) {
					$.ajax({
						url: WISE.Constants.context + '/report/createNewUserFolder.do',
						method: 'POST',
						data: {
							name: folderName,
							parentFolder: selectedUserFolderNode ? selectedUserFolderNode.itemData.FLD_ID : 0,
							user_no : userJsonObject.userNo
						},
						success: function(msg) {
							if (msg) {
								WISE.alert(msg);
							} else {
								$('#folderNamePopup').dxPopup('instance').hide();
								initUserFolderSettings();
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
					WISE.alert(gMessage.get('config.folder.name.isnull'));
				}
			});
		});
		
		$('#editUserFolder').on('click', function() {
			if (selectedUserFolderNode) {
				$('#folderNamePopup').dxPopup('instance').show();
				$('.folder-name-edit').val(selectedUserFolderNode.itemData.FLD_NM);
				$('.folder-edit-ok').off('click').on('click', function() {
					var folderName = $('.folder-name-edit').val();
					if (folderName.length > 0) {
						$.ajax({
							url: WISE.Constants.context + '/report/editUserFolderName.do',
							method: 'POST',
							data: {
								id: selectedUserFolderNode.itemData.FLD_ID,
								name: folderName,
								originalName: selectedUserFolderNode.itemData.FLD_NAME,
								parentId: selectedUserFolderNode.itemData.PARENT_FLD_ID
							},
							success: function(msg) {
								if (msg) {
									WISE.alert(msg);
								} else {
									$('#folderNamePopup').dxPopup('instance').hide();
									initUserFolderSettings();
									//2020.01.21 mksong 경고창 타입 지정 dogfoot
									WISE.alert(gMessage.get('config.folder.name.change.success'),'success');
								}
							},
							error: function() {
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.folder.name.change.failed'),'error');
							}
						});
					} else {
						WISE.alert(gMessage.get('config.folder.name.isnull'));
					}
				});
			}
		});
		
		$('#deleteUserFolder').on('click', function() {
			if (selectedUserFolderNode) {
				$('#deleteFolderPopup').dxPopup('instance').show();
				var folderList = getFolderStructure(selectedUserFolderNode);

				if (selectedUserFolderNode.children.length > 0) {
					$('#deleteConfirmText').text(gMessage.get('config.folder.multiple-folder-delete'));
				} else {
					$('#deleteConfirmText').text(gMessage.get('config.delete.confirm'));
				}
				$('.folder-delete-ok').off('click').on('click', function() {
					$.ajax({
						url: WISE.Constants.context + '/report/nestedReportsExist.do',
						method: 'POST',
						data: {folders: folderList},
						beforeSend: function() {
							$('#deleteFolderPopup').dxPopup('instance').hide();
						},
						success: function(exists) {
							if (exists === 'Y') {
								$('#deleteFolderPopup').dxPopup('instance').show();
								$('#deleteConfirmText').text(gMessage.get('config.folder.multiple-report-delete'));
								$('.folder-delete-ok').off('click').on('click', function() {
									$.ajax({
										url: WISE.Constants.context + '/report/deleteUserFoldersAndReports.do',
										method: 'POST',
										data: {
											parent: selectedUserFolderNode.key,
											folders: folderList
										},
										beforeSend: function() {
											$('#deleteFolderPopup').dxPopup('instance').hide();
										},
										success: function() {
											//2020.01.21 mksong 경고창 타입 지정 dogfoot
											WISE.alert(gMessage.get('config.delete.success'),'success');
											initUserFolderSettings();
										},
										error: function() {
											//2020.01.21 mksong 경고창 타입 지정 dogfoot
											WISE.alert(gMessage.get('config.delete.failed'),'error');
										}
									});
								});
							} else {
								$.ajax({
									url: WISE.Constants.context + '/report/deleteUserFolders.do',
									method: 'POST',
									data: {
										parent: selectedUserFolderNode.key,
										folders: folderList
									},
									success: function() {
										//2020.01.21 mksong 경고창 타입 지정 dogfoot
										WISE.alert(gMessage.get('config.delete.success'),'success');
										initUserFolderSettings();
									},
									error: function() {
										//2020.01.21 mksong 경고창 타입 지정 dogfoot
										WISE.alert(gMessage.get('config.delete.failed'),'error');
									}
								});
							}
						},
						error: function() {
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.delete.failed'),'error');
						}
					});
				});
			}
		});
	}
	
	function getFolderStructure(folderNode) {
		var list = [];
		if (!folderNode) {
			return list;
		} if (folderNode.children.length > 0) {
			list.push(folderNode.key);
			folderNode.children.forEach(function(child) {
				var secondChildrenIds = getFolderStructure(child);
				list = list.concat(secondChildrenIds);
			});
			return list;
		} else {
			return [folderNode.key];
		}
	}
	
	function initUserReportSettings() {
		$.ajax({
			url: WISE.Constants.context + '/report/getUserReportList.do',
			method: 'POST',
			data: {user_no : userJsonObject.userNo},
			async: false,
			dataType: "json",
			success: function(result) {
				$.each(result, function(_i,_items) {
					switch (_items.TYPE) {
						case 'REPORT':
							if (_items.REPORT_TYPE === 'DashAny') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_squariFied.png';
							} else if (_items.REPORT_TYPE === 'AdHoc') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_atypical01.png';	            						
							} else if (_items.REPORT_TYPE === 'Spread' || _items.REPORT_TYPE === 'Excel') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msexcell.png';
							} else if (_items.REPORT_TYPE === 'Word' || _items.REPORT_TYPE === 'WordGrp') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msword.png';
							}
							break;
						case 'FOLDER':
							_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
							break;
						default: break;
					}
				});
				
				$('#reportId').text('');
				$('#reportDataLoad').prop('checked', false);
				$('#reportTitle').val('');
				$('#reportSubtitle').val('');
				$('#reportType').text('');
				$('#publisherName').text('');
				$('#publishedDate').text('');
				$('#reportTag').val('');
				$('#reportDesc').val('');
				$('#reportQuerySql').val('');
				
				var report_id, report_nm, report_type, item_type;
				$('#reportList').dxTreeView({
					dataSource: result,
					dataStructure: 'plain',
					keyExpr: "ID",
					parentIdExpr: "UPPERID",
					// mksong 2019.12.20 보고서 검색 추가 dogfoot
					searchEnabled: true,
        			searchMode : "contains",
        			searchTimeout:undefined,
        			searchValue:"",
        			// 2019.12.20 mksong nodata 텍스트 수정 dogfoot
        			noDataText:"조회된 보고서가 없습니다.",
					displayExpr: "TEXT",
					showCloseButton: false,
					selectionMode: 'single',
					selectByClick: true,
					selectNodesRecursive: false,
					focusStateEnabled: false,
					repaintChangesOnly: true,
					onItemClick:function(_e){
						report_id = _e.itemData['ID'];
						report_nm = _e.itemData['TEXT'];
						report_type = _e.itemData['REPORT_TYPE'];
						item_type = _e.itemData['TYPE'];
						
						var item = _e.itemData;
						if (item.TYPE === 'REPORT') {
							$('#reportId').text(item.ID);
							$('#reportDataLoad').prop('checked', item.PROMPT === 'Y');
							$('#reportTitle').val(item.TEXT);
							$('#reportSubtitle').val(item.SUBTITLE);
							$('#reportType').text(item.REPORT_TYPE);
							$('#publisherName').text(item.CREATED_BY);
							$('#publishedDate').text(item.CREATED_DATE);
							$('#reportTag').val(item.TAG);
							$('#reportOrder').val(item.ORDINAL);
							$('#reportDesc').val(item.DESCRIPTION);
							$('#reportQuerySql').val(item.QUERY);
						} else if (item.TYPE === 'FOLDER') {
							$('#reportId').text('');
							$('#reportDataLoad').prop('checked', false);
							$('#reportTitle').val('');
							$('#reportSubtitle').val('');
							$('#reportType').text('');
							$('#publisherName').text('');
							$('#publishedDate').text('');
							$('#reportTag').val('');
							$('#reportOrder').val('');
							$('#reportDesc').val('');
							$('#reportQuerySql').val('');
						}
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('reportList')
						gProgressbar.hide();
					},
				});
				
				$('#saveUserReport').on('click', function() {
					if (report_id) {
						$.ajax({
							url: WISE.Constants.context + '/report/savePublicReport.do',
							method: 'POST',
							data: { 
								ID: report_id,
								PROMPT: $('#reportDataLoad').prop('checked') ? 'Y' : 'N',
										TEXT: $('#reportTitle').val(),
										SUBTITLE: $('#reportSubtitle').val(),
										TAG: $('#reportTag').val(),
										ORDINAL: $('#reportOrder').val(),
										DESCRIPTION: $('#reportDesc').val()
							},
							success: function() {
								initUserReportSettings();
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.save.success'),'success');
							},
							error: function() {
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.save.failed'),'error');
							}
						});
					}
				});
				
				$('#deleteReportPopup').dxPopup({
					title: '보고서 삭제',
					width: 500,
					height: 'auto',
					contentTemplate: function(e) {
						var html = 	'<p id="reportDeleteConfirmText">' + gMessage.get('config.delete.confirm') + '</p>' +
									'<div class="row center popup-footer">' +
										'<a href="#" class="btn positive report-delete-ok">확인</a>' +
										'<a href="#" class="btn neutral report-delete-cancel">취소</a>' +
									'</div>';
						e.append(html);
					},
					onContentReady: function(e) {
						$('.report-delete-ok').on('click', function() {
							e.component.hide();
						});
						$('.report-delete-cancel').on('click', function() {
							e.component.hide();
						});
					}
				});
				
				$('#deleteUserReport').on('click', function() {
					if (report_id) {
						$('#deleteReportPopup').dxPopup('instance').show();
						$('.report-delete-ok').off('click').on('click', function() {
							$.ajax({
								url: WISE.Constants.context + '/report/deletePublicReport.do',
								method: 'POST',
								data: { id: report_id },
								beforeSend: function() {
									$('#deleteReportPopup').dxPopup('instance').hide();
								},
								success: function() {
									initUserReportSettings();
									//2020.01.21 mksong 경고창 타입 지정 dogfoot
									WISE.alert(gMessage.get('config.delete.success'),'success');
								},
								error: function(error) {
									//2020.01.21 mksong 경고창 타입 지정 dogfoot
									WISE.alert(gMessage.get('config.delete.failed'),'error');
								}
							});
						});
					}
				});
			}
		});
	}

	/**
	 * Set text of selected user options.
	 */
	function showSelectedOptions() {
	//20200720 ajkim 유저 설정 즐겨찾기 한글화 dogfoot
		var paletteObject = {
				'Bright':'밝음',
				'Harmony Light':'발광체',
				'Ocean':'바다',
				'Pastel':'파스텔',
				'Soft':'부드러움',
				'Soft Pastel':'연한 파스텔',
				'Vintage':'나무',
				'Violet':'포도',
				'Carmine':'단색',
				'Dark Moon':'우주',
				'Dark Violet':'진보라',
				'Green Mist':'안개숲',
				'Soft Blue':'연파랑',
				'Material':'기본값',
				'Office':'사무실 테마',
				'Custom':'사용자 정의 테마',
			};
		
		var itemObject = {
				'None':'없음',
				'AdHoc':'비정형',
				'Bar':'막대 차트',
				'StackedBar':'스택 막대 차트',
				'FullStackedBar':'풀스택 막대 차트',
				'Point':'점 차트',
				'Line':'선 차트',
				'StackedLine':'스택 선 차트',
				'FullStackedLine':'풀스택 선 차트',
				'StepLine':'계단 차트',
				'Spline':'곡선 차트',
				'Area':'영역 차트',
				'StackedArea':'스택 영역 차트',
				'FullStackedArea':'풀스택 영역 차트',
				'StepArea':'계단 영역 차트',
				'SplineArea':'곡선 영역 차트',
				'StackedSplineArea':'스택 곡선 영역 차트',
				'FullStackedSplineArea':'풀스택 곡선 영역 차트',
				'Bubble':'버블 차트2',
				'PivotGrid':'피봇 그리드',
				'DataGrid':'일반 그리드',
				'PieChart':'파이 차트',
				'Card':'카드',
				'ChoroplethMap':'코로플레스',
				'ParallelCoordinate':'평행좌표계',
				'BubblePackChart':'버블 팩 차트',
				'Waterfallchart':'폭포수 차트',
				'HistogramChart':'히스토그램 차트',
				'BubbleD3':'버블 차트',
				'RectangularAreaChart':'네모 영역',
				'TreeMap':'트리맵',
				'StarChart':'스타 차트',
				'HeatMap':'히트맵',
				'WordCloud':'워드클라우드',
				'HierarchicalEdge':'계층 차트',
				'RangeBarChart':'레인지 바 차트',
				'RangeAreaChart':'레인지 영역 차트',
				'TimeLineChart':'타임라인 차트',
			};
		$('#datasetName').text(userDatasetNm || '');
		$('#reportName').text(userReportNm || '');
		$('#itemName').text(itemObject[userItem] || '');
		$('#paletteName').text(paletteObject[userPalette] || '');
		$('#viewerReportName').text(userViewerReportNm || '');
	}

	return {
		/**
		 * Initialize accountMaster class.
		 */
		initUserSettings: function() {
			init();
			initLayout();
//			initUserInfo();
//			initUserInputValidation();
			initUserEditorSettings();
			initUserViewerSettings();
			/* DOGFOOT ktkang 개인보고서 추가  20200107 */
			initUserFolderSettings();
			initUserReportSettings();
			showSelectedOptions();
		}
	}
})();

/**
 * Main
 */
$(document).ready(function() {
	gConsole = new WISE.Console();
	gMessage = new WISE.lang.Message();
	if (!$('#progress_box').length) {
		gProgressbar = new WISE.libs.Progressbar();
	}
	gDashboard = new WISE.libs.Dashboard('gDashboard', 'contentContainer');
	gDashboard.init();

	accountMaster.initUserSettings();
});
