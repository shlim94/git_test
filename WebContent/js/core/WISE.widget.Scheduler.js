/**
 * Scheduler for saving and loading datasets.
 */

WISE.libs.Dashboard.Scheduler = function() {
	var self = this;
	
	/*
	 * variables
	 */
	var multiView, dataTree, mainSchedule, mainLoad, mainDelete, dateList, dateScheduler, dateScheduleBtn, dateDeleteBtn, dateBackBtn, running;
	this.reportId, this.userId, this.dataList, this.scheduleList;
	
	/*
	 * functions
	 */
	this.getDataFileList = function() {
		$.ajax({
			url: WISE.Constants.context + '/report/getScheduledData.do',
			async: false,
			success: function(data) {
				var files = JSON.parse(data);
				var validFiles = [];
				$.each(files, function(i, file) {
					if (parseInt(file.text.split('-')[1]) == self.reportId) {
						validFiles.push(file);
					}
				});
				self.dataList[0].items = validFiles;
			}
		});
	}
	
	this.getScheduleList = function() {
		$.ajax({
			type: 'post',
			url: WISE.Constants.context + '/report/selectReportScheduleList.do',
			data: {
				user_id: self.userId,
				report_id: self.reportId
			},
			async: false,
			success: function(data) {
				self.scheduleList = JSON.parse(data).data;
			}
		});
	}
	
	/*
	 * main function
	 */
	this.init = function() {
		// initialize variables
		self.reportId = gDashboard.structure.ReportMasterInfo.id;
		self.userId = userJsonObject.userNo+"";
		// self.userId = gDashboard.structure.ReportMasterInfo.fld_id;
		self.dataList = [
			{
				id: '0',
				text: self.reportId,
				expanded: true,
				items: undefined
			}
		];
		self.scheduleList = [];
		
		// initialize popup
		$('body').append('<div id="schedulerPopup"></div>');
		var popup = $('#schedulerPopup').dxPopup({
			contentTemplate: function(element) {
				element.append('<div id="popupMultiView"></div>');
				// initiate main view and date view
				multiView = $('#popupMultiView').dxMultiView({
					items: [
						{
							template: $('<div id="scheduleDateView"></div>')
						},
						{
							template: $('<div id="scheduleMainView"></div>')
						}
					],
					deferRendering: false,
					height: '100%',
					width: '100%',
					selectedIndex: 0,
					loop: false,
					swipeEnabled: false,
					onContentReady: function(e)  {
						self.getScheduleList();
						self.getDataFileList();
						
						/*
						 * view 1
						 */
						$('#scheduleDateView').append('<div id="dateScheduleToolbar"></div>');
						$('#scheduleDateView').append('<div id="dateScheduleList" class="list-container"></div>');
						//$('#scheduleDateView').append('<div id="dateScheduleMaker"></div>');
						$('#scheduleDateView').append('<div id="dateScheduleBtnParent" style="position:relative;bottom:-10px;"><div id="dateScheduleBtn" class="scheduler-widget date-button"></div></div>');
						$('#scheduleDateView').append('<div id="scheduleList" style="position:relative;top:-30px;color:white;">list</div>');
						//$('#scheduleDateView').append('<div id="dateDeleteBtn" class="scheduler-widget middle-widget date-button"></div>');
						//$('#scheduleDateView').append('<div id="dateBackBtn" class="scheduler-widget right-widget date-button"></div>');
						/* DOGFOOT ktkang 스케줄링 오류 수정  20201007 */
						var cycleType = '2';
						dateScheduleToolbar = $('#dateScheduleToolbar').dxToolbar({
							items: [{
								location: 'before',
								template: function() {
									return $('<divc class="toolbar-label">실행주기 유형</div>');
								}
							},{
								location: 'before',
								widget: 'dxSelectBox',
								options: {
									dataSource: [{
										caption: '정기',
										value: '1'
									},{
										caption: '비정기',
										value: '2'
									}],
									displayExpr: "caption",
				                    valueExpr: "value",
									value: '2',
									onValueChanged: function(args) {
										cycleType = args.value;
									}
								}
							},{
								location: 'after',
								widget: 'dxButton',
								options: {
									icon: "plus",
									onClick: function() {
										if(cycleType=='1')
											popupCycleRegular.show()
										else if(cycleType=='2')
											popupCycleInRegular.show()
									}
								}
							},{
								location: 'after',
								widget: 'dxButton',
								options: {
									icon: "trash",
									onClick: function() {
										var selectedDates = dateList.getSelectedRowsData();
										if (selectedDates.length>0) {
											var schIds = [];
											$.each(selectedDates,function(i,d){
												schIds.push(selectedDates[i]['SCH_ID']);
											});
											$.ajax({
												type: 'post',
												data: {
													selectSchId: schIds.join(','),
													user_id: self.userId
												},
												url: WISE.Constants.context + '/report/deleteReportSchedule.do',
												success: function(data) {
													self.getScheduleList();
													dateList.option('dataSource', self.scheduleList);
												},
												error: function(x) {
													WISE.alert('error'+ajax_error_message(x),'error');
												}
											});
										}
									}
								}
							}]
						}).dxToolbar('instance');
						// list of scheduled routines
						dateList = $('#dateScheduleList').dxDataGrid({
							dataSource: self.scheduleList,
							columns: [
								{
									caption: '예약ID',
									dataField: 'SCH_ID',
									width: 100
								},{
									caption: '현재상태',
									dataField: 'STATUS_CD',
									lookup: {
										dataSource: [{
											caption: '실행대기',
											value: '40'
										},{
											caption: '실행중',
											value: '50'
										},{
											caption: '실행완료',
											value: '60'
										},{
											caption: '에러',
											value: '99'
										}],
										displayExpr: "caption",
					                    valueExpr: "value"
									},
									width: 100
								},{
									caption: '실행일시',
									dataField: 'SCH_DT'
								}
							],
							onSelectionChanged: function(selectedItems) {
								/*
								if (selectedItems.selectedRowsData.length === 0) {
									dateDeleteBtn.option('disabled', true);
								} else {
									dateDeleteBtn.option('disabled', false);
								}
								*/
							},
							scrolling: {
								mode: 'standard',
								scrollByThumb: 'true',
								showScrollbar: 'onScroll',
								useNative: false
							},
							selection: {
								mode: 'multiple'
							},
							showScrollbar: 'onScroll',
							useNativeScrolling: 'false'
						}).dxDataGrid('instance');
						// routine scheduler
						dateScheduler = $('#dateScheduleMaker').dxDateBox({
							acceptCustomValue: false,
							applyButtonText: '확인',
							cancelButtonText: '취소',
							dateSerializationFormat: 'yyyy-MM-dd HH:mm:ss',
							pickerType: 'calendar',
							showAnalogClock: true,
							type: 'datetime',
							width: 460,
						}).dxDateBox('instance');
						// confirm routine scheduling button
						dateScheduleBtn = $('#dateScheduleBtn').dxButton({
							text: '확인',
							onClick: function() {
								popup.hide();
								/*
								var newDate = dateScheduler.option('value');
								$.ajax({
				            		type: 'post',
				            		async: false,
				            		data: {
				            			date: newDate,
				            			report_id: self.reportId,
				            			user_id: self.userId
				            		},
				            		url: WISE.Constants.context + '/report/insertReportSchedule.do',
				            		success: function(data) {
				            			self.getScheduleList();
				            			dateList.option('dataSource', self.scheduleList);
				            		},
				            		error: function(e) {
				            			WISE.alert('error'+ajax_error_message(e),'error');
				            		}
				            	});
								*/
							}
						}).dxButton('instance');
						/*
						// delete scheduled routine button
						dateDeleteBtn = $('#dateDeleteBtn').dxButton({
							text: '삭제',
							disabled: true,
							onClick: function() {
								var selectedDates = dateList.getSelectedRowsData();
								if (selectedDates.length === 0) {
									//
								} else {
									$.ajax({
										type: 'post',
										data: {
											selectSchId: selectedDates[0]['스케쥴ID'],
											user_id: self.userId
										},
										url: WISE.Constants.context + '/report/deleteReportSchedule.do',
										success: function(data) {
											self.getScheduleList();
											dateList.option('dataSource', self.scheduleList);
										},
										error: function(x) {
											WISE.alert('error'+ajax_error_message(x),'error');
										}
									});
								}
							}
						}).dxButton('instance');
						// back to main view button
						dateBackBtn = $('#dateBackBtn').dxButton({
							text: '뒤로',
							onClick: function() {
								self.getDataFileList();
								dataTree.option('items', self.dataList);
								popup.option('title', '저장 된 데이터');
								multiView.option('selectedIndex', 0);
							}
						}).dxButton('instance');
						*/
						$("#scheduleList").dblclick(function(e){
							multiView.option('selectedIndex', 1);
						});
						
						/*
						 * view 2
						 */
						$('#scheduleMainView').append('<div id="mainDataTree" class="list-container"></div>');
						$('#scheduleMainView').append('<div id="mainWidgetContainer" class="scheduler-widget-container"></div>')
						$('#mainWidgetContainer').append('<div id="mainScheduleBtn" class="scheduler-widget left-widget main-button"></div>');
						$('#mainWidgetContainer').append('<div id="mainLoadBtn" class="scheduler-widget middle-widget main-button"></div>');
						$('#mainWidgetContainer').append('<div id="mainDeleteBtn" class="scheduler-widget right-widget main-button"></div>');
					
						// list of saved routines
						dataTree = $('#mainDataTree').dxTreeView({
							items: self.dataList,
							onItemClick: function(e) {
								e.component.selectedItem = e.itemData;
								mainLoad.option('disabled', false);
								//mainDelete.option('disabled', false);
							},
							selectByClick: true,
							selectionMode: 'single',
							scrolling: {
								mode: 'standard',
								rowRenderingMode: 'standard',
								showScrollbar: 'onScroll',
								useNative: false
							}
						}).dxTreeView('instance');
						// schedule routine button
						mainSchedule = $('#mainScheduleBtn').dxButton({
							text: '스케줄 편집',
							onClick: function() {
                                //self.getScheduleList();
                                //dateList.option('dataSource', self.scheduleList);
								//popup.option('title', '스케줄 편집');
								multiView.option('selectedIndex', 0);
							}
						}).dxButton('instance');
						// load data button
						mainLoad = $('#mainLoadBtn').dxButton({
							disabled: true,
							text: '불러오기',
							onClick: function() {
                                var dataFileName = dataTree.selectedItem.text;
                                gProgressbar.show();
								$.ajax({
									data: {
										fileName: dataFileName
									},
									url: WISE.Constants.context + '/report/loadSavedData.do',
									success: function(data) {
										var loadData = JSON.parse(data);

                                        gDashboard.itemGenerateManager.dxItemBasten.forEach(function(item) {
                                            var dataSourceName;
                                            for (var i = 0; i < item.dataSources.length; i++) {
                                                if (item.dataSourceId === item.dataSources[i].ComponentName) {
                                                    dataSourceName = item.dataSources[i].Name;
                                                    break;
                                                }
                                            }
                                            item.bindData(loadData[dataSourceName], true);
                                        });
                                        gProgressbar.hide();
                                        popup.hide();
									},
									error: function(x) {
                                        gProgressbar.hide();
                                        WISE.alert('error'+ajax_error_message(x),'error');
									}
								});	
							}
						}).dxButton('instance');
						// delete data from server button
						/*
						mainDelete = $('#mainDeleteBtn').dxButton({
							disabled: true,
							text: '삭제',
							onClick: function() {
								var dataFileName = dataTree.selectedItem.text;
								var dataSchId = dataFileName.split('-')[0];
								var dataReportId = dataFileName.split('-')[1];
								$.ajax({
									type: 'post',
									data: {
										schId: dataSchId,
										reportId: dataReportId,
										fileName: dataFileName
									},
									url: WISE.Constants.context + '/report/deleteSavedData.do',
									success: function() {
										self.getDataFileList();
										dataTree.option('items', self.dataList);
									},
									error: function(x) {
										WISE.alert('error'+ajax_error_message(x),'error');
									}
								});									
							}
						}).dxButton('instance');						
						*/
					}
				}).dxMultiView('instance');
			},
			onHidden: function() {
				dateList.deselectAll();
				//mainLoad.option('disabled', true);
				//mainDelete.option('disabled', true);
			},
			showTitle: true,
			title: '스케줄 편집',
			visible: false,
			width: 'auto',
			height: 'auto'
		}).dxPopup('instance');

		//정기 스케쥴		
		$('body').append('<div id="schedulerRegularPopup"></div>');
		var popupCycleRegular = $('#schedulerRegularPopup').dxPopup({
			contentTemplate: function(element) {
				element.append('<div id="popupRegularView"></div>');
				var popupRegularViewHtml = '<div class="row">'+
					'<div class="col"><div class="scheduleStartDateLabel">시작일자</div><div class="scheduleEndDateLabel">종료일자</div></div>'+
					'<div class="col"><div id="regularStartDate"></div><div id="regularEndDate"></div></div>'+
					'<div class="col"><div id="regularTime"></div></div>'+
				'</div>'+
				'<div class="row">'+
					'<div class="col scheduleStandardDateLabel">실행기준 일자</div>'+
					'<div class="col">'+
						'<div class="row">'+
							'<div class="col" id="regularGrid1"></div>'+
							'<div class="col" id="regularGrid2"></div>'+
							'<div class="col" id="regularGrid3"></div>'+
						'</div>'+
					'</div>'+
				'</div>'+
				'<div id="dateRegularBtnParent">'+
					'<div id="dateRegularOKBtn" class="scheduler-widget date-button"></div>'+
					'<div id="dateRegularCancelBtn" class="scheduler-widget date-button"></div>'+
				'</div>';
				$('#popupRegularView').append(popupRegularViewHtml);
				
				regularStartDate = $('#regularStartDate').dxDateBox({
					acceptCustomValue: false,
					applyButtonText: '확인',
					cancelButtonText: '취소',
					dateSerializationFormat: 'yyyy-MM-dd',
					pickerType: 'calendar',
					showAnalogClock: false,
					type: 'date',
					width: 200,
					value: new Date().format('yyyy-MM-dd')
				}).dxDateBox('instance');
				
				regularEndDate = $('#regularEndDate').dxDateBox({
					acceptCustomValue: false,
					applyButtonText: '확인',
					cancelButtonText: '취소',
					dateSerializationFormat: 'yyyy-MM-dd',
					pickerType: 'calendar',
					showAnalogClock: false,
					type: 'date',
					width: 200,
					value: new Date().format('yyyy-MM-dd')
				}).dxDateBox('instance');
				
				regularTime = $('#regularTime').dxDateBox({
					acceptCustomValue: false,
					applyButtonText: '확인',
					cancelButtonText: '취소',
					dateSerializationFormat: 'HH:mm:ss',
					pickerType: 'rollers',
					showAnalogClock: true,
					type: 'time',
					width: 200,
					value: new Date().format('HH:mm:ss')
				}).dxDateBox('instance');
				
				var months = [];
				for(var i=1;i<13;i++) months.push({'month':i});
				var weekStr = ['월', '화', '수', '목', '금', '토', '일'];
				var weeks = [];
				for(var i=1;i<8;i++) weeks.push({'week':i});
				var days = [];
				for(var i=0;i<32;i++) days.push({'day':i});

				regularGrid1 = $('#regularGrid1').dxDataGrid({
					width: 200,
					height: 400,
					showBorders: true,
					showColumnLines: true,
					//showRowLines: true,
					dataSource: months,
					columns: [{
						caption: '월 기준',
						dataField: 'month',
						customizeText: function(cellInfo) {
							return cellInfo.value+"월";
						}
					}],
					selection: {
						mode: 'multiple'
					},
				}).dxDataGrid('instance');

				regularGrid2 = $('#regularGrid2').dxDataGrid({
					width: 200,
					height: 400,
					showBorders: true,
					showColumnLines: true,
					//showRowLines: true,
					dataSource: weeks,
					columns: [{
						caption: '요일 기준',
						dataField: 'week',
						width: 100,
						customizeText: function(cellInfo) {
							return weekStr[cellInfo.value-1];
						}
					}],
					selection: {
						mode: 'multiple'
					},
				}).dxDataGrid('instance');
				setTimeout(function(){
					$('#regularGrid2 .dx-freespace-row').css('height','124px');
				},300);

				regularGrid3 = $('#regularGrid3').dxDataGrid({
					width: 200,
					height: 400,
					showBorders: true,
					showColumnLines: true,
					//showRowLines: true,
					dataSource: days,
					columns: [{
						caption: '일 기준',
						dataField: 'day',
						width: 100,
						customizeText: function(cellInfo) {
							if(cellInfo.value==0) {
								return '월말';
							} else {
								return cellInfo.value+"일";
							}
						}
					}],
					selection: {
						mode: 'multiple'
					},
					paging: {
						enabled: false
					}
				}).dxDataGrid('instance');

				dateRegularOKBtn = $('#dateRegularOKBtn').dxButton({
					text: '확인',
					onClick: function() {
						var startDate = regularStartDate.option('value');
						var endDate = regularEndDate.option('value');
						var execTime = regularTime.option('value');
						$.ajax({
		            		type: 'post',
		            		async: false,
		            		data: {
		            			start_date: startDate,
								end_date: endDate,
								exec_time: execTime,
								regular_month: JSON.stringify(regularGrid1.getSelectedRowsData()),
								regular_week: JSON.stringify(regularGrid2.getSelectedRowsData()),
								regular_day: JSON.stringify(regularGrid3.getSelectedRowsData()),
		            			report_id: self.reportId,
		            			user_id: self.userId
		            		},
		            		url: WISE.Constants.context + '/report/insertReportScheduleRegular.do',
		            		success: function(data) {
		            			self.getScheduleList();
		            			dateList.option('dataSource', self.scheduleList);
								popupCycleRegular.hide();
		            		},
		            		error: function(e) {
		            			WISE.alert('error'+ajax_error_message(e),'error');
		            		}
		            	});
					}
				}).dxButton('instance');
				
				dateRegularCancelBtn = $('#dateRegularCancelBtn').dxButton({
					text: '취소',
					onClick: function() {
						popupCycleRegular.hide();
					}
				}).dxButton('instance');
			},
			showTitle: true,
			title: '스케쥴 관리',
			visible: false,
			width: 'auto',
			height: 'auto'			
		}).dxPopup('instance');
		
		
		//비정기 스케쥴
		$('body').append('<div id="schedulerInRegularPopup"></div>');
		var popupCycleInRegular = $('#schedulerInRegularPopup').dxPopup({
			contentTemplate: function(element) {
				element.append('<div id="popupInRegularView"></div>');
				var popupInRegularViewHtml = '<div class="row">'+
					'<div class="col"><div class="scheduleExecDateLabel">비정기 실행일자</div></div>'+
					'<div class="col"><div id="inRegularExecDate"></div></div>'+
				'</div>'+
				'<div id="dateInRegularBtnParent">'+
					'<div id="dateInRegularOKBtn" class="scheduler-widget date-button"></div>'+
					'<div id="dateInRegularCancelBtn" class="scheduler-widget date-button"></div>'+
				'</div>';
				$('#popupInRegularView').append(popupInRegularViewHtml);
				
				inRegularExecDate = $('#inRegularExecDate').dxDateBox({
					acceptCustomValue: false,
					applyButtonText: '확인',
					cancelButtonText: '취소',
					dateSerializationFormat: 'yyyy-MM-dd HH:mm:ss',
					pickerType: 'calendar',
					showAnalogClock: true,
					type: 'datetime',
					width: 300,
					value: new Date().format('yyyy-MM-dd HH:mm:ss')
				}).dxDateBox('instance');

				dateInRegularOKBtn = $('#dateInRegularOKBtn').dxButton({
					text: '확인',
					onClick: function() {
						var newDate = inRegularExecDate.option('value');
						$.ajax({
		            		type: 'post',
		            		async: false,
		            		data: {
		            			date: newDate,
		            			report_id: self.reportId,
		            			user_id: self.userId
		            		},
		            		url: WISE.Constants.context + '/report/insertReportSchedule.do',
		            		success: function(data) {
		            			self.getScheduleList();
		            			dateList.option('dataSource', self.scheduleList);
								popupCycleInRegular.hide();
		            		},
		            		error: function(e) {
		            			WISE.alert('error'+ajax_error_message(e),'error');
		            		}
		            	});
					}
				}).dxButton('instance');
				
				dateInRegularCancelBtn = $('#dateInRegularCancelBtn').dxButton({
					text: '취소',
					onClick: function() {
						popupCycleInRegular.hide();
					}
				}).dxButton('instance');
			},
			showTitle: true,
			title: '스케쥴 관리',
			visible: false,
			width: 'auto',
			height: 'auto'						
		}).dxPopup('instance');
		
		// initialize scheduler button
		$('#openScheduler').on('click', function() {
            if (gDashboard.structure.ReportMasterInfo.id) {
				self.reportId = gDashboard.structure.ReportMasterInfo.id;
				popup.show();
			}
			/*
			var condition = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
            if (gDashboard.structure.ReportMasterInfo.id) {
				$.ajax({
					type: 'post',
					url: WISE.Constants.context + '/report/runScheduleChecker.do',
					async: false,
					data: {
						reportId: self.reportId,
						userId: self.userId,
						params: $.toJSON(condition)
					},
					success: function() {
						popup.show();
					}
				});
            }
			*/
        });
	}
}
