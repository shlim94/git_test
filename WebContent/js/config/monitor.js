var monitorManager = (function() {
	/* DOGFOOT ktkang 모니터링 부분 기능 추가  20201014 */
	var self = this;
	
	this.log_seq;
	/* private methods */
	function getRangeColor(p) {
		if (p < 33.0) {
			return '#77DD77';
		} else if (p >= 33.0 && p < 67.0) {
			return '#E6E200';
		} else {
			return '#FF0000';
		}
	}

	function initSystemInfo() {
		var systemItems = [
			{
				dataField: 'OS Name',
			}, 
			{
				dataField: 'TotalMem',
			}, 
			{
				dataField: 'FreeMem',
			}, 
			{
				dataField: 'TotalSpace',
			}, 
			{
				dataField: 'FreeSpace',
			}, 
			{
				dataField: 'IO Read',
			}, 
			{
				dataField: 'IO Write',
			}
		];
		
		// data variables
		var cpuGauge, memGauge, diskGauge, memPer, cpuPer, diskPer, ioRead, ioWrite;
		
		var cpuDataSource = new DevExpress.data.DataSource({ 
			store: {
				type: "array"
			},
			paginate: false
		});
		var cpuStore = cpuDataSource.store();

		var memDataSource = new DevExpress.data.DataSource({ 
			store: {
				type: "array"
			},
			paginate: false
		});
		var memStore = memDataSource.store();
		
		var diskDataSource = new DevExpress.data.DataSource({
			store: {
				type: "array"
			},
			paginate: false
		});
		var diskStore = diskDataSource.store();
		
		$.ajax({
			url: './getSystemProperty.do',
			async: false,
			cache: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				
				var systemProper = JSON.parse(_data);
			
				// form
				$('#systemInfo').dxForm({
					formData: systemProper.OSobj,
					items: systemItems,
					readOnly: true,
					scrollingEnabled: true
				});
				
				cpuPer = parseFloat((systemProper.OSobj.cpu * 100).toFixed(2));
				memPer = parseFloat((systemProper.OSobj.PerMem * 1).toFixed(2));
				diskPer = parseFloat((systemProper.OSobj.PerSpace * 100).toFixed(2));
				ioRead = parseFloat(systemProper.OSobj['IO Read'].split(' ')[0]);
				ioWrite = parseFloat(systemProper.OSobj['IO Write'].split(' ')[0]);
				
				// cpu
				cpuGauge = $('#cpuGauge').dxCircularGauge({
					rangeContainer: {
						ranges: [
							{ startValue: 0, endValue: 33, color: '#77DD77' },
							{ startValue: 33, endValue: 67, color: '#E6E200' },
							{ startValue: 67, endValue: 100, color: '#FF0000' }
						]
					},
					scale: {
						startValue: 0, endValue: 100,
						customTicks: [0, 33, 67, 100],
						label: {
							customizeText: function (arg) {
								return arg.valueText + ' %';
							}
						}
					},
					value: cpuPer,
					valueIndicator: {
						type: 'TriangleNeedle'
					},
					subvalues: cpuPer,
					subvalueIndicator: {
						type: 'textCloud',
						color: getRangeColor(cpuPer),
						text: {
							customizeText: function (arg) {
								return arg.valueText + ' %';
							}
						}
					}
				}).dxCircularGauge('instance');

				cpuStore.insert({ time: new Date(), per: cpuPer })

				
				$('#cpuChart').dxChart({
					dataSource: cpuDataSource,
					commonSeriesSettings: {
						argumentField: 'time'
					},
					series: [
						{
							valueField: 'per',
							type: 'line',
							point: {
								visible: false
							}
						}
					],
					argumentAxis: {
						type: 'continuous',
						aggregationInterval: {
							seconds: 15
						},
						label: {
							format: "HH:mm:ss"
						}
					},
					valueAxis: {
						type: 'continuous',
						tickInterval: 50,
						valueType: 'numeric',
						position: 'right',
						label: {
							customizeText: function(e) {
								return e.valueText + ' %';
							}
						},
						// 18.1
						min: 0,
						max: 100,
						// 18.2
						visualRange: {
							startValue: 0,
							endValue: 100
						},
						visualRangeUpdateMode: 'keep'
					},
					legend: {
						visible: false
					},
					point: {
						visible: false
					}
				});
				
				// memory
				memGauge = $('#memGauge').dxCircularGauge({
					rangeContainer: {
						ranges: [
							{ startValue: 0, endValue: 33, color: '#77DD77' },
							{ startValue: 33, endValue: 67, color: '#E6E200' },
							{ startValue: 67, endValue: 100, color: '#FF0000' }
						]
					},
					scale: {
						startValue: 0, endValue: 100,
						customTicks: [0, 33, 67, 100],
						label: {
							customizeText: function (arg) {
								return arg.valueText + ' %';
							}
						}
					},
					value: memPer,
					valueIndicator: {
						type: 'TriangleNeedle'
					},
					subvalues: memPer,
					subvalueIndicator: {
						type: 'textCloud',
						color: getRangeColor(memPer),
						text: {
							customizeText: function (arg) {
								return arg.valueText + ' %';
							}
						}
					}
				}).dxCircularGauge('instance');
				
				memStore.insert({ time: new Date(), per: memPer })

				
				memChart = $('#memChart').dxChart({
					dataSource: memDataSource,
					commonSeriesSettings: {
						argumentField: 'time'
					},
					series: [
						{
							valueField: 'per',
							type: 'line',
							point: {
								visible: false
							}
						}
					],
					argumentAxis: {
						type: 'continuous',
						aggregationInterval: {
							seconds: 15
						},
						label: {
							format: "HH:mm:ss"
						}
					},
					valueAxis: {
						type: 'continuous',
						tickInterval: 50,
						valueType: 'numeric',
						position: 'right',
						label: {
							customizeText: function(e) {
								return e.valueText + ' %';
							}
						},
						// 18.1
						min: 0,
						max: 100,
						// 18.2
						visualRange: {
							startValue: 0,
							endValue: 100
						},
						visualRangeUpdateMode: 'keep'
					},
					legend: {
						visible: false
					},
					point: {
						visible: false
					}
				});
				
				// disk
				diskGauge = $('#diskGauge').dxCircularGauge({
					rangeContainer: {
						ranges: [
							{ startValue: 0, endValue: 33, color: '#77DD77' },
							{ startValue: 33, endValue: 67, color: '#E6E200' },
							{ startValue: 67, endValue: 100, color: '#FF0000' }
						]
					},
					scale: {
						startValue: 0, endValue: 100,
						customTicks: [0, 33, 67, 100],
						label: {
							customizeText: function (arg) {
								return arg.valueText + ' %';
							}
						}
					},
					value: diskPer,
					valueIndicator: {
						type: 'TriangleNeedle',
					},
					subvalues: diskPer,
					subvalueIndicator: {
						type: 'textCloud',
						color: getRangeColor(diskPer),
						text: {
							customizeText: function (arg) {
								return arg.valueText + ' %';
							}
						}
					}
				}).dxCircularGauge('instance');
				
				diskStore.insert({ time: new Date(), ioRead: ioRead, ioWrite: ioWrite })

				
				$('#diskChart').dxChart({
					dataSource: diskDataSource,
					commonSeriesSettings: {
						argumentField: 'time'
					},
					series: [
						{
							name: 'IO Read',
							valueField: 'ioRead',
							type: 'line',
							point: {
								visible: false
							}
						},
						{
							name: 'IO Write',
							valueField: 'ioWrite',
							type: 'line',
							point: {
								visible: false
							}
						},
					],
					argumentAxis: {
						type: 'continuous',
						aggregationInterval: {
							seconds: 15
						},
						label: {
							format: "HH:mm:ss"
						}
					},
					valueAxis: {
						type: 'continuous',
						valueType: 'numeric',
						position: 'right',
						label: {
							customizeText: function(e) {
								//return e.valueText + ' KB/s';
								return e.valueText;
							}
						},
						// 18.1
						min: 0,
						// 18.2
						visualRange: {
							startValue: 0,
							endValue: null
						},
						visualRangeUpdateMode: 'auto'
					},
					legend: {
						visible: true,
						position: 'outside',
						orientation: 'horizontal',
						itemTextPosition: 'right',
						horizontalAlignment: 'right'
					},
					point: {
						visible: false
					},
					onContentReady: function() {
						gProgressbar.hide();
					}
				});
			}
		});	

		/* update values every 3 seconds*/
		var interval;
		
		var startInterval = function() {
			interval = setInterval(function() {
				// overview tab
				// if (!$.active) {
					$.ajax({
						url : './getSystemProperty.do',
						cache: false,
						success: function(_data){
							var systemProper = JSON.parse(_data);
							
							cpuPer = parseFloat((systemProper.OSobj.cpu * 100).toFixed(2));
							memPer = parseFloat((systemProper.OSobj.PerMem * 1).toFixed(2));
							diskPer = parseFloat((systemProper.OSobj.PerSpace * 100).toFixed(2));
							ioRead = parseFloat(systemProper.OSobj['IO Read'].split(' ')[0]);
							ioWrite = parseFloat(systemProper.OSobj['IO Write'].split(' ')[0]);
							
							// form
							$('#systemInfo').dxForm('instance').option('formData', systemProper.OSobj);
							
							// cpu
							cpuGauge.option('subvalueIndicator.color', getRangeColor(cpuPer));
							cpuGauge.option('value', cpuPer);
							cpuGauge.option('subvalues', cpuPer);
							cpuStore.totalCount()
								.done(function(count) {
									if (count >= 12) {
										cpuStore._array.shift();
									}
								})
								.fail(function(error) {

									clearInterval(interval);
								});
							cpuStore.insert({ time: new Date(), per: cpuPer })
								.done(function() { cpuDataSource.load(); })

							
							// memory
							memGauge.option('subvalueIndicator.color', getRangeColor(memPer));
							memGauge.option('value', memPer);
							memGauge.option('subvalues',memPer);
							memStore.totalCount()
								.done(function(count) {
									if (count >= 12) {
										memStore._array.shift();
									}
								})
								.fail(function(error) {

									clearInterval(interval);
								});
							memStore.insert({ time: new Date(), per: memPer })
								.done(function() { memDataSource.load(); })

							
							// disk
							diskGauge.option('subvalueIndicator.color', getRangeColor(diskPer));
							diskGauge.option('value', diskPer);
							diskGauge.option('subvalues', diskPer);
							diskStore.totalCount()
								.done(function(count) {
									if (count >= 12) {
										diskStore._array.shift();
									}
								})
								.fail(function(error) {

									clearInterval(interval);
								});
							diskStore.insert({ time: new Date(), ioRead: ioRead, ioWrite: ioWrite })
								.done(function() { diskDataSource.load(); })

						},
						error: function(x, y, z) {

						}
					});
				// }
			},2000);

		};
		/* DOGFOOT ktkang 모니터링에서 시스템 부분 자동시작 안하도록  20200924*/
//		startInterval();
		/* terminate system interval when user opens another page */
		var terminateIntervalEvent = function() {
			if (!($(this).hasClass('monitoring'))) {
				clearInterval(interval);
				$('li.configuration').off('click', null, terminateIntervalEvent);
				$('#refreshButton').off('click', null, terminateIntervalEvent);
				WISE.alert('모니터링이 중지되었습니다.');
				$('li.monitoring').on('click', null, startIntervalEvent);
				$('#refreshButton').off('click').on('click', null, startIntervalEvent);
			}
		};
		
		var startIntervalEvent = function() {
			if (!($(this).hasClass('monitoring'))) {
				startInterval();
				$('li.configuration').off('click', null, startIntervalEvent);
				$('#refreshButton').off('click', null, startIntervalEvent);
				WISE.alert('모니터링이 시작되었습니다.');
				$('li.configuration').on('click', null, terminateIntervalEvent);
				$('#refreshButton').off('click').on('click', null, terminateIntervalEvent);
			}
		};
		
		$('li.configuration').on('click', null, terminateIntervalEvent);
		/* DOGFOOT ktkang 모니터링에서 시스템 부분 자동 시작 안하도록  20200924*/
		$('#refreshButton').off('click').on('click', null, startIntervalEvent);
	}

	function initJobInfo() {
		var jobColumnOrder = [
			{
				dataField: '보고서 아이디',
				sortOrder:'asc',
				alignment: 'left'
			},
			{
				dataField: '보고서 이름',
				sortOrder:'asc',
				width: '25%'
			},
			{
				dataField: '사용자 ID',
				sortOrder:'asc'
			},
			{
				dataField: '사용자 명'
			},
			{
				dataField: '사용자 IP',
			},
			{
				dataField: '보고서 유형',
			},
			{
				dataField: '작업 유형',
			},
			{
				dataField: '경과 시간',
			},
			/*
			{
				dataField: '상태 명',
			}
			*/
		];

		$.ajax({
			url : './getJobList.do',
			async: false,
			cache: false,
			success: function(_data){
				
				_data = JSON.parse(_data);
				
				// $('#jobDescription').text('진행중인 작업 (' + _data.jobResult.length + ' 개)');
				
				$('#jobInfoList').dxDataGrid({
					dataSource: _data.jobResult,
					columns: jobColumnOrder,
					visible: true,
					showColumnLines: true,
					columnAutoWidth: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					/* DOGFOOT ktkang 모니터링 부분 기능 추가  20201014 */
					selection: {
						mode: 'single'
					},
					/* DOGFOOT ktkang 전체 작업 수 표시  20200924*/
					paging: {
		   				pageSize: 20,
						enabled: true
		   			},
		   			pager: {
		   				showPageSizeSelector: true,
		   				allowedPageSizes: [10, 20, 50],
		   				showInfo: true,
		   				infoText: "전체 {2} 개 진행 중 ",
						visible: true
		   			},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'monitoring-processes') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('jobInfoList');
						gProgressbar.hide();
					/* DOGFOOT ktkang 모니터링 부분 기능 추가  20201014 */
					},
					onSelectionChanged: function(e) {
						if(typeof e.selectedRowKeys[0] != 'undefined') {
							self.log_seq = e.selectedRowKeys[0].seq;
						}
					}
				});
			}
		});
	}

	function initUserInfo() {
		var userColumnOrder = [
			{
				dataField: '사용자 ID',
				sortOrder:'asc'
			},
			{
				dataField: '사용자 IP',
			},
			{
				dataField: '로그 타입',
			},
			{
				dataField: '마지막 접속 시간',
			}
		];
		
		$.ajax({
			url : './getSameTimeConnection.do',
			async: false,
			cache: false,
			success: function(_data){
				_data = JSON.parse(_data);
				
				// $('#sametimeUser').text('동시 접속자 (' + _data.sameResult.length + ' 명)');
				
				$('#activeUserList').dxDataGrid({
					dataSource: _data.sameResult,
					columns: userColumnOrder,
					visible: true,
					showColumnLines: true,
					columnAutoWidth: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					/* DOGFOOT ktkang 전체 접속자 수 표시  20200924*/
					paging: {
		   				pageSize: 20,
						enabled: true
		   			},
		   			pager: {
		   				showPageSizeSelector: true,
		   				allowedPageSizes: [10, 20, 50],
		   				showInfo: true,
		   				infoText: "전체 {2} 명 사용 중 ",
						visible: true
		   			},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'monitoring-users') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('activeUserList');
						gProgressbar.hide();
					}
				});
			}
		});
	}

	/* public methods */
	return {
		initMonitoring: function() {
			/* DOGFOOT ktkang 모니터링에서 시스템 부분 주석처리  20200924*/
//			initSystemInfo();
			initJobInfo();
			initUserInfo();
		},

//		handleMonitorSystemRefresh: function() {
//			gProgressbar.show();
//			initSystemInfo();
//		},

		handleMonitorJobRefresh: function() {
			$.ajax({
				url : './getJobList.do',
				async : false,
				cache: false,
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(_data){
					_data = JSON.parse(_data);
					// $('#jobDescription').text('진행중인 작업  (' + _data.jobResult.length +' 개)');
					$('#jobInfoList').dxDataGrid('instance').option('dataSource', _data.jobResult);
				}
			});
		},

		handleMonitorUserRefresh: function() {
			$.ajax({
				url : './getSameTimeConnection.do',
				async : false,
				cache: false,
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(_data){
					_data = JSON.parse(_data);
					// $('#sametimeUser').text('동시 접속자 (' + _data.sameResult.length +' 명)');
					$('#activeUserList').dxDataGrid('instance').option('dataSource', _data.sameResult);
				}
			}); 
		},
		/* DOGFOOT ktkang 모니터링 부분 기능 추가  20201014 */
		handleProcessDelete: function() {
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/report/updateReportLog.do', 
				data: {
					logSeq: self.log_seq,
					status: '99'
				},
				async: false,
				success: function(data) {
					$.ajax({
						url : './getJobList.do',
						async : false,
						cache: false,
						beforeSend: function() {
							gProgressbar.show();
						},
						success: function(_data){
							_data = JSON.parse(_data);
							// $('#jobDescription').text('진행중인 작업  (' + _data.jobResult.length +' 개)');
							$('#jobInfoList').dxDataGrid('instance').option('dataSource', _data.jobResult);
						}
					});
				}
			});
		}
	}
})();