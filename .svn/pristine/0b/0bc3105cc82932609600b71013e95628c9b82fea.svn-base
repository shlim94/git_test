var logManager = (function() {
	/**
	 * Initialize log date filters.
	 */
	initLogFilter = function() {
		$('#filterContainer').append(
			'<div id="startDate"></div>' +
			'<h1 class="tit-config date-tilde">~</h1>' +
			'<div id="endDate"></div>'
		);
		$('#startDate').dxDateBox({
			value: new Date(),
			displayFormat: "yyyy/MM/dd",
			visible:true,
			showClearButton: false,
			adaptabilityEnabled: true
		});
		$('#endDate').dxDateBox({
			value: new Date(),
			displayFormat: "yyyy/MM/dd",
			visible:true,
			showClearButton: false,
			adaptabilityEnabled: true
		});
		/* DOGFOOT HSSHIM 200107 환경설정 필터바 UI 수정 */
		$('#filterContainer').css('width', 'calc(100% - 155px)');
	}

	/**
	 * Initialize functions for user log page.
	 * @param {Date} startDate
	 * @param {Date} endDate
	 */
	function queryUserLog(startDate, endDate) {
		var type = 'User';
		var columnOrder = [
			{
				dataField: "logNo",
				visible: false
			},
			{
				dataField: "일자",
				sortOrder:'desc'
			},
			{
				dataField: "시간",
				sortOrder: 'desc'
				
			},
			{
				dataField: "로그 유형"
			},
			{
				dataField: "사용자 ID",
			},
			{
				dataField: "사용자 명",
			},
			{
				dataField: "그룹 명",
			},
			{
				dataField: "접속 IP",
			},
			{
				dataField: "수정일자"
			},
		];
		$.ajax({
			url : './getAuditResource.do',
			async : false,
			data: {
				selectType: type,
				startdate: startDate,
				enddate: endDate
			},
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				$('#logUserList').dxDataGrid({
					dataSource:_data.logResult,
					columns:columnOrder,
					visible:true,
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					columnAutoWidth: true,
					paging: {
						enabled: true
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'log-user') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('logUserList')
						gProgressbar.hide();
					}
				});
				$('#logUserList').show();
				
			}
		});
	}

	/**
	 * Initialize functions for report log page.
	 * @param {Date} startDate
	 * @param {Date} endDate
	 */
	function queryReportLog(startDate, endDate) {
		var type = 'Report';
		var columnOrder = [
			{
				dataField: "logNo",
				visible: false
			},
			{
				dataField: "보고서 ID",
				alignment: 'left'
			},
			{
				dataField: "보고서 명"
			},
			{
				dataField: "보고서 유형"
			},
			{
				dataField: "시작시간",
				sortOrder:'asc'
			},
			{
				dataField: "종료시간",
				calculateDisplayValue: function(rowData) {
					if(rowData["종료시간"].indexOf("1970-01-01 09:00:00") > -1)
						return "NULL";
					return rowData["종료시간"]
				},
			},
			{
				dataField: "수행시간",
				calculateDisplayValue: function(rowData) {
					if(rowData["종료시간"].indexOf("1970-01-01 09:00:00") > -1)
						return "NULL";
					return rowData["수행시간"]
				},
			},
			{
				dataField: "사용자 ID"
			},
			{
				dataField: "사용자 명"
			},
			{
				dataField: "그룹 명"
			},
			{
				dataField: "접속 IP"
			}
		];
		$.ajax({
			url : './getAuditResource.do',
			async : false,
			data: {
				selectType: type,
				startdate: startDate,
				enddate: endDate
			},
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				$('#logReportList').dxDataGrid({
					dataSource:_data.logResult,
					columns:columnOrder,
					visible:true,
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					columnAutoWidth: true,
					paging: {
						enabled: true
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'log-report') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('logReportList')
						gProgressbar.hide();
					}
				});
				$('#logReportList').show();
			}
		});
	}

	/**
	 * Initialize functions for export log page.
	 * @param {Date} startDate
	 * @param {Date} endDate
	 */
	function queryExportLog(startDate, endDate) {
		var type = 'Export';
		var columnOrder = [
			{
				dataField: "logNo",
				visible: false
			},
			{
				dataField: "일자",
				sortOrder:'desc'
			},
			{
				dataField: "시간",
				sortOrder: 'desc'
				
			},
			{
				dataField: "보고서 명",
			},
			{
				dataField: "보고서 유형",
			},
			{
				dataField:"컨트롤 아이디",
			},
			{
				dataField:"컨트롤 이름",
			},
			{
				dataField: "사용자 ID",
			},
			{
				dataField: "사용자 명",
			},
			{
				dataField: "그룹 명",
			},
			{
				dataField: "접속 IP"
			},
		];
		$.ajax({
			url : './getAuditResource.do',
			async : false,
			data: {
				selectType: type,
				startdate: startDate,
				enddate: endDate
			},
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				$('#logExportList').dxDataGrid({
					dataSource:_data.logResult,
					columns:columnOrder,
					visible:true,
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					columnAutoWidth: true,
					paging: {
						enabled: true
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'log-export') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('logExportList')
						gProgressbar.hide();
					}
				});
				$('#logExportList').show();
				
			}
		});
	}

	/**
	 * Initialize functions for export log page.
	 * @param {Date} startDate
	 * @param {Date} endDate
	 */
	function queryQueryLog(startDate, endDate) {
		var type = 'Query';
		var columnOrder = [
			{
				dataField: "logNo",
				visible: false
			},
			{
				dataField: "일자",
				sortOrder:'desc'
			},
			{
				dataField: "시간",
				sortOrder: 'desc'
				
			},
			{
				dataField: "보고서 유형"
			},
			{
				dataField: "사용자 ID",
			},
			{
				dataField: "사용자 명",
			},
			{
				dataField: "그룹 명",
			},
			{
				dataField: "접속 IP"
			},
			{
				dataField: "데이터 원본 명",
			},
			{
				dataField: "DB 명",
			},
			{
				dataField: "서버 주소(명)",
			},
			{
				dataField: "DB 유형",
			},
			{
				dataField: "수행 시간",
			}
		];
		$.ajax({
			url : './getAuditResource.do',
			async : false,
			data: {
				selectType: type,
				startdate: startDate,
				enddate: endDate
			},
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				$('#logQueryList').dxDataGrid({
					dataSource:_data.logResult,
					columns:columnOrder,
					visible:true,
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					columnAutoWidth: true,
					selection: {
						mode: 'single'
					},
					paging: {
						enabled: true
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'log-query') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick: function(e) {

						$('#logQuerySql').val(e.data.sql);
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('logQueryList')
						gProgressbar.hide();
					}
				});
				$('#logQueryList').show();
			}
		});
	}

	// /**
	//  * Initialize functions for analysis log page.
	//  * @param {Date} startDate
	//  * @param {Date} endDate
	//  */
	// function queryAnalysisLog(startDate, endDate) {
	// 	var type = 'Analysis';
	// 	var columnOrder = [
	// 		{
	// 			dataField: "logNo",
	// 			visible: false
	// 		},
	// 		{
	// 			dataField: "비정형 보고서",
	// 			sortOrder:'desc'
	// 		},
	// 		{
	// 			dataField: "데이터 원본 명"
	// 		},
	// 		{
	// 			dataField: "DB 명"
	// 		},
	// 		{
	// 			dataField: "서버 주소(명)"
	// 		},
	// 		{
	// 			dataField: "DB 유형"
	// 		},
	// 		{
	// 			dataField: "소유자"
	// 		},
	// 		{
	// 			dataField: "테이블 물리명"
	// 		},
	// 		{
	// 			dataField: "테이블 논리명"
	// 		},
	// 		{
	// 			dataField: "컬럼 물리명"
	// 		},
	// 		{
	// 			dataField: "컬럼 논리명"
	// 		}
	// 	];
	// 	$.ajax({
	// 		url : './getAuditResource.do',
	// 		async : false,
	// 		data: {
	// 			selectType: type,
	// 			startdate: startDate,
	// 			enddate: endDate
	// 		},
	// 		beforeSend: function() {
	// 			gProgressbar.show();
	// 		},
	// 		success: function(_data){
	// 			_data = JSON.parse(_data);
	// 			$('#logAnalysisList').dxDataGrid({
	// 				dataSource:_data.logResult,
	// 				columns:columnOrder,
	// 				visible:true,
	// 				showColumnLines: false,
	// 				showRowLines: true,
	// 				rowAlternationEnabled: true,
	// 				showBorders: true,
	// 				columnAutoWidth: true,
	// 				paging: {
	// 					enabled: true
	// 				},
	// 				onInitialized: function(e) {
	// 					$('.panel-head').on('click', function() {
	// 						if ($(this).find('.select-category').data('category') === 'log-analysis') {
	// 							e.component.updateDimensions();
	// 						}
	// 					});
	// 				},
	// 				onContentReady: function() {
	// 					gProgressbar.hide();
	// 				}
	// 			});
	// 			$('#logAnalysisList').show();
	// 		}
	// 	});
	// }

	/* public methods */
	return {
		/**
		 * Main.
		 */
		initLog: function() {
			initLogFilter();
			var currentDate = moment().format('YYYYMMDD');
			queryUserLog(currentDate, currentDate);
			queryReportLog(currentDate, currentDate);
			queryExportLog(currentDate, currentDate);
			queryQueryLog(currentDate, currentDate);
			// queryAnalysisLog(currentDate, currentDate);
		},

		/**
		 * Redirect query request to the appropriate category page.
		 */
		handleLogQuery: function() {
			var category = $('.panel-head.on').find('.select-category').data('category').split('-')[1];
			var startDate = moment($('#startDate').dxDateBox('instance').option('value')).format('YYYYMMDD');
			var endDate = moment($('#endDate').dxDateBox('instance').option('value')).format('YYYYMMDD');
			switch(category) {
				case 'user':
					queryUserLog(startDate, endDate);
					break;
				case 'report':
					queryReportLog(startDate, endDate);
					break;
				case 'export':
					queryExportLog(startDate, endDate);
					break;
				case 'query':
					queryQueryLog(startDate, endDate);
					break;
				// case 'analysis':
				// 	queryAnalysisLog(startDate, endDate);
				// 	break;
				default: break;
			}
		}
	}
})();