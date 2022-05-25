WISE.libs.Dashboard.DownloadManager = function() {
	var self = this;
	var html;
	var tabDownload = false;

	this.init = function(){
		$('.downloadReport').off('click').on('click',function(e){
//	        	 e.event.preventDefault();
			var downloadType;
			var exit = true;
			var eventElementId = e.target.id == '' ? e.currentTarget.id : e.target.id;

			if (WISE.Constants.editmode === 'viewer' && (gDashboard.reportType === 'Spread' || gDashboard.reportType === 'Excel')) {
				if(eventElementId === 'downloadReportXLSX'){
					document.getElementById("ss"+gDashboard.structure.ReportMasterInfo.id).contentWindow.document.getElementById('export-excel').click();
					document.getElementById("ss"+gDashboard.structure.ReportMasterInfo.id).contentWindow.document.getElementById('saveAsFileName').value = gDashboard.structure.ReportMasterInfo.name;
					$('#saveAsFileName').val(parent.gDashboard.structure.ReportMasterInfo.name);
				}else if(eventElementId === 'downloadReportCSV'){
					document.getElementById("ss"+gDashboard.structure.ReportMasterInfo.id).contentWindow.document.getElementById('export-csv').click();
					document.getElementById("ss"+gDashboard.structure.ReportMasterInfo.id).contentWindow.document.getElementById('saveAsFileName').value = gDashboard.structure.ReportMasterInfo.name;
					$('#saveAsFileName').val(parent.gDashboard.structure.ReportMasterInfo.name);
				}

				return false;
			}
			else if(gDashboard.itemGenerateManager.dxItemBasten.length == 0){
				return false;
			}

			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_e){
				if(!_e.meta && _e.type == "PIVOT_GRID" && gDashboard.reportType == "AdHoc"){
					WISE.libs.Dashboard.item.PivotUtility.setPivotMeta(_e)
				}
				
				if(_e.meta == undefined && exit == true){
    				WISE.alert("보고서에 데이터가 조회되지 않았거나, 데이터가 없습니다.");
    				exit = false;
    				return false;
				}else if(exit ==false){
					return false;
				}
			});

			/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
			/*dogfoot 통계 분석 추가 shlim 20201102*/
			if((gDashboard.reportType == 'DashAny' || gDashboard.reportType == 'StaticAnalysis') && !gDashboard.downloadReady && gDashboard.hasTab == true) {
				// yyb 재조회 안타게 막음 20210308
				gDashboard.downloadFull = true;
				gDashboard.tabQuery = false;
				gDashboard.hasTab = false;
				self.tabDownload = true;
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _item){
	                	if(_item.type == 'PIE_CHART'){
	                		_item.prevAnimation = _item.meta['Animation'];
	                		_item.meta['Animation'] = 'none';
	                	}
	              });
				 
				gDashboard.query();
			}
			self.pieCount=0;
			if(exit == true){
				switch(eventElementId){
					case 'downloadReportXLSX':
						downloadType = 'xlsx';
						break;
					case 'downloadReportXLS':
						downloadType = 'xls';
						break;
					case 'downloadReportDOC':
						downloadType = 'docx';
						break;
					case 'downloadReportPPT':
						downloadType = 'pptx';
						break;
					case 'downloadReportHanCell':
						downloadType = 'cell';
						break;
					case 'downloadReportHanHWP':
						downloadType = 'hwp';
						break;
					case 'downloadReportHanShow':
						downloadType = 'show';
						break;
					case 'downloadReportCSV':
						downloadType = 'csv';
						break;
					case 'downloadReportTXT':
						downloadType = 'txt';
						break;
					case 'downloadReportHTML':
						downloadType = 'html';
						break;
					case 'downloadReportPDF':
						downloadType = 'pdf';
						break;
					case 'downloadReportIMG':
						downloadType = 'img';
						break;
				}
				/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */

				var paramItemsStr = self.extractParamItemsStr();
			    var contentList = [];
			    // 2019.12.10 수정자 : mksong 다운로드 프로그레스 바 기능 추가 DOGFOOT
			    /*dogfoot 이미지 전체 다운로드 위치 변경 shlim 20200828*/
//	      	   	self.converToXlsx();
//			    if(downloadType == 'img'){
//			    	//2020.02.19 MKSONG 프로그레스바 위치 변경 DOGFOOT
//			    	gProgressbar.show();
//			    	$('.lm_title').attr('style', 'display: block !important');
//			    	var containerId = WISE.Constants.editmode === 'viewer' ? '#reportContainer' : '#canvas-container';
//			    	html2canvas.allowTaint = true;
//			    	html2canvas(document.querySelector(containerId), {letterRendering:true}).then(function(canvas) {
//			    		canvas.toBlob(function(blob){
//			    			self.saveImgFunc(blob);
//			    			$('.lm_title').attr('style', '');
//
//			    		});
//			    	});
//			    }else{
			    	var layout;
			    	var sortedItemIdx = [];
			    	/**
			    	 * Sort dashboard items in order of appearance.
			    	 */
			    	function setSortedItemIdx(item) {
			    		var childElements = [];
			    		// get all child elements of item
		    			$.each(item.LayoutItem, function(_i, _o) {
		    				childElements.push({ type: 'LayoutItem', content: _o });
		    			});
		    			$.each(item.LayoutGroup, function(_i, _o) {
		    				childElements.push({ type: 'LayoutGroup', content: _o });
		    			});
		    			$.each(item.LayoutTabContainer, function(_i, _o) {
		    				childElements.push({ type: 'LayoutTabContainer', content: _o });
		    			});
		    			$.each(item.LayoutTabPage, function(_i, _o) {
		    				childElements.push({ type: 'LayoutTabPage', content: _o });
		    			});
		    			// sort items by value "index"
		    			childElements.sort(function(a, b) {
		    				return a.content.Index - b.content.Index;
		    			});
		    			// add to sortedItemIdx if item is found, otherwise keep searching
		    			$.each(childElements, function(_i, _element) {
		    				if (_element.type === 'LayoutItem') {
		    					// 2020.02.04 mksong 다운로드 오류 수정 dogfoot
		    					var itemtype = _element.content.DashboardItem.substr(0,_element.content.DashboardItem.indexOf('Dash'));
		    					switch (itemtype){
		    						/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
		    						/* DOGFOOT syjin 카카오 지도 추가  20200820 */
		    						case 'pivot': case 'chart': case 'grid': case 'pie': case 'treemap': case 'starchart': case 'textBox': case 'card':
		    						case 'WordCloud' : case 'heatmap' : case 'heatmap2' : case 'parallel' : case 'RectangularAreaChart' : case 'waterfallchart' : case 'bubbled3' : case 'histogramchart' :
		    						case 'forceDirect' : case 'forceDirectExpand' : case 'hierarchical' : case 'sankeychart' : case 'bipartitechart':  case 'divergingchart' : case 'dependencywheel': case 'scatterplot': case 'scatterplot2':
		    							case 'radialtidytree': case 'scatterplotmatrix': case 'historytimeline': case 'arcdiagram': case 'boxplot' : case 'coordinateline' : case 'sequencessunburst' : case 'liquidfillgauge':
		    							case 'funnelchart': case 'pyramidchart': case 'bubblepackchart': case 'wordcloudv2': case 'dendrogrambarchart': case 'calendarviewchart':case 'kakaoMap':case 'kakaoMap2':
		    							case 'calendarview2chart':case 'calendarview3chart':case 'collapsibletreechart': case 'syncchart': case 'coordinatedot': case 'choroplethMap':
		    							sortedItemIdx.push(_element.content.DashboardItem);
		    							break;
		    						default:
		    							break;
		    					}
		    				} else {
		    					setSortedItemIdx(_element.content);
		    				}
		    			});
					}
					/* DOGFOOT hsshim 200107
					 * 뷰어 일반 레이아웃 다운로드 방식 적용
					 */
			    	//2020.03.05 MKSONG 비정형 다운로드 방식 변경 DOGFOOT
			    	if(gDashboard.reportType == 'AdHoc'){
					   	switch(gDashboard.structure.Layout){
							case 'CTGB' : case 'CLGR':
								$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
									if(_o.type == 'PIVOT_GRID'){
										sortedItemIdx[1] = _o.ComponentName;
									}else{
										sortedItemIdx[0] = _o.ComponentName;
									}
								});
								break;
							case 'GTCB' : case 'GLCR': case 'CBGT' :
								$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
									if(_o.type == 'PIVOT_GRID'){
										sortedItemIdx[0] = _o.ComponentName;
									}else{
										sortedItemIdx[1] = _o.ComponentName;
									}
								});
								break;
							case 'C' :
								$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
									if(_o.type != 'PIVOT_GRID'){
										sortedItemIdx[0] = _o.ComponentName;
									}
								});
								break;
							case 'G':
								$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
									if(_o.type == 'PIVOT_GRID'){
										sortedItemIdx[0] = _o.ComponentName;
									}
								});
								break;
						}
					}else{
						if (WISE.Constants.editmode === 'viewer') {
							// 일반레이아웃 방식
//								$.each(gDashboard.structure.sortedItemIdx,function(_i,_o){
//									sortedItemIdx.push(_o.itemID);
//								});

							// 골든레이아웃 방식
							 /*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
						 	 if(gDashboard.reportType === 'StaticAnalysis'){
								layout = gDashboard.reportUtility.setAysLayoutTree(gDashboard.structure.ReportMasterInfo.id);
						 	 }else{
								layout = gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id);
							 }
//							 layout = gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id);
							 setSortedItemIdx(layout);
				    	} else {
				    		/*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
						 	if(gDashboard.reportType === 'StaticAnalysis'){
						 		layout = gDashboard.reportUtility.setAysLayoutTree();
						 	}else{
						 		layout = gDashboard.reportUtility.setLayoutTree();
							}
//							layout = gDashboard.reportUtility.setLayoutTree();
							setSortedItemIdx(layout);
						}
						/* DOGFOOT hsshim 200107 끝 */
					}
			    	//2020.03.05 MKSONG 비정형 다운로드 방식 변경 수정 끝 DOGFOOT
//				}
				/* DOGFOOT hsshim 200107
				 * 내려받기 로그 기록 기능 추가
				 */
			    var setTimeDown = 0;
			    if(self.tabDownload) {
			    	setTimeDown = 3000;
			    }
			    setTimeout(function(){
			    	if (downloadType !== 'img') {
			    		//2020.02.19 MKSONG 다운로드 CONFIRM 기능 추가 DOGFOOT
			    		var countGridCell = self.countGridCell();
			    		// 2020.02.21 mksong keris 건수 확인 추가 dogfoot
			    		var countData = self.countData();
			    		var confirmOk = true;

			    		var totalSecond = countGridCell / 480;
			    		var loadingMinute = parseInt(totalSecond / 60);
			    		var loadingSecond = parseInt(totalSecond % 60);

			    		/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
			    		/* DOGFOOT syjin 다운로드 시 알림창 조건 변경 (환경설정 엑셀 다운로드 서버 처리 건수로 비교) 20210304 */
			    		//if(totalSecond >= 0){
			    		if(countGridCell > userJsonObject.excelDownloadServerCount){
			    			var message = '데이터가 많을 경우 다운로드 하는 동안 장시간 소요될 수 있습니다.\n';
			    			// 2020.02.21 mksong keris 건수 확인 추가 dogfoot
//			    			message += '(데이터 총 ' + countData + '건)\n그래도 계속하시겠습니까?';
			    			message += '그래도 계속하시겠습니까?';
//			    			message += '(약 ';
//			    			if(loadingMinute > 0){
//			    			message += loadingMinute +'분 ';
//			    			}
//			    			if(loadingSecond > 0){
//			    			message += loadingSecond +'초 ';
//			    			}

//			    			message += ' 소요예정)\n그래도 계속하시겠습니까?';
			    			var options = {
			    					buttons: {
			    						confirm: {
			    							id: 'confirm',
			    							className: 'blue',
			    							text: '확인',
			    							action: function() {
			    								gProgressbar.hide();
			    								$AlertPopup.hide();
			    								gProgressbar.show();
			    								/*dogfoot 대용량 다운로드 시  프로그레스바 와 다운로드 동작 화면에서 겹치지않게 시간조정 shlim 20210126*/
			    								setTimeout(function(){
			    									self.downloadSet(0, contentList, sortedItemIdx, downloadType, paramItemsStr);
			    									var param = {
			    											'pid': WISE.Constants.pid,
			    											'userId':userJsonObject.userId,
			    											'reportType':gDashboard.reportType,
			    											'itemid' : '',
			    											'itemNm' : ''
			    									}
			    									$.ajax({
			    										type : 'post',
			    										data : param,
			    										cache : false,
			    										url : WISE.Constants.context + '/report/exportLog.do',
			    										complete: function() {
			    											// 2020.01.16 mksong 프로그레스바 hide 시점 변경 dogfoot
			    											//													gProgressbar.hide();
			    										}
			    									});
			    								}, 30);
			    							}
			    						},
			    						cancel: {
			    							id: 'cancel',
			    							className: 'negative',
			    							text: '취소',
			    							action: function() {
			    								$AlertPopup.hide();
			    								gProgressbar.hide();
			    							}
			    						}
			    					}
			    			};
			    			setTimeout(function(){
			    				WISE.confirm(message, options);
			    			},1000);
			    		}else{
			    			//2020.02.19 MKSONG 프로그레스바 위치 변경 DOGFOOT
			    			/*dogfoot 프로그레스바 활성화 및 다운로드 기능 과 겹치지 않도록 시간조정  shlim 20210219*/
			    			gProgressbar.show();
			    			setTimeout(function(){
			    				self.downloadSet(0, contentList, sortedItemIdx, downloadType, paramItemsStr);
			    				var param = {
			    						'pid': WISE.Constants.pid,
			    						'userId':userJsonObject.userId,
			    						'reportType':gDashboard.reportType,
			    						'itemid' : '',
			    						'itemNm' : ''
			    				}
			    				$.ajax({
			    					type : 'post',
			    					data : param,
			    					cache : false,
			    					url : WISE.Constants.context + '/report/exportLog.do',
			    					complete: function() {
			    						// 2020.01.16 mksong 프로그레스바 hide 시점 변경 dogfoot
//			    						gProgressbar.hide();
			    					}
			    				});
			    			}, 30);
			    		}
			    	}else{
			    		/*dogfoot 이미지 전체 다운로드 추가 shlim 20200828*/
			    		var countGridCell = self.countGridCell();
			    		// 2020.02.21 mksong keris 건수 확인 추가 dogfoot
			    		var countData = self.countData();
			    		var confirmOk = true;

			    		var totalSecond = countGridCell / 480;
			    		var loadingMinute = parseInt(totalSecond / 60);
			    		var loadingSecond = parseInt(totalSecond % 60);

			    		/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
			    		/* DOGFOOT syjin 다운로드 시 알림창 조건 변경 (환경설정 엑셀 다운로드 서버 처리 건수로 비교) 20210304 */
			    		//if(totalSecond >= 0){
			    		if(countGridCell > userJsonObject.excelDownloadServerCount){
			    			var message = '데이터가 많을 경우 다운로드 하는 동안 장시간 소요될 수 있습니다.\n';
			    			// 2020.02.21 mksong keris 건수 확인 추가 dogfoot
//			    			message += '(데이터 총 ' + countData + '건)\n그래도 계속하시겠습니까?';
			    			message += '그래도 계속하시겠습니까?';
//			    			message += '(약 ';
//			    			if(loadingMinute > 0){
//			    			message += loadingMinute +'분 ';
//			    			}
//			    			if(loadingSecond > 0){
//			    			message += loadingSecond +'초 ';
//			    			}

//			    			message += ' 소요예정)\n그래도 계속하시겠습니까?';
			    			var options = {
			    					buttons: {
			    						confirm: {
			    							id: 'confirm',
			    							className: 'blue',
			    							text: '확인',
			    							action: function() {
			    								gProgressbar.hide();
			    								$AlertPopup.hide();
			    								gProgressbar.show();
			    								if(gDashboard.reportType === 'StaticAnalysis'){
			    									self.blockImgList = [];
			    								}
			    								self.downloadSetImg(0, contentList, sortedItemIdx, downloadType, paramItemsStr);
			    								var param = {
			    										'pid': WISE.Constants.pid,
			    										'userId':userJsonObject.userId,
			    										'reportType':gDashboard.reportType,
			    										'itemid' : '',
			    										'itemNm' : ''
			    								}
			    								$.ajax({
			    									type : 'post',
			    									data : param,
			    									cache : false,
			    									url : WISE.Constants.context + '/report/exportLog.do',
			    									complete: function() {
			    										// 2020.01.16 mksong 프로그레스바 hide 시점 변경 dogfoot
//			    										gProgressbar.hide();
			    									}
			    								});
			    							}
			    						},
			    						cancel: {
			    							id: 'cancel',
			    							className: 'negative',
			    							text: '취소',
			    							action: function() {
			    								$AlertPopup.hide();
			    								gProgressbar.hide();
			    							}
			    						}
			    					}
			    			};
			    			setTimeout(function(){
			    				WISE.confirm(message, options);
			    			},3000);
			    		}else{
			    			//2020.02.19 MKSONG 프로그레스바 위치 변경 DOGFOOT
			    			/* DOGFOOT syjin 이미지 다운로드 시 downloadSetImg 함수로 변경 20210304 */
			    			gProgressbar.show();
			    			setTimeout(function(){
			    				self.downloadSetImg(0, contentList, sortedItemIdx, downloadType, paramItemsStr);

			    				var param = {
			    						'pid': WISE.Constants.pid,
			    						'userId':userJsonObject.userId,
			    						'reportType':gDashboard.reportType,
			    						'itemid' : '',
			    						'itemNm' : ''
			    				}

			    				$.ajax({
			    					type : 'post',
			    					data : param,
			    					cache : false,
			    					url : WISE.Constants.context + '/report/exportLog.do',
			    					complete: function() {
			    						// 2020.01.16 mksong 프로그레스바 hide 시점 변경 dogfoot
//			    						gProgressbar.hide();
			    					}
			    				});
			    			},70);
			    		}
			    	}
			    }, setTimeDown);
			}else{
			    gProgressbar.hide();
			}
		});
	};

	/*dogfoot 다운로드 명칭 오류 수정 shlim 20200715*/
	 this.reformItemName = function(_reformItemName,_idx){
	    	var getMetaName = _reformItemName;
	    	if(getMetaName){
//	    		if((getMetaName.indexOf('피벗 ')>-1) || (getMetaName.indexOf('그리드 ')>-1)|| (getMetaName.indexOf('파이 ')>-1) || (getMetaName.indexOf('차트 ')>-1)
//	   				 || (getMetaName.indexOf('히트맵')>-1) || (getMetaName.indexOf('워드클라우드 ')>-1) || (getMetaName.indexOf('히스토그램 ')>-1) || (getMetaName.indexOf('평행좌표계 ')>-1)
//	   				 || (getMetaName.indexOf('지도 ')>-1) || (getMetaName.indexOf('트리맵 ')>-1) || (getMetaName.indexOf('스타차트 ')>-1) || (getMetaName.indexOf('네모차트 ')>-1)
//	   				 || (getMetaName.indexOf('폭포수차트')>-1) || (getMetaName.indexOf('D3버블차트 ')>-1) || (getMetaName.indexOf('텍스트 상자 ')>-1) ){
//	                getMetaName = _idx;
//	    		}else{
	    			getMetaName = getMetaName.replace(/\//g,'_');
					getMetaName = getMetaName.replace(/\\/g,'_');
					getMetaName = getMetaName.replace(/\./g,'_');
					getMetaName = getMetaName.replace(/\*/g,'_');
					getMetaName = getMetaName.replace(/\[/g,'_');
					getMetaName = getMetaName.replace(/\]/g,'_');
					getMetaName = getMetaName.replace(/\:/g,'_');
					getMetaName = getMetaName.replace(/\?/g,'_');
					getMetaName = getMetaName.replace(/\</g,'(');
					getMetaName = getMetaName.replace(/\>/g,')');
//	    		}
	    	}
	    	return getMetaName;
	 };

	 this.sqlLikeExcelDown = function (_o, param) {
		try {
			var _idx = param.idx;
			var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
  			var _contentList = SQLikeUtil.pivotGridSqlLikeExcel([], _o, param.downloadType);
  			gProgressbar.hide();

			$.each(_contentList, function(_i, _content) {
				_content.uploadPath = 'pivotgridDownload';		// 임의값 세팅
				
				if (gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == "") {
					_content.reportName = "NewReport" + param.gridNumber == 1 ? "" : param.gridNumber.toString();
				}
				else {
					_content.reportName = param.reportName + param.gridNumber == 1 ? "" : param.gridNumber.toString();
				}
				
				_content.itemName = Base64.encode(param.itemName);
				_content.originItemName = param.originItemName;
				_content.pvExYn = param.pvExYn;
				if(gDashboard.reportType == 'AdHoc') {
					_content.delta = _o.deltaItems;
				}
				gDashboard.downloadParams = _content.downloadParams = WISE.libs.Dashboard.item.PivotUtility.getRemoteOperationParameter(_o);
				param.contentList.push(_content);
				_idx++;
			});

			if (param.contentList.length == param.sortedItemIdx.length) {
				self.downloadStart(param.contentList, param.paramItemsStr, param.downloadType, false);
			}
			else {
				self.downloadSet(_idx, param.contentList, param.sortedItemIdx, param.downloadType, param.paramItemsStr);
			}
		}
		catch(exx) {
			self.gridNumber = 0;
			WISE.alert(exx.message, 'error');
		}
	};
	this.downloadSet = function(_idx, contentList,_sortedItemIdx, downloadType, paramItemsStr){
		// 2019.12.10 수정자 : mksong 다운로드 컨테이너 이름으로 시트 이름 구성 기능 추가 DOGFOOT
		var layoutTree;
		if(WISE.Constants.editmode != 'viewer'){
			/*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
		 	if(gDashboard.reportType === 'StaticAnalysis'){
		 		if(gDashboard.reportUtility.setAysLayoutTree().LayoutTabContainer != undefined){
					layoutTree = gDashboard.reportUtility.setAysLayoutTree().LayoutTabContainer[0].LayoutTabPage;
				}else{
					layoutTree = false;
				}
		 	}else{
		 		if(gDashboard.reportUtility.setLayoutTree().LayoutTabContainer != undefined){
					layoutTree = gDashboard.reportUtility.setLayoutTree().LayoutTabContainer[0].LayoutTabPage;
				}else{
					layoutTree = false;
				}
			}

		}else{
			/* DOGFOOT hsshim 200107
			 * 뷰어 일반 레이아웃 다운로드 방식 적용
			 */
//			layoutTree = false;
			// 골든레이아웃 방식
//			 layoutTree = gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer == undefined ? false : gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer[0].LayoutTabPage;
			 /*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
		 	if(gDashboard.reportType === 'StaticAnalysis'){
		 		layoutTree = gDashboard.reportUtility.setAysLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer == undefined ? false : gDashboard.reportUtility.setAysLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer[0].LayoutTabPage;
		 	}else{
		 		layoutTree = gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer == undefined ? false : gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer[0].LayoutTabPage;
			}
		}

		if(_idx <= _sortedItemIdx.length){
			/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
			var gridNumber = 0;
			var totalCountOver = false;
			/* goyong ktkang 데이터 없을때 다운로드 오류 수정  20210603 */
			var nullCount = 0;
			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i, _o){
				if(typeof _o.filteredData != 'undefined' && _o.filteredData.length == 0) {
					nullCount++;
				}
			});
			
			if($('.nodata-layer').length > 0 || (gDashboard.itemGenerateManager.dxItemBasten.length == nullCount && gDashboard.confirmValue)) {
				gProgressbar.hide();
				WISE.alert('조회된 데이터가 없어 다운로드를 할 수 없습니다.');
				return false;
			}
			
//			if(gDashboard.reportType == 'AdHoc' && !gDashboard.confirmValueSqllike){
//				gDashboard.confirmValue = true;
//				$('#btn_query').click();
//				return false;
//			}
			if(!contentList){
				contentList = [];
			}
			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i, _o){
				
				if(_sortedItemIdx[_idx] == _o.ComponentName || _sortedItemIdx[_idx] == _o.itemid.substr(0,_o.itemid.indexOf('_'))){
					/* DOGFOOT ktkang 다운로드 오류 수정  20200909 */
//					if((_o.type == 'PIVOT_GRID' || _o.type == 'DATA_GRID') && downloadType == 'xlsx'){
					if((_o.type == 'DATA_GRID') && downloadType == 'xlsx'){
						var ds = _o.dxItem.getDataSource();
						var totalCnt = (_o.type=='DATA_GRID')?ds.totalCount():ds._data.values.length;
						/* 2020.12.18 mksong 다운로드 sqlLikeExcel만 되는 오류 수정 dogfoot */
						if(totalCnt>=userJsonObject.excelDownloadServerCount && userJsonObject.excelDownloadServerCount != 0) {
							totalCountOver = true;
							gridNumber++;
						}
					}

					// 2019.12.10 수정자 : mksong 다운로드 컨테이너 이름으로 시트 이름 구성 기능 추가 DOGFOOT
					var content;
					/*dogfoot 다운로드 명칭 오류 수정 shlim 20200715*/
					var itemName = self.reformItemName(_o.meta.Name,_idx);
		   		   	/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
		   		   	var hidecaption;
		   		   	//2020.03.05 MKSONG 비정형일 경우 예외 처리 DOGFOOT
		   		   	var originItemName = gDashboard.reportType != 'AdHoc' ? _o.meta.Name : "";
		   		   	var dashboardItemName = _sortedItemIdx[_idx];
		   		   	var dashboardTabname = "";
		   		   	if(layoutTree){
		   		   		$.each(layoutTree,function(_tabindex,_tab){
		   		   			var tabname = $('#'+_tab.DashboardItem+'_item_title').attr('title');
		   		   			// 2020.01.07 mksong 탭컨테이너 사용시 다운로드 오류 수정 dogfoot
		   		   			if(_tab.LayoutGroup != undefined){
			   		   			$.each(_tab.LayoutGroup,function(_groupIndex,_group){
				   		   			if(!_group.LayoutItem){
			   		   					$.each(_group.LayoutGroup,function(_itemIndex,_group2){
											$.each(_group2.LayoutItem,function(_itemIndex,_item){
												if(_item.DashboardItem == dashboardItemName){
//													itemName = tabname + '_'+itemName;
													dashboardTabname = _tab.DashboardItem;
												}
											});
										});
			   		   				}else{
			   		   					$.each(_group.LayoutItem,function(_itemIndex,_item){
											if(_item.DashboardItem == dashboardItemName){
//												itemName = tabname + '_'+itemName;
												dashboardTabname = _tab.DashboardItem;
											}
										});
			   		   				}
				   		   			
				   		   			//20210907 shlim BEGIN
									if(_group.LayoutGroup != undefined){
										$.each(_group.LayoutGroup,function(_itemIndex,_group2){
											$.each(_group2.LayoutItem,function(_itemIndex,_item){
												if(_item.DashboardItem == dashboardItemName){
//													itemName = tabname + '_'+itemName;
													dashboardTabname = _tab.DashboardItem;
												}
											});
										});
									}
									//20210907 shlim END
									
			   		   			});
		   		   			}else{
			   		   			$.each(_tab.LayoutItem,function(_itemIndex,_item){
			   		   				if(_item.DashboardItem == dashboardItemName){
//			   		   					itemName = tabname + '_'+itemName;
			   		   					dashboardTabname = _tab.DashboardItem
			   		   				}
			   		   			});
		   		   			}
		   		   		});
		   		   	}

		   		   	itemName = itemName.replace(/\//g,'_');
		   		   	// 2019.12.10 수정자 : mksong 다운로드 컨테이너 이름으로 시트 이름 구성 기능 수정 끝 DOGFOOT
		   		   	itemName = itemName.replace(/\\/g,'_');
		   		   	itemName = itemName.replace(/\./g,'_');
		   		   	itemName = itemName.replace(/\*/g,'_');
		   		   	itemName = itemName.replace(/\[/g,'_');
   		   			itemName = itemName.replace(/\]/g,'_');
		   		   	itemName = itemName.replace(/\:/g,'_');
		   		   	itemName = itemName.replace(/\?/g,'_');
		   		   	itemName = itemName.replace(/\</g,'(');
		   		   	itemName = itemName.replace(/\>/g,')');
		   		   /* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
		   		   	var reportName = gDashboard.reportUtility.reportInfo.ReportMasterInfo.name;
		   		   	reportName = reportName.replace(/\//g,'_');
		   		   	reportName = reportName.replace(/\\/g,'_');

		   		   	/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
					var memoText = _o.memoText;

		   		   	switch(_o.type){
			   		   	case 'PIVOT_GRID' :
			   		   		// 피벗확장용 파라미터
			   		   		var sqlLikeDownParam = {
			   		   			idx: _idx
			   		   			,reportName: reportName
			   		   			,itemName : itemName
			   		   			,originItemName: originItemName
			   		   			,pvExYn: 'Y'
			   		   			,contentList: contentList
			   		   			,sortedItemIdx: _sortedItemIdx
			   		   			,paramItemsStr: paramItemsStr
			   		   			,downloadType: downloadType
			   		   			,gridNumber: gridNumber
			   		   		};
			   		   		self.sqlLikeExcelDown(_o, sqlLikeDownParam);
			   		   		break;
			   		   	case 'DATA_GRID' :
							/* DOGFOOT ktkang 다운로드 오류 수정  202001005 */
							/*dogfoot 비정형 피벗 조회 다운로드 기능 추가 shlim 20210728*/
			   		   		// 비정형 피벗 조회 기능 막음
//			   		   		if(gDashboard.reportType == 'AdHoc' && !gDashboard.confirmValueSqllike){
//			   		   			gDashboard.confirmValue = true;
//			   		   			$('#btn_query').click();
//			   		   			return false;
//			   		   		} else{
				   		   		if(totalCountOver && downloadType == 'xlsx') {
									/* 2020.12.18 mksong 다운로드 sqlLikeExcel만 되는 오류 수정 dogfoot */
									/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
									if(contentList.length == _sortedItemIdx.length - gridNumber){
										self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
									}else{
										self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
									}
								} else {
									
									/*dogfoot 엑셀 다운로드 타입별 설정 적용 shlim 20210317*/
									var dwType;
								    if(typeof userJsonObject.menuconfig != "undefined"){
								    	if(typeof userJsonObject.menuconfig.Menu.DOWNLOAD_TYPE){
								    		dwType = userJsonObject.menuconfig.Menu.DOWNLOAD_TYPE.DownLoadType
								    	}else{
								    		dwType = "Default";
								    	}
								    }else{
								    	dwType = "Default";
								    }
								    switch(dwType){
									    case "Default" :
									    	gProgressbar.show();
									    	var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
											
											var downFile = SQLikeUtil.doSqlLikeExcel(contentList, _o, downloadType);
											if (downFile) {
												_idx++;
												_.each(downFile, function(con) {
													con.originItemName = originItemName;
													con.itemtype = _o.type;
													con.memoText = memoText;
												});
												
												if (contentList.length == _sortedItemIdx.length - gridNumber){
													self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
												}
												else {
													self.downloadSet(_idx, contentList, _sortedItemIdx, downloadType, paramItemsStr);
												}
											}
									    	break;
									    case "Dev_nonExcelJs" :
									    	_o.dxItem.off('fileSaving').on('fileSaving',function(_e){
													var formData = new FormData();
													if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
														formData.append("reportName","NewReport");
													}else{
														formData.append("reportName",reportName);
													}
													/* DOGFOOT ktkang 파일 이름 js에서 encode하고 java에서는 decode 없던 오류 수정  20200727 */
													itemName = itemName.replace(/_피벗/,"");
													itemName = itemName.replace(/피벗 /,"");
													itemName = itemName.replace(/피벗_/,"");
													formData.append("itemName", Base64.encode(itemName));
													// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
													formData.append("originItemName",originItemName);
													
													formData.append("exceldata", _e.data);
		
													var isRunning = false;
													if(!isRunning){
														$.ajax({
															type : 'POST',
															data : formData,
															async : false,
															url : WISE.Constants.context + '/download/saveXLSX.do',
															contentType: false,
															processData: false,
															success : function(_data) {
																isRunning = true;
																_idx++;
																if(typeof _data == 'string'){
										                    		_data = JSON.parse(_data);
										                    	}
																if(_data.checkValue){
																	_data.item = itemName;
																	// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
																	_data.originItemName = originItemName;
																	_data.itemtype = _o.type;
																	_data.memoText = memoText;
																	/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
																	if(typeof _o.meta.ShowCaption != 'undefined'){
																		if(!_o.meta.ShowCaption){
																			_data.hidecaption = itemName;
																		}
																	}
																	if(_o.type == 'PIVOT_GRID' && gDashboard.reportType == 'AdHoc') {
																		_data.rows = _o.R;
																		_data.cols = _o.C;
																		_data.delta = _o.deltaItems;
																	} else if(_o.type == 'PIVOT_GRID' && gDashboard.reportType == 'DashAny') {
																		_data.rows = _o.rows;
																		_data.cols = _o.columns;
																	}
																	
																	// 데이터 그리드일때 셀병합여부와 헤더로우 카운트를 넘기기 위해 처리
																	if (_o.type == 'DATA_GRID') {
																		_data.isGrdCellMerge = isNull(_o.Grid.GridOptions.AllowGridCellMerge) ? false : _o.Grid.GridOptions.AllowGridCellMerge;
																		_data.hdRowCnt = $('#' + _o.itemid).find('.dx-datagrid-headers').find("tr").length;
																		
																		// rowspan을 갖고 있는지 여부를 판단해 그 값을 저장
																		if (_data.isGrdCellMerge) {
																			gProgressbar.show();
																			_data.mergeRange = [];
																			var paging = _o.dxItem.option('paging');
																			var pagingF = {
																				enabled: false
																   			};
																			_o.dxItem.option('paging', pagingF);
																			setTimeout(function(){
																				var _grdBody = $('#' + _o.itemid).find('.dx-datagrid-table').find('.dx-data-row');
																				var bodyRCnt = _grdBody.length;
																				for (var ii=0; ii<bodyRCnt; ii++) {
																					var _tds = _grdBody.eq(ii).find('td');
																					var nRowIndex = _grdBody.eq(ii).attr('aria-rowindex') -1;
																					var _tdsLen = _tds.length;
																					for (var k=0; k<_tdsLen; k++) {
																						var _td = _tds.eq(k);
																						// rowspan여부 체크
																						if (!isNull(_td.attr('rowspan'))) {
																							var nRowSpan = parseInt(_td.attr('rowspan'));
																							var nColIndex = parseInt(_td.attr('aria-colindex')) - 1;
																							if (nRowSpan > 1) {
																								_data.mergeRange.push({
																									row: nRowIndex,
																									col: nColIndex,
																									range: nRowSpan
																								});
																							}
																						}
																					}
																				}
																				_o.dxItem.option('paging', paging);

																				contentList.push(_data);
																				/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
																				if(contentList.length == _sortedItemIdx.length - gridNumber){
																					self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
																				}else{
																					self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																				}
																			}, 5000);
																		} else {
																			contentList.push(_data);
																			/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
																			if(contentList.length == _sortedItemIdx.length - gridNumber){
																				self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
																			}else{
																				self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																			}
																		}
																		
																	} else {
																		contentList.push(_data);
																		/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
																		if(contentList.length == _sortedItemIdx.length - gridNumber){
																			self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
																		}else{
																			self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																		}
																	}
																	
																	
																}
															// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
															}
														});
													}
													_e.cancel = true;
												});
//									    	if (_o.type == 'PIVOT_GRID' && _o.Pivot.PagingOptions.PagingEnabled) {
//									    		_o.Pivot.PagingOptions.PagingEnabled = false;
//												// 피벗그리드 페이징 옵션에 따른 UI 처리를 위한 높이 조정
//												$("#" + _o.itemid + "_bas").height("100%");
//												if (WISE.Constants.editmode === 'viewer') {
//													gDashboard.goldenLayoutManager[WISE.Constants.pid].resize(_o);
//												}
//												else {
//													gDashboard.goldenLayoutManager.resize(_o);
//												}
//												_o.renderPivot(_o, _o.downLoadData);
//												setTimeout(function () {
//													 if (_o.meta.ColRowSwitch ) {
//															var dataSource = _o.dxItem.getDataSource();
//															var columns = dataSource.getAreaFields('column');
//															var rows = dataSource.getAreaFields('row');
//
//															var i = 0;
//															_.each(rows, function(_row) {
//																dataSource.field(_row.caption, {area: 'column', areaIndex : i});
//																i++;
//															});
//
//															var j = 0;
//															_.each(columns, function(_column) {
//																dataSource.field(_column.caption, {area: 'row', areaIndex : j});
//																j++;
//															});
//
//															dataSource.reload();
//														}
//													 
//													 _o.dxItem.exportToExcel();
//												},3000);
//									    	 }
//											else {
												_o.dxItem.exportToExcel();
											//}
									    		
									    	break;
									    case "Dev_ExcelJs" :
											_o.dxItem.off('fileSaving').on('fileSaving',function(_e){
		//											window.jsPDF = window.jspdf.jsPDF;
		//											applyPlugin(window.jsPDF);
		//											var doc = new jsPDF();
		//											  DevExpress.pdfExporter.exportDataGrid({
		//												jsPDFDocument: doc,
		//												component: _e.component
		//											  }).then(function() {
		//												doc.save('Customers.pdf');
		//											  });
													var formData = new FormData();
													if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
														formData.append("reportName","NewReport");
													}else{
														formData.append("reportName",reportName);
													}
													
													var workbook = new ExcelJS.Workbook();
													var worksheet = workbook.addWorksheet("Main sheet");
													DevExpress.excelExporter
													  .exportDataGrid({
														worksheet: worksheet,
														component: _e.component,
													  })
													  .then(function () {
														workbook.xlsx.writeBuffer().then(function (buffer) {
															formData.append("itemName", Base64.encode(itemName));
															// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
															formData.append("originItemName",originItemName);
		
															formData.append("exceldata", new Blob([buffer], {type: "application/octet-stream"}));
		
															var isRunning = false;
															if(!isRunning){
																$.ajax({
																	type : 'POST',
																	data : formData,
																	async : false,
																	url : WISE.Constants.context + '/download/saveXLSX.do',
																	contentType: false,
																	processData: false,
																	success : function(_data) {
																		isRunning = true;
																		_idx++;
																		if(typeof _data == 'string'){
												                    		_data = JSON.parse(_data);
												                    	}
																		if(_data.checkValue){
																			_data.item = itemName;
																			// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
																			_data.originItemName = originItemName;
																			_data.itemtype = _o.type;
																			_data.memoText = memoText;
																			/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
																			if(typeof _o.meta.ShowCaption != 'undefined'){
																				if(!_o.meta.ShowCaption){
																					_data.hidecaption = itemName;
																				}
																			}
																			contentList.push(_data);
																			/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
																			if(contentList.length == _sortedItemIdx.length - gridNumber){
																				self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
																			}else{
																				self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																			}
																		}
																	// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
																	}
																});
															}
														});
													  });
													_e.cancel = true;
												});
												_o.dxItem.exportToExcel();
									    	break;
									    default:
									    	break;
							    	}
								}
			   		   		//}
			   		   		
							
							break;
						case 'SIMPLE_CHART' :
						// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
						case 'TREEMAP' :
						case 'STAR_CHART' :
						case 'PYRAMID_CHART' :
						/* DOGFOOT syjin 카카오 지도 추가  20200820 */
						case 'KAKAO_MAP' :
						case 'KAKAO_MAP2' :
						case 'FUNNEL_CHART' :
						case 'CHOROPLETH_MAP':
							
							//20210907 shlim BEGIN
						    var displayCheck = false,tabDisplayCheck = false;
							if(dashboardTabname != ''){
								if($('#'+_o.itemid).parent().parent().css("display") === "none" || $('#'+dashboardTabname).css("display") === "none"){
									if($('#'+dashboardTabname).css("display") === "none"){
										$('#'+dashboardTabname).css("display",'block');
										tabDisplayCheck = true;
									}
									if($('#'+_o.itemid).parent().parent().css("display") === "none"){
										$('#'+_o.itemid).parent().parent().css("display",'block')
										displayCheck = true;
									}
									$('#'+_o.itemid).parent().css('height','100%')
									
								}
								_o.dxItem.render();
							}
							//20210907 shlim END
							
						   	_o.dxItem.off('fileSaving').on('fileSaving',function(_e){
					 	 		var formData = new FormData();
					   			if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
					   				formData.append("reportName","NewReport");
					   			}else{
					   			/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
					   				formData.append("reportName",reportName);
					   			}
					   			formData.append("imagedata",_e.data);
					   			formData.append("itemName",Base64.encode(itemName));
					   			var isRunning = false;
					      		if(!isRunning){
					      			$.ajax({
					                    type : 'POST',
					                    data : formData,
					                    url : WISE.Constants.context + '/download/saveImage.do',
					                    async : false,
					                    contentType: false,
					                    processData: false,
					                    success : function(_data) {
					                    	isRunning = true;
					                    	_idx++;
					                    	_o.dxItem.option('size',{'height':'100%'});
					                    	if(typeof _data == 'string'){
					                    		_data = JSON.parse(_data);
					                    	}
					                    	
											if(_data.checkValue){
												_data.item = itemName;
												_data.itemtype = _o.type;												
												
												/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
												_data.memoText = memoText;
												/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
												if(typeof _o.meta.ShowCaption != 'undefined'){
													if(!_o.meta.ShowCaption){
														_data.hidecaption = itemName;
													}
												}
												contentList.push(_data);
												
												//20210907 shlim BEGIN
												if(tabDisplayCheck){
													$('#'+dashboardTabname).css("display",'none');
												}
												if(displayCheck){
													$('#'+_o.itemid).parent().parent().css("display",'none')
												}
												//20210907 shlim END
												
												/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
												if(contentList.length == _sortedItemIdx.length - gridNumber){
													self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
												}else{
													self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
												}
											}
											// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
					                  	}
					      			});
					      		}
					      		_e.cancel = true;
							});
							if(_o.dxItem  && downloadType == 'pdf'){
								if($('#'+_o.itemid).height() > $('#'+_o.itemid).width()){
								    _o.dxItem.option('size',{'height':$('#'+_o.itemid).width()/1.7});
								}
							}
						   	_o.dxItem.exportTo('filename,png');
							break;
						case 'PIE_CHART' :
							var piePictureList = [];
						   	$.each(_o.dxItem,function(_index,_pie){
						   		
						   		//20210907 shlim BEGIN
						   		var displayCheck = false,tabDisplayCheck = false;
						   		/* DOGFOOT syjin 파이차트 다운로드 무한로딩 현상 수정 20211130 */
						   		self.pieCount = 0;
								if(dashboardTabname != ''){
									if($('#'+_o.itemid).parent().parent().css("display") === "none" || $('#'+dashboardTabname).css("display") === "none"){
										if($('#'+dashboardTabname).css("display") === "none"){
											$('#'+dashboardTabname).css("display",'block');
											tabDisplayCheck = true;
										}
										if($('#'+_o.itemid).parent().parent().css("display") === "none"){
											$('#'+_o.itemid).parent().parent().css("display",'block')
											displayCheck = true;
										}
										$('#'+_o.itemid).parent().css('height','100%')

									}
									_o.dxItem[0].render();
									if (_o.dxItem.length == 1) {
										var size = { 'height': $('#' + _o.itemid).height(), 'width': $('#' + _o.itemid).width() };
										_o.dxItem[0].option('size', size);
										_o.dxItem[0].render();
									} else {
										_o.resize();
									}
								}
								//20210907 shlim END
						   		
								_pie.off('fileSaving').on('fileSaving',function(_e){
									var formData = new FormData();
									if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
										formData.append("reportName","NewReport");
									}else{
									/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
										formData.append("reportName",reportName);
									}
									formData.append("imagedata",_e.data);
									formData.append("itemName",Base64.encode(itemName));
									var isRunning = false;
									if(!isRunning){
										$.ajax({
											type : 'POST',
											data : formData,
											async : false,
											url : WISE.Constants.context + '/download/saveImage.do',
											contentType: false,
											processData: false,
											success : function(_data) {
												self.pieCount++;
												isRunning = true;
												if(typeof _data == "string"){
													_data = JSON.parse(_data);
												} 
												if(_data.checkValue){
													piePictureList.push(_data.uploadPath);
												}
												_o.dxItem[_index].option('size',{'height': '100%'});
												
												//20210907 shlim BEGIN
												if(tabDisplayCheck){
													$('#'+dashboardTabname).css("display",'none');
												}
												if(displayCheck){
													$('#'+_o.itemid).parent().parent().css("display",'none')
												}
												//20210907 shlim  END
												
												if(_o.dxItem.length == self.pieCount){
													if(self.pieCount == 1){
														_idx++;
														if(_data.checkValue){
															_data.item = itemName;
															_data.itemtype = _o.type;
															/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
															_data.memoText = memoText;
															/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
															if(typeof _o.meta.ShowCaption != 'undefined'){
																if(!_o.meta.ShowCaption){
																	_data.hidecaption = itemName;
																}
															}
															contentList.push(_data);
															/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
															if(contentList.length == _sortedItemIdx.length - gridNumber){
																self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
															}else{
																self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
															}
														}
													}else{
														isRunning = false;
														$.ajaxSettings.traditional = true;
														$.ajax({
															type : 'POST',
															data : {
																'pictureList' : piePictureList
															},
															async : false,
															url : WISE.Constants.context + '/download/mergeImage.do',
															success : function(_data) {
																isRunning = true;
																_idx++;
																if(typeof _data == 'string'){
										                    		_data = JSON.parse(_data);
										                    	}
																if(_data.checkValue){
																	_data.item = itemName;
																	_data.itemtype = _o.type;
																	//2020.12.22 mksong 다운로드 memoText 누락부분 수정 dogfoot
																	_data.memoText = memoText;
																	/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
																	if(typeof _o.meta.ShowCaption != 'undefined'){
																		if(!_o.meta.ShowCaption){
																			_data.hidecaption = itemName;
																		}
																	}
																	contentList.push(_data);
																	/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
																	if(contentList.length == _sortedItemIdx.length - gridNumber){
																		self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
																	}else{
																		self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																	}
																}
															}
														});
													}
												}
												// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
											}
										});
									}
								_e.cancel = true;
							});
							if(_pie && downloadType == 'pdf' ){
								if($('#'+_o.itemid).height() > $('#'+_o.itemid).width()){
								    _pie.option('size',{'height':$('#'+_o.itemid).width()/1.7});
								}
							}
							_pie.exportTo('filename,png');
							
							if(_o.prevAnimation){
								_o.meta['Animation'] = _o.prevAnimation;
								
								_pie.option("animation", {
				    				enabled: _o.meta['Animation'] === 'none' ? false : true,
		    	    				easing: _o.meta['Animation'] === 'none' ? 'easeOutCubic' : _o.meta['Animation']
		    					});
							}
				   		});
						if(_o.prevAnimation){
							_o.prevAnimation = undefined;
						}
					   	break;
					   	/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
						case 'CARD_CHART':
							var cardPictureList = [];
							var cardCount = 0;
							 $.each(_o.dxItem,function(_index,_card){
									var formData = new FormData();
									if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
										formData.append("reportName","NewReport");
									}else{
									/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
										formData.append("reportName",reportName);
									}

									//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
									WISE.loadedSourceCheck('html2canvas');
									html2canvas(_card[0], {letterRendering:true}).then(function(canvas) {
							    		canvas.toBlob(function(blob){
							    			formData.append("imagedata", blob);
											formData.append("itemName",Base64.encode(_o.itemNm));
//											formData.append("itemName",_o.itemNm);
											var isRunning = false;
											if(!isRunning){
												$.ajax({
													type : 'POST',
													data : formData,
													async : false,
													url : WISE.Constants.context + '/download/saveImage.do',
													contentType: false,
													processData: false,
													success : function(_data) {
														cardCount++;
														isRunning = true;
														if(typeof _data == 'string'){
								                    		_data = JSON.parse(_data);
								                    	}
														if(_data.checkValue){
															cardPictureList.push(_data.uploadPath);
														}
														if(_o.dxItem.length == cardCount){
															if(cardCount == 1){
																_idx++;
																if(_data.checkValue){
																	_data.item = itemName;
																	_data.itemtype = _o.type;
																	/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
																	_data.memoText = memoText;
																	/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/

																	contentList.push(_data);
																	/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
																	if(contentList.length == _sortedItemIdx.length - gridNumber){
																		gDashboard.downloadManager.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
																	}else{
																		gDashboard.downloadManager.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																	}
																}
															}else{
																isRunning = false;
																$.ajaxSettings.traditional = true;
																$.ajax({
																	type : 'POST',
																	data : {
																		'pictureList' : cardPictureList
																	},
																	async : false,
																	url : WISE.Constants.context + '/download/mergeImage.do',
																	success : function(_data) {
																		isRunning = true;
																		_idx++;
																		if(typeof _data == 'string'){
												                    		_data = JSON.parse(_data);
												                    	}
																		if(_data.checkValue){
																			_data.item = itemName;
																			_data.itemtype = _o.type;
																			//2020.12.22 mksong 다운로드 memoText 누락부분 수정 dogfoot
																			_data.memoText = memoText;
																			/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
																			if(typeof _o.meta.ShowCaption != 'undefined'){
																				if(!_o.meta.ShowCaption){
																					_data.hidecaption = itemName;
																				}
																			}
																			contentList.push(_data);
																			/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
																			if(contentList.length == _sortedItemIdx.length - gridNumber){
																				self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
																			}else{
																				self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																			}
																		}
																	}
																});
															}
														}
														// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
													}
												});
											}
							    		});
							    	});
								});
							break;
					   	// 2020.02.21 mksong textbox 다운로드 추가 dogfoot
						case 'TEXTBOX':
							var formData = new FormData();
							if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
								formData.append("reportName","NewReport");
							}else{
							/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
								formData.append("reportName",reportName);
							}
							formData.append("textbox_html",_o.meta.Text);
							formData.append("itemName",itemName);

							var isRunning = false;
					  		if(!isRunning){
					  			$.ajax({
					                type : 'POST',
					                data : formData,
					                async : false,
					                url : WISE.Constants.context + '/download/saveXLSXForTextBox.do',
					                contentType: false,
					                processData: false,
					                success : function(_data) {
					                	isRunning = true;
					                	_idx++;
					                	if(typeof _data == 'string'){
				                    		_data = JSON.parse(_data);
				                    	}
										if(_data.checkValue){
											_data.item = itemName;
											// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
											_data.originItemName = originItemName;
											/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
											_data.memoText = memoText;
											_data.itemtype = _o.type;
											/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
											if(typeof _o.meta.ShowCaption != 'undefined'){
												if(!_o.meta.ShowCaption){
													_data.hidecaption = itemName;
												}
											}
											contentList.push(_data);
											/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
											if(contentList.length == _sortedItemIdx.length - gridNumber){
												self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
											}else{
												self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
											}
										}
									// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
					              	}
				  				});
					  		}

							break;
						case 'HISTOGRAM_CHART':
						case 'DIVERGING_CHART':
						case 'SCATTER_PLOT':
						case 'SCATTER_PLOT2':
						case "HISTORY_TIMELINE":
						case "ARC_DIAGRAM":
						case "RADIAL_TIDY_TREE":
						case "SCATTER_PLOT_MATRIX":
						case 'BOX_PLOT':
						case 'COORDINATE_LINE':
						case 'DEPENDENCY_WHEEL':
						case 'SEQUENCES_SUNBURST':
						case 'LIQUID_FILL_GAUGE':
						case 'WATERFALL_CHART':
						case 'BIPARTITE_CHART':
						case 'SANKEY_CHART':
						case 'PARALLEL_COORDINATE':
						case 'BUBBLE_PACK_CHART':
						case 'WORD_CLOUD_V2':
						case 'DENDROGRAM_BAR_CHART':
						case 'CALENDAR_VIEW_CHART':
						case 'CALENDAR_VIEW2_CHART':
						case 'CALENDAR_VIEW3_CHART':
						case 'COLLAPSIBLE_TREE_CHART':
						case 'HEATMAP':
						case 'HEATMAP2':
						case 'COORDINATE_DOT':
                        case 'SYNCHRONIZED_CHARTS':
						case 'RECTANGULAR_ARAREA_CHART':
						case 'WORD_CLOUD':
						case 'BUBBLE_D3':
						case 'FORCEDIRECT':
						case 'FORCEDIRECTEXPAND':
						case 'HIERARCHICAL_EDGE':
							gProgressbar.show();
							var displayCheck = false,tabDisplayCheck = false;
							if(gDashboard.reportType === 'StaticAnalysis'){
								if($('#'+_o.itemid).parent().parent().css("display") === "none" || $('#'+dashboardTabname).css("display") === "none"){
									if($('#'+dashboardTabname).css("display") === "none"){
										$('#'+dashboardTabname).css("display",'block');
										tabDisplayCheck = true;
									}
									if($('#'+_o.itemid).parent().parent().css("display") === "none"){
										$('#'+_o.itemid).parent().parent().css("display",'block')
										displayCheck = true;
									}
									$('#'+_o.itemid).parent().css('height','100%')
									_o.resize();
								}
							}

							var resizeCheck = false;
							if(downloadType == 'pdf'){
								if($('#'+_o.itemid).height() > $('#'+_o.itemid).width()){
									var heiee = $('#'+_o.itemid).width()/1.7;
									$('#'+_o.itemid).css('cssText','height:'+ heiee+"px !important");
									_o.resize();
									resizeCheck = true;
								}
							}

							setTimeout(function(){
                                var svg = $('#'+_o.itemid).find('svg')[0];
								var svgNode = getSVGString(svg);

								self.saveImg = function(imgData){
									//2020.11.03 mksong resource Import 동적 구현 dogfoot

									var blob = new Blob([imgData],{type: "image/png;charset=utf-8"});
									var reportName = "newReport";
									if(gDashboard.structure.ReportMasterInfo != undefined){
										reportName = gDashboard.structure.ReportMasterInfo.name == "" ? 'newReport' : gDashboard.structure.ReportMasterInfo.name.replace( /\s/gi,"_");
										reportName = reportName.replace(/\//g,'_');
										reportName = reportName.replace(/\\/g,'_');
									}
									var formData = new FormData();
									if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
										formData.append("reportName","NewReport");
									}else{
										formData.append("reportName",reportName);
									}
	//								formData.append("imagedata",blob);
									formData.append("imagedata",blob);
									formData.append("svgXml",Base64.decode(imgData));
									formData.append("imageType",'D3Png');
									formData.append("itemName",Base64.encode(_o.itemNm.replace(/\//g,'_')));

									if(downloadType == 'pdf'){
										if(resizeCheck){
											$('#'+_o.itemid).css('cssText','');
											_o.resize();
										}
									}
									$.ajax({
										type : 'POST',
										data : formData,
										async : false,
										url : WISE.Constants.context + '/download/saveImage.do',
										contentType: false,
										processData: false,
										success : function(_data) {
											gProgressbar.hide();
											isRunning = true;
											_idx++;
											if(typeof _data == 'string'){
					                    		_data = JSON.parse(_data);
					                    	}
											if(_data.checkValue){
												_data.item = itemName;
												_data.itemtype = _o.type;
												/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
												_data.memoText = memoText;
												/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
												if(typeof _o.meta.ShowCaption != 'undefined'){
													if(!_o.meta.ShowCaption){
														_data.hidecaption = itemName;
													}
												}

												if(tabDisplayCheck){
													$('#'+dashboardTabname).css("display",'none');
												}
												if(displayCheck){
													$('#'+_o.itemid).parent().parent().css("display",'none')
												}

												contentList.push(_data);
												/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
												if(contentList.length == _sortedItemIdx.length - gridNumber){
													self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
												}else{
													self.downloadSet(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
												}
											}

										}

									});
									//saveAs(blob, reportName + '.png');
								}
								//2020.11.03 mksong resource Import 동적 구현 dogfoot
								WISE.loadedSourceCheck('saveSvgAsPng');
								saveSvgAsPng(svgNode, _o.Name + '.png', { canvg: canvg, backgroundColor: 'white'},true);

							},100);
							break;
		   		   	}
				}
			});
		}
	};
	/*dogfoot 이미지 전체 다운로드 추가 shlim 20200828*/
	this.downloadSetImg = function(_idx, contentList,_sortedItemIdx, downloadType, paramItemsStr){
		// 2019.12.10 수정자 : mksong 다운로드 컨테이너 이름으로 시트 이름 구성 기능 추가 DOGFOOT
		var layoutTree;
		if(WISE.Constants.editmode != 'viewer'){
			/*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
			if(gDashboard.reportType === 'StaticAnalysis'){
				if(gDashboard.reportUtility.setAysLayoutTree().LayoutTabContainer != undefined){
					layoutTree = gDashboard.reportUtility.setAysLayoutTree().LayoutTabContainer[0].LayoutTabPage;
				}else{
					layoutTree = false;
				}
		 	}else{
		 		if(gDashboard.reportUtility.setLayoutTree().LayoutTabContainer != undefined){
					layoutTree = gDashboard.reportUtility.setLayoutTree().LayoutTabContainer[0].LayoutTabPage;
				}else{
					layoutTree = false;
				}
			}

//			if(gDashboard.reportUtility.setLayoutTree().LayoutTabContainer != undefined){
//				layoutTree = gDashboard.reportUtility.setLayoutTree().LayoutTabContainer[0].LayoutTabPage;
//			}else{
//				layoutTree = false;
//			}
		}else{
			/* DOGFOOT hsshim 200107
			 * 뷰어 일반 레이아웃 다운로드 방식 적용
			 */
//			layoutTree = false;
			// 골든레이아웃 방식
//			 layoutTree = gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer == undefined ? false : gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer[0].LayoutTabPage;
			/*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
			 if(gDashboard.reportType === 'StaticAnalysis'){
				layoutTree = gDashboard.reportUtility.setAysLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer == undefined ? false : gDashboard.reportUtility.setAysLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer[0].LayoutTabPage;
		 	 }else{
		 		layoutTree = gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer == undefined ? false : gDashboard.reportUtility.setLayoutTree(gDashboard.structure.ReportMasterInfo.id).LayoutTabContainer[0].LayoutTabPage;
			 }
		}

		if(_idx <= _sortedItemIdx.length){
			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i, _o){
				if(_sortedItemIdx[_idx] == _o.ComponentName || _sortedItemIdx[_idx] == _o.itemid.substr(0,_o.itemid.indexOf('_'))){
				// 2019.12.10 수정자 : mksong 다운로드 컨테이너 이름으로 시트 이름 구성 기능 추가 DOGFOOT
					var content;
					/*dogfoot 다운로드 명칭 오류 수정 shlim 20200715*/
					var itemName = self.reformItemName(_o.meta.Name,_idx);
		   		   	/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
		   		   	var hidecaption;
		   		   	//2020.03.05 MKSONG 비정형일 경우 예외 처리 DOGFOOT
		   		   	var originItemName = gDashboard.reportType != 'AdHoc' ? _o.meta.Name : "";
		   		   	var dashboardItemName = _sortedItemIdx[_idx];
		   			var dashboardTabname = "";
		   		   	if(layoutTree){
		   		   		$.each(layoutTree,function(_tabindex,_tab){
		   		   			var tabname = $('#'+_tab.DashboardItem+'_item_title').attr('title');
		   		   			// 2020.01.07 mksong 탭컨테이너 사용시 다운로드 오류 수정 dogfoot
		   		   			if(_tab.LayoutGroup != undefined){
			   		   			$.each(_tab.LayoutGroup,function(_groupIndex,_group){
				   		   			if(!_group.LayoutItem){
			   		   					$.each(_group.LayoutGroup,function(_itemIndex,_group2){
											$.each(_group2.LayoutItem,function(_itemIndex,_item){
												if(_item.DashboardItem == dashboardItemName){
													itemName = tabname + '_'+itemName;
													dashboardTabname = _tab.DashboardItem;
												}
											});
										});
			   		   				}else{
			   		   					$.each(_group.LayoutItem,function(_itemIndex,_item){
											if(_item.DashboardItem == dashboardItemName){
												itemName = tabname + '_'+itemName;
												dashboardTabname = _tab.DashboardItem;
											}
										});
			   		   				}
			   		   			});
		   		   			}else{
			   		   			$.each(_tab.LayoutItem,function(_itemIndex,_item){
			   		   				if(_item.DashboardItem == dashboardItemName){
			   		   					itemName = tabname + '_'+itemName;
			   		   					dashboardTabname = _tab.DashboardItem;
			   		   				}
			   		   			});
		   		   			}
		   		   		});
		   		   	}

		   		   	itemName = itemName.replace(/\//g,'_');
		   		   	// 2019.12.10 수정자 : mksong 다운로드 컨테이너 이름으로 시트 이름 구성 기능 수정 끝 DOGFOOT
		   		   	itemName = itemName.replace(/\\/g,'_');
		   		   	itemName = itemName.replace(/\./g,'_');
		   		   	itemName = itemName.replace(/\*/g,'_');
		   		   	itemName = itemName.replace(/\[/g,'_');
   		   			itemName = itemName.replace(/\]/g,'_');
		   		   	itemName = itemName.replace(/\:/g,'_');
		   		   	itemName = itemName.replace(/\?/g,'_');
		   		   	itemName = itemName.replace(/\</g,'(');
		   		   	itemName = itemName.replace(/\>/g,')');
		   		   /* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
		   		   	var reportName = gDashboard.reportUtility.reportInfo.ReportMasterInfo.name;
		   		   	reportName = reportName.replace(/\//g,'_');
		   		   	reportName = reportName.replace(/\\/g,'_');

		   		   	switch(_o.type){
			   		   	case 'PIVOT_GRID' :
			   		   	case 'DATA_GRID' :
			   		   	case 'TEXTBOX':
							//OutOfMemory로 서버 다운로드로 전환
				   		   	gProgressbar.show();

				   		   	var displayCheck = false,tabDisplayCheck = false;
				   		   	if(gDashboard.reportType === 'StaticAnalysis'){
					   		   	if($('#'+_o.itemid).parent().parent().css("display") === "none" || $('#'+dashboardTabname).css("display") === "none"){
									if($('#'+dashboardTabname).css("display") === "none"){
										$('#'+dashboardTabname).css("display",'block');
										tabDisplayCheck = true;
										self.blockImgList.push(dashboardTabname)
									}
									if($('#'+_o.itemid).parent().parent().css("display") === "none"){
										$('#'+_o.itemid).parent().parent().css("display",'block')
										displayCheck = true;
										self.blockImgList.push(_o.itemid)
									}
									_o.dxItem.refresh()
								}
				   		   	}

					    	$('.lm_title').attr('style', 'display: block !important');
					    	var containerId = '#'+_o.itemid
							//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
							WISE.loadedSourceCheck('html2canvas');

					    	html2canvas.allowTaint = true;
					    	html2canvas(document.querySelector(containerId), {letterRendering:true}).then(function(canvas) {
					    		canvas.toBlob(function(blob){
					    			self.saveImg = function(imgData){
										var blob = new Blob([imgData],{type: "image/png;charset=utf-8"});
										var reportName = "newReport";
										var itemNm = _o.itemNm ? _o.itemNm : _o.Name
										if(gDashboard.structure.ReportMasterInfo != undefined){
											reportName = gDashboard.structure.ReportMasterInfo.name == "" ? 'newReport' : gDashboard.structure.ReportMasterInfo.name.replace( /\s/gi,"_");
											reportName = reportName.replace(/\//g,'_');
											reportName = reportName.replace(/\\/g,'_');
										}
										var formData = new FormData();
										if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
											formData.append("reportName","NewReport");
										}else{
											formData.append("reportName",reportName);
										}
//										formData.append("imagedata",blob);

										formData.append("imagedata",imgData);
										formData.append("itemName",Base64.encode(itemNm));
										$.ajax({
											type : 'POST',
											data : formData,
											async : false,
											url : WISE.Constants.context + '/download/saveImage.do',
											contentType: false,
											processData: false,
											success : function(_data) {
												gProgressbar.hide();
												isRunning = true;
						                    	_idx++;
						                    	if(typeof _data == 'string'){
						                    		_data = JSON.parse(_data);
						                    	}
												if(_data.checkValue){
													_data.item = itemName;
													_data.itemtype = _o.type;
													_data.itemid = _o.itemid;
													/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
													if(typeof _o.meta.ShowCaption != 'undefined'){
														if(!_o.meta.ShowCaption){
															_data.hidecaption = itemName;
														}
													}
													if(gDashboard.reportType !== 'StaticAnalysis'){
														contentList.push(_data);
														if(contentList.length == _sortedItemIdx.length){
															self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
														}else{
															self.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
														}
										   		    }else{
										   		    	if(tabDisplayCheck){
															$('#'+dashboardTabname).css("display",'none');
														}
														if(displayCheck){
															$('#'+_o.itemid).parent().parent().css("display",'none')
														}
										   		    	if(_idx == _sortedItemIdx.length){
															self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
														}else{
															self.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
														}
										   		    }


												}

											}

										});
										//saveAs(blob, reportName + '.png');
									}
					    			self.saveImg(blob);
					    		});
					    	});
							break;
						case 'SIMPLE_CHART' :
						// 2020.02.04 mksong 다운로드 아이템 추가 dogfoot
						case 'TREEMAP' :
						case 'STAR_CHART' :
						case 'PYRAMID_CHART' :
						case 'FUNNEL_CHART' :
						case 'CHOROPLETH_MAP':
						   	_o.dxItem.off('fileSaving').on('fileSaving',function(_e){
					 	 		var formData = new FormData();
					   			if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
					   				formData.append("reportName","NewReport");
					   			}else{
					   			/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
					   				formData.append("reportName",reportName);
					   			}
					   			formData.append("imagedata",_e.data);
					   			formData.append("itemName",Base64.encode(itemName));
					   			var isRunning = false;
					      		if(!isRunning){
					      			$.ajax({
					                    type : 'POST',
					                    data : formData,
					                    url : WISE.Constants.context + '/download/saveImage.do',
					                    async : false,
					                    contentType: false,
					                    processData: false,
					                    success : function(_data) {
					                    	isRunning = true;
					                    	_idx++;
					                    	_o.dxItem.option('size',{'height':'100%'});
											if(_data.checkValue){
												_data.item = itemName;
												_data.itemtype = _o.type;
												_data.itemid = _o.itemid;
												/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
												if(typeof _o.meta.ShowCaption != 'undefined'){
													if(!_o.meta.ShowCaption){
														_data.hidecaption = itemName;
													}
												}
												contentList.push(_data);
												if(contentList.length == _sortedItemIdx.length){
//													self.downloadStart(contentList, paramItemsStr, downloadType);
													self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
												}else{
													self.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
												}
											}
											// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
					                  	}
					      			});
					      		}
					      		_e.cancel = true;
							});
							if(_o.dxItem  && downloadType == 'pdf'){
								if($('#'+_o.itemid).height() > $('#'+_o.itemid).width()){
								    _o.dxItem.option('size',{'height':$('#'+_o.itemid).width()/1.7});
								}
							}
						   	_o.dxItem.exportTo('filename,png');
							break;
						case 'PIE_CHART' :
							var piePictureList = [];
						   	$.each(_o.dxItem,function(_index,_pie){
								_pie.off('fileSaving').on('fileSaving',function(_e){
								var formData = new FormData();
									if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
										formData.append("reportName","NewReport");
									}else{
									/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
										formData.append("reportName",reportName);
									}
									formData.append("imagedata",_e.data);
									formData.append("itemName",Base64.encode(itemName));
									var isRunning = false;
									if(!isRunning){
										$.ajax({
											type : 'POST',
											data : formData,
											async : false,
											url : WISE.Constants.context + '/download/saveImage.do',
											contentType: false,
											processData: false,
											success : function(_data) {
												self.pieCount++;
												isRunning = true;
												if(_data.checkValue){
													piePictureList.push(_data.uploadPath);
												}
												_o.dxItem[_index].option('size',{'height': '100%'});
												if(_o.dxItem.length == self.pieCount){
													if(self.pieCount == 1){
														_idx++;
														if(_data.checkValue){
															_data.item = itemName;
															_data.itemtype = _o.type;
															_data.itemid = _o.itemid;
															/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
															if(typeof _o.meta.ShowCaption != 'undefined'){
																if(!_o.meta.ShowCaption){
																	_data.hidecaption = itemName;
																}
															}
															contentList.push(_data);
															if(contentList.length == _sortedItemIdx.length){
//																self.downloadStart(contentList, paramItemsStr, downloadType);
																self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
															}else{
																self.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
															}
														}
													}else{
														isRunning = false;
														$.ajaxSettings.traditional = true;
														$.ajax({
															type : 'POST',
															data : {
																'pictureList' : piePictureList
															},
															async : false,
															url : WISE.Constants.context + '/download/mergeImage.do',
															success : function(_data) {
																isRunning = true;
																_idx++;
																if(typeof _data == 'string'){
										                    		_data = JSON.parse(_data);
										                    	}
																if(_data.checkValue){
																	_data.item = itemName;
																	_data.itemtype = _o.type;
																	_data.itemid = _o.itemid;
																	/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
																	if(typeof _o.meta.ShowCaption != 'undefined'){
																		if(!_o.meta.ShowCaption){
																			_data.hidecaption = itemName;
																		}
																	}
																	contentList.push(_data);
																	if(contentList.length == _sortedItemIdx.length){
//																		self.downloadStart(contentList, paramItemsStr, downloadType);
																		self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
																	}else{
																		self.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																	}
																}
															}
														});
													}
												}
												// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
											}
										});
									}
								_e.cancel = true;
							});
							if(_pie && downloadType == 'pdf' ){
								if($('#'+_o.itemid).height() > $('#'+_o.itemid).width()){
								    _pie.option('size',{'height':$('#'+_o.itemid).width()/1.7});
								}
							}
							_pie.exportTo('filename,png');
				   		});
					   	break;
					   	/* DOGFOOT mksong 2020-08-05 카드 이미지 다운로드 */
						case 'CARD_CHART':
							var cardPictureList = [];
							var cardCount = 0;
							 $.each(_o.dxItem,function(_index,_card){
									var formData = new FormData();
									if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
										formData.append("reportName","NewReport");
									}else{
									/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
										formData.append("reportName",reportName);
									}
									//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
									WISE.loadedSourceCheck('html2canvas');

									html2canvas(_card[0], {letterRendering:true}).then(function(canvas) {
							    		canvas.toBlob(function(blob){
							    			formData.append("imagedata", blob);
											formData.append("itemName",Base64.encode(_o.itemNm));
//											formData.append("itemName",_o.itemNm);
											var isRunning = false;
											if(!isRunning){
												$.ajax({
													type : 'POST',
													data : formData,
													async : false,
													url : WISE.Constants.context + '/download/saveImage.do',
													contentType: false,
													processData: false,
													success : function(_data) {
														cardCount++;
														isRunning = true;
														if(_data.checkValue){
															cardPictureList.push(_data.uploadPath);
														}
														if(_o.dxItem.length == cardCount){
															if(cardCount == 1){
																_idx++;
																if(_data.checkValue){
																	_data.item = itemName;
																	_data.itemtype = _o.type;
																	/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
																	_data.itemid = _o.itemid;
																	contentList.push(_data);
																	if(contentList.length == _sortedItemIdx.length){
//																		gDashboard.downloadManager.downloadStart(contentList, paramItemsStr, downloadType);
																		self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
																	}else{
																		gDashboard.downloadManager.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																	}
																}
															}else{
																isRunning = false;
																$.ajaxSettings.traditional = true;
																$.ajax({
																	type : 'POST',
																	data : {
																		'pictureList' : cardPictureList
																	},
																	async : false,
																	url : WISE.Constants.context + '/download/mergeImage.do',
																	success : function(_data) {
																		isRunning = true;
																		_idx++;
																		if(typeof _data == 'string'){
												                    		_data = JSON.parse(_data);
												                    	}
																		if(_data.checkValue){
																			_data.item = itemName;
																			_data.itemtype = _o.type;
																			_data.itemid = _o.itemid;
																			/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
																			if(typeof _o.meta.ShowCaption != 'undefined'){
																				if(!_o.meta.ShowCaption){
																					_data.hidecaption = itemName;
																				}
																			}
																			contentList.push(_data);
																			if(contentList.length == _sortedItemIdx.length){
//																				self.downloadStart(contentList, paramItemsStr, downloadType);
																				self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
																			}else{
																				self.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
																			}
																		}
																	}
																});
															}
														}
														// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
													}
												});
											}
							    		});
							    	});
								});
							break;
					   	// 2020.02.21 mksong textbox 다운로드 추가 dogfoot
						case 'HISTOGRAM_CHART':
						case 'WATERFALL_CHART':
						case 'BIPARTITE_CHART':
						case 'SANKEY_CHART':
						case 'DIVERGING_CHART':
                        case 'SCATTER_PLOT':
                        case 'SCATTER_PLOT2':
                        case 'COORDINATE_LINE':
                        case "HISTORY_TIMELINE":
                        case "ARC_DIAGRAM":
                        case "RADIAL_TIDY_TREE":
                        case "SCATTER_PLOT_MATRIX":
                        case 'BOX_PLOT':
                        case 'DEPENDENCY_WHEEL':
                        case 'SEQUENCES_SUNBURST':
                        case 'LIQUID_FILL_GAUGE':
						case 'PARALLEL_COORDINATE':
						case 'BUBBLE_PACK_CHART':
						case 'WORD_CLOUD_V2':
						case 'DENDROGRAM_BAR_CHART':
						case 'CALENDAR_VIEW_CHART':
						case 'CALENDAR_VIEW2_CHART':
						case 'CALENDAR_VIEW3_CHART':
						case 'COLLAPSIBLE_TREE_CHART':
						case 'HEATMAP':
						case 'HEATMAP2':
						case 'COORDINATE_DOT':
						case 'SYNCHRONIZED_CHARTS':
						case 'RECTANGULAR_ARAREA_CHART':
						case 'WORD_CLOUD':
						case 'BUBBLE_D3':
						case 'FORCEDIRECT':
						case 'FORCEDIRECTEXPAND':
						case 'HIERARCHICAL_EDGE':
							gProgressbar.show();
							var displayCheck = false,tabDisplayCheck = false;
							if(gDashboard.reportType === 'StaticAnalysis'){
								if($('#'+_o.itemid).parent().parent().css("display") === "none" || $('#'+dashboardTabname).css("display") === "none"){
									if($('#'+dashboardTabname).css("display") === "none"){
										$('#'+dashboardTabname).css("display",'block');
										tabDisplayCheck = true;
										self.blockImgList.push(_o.dashboardTabname)
									}
									if($('#'+_o.itemid).parent().parent().css("display") === "none"){
										$('#'+_o.itemid).parent().parent().css("display",'block')
										displayCheck = true;
										self.blockImgList.push(_o.itemid)
									}
									$('#'+_o.itemid).parent().css('height','100%')
									_o.resize();
								}
							}

							setTimeout(function(){
                                var svg = $('#'+_o.itemid).find('svg')[0];
								var svgNode = getSVGString(svg);

								self.saveImg = function(imgData){
									var blob = new Blob([imgData],{type: "image/png;charset=utf-8"});
									var reportName = "newReport";
									if(gDashboard.structure.ReportMasterInfo != undefined){
										reportName = gDashboard.structure.ReportMasterInfo.name == "" ? 'newReport' : gDashboard.structure.ReportMasterInfo.name.replace( /\s/gi,"_");
										reportName = reportName.replace(/\//g,'_');
										reportName = reportName.replace(/\\/g,'_');
									}
									var formData = new FormData();
									if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
										formData.append("reportName","NewReport");
									}else{
										formData.append("reportName",reportName);
									}
//									formData.append("imagedata",blob);
									formData.append("imagedata",blob);
									formData.append("svgXml",Base64.decode(imgData));
									formData.append("imageType",'D3Png');
									formData.append("itemName",Base64.encode(_o.itemNm.replace(/\//g,'_')));
									$.ajax({
										type : 'POST',
										data : formData,
										async : false,
										url : WISE.Constants.context + '/download/saveImage.do',
										contentType: false,
										processData: false,
										success : function(_data) {
											gProgressbar.hide();
											isRunning = true;
					                    	_idx++;
											if(_data.checkValue){
												_data.item = itemName;
												_data.itemtype = _o.type;
												_data.itemid = _o.itemid;
												/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
												if(typeof _o.meta.ShowCaption != 'undefined'){
													if(!_o.meta.ShowCaption){
														_data.hidecaption = itemName;
													}
												}
												if(gDashboard.reportType !== 'StaticAnalysis'){
													contentList.push(_data);
													if(contentList.length == _sortedItemIdx.length){
														self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
													}else{
														self.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
													}
									   		    }else{
									   		    	contentList.push(_data);
									   		    	if(_idx == _sortedItemIdx.length){
														self.downloadStart(contentList, paramItemsStr, downloadType,_sortedItemIdx);
													}else{
														self.downloadSetImg(_idx,contentList,_sortedItemIdx,downloadType,paramItemsStr);
													}
									   		    }
											}

										}

									});
									//saveAs(blob, reportName + '.png');
								}
								//2020.11.03 mksong resource Import 동적 구현 dogfoot
								WISE.loadedSourceCheck('saveSvgAsPng');
								saveSvgAsPng(svgNode, _o.Name + '.png', { canvg: canvg, backgroundColor: 'white'},true);

							},100);
							break;
		   		   	}
				}
			});
		}


	}

	this.downloadStart = function(contentList, paramItemsStr, downloadType, totalCountOver){
		gProgressbar.show();
		/* DOGFOOT ktkang 다운로드 오류 수정  202001005 */
		var path = '';
		if(contentList.length != 0) {
			path = contentList[0].uploadPath.substr(0,contentList[0].uploadPath.lastIndexOf("\\"));
		}
      	var tempType;
      	switch (downloadType){
	      	case 'xlsx':
			case 'xls':
			case 'cell':
				tempType = 'xlsx';
				break;
			case 'docx':
				tempType = 'docx';
				break;
			case 'pptx':
			case 'show':
				tempType = 'pptx';
				break;
			case 'html':
				tempType = 'xlsx';
				break;
			case 'pdf':
				tempType = 'pdf';
				break;
			case 'hwp':
				tempType = 'hwp';
				break;
			case 'csv':
			case 'txt':
				tempType = 'csv';
      	}

      	var reportName = gDashboard.structure.ReportMasterInfo.name == "" ? 'newReport' : gDashboard.structure.ReportMasterInfo.name.replace( /\s/gi,"_");
		   	reportName = reportName.replace(/\//g,'_');
		   	reportName = reportName.replace(/\\/g,'_');

      	if(downloadType != 'html' && downloadType != 'img'){
      		/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
      		if(totalCountOver && tempType == 'xlsx') {
      			var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
      			var downFile = SQLikeUtil.doSqlLikeExcel(contentList);
      			if(downFile) {
      				$('#downFileName').val(downFile.fileName);
      				$('#downFilePath').val(downFile.filePath);

      				$('#downForm').submit();
      				gProgressbar.hide();
      			} else {
      				gProgressbar.hide();
      			}
	      	}
      		else if(tempType == 'xlsx') {
      			var params = gDashboard.downloadParams;
      			if(typeof params == 'undefined') params = {};
//      			var params = {};
      			params.contentList = JSON.stringify(contentList),
      			params.reportName = reportName;
      			params.tempType = tempType;
      			params.srcFolderNm = srcFolderNm;
      			params.downloadType = downloadType;
      			params.params = paramItemsStr;
      			params.filepath = path;
      			params.downloadFilter = userJsonObject.downloadFilter;
      			params.userName = userJsonObject.userNm;
      			params.userId = userJsonObject.userId;
      			
      			$.ajax({
      				type : 'POST',
      				data : params,
      				contentType: "application/x-www-form-urlencoded; charset=UTF-8",
      				url : WISE.Constants.context + '/download/xlsxPivot.do',
      				success : function(_data) {
      					if(_data.fileName != undefined){
      						$('#downFileName').val(_data.fileName);
      						$('#downFilePath').val(_data.filePath);

      						$('#downForm').submit();
      						//2020.02.12 mksong 프로그레스바 hide 오류 수정 dogfoot
      						gProgressbar.hide();
      					}
      				},
      				error : function(request, status, error) {
      					WISE.alert("code: "+request.status+"\n"+"message: "+request.responseText+"\n"+"error: "+error);
      					// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
      					gProgressbar.hide();
      				}

      			});
      		} 
      		else {
      			$.ajax({
      				type : 'POST',
      				data : {
      					contentList : JSON.stringify(contentList),
      					reportName : reportName,
      					tempType : tempType,
      					//2020.03.03 mksong KERIS 출처 내용에 포함 dogfoot
      					srcFolderNm : srcFolderNm,
      					downloadType : downloadType,
      					params : paramItemsStr,
      					filepath : path,
      					/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
          				downloadFilter : userJsonObject.downloadFilter,
          				userName : userJsonObject.userNm,
          				userId : userJsonObject.userId,
          				paramObj : $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues()),
          				sqlTimeout : userJsonObject.searchLimitTime
      				},
      				contentType: "application/x-www-form-urlencoded; charset=UTF-8",
      				url : WISE.Constants.context + '/download/'+tempType+'.do',
      				success : function(_data) {
      					if(_data.fileName != undefined){
      						$('#downFileName').val(_data.fileName);
      						$('#downFilePath').val(_data.filePath);

      						$('#downForm').submit();
      						//2020.02.12 mksong 프로그레스바 hide 오류 수정 dogfoot
      						gProgressbar.hide();
      					}
      				},
      				error : function(request, status, error) {
      					WISE.alert("code: "+request.status+"\n"+"message: "+request.responseText+"\n"+"error: "+error);
      					// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
      					gProgressbar.hide();
      				}

      			});
      		}
      	} else if(downloadType == 'img'){/*dogfoot 이미지 전체 다운로드 추가 shlim 20200828*/
      		var containerId = WISE.Constants.editmode === 'viewer' ? '#reportContainer' : '#canvas-container';
      		var wi = $(containerId).width();
      		var hei = $(containerId).height();
      		var itemLocList = self.getImgLocation(contentList,totalCountOver);
      		self.reportNameSet = reportName+".png";
      		var pictureList =[];
      		$.each(contentList,function(_i,_path){
      			pictureList.push(_path.uploadPath);
      		});
      		$.ajaxSettings.traditional = true;

      		if(gDashboard.reportType === 'StaticAnalysis'){
      			$.each(self.blockImgList,function(_i,_l){
      				if(_l.indexOf('dashboardTabPage') > -1){
      					$('#'+_l).css("display",'none');
      				}else{
      					$('#'+_l).parent().parent().css("display",'none')
      				}
      			})
                hei = 0;
      			$.each(itemLocList,function(_j,_itemlist){
      				hei += parseInt(_itemlist.itemHeight)
      			})
      		}
      		$.ajax({
				type : 'POST',
				data : {
					'pictureList' : pictureList,
					'clientWidth' : wi,
					'clientHeight': hei,
					'itemLocationList' : JSON.stringify(itemLocList)
				},
				async : false,
				url : WISE.Constants.context + '/download/mergeImageAll.do',
				success : function(_data) {
					if(_data.checkValue){
						$('#downFileName').val(self.reportNameSet);
          				$('#downFilePath').val(_data.uploadPath);

          				$('#downForm').submit();
					}
       				//2020.02.12 mksong 프로그레스바 hide 오류 수정 dogfoot
      				gProgressbar.hide();

				}
			});
      	} else{
      		/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
      		$.ajax({
      			type : 'POST',
      			data : {
      				contentList : JSON.stringify(contentList),
      				reportName : gDashboard.structure.ReportMasterInfo.name == "" ? 'newReport' : gDashboard.structure.ReportMasterInfo.name.replace( /\s/gi,"_"),
//    				reportName : 'NewReport',
      				tempType : tempType,
      				//2020.03.03 mksong KERIS 출처 내용에 포함 dogfoot
      				srcFolderNm : srcFolderNm,
      				downloadType : downloadType,
      				params : paramItemsStr,
      				filepath : path,
      				/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
      				downloadFilter : userJsonObject.downloadFilter,
      				userName : userJsonObject.userNm,
      				userId : userJsonObject.userId
      			},
      			contentType: "application/x-www-form-urlencoded; charset=UTF-8",
      			url : WISE.Constants.context + '/download/'+downloadType+'.do',
      			success : function(_data) {
//    				saveAs(_data.workbook);
      				if(_data.fileName != undefined){
      					$('#downFileName').val(_data.fileName);
      					$('#downFilePath').val(_data.filePath);

      					$('#downForm').submit();
      					//2020.03.03 mksong 프로그레스바 hide 오류 수정 dogfoot
      					gProgressbar.hide();
      				}
      			},
      			error : function(request, status, error) {
      				WISE.alert("code: "+request.status+"\n"+"message: "+request.responseText+"\n"+"error: "+error,'error');
      				// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
      				gProgressbar.hide();
      			}

      		});
      	}

	};
	/*dogfoot 이미지 다운로드 시 레이아웃 위치 설정 shlim 20200828*/
	this.getImgLocation = function(_contentList,_sortedItemIdx){

		var containerId = WISE.Constants.editmode === 'viewer' ? '#reportContainer' : '#canvas-container';
		var conTop = $(containerId).offset().top;
  		var conLeft = $(containerId).offset().left;
  		var AysItemTop,preTop = 0
  		var imgLocList = [];
  		$.each(_contentList,function(_i,_list){

  			var itemTop,itemLeft


  			if(gDashboard.reportType == 'StaticAnalysis'){
  				itemLeft = ($('#'+_list.itemid).offset().left - conLeft) < 30 ? 0:$('#'+_list.itemid).offset().left - conLeft;
  				if(_i == 0){
                    AysItemTop = 0
                    preTop = $('#'+_list.itemid).height()
  				}else{
  					AysItemTop += parseInt(preTop);
  					preTop = $('#'+_list.itemid).height()
  				}
  				itemTop = AysItemTop
  			}else{
  				itemTop = ($('#'+_list.itemid).offset().top - conTop) < 100 ? 0 : $('#'+_list.itemid).offset().top - conTop ;
  			    itemLeft = ($('#'+_list.itemid).offset().left - conLeft) < 30 ? 0:$('#'+_list.itemid).offset().left - conLeft;
  			}

  			var itemWidth = $('#'+_list.itemid).width();
  			var itemHeight = $('#'+_list.itemid).height();


  			var itemLoc = {
	  			'itemPath': _list.uploadPath,
  				'itemTop' : itemTop.toString().split('.')[0],
  				'itemLeft': itemLeft.toString().split('.')[0],
				'itemWidth': itemWidth.toString().split('.')[0],
				'itemHeight': itemHeight.toString().split('.')[0]
  			}
  			imgLocList.push(itemLoc);
//  			switch(_list.itemtype){
//  				case 'PIVOT_GRID' :
//  					break;
//				case 'DATA_GRID' :
//					break;
//				case 'TEXTBOX':
//					break;
//                case 'SIMPLE_CHART' :
//                	break;
//				case 'TREEMAP' :
//					break;
//				case 'STAR_CHART' :
//					break;
//				case 'PYRAMID_CHART' :
//					break;
//				case 'FUNNEL_CHART' :
//					break;
//				case 'PIE_CHART' :
//					break;
//				case 'CARD_CHART':
//					break;
//				case 'HISTOGRAM_CHART':
//					break;
//				case 'WATERFALL_CHART':
//					break;
//				case 'BIPARTITE_CHART':
//					break;
//				case 'SANKEY_CHART':
//					break;
//				case 'PARALLEL_COORDINATE':
//					break;
//				case 'HEATMAP':
//					break;
//				case 'RECTANGULAR_ARAREA_CHART':
//					break;
//				case 'WORD_CLOUD':
//					break;
//				case 'BUBBLE_D3':
//					break;
//				case 'FORCEDIRECT':
//					break;
//				case 'FORCEDIRECTEXPAND':
//					break;
//				case 'HIERARCHICAL_EDGE':
//					break;
//  			}
  		});
  		return imgLocList;
	}

	this.extractParamItemsStr = function(){
		var param;
		//2020.07.24 MKSONG 다운로드 필터조건 포함  뷰어 오류 수정 DOGFOOT
		if(WISE.Constants.editmode == 'viewer'){
			if(_.keys(gDashboard.viewerParameterBars[gDashboard.structure.ReportMasterInfo.id].state.paramValues).length != 0){
				param = gDashboard.viewerParameterBars[gDashboard.structure.ReportMasterInfo.id].state.paramValues;
			}
		}else{
			//2020.07.22 MKSONG 다운로드 필터조건 포함 DOGFOOT
			if(_.keys(gDashboard.parameterFilterBar.state.paramValues).length != 0){
				param = gDashboard.parameterFilterBar.state.paramValues;
			}
		}


      	var paramItemsJsonArray = [];
      	if(param != undefined){
      		$.each(param,function(_key,_param){
      			paramItemsJsonArray.push({'key':_param.name,'value':_param.value});
      		});
      	}

		return JSON.stringify(paramItemsJsonArray);
		//2020.07.22 MKSONG 다운로드 필터조건 포함 끝 DOGFOOT
	}

	this.downloadCSV = function(_item){
		gProgressbar.show();
		switch (_item.type){
			case 'PIVOT_GRID' :
				_item.dxItem.off('fileSaving').on('fileSaving',function(_e){
					var contentList = [];
					paramItemsStr = self.extractParamItemsStr();
					var formData = new FormData();
					if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
						formData.append("reportName","NewReport");
					}else{
						formData.append("reportName",gDashboard.reportUtility.reportInfo.ReportMasterInfo.name);
					}

					formData.append("exceldata",_e.data);
					// 2020.09.14 mksong 아이템이름 Base64 인코딩 추가 dogfoot
					formData.append("itemName",Base64.encode(_item.Name));
					// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
					formData.append("originItemName","");

					var isRunning = false;
			  		if(!isRunning){
			  			$.ajax({
			                type : 'POST',
			                data : formData,
			                async : false,
			                url : WISE.Constants.context + '/download/saveXLSX.do',
			                contentType: false,
			                processData: false,
			                success : function(_data) {
			                	isRunning = true;
								if(_data.checkValue){
									_data.item = _item.Name;
									// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
									_data.originItemName = "";
									_data.itemtype = _item.type;
									contentList.push(_data);
									self.downloadStart(contentList, paramItemsStr, "csv");
								}
							// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
			              	}
		  				});
			  		}
			  	    _e.cancel = true;
				});
				_item.dxItem.exportToExcel();
				break;
			case 'SIMPLE_CHART' :
			case 'PIE_CHART' :
			case 'TREEMAP' :
			case 'PYRAMID_CHART' :
			case 'FUNNEL_CHART' :
			case 'RANGE_BAR_CHART':
			case 'RANGE_AREA_CHART':
			case 'TIME_LINE_CHART':
				var keyset = _.keys(_item.csvData[0]);
				var fulldata ="";
				$.each(keyset, function(_i,_o){
					if(_i != keyset.length-1){
						fulldata += _o + ",";
					}else{
						fulldata += _o + "\r\n";
					}
				});

				$.each(_item.csvData,function(_i,_o){
					$.each(keyset, function(_index,_key){
						if(_index != keyset.length-1){
							fulldata += _o[_key] + ",";
						}else{
							fulldata += _o[_key] + "\r\n";
						}

					});
				});
				// 2020.01.16 mksong 다운로드 파일명 변경 dogfoot
				self.saveFile('.csv',fulldata,_item.Name);

				break;
			//2020.03.09 MKSONG 데이터그리드 다운로드 수정 DOGFOOT
			case 'DATA_GRID' :
				/* DOGFOOT ktkang 데이터 그리드 페이징 시 다운로드 전체 받아지도록 수정  20201014 */
				if(userJsonObject.gridDataPaging === 'Y'){
					gProgressbar.hide();
					/* DOGFOOT syjin 데이터 그리드 다운로드 문구 변경  20210303 */
					var message = '데이터가 많을 경우 다운로드 하는 동안 장시간 소요될 수 있습니다.\n';
					message += '그래도 계속하시겠습니까?';
					var options = {
						buttons: {
							confirm: {
								id: 'confirm',
								className: 'blue',
								text: '확인',
								action: function() {
									$AlertPopup.hide();
									var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
									var csvDataConfig;
									/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
									if(gDashboard.reportType === "DSViewer"){
										var fields = _item.getAllFields();
										csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(fields.dim, fields.mea, []);
									}else{
										csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(_item.dimensions, _item.measures, []);
									}

									_item.csvData = SQLikeUtil.doSqlLike(_item.dataSourceId, csvDataConfig, _item);

									var columns = _item.dimensions.concat(_item.HiddenMeasures);
									columns = columns.concat(_item.measures);

									var keyset = [];
									if(gDashboard.reportType === "DSViewer"){
										$.each(_item.columns, function(i, col){
											keyset.push(col.caption);
										})
									}else{
										keyset = _.keys(_item.csvData[0]);
									}

									var fulldata = "";
									$.each(keyset, function(_i,_o){
										$.each(columns, function(_k, _column){
											if(_column.type != 'dimension'){
												if(_column.nameBySummaryType == _o){
													_o = _column.caption;
												}
											}
										});
										if(_i != keyset.length-1){
											fulldata += _o + ",";
										}else{
											fulldata += _o + "\r\n";
										}
									});

									$.each(_item.csvData,function(_i,_o){
										$.each(keyset, function(_index,_key){
											if(_index != keyset.length-1){
												fulldata += _o[_key] + ",";
											}else{
												fulldata += _o[_key] + "\r\n";
											}

										});
									});
									// 2020.01.16 mksong 다운로드 파일명 변경 dogfoot
									self.saveFile('.csv',fulldata,_item.Name);
								}
							},
							cancel: {
								id: 'cancel',
								className: 'negative',
								text: '취소',
								action: function() {
									$AlertPopup.hide();
									gProgressbar.hide();
									return false;
								}
							}
						}
					};
					setTimeout(function(){
						WISE.confirm(message, options);
					},1000);
				} else {
					var columns = _item.dimensions.concat(_item.HiddenMeasures);
					columns = columns.concat(_item.measures);

					var keyset = [];
					if(gDashboard.reportType === "DSViewer"){
						$.each(_item.columns, function(i, col){
							keyset.push(col.dataField);
						})
					}else{
						keyset = _.keys(_item.csvData[0]);
					}

					var fulldata = "";
					$.each(keyset, function(_i,_o){
						$.each(columns, function(_k, _column){
							if(_column.type != 'dimension'){
								if(_column.nameBySummaryType == _o){
									_o = _column.caption;
								}
							}
						});
						if(_i != keyset.length-1){
							fulldata += _o + ",";
						}else{
							fulldata += _o + "\r\n";
						}
					});

					$.each(_item.csvData,function(_i,_o){
						$.each(keyset, function(_index,_key){
							if(_index != keyset.length-1){
								fulldata += _o[_key] + ",";
							}else{
								fulldata += _o[_key] + "\r\n";
							}

						});
					});
					// 2020.01.16 mksong 다운로드 파일명 변경 dogfoot
					self.saveFile('.xlsx',fulldata,_item.Name);
					break;
				}
		}
	};
	
	this.downloadXLSX = function(_item, type){
		
		switch (_item.type){
			case 'PIVOT_GRID' :
				gProgressbar.show();
				
				var contentList = [];
				var downloadType = 'xlsx';
				if(type == 'typeXls') {
					downloadType = 'xls';
				}
				
				_item.dwType = downloadType;
				
				/*dogfoot shlim 비정형 개별 다운로드 수정*/
				try {
					
					var buttonPanelId = _item.itemid + '_topicon';
					var topIconPanel = $('#' + buttonPanelId);
					var dsSrc = isNull(_item.dxItem) ? null : _item.dxItem.getDataSource();
					var dsCnt = isNull(dsSrc) ? 0 : dsSrc._data.values.length;
					
					// icon의 갯수가 1이 아니면 다운로드 상태가 아닌것임
					// 조회안하고 다운로드 처리여부
					var topIconLen = topIconPanel.children("[id^='" + buttonPanelId + "_']").length;
					if (topIconLen != 1 || dsCnt > 0){
						gDashboard.itemGenerateManager.isDirectExportBtn = false;
					}
					else {
						gDashboard.itemGenerateManager.isDirectExportBtn = true;
					}
					
					if(gDashboard.itemGenerateManager.isDirectExportBtn){
						_item.isDownLoad = true;
	   		   			$('#btn_query').click();
	   		   			return false;
	   		   		}
					else {
						if (dsCnt > 0) {		// 여긴 조회후 실행되어야 함
							_item.isDownLoad = false;
							
							_item.dxItem.off('fileSaving').on('fileSaving',function(_e){
								var contentList = [];
								paramItemsStr = self.extractParamItemsStr();
								var formData = new FormData();
								if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
									formData.append("reportName","NewReport");
								}else{
									formData.append("reportName",gDashboard.reportUtility.reportInfo.ReportMasterInfo.name);
								}

								formData.append("exceldata",_e.data);
								// 2020.09.14 mksong 아이템이름 Base64 인코딩 추가 dogfoot
								formData.append("itemName",Base64.encode(_item.Name));
								// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
								formData.append("originItemName","");

								var isRunning = false;
						  		if(!isRunning){
						  			$.ajax({
						                type : 'POST',
						                data : formData,
						                async : false,
						                url : WISE.Constants.context + '/download/saveXLSX.do',
						                contentType: false,
						                processData: false,
						                success : function(_data) {
						                	isRunning = true;
						                	if(typeof _data == 'string'){
					                    		_data = JSON.parse(_data);
					                    	}
											if(_data.checkValue){
												_data.item = itemName;
												// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
												_data.originItemName = originItemName;
												_data.itemtype = _o.type;
												_data.memoText = memoText;
												/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
												if(typeof _item.meta.ShowCaption != 'undefined'){
													if(!_item.meta.ShowCaption){
														_data.hidecaption = itemName;
													}
												}
												if(_item.type == 'PIVOT_GRID' && gDashboard.reportType == 'AdHoc') {
													_data.rows = _item.R;
													_data.cols = _item.C;
													_data.delta = _item.deltaItems;
												} else if(_item.type == 'PIVOT_GRID' && gDashboard.reportType == 'DashAny') {
													_data.rows = _item.rows;
													_data.cols = _item.columns;
												}

												// 데이터 그리드일때 셀병합여부와 헤더로우 카운트를 넘기기 위해 처리
												contentList.push(_data);
												self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
											}
										// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
						              	}
					  				});
						  		}
						  	    _e.cancel = true;
							});
							_item.dxItem.exportToExcel();
//								var totalCountOver = false;
//								var downloadType = 'xlsx';
//								if(type == 'typeXls') {
//									downloadType = 'xls';
//								}
//								var paramItemsStr = self.extractParamItemsStr();
//								var originItemName = gDashboard.reportType != 'AdHoc' ? _item.meta.Name : "";
//								var contentList = [];
//								var itemName = _item.Name;
//								var memoText = _item.memoText;
//								
//								itemName = itemName.replace(/_피벗/,"");
//								itemName = itemName.replace(/피벗 /,"");
//								itemName = itemName.replace(/피벗_/,"");
//								itemName = itemName.replace(/\//g,'_');
//								itemName = itemName.replace(/\\/g,'_');
//								
//								var _data = {};
//								_data.uploadPath = downFile.filePath;
//								_data.item = itemName;
//								_data.originItemName = originItemName;
//								_data.itemtype = _item.type;
//								_data.memoText = memoText;
//								if(gDashboard.reportType == 'AdHoc') {
//									_data.rows = _item.R;
//									_data.cols = _item.C;
//								}
//								else if(gDashboard.reportType == 'DashAny') {
//									_data.rows = _item.rows;
//									_data.cols = _item.columns;
//								}
//								/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
//								if(typeof _item.meta.ShowCaption != 'undefined'){
//									if(!_item.meta.ShowCaption){
//										_data.hidecaption = itemName;
//									}
//								}
//											
//								contentList.push(_data);
//								self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
//								var param = {
//									'pid': WISE.Constants.pid,
//									'userId':userJsonObject.userId,
//									'reportType':gDashboard.reportType,
//									'itemid' : '',
//									'itemNm' : ''
//								}
//								$.ajax({
//									type : 'post',
//									data : param,
//									cache : false,
//									url : WISE.Constants.context + '/report/exportLog.do',
//									complete: function() {
//									}
//								});
//							}
						}
					}
				}
				catch(exx) {
					_item.isDownLoad = false;
					WISE.alert(exx.message, 'error');
				}
				break;
			case 'DATA_GRID' :
				gProgressbar.show();
		    	var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
				
				var contentList = [];
				var downloadType = 'xlsx';
				if(type == 'typeXls') {
					downloadType = 'xls';
				}
				var downFile = SQLikeUtil.doSqlLikeExcel(contentList, _item, downloadType);
				if(downFile) {
					if(!Array.isArray(downFile)){
          				$('#downFileName').val(downFile.fileName);
          				$('#downFilePath').val(downFile.filePath);

          				$('#downForm').submit();
      				}else {
      					$('#downFileName').val(downFile[0].fileName);
          				$('#downFilePath').val(downFile[0].uploadPath);

          				$('#downForm').submit();
      				}
      				
				}
				
//				_item.dxItem.off('fileSaving').on('fileSaving',function(_e){
//					/*dogfoot 비정형 피벗 조회 다운로드 기능 추가 shlim 20210728*/
//					gProgressbar.show();
//					var totalCountOver = false;
//					var downloadType = 'xlsx';
//					if(type == 'typeXls') {
//						downloadType = 'xls';
//					}
//					var paramItemsStr = self.extractParamItemsStr();
//					var originItemName = gDashboard.reportType != 'AdHoc' ? _item.meta.Name : "";
//					var contentList = [];
//					var reportName = gDashboard.reportUtility.reportInfo.ReportMasterInfo.name;
//			   		   	reportName = reportName.replace(/\//g,'_');
//			   		   	reportName = reportName.replace(/\\/g,'_');
//					var itemName = _item.Name;
//					var memoText = _item.memoText;
//					
//					var formData = new FormData();
//					if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
//						formData.append("reportName","NewReport");
//					}else{
//						formData.append("reportName",reportName);
//					}
//					/* DOGFOOT ktkang 파일 이름 js에서 encode하고 java에서는 decode 없던 오류 수정  20200727 */
//					itemName = itemName.replace(/_피벗/,"");
//					itemName = itemName.replace(/피벗 /,"");
//					itemName = itemName.replace(/피벗_/,"");
//					formData.append("itemName", Base64.encode(itemName));
//					// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
//					formData.append("originItemName",originItemName);
//					
//					formData.append("exceldata", _e.data);
//
//					var isRunning = false;
//					if(!isRunning){
//						$.ajax({
//							type : 'POST',
//							data : formData,
//							async : false,
//							url : WISE.Constants.context + '/download/saveXLSX.do',
//							contentType: false,
//							processData: false,
//							success : function(_data) {
//								isRunning = true;
//								if(_data.checkValue){
//									_data.item = itemName;
//									// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
//									_data.originItemName = originItemName;
//									_data.itemtype = _item.type;
//									_data.memoText = memoText;
//									if(_item.type == 'PIVOT_GRID' && gDashboard.reportType == 'AdHoc') {
//										_data.rows = _item.R;
//										_data.cols = _item.C;
//									} else if(_item.type == 'PIVOT_GRID' && gDashboard.reportType == 'DashAny') {
//										_data.rows = _item.rows;
//										_data.cols = _item.columns;
//									}
//									/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
//									if(typeof _item.meta.ShowCaption != 'undefined'){
//										if(!_item.meta.ShowCaption){
//											_data.hidecaption = itemName;
//										}
//									}
//									
//									// 데이터 그리드일때 셀병합여부와 헤더로우 카운트를 넘기기 위해 처리
//									if (_data.type == 'DATA_GRID') {
//										_data.isGrdCellMerge = isNull(_item.Grid.GridOptions.AllowGridCellMerge) ? false : _item.Grid.GridOptions.AllowGridCellMerge;
//										_data.hdRowCnt = $('#' + _item.itemid).find('.dx-datagrid-headers').find("tr").length;
//										
//										// rowspan을 갖고 있는지 여부를 판단해 그 값을 저장
//										if (_data.isGrdCellMerge) {
//											_data.mergeRange = [];
//											var _grdBody = $('#' + _item.itemid).find('.dx-datagrid-table').find('.dx-data-row');
//											var bodyRCnt = _grdBody.length;
//											for (var ii=0; ii<bodyRCnt; ii++) {
//												var _tds = _grdBody.eq(ii).find('td');
//												var _tdsLen = _tds.length;
//												for (var k=0; k<_tdsLen; k++) {
//													var _td = _tds.eq(k);
//													// rowspan여부 체크
//													if (!isNull(_td.attr('rowspan'))) {
//														var nRowSpan = parseInt(_td.attr('rowspan'));
//														if (nRowSpan > 1) {
//															_data.mergeRange.push({
//																row: ii,
//																col: k,
//																range: nRowSpan
//															});
//														}
//													}
//												}
//											}
//										}
//									}
//									
//									contentList.push(_data);
//									self.downloadStart(contentList, paramItemsStr, downloadType, totalCountOver);
//								}
//							}
//						});
//					}
//					_e.cancel = true;
//				});
//				
//				_item.dxItem.exportToExcel();
				
				break;
			case 'SIMPLE_CHART' :
				var contentList = [];
			    var paramItemsStr = self.extractParamItemsStr();
			    var reportName = gDashboard.reportUtility.reportInfo.ReportMasterInfo.name;
		   		   	reportName = reportName.replace(/\//g,'_');
		   		   	reportName = reportName.replace(/\\/g,'_');
			    	_item.dxItem.off('fileSaving').on('fileSaving',function(_e){
					 	 		var formData = new FormData();
					   			if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
					   				formData.append("reportName","NewReport");
					   			}else{
					   			/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
					   				formData.append("reportName",reportName);
					   			}
					   			formData.append("imagedata",_e.data);
					   			formData.append("itemName",Base64.encode(_item.Name));
					   			var isRunning = false;
					      		if(!isRunning){
					      			$.ajax({
					                    type : 'POST',
					                    data : formData,
					                    url : WISE.Constants.context + '/download/saveImage.do',
					                    async : false,
					                    contentType: false,
					                    processData: false,
					                    success : function(_data) {
					                    	isRunning = true;
					                    	_item.dxItem.option('size',{'height':'100%'});
					                    	if(typeof _data == "string"){
					                    	    _data = JSON.parse(_data)	
					                    	}
											if(_data.checkValue){
												_data.item = _item.Name;
												_data.itemtype = _item.type;
												/* 2020.12.18 mksong 주택금융공사 텍스트 입력 내용 포함 다운로드 dogfoot */
												//_data.memoText = memoText;
												/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
												if(typeof _item.meta.ShowCaption != 'undefined'){
													if(!_item.meta.ShowCaption){
														_data.hidecaption = _item.Name;
													}
												}
												contentList.push(_data);
												/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
												
													self.downloadStart(contentList, paramItemsStr, 'xlsx', false);
												
											}
											// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
					                  	}
					      			});
					      		}
					      		_e.cancel = true;
							});
						   	_item.dxItem.exportTo('filename,png');
					break;
			case 'PIE_CHART' :
			var contentList = [];
		    var paramItemsStr = self.extractParamItemsStr();
		    var reportName = gDashboard.reportUtility.reportInfo.ReportMasterInfo.name;
	   		   	reportName = reportName.replace(/\//g,'_');
	   		   	reportName = reportName.replace(/\\/g,'_');
				var piePictureList = [];
				var pieCount = 0;
			   	$.each(_item.dxItem,function(_index,_pie){
			   		_pie.off('fileSaving').on('fileSaving',function(_e){
			   			var formData = new FormData();
			   			if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
			   				formData.append("reportName","NewReport");
			   			}else{
			   				/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
			   				formData.append("reportName",reportName);
			   			}
			   			formData.append("imagedata",_e.data);
			   			formData.append("itemName",Base64.encode(_item.Name));
			   			var isRunning = false;
			   			if(!isRunning){
			   				$.ajax({
			   					type : 'POST',
			   					data : formData,
			   					async : false,
			   					url : WISE.Constants.context + '/download/saveImage.do',
			   					contentType: false,
			   					processData: false,
			   					success : function(_data) {
			   						pieCount++;
			   						isRunning = true;
			   						if(typeof _data == "string"){
			   					    	_data = JSON.parse(_data);
			   					    } 
			   						if(_data.checkValue){
			   							piePictureList.push(_data.uploadPath);
			   						}
			   						_item.dxItem[_index].option('size',{'height': '100%'});
			   						if(_item.dxItem.length == pieCount){
			   							if(pieCount == 1){
			   								if(_data.checkValue){
			   									_data.item = _item.Name;
			   									_data.itemtype = _item.type;
			   									_data.itemid = _item.itemid;
			   									/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
			   									if(typeof _item.meta.ShowCaption != 'undefined'){
			   										if(!_item.meta.ShowCaption){
			   											_data.hidecaption = _item.Name;
			   										}
			   									}
			   									contentList.push(_data);
			   									self.downloadStart(contentList, paramItemsStr, "xlsx", false);
			   								}
			   							}else{
			   								isRunning = false;
			   								$.ajaxSettings.traditional = true;
			   								$.ajax({
			   									type : 'POST',
			   									data : {
			   										'pictureList' : piePictureList
			   									},
			   									async : false,
			   									url : WISE.Constants.context + '/download/mergeImage.do',
			   									success : function(_data) {
			   										isRunning = true;
			   										if(typeof _data == 'string'){
							                    		_data = JSON.parse(_data);
							                    	}
			   										if(_data.checkValue){
			   											_data.item = _item.Name;
			   											_data.itemtype = _item.type;
			   											_data.itemid = _item.itemid;
			   											/*dogfoot 캡션숨긴 아이템 리스트업 shlim 20200625*/
			   											if(typeof _item.meta.ShowCaption != 'undefined'){
			   												if(!_item.meta.ShowCaption){
			   													_data.hidecaption = _item.Name;
			   												}
			   											}
			   											contentList.push(_data);
			   											self.downloadStart(contentList, paramItemsStr, "xlsx", false);
			   										}
			   									}
			   								});
			   							}
			   						}
			   						// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
			   					}
			   				});
			   			}
			   			_e.cancel = true;
			   		});
			   	_pie.exportTo('filename,png');
	   		});
				break;
			//2020.03.09 MKSONG 데이터그리드 다운로드 수정 DOGFOOT
			/*case 'DATA_GRID' :
				if(userJsonObject.gridDataPaging === 'Y'){
					gProgressbar.hide();
					var message = '데이터가 많을 경우 다운로드 하는 동안 장시간 소요될 수 있습니다.\n';
					message += '그래도 계속하시겠습니까?';
					var options = {
						buttons: {
							confirm: {
								id: 'confirm',
								className: 'blue',
								text: '확인',
								action: function() {
									$AlertPopup.hide();
									var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
									var csvDataConfig;
									if(gDashboard.reportType === "DSViewer"){
										var fields = _item.getAllFields();
										csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(fields.dim, fields.mea, []);
									}else{
										csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(_item.dimensions, _item.measures, []);
									}

									_item.csvData = SQLikeUtil.doSqlLike(_item.dataSourceId, csvDataConfig, _item);

									var columns = _item.dimensions.concat(_item.HiddenMeasures);
									columns = columns.concat(_item.measures);

									var keyset = [];
									if(gDashboard.reportType === "DSViewer"){
										$.each(_item.columns, function(i, col){
											keyset.push(col.caption);
										})
									}else{
										keyset = _.keys(_item.csvData[0]);
									}

									var fulldata = "";
									$.each(keyset, function(_i,_o){
										$.each(columns, function(_k, _column){
											if(_column.type != 'dimension'){
												if(_column.nameBySummaryType == _o){
													_o = _column.caption;
												}
											}
										});
										if(_i != keyset.length-1){
											fulldata += _o + ",";
										}else{
											fulldata += _o + "\r\n";
										}
									});

									$.each(_item.csvData,function(_i,_o){
										$.each(keyset, function(_index,_key){
											if(_index != keyset.length-1){
												fulldata += _o[_key] + ",";
											}else{
												fulldata += _o[_key] + "\r\n";
											}

										});
									});
									// 2020.01.16 mksong 다운로드 파일명 변경 dogfoot
									self.saveFile('.xlsx',fulldata,_item.Name);
								}
							},
							cancel: {
								id: 'cancel',
								className: 'negative',
								text: '취소',
								action: function() {
									$AlertPopup.hide();
									gProgressbar.hide();
									return false;
								}
							}
						}
					};
					setTimeout(function(){
						WISE.confirm(message, options);
					},1000);
				} else {
					var columns = _item.dimensions.concat(_item.HiddenMeasures);
					columns = columns.concat(_item.measures);

					var keyset = [];
					if(gDashboard.reportType === "DSViewer"){
						$.each(_item.columns, function(i, col){
							keyset.push(col.dataField);
						})
					}else{
						keyset = _.keys(_item.csvData[0]);
					}

					var fulldata = "";
					$.each(keyset, function(_i,_o){
						$.each(columns, function(_k, _column){
							if(_column.type != 'dimension'){
								if(_column.nameBySummaryType == _o){
									_o = _column.caption;
								}
							}
						});
						if(_i != keyset.length-1){
							fulldata += _o + ",";
						}else{
							fulldata += _o + "\r\n";
						}
					});

					$.each(_item.csvData,function(_i,_o){
						$.each(keyset, function(_index,_key){
							if(_index != keyset.length-1){
								fulldata += _o[_key] + ",";
							}else{
								fulldata += _o[_key] + "\r\n";
							}

						});
					});
					// 2020.01.16 mksong 다운로드 파일명 변경 dogfoot
					self.saveFile('.xlsx',fulldata,_item.Name);
					break;
				}*/
		}
	};
	
	this.downloadTXT = function(_item){
		gProgressbar.show();
		switch (_item.type){
			case 'PIVOT_GRID' :
				_item.dxItem.off('fileSaving').on('fileSaving',function(_e){
					var contentList = [];
					var paramItemsStr = self.extractParamItemsStr();
					var formData = new FormData();
					if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
						formData.append("reportName","NewReport");
					}else{
						formData.append("reportName",gDashboard.reportUtility.reportInfo.ReportMasterInfo.name);
					}

					formData.append("exceldata",_e.data);
					// 2020.09.14 mksong 아이템이름 Base64 인코딩 추가 dogfoot
					formData.append("itemName",Base64.encode(_item.Name));
					// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
					formData.append("originItemName","");

					var isRunning = false;
			  		if(!isRunning){
			  			$.ajax({
			                type : 'POST',
			                data : formData,
			                async : false,
			                url : WISE.Constants.context + '/download/saveXLSX.do',
			                contentType: false,
			                processData: false,
			                success : function(_data) {
			                	isRunning = true;
								if(_data.checkValue){
									_data.item = _item.Name;
									// 2020.01.07 mksong 다운로드 아이템 이름 추가 dogfoot
									_data.originItemName = "";
									_data.itemtype = _item.type;
									contentList.push(_data);
									self.downloadStart(contentList, paramItemsStr, "txt");
								}
							// 2019.12.10 수정자 : mksong 프로그레스바 오류 수정 DOGFOOT
			              	}
		  				});
			  		}
			  	    _e.cancel = true;
				});
				_item.dxItem.exportToExcel();
				break;
			case 'SIMPLE_CHART' :
			case 'PIE_CHART' :
			case 'TREEMAP' :
			case 'PYRAMID_CHART' :
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
			case 'KAKAO_MAP' :
			case 'KAKAO_MAP2' :
			case 'FUNNEL_CHART' :
			case 'RANGE_BAR_CHART':
			case 'RANGE_AREA_CHART':
			case 'TIME_LINE_CHART':
				var keyset = _.keys(_item.csvData[0]);
				var fulldata ="";
				$.each(keyset, function(_i,_o){
					if(_i != keyset.length-1){
						fulldata += _o + "\t";
					}else{
						fulldata += _o + "\r\n";
					}
				});

				$.each(_item.csvData,function(_i,_o){
					$.each(keyset, function(_index,_key){
						if(_index != keyset.length-1){
							fulldata += _o[_key] + "\t";
						}else{
							fulldata += _o[_key] + "\r\n";
						}
					});
				});
				// 2020.01.16 mksong 다운로드 파일명 변경 dogfoot
				self.saveFile('.txt',fulldata,_item.Name);
		   		break;
		   	//2020.03.09 MKSONG 데이터그리드 다운로드 수정 DOGFOOT
			case 'DATA_GRID' :
				/* DOGFOOT ktkang 데이터 그리드 페이징 시 다운로드 전체 받아지도록 수정  20201014 */
				if(userJsonObject.gridDataPaging === 'Y'){
					gProgressbar.hide();
					var message = '데이터가 많을 경우 다운로드 하는 동안 장시간 소요될 수 있습니다.\n';
					message += '그래도 계속하시겠습니까?';
					var options = {
						buttons: {
							confirm: {
								id: 'confirm',
								className: 'blue',
								text: '확인',
								action: function() {
									$AlertPopup.hide();
									var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
									var csvDataConfig;
									/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
									if(gDashboard.reportType === "DSViewer"){
										var fields = _item.getAllFields();
										csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(fields.dim, fields.mea, []);
									}else{
										csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(_item.dimensions, _item.measures, []);
									}

									_item.csvData = SQLikeUtil.doSqlLike(_item.dataSourceId, csvDataConfig, _item);

									var columns = _item.dimensions.concat(_item.HiddenMeasures);
									columns = columns.concat(_item.measures);

									var keyset = [];
									if(gDashboard.reportType === "DSViewer"){
										$.each(_item.columns, function(i, col){
											keyset.push(col.caption);
										})
									}else{
										keyset = _.keys(_item.csvData[0]);
									}
									var fulldata ="";
									$.each(keyset, function(_i,_o){
										$.each(columns, function(_k, _column){
											if(_column.type != 'dimension'){
												if(_column.nameBySummaryType == _o){
													_o = _column.caption;
												}
											}
										});

										if(_i != keyset.length-1){
											fulldata += _o + "\t";
										}else{
											fulldata += _o + "\r\n";
										}
									});

									$.each(_item.csvData,function(_i,_o){
										$.each(keyset, function(_index,_key){
											if(_index != keyset.length-1){
												fulldata += _o[_key] + "\t";
											}else{
												fulldata += _o[_key] + "\r\n";
											}
										});
									});
									// 2020.01.16 mksong 다운로드 파일명 변경 dogfoot
									self.saveFile('.txt',fulldata,_item.Name);
								}
							},
							cancel: {
								id: 'cancel',
								className: 'negative',
								text: '취소',
								action: function() {
									$AlertPopup.hide();
									gProgressbar.hide();
									return false;
								}
							}
						}
					};
					setTimeout(function(){
						WISE.confirm(message, options);
					},1000);
				} else {
					var columns = _item.dimensions.concat(_item.HiddenMeasures);
					columns = columns.concat(_item.measures);

					var keyset = [];
					if(gDashboard.reportType === "DSViewer"){
						$.each(_item.columns, function(i, col){
							keyset.push(col.dataField);
						})
					}else{
						keyset = _.keys(_item.csvData[0]);
					}
					var fulldata ="";
					$.each(keyset, function(_i,_o){
						$.each(columns, function(_k, _column){
							if(_column.type != 'dimension'){
								if(_column.nameBySummaryType == _o){
									_o = _column.caption;
								}
							}
						});

						if(_i != keyset.length-1){
							fulldata += _o + "\t";
						}else{
							fulldata += _o + "\r\n";
						}
					});

					$.each(_item.csvData,function(_i,_o){
						$.each(keyset, function(_index,_key){
							if(_index != keyset.length-1){
								fulldata += _o[_key] + "\t";
							}else{
								fulldata += _o[_key] + "\r\n";
							}
						});
					});
					// 2020.01.16 mksong 다운로드 파일명 변경 dogfoot
					self.saveFile('.txt',fulldata,_item.Name);
					break;
					break;
				}
		}
	}

	this.saveFile = function(extension,row,itemName){
		//2020.11.03 mksong resource Import 동적 구현 dogfoot

		var blob = new Blob([row], {type: "text/plain;charset=utf-8"});
  		var reportName = "newReport";
  		if(gDashboard.structure.ReportMasterInfo != undefined){
  		/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
  			reportName = gDashboard.structure.ReportMasterInfo.name == "" ? 'newReport' : gDashboard.structure.ReportMasterInfo.name.replace( /\s/gi,"_");
		   	reportName = reportName.replace(/\//g,'_');
		   	reportName = reportName.replace(/\\/g,'_');
  		}

  		saveAs(blob, reportName+"_"+ itemName + extension);
  		gProgressbar.hide();
	}

	this.saveImgFunc = function(imgData){
		//2020.11.03 mksong resource Import 동적 구현 dogfoot

		var blob = new Blob([imgData],{type: "image/png;charset=utf-8"});
  		var reportName = "newReport";
  		if(gDashboard.structure.ReportMasterInfo != undefined){
  		/* DOGFOOT ktkang 다운로드 시 파일 이름 에러 수정  20200618 */
  			reportName = gDashboard.structure.ReportMasterInfo.name == "" ? 'newReport' : gDashboard.structure.ReportMasterInfo.name.replace( /\s/gi,"_");
		   	reportName = reportName.replace(/\//g,'_');
		   	reportName = reportName.replace(/\\/g,'_');
  		}

		/* DOGFOOT ktkang 확장자 없이 다운로드 되는 오류 수정 20191220 */
  		saveAs(blob, reportName + '.png');
  		gProgressbar.hide();
	}

	this.countGridCell = function(){
		var count = 0;
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i,_item){
			if(_item.type == 'PIVOT_GRID'){
				var dataRow = 0;
				if(_item.filteredData){
					dataRow = _item.filteredData.length;
				}
				count += dataRow * _item.rows.length * _item.columns.length;
			}else if(_item.type == 'DATA_GRID'){
				var dataRow = 0;
				if(_item.filteredData){
					dataRow = _item.filteredData.length;
				}
				count += dataRow * _item.columns.length;
			}
		});

		return count;
	}
	// 2020.02.21 mksong 건수 확인 추가 dogfoot
	this.countData = function(){
		var count = 0;
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i,_item){
			if(_item.filteredData != undefined){
				count += _item.filteredData.length;
			}
		});

		return count;
	}
};

