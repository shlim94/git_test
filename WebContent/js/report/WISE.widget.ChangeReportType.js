WISE.libs.Dashboard.item.ChangeReportTypeManager = function() {
	var self = this;
	
	this.init = function(){
		$('.changeReport').on('click',function(e){
			e.preventDefault();
			var checkOpinion;
			
			switch(gDashboard.reportType){
				case 'DashAny':
					if($(this).attr('id') == 'insertInformal'){
						checkOpinion = confirm('비정형 아이템을 추가할 경우 현재 저장되지 않은 작업중인 내용은 소멸 됩니다. 그래도 계속하시겠습니까?');	
					}
					break;
				case 'AdHoc':
					if($(this).attr('id') == 'insertInformal'){
						break;
					}
					checkOpinion = confirm('현재 저장되지 않은 작업중인 내용은 소멸 됩니다. 그래도 계속하시겠습니까?');
					if(!checkOpinion){
						$('#'+gDashboard.itemGenerateManager.dxItemBasten[gDashboard.itemGenerateManager.dxItemBasten.length-1].itemid +'_topicon').find('.lm_close').click();
					}
					break;
				/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
				case 'StaticAnalysis':
					gDashboard.analysisType = $(this).attr('id');
					break;
				default:
					checkOpinion = confirm('현재 저장되지 않은 작업중인 내용은 소멸 됩니다. 그래도 계속하시겠습니까?');
					break;
			}
			
			if(checkOpinion){
				gDashboard.changeReportTypeManager.changeReportType();
			}
		});
		
		/* DOGFOOT ktkang 비정형 불러오기 하고나서 레이아웃 변경 안되는 오류 수정  20200207 */
		$('.changeLayout').on('click',function(e){
			var eventElementId = e.target.id == '' ? e.currentTarget.id : e.target.id;
			
			/*dogfoot 비정형 그리드만 보기에서 차트 변경시 차트 그리기 shlim 20210223*/
			var renderBoolean = false;
            if(gDashboard.structure.Layout == "G"){
				renderBoolean = true;
			}

            switch(eventElementId){
			case 'changeLayoutC':
			case 'changeLayoutCG':
			    if(typeof gDashboard.itemGenerateManager.dxItemBasten[1].filteredData != 'undefined'){
					if(gDashboard.itemGenerateManager.dxItemBasten[1].filteredData.length > 100) {
						var message = '데이터가 많을 경우 차트를 그리는동안 장시간 소요될 수 있습니다.\n';
						message += '그래도 계속하시겠습니까?';
						var options = {
								buttons: {
									confirm: {
										id: 'confirm',
										className: 'blue',
										text: '확인',
										action: function() {
											gProgressbar.hide();
											$AlertPopup.hide();
											switch(eventElementId){
											case 'changeLayoutC':
												self.activeAdhocLayout('C');
												break;
											case 'changeLayoutCG':
												self.activeAdhocLayout('CG');
												break;
											}
											
											/*dogfoot 비정형 그리드만 보기에서 차트 변경시 차트 그리기 shlim 20210223*/
											if(renderBoolean){
												gDashboard.queryByGeneratingSql = true;
												gDashboard.itemGenerateManager.clearTrackingConditionAll();
												gDashboard.itemGenerateManager.clearItemData();
												gDashboard.query();
												
												$('#singleView_layout').css('display','none');
											}
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
						},100);
					} else {
						switch(eventElementId){
						case 'changeLayoutC':
							self.activeAdhocLayout('C');
							break;
						case 'changeLayoutCG':
							self.activeAdhocLayout('CG');
							break;
						}
						
						/*dogfoot 비정형 그리드만 보기에서 차트 변경시 차트 그리기 shlim 20210223*/
						if(renderBoolean){
							gDashboard.queryByGeneratingSql = true;
							gDashboard.itemGenerateManager.clearTrackingConditionAll();
							gDashboard.itemGenerateManager.clearItemData();
							gDashboard.query();
							
							$('#singleView_layout').css('display','none');
						}
					}
			    }
				break;
			case 'changeLayoutG':
					if(!renderBoolean){
						self.activeAdhocLayout('G');
						gDashboard.queryByGeneratingSql = true;
						gDashboard.itemGenerateManager.clearTrackingConditionAll();
						gDashboard.itemGenerateManager.clearItemData();
						gDashboard.query();
						
						$('#singleView_layout').css('display','none');
					}
				break;
			case 'recoveryLayout':
				var layout = userJsonObject.defaultLayout;
				if(layout && (layout === 'C' || layout === 'G' || layout === 'CG'))
					self.activeAdhocLayout(userJsonObject.defaultLayout);
				else
					self.activeAdhocLayout('CG');
				break;
            }
            
		});
		
//		$('#insertInformal').on('click',function(e){
//			e.preventDefault();
//			var checkOpinion;
//			
//			switch(gDashboard.reportType){
//				case 'DashAny':
//					checkOpinion = confirm('비정형 아이템을 추가할 경우 현재 저장되지 않은 작업중인 내용은 소멸 됩니다. 그래도 계속하시겠습니까?');
//					break;
//				case 'AdHoc':
//					checkOpinion = confirm('현재 저장되지 않은 작업중인 내용은 소멸 됩니다. 그래도 계속하시겠습니까?');
//					break;
//				default:
//					checkOpinion = confirm('현재 저장되지 않은 작업중인 내용은 소멸 됩니다. 그래도 계속하시겠습니까?');
//					break;
//			}
//			
//			if(checkOpinion){
//				gDashboard.changeReportTypeManager.changeReportType();
//			}
//		});
	};
	
	this.changeReportType = function(){
		//2020.02.04 mksong itemQuantity 내용 추가 dogfoot
		gDashboard.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'parallel':0
				, 'choroplethMap':0,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0, 'comboBox':0, 'image':0, 'textBox':0
				, 'RectangularAreaChart':0, 'waterfallchart':0,'bubbled3':0, 'histogramchart':0, 'gauge': 0, 'card':0, 'bubble':0
				, 'adhocItem':0, 'hierarchical': 0, 'funnelchart':0, 'pyramidchart':0, 'bipartitechart':0,'sankeychart':0, 'radialtidytree' : 0, 'scatterplotmatrix' : 0, 'historytimeline' : 0
				, 'rangebarchart':0,'rangeareachart':0,'timelinechart':0,'bubblepackchart':0, 'wordcloudv2':0, 'dendrogrambarchart':0, 'arcdiagram': 0
				, 'calendarviewchart':0, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0, 'boxplot': 0, 'coordinateline': 0, 'scatterplot': 0 , 'scatterplot2': 0
				, 'liquidfillgauge': 0, 'kakaoMap':0, 'kakaoMap2':0, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0
				, 'onewayAnova':0, 'twowayAnova':0, 'onewayAnova2':0, 'pearsonsCorrelation':0, 'spearmansCorrelation':0
				, 'simpleRegression':0, 'multipleRegression':0, 'logisticRegression':0, 'multipleLogisticRegression':0
				, 'tTest':0, 'zTest':0, 'chiTest':0, 'fTest':0, 'multivariate':0};
		WISE.Constants.pid = "";
		gDashboard.isNewReport = true;
		
		// 2019.12.10 수정자 : mksong 리포트 타입 변경 오류 수정 DOGFOOT
		gDashboard.insertItemManager.clearCanvasLayout();
		
		$('.content').children().remove();
		// 수정 끝
		gDashboard.itemGenerateManager.dxItemBasten = [];
		gDashboard.dataSourceManager.datasetInformation = {};
		gDashboard.dataSetCreate.lookUpItems = [];
		gDashboard.dataSetCreate.infoTreeList = [];
		gDashboard.dataSourceQuantity = 0;
		
		switch(gDashboard.reportType){
			case 'DashAny':
				gDashboard.reportType = 'AdHoc';
				$('.activeChangeLayout').css('display','block');
				/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
				$('.design').css('display','block');
				compMoreMenuUi();
				break;
			case 'AdHoc':
				$('.activeChangeLayout').css('display','none');
				/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
				$('.design').css('display','none');
				gDashboard.reportType = 'DashAny';
				break;
		}
		
		gDashboard.init();
	};

	/* DOGFOOT ktkang 비정형 레이아웃 오류 수정  20200130 */
	this.activeAdhocLayout = function(layoutChar){
		var height = $('.lm_goldenlayout').height();
		var width = $('.lm_goldenlayout').width();

		//2020.01.21 mksong 비정형 레이아웃 수정 dogfoot
		var chartItem,chartInstance;
		var pivotItem,pivotInstance;
		var isPaging = false;
		
		$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
			if(_item.type == 'PIVOT_GRID'){
				pivotItem = $('#'+_item.ComponentName);
				pivotInstance = _item
			}else{
				chartItem = $('#'+_item.ComponentName);
				chartInstance = _item
			}
		});

		switch(layoutChar){
		case 'C':
			gDashboard.structure.Layout = 'C';
			pivotItem.css('display','none');
			chartItem.css('display','block');
			chartItem.width('100%');
			chartItem.height('100%');
			chartItem.find('.lm_items').width('100%');
			chartItem.find('.lm_items').height(height-40+'px');
			chartItem.find('.lm_item_container').width('100%');
			chartItem.find('.lm_item_container').height(height-40+'px');
			// mksong 2019.12.20 비정형 레이아웃 수정 dogfoot
			chartItem.find('.lm_content').height(height-40+'px');
			chartItem.find('.lm_content').width('100%');
			$('.lm_splitter').css('display','none');
			break;
		case 'G':
			gDashboard.structure.Layout = 'G';
			chartItem.css('display','none');
			pivotItem.css('display','block');
			pivotItem.width('100%');
			pivotItem.height('100%');
			pivotItem.find('.lm_items').width('100%');
			pivotItem.find('.lm_items').height(height-40+'px');
			pivotItem.find('.lm_item_container').width('100%');
			pivotItem.find('.lm_item_container').height(height-40+'px');
			// mksong 2019.12.20 비정형 레이아웃 수정 dogfoot
			pivotItem.find('.lm_content').height(height-40+'px');
			pivotItem.find('.lm_content').width('100%');
			$('.lm_splitter').css('display','none');
			break;
		case 'CG':
			if(gDashboard.structure.Layout != 'GTCB'){
				gDashboard.structure.Layout = 'GTCB';
				chartItem.css('display','block');
				pivotItem.css('display','block');

				$('.lm_splitter').css('display','block');
				if($('.lm_splitter').hasClass('lm_vertical')){
					var itemHeight = (height-48)/2;

					$('.cont_box').width(width+'px');
					$('.cont_box').height(itemHeight+'px');
					$('.cont_box').find('.lm_items').width(width+'px');
					$('.cont_box').find('.lm_items').height(itemHeight-40+'px');
					$('.cont_box').find('.lm_item_container').width(width+'px');
					$('.cont_box').find('.lm_item_container').height(itemHeight-40+'px');
					$('.cont_box').find('.lm_content').height('100%');
					//dogfoot 뷰어에서 차트와 그리드 동시에 보기 시 차트 짤리는 오류 수정 syjin 20210712
					chartItem.find('.lm_content').height('100%');
				}else if($('.lm_splitter').hasClass('lm_horizontal')){
					var itemWidth = (width-45)/2;

					$($('.cont_box').get(0)).width(itemWidth+0.5+'px');
					$($('.cont_box').get(1)).width(itemWidth-0.5+'px');
					$('.cont_box').height(height+'px');
					$($('.cont_box').get(0)).find('.lm_items').width(itemWidth+0.5+'px');
					$($('.cont_box').get(1)).find('.lm_items').width(itemWidth-0.5+'px');
					$('.cont_box').find('.lm_items').height(height-40+'px');
					$($('.cont_box').get(0)).find('.lm_item_container').width(itemWidth+0.5+'px');
					$($('.cont_box').get(1)).find('.lm_item_container').width(itemWidth-0.5+'px');
					$('.cont_box').find('.lm_item_container').height(height-40+'px');
				}

			}
			break;
		}

		if(gDashboard.itemGenerateManager.dxItemBasten.length != 0){
			var itemList = gDashboard.itemGenerateManager.dxItemBasten;
			for (var i = 0; i < itemList.length; i++) {
				if (itemList[i].dxItem != undefined) {
					switch (itemList[i].type) {
					case 'PIVOT_GRID':
						if(gDashboard.reportType != 'AdHoc' || gDashboard.structure.Layout != 'C'){
							itemList[i].dxItem.option('width',$('#' + itemList[i].itemid).parent().width());
							// mksong 2019.12.20 비정형 레이아웃 수정 dogfoot
							itemList[i].dxItem.option('height',$('#' + itemList[i].itemid).parent().height());
						}
						break;
					case 'SIMPLE_CHART':
						if(gDashboard.reportType != 'AdHoc' || gDashboard.structure.Layout != 'G'){
							itemList[i].dxItem.option('width',$('#' + itemList[i].itemid).parent().width());
							itemList[i].dxItem.option('height',$('#' + itemList[i].itemid).parent().height()-50);
						}
						break;
					}
				}
			}
			
			if (gDashboard.structure.Layout != 'G' && itemList[0] != undefined) {
				if($window != null){
					$window.resize();
				}
			}
		}
		//2020.01.21 mksong 비정형 레이아웃 수정 끝 dogfoot
		/* DOGFOOT ktkang 비정형 레이아웃 오류 수정 끝  20200130 */
	};
	
	this.activeViewerAdhocLayout = function(){
		$('.changeLayout').on('click',function(e){
			var eventElementId = e.target.id == '' ? e.currentTarget.id : e.target.id;
			var height = $('.AdhoccontentContainer').height();
			var width = $('.AdhoccontentContainer').width();
			
			var chartItem;
			var pivotItem;
			
			$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i,_item){
				if(_item.type == 'SIMPLE_CHART'){
					chartItem = _item;
				}else if(_item.type == 'PIVOT_GRID'){
					pivotItem = _item;
				}
			});
			
			switch(eventElementId){
				case 'changeLayoutC':
					gDashboard.structure.Layout = 'C';
					$('#'+pivotItem.ComponentName).css('display','none');
					$('#'+chartItem.ComponentName).css('display','block');
					$('#'+chartItem.ComponentName).css('margin-top','0px');
					$('#'+chartItem.ComponentName).width('100%');
					$('#'+chartItem.ComponentName).height('97%');
					$('#'+chartItem.ComponentName).removeClass('content-left').removeClass('content-right').addClass('content-full');
					break;
				case 'changeLayoutG':
					gDashboard.structure.Layout = 'G';
					$('#'+chartItem.ComponentName).css('display','none');
					$('#'+pivotItem.ComponentName).css('display','block');
					$('#'+pivotItem.ComponentName).width('100%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot
					$('#'+pivotItem.ComponentName).height('97%');
					$('#'+pivotItem.ComponentName).removeClass('content-left').removeClass('content-right').addClass('content-full');
					break;
				case 'changeLayoutCLGR':
					gDashboard.structure.Layout = 'CLGR';
					$('#'+chartItem.ComponentName).insertBefore($('#'+pivotItem.ComponentName));
					$('#'+chartItem.ComponentName).css('display','block');
					$('#'+pivotItem.ComponentName).css('display','block');
					$('#'+chartItem.ComponentName).css('margin-top','0px');
					$('#'+chartItem.ComponentName).width('50%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot					
					$('#'+chartItem.ComponentName).height('97%');
					$('#'+pivotItem.ComponentName).width('50%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot					
					$('#'+pivotItem.ComponentName).height('97%');
					$('#'+chartItem.ComponentName).addClass('content-left').removeClass('content-top').removeClass('content-bottom').removeClass('content-right').removeClass('content-full');
					$('#'+pivotItem.ComponentName).removeClass('content-left').removeClass('content-top').removeClass('content-bottom').addClass('content-right').removeClass('content-full');
					break;
				case 'changeLayoutCRGL':
					gDashboard.structure.Layout = 'CRGL';
					$('#'+chartItem.ComponentName).insertAfter($('#'+pivotItem.ComponentName));
					$('#'+chartItem.ComponentName).css('display','block');
					$('#'+pivotItem.ComponentName).css('display','block');
					$('#'+chartItem.ComponentName).css('margin-top','0px');
					$('#'+chartItem.ComponentName).width('50%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot					
					$('#'+chartItem.ComponentName).height('97%');
					$('#'+pivotItem.ComponentName).width('50%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot					
					$('#'+pivotItem.ComponentName).height('97%');
					$('#'+chartItem.ComponentName).removeClass('content-left').addClass('content-right').removeClass('content-top').removeClass('content-bottom').removeClass('content-full');
					$('#'+pivotItem.ComponentName).addClass('content-left').removeClass('content-right').removeClass('content-top').removeClass('content-bottom').removeClass('content-full');
					break;
				case 'changeLayoutCTGB':
					gDashboard.structure.Layout = 'CTGB';
					$('#'+chartItem.ComponentName).insertBefore($('#'+pivotItem.ComponentName));
					$('#'+chartItem.ComponentName).css('margin-top','0px');
					$('#'+chartItem.ComponentName).css('display','block');
					$('#'+pivotItem.ComponentName).css('display','block');
					$('#'+chartItem.ComponentName).width('100%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot					
					$('#'+chartItem.ComponentName).height('48.5%');
					$('#'+pivotItem.ComponentName).width('100%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot					
					$('#'+pivotItem.ComponentName).height('48.5%');
					$('#'+chartItem.ComponentName).addClass('content-top').removeClass('content-bottom').removeClass('content-left').removeClass('content-right').removeClass('content-full');
					$('#'+pivotItem.ComponentName).removeClass('content-top').addClass('content-bottom').removeClass('content-left').removeClass('content-right').removeClass('content-full');
					break;
				case 'changeLayoutCBGT':
					gDashboard.structure.Layout = 'CBGT';
					$('#'+chartItem.ComponentName).insertAfter($('#'+pivotItem.ComponentName));
					$('#'+chartItem.ComponentName).css('display','block');
					$('#'+chartItem.ComponentName).css('margin-top','30px');
					$('#'+pivotItem.ComponentName).css('display','block');
					$('#'+chartItem.ComponentName).width('100%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot					
					$('#'+chartItem.ComponentName).height('40%');
					$('#'+pivotItem.ComponentName).width('100%');
					// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot					
					$('#'+pivotItem.ComponentName).height('48.5%');
					$('#'+chartItem.ComponentName).removeClass('content-top').addClass('content-bottom').removeClass('content-left').removeClass('content-right').removeClass('content-full');
					$('#'+pivotItem.ComponentName).addClass('content-top').removeClass('content-bottom').removeClass('content-left').removeClass('content-right').removeClass('content-full');
					break;
			}
			
        	if(gDashboard.reportType != 'AdHoc' || gDashboard.structure.Layout != 'C'){
        		pivotItem.dxItem.option('width',$('#' + pivotItem.itemid).parent().width());
        		pivotItem.dxItem.option('height',$('#' + pivotItem.itemid).parent().height());	
        	}
        	if(gDashboard.reportType != 'AdHoc' || !(gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer')){
        		chartItem.dxItem.render();	
        	}
		});
	};
	
	this.initAdhocLayout = function() {
		$("[id$='contextMenu']").remove();
		
		/* DOGFOOT ktkang 비정형 기본 레이아웃 설정  20200120 */
		if(typeof userJsonObject.defaultLayout != 'undefined' && userJsonObject.defaultLayout) {
			gDashboard.structure.Layout = userJsonObject.defaultLayout;
		} else {
			gDashboard.structure.Layout = 'CTGB';
		}
		
//				$('.insertItemList').css('display','none');
//				$('#insertInformal').css('display','none');
		var fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
		//chart 넣기
		//2020.11.06 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('itemJS','Chart');
		var item = new WISE.libs.Dashboard.item.ChartGenerator();
		item.kind = 'chart';
		gDashboard.itemQuantity[item.kind]++;
		item.Name = '차트 ';
		item.ComponentName = 'chartDashboardItem' + gDashboard.itemQuantity[item.kind];
		item.isAdhocItem = true;
		/*dogfoot 비정형 주제영역보고서 열었을때 데이터 항목 index 오류 수정 shlim 20200715*/
		item.adhocIndex = 1;
		
		gDashboard.fieldManager = item.fieldManager = fieldManager;
		item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
		item.fieldManager.seriesType = 'Bar';
		item.itemid = item.ComponentName + '_item';
		
		//피벗 생성
		//2020.11.06 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('itemJS','PivotGrid');
		var item2 = new WISE.libs.Dashboard.item.PivotGridGenerator();
		item2.kind = 'pivotGrid';
		gDashboard.itemQuantity[item2.kind]++;
		item2.Name = '피벗';
		item2.ComponentName = 'pivotDashboardItem' + gDashboard.itemQuantity[item2.kind];
		item2.isAdhocItem = true;

		gDashboard.fieldManager = item2.fieldManager = fieldManager; 
		item2.fieldManager.index = item2.index = gDashboard.itemQuantity[item2.kind];
		
		item.fieldManager.focusItemType = 'adhocItem';
		item2.fieldManager.focusItemType = 'adhocItem';
		
		gDashboard.itemQuantity[fieldManager.focusItemType]++;
		item.adhocIndex = gDashboard.itemQuantity[gDashboard.fieldManager.focusItemType];
		item2.adhocIndex = gDashboard.itemQuantity[gDashboard.fieldManager.focusItemType];
		
		gDashboard.fieldChooser.setAnalysisFieldArea(item2, true);
		item2.itemid = item2.ComponentName + '_item';
		
		// initialize chart and pivot
		gDashboard.itemGenerateManager.dxItemBasten.push(item);
		gDashboard.itemGenerateManager.dxItemBasten.push(item2);
		
		gDashboard.insertItemManager.generateItemContainer('adhoc', true);
		gDashboard.itemGenerateManager.init();
		item2.dragNdropController = new WISE.widget.DragNDropController(item2);
		item2.dragNdropController.addDroppableOptions(item2);
		item.dragNdropController = item2.dragNdropController;
		// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot		
		/* DOGFOOT ktkang 비정형 레이아웃 오류 수정  20200130 */
		self.activeAdhocLayout(gDashboard.structure.Layout);
		
		$('.changeLayout').on('click',function(e){
			var eventElementId = e.target.id == '' ? e.currentTarget.id : e.target.id;

			switch(eventElementId){
			case 'changeLayoutC':
				self.activeAdhocLayout('C');
				break;
			case 'changeLayoutG':
				self.activeAdhocLayout('G');
				break;
			case 'changeLayoutCG':
				self.activeAdhocLayout('CG');
				break;
			case 'recoveryLayout':
				var layout = userJsonObject.defaultLayout;
				if(layout&& (layout === 'C' || layout === 'G' || layout === 'CG'))
					self.activeAdhocLayout(layout);
				else
					self.activeAdhocLayout('CG');
				break;
			}
		});
		//2020.02.13 mksong 비정형 아이템 삭제 방지 dogfoot
		$('.lm_close_tab').css('display','none');
	}
	
	this.renderButtons = function(){
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i,_item){
//			_item.renderButtons(_item.itemid);
			// 뷰어일때 renderbuttons 처리시 pivotgrid 처리
			if (_item.type == 'PIVOT_GRID') {
				var bChk = false;
				if (!isNull(_item.dxItem)) {
					var dataSrc = _item.dxItem.getDataSource();
					if (!isNull(dataSrc) && dataSrc._data.values.length > 0) {
						bChk = false;
					}
					else {
					    bChk = true;
					}
				}
				else {
					bChk = true;
				}
				
				// 조회하지 않은 상태 체크
				if (bChk) {
					gDashboard.itemGenerateManager.renderButtons(_item, _item.isAdhocItem, true);
				}
				else {
					gDashboard.itemGenerateManager.renderButtons(_item);
				}
			}
			else {
				gDashboard.itemGenerateManager.renderButtons(_item);
			}
		});
	}
	
	this.generateItemContainer = function(item,_layoutMeta){
		gDashboard.goldenLayoutManager.render(item,_layoutMeta);
	};
	this.clearCanvasLayout = function(){
		gDashboard.goldenLayoutManager.clear();
	};
	
	//2020.02.13 mksong 비정형 아이템 리사이즈 dogfoot
	this.adhocResize = function(){
		var isPaging = userJsonObject.menuconfig.Menu.PIVOT_PAGING_OPTION
		var height = $('.lm_goldenlayout').height();
		var width = $('.lm_goldenlayout').width();

		//2020.01.21 mksong 비정형 레이아웃 수정 dogfoot
		var chartItem,chartMeta;
		var pivotItem,pivotMeta;

		$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
			if(_item.type == 'PIVOT_GRID'){
				pivotMeta = _item;
				pivotItem = $('#'+_item.ComponentName);
			}else{
				chartMeta = _item;
				chartItem = $('#'+_item.ComponentName);
			}
		});

		switch(gDashboard.structure.Layout){
			case 'C':
				pivotItem.css('display','none');
				chartItem.css('display','block');
				chartItem.width('100%');
				chartItem.height('100%');
				chartItem.find('.lm_items').width('100%');
				chartItem.find('.lm_items').height(height-40+'px');
				chartItem.find('.lm_item_container').width('100%');
				chartItem.find('.lm_item_container').height(height-40+'px');
				// mksong 2019.12.20 비정형 레이아웃 수정 dogfoot
				chartItem.find('.lm_content').height(height-40+'px');
				chartItem.find('.lm_content').width('100%');
				$('.lm_splitter').css('display','none');
				break;
			case 'G':
				/* goyong ktkang 비정형 오류 수정  20210603 */
				if(typeof chartItem != 'undefined' && typeof chartItem.css('display') != 'undefined') {
					chartItem.css('display','none');
				}
				if(typeof pivotItem != 'undefined') {
					if(pivotMeta.dxItem){
						isPaging = userJsonObject.menuconfig.Menu.PIVOT_PAGING_OPTION && pivotMeta.Pivot.PagingOptions.PagingEnabled;
					}
					if(isPaging){
						height -=20;
					}
						
					pivotItem.css('display','block');
					pivotItem.width('100%');
					pivotItem.height('100%');
					pivotItem.find('.lm_items').width('100%');
					pivotItem.find('.lm_items').height(height-40+'px');
					pivotItem.find('.lm_item_container').width('100%');
					pivotItem.find('.lm_item_container').height(height-40+'px');
					// mksong 2019.12.20 비정형 레이아웃 수정 dogfoot
					pivotItem.find('.lm_content').height(height-40+'px');
					pivotItem.find('.lm_content').width('100%');
				}
				if(typeof pivotMeta == 'undefined'){
					
				}else if(pivotMeta.dxItem){
					(gDashboard.goldenLayoutManager[WISE.Constants.pid] || gDashboard.goldenLayoutManager).resize(pivotMeta, false);
				}else{
					(gDashboard.goldenLayoutManager[WISE.Constants.pid] || gDashboard.goldenLayoutManager).resize(null, false);
				}
				
				$('.lm_splitter').css('display','none');
				break;
			case 'CRGL':
			case 'CLGR':
			case 'CBGT':
			case 'CTGB':
					chartItem.css('display','block');
					pivotItem.css('display','block');
	
					$('.lm_splitter').css('display','block');
					if($('.lm_splitter').hasClass('lm_vertical')){
						var itemHeight = (height-48)/2;
	
						$('.cont_box').width(width+'px');
						$('.cont_box').height(itemHeight+'px');
						$('.cont_box').find('.lm_items').width(width+'px');
						$('.cont_box').find('.lm_items').height(itemHeight-40+'px');
						$('.cont_box').find('.lm_item_container').width(width+'px');
						$('.cont_box').find('.lm_item_container').height(itemHeight-40+'px');
						$('.cont_box').find('.lm_content').height('100%');
					}else if($('.lm_splitter').hasClass('lm_horizontal')){
						var itemWidth = (width-45)/2;
	
						$($('.cont_box').get(0)).width(itemWidth+0.5+'px');
						$($('.cont_box').get(1)).width(itemWidth-0.5+'px');
						$('.cont_box').height(height+'px');
						$($('.cont_box').get(0)).find('.lm_items').width(itemWidth+0.5+'px');
						$($('.cont_box').get(1)).find('.lm_items').width(itemWidth-0.5+'px');
						$('.cont_box').find('.lm_items').height(height-20+'px');
						$($('.cont_box').get(0)).find('.lm_item_container').width(itemWidth+0.5+'px');
						$($('.cont_box').get(1)).find('.lm_item_container').width(itemWidth-0.5+'px');
						$('.cont_box').find('.lm_item_container').height(height-20+'px');
					}
					break;
		}

		if(gDashboard.itemGenerateManager.dxItemBasten.length != 0){
			var itemList = gDashboard.itemGenerateManager.dxItemBasten;
			for (var i = 0; i < itemList.length; i++) {
				if (itemList[i].dxItem != undefined) {
					switch (itemList[i].type) {
					case 'PIVOT_GRID':
						if(gDashboard.reportType != 'AdHoc' || gDashboard.structure.Layout != 'C'){
							itemList[i].dxItem.option('width',$('#' + itemList[i].itemid).parent().width());
							// mksong 2019.12.20 비정형 레이아웃 수정 dogfoot
							itemList[i].dxItem.option('height',$('#' + itemList[i].itemid).parent().height());
							itemList[i].dxItem.resize();
						}
						break;
					case 'SIMPLE_CHART':
						if(gDashboard.reportType != 'AdHoc' || gDashboard.structure.Layout != 'G'){
							itemList[i].dxItem.option('width',$('#' + itemList[i].itemid).parent().width());
							itemList[i].dxItem.option('height',$('#' + itemList[i].itemid).parent().height());
							itemList[i].dxItem.render();
						}
						break;
					}
				}
			}
		}
	}
	
};

WISE.libs.Dashboard.AdhoceItemFieldManager = function() {
	var self = this;
	
	this.initialized = false;
	this.alreadyFindOutMeta = false;
	
	//검색 - searchDisable
	this.searchDisable = false;
	//검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	//검색
	
	this.meta;
	this.isChange = false; // 사용자가 필드를 변경했는지 여부 체크
	this.columnMeta = {}; // 쿼리된 모든 컬럼정보 저장
	this.isColumnChooser = false;
	
	this.dataItemNo=0;
	
	this.all = [];
	this.hide_column_list_dim = [];
	this.hide_column_list_mea = [];
//	this.hide_column_list = {'dimension': [],'measure': []};
	
	this.tables = [];
	
	this.Constants = {
		CUSTOMIZED: '계산된필드',
		DELTA: '변동측정필드',
		UNSELECTED_FIELD: 'UNSELECTED_FIELD'
	}
	
	this.init = function() {
		this.columnMeta = {};
		this.tables = [];
		this.all = [];
		this.meta = gDashboard.structure.ReportMasterInfo.dataSource;
		
		this.initialized = true;
	};
	
	this.setMetaTables = function(tables){
		this.meta.tables = tables;
	}
	
	this.setDataItemByField = function(_fieldlist){
		this.DataItems = {};
		self.DataItems['Dimension'] = [];
		self.DataItems['Measure'] = [];
//		var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
		
		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				dataItem['UNI_NM'] = $(_fieldlist[i]).attr('UNI_NM');
				self.DataItems['Dimension'].push(dataItem);
			} else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['NumericFormat'] = $(_fieldlist[i][0]).data('formatOptions');
				dataItem['UNI_NM'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};
	
	this.setPanesByField = function(_panes){
		this.Panes = {};
		self.Panes.Pane = { Name: "창 1", Series: {} };	
		
		_.each(_panes,function(_p) {
			if(_p.options != undefined){
				var overlappingMode = '';
				if(_p.options.pointLabelOptions == undefined) {
					overlappingMode = '';
				} else if(_p.options.pointLabelOptions.overlappingMode == 'Reposition') {
					overlappingMode = 'Stack';
				} else {
					overlappingMode = _p.options.pointLabelOptions.overlappingMode;
				}
				var Value = {
					SeriesType: _p.options.seriesType,
					PlotOnSecondaryAxis: _p.options.plotOnSecondaryAxis,
					IgnoreEmptyPoints: _p.options.ignoreEmptyPoints,
					ShowPointMarkers: _p.options.showPointMarkers,
					PointLabelOptions: {
						Orientation:_p.options.pointLabelOptions == undefined ? '' : _p.options.pointLabelOptions.orientation,
						ContentType: _p.options.pointLabelOptions == undefined ? '' :_p.options.pointLabelOptions.contentType,
						OverlappingMode: overlappingMode,
						ShowForZeroValues: _p.options.pointLabelOptions == undefined ? false : _p.options.pointLabelOptions.showForZeroValues,
						Position: _p.options.pointLabelOptions == undefined ? '' :_p.options.pointLabelOptions.position,
						FillBackground: _p.options.pointLabelOptions == undefined ? false : _p.options.pointLabelOptions.fillBackground,
						ShowBorder: _p.options.pointLabelOptions == undefined ? false : _p.options.pointLabelOptions.showBorder,
						ShowCustomTextColor: _p.options.pointLabelOptions == undefined ? false : _p.options.pointLabelOptions.showCustomTextColor,
						CustomTextColor: _p.options.pointLabelOptions == undefined ? '#000000' : _p.options.pointLabelOptions.customTextColor
					}
				};
				if (Value.PlotOnSecondaryAxis) {
					var secondAxisY = {
						UniqueName: _p.uniqueName,
						Title: _p.caption,
						ShowZero: !(_p.options.IgnoreEmptyPoints),
						ShowLabelMarkers: _p.options.showPointMarkers,
						Visible: true,
						Reverse: false,
						ShowGridLines: false,
						TitleVisible: true
					};
					self.Panes.Pane.SecondaryAxisY = secondAxisY;
				}
				if (_p.options.seriesType === 'Bubble') {
					if (self.Panes.Pane.Series.Weighted == null) {
						self.Panes.Pane.Series.Weighted = [];					
					}
					if(!_p.ishidden) {
						Value.Value = { UniqueName: _p.uniqueName };
						Value.Weight = { UniqueName: _p.uniqueName };
						self.Panes.Pane.Series.Weighted.push(Value);
					}
					// for (var i = 0; i < _panes.length; i+=2) {
					// 	var value;
					// 	value = {'Value': {'UniqueName' : _panes[i].uniqueName}, 'Weight': {'UniqueName' : _panes[i].uniqueName}};
					// 	if (i + 1 === _panes.length) {
					// 		value = {'Value': {'UniqueName' : _panes[i].uniqueName}, 'Weight': {'UniqueName' : _panes[i].uniqueName}};
					// 	} else {
					// 		value = {'Value': {'UniqueName' : _panes[i].uniqueName}, 'Weight': {'UniqueName' : _panes[i + 1].uniqueName}};
					// 	}
					// 	self.Panes.Pane.Series.Weighted.push(value);
					// }
				} else {
					if (self.Panes.Pane.Series.Simple == null) {
						self.Panes.Pane.Series.Simple = [];					
					}
					if(!_p.ishidden) {
						Value.Value = { UniqueName: _p.uniqueName };
						self.Panes.Pane.Series.Simple.push(Value);
					}
				}
			}
		});
		return self.Panes;
	};
	
	this.setSeriesDimensionsByField = function(_series){
		this.SeriesDimensions = {'SeriesDimension' : []};
		_.each(_series,function(_s){
			var Value = {'UniqueName' : _s.uniqueName};
			self.SeriesDimensions['SeriesDimension'].push(Value);
		})
		return self.SeriesDimensions;
	};
	
	this.setArgumentsByField = function(_argument){
		this.Arguments = {'Argument' : []};
		_.each(_argument,function(_a){
			var Value = {'UniqueName' : _a.uniqueName};
			self.Arguments['Argument'].push(Value);
		})
		return self.Arguments;
	};
	
	this.getherFields = function(_fieldManager) {
		var _panelManager = _fieldManager.panelManager;
		var all = _panelManager['allContentPanel'].children();
		var datas = _panelManager['datafieldAdHocContentPanel'+_fieldManager.index].children('ul.analysis-data');
    	var rows = _panelManager['rowAdHocContentPanel'+_fieldManager.index].children('ul.analysis-data');
    	var cols = _panelManager['colAdHocContentPanel'+_fieldManager.index].children('ul.analysis-data');
    	var hide_column_list = _panelManager['adhoc_hide_column_list_meaContentPanel'+_fieldManager.index].children('ul.analysis-data');
    	
    	this.measures = [];
    	this.dimensions = [];
    	this.arguments = [];
    	this.seriesDimensions = [];
    	this.HiddenMeasures = {'Measure':[],'Dimension':[]};
    	
    	this.Panes = {};
    	
    	if (datas.length ===0 && rows.length ===0 && cols.length ===0) {
    		/* DOGFOOT ktkang 경고창 처리  20200130 */
    		WISE.alert('데이터 항목에 아무것도 넣지 않으셨습니다. 하나 이상의 데이터를 넣고 조회하시기 바랍니다.');
    		gProgressbar.hide();
    		return false;
    	}
    	
    	this.dimensions = [];
    	this.Values = {'Value':[]};
    	this.Rows = {'Row':[]};
    	this.Columns = {'Column':[]};
    	var allSelectedFields = [];
    	
    	var measureFieldOption = function(_elem){
			var summaryType = $(_elem).find('.on >.summaryType').attr('summarytype');
			var caption = $(_elem).children().get(0).innerText;
			var options = $(_elem).children('.seriesoption').data('dataItemOptions');
    		var measure  = {
    			caption: caption,
    			captionBySummaryType: caption + '(' + summaryType + ')',
    			currencyCulture: undefined,
    			format: 'fixedPoint',
    			name: caption,
    			nameBySummaryType: summaryType + '_' + caption,
    			precision: 0,
    			precisionOption: '반올림',
    			type: 'measure',
				uniqueName:  $(_elem).attr('dataitem'),
				wiseUniqueName: $(_elem).attr('UNI_NM'),
				cubeUniqueName: $(_elem).attr('cubeUniNm'),
				options: options
    		};
    		return measure;
    	};
    	
    	var dimensionFieldOption = function(_elem){
			var caption = $(_elem).children().get(0).innerText;
    		var dimension  = {
    			caption: caption,
    			name: caption,
    			rawCaption: undefined,
    			type: 'dimension',
    			wiseUniqueName: $(_elem).attr('UNI_NM'),
    			cubeUniqueName: $(_elem).attr('cubeUniNm'),
				uniqueName:  $(_elem).attr('dataitem')
    		};
    		return dimension;
    	};
    	
		
    	_.each(datas, function(_elem, _i) {
    		var child = $(_elem).children();
    		allSelectedFields.push(child);
    		var value = {'UniqueName': null};
    		value['UniqueName'] = $(child).attr('dataitem');
    		value['wiseUniqueName'] = $(child).attr('UNI_NM');
    		value['cubeUniqueName'] = $(child).attr('cubeUniNm');
    		self.Values['Value'].push(value);
    		var measureMeta = measureFieldOption(child);
    		self.measures.push(measureMeta);
    	});
    	
    	_.each(rows, function(_elem, _i) {
    		var child = $(_elem).children();
    		allSelectedFields.push(child);
    		var row = {'UniqueName': null};
    		row['UniqueName'] = $(child).attr('dataitem');
    		row['wiseUniqueName'] = $(child).attr('UNI_NM');
    		row['cubeUniqueName'] = $(child).attr('cubeUniNm');
    		self.Rows['Row'].push(row);
    		var dimensionMeta = dimensionFieldOption(child);
    		self.arguments.push(dimensionMeta);
    		self.dimensions.push(dimensionMeta);
    	});
    	
    	_.each(cols, function(_elem, _i) {
    		var child = $(_elem).children();
    		allSelectedFields.push(child);
    		var column = {'UniqueName': null};
    		column['UniqueName'] = $(child).attr('dataitem');
    		column['wiseUniqueName'] = $(child).attr('UNI_NM');
    		column['cubeUniqueName'] = $(child).attr('cubeUniNm');
    		self.Columns['Column'].push(column);
    		var dimensionMeta = dimensionFieldOption(child);
    		self.seriesDimensions.push(dimensionMeta);
    	});
    	
    	_.each(hide_column_list, function(_elem, _i) {
			var child = $(_elem).children();
			allSelectedFields.push(child);
			var column = {'UniqueName': null};
			column['UniqueName'] = $(child).attr('dataitem');
			//2020.02.13 mksong 비정형 주제영역 정렬 컬럼 추가 dogfoot
    		column['wiseUniqueName'] = $(child).attr('UNI_NM');
    		column['cubeUniqueName'] = $(child).attr('cubeUniNm');
    		if($(child).attr('data-field-type') == 'measure'){
    			self.HiddenMeasures['Measure'].push(column);	
    		}else{
    			self.HiddenMeasures['Dimension'].push(column);
    		}
			
		});
    	
    	this.DataItems = self.setDataItemByField(allSelectedFields);
    	this.Panes = self.setPanesByField(self.measures);
    	this.SeriesDimensions = self.setSeriesDimensionsByField(self.seriesDimensions);
		this.Arguments = self.setArgumentsByField(self.arguments);
		this.initialized = true;
	};
	
	this.setAllFields = function(_allFieldSet){
		this.all = _allFieldSet;
    	_.each(this.all, function(_uid) {
        	var o =self.columnMeta[_uid];
    		self.all.push(o);
        });    	
    	
    	return this;
	}
	
	this.getherFieldsByFieldSet = function(_fieldSet) {
		var rows = _fieldSet.rows;
    	var columns = _fieldSet.columns;
    	var datas = _fieldSet.datas;
    	
    	var columnMetaSet = _.map(this.columnMeta, 'uid');
    	var all = [].concat(rows).concat(columns).concat(datas);
    	all = _.difference(columnMetaSet, all);
    	
    	this.rows = [];
    	_.each(rows, function(_uid) {
    		var o = self.columnMeta[_uid];
    		self.rows.push(o);
    	});
    	
    	this.columns = [];
    	_.each(columns, function(_uid) {
    		var o =self.columnMeta[_uid];
    		self.columns.push(o);
    	});
    	
    	this.datas = [];
    	_.each(datas, function(_uid) {
    		var o =self.columnMeta[_uid];
    		self.datas.push(o);
    	});
    	
    	this.all = [];
    	_.each(all, function(_uid) {
        	var o =self.columnMeta[_uid];
    		self.all.push(o);
        });    	
    	
    	return this;
	};
}
