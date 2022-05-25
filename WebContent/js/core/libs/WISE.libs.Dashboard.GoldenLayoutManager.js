/**i
 * Golden Layout manager class.
 */
WISE.libs.Dashboard.GoldenLayoutManager = function() {
	var self = this;
    this.canvasLayout;
    this.layoutIndex;
    this.containerItemNo = 1;
    this.reportIdSuffix = '';
	this.isViewer;
	/* DOGFOOT hsshim 2020-01-23 텝 컨테이너 추가하는 기능 개선 */
	this.selectedTabContainer;
	this.resizecount = 0;
    
    /**
     * Initialize golden layout instance.
     */
    this.init = function(item, isAdhoc, reportId,_type,_tabTitle) { /*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
    	/*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
    	var headerHeightLen= 0;
    	if(WISE.Constants.editmode === 'viewer'){
    		headerHeightLen = gDashboard.layoutConfig[WISE.Constants.pid] !="" && typeof gDashboard.layoutConfig[WISE.Constants.pid] != 'undefined' && gDashboard.layoutConfig[WISE.Constants.pid] != "\"\""&& Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0
    						? Number(gDashboard.layoutConfig[WISE.Constants.pid].TITLE_HEIGHT_SETTING):Number(userJsonObject.layoutConfig.TITLE_HEIGHT_SETTING)
    	}else{
    		headerHeightLen = gDashboard.layoutConfig !="" && typeof gDashboard.layoutConfig != 'undefined' && gDashboard.layoutConfig != "\"\""&& Object.keys(gDashboard.layoutConfig).length != 0
    						? Number(gDashboard.layoutConfig.TITLE_HEIGHT_SETTING):Number(userJsonObject.layoutConfig.TITLE_HEIGHT_SETTING)
    	}
    	
    	var config = {
            settings: {
                selectionEnabled: false,
//                showMaximiseIcon : WISE.Constants.editmode == 'viewer' ? true : false,
                showMaximiseIcon :false,
                showPopoutIcon: false,
                //constrainDragToContainer: false,
            },
            content: [],
            /*dogfoot 골든레이아웃 헤더 값 설정 추가 shlim 20200821*/
            dimensions:{
            	headerHeight : headerHeightLen
            }
        };
    	var canvasContainer = $('#canvas-container');
    	if (reportId) {
    		self.isViewer = true;
    		/* DOGFOOT ktkang 뷰어에서 X축 기울기 오류 수정 20191218*/
    		/* DOGFOOT hsshim 1220
    		 * 골든레이아웃 UI 적용
    		 */
			self.reportIdSuffix = self.reportIdSuffix + '_' + reportId;
    		canvasContainer = $('#contentContainer_' + reportId);
    		config.dimensions = {
    			headerHeight: headerHeightLen ? headerHeightLen : 36
    		};
    		config.settings.showCloseIcon = false;
    	}
    	// init with empty container
    	if (!item) {
    		config.content.push({
				type: 'stack',
				name: 'tabContainerDashboardItem' + self.containerItemNo,
				number: self.containerItemNo,
				enableHeaderDrop: true,
                content: [{
					type: 'stack',
					id: 'container',
					title: '컨테이너 ' + self.containerItemNo,
					name: 'dashboardTabPage' + self.containerItemNo,
					number: self.containerItemNo,
					/*dogfoot 컨테이너/아이템 헤더 구분 기능 추가 shlim 20200918*/
					nTabHdVisible:true,
            		hasHeaders: false,
        		}]
    		});
    		/*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
    		self.containerItemNo++;
    	} 
    	// init with opened report items
    	else if (item === 'open') {
    		self.clear();
			self.layoutIndex = 0;
			var layoutStructure = gDashboard.structure.LayoutTree;
			var canvasLayout = undefined;
			var sortItemList = gDashboard.structure.sortedItemIdx;
			/* DOGFOOT ktkang 모바일일 때 뷰어 수정  20200813 */
			if($("html").hasClass("mobile")) {
				var phoneH = $("body").height() - 40;
				$("body").css("overflow", "inherit");
				var itemHeight = phoneH;
				if(typeof sortItemList != 'undefined') {
					itemHeight = sortItemList.length * phoneH;
				}
				 
				$('#container').css('height', 'auto');
				/* DOGFOOT ktkang 모바일 뷰어 오류 수정  20200903 */
				$('.container-inner').css('height', itemHeight + 80);
				$('#reportContainer').css('height', itemHeight);
				
//				 $('#reportContainer').dxScrollView({
//				        scrollByContent: true,
//				        scrollByThumb: true,
//				        height: "inherit",
//				        showScrollbar: "onScroll"
//				    });
				 
				 $('.contentContainer').css('height', itemHeight);
			}
			/*dogfoot 통계 분석 레이아웃 불러오기 shlim 20201102*/
    		var layout
    		if(gDashboard.reportType == "StaticAnalysis"){
    			layout = self.renderAysLayout(layoutStructure, canvasLayout, sortItemList);
    		}else{
    			layout = self.renderLayout(layoutStructure, canvasLayout, sortItemList);
    		}
    		config.content.push(layout);
    	}
    	// init adhoc report
    	else if (isAdhoc) {
			config.settings.showCloseIcon = false;
    		self.setupAdhocLayout(config);
    	}
    	/*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
    	else if (_type == 'AysItem') {
    		config.content.push({
				type: 'stack',
				name: 'tabContainerDashboardItem' + self.containerItemNo,
				number: self.containerItemNo,
				enableHeaderDrop: true,
                content: [{
					type: 'stack',
					id: 'container',
					title: _tabTitle,
					name: 'dashboardTabPage' + self.containerItemNo,
					number: self.containerItemNo,
					/*dogfoot 컨테이너/아이템 헤더 구분 기능 추가 shlim 20200918*/
					nTabHdVisible:true,
            		hasHeaders: false,
            		content: item
        		}]
    		});
    		self.containerItemNo++;
    	}
    	// init with selected item
    	else {
    		config.content.push({
				type: 'stack',
				contentId: item ? item.ComponentName + self.reportIdSuffix : undefined,
                content: [{
                    type: 'component',
                    componentName: 'dashboardItem',
                    id: item.ComponentName + self.reportIdSuffix,
                    componentState: { item: item.ComponentName + self.reportIdSuffix },
                    /* 개발 hsshim 1209 */
    				title: item.Name + '',
                }]
    		});
    	}
    	// new GoldenLayout manager object
    	self.canvasLayout = new GoldenLayout(config, canvasContainer);
    	// set up component factory
    	self.canvasLayout.registerComponent('dashboardItem', function(container, componentState) {
    		/* DOGFOOT hsshim 1220
			 * 틀고정 기능 추가
			 */
    		if (componentState.item.indexOf('pivotDashboardItem') !== -1) {
    			container.getElement().append(	'<div class="dashboard-item">' + 
    												'<div style="width:auto; height:100%;" id="' + componentState.item + '_item_bas">' +
    													'<div id="' + componentState.item + '_item"></div>' +
													'</div>' +
												'</div>');
    		} else {
    			container.getElement().append('<div class="dashboard-item" id="' + componentState.item + '_item"></div>');
    		}
    	});
		// page resize event
        $(window).on('resize', function(){
            var panelContW = $('.panel.cont').width();
            var panelContWM = panelContW - 42;
            self.canvasLayout.updateSize(panelContWM);
            /*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
        });
        // component created event
        self.canvasLayout.on('componentCreated', function(component) {
			if (WISE.Constants.editmode === 'designer' ||(userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && gDashboard.reportType == "DashAny") || gDashboard.reportType == 'DSViewer') {
				var item = WISE.libs.Dashboard.item.ItemUtility.getItemById(component.config.id);
				var focusItem = item;
				if(item !== null && item.isAdhocItem && item.type != 'PIVOT_GRID'){ /*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
					$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
						if(_item.isAdhocItem && _item.type == 'PIVOT_GRID' && item.adhocIndex == _item.adhocIndex){
							focusItem = _item;
						}
					});	
				}
				if (item) {
					component.element.on('click', function(e) {
						// 피봇그리드 페이지 클릭일때 예외처리
						var bPivotPageClick = $(e.target).hasClass("dx-pivot-page-size") 			// 페이지사이즈
													|| $(e.target).hasClass("dx-pivot-page")		// 페이지
													|| $(e.target).hasClass("dx-pivot-page-prev")	// 이전
													|| $(e.target).hasClass("dx-pivot-page-next") ? true : false;		// 다음
						if (!bPivotPageClick) {
							gDashboard.fieldManager = focusItem.fieldManager;
							gDashboard.itemGenerateManager.focusItem(item,focusItem);
							gDashboard.fieldChooser.resetAnalysisFieldArea(focusItem);
							/* DOGFOOT ktkang 주제영역 여러아이템 사용 시 아이템 별 연계 차원 표시  20200717 */
							item.dragNdropController = new WISE.widget.DragNDropController();
							if(WISE.Context.isCubeReport) {
								item.dragNdropController.cubeRelationCheck(item);
							}
						}
					});
				}
			}
	    	//20201112 AJKIM 통계 라벨에 x표시 제거 dogfoot
	    	/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
			if(gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer'){
				$('.lm_close_tab').css('display','none');
				$('.lm_close').css('display','none');
			}
			/*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
        });
        // stack created event
        self.canvasLayout.on('stackCreated', function(stack) {
        	// add header classes if stack's immediate child is a component
        	if (stack.config.contentId) {
        		stack.element.attr('id', stack.config.contentId).addClass('cont_box');
            	stack.header.controlsContainer.addClass('cont_box_top_icon').attr('id', stack.config.contentId + '_item_topicon');
        	} else if (stack.config.name) {
				stack.element.attr('id', stack.config.name);
				if (stack.config.id !== 'container') {
					stack.element.addClass('tab_cont_box');
					/* DOGFOOT hsshim 2020-01-23 텝 컨테이너 추가하는 기능 개선 */
					stack.element.on('click', function() {
						$('.tab_cont_box').removeClass('selected');
						stack.element.addClass('selected');
						self.selectedTabContainer = stack;
					});
					if (self.selectedTabContainer == undefined) {
						$('.tab_cont_box').removeClass('selected');
						stack.element.addClass('selected');
						self.selectedTabContainer = stack;
					}
					/* DOGFOOT hsshim 2020-01-23 끝 */
				}
			}
        	//20201112 AJKIM 통계 라벨에 x표시 제거 dogfoot
    		if(gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer'){
    			$('.lm_close_tab').css('display','none');
    			$('.lm_close').css('display','none');
    		}
		/*dogfoot 보고서 레이아웃 설정 불러오기 리사이즈 변경 shlim 20200821*/
        });
        // tab created event
        self.canvasLayout.on('tabCreated', function(tab) {
        	// component tab
        	if (tab.contentItem.isComponent) {
        		var id = tab.contentItem.config.id;
        		var item = WISE.libs.Dashboard.item.ItemUtility.getItemById(id);
        		var focusItem = item;
	        		if(item !== null && item.isAdhocItem && item.type != 'PIVOT_GRID'){/*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
	        			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
	        				if(_item.isAdhocItem && _item.type == 'PIVOT_GRID' && item.adhocIndex == _item.adhocIndex){
	        					focusItem = _item;
	        				}
	        			});	
	        		}
        		tab.element.attr('id', id + '_item_title').addClass('cont_box_top_tit');
        		// hide caption option
        		//2020.11.13 mksong 비정형 보고서 showCaption 기능 추가 dogfoot
        		/* DOGFOOT syjin 뷰어 불러오기 수정  20211118*/
        		if(item !== null){
        			if (item.meta && item.meta.ShowCaption === false ||  item.ShowCaption === false) {
            			tab.element.hide();
            		}
        		}
        		
        		// focus event
//        		if (!self.isViewer && item !== null) {
        		if (item !== null) {
        			tab.element.on('click', function() {
        				if(self.isViewer && (item.isAdhocItem || gDashboard.reportType == 'DSViewer' ||  (gDashboard.reportType == 'DashAny' && userJsonObject.menuconfig.Menu.DASH_DATA_FIELD))){
							/* 2021-04-30 데이터항목 visible 권한 처리 */
							if (gDashboard.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
        						$('.data-view').css('display','block');
							}
							else {
								$('.data-view').css('display','none');	
							}
        				}else{
        					$('.data-view').css('display','none');
        				}
        				gDashboard.fieldManager = focusItem.fieldManager;
        				gDashboard.itemGenerateManager.focusItem(item,focusItem);
        				if(item.isAdhocItem){
        					gDashboard.fieldChooser.resetAnalysisFieldArea(focusItem);	
        				}
        			});
        			
        			if(!self.isViewer || item.isAdhocItem){
        				gDashboard.fieldManager = focusItem.fieldManager;
            			gDashboard.itemGenerateManager.focusItem(item,focusItem);
            			gDashboard.fieldChooser.resetAnalysisFieldArea(focusItem);
            			tab.contentItem.parent.element.addClass('active');
            			tab.contentItem.parent.element.addClass('tabactive');
        			}else if(self.isViewer && ((gDashboard.reportType == "DashAny" && userJsonObject.menuconfig.Menu.DASH_DATA_FIELD) || gDashboard.reportType == 'DSViewer')){
        				gDashboard.fieldManager = focusItem.fieldManager;
        				
        				// 2021-07-07 yyb 뷰어에서 주제영역일때 불필요하게 focusItem이 중복호출되어 예외처리
        				//20210715 AJKIM 이미지 뷰어 조회 오류 수정 dogfoot
        				if (focusItem.dataSourceId && gDashboard.dataSourceManager.datasetInformation[focusItem.dataSourceId].DATASRC_TYPE != 'CUBE') {
            			    gDashboard.itemGenerateManager.focusItem(item,focusItem);
            			}
            			gDashboard.fieldChooser.resetAnalysisFieldArea(focusItem);
            			tab.contentItem.parent.element.addClass('active');
            			tab.contentItem.parent.element.addClass('tabactive');
        			}
        		}
        	} else if (tab.contentItem.config.id === 'container') {
				tab.element.attr('id', tab.contentItem.config.name + '_item_title').addClass('tab_cont_box_top_tit');
				// name change
				/* DOGFOOT ktkang 뷰어에서는 컨테이너 이름 변경하지 못하도록 수정  20191224 */
				if(!self.isViewer && gDashboard.reportType != "StaticAnalysis") {
					tab.element.on('dblclick', function() {
						$('#cont_popup').dxPopup({
							height: 'auto',
							width: 500,
							visible: false,
							showCloseButton: false
						});

						var p = $('#cont_popup').dxPopup('instance');

						p.option({
							title: '이름 편집',
							contentTemplate: function(contentElement) {
								// initialize title input box
								contentElement.append('<p>컨테이너 이름</p><div id="newName_titleInput">');
								var html = '<div class="modal-footer" style="padding-bottom:0px;">';
								html += '<div class="row center">';
								html += '<a id="cont-ok-hide" href="#" class="btn positive ok-hide">확인</a>';
								html += '<a id="cont-close" href="#" class="btn neutral close">취소</a>';
								html += '</div>';
								html += '</div>';
								html += '</div>';
								contentElement.append(html);

								// confirm and cancel
								$('#cont-ok-hide').on('click', function() {
									var newName = $('#newName_titleInput').dxTextBox('instance').option('text');
									tab.contentItem.setTitle(newName);
									p.hide();
								});
								$('#cont-close').on('click', function() {
									p.hide();
								});

								$('#newName_titleInput').dxTextBox({
									text: tab.element.text()
								});
							}
						});

						p.show();
					});
				}
        	}
        	//20201112 AJKIM 통계 라벨에 x표시 제거 dogfoot
			if(gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer'){
				$('.lm_close_tab').css('display','none');
				$('.lm_close').css('display','none');
			}
        	/*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
        });
        // item (component) destroyed event
        self.canvasLayout.on('itemDestroyed', function(item) {
        	if (item.isComponent) {
        		if(gDashboard.reportType == 'AdHoc') {
        			if(gDashboard.structure.Layout != 'G' || gDashboard.structure.Layout != 'C') {
        				if(item.config.id.indexOf('chart') < 0){
        					gDashboard.structure.Layout = 'C';
        				}else{
        					gDashboard.structure.Layout = 'G';
        				}
        			}	
        		} else {
        			$('#' + item.config.id + 'fieldManager').remove();	
        		}
        		
        		$('.panelDataA-2').remove();
        		$('.itemDelete').remove();
        		$('#menulist').removeClass('col-2');
        		
        		$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item) {
        			if (_item.ComponentName == item.config.id) {
        				$("#" + item.config.id + "_contextMenu").remove();
        				delete gDashboard.itemGenerateManager.trackingConditionManager[_item.itemid];
        				if (gDashboard.itemGenerateManager.dxItemBasten.length === 1) {
        					gDashboard.itemGenerateManager.dxItemBasten = [];
        				} else {
        					gDashboard.itemGenerateManager.dxItemBasten.splice(_i,1);
        					gDashboard.itemGenerateManager.focusItem(gDashboard.itemGenerateManager.dxItemBasten[gDashboard.itemGenerateManager.dxItemBasten.length-1], gDashboard.itemGenerateManager.dxItemBasten[gDashboard.itemGenerateManager.dxItemBasten.length-1]);
        					gDashboard.fieldChooser.resetAnalysisFieldArea(gDashboard.itemGenerateManager.dxItemBasten[gDashboard.itemGenerateManager.dxItemBasten.length-1]);
        					/*dogfoot 아이템 삭제 시 viewedItemList 에서 해당 아이템 삭제 shlim 20210222*/
        					gDashboard.itemGenerateManager.viewedItemList.splice(gDashboard.itemGenerateManager.viewedItemList.indexOf(item.id),1);
        					
        					if(gDashboard.reportType == 'AdHoc') {
        						gDashboard.itemGenerateManager.dxItemBasten[gDashboard.itemGenerateManager.dxItemBasten.length-1].isAdhocItem = false;
        					}
        				}
        				return false;
        			}
        		});
			}
			/* DOGFOOT hsshim 2020-01-23 텝 컨테이너 추가하는 기능 개선 */ 
			// deselect tab container if it is selected
			else if (self.selectedTabContainer && self.selectedTabContainer.config.name === item.config.name) {
				self.selectedTabContainer = undefined;
			}
			/*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
        });
        // state changed event
        self.canvasLayout.on('stateChanged', function(event) {
			// reassign container info if required
			if (event && event.origin.isStack && typeof event.origin.config.number !== 'undefined') {
				var contents = event.origin.config.content;
				var lowestContainerNum = Number.MAX_VALUE;
				var i;
				for (i = 0; i < contents.length; i++) {
					var containerNum = contents[i].number;
					if (event.origin.config.number === containerNum) {
						break;
					}
					if (lowestContainerNum > containerNum) {
						lowestContainerNum = containerNum;
					}
				}
				if (i > 0 && i === contents.length) {
					event.origin.element.attr('id', 'tabContainerDashboardItem' + lowestContainerNum);
					event.origin.config.name = 'tabContainerDashboardItem' + lowestContainerNum;
					event.origin.config.number = lowestContainerNum;
				}
			}
			// resize component items
			/*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
			//2020.02.13 MKSONG 비정형 리사이즈 오류 수정 DOGFOOT
			if(WISE.Constants.editmode != 'viewer'){
				if(gDashboard.reportType == 'AdHoc'){
					$('.lm_close_tab').css('display','none');
					if(gDashboard.structure.Layout == 'C' || gDashboard.structure.Layout == 'G'){
						gDashboard.changeReportTypeManager.adhocResize();	
					}else{
						self.resize();
					}
				}else{
					self.resize();
				}
			}else{
				/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
				if(gDashboard.itemGenerateManager.isParamReady) {
					if(gDashboard.hasTab) {
						gDashboard.tabQuery = true;
						gDashboard.itemGenerateManager.viewedItemList = [];
						if(!gDashboard.isOpened && gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
							gDashboard.clickedfolderList = false;
						}else if(!gDashboard.clickedfolderList && gDashboard.isOpened){
                            gDashboard.query();
                            $.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
								$('#'+_item.itemid).css('display','block');
							});
						}else{
							gDashboard.clickedfolderList = false;
						};
					}
				}
				
				self.resize();
				if(gDashboard.reportType == 'AdHoc'){
					//2020.03.09 MKSONG 뷰어에서 비정형 열기 레이아웃 오류 수정 DOGFOOT
					if(gDashboard.structure.Layout == 'C' || gDashboard.structure.Layout == 'G'){
						gDashboard.changeReportTypeManager.adhocResize();
					}else{
						self.resize();
					}
				}
				gDashboard.changeReportTypeManager.renderButtons();
			}
			
			if (event && event.origin.isStack && event.origin.config.contentId) {
				var item = WISE.libs.Dashboard.item.ItemUtility.getItemById(event.origin.config.contentId);
				if (item) {
					var itemButtons = $('#' + item.itemid + '_topicon');
					if (item.initialized && itemButtons.length > 0 && itemButtons.children().length <= 3) {
//						item.renderButtons(item.itemid);
						gDashboard.itemGenerateManager.renderButtons(item);
					}
				}
				if(item!=null) {
					var ele = $('#' + item.itemid + '_title');
	                ele.find( '.lm_title' ).html(item.Name);
	                // 20200609 ajkim 데이터가 없을 때 창을 옮겨도 텍스트 라벨 사라지지 않도록 수정 dogfoot
					if(!item.memoText) item.memoText = '';
					if($('#' + item.itemid + '_text').length === 0){
						var textHtml = '<ul class="lm_text" title="text" id="' + item.itemid + '_text">' + item.memoText + '</ul>';		
							$('#' + item.ComponentName + ' .lm_controls').prepend($(textHtml));
					}else{
						$('#' + item.itemid + '_text').text(item.memoText);
					}
					
					if(item.memoText === '') $('#' + item.itemid + '_text').attr('style', 'border: none; display:none;');
					else $('#' + item.itemid + '_text').attr('style', '');
				}
			}
			if(gDashboard.reportType == 'Spread' || gDashboard.reportType == 'Excel'){
				if(typeof gDashboard.goldenLayoutManager != 'undefined')
					gDashboard.goldenLayoutManager.render_config_layout();
				else
					(gDashboard.goldenLayoutManager = new WISE.libs.Dashboard.GoldenLayoutManager()).render_config_layout();
			}
			else if(WISE.Constants.editmode === 'viewer'){
				if(typeof gDashboard.goldenLayoutManager[WISE.Constants.pid] != 'undefined'){
				    gDashboard.goldenLayoutManager[WISE.Constants.pid].render_config_layout();	
				}
	        }else{
	        	gDashboard.goldenLayoutManager.render_config_layout();
	        }
//			gDashboard.pOver = $('#tabdropdownPopover').dxPopover({
//				height: 'auto',
//				width: 195,
//				position: 'bottom',
//				visible: false,
//			});
	    	//20201112 AJKIM 통계 라벨에 x표시 제거 dogfoot
			if(gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer'){
				$('.lm_close_tab').css('display','none');
				$('.lm_close').css('display','none');
			}
			//2021-06-28 Jhseo 일반그리드 일때 최대화 없애기
			$('.lm_maximise').css('display','none');
        });
        /*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
        if(WISE.Constants.editmode === 'viewer'){
        	if(typeof gDashboard.goldenLayoutManager[WISE.Constants.pid] != 'undefined'){
			    gDashboard.goldenLayoutManager[WISE.Constants.pid].render_config_layout();	
			    //$('#reportContainer').css('height', 'calc(100vh - ' + (123 - 39 + $('.filter-bar').height()) + 'px)')
			}
        }else{
        	gDashboard.goldenLayoutManager.render_config_layout();
        	$('.panel.cont').css('height', 'calc(100vh - ' + (123 - 39 + $('.filter-bar').height()) + 'px)')
        }
        /*dogfoot 디자이너 화면 그릴때 필터영역 계산 shlim 20200821*/
		
    	// initialize GoldenLayout
    	self.canvasLayout.init();
    };

    /**
     * Controller function. Call the appropriate action based on current GoldenLayout instance state.
     */
    
    //2020.02.13 MKSONG 리사이즈 함수화 DOGFOOT
    this.resize = function(_dxItemBasten, isRepaint){
    	var _isRepaint = isNull(isRepaint) ? true : false;
    	self.resizecount++;
    	if(gDashboard.itemGenerateManager.dxItemBasten.length != 0){
        	$('.cont_box_cont').css('width', '100%');
            $('.cont_box_cont').css('height', '100%');
            
            if (!isNull(_dxItemBasten)) {
            	var _itemType = _dxItemBasten.type;
            	switch (_itemType){
                    case 'PIVOT_GRID':                       
                	    /* DOGFOOT hsshim 1220
                    	 * 틀고정 기능 추가
                    	 */
                    	if(typeof _dxItemBasten.dxItem != 'undefined'){
	                    	if (_dxItemBasten.dxItem.element().parent().css('width') !== '0px') {
	//	                                	_dxItemBasten.dxItem.option('width',$('#' + _dxItemBasten.itemid).closest('.dashboard-item').innerWidth());
	//                                		_dxItemBasten.dxItem.option('height',$('#' + _dxItemBasten.itemid).closest('.dashboard-item').innerHeight());
	                    		_dxItemBasten.dxItem.option('width',$('#' + _dxItemBasten.itemid).parent().innerWidth()-15);
	                    		_dxItemBasten.dxItem.option('height',$('#' + _dxItemBasten.itemid).parent().innerHeight());
	                    	}
	                    	if (_isRepaint) {
		                		_dxItemBasten.dxItem.repaint();
		                	}                   	
                    	}
                        break;
                    case 'DATA_GRID':
                    	_dxItemBasten.dxItem.repaint();
                        break;
                    case 'SIMPLE_CHART':
                    case 'RANGE_BAR_CHART':
                    case 'RANGE_AREA_CHART':
                    case 'TIME_LINE_CHART':
                    case 'BUBBLE_CHART':
                    case 'PYRAMID_CHART':
                    case 'FUNNEL_CHART':
                    case 'STAR_CHART':
                    	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
                    	$('#' + _dxItemBasten.itemid).css('display', 'block');
                        _dxItemBasten.dxItem.render();
                        break;
                    case 'PIE_CHART':
                        if (_dxItemBasten.dxItem.length == 1) {
                        	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
                        	$('#' + _dxItemBasten.itemid).css('display', 'block');
                            var size = { 'height': $('#' + _dxItemBasten.itemid).height(), 'width': $('#' + _dxItemBasten.itemid).width() };
                            _dxItemBasten.dxItem[0].option('size', size);
                            _dxItemBasten.dxItem[0].render();
                        } else {
                        	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
                        	$('#' + _dxItemBasten.itemid).css('display', 'block');
                            _dxItemBasten.resize();
                        }
						break;
                    case 'TREEMAP':
                    	_dxItemBasten.dxItem.option('size',{'height': $('#'+_dxItemBasten.itemid).height(),'width': $('#'+_dxItemBasten.itemid).width()});
                    	break;
                    /* DOGFOOT syjin 카카오 지도 추가  20200820 */
                    case 'KAKAO_MAP':
                    	//2020.11.17 mksong 카카오맵 리사이즈시 폴리곤 그리도록 수정 dogfoot
                    	_dxItemBasten.drawByChanged();
						//2020.09.22 mksong dogfoot kakaomap resize 오류 수정
                    	_dxItemBasten.dxItem.relayout();               	
                    	break;
                    case 'KAKAO_MAP2':
                    	_dxItemBasten.resize();
                    	map.relayout();               	
                    	break;
                    	
                    case 'CARD_CHART':
                    case 'HEATMAP':
                    case 'HEATMAP2':
                    case 'COORDINATE_DOT':
                    case 'SYNCHRONIZED_CHARTS':
                    case 'WORD_CLOUD':
                    case 'RECTANGULAR_ARAREA_CHART':
                    case 'PARALLEL_COORDINATE':
                    case 'BUBBLE_PACK_CHART':
                    case 'WORD_CLOUD_V2':
                    case 'DENDROGRAM_BAR_CHART':
                    case 'CALENDAR_VIEW_CHART':
                    case 'CALENDAR_VIEW2_CHART':
                    case 'CALENDAR_VIEW3_CHART':
                    case 'COLLAPSIBLE_TREE_CHART':
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
                    case 'BUBBLE_D3':
                    case 'HISTOGRAM_CHART':
                    case 'IMAGE':
                    case 'TEXTBOX':
                    case 'FORCEDIRECT':
                    case 'FORCEDIRECTEXPAND':
                    	_dxItemBasten.resize();
                        break;
                    case 'COMBOBOX':
                    	$('#'+_dxItemBasten.itemid).height('27px');
                    	break;
                    case 'HIERARCHICAL_EDGE':
                    	_dxItemBasten.resize();
                        break;
                    /*dogfoot 코로플레스 리사이즈 추가 syjin 20210607*/   
	                case 'CHOROPLETH_MAP':
	                	_dxItemBasten.dxItem.render();
					break;
                }
            }
    		else{
            	if (gDashboard.itemGenerateManager.dxItemBasten[0].dxItem != undefined) {
                    var itemList = gDashboard.itemGenerateManager.dxItemBasten;
                    for (var i = 0; i < itemList.length; i++) {
                        if (itemList[i].dxItem != undefined) {
                        	this.resize(itemList[i]);
                        }
                    }
                }
            	else {
                	// 20200629 AJKIM 텍스트 박스는 조회 전에도 resize호출하게 수정 dogfoot
                	$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, item){
                		if(item.type === "TEXTBOX")
                			item.resize();
                	});
                }
            }
        /*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
//            self.render_config_layout();
    	}
    	
    	//20201112 AJKIM 통계 라벨에 x표시 제거 dogfoot
    	/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
		if(gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer'){
			$('.lm_close_tab').css('display','none');
			$('.lm_close').css('display','none');
		}
    }
    
    this.render_config_layout = function(){
    	/* DOGFOOT syjin 타이틀&필터 레이아웃 설정  20200814 */
			var layoutObj;
			/*dogfoot 보고서 레이아웃 불러오기 뷰어 디자이너 동작 구분 shlim 20200821*/
			if(WISE.Constants.editmode === 'viewer'){
				var setTitle = {
						common : function(layoutObj){
							if(layoutObj.TITLE_HEIGHT_SETTING) {
								/* DOGFOOT shlim 헤더영역 재설정 20200820 */
//								$(".lm_header").attr("style", "height:"+(layoutObj.TITLE_HEIGHT_SETTING)+"px !important;line-height:"+(Number(layoutObj.TITLE_HEIGHT_SETTING) - 7)+"px; z-index: inherit;  display:flex; align-items:center");
//								$(".lm_tabs").attr("style", "height:"+(layoutObj.TITLE_HEIGHT_SETTING)+"px !important; display:flex; align-items:center");
								$(".lm_close_tab").css('top',((layoutObj.TITLE_HEIGHT_SETTING)/2 - 7));
								$(".lm_close_tab").css('margin-top',5);
								$(".lm_header").not('.tab_header').attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important; line-height:"+(layoutObj.TITLE_HEIGHT_SETTING - 7)+"px; z-index: inherit; display:flex; align-items:center;");
								$(".lm_tabs").attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important; line-height:"+(layoutObj.TITLE_HEIGHT_SETTING)+"px; display:flex; align-items:center;position:relative");
								$(".lm_controls").attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important; line-height:"+(layoutObj.TITLE_HEIGHT_SETTING)+"px; display:flex; align-items:center;");
								$(".lm_controls").find('li').not('.invisible').not('.lm_tabdropdown').attr("style", "display:flex; align-items:center;");
//								$(".lm_text").attr("style", "height:"+(layoutObj.TITLE_HEIGHT_SETTING-6)+"px !important;  display:flex; align-items:center");
//								$(".lm_header").attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important; display:flex; align-items:flex-end;");
//								$(".lm_tab").attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important;  display:flex; align-items:flex-end");
							}
							
						},
						main : function(layoutObj){
							if(layoutObj.TITLE_MAIN_FONT_SETTING) $(".lm_title").css("font-family", layoutObj.TITLE_MAIN_FONT_SETTING);
							if(layoutObj.TITLE_MAIN_FONTSIZE_SETTING){
								$(".lm_title").css("font-size", layoutObj.TITLE_MAIN_FONTSIZE_SETTING+"px");
//								$(".lm_header").attr("style", "height:"+(Number(layoutObj.TITLE_MAIN_FONTSIZE_SETTING)+30)+"px !important; display:flex; align-items:flex-end;");	
//								$(".lm_tab").attr("style", "height:"+(Number(layoutObj.TITLE_MAIN_FONTSIZE_SETTING)+30)+"px !important; display:flex; padding-left:10px; align-items:center");	
							}
							if(layoutObj.TITLE_MAIN_COLOR_SETTING) $(".lm_title").css("color", layoutObj.TITLE_MAIN_COLOR_SETTING); else $(".lm_title").css("color", "#6a6f7f");
							//20201112 AJKIM 통계 컨테이너 타이틀 크기 증가 및 X표시 제거 dogfoot
							if(gDashboard.reportType === 'StaticAnalysis'){
								$('.tab_cont_box_top_tit').not('[title="분석결과"]').attr("style", "height: 35px !important; line-height: 35px; display:flex; align-items:center;position:relative");
								$('.tab_cont_box_top_tit').not('[title="분석결과"]').find('.lm_title').css("font-size", "18px");
								$('.tab_cont_box_top_tit').not('[title="분석결과"]').parent().attr("style", "height:35px !important; line-height:25px; display:flex; align-items:center;position:relative");
								$($('.tab_cont_box_top_tit').not('[title="분석결과"]').parent().parent()[0]).attr("style", "height:35px !important; line-height:25px; display:flex; align-items:center;position:relative");
								$('.lm_items .lm_controls .lm_close').css("display", "none");
							}
						},
						serve : function(layoutObj){
							if(layoutObj.TITLE_SERVE_FONT_SETTING) $(".lm_text").css("font-family", layoutObj.TITLE_SERVE_FONT_SETTING);
							if(layoutObj.TITLE_SERVE_FONTSIZE_SETTING) $(".lm_text").css("font-size", layoutObj.TITLE_SERVE_FONTSIZE_SETTING+"px");
							if(layoutObj.TITLE_SERVE_COLOR_SETTING) $(".lm_text").css("color", layoutObj.TITLE_SERVE_COLOR_SETTING);
						}
					};
					
					var setFilter = {
						common : function(layoutObj){
							if(layoutObj.FILTER_D_SETTING!=""){
							    $(".condition-item-container").attr("style", "margin-right:"+layoutObj.FILTER_D_SETTING+"px");	
							}
							if(layoutObj.FILTER_RD_SETTING!="" && layoutObj.FILTER_LD_SETTING!=""){
							/*dogfoot shlim 20210415*/
								$(".condition-caption").css({
									'white-space': 'pre',
									'margin-left': layoutObj.FILTER_LD_SETTING+"px",
									'margin-right': layoutObj.FILTER_RD_SETTING+"px"
								});
								
								if($(".condition-caption").length > 0){
									$.each($(".condition-caption"), function(_i, _v){
										$.each(gDashboard.parameterFilterBar.parameterInformation, function(p_i, p_v){
											if(_v.innerText == p_v.PARAM_CAPTION && p_v.CAPTION_WIDTH_VISIBLE == 'Y'){
												//$(".condition-caption")[_i].css('width', p_v.CAPTION_WIDTH);
												$($(".condition-caption")[_i]).css('width', p_v.CAPTION_WIDTH);
											}
										})
									})
								}
							}	
							
						
							if(layoutObj.FILTER_HEIGHT_SETTING!=""){
								if($('.filter-bar').hasClass('on')){
									$("#filter-bar").css({
										"max-height" : "1000px",
										"height" : "auto"
									});
									
									//dogfoot 자산관리공사 필터 영역 4분할 syjin 20210826
									var kamkoWidth = 'auto';
									if(userJsonObject.siteNm == 'KAMKO'){
										kamkoWidth = '25%';
									}

									$.each($(".condition-item-container"),function(_i,_v){
										if($(_v).attr('paramVisible') === 'block'){
											$(_v).css({
												"max-height" : "1000px",
												"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
												"display" : "flex",
//												"flex-wrap" : "wrap",
												"align-items" : "center",											
												"width" : kamkoWidth
											});
										}else{
											$(_v).css({
												"max-height" : "1000px",
												"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
												"display" : "none",
//												"flex-wrap" : "wrap",
												"align-items" : "center",											
												"width" : kamkoWidth
											});
										}
									})
									$("#"+WISE.Constants.pid+"_paramContainer").css({
										"max-height" : "1000px",
										"height" : "auto",
										"display" : "flex",
										"flex-wrap" : "wrap",
										"align-items" : "center"
									});
								}else{
									$("#filter-bar").css({
										"max-height" : "1000px",
										/*2021-07-15 jhseo 현재 디폴트가 45px인데 DB에 40px, 60px, null, {} 이런식으로 저장되있어서 필터 높낮이가 천차만별임 일단 하드코딩으로 45로 고정*/
										"height" : "45px"
//										"height" : layoutObj.FILTER_HEIGHT_SETTING+"px"
									});
									/*dogfoot shlim 20210415*/
									if(gDashboard.isSingleView){
										if(gDashboard.reportType == "AdHoc"){
                                            $('#viewerAdhoc').css('right','16px')
											$('#viewerDownload').css('right','54px')
											$('#btn_query').css('right','89px')
										}else{
											$('#viewerDownload').css('right','16px')
											$('#btn_query').css('right','20px')
										}
									}else{
										$(".dataAttrArea").css({
											"margin-left":"7px",
											"margin-top":layoutObj.FILTER_HEIGHT_SETTING >= 40 ? layoutObj.FILTER_HEIGHT_SETTING - 40 : 0 +"px"
										});
									}

									
									var kamkoWidth = 'auto';
									if(userJsonObject.siteNm == 'KAMKO'){
										kamkoWidth = '25%';
									}
									
									$.each($(".condition-item-container"),function(_i,_v){
										if($(_v).attr('paramVisible') === 'block'){
											$(_v).css({
												"max-height" : "1000px",
												"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
												"display" : "flex",
//												"flex-wrap" : "wrap",
												"align-items" : "center",												
												"width" : kamkoWidth
											});
										}else{
											$(_v).css({
												"max-height" : "1000px",
												"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
												"display" : "none",
//												"flex-wrap" : "wrap",
												"align-items" : "center",												
												"width" : kamkoWidth
											});
										}
									})
									
									$("#"+WISE.Constants.pid+"_paramContainer").css({
										"max-height" : "1000px",
										"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
										"display" : "flex",
										"flex-wrap" : "wrap",
										"align-items" : "center"
									});
									
								}
								
							}
							
						},
						label : function(layoutObj){
							$(".condition-caption").css({
								"font-family" : layoutObj.FILTER_LABEL_FONT_SETTING,
								"font-size" : layoutObj.FILTER_LABEL_FONTSIZE_SETTING+"px",
								"color" : '#222',
								/*dogfoot shlim 20210419*/
								"white-space":"pre",/*dogfoot shlim 20210415*/
								"font-weight": "normal"
							});
						},
						data : function(layoutObj){
							/*dogfoot shlim 20210415*/
							$(".condition-item").not('.between-item').css({
								/*dogfoot shlim 보고서 레이아웃 설정 영역 수정 20200826*/													
								"border" : "solid 1px "+layoutObj.FILTER_DATA_BOCOLOR_SETTING
							});
							$("#"+WISE.Constants.pid+"_paramContainer").find(".dx-texteditor-input").css({
								"font-family" : layoutObj.FILTER_DATA_FONT_SETTING,
								"font-size" : layoutObj.FILTER_DATA_FONTSIZE_SETTING+"px",
//								"background": "url("+WISE.Constants.domain+"/editds/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
							})
							
							$(".betweencalendarBox").css({
								"font-family" : layoutObj.FILTER_DATA_FONT_SETTING,
								"font-size" : layoutObj.FILTER_DATA_FONTSIZE_SETTING+"px",
								"color" : '#222',
								"font-weight": "normal",
								"margin-top": "9px"
//								"background": "url("+WISE.Constants.domain+"/editds/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
							})
							
							$("#"+WISE.Constants.pid+"_paramContainer").find(".dx-texteditor-input").css({
								"font-family" : layoutObj.FILTER_DATA_FONT_SETTING,
								"color" : layoutObj.FILTER_DATA_COLOR_SETTING,
								"line-height" : "0px",
//								"background": "url("+WISE.Constants.domain+"/editds/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
							});
						}
					}
			}else{
				var setTitle = {
						common : function(layoutObj){
							if(layoutObj.TITLE_HEIGHT_SETTING) {
								/* DOGFOOT shlim 헤더영역 재설정 20200820 */
//								$(".lm_header").attr("style", "height:"+(layoutObj.TITLE_HEIGHT_SETTING)+"px !important;line-height:"+(Number(layoutObj.TITLE_HEIGHT_SETTING) - 7)+"px; z-index: inherit;  display:flex; align-items:center");
//								$(".lm_tabs").attr("style", "height:"+(layoutObj.TITLE_HEIGHT_SETTING)+"px !important; display:flex; align-items:center");
								$(".lm_close_tab").css('top',((layoutObj.TITLE_HEIGHT_SETTING)/2 - 7));
								$(".lm_close_tab").css('margin-top',5);
								$(".lm_header").not('.tab_header').attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important; line-height:"+(layoutObj.TITLE_HEIGHT_SETTING - 7)+"px; z-index: inherit; display:flex; align-items:center;");
								$(".lm_tabs").attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important; line-height:"+(layoutObj.TITLE_HEIGHT_SETTING)+"px; display:flex; align-items:center;position:relative");
								/*dogfoot shlim 보고서 레이아웃 설정 영역 수정 20200826*/													
								$(".lm_controls").attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important; line-height:"+(layoutObj.TITLE_HEIGHT_SETTING)*(2/3)+"px; display:flex; align-items:center;");
								/* DOGFOOT ktkang 리포트 다운로드 권한 구현  20201109 */
								if(gDashboard.structure.ReportMasterInfo.export_yn == 'N') {
									$.each($(".lm_controls").find('li').not('.invisible').not('.lm_tabdropdown'),function(_i,_v){
										if(typeof $(_v).attr('id') != 'undefined' && $(_v).attr('id').indexOf('_exp') > -1){
											$(_v).attr("style", "display:none; align-items:center;")
										}else{
											$(_v).attr("style", "display:flex; align-items:center;")
										}
									})
								} else {
									$(".lm_controls").find('li').not('.invisible').not('.lm_tabdropdown').attr("style", "display:flex; align-items:center;");
								}
//								$(".lm_text").attr("style", "height:"+(layoutObj.TITLE_HEIGHT_SETTING-6)+"px !important;  display:flex; align-items:center");
//								$(".lm_header").attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important; display:flex; align-items:flex-end;");
//								$(".lm_tab").attr("style", "height:"+layoutObj.TITLE_HEIGHT_SETTING+"px !important;  display:flex; align-items:flex-end");
							}

							
						},
						main : function(layoutObj){
							if(layoutObj.TITLE_MAIN_FONT_SETTING) $(".lm_title").css("font-family", layoutObj.TITLE_MAIN_FONT_SETTING);
							if(layoutObj.TITLE_MAIN_FONTSIZE_SETTING){
								$(".lm_title").css("font-size", layoutObj.TITLE_MAIN_FONTSIZE_SETTING+"px");
//								$(".lm_header").attr("style", "height:"+(Number(layoutObj.TITLE_MAIN_FONTSIZE_SETTING)+30)+"px !important; display:flex; align-items:flex-end;");	
//								$(".lm_tab").attr("style", "height:"+(Number(layoutObj.TITLE_MAIN_FONTSIZE_SETTING)+30)+"px !important; display:flex; padding-left:10px; align-items:center");	
							}
							if(layoutObj.TITLE_MAIN_COLOR_SETTING) $(".lm_title").css("color", layoutObj.TITLE_MAIN_COLOR_SETTING); else $(".lm_title").css("color", "#6a6f7f");
							
							//20201112 AJKIM 통계 컨테이너 타이틀 크기 증가 및 X표시 제거 dogfoot
							if(gDashboard.reportType === 'StaticAnalysis'){
								$('.tab_cont_box_top_tit').not('[title="분석결과"]').attr("style", "height: 35px !important; line-height: 35px; display:flex; align-items:center;position:relative");
								$('.tab_cont_box_top_tit').not('[title="분석결과"]').find('.lm_title').css("font-size", "18px");
								$('.tab_cont_box_top_tit').not('[title="분석결과"]').parent().attr("style", "height:35px !important; line-height:25px; display:flex; align-items:center;position:relative");
								$($('.tab_cont_box_top_tit').not('[title="분석결과"]').parent().parent()[0]).attr("style", "height:35px !important; line-height:25px; display:flex; align-items:center;position:relative");
								$('.lm_items .lm_controls .lm_close').css("display", "none");
							}
						},
						serve : function(layoutObj){
							if(layoutObj.TITLE_SERVE_FONT_SETTING) $(".lm_text").css("font-family", layoutObj.TITLE_SERVE_FONT_SETTING);
							if(layoutObj.TITLE_SERVE_FONTSIZE_SETTING) $(".lm_text").css("font-size", layoutObj.TITLE_SERVE_FONTSIZE_SETTING+"px");
							if(layoutObj.TITLE_SERVE_COLOR_SETTING) $(".lm_text").css("color", layoutObj.TITLE_SERVE_COLOR_SETTING);
						}
					};
					
					var setFilter = {
						common : function(layoutObj){
//							$(".condition-item-container").css({
//								"margin-left" : layoutObj.FILTER_D_SETTING==0?layoutObj.FILTER_LD_SETTING:layoutObj.FILTER_D_SETTING+"px",
//								"margin-right" : layoutObj.FILTER_D_SETTING==0?layoutObj.FILTER_RD_SETTING:layoutObj.FILTER_D_SETTING+"px",
//								//"margin" : filterD+"px"
//							});
							
							if(layoutObj.FILTER_D_SETTING!=""){
							    $(".condition-item-container").attr("style", "margin-right:"+layoutObj.FILTER_D_SETTING+"px");	
							}
							if(layoutObj.FILTER_RD_SETTING!="" && layoutObj.FILTER_LD_SETTING!=""){
							/*dogfoot shlim 20210415*/
							    $(".condition-caption").attr("style", "white-space:pre;margin-left:"+layoutObj.FILTER_LD_SETTING+"px; margin-right:"+layoutObj.FILTER_RD_SETTING+"px");
							    
							    if($(".condition-caption").length > 0){
									$.each($(".condition-caption"), function(_i, _v){
										$.each(gDashboard.parameterFilterBar.parameterInformation, function(p_i, p_v){
											if(_v.innerText == p_v.PARAM_CAPTION && p_v.CAPTION_WIDTH_VISIBLE == 'Y'){
												//$(".condition-caption")[_i].css('width', p_v.CAPTION_WIDTH);
												$($(".condition-caption")[_i]).css('width', p_v.CAPTION_WIDTH);
											}
										})
									})
								}
							}	
							
						
							if(layoutObj.FILTER_HEIGHT_SETTING!=""){
								if($('.filter-bar').hasClass('on')){
//									$("#filter-bar").css({
//										"max-height" : "1000px",
//										"height" : layoutObj.FILTER_HEIGHT_SETTING+"px"
//									});
//									$(".filter-row").css({
//										"max-height" : "1000px",
//										"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
//										"display" : "flex",
//										"flex-wrap" : "wrap",
//										"align-items" : "center"
//									});
									$("#filter-bar").css({
										"max-height" : "1000px",
										"height" : "auto"
									});
									var kamkoWidth = 'auto';
									if(userJsonObject.siteNm == 'KAMKO'){
										kamkoWidth = '25%';
									}
									
									$.each($(".condition-item-container"),function(_i,_v){
										if($(_v).attr('paramVisible') === 'block'){
											$(_v).css({
												"max-height" : "1000px",
												"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
												"display" : "flex",
//												"flex-wrap" : "wrap",
												"align-items" : "center",												
												"width" : kamkoWidth
											});
										}else{
											$(_v).css({
												"max-height" : "1000px",
												"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
												"display" : "none",
//												"flex-wrap" : "wrap",
												"align-items" : "center",												
												"width" : kamkoWidth
											});
										}
									})
									$(".filter-item").css({
										"max-height" : "1000px",
										"height" : "auto",
										"display" : "flex",
										"flex-wrap" : "wrap",
										"align-items" : "center",
										/* goyong ktkang 디자인 수정  20210513 */
										"padding" : "0px 9px"
									});
								}else{
									$("#filter-bar").css({
										"max-height" : "1000px",
										"height" : layoutObj.FILTER_HEIGHT_SETTING+"px"
									});
//									$(".condition-item-container").css({
//										"max-height" : "1000px",
//										"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
//										"display" : "flex",
//										"flex-wrap" : "wrap",
//										"align-items" : "center"
//									});
									
									var kamkoWidth = 'auto';
									if(userJsonObject.siteNm == 'KAMKO'){
										kamkoWidth = '25%';
									}
									
									$.each($(".condition-item-container"),function(_i,_v){
										if($(_v).attr('paramVisible') === 'block'){
											$(_v).css({
												"max-height" : "1000px",
												"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
												"display" : "flex",
//												"flex-wrap" : "wrap",
												"align-items" : "center",												
												"width" : kamkoWidth
											});
										}else{
											$(_v).css({
												"max-height" : "1000px",
												"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
												"display" : "none",
//												"flex-wrap" : "wrap",
												"align-items" : "center",												
												"width" : kamkoWidth
											});
										}
									})
									
									$(".filter-item").css({
										"max-height" : "1000px",
										"height" : layoutObj.FILTER_HEIGHT_SETTING+"px",
										"display" : "flex",
										"flex-wrap" : "wrap",
										"align-items" : "center",
										/* goyong ktkang 디자인 수정  20210513 */
										"padding" : "0px 9px"
									});
								}

							}
						},
						label : function(layoutObj){
							$(".condition-caption").css({
								"font-family" : layoutObj.FILTER_LABEL_FONT_SETTING,
								"font-size" : layoutObj.FILTER_LABEL_FONTSIZE_SETTING+"px",
								"color" : '#222',
								"white-space":"pre",/*dogfoot shlim 20210415*/
								"font-weight": "normal"
							});
						},
						data : function(layoutObj){
						/*dogfoot shlim 20210415*/
							$(".condition-item").not('.between-item').css({	
							/*dogfoot shlim 보고서 레이아웃 설정 영역 수정 20200826*/																								
								"border" : "solid 1px "+layoutObj.FILTER_DATA_BOCOLOR_SETTING
							});
							$(".filter-item .dx-texteditor-input").css({
								"font-family" : layoutObj.FILTER_DATA_FONT_SETTING,
								"font-size" : layoutObj.FILTER_DATA_FONTSIZE_SETTING+"px",
								"color" : '#222',
								"font-weight": "normal"
//								"background": "url("+WISE.Constants.domain+"/editds/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
							})
							
							$(".betweencalendarBox").css({
								"font-family" : layoutObj.FILTER_DATA_FONT_SETTING,
								"font-size" : layoutObj.FILTER_DATA_FONTSIZE_SETTING+"px",
								"color" : '#222',
								"font-weight": "normal",
								//"margin-top": "9px"
//								"background": "url("+WISE.Constants.domain+"/editds/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
							})
							
							$(".filter-item .dx-texteditor-container>.dx-texteditor-input").css({
								"font-family" : layoutObj.FILTER_DATA_FONT_SETTING,
								"color" : '#222',
								"font-weight": "normal",
								"line-height" : "0px",
//								"background": "url("+WISE.Constants.domain+"/editds/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
							});
						}
					}
			}
			
			//보고서 작성할 때
			
			//보고서 불러오기 할 때
			if(WISE.Constants.editmode === 'viewer'){
				if(typeof gDashboard.layoutConfig[WISE.Constants.pid]!='undefined' && gDashboard.layoutConfig[WISE.Constants.pid] !=""
					&& gDashboard.layoutConfig[WISE.Constants.pid] !="\"\"" && Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0){
					setFilter.common(gDashboard.layoutConfig[WISE.Constants.pid]);
					setFilter.label(gDashboard.layoutConfig[WISE.Constants.pid]);
					setFilter.data(gDashboard.layoutConfig[WISE.Constants.pid]);	
					setTitle.common(gDashboard.layoutConfig[WISE.Constants.pid]);
					setTitle.main(gDashboard.layoutConfig[WISE.Constants.pid]);
					setTitle.serve(gDashboard.layoutConfig[WISE.Constants.pid]);
				}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){
					setFilter.common(userJsonObject.layoutConfig);
					setFilter.label(userJsonObject.layoutConfig);
					setFilter.data(userJsonObject.layoutConfig);
					setTitle.common(userJsonObject.layoutConfig);
					setTitle.main(userJsonObject.layoutConfig);
					setTitle.serve(userJsonObject.layoutConfig);
				}
			}else{
				if(typeof gDashboard.layoutConfig!='undefined' && gDashboard.layoutConfig !="" 
					&& gDashboard.layoutConfig !="\"\"" && Object.keys(gDashboard.layoutConfig).length != 0){
					setFilter.common(gDashboard.layoutConfig);
					setFilter.label(gDashboard.layoutConfig);
					setFilter.data(gDashboard.layoutConfig);	
					setTitle.common(gDashboard.layoutConfig);
					setTitle.main(gDashboard.layoutConfig);
					setTitle.serve(gDashboard.layoutConfig);
				}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){
					setFilter.common(userJsonObject.layoutConfig);
					setFilter.label(userJsonObject.layoutConfig);
					setFilter.data(userJsonObject.layoutConfig);
					setTitle.common(userJsonObject.layoutConfig);
					setTitle.main(userJsonObject.layoutConfig);
					setTitle.serve(userJsonObject.layoutConfig);
				}
			}
			
			
//			if(gDashboard.goldenLayoutManager.canvasLayout){
//	        	$('.panel.cont').css('height', 'calc(100vh - ' + (84 + ($('.filter-bar').height() < 40? 40 : $('.filter-bar').height())) + 'px)')
//	            gDashboard.goldenLayoutManager.canvasLayout.updateSize($('.panel.cont').width());
//	        }
    }
    
    this.render = function(item, isAdhoc, reportId) {
    	// GoldenLayout is uninitialized
    	if (self.canvasLayout == undefined) {
			self.init(item, isAdhoc, reportId);
        }
    	// Add container
    	else if (item === 'container') {
    		self.addContainerItem();
    	}
    	// Add item
    	else {
    		self.addDashboardItem(item);
        }
    };
    /*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
    this.aysRender = function(item, isAdhoc, reportId,type,tabTitle) {
    	// GoldenLayout is uninitialized
    	if (self.canvasLayout == undefined) {
			self.init(item, isAdhoc, reportId,type,tabTitle);
			/*dogfoot 통계분석 그리드 분할 추가 shlim 20201111*/
			self.containerItemNozero=0;
    	}
    	else if (item === 'container') {
    		self.addAysContainerItem();
    	}
    	else if (type === 'AysItem') {
    		self.addAysContainerItem(item, isAdhoc, reportId,type,tabTitle);
        }
    	// Add item
    	else {
    		self.addDashboardItem(item);
        }
        
    	
    };
    /*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
    /*dogfoot 통계분석 그리드 분할 추가 shlim 20201111*/
    this.setAysItem = function(itemList,_listType) {
    	/*dogfoot 한 컨테이너 안에 아이템 여러개 생성 생성 shlim 20201021*/
    	var gLayoutItemList = [],gLayoutItemArray=[],returnArr;
    	if(typeof self.containerItemNozero === 'undefined'){
    		self.containerItemNozero = 0;
    	}
    	if(_listType && _listType=="inContainer"){
    		var containerChk = false;
	    	$.each(WISE.util.Object.toArray(itemList),function(_i,_item){
	    		if(typeof _item.ComponentName == 'undefined' && _item.length > 0){
	    			var gLayoutItemConList=[];gLayoutItemArrCon = [];
	    			$.each(WISE.util.Object.toArray(_item),function(_j,_inItem){
	    				gLayoutItemArrCon.push({
							type: 'column',
							contentId: _inItem.ComponentName,
							nTabHdVisible:false,
							hasHeaders: false,
							reorderEnabled : false,
							content: [{
								type: 'component',
								componentName: 'dashboardItem',
								id: _inItem.ComponentName + self.reportIdSuffix,
								componentState: { item: _inItem.ComponentName + self.reportIdSuffix },
								title: _inItem.Name + '',
								nTabHdVisible:false,
								hasHeaders: false,
								reorderEnabled : false,
								isClosable: false,
								constrainDragToContainer: false,
							}]
						})
	    			})
	    			
	    			self.containerItemNozero++;
					var tabConfig = {
						type: 'column',
						id: 'container',
						title: '분석결과 ',
						name: 'dashboardTabPage' + self.containerItemNozero,
						number: self.containerItemNozero,
						/*dogfoot 컨테이너/아이템 헤더 구분 기능 추가 shlim 20200918*/
						nTabHdVisible:false,
						hasHeaders: false,
						reorderEnabled : false,
						constrainDragToContainer: true,
						content: gLayoutItemArrCon
					};
					gLayoutItemArray.push(tabConfig);
	    		}else{
	    		    gLayoutItemArray.push({
						type: 'component',
						componentName: 'dashboardItem',
						id: _item.ComponentName + self.reportIdSuffix,
						componentState: { item: _item.ComponentName + self.reportIdSuffix },
						title: _item.Name + '',
						nTabHdVisible:true,
						reorderEnabled : false,
					})	
	    		}
	    		
	    	})
	    	
	    	gLayoutItemList.push({
				type: 'stack',
				enableHeaderDrop: true,
				id:"container",
				content: gLayoutItemArray,
				nTabHdVisible:true,
				reorderEnabled : false,
			})
	    	returnArr = gLayoutItemList; 
        }else{
        	$.each(WISE.util.Object.toArray(itemList),function(_i,_item){
	    		gLayoutItemArray.push({
	                type: 'component',
	                componentName: 'dashboardItem',
	                id: _item.ComponentName + self.reportIdSuffix,
	                componentState: { item: _item.ComponentName + self.reportIdSuffix },
					title: _item.Name + '',
					nTabHdVisible:true,
					reorderEnabled : false,
	            })
	    	})
	    	gLayoutItemList.push({
				type: 'stack',
				enableHeaderDrop: true,
				id:"container",
	            content: gLayoutItemArray,
	          nTabHdVisible:true,
	          reorderEnabled : false,
	        })
	        returnArr = gLayoutItemList;
        }
        
    	return returnArr;
    };
    /**
     * Initialize golden layout instance for an opened report.
     */
    this.openInit = function(item) {
    	self.init('open');
    }

    /**
     * Clear GoldenLayout instance.
     */
    this.clear = function() {
		if (typeof self.canvasLayout !== 'undefined') {
			self.canvasLayout.destroy();
			self.canvasLayout = undefined;
		}
		self.layoutIndex = 0;
    	self.containerItemNo = 1;
    };
    
    /**
     * Add dashboard item to GoldenLayout instance. 
     */
    this.addDashboardItem = function(item) {
    	var base = self.canvasLayout.root.contentItems[0];
    	var config = {
    		type: 'stack',
    		contentId: item.ComponentName + self.reportIdSuffix,
    		content: [{
    			type: 'component',
                componentName: 'dashboardItem',
                id: item.ComponentName + self.reportIdSuffix,
                componentState: { item: item.ComponentName + self.reportIdSuffix },
                /* 개발 hsshim 1209 */
    			title: item.Name + '',
    		}]
    	};
    	// layout is empty
    	if (!base) {
    		self.clear();
    		self.init(item);
    	}
    	// only one item in root stack
    	else if (!base.isRow && !base.isColumn) {
    		var rowOrColumn = self.canvasLayout.createContentItem( { type: 'row' }, base );
    		self.canvasLayout.root.replaceChild( base, rowOrColumn );
    		var newBase = self.canvasLayout.root.contentItems[0];
    		newBase.addChild(base);
    		newBase.config.width = 50;
    		config.width = 50;
    		newBase.addChild(config);
    		rowOrColumn.callDownwards( 'setSize' );
    	}
    	// multiple items in root stack
    	else {
    		base.addChild(config);
    	}
    };
    
    /**
     * Add container item to GoldenLayout instance.
     */
    this.addContainerItem = function() {
		var base = self.canvasLayout.root.contentItems[0];
		/* DOGFOOT hsshim 2020-01-23 텝 컨테이너 추가하는 기능 개선 */
		var tabConfig = {
			type: 'stack',
			id: 'container',
			title: '컨테이너 ' + self.containerItemNo,
			name: 'dashboardTabPage' + self.containerItemNo,
			number: self.containerItemNo,
			/*dogfoot 컨테이너/아이템 헤더 구분 기능 추가 shlim 20200918*/
			nTabHdVisible:true,
			hasHeaders: false
		};
    	var config = {
    		type: 'stack',
			enableHeaderDrop: true,
			name: 'tabContainerDashboardItem' + self.containerItemNo,
			number: self.containerItemNo,
    		content: [tabConfig]
    	};
    	/* DOGFOOT hsshim 2020-01-23 끝 */
    	// layout is empty
    	if (!base) {
    		self.clear();
    		self.init();
		}
		/* DOGFOOT hsshim 2020-01-23 텝 컨테이너 추가하는 기능 개선 */
		// if tab container exists, add tab to container
		else if (self.selectedTabContainer != undefined) {
			self.selectedTabContainer.addChild(tabConfig);
		}
    	// only one item in root stack
    	else if (!base.isRow && !base.isColumn) {
    		var rowOrColumn = self.canvasLayout.createContentItem( { type: 'row' }, base );
    		self.canvasLayout.root.replaceChild( base, rowOrColumn );
    		var newBase = self.canvasLayout.root.contentItems[0];
    		newBase.addChild(base);
    		newBase.addChild(config);
    	}
    	// multiple items in root stack
    	else {
    		base.addChild(config);
    	}
    	self.containerItemNo++;
    };
    /*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
    this.addAysContainerItem = function(item, isAdhoc, reportId,type,tabTitle) {
		var base = self.canvasLayout.root.contentItems[0];
		/* DOGFOOT hsshim 2020-01-23 텝 컨테이너 추가하는 기능 개선 */
		var tabConfig = {
			type: 'stack',
			id: 'container',
			title: tabTitle,
			name: 'dashboardTabPage' + self.containerItemNo,
			number: self.containerItemNo,
			/*dogfoot 컨테이너/아이템 헤더 구분 기능 추가 shlim 20200918*/
			nTabHdVisible:true,
			hasHeaders: false,
			constrainDragToContainer: true,
			content: item
		};
    	var config = {
    		type: 'stack',
			enableHeaderDrop: true,
			name: 'tabContainerDashboardItem' + self.containerItemNo,
			number: self.containerItemNo,
    		content: [tabConfig],
    		cnType : 'container'
    	};
    	/* DOGFOOT hsshim 2020-01-23 끝 */
    	// layout is empty
    	if (!base) {
    		self.clear();
    		self.init(item, isAdhoc, reportId,type,tabTitle);
		}
		/* DOGFOOT hsshim 2020-01-23 텝 컨테이너 추가하는 기능 개선 */
		// if tab container exists, add tab to container
		else if (self.selectedTabContainer != undefined) {
			self.selectedTabContainer.addChild(tabConfig);
			self.containerItemNo++;
		}
    	// only one item in root stack
    	else if (!base.isRow && !base.isColumn) {
    		var rowOrColumn = self.canvasLayout.createContentItem( { type: 'row' }, base );
    		self.canvasLayout.root.replaceChild( base, rowOrColumn );
    		var newBase = self.canvasLayout.root.contentItems[0];
    		newBase.addChild(base);
    		newBase.addChild(config);
    		self.containerItemNo++;
    	}
    	// multiple items in root stack
    	else {
    		base.addChild(config);
    		self.containerItemNo++;
    	}
    	
    };
    
    /**
     * Render golden layout contents with current dashboard settings.
     */
    this.renderLayout = function(_layoutStructure, _layoutObject, _sortItemList) {
    	// vertical or horizontal layout
		var layoutType;
		switch(_layoutStructure.Orientation) {
			case 'Vertical':
				layoutType = 'column';
				break;
			case 'Horizontal':
				layoutType = 'row';
				break;
			default:
				/*DOGFOOT cshan 20200113 - 특정 대시보드 배치에 레이아웃이 깨지는 현상 수정*/
				if(_layoutStructure.LayoutGroup != null){
					var layoutDecision = WISE.util.Object.toArray(_layoutStructure.LayoutGroup);
					if(layoutDecision[0].Orientation == 'Vertical'){
						layoutType = 'column';
					}else{
						layoutType = 'row';
					}
				}else{
					layoutType = 'row';
				}
				break;
		}
		/* DOGFOOT ktkang 모바일일 때 뷰어 수정  20200813 */
		if($("html").hasClass("mobile")) {
			layoutType = 'column';
		}
    	for (var i = 0; i < _sortItemList.length; i++) {
    		// object has LayoutTabContainer
    		if (typeof _layoutStructure.LayoutTabContainer !== 'undefined') {
    			$.each(WISE.util.Object.toArray(_layoutStructure.LayoutTabContainer), function(j, _container) {
    				if (self.layoutIndex < _sortItemList.length && _container.DashboardItem === _sortItemList[self.layoutIndex].itemID) {
						var containerNum = parseInt(_container.DashboardItem.replace('tabContainerDashboardItem', ''));
						var newLayoutObj = { 
							type: 'stack',
							enableHeaderDrop: true,
							name: _container.DashboardItem + self.reportIdSuffix,
							number: containerNum,
							content: [] 
						};
						if (layoutType == 'column') {
							newLayoutObj.width = _container.Weight == undefined ? 100 : Number(_container.Weight);
						} else if (layoutType === 'row') {
							newLayoutObj.height = _container.Weight == undefined ? 100 : Number(_container.Weight);
						}
						self.layoutIndex++;
						// recursive call for each tab in container
						$.each(WISE.util.Object.toArray(_container.LayoutTabPage), function(k, _tab) {
							if (self.layoutIndex < _sortItemList.length && _tab.DashboardItem === _sortItemList[self.layoutIndex].itemID) {
								var tabNum = parseInt(_tab.DashboardItem.replace('dashboardTabPage', ''));
								var tabStructure = { 
									type: 'stack',
									id: 'container',
									title: self.getContainerTabTitle(_tab.DashboardItem),
									name: _tab.DashboardItem + self.reportIdSuffix,
									number: tabNum,
									/*dogfoot 컨테이너/아이템 헤더 구분 기능 추가 shlim 20200918*/
									nTabHdVisible:true,
									hasHeaders: false,
									content: []
								};
								var tabItemStructure = { type: layoutType, content: [] };
								self.layoutIndex++;
								tabItemStructure = self.renderLayout(_tab, tabItemStructure, _sortItemList);
								$.each(tabItemStructure.content, function(j, _tabItem) {
									tabStructure.content.push(_tabItem);
								});
								newLayoutObj.content.push(tabStructure);
								if (self.containerItemNo <= tabNum) {
									self.containerItemNo = tabNum + 1;
								}
							}
						});
						if (typeof _layoutObject === 'undefined') {
							_layoutObject = newLayoutObj;
						} else {
							_layoutObject.content.push(newLayoutObj);
						}
					}
    			});
    		}
    		// object has LayoutGroup
    		if (typeof _layoutStructure.LayoutGroup !== 'undefined') {
    			$.each(WISE.util.Object.toArray(_layoutStructure.LayoutGroup), function(j,_grp) {
    				// get contents of each object in LayoutGroup
    				var newLayoutObj = { type: layoutType, content: [] };
    				newLayoutObj = self.renderLayout(_grp, newLayoutObj, _sortItemList);
    				// add weights and push contents if they exist
    				if (newLayoutObj.content.length !== 0) {
    					if (newLayoutObj.type == 'column') {
    						newLayoutObj.width = _grp.Weight == undefined ? 100 : Number(_grp.Weight);
    					} else if (newLayoutObj.type === 'row') {
    						newLayoutObj.height = _grp.Weight == undefined ? 100 : Number(_grp.Weight);
    					}
    					if (typeof _layoutObject === 'undefined') {
							_layoutObject = newLayoutObj;
						} else {
							_layoutObject.content.push(newLayoutObj);
						}
    				}
    			});
    		}
    		// object has LayoutItem
    		if (typeof _layoutStructure.LayoutItem !== 'undefined') {
    			$.each(WISE.util.Object.toArray(_layoutStructure.LayoutItem), function(j, _layoutItem) {
    				var Component;
    				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(k, _item) {
    					if (self.layoutIndex < _sortItemList.length) {
	    					if (_layoutItem.DashboardItem === _item.meta.ComponentName && _layoutItem.DashboardItem === _sortItemList[self.layoutIndex].itemID) {
	    						Component =  {
	    							type: 'stack',
	    							contentId: _item.meta.ComponentName + self.reportIdSuffix,
	    							content: [{
	    								type: 'component', 
	    								componentName: 'dashboardItem', 
	    								id: _item.meta.ComponentName + self.reportIdSuffix, 
	    								componentState: { item: _item.meta.ComponentName + self.reportIdSuffix }, 
	    								/* 개발 hsshim 1209 */
	    								title: _item.itemNm + '',
	    							}]
								};
								if (typeof _layoutObject === 'undefined') {
									_layoutObject = Component;
								} else {
									if (layoutType === 'column') {
										_layoutObject.type = 'column';
										Component.height = _layoutItem.Weight == undefined ? 100 : Number(_layoutItem.Weight);
										if($("html").hasClass("mobile")) {
											Component.height = 100 / _sortItemList.length;
										}
									} else if (layoutType === 'row') {
										_layoutObject.type = 'row';
										Component.width = _layoutItem.Weight == undefined ? 100 : Number(_layoutItem.Weight);
									}
									_layoutObject.content.push(Component);
								}
	    						self.layoutIndex++;
	    						return false;
	    					}
    					}
    				});
    			});
    		}
    	}
    	return _layoutObject;
	}
	
	/*dogfoot 통계분석 그리드 분할 추가 shlim 20201111*/
    this.renderAysLayout = function(_layoutStructure, _layoutObject, _sortItemList) {
    	// vertical or horizontal layout
    	var layoutType;
    	switch(_layoutStructure.Orientation) {
    	case 'Vertical':
    		layoutType = 'column';
    		break;
    	case 'Horizontal':
    		layoutType = 'row';
    		break;
    	default:
    		/*DOGFOOT cshan 20200113 - 특정 대시보드 배치에 레이아웃이 깨지는 현상 수정*/
    		if(_layoutStructure.LayoutGroup != null){
    			var layoutDecision = WISE.util.Object.toArray(_layoutStructure.LayoutGroup);
    			if(layoutDecision[0].Orientation == 'Vertical'){
    				layoutType = 'column';
    			}else{
    				layoutType = 'row';
    			}
    		}else{
    			layoutType = 'row';
    		}
    	break;
    	}
    	/* DOGFOOT ktkang 모바일일 때 뷰어 수정  20200813 */
    	if($("html").hasClass("mobile")) {
    		layoutType = 'column';
    	}
    	for (var i = 0; i < _sortItemList.length; i++) {
    		// object has LayoutTabContainer
    		if (typeof _layoutStructure.LayoutTabContainer !== 'undefined') {
    			$.each(WISE.util.Object.toArray(_layoutStructure.LayoutTabContainer), function(j, _container) {
    				if (self.layoutIndex < _sortItemList.length && _container.DashboardItem === _sortItemList[self.layoutIndex].itemID) {
    					var containerNum = parseInt(_container.DashboardItem.replace('tabContainerDashboardItem', ''));
    					var newLayoutObj = { 
    							type: 'stack',
    							enableHeaderDrop: true,
    							name: _container.DashboardItem + self.reportIdSuffix,
    							number: containerNum,
    							content: [] 
    					};
    					if (layoutType == 'column') {
    						newLayoutObj.width = _container.Weight == undefined ? 100 : Number(_container.Weight);
    					} else if (layoutType === 'row') {
    						newLayoutObj.height = _container.Weight == undefined ? 100 : Number(_container.Weight);
    					}
    					self.layoutIndex++;
    					// recursive call for each tab in container
    					$.each(WISE.util.Object.toArray(_container.LayoutTabPage), function(k, _tab) {
    						if (self.layoutIndex < _sortItemList.length && _tab.DashboardItem === _sortItemList[self.layoutIndex].itemID) {
    							var tabNum = parseInt(_tab.DashboardItem.replace('dashboardTabPage', ''));
    							var tabStructure = { 
    									type: 'stack',
    									id: 'container',
    									title: self.getContainerTabTitle(_tab.DashboardItem),
    									name: _tab.DashboardItem + self.reportIdSuffix,
    									number: tabNum,
    									/*dogfoot 컨테이너/아이템 헤더 구분 기능 추가 shlim 20200918*/
    									nTabHdVisible:true,
    									hasHeaders: false,
//    									reorderEnabled : false,
    									content: []
    							};
    							var tabItemStructure = { type: layoutType, content: [] };
    							self.layoutIndex++;
    							tabItemStructure = self.renderAysLayout(_tab, tabItemStructure, _sortItemList);
    							$.each(tabItemStructure.content, function(j, _tabItem) {
    								tabStructure.content.push(_tabItem);
    							});
    							newLayoutObj.content.push(tabStructure);
    							if (self.containerItemNo <= tabNum) {
    								self.containerItemNo = tabNum + 1;
    							}
    						}
    					});
    					if (typeof _layoutObject === 'undefined') {
    						_layoutObject = newLayoutObj;
    					} else {
    						_layoutObject.content.push(newLayoutObj);
    					}
    				}
    			});
    		}
    		// object has LayoutGroup
    		if (typeof _layoutStructure.LayoutGroup !== 'undefined') {
    			if(typeof _layoutStructure.LayoutGroup.LayoutItem !== 'undefined'){
    				$.each(WISE.util.Object.toArray(_layoutStructure.LayoutGroup), function(j,_grp) {
						// get contents of each object in LayoutGroup
	//    				var newLayoutObj = { type: layoutType, content: [] };
						var newLayoutObj ={
								type: 'stack',
								enableHeaderDrop: true,
								id:"container",
								reorderEnabled : false,
								content:[]
							};
						newLayoutObj = self.renderAysLayout(_grp, newLayoutObj, _sortItemList);
						// add weights and push contents if they exist
						if (newLayoutObj.content.length !== 0) {
							if (newLayoutObj.type == 'column') {
								newLayoutObj.width = _grp.Weight == undefined ? 100 : Number(_grp.Weight);
							} else if (newLayoutObj.type === 'row') {
								newLayoutObj.height = _grp.Weight == undefined ? 100 : Number(_grp.Weight);
							}
							if (typeof _layoutObject === 'undefined') {
								_layoutObject = newLayoutObj;
							} else {
								_layoutObject.content.push(newLayoutObj);
							}
						}
					});
    			}else{

    				
					
					var gLayoutItemArray =[] , gLayoutItemList=[];
    				$.each(WISE.util.Object.toArray(_layoutStructure.LayoutGroup.LayoutGroup), function(j,_grp) {
						// get contents of each object in LayoutGroup
	//    				var newLayoutObj = { type: layoutType, content: [] };
						var newLayoutObj ={
								type: 'stack',
								enableHeaderDrop: true,
								id:"container",
								reorderEnabled : false,
								content:[]
							};
						newLayoutObj = self.renderAysLayout(_grp, newLayoutObj, _sortItemList);
						
						if(newLayoutObj.content.length > 1){
							var gLayoutItemConList=[],gLayoutItemArrCon = [];
							$.each(newLayoutObj.content,function(_j,_inItem){
								gLayoutItemArrCon.push({
									type: 'column',
									contentId: _inItem.id,
									nTabHdVisible:false,
									hasHeaders: false,
									reorderEnabled : false,
									content: [{
										type: 'component',
										componentName: 'dashboardItem',
										id: _inItem.id,
										componentState: _inItem.componentState,
										title: _inItem.title + '',
										nTabHdVisible:false,
										hasHeaders: false,
										reorderEnabled : false,
										isClosable: false,
										constrainDragToContainer: false,
									}]
								})
							})
							
							var tabConfig = {
								type: 'column',
								id: 'container',
								title: '분석결과',
								name: 'dashboardTabPage' + self.containerItemNozero,
								number: self.containerItemNozero,
								/*dogfoot 컨테이너/아이템 헤더 구분 기능 추가 shlim 20200918*/
								nTabHdVisible:false,
								hasHeaders: false,
								reorderEnabled : false,
								constrainDragToContainer: true,
								content: gLayoutItemArrCon
							};
							gLayoutItemArray.push(tabConfig);
						}else{
							if(newLayoutObj.content.length != 0){
								$.each(newLayoutObj.content[0].content,function(_j,_inItem){
									gLayoutItemArray.push({
										type: 'component',
										componentName: 'dashboardItem',
										id: _inItem.id,
										componentState: _inItem.componentState,
										title: _inItem.title + '',
										nTabHdVisible:false,
										hasHeaders: false,
										reorderEnabled : false,
									})
								})
                            }
							
                           
						}
						// add weights and push contents if they exist
						
					});
					gLayoutItemList.push({
						type: 'stack',
						enableHeaderDrop: true,
						id:"container",
						content: gLayoutItemArray,
						nTabHdVisible:true,
						reorderEnabled : false,
					})
					if (gLayoutItemList[0].content.length !== 0) {
							
							_layoutObject.content.push(gLayoutItemList[0]);
					}
    			}	
    		}
    		// object has LayoutItem
    		if (typeof _layoutStructure.LayoutItem !== 'undefined') {
    			$.each(WISE.util.Object.toArray(_layoutStructure.LayoutItem), function(j, _layoutItem) {
    				if(WISE.util.Object.toArray(_layoutStructure.LayoutItem).length == 1){
    					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(k, _item) {
        					if (self.layoutIndex < _sortItemList.length) {
        						if (_layoutItem.DashboardItem === _item.meta.ComponentName && _layoutItem.DashboardItem === _sortItemList[self.layoutIndex].itemID) {
        							Component =  {
        									type: 'stack',
        	    							contentId: _item.meta.ComponentName + self.reportIdSuffix,
        	    							content: [{
        	    								type: 'component', 
        	    								componentName: 'dashboardItem', 
        	    								id: _item.meta.ComponentName + self.reportIdSuffix, 
        	    								componentState: { item: _item.meta.ComponentName + self.reportIdSuffix },
        	    								reorderEnabled : false,
        	    								/* 개발 hsshim 1209 */
        	    								title: _item.itemNm + '',
        	    							}],
        									reorderEnabled : false,
        							};
        							if (typeof _layoutObject === 'undefined') {
        								_layoutObject = Component;
        							} else {
        								if (layoutType === 'column') {
        									_layoutObject.type = 'column';
        									Component.height = _layoutItem.Weight == undefined ? 100 : Number(_layoutItem.Weight);
        									if($("html").hasClass("mobile")) {
        										Component.height = 100 / _sortItemList.length;
        									}
        								} else if (layoutType === 'row') {
        									_layoutObject.type = 'stack';
        									Component.width = _layoutItem.Weight == undefined ? 100 : Number(_layoutItem.Weight);
        								}
        								_layoutObject.content.push(Component);
        							}
        							self.layoutIndex++;
        							return false;
        						}
        					}
        				});
    					
    				}else{
    					var Component;
        				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(k, _item) {
        					if (self.layoutIndex < _sortItemList.length) {
        						if (_layoutItem.DashboardItem === _item.meta.ComponentName && _layoutItem.DashboardItem === _sortItemList[self.layoutIndex].itemID) {
        							Component =  {
    										type: 'component', 
    										componentName: 'dashboardItem', 
    										id: _item.meta.ComponentName + self.reportIdSuffix, 
    										componentState: { item: _item.meta.ComponentName + self.reportIdSuffix }, 
    										/* 개발 hsshim 1209 */
    										title: _item.itemNm + '',
    										reorderEnabled : false,
        							};
        							if (typeof _layoutObject === 'undefined') {
        								_layoutObject = Component;
        							} else {
        								if (layoutType === 'column') {
        									_layoutObject.type = 'column';
        									Component.height = _layoutItem.Weight == undefined ? 100 : Number(_layoutItem.Weight);
        									if($("html").hasClass("mobile")) {
        										Component.height = 100 / _sortItemList.length;
        									}
        								} else if (layoutType === 'row') {
        									_layoutObject.type = 'stack';
        									Component.width = _layoutItem.Weight == undefined ? 100 : Number(_layoutItem.Weight);
        								}
        								_layoutObject.content.push(Component);
        							}
        							self.layoutIndex++;
        							return false;
        						}
        					}
        				});
    				}
    			});
    		}
    	}
    	return _layoutObject;
    }
	
	/**
	 * Helper function for renderLayout(). Get a container tab's caption from LAYOUT_XML.
	 */
	this.getContainerTabTitle = function(tabName) {
		var title = '';
		$.each(WISE.util.Object.toArray(gDashboard.structure.Items.TabContainer), function(i, tabContainer) {
			var found = false;
			$.each(WISE.util.Object.toArray(tabContainer.Pages.Page), function(j, tab) {
				if (tabName === tab.ComponentName) {
					/* 개발 hsshim 1209 */
					title = tab.Name + '';
					found = true;
					return false;
				}
			});
			if (found) {
				return false;
			}
		});
		return title;
	}

	/**
	 * Return an object with tab container information for LAYOUT_XML.
	 * If tab containers do not exist, return null.
	 */
	this.getTabContainerInfo = function() {
		var result = [];
		var containerNum = 1;
		$('.tab_cont_box').each(function(i, tabContainer) {
			var container = {
				ComponentName: $(tabContainer).attr('id'),
				Name: '텝 컨테이너 ' + containerNum++,
				Pages: {
					Page: []
				}
			};
			$(tabContainer).children('.lm_header').find('.tab_cont_box_top_tit').each(function(j, tab) {
				container.Pages.Page.push({
					ComponentName: $(tab).attr('id').split('_item_title')[0],
					Name: $(tab).attr('title')
				});
			});
			result.push(container);
		});
		if (result.length > 0) {
			return result;
		} else {
			return null;
		}
	}
	
	/**
	 * 비정형 가능
	 */
	this.getAdhocLayout = function() {
		// not adhoc report
		if (gDashboard.reportType !== 'AdHoc') {

			return '';
		} 
		// no item
		else if (gDashboard.itemGenerateManager.dxItemBasten.length === 0) {

			return 'CTGB';
		}

		var layout;
		var container = this.canvasLayout.root.contentItems[0];
		var chartItem = container.contentItems.filter(function(item) {
			return item.config.contentId.indexOf('chart') !== -1;
		})[0];
		var pivotItem = container.contentItems.filter(function(item) {
			return item.config.contentId.indexOf('pivot') !== -1;
		})[0];
		if (chartItem.isMaximised) {
			layout = 'C';
		} else if (pivotItem.isMaximised) {
			layout = 'G';
		} else if (container.config.type === 'column') {
			if (chartItem.config.contentId === container.contentItems[0].config.contentId) {
				layout = 'CTGB';
			} else {
				layout = 'CBGT';
			}
		} else if (container.config.type === 'row') {
			if (chartItem.config.contentId === container.contentItems[0].config.contentId) {
				layout = 'CLGR';
			} else {
				layout = 'CRGL';
			}
		} else {
			layout = 'CTGB';
		}
		
		return layout;
	}
	
	/**
	 * Return layout object for adhoc reports.
	 */
	this.setupAdhocLayout = function(config) {
		var layout = {
			type: 'column',
            content: [],
		};
		var chartItem = WISE.libs.Dashboard.item.ItemUtility.getItemById('chartDashboardItem1' + self.reportIdSuffix);
		var pivotItem = WISE.libs.Dashboard.item.ItemUtility.getItemById('pivotDashboardItem1' + self.reportIdSuffix);
		var chartVisible = true;
		var pivotVisible = true;
		var adhocLayout = gDashboard.structure.Layout;
		if(adhocLayout == 'C') {
			pivotVisible = false;
		} else if(adhocLayout == 'G') {
			chartVisible = false;
		}
		var chartLayout = {
			type: 'stack',
			contentId: chartItem.ComponentName,
			content: [{
				type: 'component',
				componentName: 'dashboardItem',
				id: chartItem.ComponentName,
				componentState: { item: chartItem.ComponentName },
				/* 개발 hsshim 1209 */
				title: chartItem.Name + '',
			}]
		};
		var pivotLayout = {
			type: 'stack',
			contentId: pivotItem.ComponentName,
			content: [{
				type: 'component',
				componentName: 'dashboardItem',
				id: pivotItem.ComponentName,
				componentState: { item: pivotItem.ComponentName },
				/* 개발 hsshim 1209 */
				title: pivotItem.Name + '',
			}]
		};
		switch (gDashboard.structure.Layout) {
			case 'C':
				config.maximisedItemId = '_glMaximised';
				chartLayout.id = '_glMaximised';
				layout.content.push(pivotLayout);
				layout.content.push(chartLayout);
				break;
			case 'G':
				config.maximisedItemId = '_glMaximised';
				pivotLayout.id = '_glMaximised';
				layout.content.push(pivotLayout);
				layout.content.push(chartLayout);
				break;
			case 'CTGB':
				layout.content.push(chartLayout);
				layout.content.push(pivotLayout);
				break;
			case 'CBGT':
				layout.content.push(pivotLayout);
				layout.content.push(chartLayout);
				break;
			case 'CLGR':
				layout.type = 'row';
				layout.content.push(pivotLayout);
				layout.content.push(chartLayout);
				break;
			case 'CRGL':
				layout.type = 'row';
				layout.content.push(pivotLayout);
				layout.content.push(chartLayout);
				break
		}
		config.content.push(layout);
	}
	
	/**
	 * Change title of item with id.
	 */
	this.changeTitle = function (id, name, contentItems) {
        contentItems.forEach(function (item) {
            if (item.container && item.container.getElement().find('.dashboard-item').attr('id') === id) {
                item.container.setTitle(name);
                return;
            }
            if (item.contentItems) {
                return self.changeTitle(id, name, item.contentItems);
            }
        });
    }
}
