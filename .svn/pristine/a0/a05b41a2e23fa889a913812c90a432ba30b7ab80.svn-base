WISE.libs.Dashboard.item.BipartiteChartGenerator = function() {
	var self = this;

	this.type = 'BIPARTITE_CHART';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];

	var dataMember;
	var Exprname;
	var FilterArray = [];

	this.BipartiteChart = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	//팔레트 
	this.customPalette = [];
	this.isCustomPalette = false;
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [];
	this.trackingData = [];
	/**
	 * @param _item:
	 *            meta object
	 */
	var CheckCurrentFilter;
	this.getDxItemConfig = function(_item) {

		this.dataSourceConfig = {};
		this.dataSourceConfig.fields = [];

		var count = 0;

//		D = _item.FilterDimensions ? WISE.util.Object
//		.toArray(_item.DataItems.Dimension) : [];

		this.DU = WISE.libs.Dashboard.item.DataUtility;

		this.DI = _item.DataItems;
		this.V = WISE.util.Object.toArray((_item.Values && _item.Values.Value) || []);
		this.A = WISE.util.Object.toArray((_item.Arguments && _item.Arguments.Argument) || []);

		this.measures = [];
		$.each(this.V, function(_i0, _a0) {
			var uniqueName = _a0['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			self.measures.push(dataMember);
		});
		this.dimensions = [];
		$.each(this.A, function(_i0, _a0) {
			var uniqueName = _a0['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			self.dimensions.push(dataMember);
		});

		var dxConfigs = {
				dataSource : this.dataSourceConfig,
				dataStructure: 'plain',
				allowExpandAll: true,
				allowFiltering: true,
				allowSorting: true,
				allowSortingBySummary: true,
				size:{
					width : $('#'+self.itemid).width(),
					height : $('#'+self.itemid).height(),
				},
				tooltip: {
					enabled: true,
					zIndex: 21,
					customizeTooltip:function(_pointInfo){
						var text = '<b>' + _pointInfo.node.data.name + '</b>' + '<br/>' +"<b>" +self.currentMeasureName+"</b> : " +WISE.util.Number.unit(_pointInfo.value,'O',0,0);
						ret = {html: text};
						return ret;
					}
				}
		}

		// extend custom-configurations
		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
		var CustomConfigs = $.extend({}, Configurations);
		$.extend(CustomConfigs, dxConfigs);
		dxConfigs = CustomConfigs;
		return dxConfigs;
	};


	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	};

	this.setBipartiteChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.BipartiteChart['ComponentName'] = this.ComponentName;
		this.BipartiteChart['Name'] = this.Name;
		this.BipartiteChart['DataSource'] = this.dataSourceId;

		this.BipartiteChart['DataItems'] = this.fieldManager.DataItems;
		this.BipartiteChart['Arguments'] = this.fieldManager.Arguments;
		this.BipartiteChart['Values'] = this.fieldManager.Values;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.BipartiteChart;
		//초기 팔레트값 설정
		if (!(this.BipartiteChart['Palette'])) {
			this.BipartiteChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		
		if (this.BipartiteChart.InteractivityOptions) {
			if (!(this.BipartiteChart.InteractivityOptions.MasterFilterMode)) {
				this.BipartiteChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BipartiteChart.InteractivityOptions.TargetDimensions)) {
				this.BipartiteChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BipartiteChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.BipartiteChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.BipartiteChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.BipartiteChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BipartiteChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.BipartiteChart.LayoutOption){
			this.BipartiteChart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.BipartiteChart['ZoomAble']){
			this.BipartiteChart.ZoomAble = 'none'
		}
	};

	this.setBipartiteChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setBipartiteChart();
		}
		else{
			this.BipartiteChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.BipartiteChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.BipartiteChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.BipartiteChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.BipartiteChart['Palette'])) {
			this.BipartiteChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BipartiteChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BIPARTITE_CHART_DATA_ELEMENT);
				
				$.each(BipartiteChartOption,function(_i,_BipartiteChartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _BipartiteChartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _BipartiteChartOption.CTRL_NM;
					}
					if(self.BipartiteChart.ComponentName == CtrlNM){
						self.BipartiteChart['Palette'] = _BipartiteChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BipartiteChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BipartiteChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.BipartiteChart.InteractivityOptions) {
			if (!(this.BipartiteChart.InteractivityOptions.MasterFilterMode)) {
				this.BipartiteChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BipartiteChart.InteractivityOptions.TargetDimensions)) {
				this.BipartiteChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BipartiteChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.BipartiteChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.BipartiteChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.BipartiteChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BipartiteChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.BipartiteChart.LayoutOption){
			this.BipartiteChart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.BipartiteChart['ZoomAble']){
			this.BipartiteChart.ZoomAble = 'none'
		}
	}
	this.setBipartiteChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setBipartiteChart();
		}
		else{
			this.BipartiteChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.BipartiteChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.BipartiteChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.BipartiteChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.BipartiteChart['Palette'])) {
			this.BipartiteChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BipartiteChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BIPARTITE_CHART_DATA_ELEMENT);
				
				$.each(BipartiteChartOption,function(_i,_BipartiteChartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _BipartiteChartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _BipartiteChartOption.CTRL_NM;
//					}
					if(self.BipartiteChart.ComponentName == CtrlNM){
						self.BipartiteChart['Palette'] = _BipartiteChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BipartiteChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BipartiteChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.BipartiteChart.InteractivityOptions) {
			if (!(this.BipartiteChart.InteractivityOptions.MasterFilterMode)) {
				this.BipartiteChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BipartiteChart.InteractivityOptions.TargetDimensions)) {
				this.BipartiteChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BipartiteChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.BipartiteChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.BipartiteChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.BipartiteChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BipartiteChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.BipartiteChart.LayoutOption){
			this.BipartiteChart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.BipartiteChart['ZoomAble']){
			this.BipartiteChart.ZoomAble = 'none'
		}
	}

	/** @Override */
	this.bindData = function(_data) {
		//2020.02.07 mksong sqllike 적용 dogfoot
//		if (!this.tracked) {
//			this.globalData = _.clone(_data);
//			this.filteredData = _.clone(_data);
//		}
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setBipartiteChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.BipartiteChart);
			gDashboard.itemGenerateManager.generateItem(self, self.BipartiteChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setBipartiteChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.BipartiteChart);
			gDashboard.itemGenerateManager.generateItem(self, self.BipartiteChart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.BipartiteChart)) {
			this.setBipartiteChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.BipartiteChart);
			gDashboard.itemGenerateManager.generateItem(self, self.BipartiteChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setBipartiteChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.BipartiteChart);
			gDashboard.itemGenerateManager.generateItem(self, self.BipartiteChart);
		}

		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
			topIconPanel.append(trackingDataContainerHtml);
		}

		var dxConfig = this.getDxItemConfig(this.meta);

//		var measureKey = this.measures[0];
//		self.currentMeasureName = measureKey.caption;
//		self.fBipartiteChart(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
		if($('#'+self.itemid).length != 0){
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
			WISE.loadedSourceCheck('d3');
			self.fBipartiteChart(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,self.measures[0]));	
		}
		
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
		
//		gDashboard.itemGenerateManager.generateDxItem(self, _data);
		
		gDashboard.itemGenerateManager.renderButtons(self);

	};
						   
	/*this.menuItemGenerate = function(){
		if($('#data').length > 0){
			$('#data').remove();
		}

		$('#menulist').removeClass('col-2');
		$('#menulist').addClass('col-2');
		if($('#data').length == 0){
			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
		}

		if($('#design').length > 0){
			$('#design').remove();
		}

		if($('#tab5primary').length == 0){
//			$('.menu-comp').append('<div  class="slide-ui"><ul id="tab5primary" class="lnb-lst-tab" style="margin-top:10px;"></ul></div>');
			// 2020.01.16 mksong 영역 크기 조정 dogfoot
			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
		}

		$('#tab5primary').empty();
		$('#tab5primary').append('<span class="drag-line"></span>');

		$('#tab4primary').empty();
		if($('#tab4primary').length == 0){
			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
		}

		// initialize UI elements
		
		tabUi();
		designMenuUi();
		compMoreMenuUi();
	}*/
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
//		if($('#data').length > 0){
//			$('#data').remove();
//		}
//		
//		$('#menulist').removeClass('col-2');
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
//		}
//		
//		if($('#design').length > 0){
//			$('#design').remove();
//		}
//		
//		if($('#tab5primary').length == 0){
////			$('.menu-comp').append('<div  class="slide-ui"><ul id="tab5primary" class="lnb-lst-tab" style="margin-top:10px;"></ul></div>');
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
//		}
//		
//		$('#tab5primary').empty();
//		$('<li class="slide-ui-item"><a id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		
//		menuItemSlideUi();
//		//d3 속성 추가
//		
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
//		}
//		
//		// initialize UI elements
//		
//		tabUi();
//		designMenuUi();
//		compMoreMenuUi();
//		 $('.single-toggle-button').on('click', function(e) {
//	            e.preventDefault();
//	            $(this).toggleClass('on');
//	        });
//	        $('.multi-toggle-button').on('click', function(e) {
//	            e.preventDefault();
//	            var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
//	            if ($(this)[0] !== currentlyOn[0]) {
//	                currentlyOn.removeClass('on');
//	            }
//	            $(this).toggleClass('on');
//			});
//
//			// toggle 'on' status according to chart options
//			if (self.IO) {
//				if (self.IO['MasterFilterMode'] === 'Single') {
//					$('#singleMasterFilter').addClass('on');
//				} else if (self.IO['MasterFilterMode'] === 'Multiple') {
//					$('#multipleMasterFilter').addClass('on');
//				}
//				if (self.IO['IsDrillDownEnabled']) {
//					$('#drillDown').addClass('on');
//				}
//				if (self['isMasterFilterCrossDataSource']) {
//					$('#crossFilter').addClass('on');
//				}
//				if (self.IO['IgnoreMasterFilters']) {
//					$('#ignoreMasterFilter').addClass('on');
//				}
//				if (self.IO['TargetDimensions'] === 'Argument') {
//					$('#targetArgument').addClass('on');
//				} else if (self.IO['TargetDimensions'] === 'Series') {
//					$('#targetSeries').addClass('on');
//				}
//	        }
//			
//			$('<div id="editPopup">').dxPopup({
//	            height: 'auto',
//				width: 500,
//				visible: false,
//				showCloseButton: false
//			}).appendTo('#tab5primary');
//			// settings popover
//			$('<div id="editPopover">').dxPopover({
//				height: 'auto',
//				width: 'auto',
//				position: 'bottom',
//				visible: false
//			}).appendTo('#tab5primary');
//			
//			$('<div id="editPopup2">').dxPopup({
//				height: 'auto',
//				width: 500,
//				visible: false,
//				showCloseButton: false
//			}).appendTo('body');
//			// settings popover
//			$('<div id="editPopover2">').dxPopover({
//				height: 'auto',
//				width: 'auto',
//				position: 'bottom',
//				visible: false
//	        }).appendTo('#tab4primary');
//			
//			$('.functiondo').on('click',function(e){
//				self.functionDo(this.id);	
//			});
	}

	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
				if (self.dxItem) d3.selectAll('.viz-biPartite-mainBar .d3label').style('stroke', 'none').attr("fitler", "false");;
				self.trackingData = [];
				self.selectedPoint = undefined;	
		}
	};
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
//		$('#'+_itemid + '_tracking_data_container').empty();
//		if (this.measures && this.measures.length > 1) {
//			var valueListId = _itemid + '_topicon_vl';
//			var popoverid = _itemid + '_topicon_vl_popover';
//
//			var listHtml = '<li><a id="' + valueListId + '" href="#"><img src="' + WISE.Constants.context + '/images/cont_box_icon_layer.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer.png\'" alt="Select Panel" title="Select Panel"></a></li>';
//			$('#' + _itemid + '_tracking_data_container').append(listHtml);
//			if($('#'+this.itemid+'editBipartiteChartPopover').length == 0 ){
//				$('<div id="'+this.itemid+'editBipartiteChartPopover">').dxPopover({
//					height: 'auto',
//					width: 'auto',
//					position: 'bottom',
//					visible: false
//				}).appendTo('#wrapper');
//			}
//			var p = $('#'+this.itemid+'editBipartiteChartPopover').dxPopover('instance');
//
//
//			var temphtml = "<div style='width:150px;'>";
//			temphtml += '<div class="add-item noitem">';
//			$.each(this.measures, function(_i, _vo) {
//				temphtml += '<div class="select-style" data-key="' + (_vo.uniqueName) + '"><span data-key="' + (_vo.uniqueName) + '">' + _vo.caption + '</span></a>';
//			});
//			temphtml += '</div>';
//			temphtml += '</div>'; 
//
//			p.option({
//				target: '#'+valueListId,
//				contentTemplate: function(contentElement) {
//					$(temphtml).appendTo(contentElement);
//					$('.select-style').on('click',function(_e){
//						p.hide();
//						var targetPanelId = _e.target.getAttribute('data-key');
//						var selectedMeasure;
//						$.each(self.measures,function(_i,_mea){
//							if(_mea.uniqueName == targetPanelId){
//								selectedMeasure = _mea;
//								return false;
//							}
//						});
//						$('#' + self.itemid + '_title > .lm_title').text(self.Name);
//						var dxConfig = self.getDxItemConfig(self.meta);
//						self.currentMeasureName = selectedMeasure.caption;
//						dxConfig.dataSource = self.deleteDuplecateData(self.filteredData,selectedMeasure);
//						self.fBipartiteChart(self.filteredData);
////						self.dxItem = $("#" + self.itemid).dxTreeMap(dxConfig).dxTreeMap(
////						"instance");
//					});
//				},
////				visible:false
//			})
//			$('#' + _itemid + '_topicon').off('click').on('click',function(){
//				p.option('visible', !(p.option('visible')));
//			});
//		}
	};
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	this.deleteDuplecateData2 = function(_data,MeasureKey){
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var dataSourceId = this.dataSourceId;		
		/**
		 * 데이터 중복 제거 코드
		 */
		var ValueArray = new Array();
		var FieldArray = new Array();
		var selectArray = new Array();

		var Dimension = WISE.util.Object.toArray(this.meta.DataItems.Dimension);
		var Measure =  WISE.util.Object.toArray(MeasureKey);

		$.each(Dimension,function(_i,_Dim){
			selectArray.push(_Dim.DataMember);
			FieldArray.push(_Dim.DataMember);
		});

		$.each(Measure,function(_i,_Mea){
			selectArray.push('|sum|');
			selectArray.push(_Mea.name);
			selectArray.push('|as|');
			selectArray.push(_Mea.captionBySummaryType);			
		})

		var sqlConfig ={};
		 /*dogfoot 데이터 집합이 같을 때만 where 절 추가 shlim 20200619*/
		if(typeof self.dataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
			if(self.dataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
			}else{
				sqlConfig.Where = [];
			}
		}else{
			sqlConfig.Where = [];
        }
		sqlConfig.Select = selectArray;
		sqlConfig.From = _data;
//		sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
		sqlConfig.GroupBy = FieldArray;
		
		sqlConfig.OrderBy = [];
		$.each(Dimension, function(_i, _d) {
			//2020.02.07 mksong sqllike 적용 dogfoot
			sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
		});
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		self.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, self);
		ValueArray.push(self.filteredData);

		var resultArr = new Array();
		$.each(ValueArray,function(_i,_e){
			$.each(_e,function(_item,_obj){
				var valArray = new Array();
				var object = new Object();
				$.each(Dimension,function(_i,_Dim){
					valArray.push(_obj[_Dim.DataMember]);
				});
				if(Measure.length == 0){
					valArray.push(1);	
				}else{
					$.each(Measure,function(_i,_Mea){
						valArray.push(_obj[_Mea.captionBySummaryType]);
					});	
				}
				resultArr.push(valArray);
			})
		});
		return resultArr;
	};
	
//	this.resize = function() {
//		if($("#" + self.itemid).length != 0){
//			self.fBipartiteChart(self.filteredData, self.measures, self.dimensions, self.deleteDuplecateData(self.filteredData,self.measures[0]));	
//		}
//		d3.selectAll('.viz-biPartite-mainBar[filter="true"] .d3label').style('stroke-opacity', 0.2).style('stroke', 'black').style('stroke-width', 5).attr("fitler", "true");
//		gProgressbar.hide();
//	};
	
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		var dupledatacehck
		
		//2020.11.03 mksong resource Import 동적 구현 dogfoot
    	WISE.loadedSourceCheck('d3');
		
		if(typeof self.resizeData != 'undefined'){
		    dupledatacehck = self.resizeData;
		    if($("#" + self.itemid).length != 0){
		    	self.fBipartiteChart(self.filteredData, self.measures, self.dimensions, dupledatacehck);
		    }
			d3.selectAll('.viz-biPartite-mainBar[filter="true"] .d3label').style('stroke-opacity', 0.2).style('stroke', 'black').style('stroke-width', 5).attr("fitler", "true");
		}
		gProgressbar.hide();
	};
	

	this.fBipartiteChart = function(jsonData, measures, dimensions, dupleData) {
		if (!dupleData || ($.type(dupleData) === 'array' && dupleData.length === 0)) {
			$('#'+self.itemid + ' .nodata-layer').remove();
			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
			$("#" + self.itemid).children().css('display','none');
			$("#" + self.itemid).prepend(nodataHtml);
			if($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0){
				$("#" + self.itemid).height('100%');
				$("#" + self.itemid).width('100%');
			}
			$("#" + self.itemid).css('display', 'block');

			if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}

			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();	
				gDashboard.updateReportLog();
			}
			
			return ;
		}else{
			self.resizeData = dupleData;
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
		d4.select("#" + self.itemid).selectAll("svg").remove();
		var margin = {top: 20, right: 20, bottom: 30, left: 30},
	    width = $('#'+self.itemid).width() * 70 / 100,
	    height = $('#'+self.itemid).height() * 90 / 100,
	    padding = 0.8;
		
		
//		var paletteName = self.BipartiteChart.Palette == undefined? 'Material' : self.BipartiteChart.Palette;
//		var rgb = getPaletteValue(paletteName);
		var rgb = gDashboard.d3Manager.getPalette(self);
		var colorDataObject = {};
		var rgbIndex = -1;
		self.paletteData = [];
		$.each(dupleData, function(_i, _data){
			if(colorDataObject[_data[0]] == undefined){
				rgbIndex++;
				if(rgbIndex == rgb.length){
					rgbIndex = 0;
				}
				colorDataObject[_data[0]] = rgb[rgbIndex % rgb.length];
				self.paletteData.push(_data[0]);
				
			}
		});
		
		
		var x = d4.scale.ordinal().rangeRoundBands([0, width], padding);

		var y = d4.scale.linear().range([height, 0]);
//
		var xAxis = d4.svg.axis().scale(x).orient("bottom");

		var yAxis = d4.svg.axis().scale(y).orient("left").tickFormat(function(d) { return dollarFormatter(d); });
		
		var wleng = ($('#'+self.itemid).width()- width +60)/2;
		var hleng = ($('#'+self.itemid).height()- height)/2;
		var svg = d4.select("#" + self.itemid).append("svg:svg")
		.style("width", '100%')
		.style("height", '100%')
		.style("paddingLeft", '30px')
		.append("svg:g")
		.attr("transform", "translate("+wleng+","+hleng+")");

		var zoomCnt = 0;
		function zoomable(){
			 var zoom = d4.behavior.zoom().on("zoom", function (d,zz) {
				 if(pressKey['z'] || pressKey['Z']){
					 d4.select("#" + self.itemid).select('g').attr("transform", function(){

						 if(zoomCnt==0){
							 d4.event.translate[0] = d4.event.sourceEvent.layerX
							 d4.event.translate[1] = d4.event.sourceEvent.layerY
							 d4.event.scale =1;
						 }
						 if(d4.event.scale <= 1){
							 zoomCnt++;
							 d4.event.translate[0] = 0
							 d4.event.translate[1] = 0
							 d4.event.scale = 1
							 zoomable();
							 return "translate(" + wleng + "," + hleng + ")scale(" + d4.event.scale + ")";
						 }
						 if(d4.event.translate[0] ===0 && d4.event.translate[1] ===0){
							 d4.event.translate[0] = d4.event.sourceEvent.layerX
							 d4.event.translate[1] = d4.event.sourceEvent.layerY
						 }
						 zoomCnt++
						 return "translate(" + d4.event.translate + ")scale(" + d4.event.scale + ")"
					 })
				 }
				 else{
					// Move scrollbars.
					  const wrapper = $('#'+self.itemid);
					  if(pressKey['Shift'] && wrapper.css('overflow-x') != 'hidden')
					      wrapper.scrollLeft(wrapper.scrollLeft() + d3.event.sourceEvent.deltaY);
					  else if(wrapper.css('overflow-y') != 'hidden')
                         wrapper.scrollTop(wrapper.scrollTop() + d3.event.sourceEvent.deltaY);
				 }
			 })

			 d4.select('#'+self.itemid).select('svg').call(zoom)
		}
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}

		var bp=viz.biPartite()
		.data(dupleData)
		.width(width)
		.height(height)
		.pad(padding)
		.fill(fill())
		;
		
		var g = d4.select("#" + self.itemid).selectAll('g')
	    .call(bp);
		
		g.selectAll(".viz-biPartite-mainBar")
		.on("mouseover",function(d){
			mouseover(d);
			$(this).attr('cursor','pointer');
		})
		.on("mouseout",mouseout)
		.attr("filter", function(d){
			var selectedData = {};
			if(d.part == 'primary'){
				selectedData[dimensions[0].name] = d.key;
			}else{
				selectedData[dimensions[1].name] = d.key;
			}
			var inArray = false;
			for (var index = 0; index < self.trackingData.length; index++) {
				if(d.part == 'primary'){
					if (self.trackingData[index][dimensions[0].name] != undefined && self.trackingData[index][dimensions[0].name] === selectedData[dimensions[0].name]) {
						inArray = true;
					}
				}else{
					if (self.trackingData[index][dimensions[1].name] != undefined &&self.trackingData[index][dimensions[1].name] === selectedData[dimensions[1].name]) {
						inArray = true;
					}
				}
			}
			
			return inArray? "true" : "false";
		})
		.on("click", function(d){mouseclick(d, this)})
		
		g.selectAll(".viz-biPartite-mainBar")
		.append("text").attr("class","d3label")
//		.attr("x",d=>(d.part=="primary"?  -60: 70))
//		.attr("x",d=>(d.part=="primary"?  -30: 30))
		.attr("x",function(d){return d.part=="primary"?-30: 30})
		.style("font-family", self.meta.LayoutOption.Label.family)
		.style("font-size", self.meta.LayoutOption.Label.size+'px')
		.style("fill", self.meta.LayoutOption.Label.color)
		.attr("y",function(d){return 6})
//		.text(d=>d.key)
		.text(function(d){return d.key})
//		.attr("text-anchor",d=>(d.part=="primary"? "end": "start"));
		.attr("text-anchor",function(d){return d.part=="primary"? "end": "start"});
		
//		g.selectAll(".viz-biPartite-mainBar")
//			.append("text").attr("class","perc")
//			.attr("x",d=>(d.part=="primary"? -30 : 30))
//			.attr("y",d=>+6)
//			.text(function(d){
//				return d3.format("0.0%")(d.percent)
//				})
//			.attr("text-anchor",d=>(d.part=="primary"? "end": "start"));
	
		function mouseover(d){
			bp.mouseover(d);
			var selectKey = d.key;
			
			g.selectAll(".viz-biPartite-mainBar")
			.select(".d3label")
			.text(function(d){
				if(d.key != selectKey && d.percent < 0.01){
//					 g.select(d).style("display",'none');
					return ""
				}
				return d.key
			});
			
//			g.selectAll(".viz-biPartite-mainBar")
//			.select(".perc")
//			.text(function(d){
//				if(d.key != selectKey && d.percent < 0.01){
////					 g.select(d).style("display",'none');
//					return ""
//				}
//				return d3.format("0.0%")(d.percent)
//			});
		}
		function mouseout(d){
			bp.mouseout(d);
			
			g.selectAll(".viz-biPartite-mainBar")
			.select(".d3label")
			.text(function(d){
				return d.key
			});
			
//			g.selectAll(".viz-biPartite-mainBar")
//				.select(".perc")
//			.text(function(d){ return d3.format("0.0%")(d.percent)})
		}
		
		function mouseclick(d, s){
			
			var selectKey = d.key;
			
//			g.selectAll(".viz-biPartite-mainBar")
//			.select(".perc")
//			.text(function(d){
//				if(d.key != selectKey && d.percent < 0.01){
////					 g.select(d).style("display",'none');
//					return ""
//				}
//				return d3.format("0.0%")(d.percent)
//			});
            switch(self.IO.MasterFilterMode){
				case 'Multiple':
					var inArray = false;
					var selectedData = {};
					if(d.part == 'primary'){
						selectedData[dimensions[0].name] = d.key;
					}else{
						selectedData[dimensions[1].name] = d.key;
					}
					for (var index = 0; index < self.trackingData.length; index++) {
						if(d.part == 'primary'){
							if (self.trackingData[index][dimensions[0].name] != undefined && self.trackingData[index][dimensions[0].name] === selectedData[dimensions[0].name]) {
								self.trackingData.splice(index, 1);
								index--;
								inArray = true;
							}
						}else{
							if (self.trackingData[index][dimensions[1].name] != undefined &&self.trackingData[index][dimensions[1].name] === selectedData[dimensions[1].name]) {
								self.trackingData.splice(index, 1);
								index--;
								inArray = true;
							}
						}
					}
					if (!inArray) {
						d3.select(s).select('text').style('stroke-opacity', 0.2).style('stroke', 'black').style('stroke-width', 5).attr("fitler", "true");
						self.trackingData.push(selectedData);
					}else{
						d3.select(s).select('text').style('stroke', 'none').attr("fitler", "false");
					}
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
				case 'Single':
					d3.selectAll('.viz-biPartite-mainBar .d3label').style('stroke', 'none').attr("fitler", "false");
					//self.selectedPoint = _e.target;
					self.trackingData = [];
					d3.select(s).select('text').style('stroke-opacity', 0.2).style('stroke', 'black').style('stroke-width', 5).attr("fitler", "true");
//					$.each(dimensions, function(_i, _ao) {
//						
//
//					});

					var selectedData = {};
					if(d.part == 'primary'){
						selectedData[dimensions[0].name] = d.key;
						self.trackingData.push(selectedData);
					}else{
						selectedData[dimensions[1].name] = d.key;
						self.trackingData.push(selectedData);
					}
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}	
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
			}
		}
	
		function fill(){
		  return function(d){ 
			  return colorDataObject[d.primary] 
		  }
		} 
		
		var tooltip = d4.select("body").append("div")
	        .attr("class", "toolTip")
	        .style("display", "none");
		var rgbLen = -1;
		g.append("rect")
	    .style("fill", function(d,i) { 
	    	
	    	rgbLen++;
	    	if(rgb[rgbLen] == undefined){
	    		rgbLen = 0;
	    	}

	    	return rgb[rgbLen];
	    })
	    .attr("width", 31)
	    .attr("height", 3)
	    .on("mouseover", function(d) { tooltip.style("display", null); })
        .on("mouseout",  function() { tooltip.style("display", "none"); })
        .on("mousemove", function(d) {
                tooltip.style("left", (d4.event.pageX + 10) + "px");
                tooltip.style("top", (d4.event.pageY - 10) + "px");
                if(d.value != null){
                	tooltip.text(d.value); 
                }
                else{
                	tooltip.text(d.end); 
                }
                
           });
		
//		 var legend = svg.append("g")
//		    .attr("class", "legend")
//			//.attr("x", w - 65)
//			//.attr("y", 50)
//		    .attr("height", 100)
//		    .attr("width", 100)
//			.attr('transform', 'translate(10,10)')  

//		var rgbLen = -1;
//		 legend.selectAll('rect')
//		  .data(dupleData)
//		  .enter()
//		  .append("rect")
//		  .attr("x", width+15)
//		  .attr("y", function(d, i){ 
//
//		  	return i *  (height/dupleData.length) - 9;
//		  })
//		  .attr("width", 10)
//		  .attr("height", 10)
//		  .style("fill", function(d, i) { 
//			rgbLen++;
//			if(rgb[rgbLen] == undefined){
//				rgbLen = 0;
//			}
//			return rgb[rgbLen];
//		  })
//
//		legend.selectAll('text')
//		  .data(dupleData)
//		  .enter()
//		  .append("text")
//		  .attr("x", width+30)
//		  .attr("y", function(d, i){ return i *  (height/dupleData.length);})
//		  .style("font-size",  function(d, i){
//			  var fontz = gDashboard.fontManager.getFontSize((width/height) * 10, 'Item');
//		  		if(Number(fontz.split('px')[0])>10 + Number(gDashboard.fontManager.getFontSize(0, 'Item').split('px')[0])){
//		  			fontz = gDashboard.fontManager.getFontSize(15, 'Item');
//		  		}else if(Number(fontz.split('px')[0]) < 5)
//		  			fontz = 5;
//		  		return fontz;
//		 	 }	  	
//		  ).style("font-family", gDashboard.fontManager.getFontFamily('Item'))
//		  .text(function(d) {
//			return d.name;
//		  });

//	});

		function type(d) {
		  d.value = +d.value;
		  return d;
		}

		function dollarFormatter(n) {
		  n = Math.round(n);
		  var result = n;
		  if (Math.abs(n) > 1000000) {
		    result = Math.round(n/1000000) + 'M';
		  }
		  return result;
		}
		
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.BipartiteChart);
	}
	
	this.functionDo2 = function(_f) {		
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.BipartiteChart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.BipartiteChart['ShowCaption'] = false;
				}
				break;
			}
			// edit chart title
			case 'editName': {
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '이름 편집',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize title input box
						contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput">');
                        var html = '<div class="modal-footer" style="padding-bottom:0px;">';
						html += '<div class="row center">';
						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
						html += '</div>';
						html += '</div>';
						html += '</div>';
						contentElement.append(html);
                        
                        $('#' + self.itemid + '_titleInput').dxTextBox({
							text: $('#' + self.itemid + '_title').text()
                        });
                                                
                        // confirm and cancel
						$('#ok-hide').on('click', function() {
                            var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
                            if(newName.trim() == '') {
                            	WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                            	$('#' + self.itemid + '_titleInput').dxTextBox('instance').option('value', self.Name);
                            } else {
                            	/* DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류 수정  20191223 */
                            	
//                            	var goldenLayout = gDashboard.goldenLayoutManager;
//                            	goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);
                            	
                            	var ele = $('#' + self.itemid + '_title');
                            	ele.attr( 'title', newName)
                                ele.find( '.lm_title' ).html(newName);
                            	
                            	self.BipartiteChart['Name'] = newName;
                            	self.Name = newName;
                            	p.hide();
                            }
						});
						$('#close').on('click', function() {
							p.hide();
						});
					}
				});
				// show popup
				p.show();
				break;
			}
			// edit color scheme
			case 'editPalette': {
				if (!(self.dxItem)) {
					break;
				}
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
				
				if (self.customPalette.length > 0) {
					paletteCollection.push('Custom');
					paletteCollection2.push('사용자 정의 테마');
				}
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chagePalette = self.BipartiteChart.Palette;
				var firstPalette = self.BipartiteChart.Palette;
				p.option({
                    target: '#editPalette',
                    onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // create html layout
                        var html = 	'<div id="' + self.itemid + '_paletteBox"></div>' +
								 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="save-ok" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="save-cancel" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        var select = $('#' + self.itemid + '_paletteBox');
                        // palette select
                        var originalPalette = paletteCollection.indexOf(self.BipartiteChart.Palette) != -1
										? self.BipartiteChart.Palette
										: 'Custom';
						select.dxSelectBox({
                            width: 400,
                            items: paletteCollection2,
                            itemTemplate: function(data) {
                                var html = $('<div />');
                                $('<p />').text(data).css({
                                    display: 'inline-block',
                                    float: 'left'
                                }).appendTo(html);
                                var itemPalette = data === '사용자 정의 테마'
										? self.customPalette 
										: DevExpress.viz.getPalette(paletteObject2[data]).simpleSet;
                                for (var i = 5; i >= 0; i--) {
                                    $('<div />').css({
                                        backgroundColor: itemPalette[i],
                                        height: 30,
                                        width: 30,
                                        display: 'inline-block',
                                        float: 'right'
                                    }).appendTo(html);
                                }
                                return html;
                            },
							value: paletteObject[originalPalette],
							onValueChanged: function(e) {
								if (e.value == '사용자 정의 테마') {
                                    self.isCustomPalette = true;
                                    /*self.dxItem.option('palette', self.customPalette);*/
                                	self.resize();
                                    
								} else {
                                    self.isCustomPalette = false;
                                    self.BipartiteChart.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.BipartiteChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	self.BipartiteChart.Palette = firstPalette;
                            chagePalette = firstPalette;
                            self.resize();
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.BipartiteChart.Palette = chagePalette;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
//			case 'editPalette': {
//				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
//					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office', 'Custom'];
//				// popup configs
//				var p = $('#editPopover').dxPopover('instance');
//				var chagePalette = self.BipartiteChart.Palette;
//				var firstPalette = self.BipartiteChart.Palette;
//				p.option({
//                    target: '#editPalette',
//					contentTemplate: function(contentElement) {
//                        // create html layout
//                        $(  "<div id=\"" + self.itemid + "_paletteBox\"></div>" +
//                            "<div class=\"modal-footer\" style=\"padding-top:15px; width:370px;\">" + 
//                            "    <div class=\"row center\">" + 
//		                    "        <a id=\"save_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>" + 
//		                    "        <a id=\"save_cancel\" class=\"btn neutral close\" href=\"#\">취소</a>" + 
//		                    "    </div>" + 
//                            "</div>"
//                        ).appendTo(contentElement);
//                        var select = $('#' + self.itemid + '_paletteBox');
//                        // palette select
//                        var originalPalette = paletteCollection.includes(self.BipartiteChart.Palette) 
//										? self.BipartiteChart.Palette
//										: 'Custom';
//						select.dxSelectBox({
//                            width: 400,
//                            items: paletteCollection,
//                            itemTemplate: function(data) {
//                                var html = $('<div />');
//                                $('<p />').text(data).css({
//                                    display: 'inline-block',
//                                    float: 'left'
//                                }).appendTo(html);
//                                var itemPalette = data === 'Custom'
//										? self.customPalette 
//										: DevExpress.viz.getPalette(data).simpleSet;
//                                for (var i = 5; i >= 0; i--) {
//                                    $('<div />').css({
//                                        backgroundColor: itemPalette[i],
//                                        height: 30,
//                                        width: 30,
//                                        display: 'inline-block',
//                                        float: 'right'
//                                    }).appendTo(html);
//                                }
//                                return html;
//                            },
//							value: originalPalette,
//							onValueChanged: function(e) {
//								if (e.value == 'Custom') {
//                                    self.isCustomPalette = true;
//                                    /*self.dxItem.option('palette', self.customPalette);*/
//                                    self.resize();
//								} else {
//                                    self.isCustomPalette = false;
//                                    /*self.dxItem.option('palette', e.value);*/
//                                    self.BipartiteChart.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.BipartiteChart.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.BipartiteChart.Palette);
//                            chagePalette = firstPalette;
//                            self.BipartiteChart.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.BipartiteChart.Palette = chagePalette;
//					}
//                });
//                p.option('visible', !(p.option('visible')));
//				break;
//			}
			default: break;
		}
	}

};


function checkingItem(_data) {
	return !_data.items.length;
};

WISE.libs.Dashboard.BipartiteChartFieldManager = function() {
	var self = this;

	this.initialized = false;
	this.alreadyFindOutMeta = false;

	//검색 - searchDisable
	this.searchDisable = false;
	//검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	//검색

	this.dataItemNo=0;

	this.meta;
	this.isChange = false; // 사용자가 필드를 변경했는지 여부 체크
	this.columnMeta = {}; // 쿼리된 모든 컬럼정보 저장
	this.isColumnChooser = false;

	this.all = [];
	this.values = [];
	this.arguments = [];
	this.series = [];
//	this.hide_column_list_dim = [];
//	this.hide_column_list_mea = [];

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
		this.values = [];
		this.arguments = [];

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
		var NumericFormat = {'ForMatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};

		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = NumericFormat;
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};

	this.setValuesByField = function(_values){
		this.Values = {'Value' : []};
		_.each(_values,function(_v){
			var Value = {'UniqueName' : _v.uniqueName};
			self.Values['Value'].push(Value);
		});
		return self.Values;
	};

	this.setArgumentsByField = function(_argument){
		this.Arguments = {'Argument' : []};
		_.each(_argument,function(_a){
			var Value = {'UniqueName' : _a.uniqueName};
			self.Arguments['Argument'].push(Value);
		});
		return self.Arguments;
	};
};
