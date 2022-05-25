WISE.libs.Dashboard.item.SankeyChartGenerator = function() {
	var self = this;

	this.type = 'SANKEY_CHART';

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

	this.SankeyChart = [];
	this.fieldManager;
	this.currentMeasureName = "";
	this.trackingData = [];
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

	this.setSankeyChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.SankeyChart['ComponentName'] = this.ComponentName;
		this.SankeyChart['Name'] = this.Name;
		this.SankeyChart['DataSource'] = this.dataSourceId;

		this.SankeyChart['DataItems'] = this.fieldManager.DataItems;
		this.SankeyChart['Arguments'] = this.fieldManager.Arguments;
		this.SankeyChart['Values'] = this.fieldManager.Values;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.SankeyChart;
		//초기 팔레트값 설정
		if (!(this.SankeyChart['Palette'])) {
			this.SankeyChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.SankeyChart.InteractivityOptions) {
			if (!(this.SankeyChart.InteractivityOptions.MasterFilterMode)) {
				this.SankeyChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.SankeyChart.InteractivityOptions.TargetDimensions)) {
				this.SankeyChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.SankeyChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.SankeyChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.SankeyChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.SankeyChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.SankeyChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.SankeyChart.LayoutOption){
			this.SankeyChart.LayoutOption = {
					Label: {
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.SankeyChart['ZoomAble']){
			this.SankeyChart.ZoomAble = 'none'
		}
	};

	this.setSankeyChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setSankeyChart();
		}
		else{
			this.SankeyChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.SankeyChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.SankeyChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.SankeyChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.SankeyChart['Palette'])) {
			this.SankeyChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var SankeyChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SANKEY_CHART_DATA_ELEMENT);
				
				$.each(SankeyChartOption,function(_i,_SankeyChartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _SankeyChartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _SankeyChartOption.CTRL_NM;
					}
					if(self.SankeyChart.ComponentName == CtrlNM){
						self.SankeyChart['Palette'] = _SankeyChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.SankeyChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.SankeyChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.SankeyChart.InteractivityOptions) {
			if (!(this.SankeyChart.InteractivityOptions.MasterFilterMode)) {
				this.SankeyChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.SankeyChart.InteractivityOptions.TargetDimensions)) {
				this.SankeyChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.SankeyChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.SankeyChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.SankeyChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.SankeyChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.SankeyChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if(!this.SankeyChart.LayoutOption){
			this.SankeyChart.LayoutOption = {
					Label: {
						color: '#000000',
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.SankeyChart['ZoomAble']){
			this.SankeyChart.ZoomAble = 'none'
		}
	}
	this.setSankeyChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setSankeyChart();
		}
		else{
			this.SankeyChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.SankeyChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.SankeyChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.SankeyChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.SankeyChart['Palette'])) {
			this.SankeyChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var SankeyChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SANKEY_CHART_DATA_ELEMENT);
				
				$.each(SankeyChartOption,function(_i,_SankeyChartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _SankeyChartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _SankeyChartOption.CTRL_NM;
//					}
					if(self.SankeyChart.ComponentName == CtrlNM){
						self.SankeyChart['Palette'] = _SankeyChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.SankeyChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.SankeyChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.SankeyChart.InteractivityOptions) {
			if (!(this.SankeyChart.InteractivityOptions.MasterFilterMode)) {
				this.SankeyChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.SankeyChart.InteractivityOptions.TargetDimensions)) {
				this.SankeyChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.SankeyChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.SankeyChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.SankeyChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.SankeyChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.SankeyChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if(!this.SankeyChart.LayoutOption){
			this.SankeyChart.LayoutOption = {
					Label: {
						color: '#000000',
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.SankeyChart['ZoomAble']){
			this.SankeyChart.ZoomAble = 'none'
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
			self.setSankeyChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.SankeyChart);
			gDashboard.itemGenerateManager.generateItem(self, self.SankeyChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setSankeyChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.SankeyChart);
			gDashboard.itemGenerateManager.generateItem(self, self.SankeyChart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.SankeyChart)) {
			this.setSankeyChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.SankeyChart);
			gDashboard.itemGenerateManager.generateItem(self, self.SankeyChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setSankeyChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.SankeyChart);
			gDashboard.itemGenerateManager.generateItem(self, self.SankeyChart);
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
//		self.fSankeyChart(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
		if($('#'+self.itemid).length != 0){
			//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
			WISE.loadedSourceCheck('d3');
			self.fSankeyChart(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,self.measure));	
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
			if (self.dxItem) d3.selectAll('path.sk-link').style('stroke-opacity', "").attr("filter", "false");;
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
//			if($('#'+this.itemid+'editSankeyChartPopover').length == 0 ){
//				$('<div id="'+this.itemid+'editSankeyChartPopover">').dxPopover({
//					height: 'auto',
//					width: 'auto',
//					position: 'bottom',
//					visible: false
//				}).appendTo('#wrapper');
//			}
//			var p = $('#'+this.itemid+'editSankeyChartPopover').dxPopover('instance');
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
//						self.fSankeyChart(self.filteredData);
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
		});

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

		var resultArr = [];
		$.each(ValueArray,function(_i,_e){
			$.each(_e,function(_item,_obj){
				var valArray = new Array();
				var linkIndex = 0; 
				$.each(_.keys(_obj),function(_index, _key){
					if(_index != _.keys(_obj).length-1){
						var linkObject = {"source":_obj[_key],"target":_obj[_.keys(_obj)[_index+1]], "value":1};
						resultArr.push(linkObject);
					}
				});
				
//				if(Measure.length == 0){
//					valArray.push(1);
//				}else{
//					$.each(Measure,function(_i,_Mea){
//						valArray.push(_obj[_Mea.captionBySummaryType]);
//					});	
//				}
			});
		});
		
//		$.each(ValueArray,function(_i,_e){
//			$.each(_e,function(_item,_obj){
//				var valArray = new Array();
//				var object = new Object();
//				$.each(Dimension,function(_i,_Dim){
//					valArray.push(_obj[_Dim.DataMember]);
//				});
//				if(Measure.length == 0){
//					valArray.push(1);	
//				}else{
//					$.each(Measure,function(_i,_Mea){
//						valArray.push(_obj[_Mea.captionBySummaryType]);
//					});	
//				}
//				resultArr.push(valArray);
//			})
//		});
		return resultArr;
	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		if(typeof self.resizeData != 'undefined'){
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fSankeyChart(self.filteredData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('.sk-link[filter="true"]').style('stroke-opacity', 0.5);
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		if($("#" + self.itemid).length != 0){
//			self.fSankeyChart(self.filteredData, self.measures, self.dimensions, self.deleteDuplecateData(self.filteredData,self.measures[0]));	
//		}
//		d3.selectAll('.sk-link[filter="true"]').style('stroke-opacity', 0.5);
//		gProgressbar.hide();
//	};
	

	this.fSankeyChart = function(jsonData, measures, dimensions, dupleData) {
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
//		var margin = {top: 20, right: 20, bottom: 30, left: 30},
//	    width = $('#'+self.itemid).width() * 70 / 100,
//	    height = $('#'+self.itemid).height() * 90 / 100,
//	    padding = 0.8;
		var configSankey = {
		    margin: { top: 10, left: 10, right: 10, bottom: 10 },
		    nodes: {
		        dynamicSizeFontNode: {
		            enabled: true,
		            minSize: 14,
		            maxSize: 30
		        },
		        fontSize: 14, // if dynamicSizeFontNode not enabled
		        draggableX: false, // default [ false ]
		        draggableY: true, // default [ true ]
		        colors: d3.scaleOrdinal(d3.schemeCategory10)
		    },
		    links: {
		        formatValue: function(val) {
//		            return d3.format(",.0f")(val) + ' TWh';
		        	return '';
		        },
		        unit: '' // if not set formatValue function
		    },
		    tooltip: {
		        infoDiv: true,  // if false display default tooltip
		        labelSource: 'Input:',
		        labelTarget: 'Output:'
		    }
		};
		
		var margin = {top: 10, right: 10, bottom: 10, left: 10},
		 width = $('#'+self.itemid).width() * 70 / 100,
	    height = $('#'+self.itemid).height() * 90 / 100,
	    padding = 0.8;
		
//		var paletteName = self.SankeyChart.Palette == undefined? 'Material' : self.SankeyChart.Palette;
//		var rgb = getPaletteValue(paletteName);
		
		var rgb = gDashboard.d3Manager.getPalette(self);
		
		var colorDataObject = {};
		var rgbIndex = -1;
//		$.each(dupleData, function(_i, _data){
//			if(colorDataObject[_data[0]] == undefined){
//				rgbIndex++;
//				if(rgbIndex == rgb.length){
//					rgbIndex = 0;
//				}
//				colorDataObject[_data[0]] = rgb[rgbIndex];
//			}
//		});
		
		
		var x = d4.scale.ordinal().rangeRoundBands([0, width], padding);

		var y = d4.scale.linear().range([height, 0]);
//
		var xAxis = d4.svg.axis().scale(x).orient("bottom");

		var yAxis = d4.svg.axis().scale(y).orient("left").tickFormat(function(d) { return dollarFormatter(d); });
		
		var wleng = ($('#'+self.itemid).width()- width +60)/2;
		var hleng = ($('#'+self.itemid).height()- height)/2;

        function label(node) {
          return node.name.replace(/\s*\(.*?\)$/, '');
        }
        function color(node, depth) {
          var id = node.id.replace(/(_score)?(_\d+)?$/, '');
          if (colors[id]) {
            return colors[id];
          } else if (depth > 0 && node.targetLinks && node.targetLinks.length == 1) {
            return color(node.targetLinks[0].source, depth-1);
          } else {
            return null;
          }
        }
		
		  //set up graph in same style as original example but empty
		  graph = {"nodes" : [], "links" : []};

		  dupleData.forEach(function (d) {
			  if(d.source != '' && d.target != ''){
				  graph.nodes.push({ "name": d.source });
			      graph.nodes.push({ "name": d.target });
			      
			      graph.links.push({ "source": d.source,
			                         "target": d.target,
			                         "value": +d.value });
			  }
		  });

		  // return only the distinct / unique nodes
		  var resultGraphNodes = [];
		  $.each(graph.nodes,function(i,value){
			    if(resultGraphNodes.indexOf(value.name) == -1 ) resultGraphNodes.push(value.name);
			});
		  
		  self.paletteData = _.cloneDeep(resultGraphNodes);
		  graph.nodes = [];
		  $.each(resultGraphNodes, function(index,graphNode){
			  rgbIndex++;
			  if(rgbIndex == rgb.length){
				  rgbIndex = 0;
			  }
			  
			  var graphObject = {'id' : index,'name' : graphNode, 'color': rgb[rgbIndex]};
			  graph.nodes.push(graphObject);
		  });
//		  graph.nodes = resultGraphNodes;

	      // loop through each link replacing the text with its index from node
	      graph.links.forEach(function (d, i) {
	    	  graph.links[i].source = resultGraphNodes.indexOf(graph.links[i].source);
	    	  graph.links[i].target = resultGraphNodes.indexOf(graph.links[i].target);
	      });

	      //now loop through each nodes to make nodes an array of objects
	      // rather than an array of strings
//	      graph.nodes.forEach(function (d, i) {
//	    	  graph.nodes[i] = { "name": d };
//	      });

	      var objSankey = self.createSankey("#" + self.itemid, configSankey, graph);
	      
//	   // append the svg object to the body of the page
//	      var svg = d4.select("#" + self.itemid).append("svg")
//	          .style("width", '100%')
//	          .style("height", '100%')
//	          .append("g")
//	          .attr("transform",
//	                "translate(" + margin.left + "," + margin.top + ")");
//
//	      // Color scale used
//	      var color = d3.scaleOrdinal(d3.schemeCategory20);
//
//	      // Set the sankey diagram properties
//	      var sankey = d3.sankey()
//	          .nodeWidth(36)
//	          .nodePadding(290)
//	          .size([width, height]);
//	      
//	   // Constructs a new Sankey generator with the default settings.
////	      sankey
////	          .nodes(graph.nodes)
////	          .links(graph.links)
////	          .layout(1);
//	      svg.append("g")
//	      .attr("fill", "none")
//	      .attr("stroke", "#000")
//	      .attr("stroke-opacity", 0.2)
//		  .selectAll("path")
//		  .data(graph.links)
//		  .join("path")
//	      .attr("d", d3.sankeyLinkHorizontal())
//	      .attr("stroke-width", function(d) { return d.width; });
//
//	      // add in the links
//	      var link = svg.append("g")
//	        .selectAll(".link")
//	        .data(graph.links)
//	        .enter()
//	        .append("path")
//	          .attr("class", "link")
//	          .attr("d", sankey.link() )
//	          .style("stroke-width", function(d) { return Math.max(1, d.dy); })
//	          .sort(function(a, b) { return b.dy - a.dy; });
//
//	      // add in the nodes
//	      var node = svg.append("g")
//	        .selectAll(".node")
//	        .data(graph.nodes)
//	        .enter().append("g")
//	          .attr("class", "node")
//	          .attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; })
//	          .call(d3.drag()
//	            .subject(function(d) { return d; })
//	            .on("start", function() { this.parentNode.appendChild(this); })
//	            .on("drag", dragmove));
//
//	      // add the rectangles for the nodes
//	      node
//	        .append("rect")
//	          .attr("height", function(d) { return Math.abs(d.dy); })
////	          .attr("height", 30)
//	          .attr("width", sankey.nodeWidth())
//	          .style("fill", function(d) { return d.color = color(d.name.replace(/ .*/, "")); })
//	          .style("stroke", function(d) { return d3.rgb(d.color).darker(2); })
//	        // Add hover text
//	        .append("title")
//	          .text(function(d) { return d.name + "\n" + "There is " + d.value + " stuff in this node"; });
//
//	      // add in the title for the nodes
//	        node
//	          .append("text")
//	            .attr("x", -6)
//	            .attr("y", function(d) { return d.dy / 2; })
//	            .attr("dy", ".35em")
//	            .attr("text-anchor", "end")
//	            .attr("transform", null)
//	            .text(function(d) { return d.name; })
//	          .filter(function(d) { return d.x < width / 2; })
//	            .attr("x", 6 + sankey.nodeWidth())
//	            .attr("text-anchor", "start");
//
//	      // the function for moving the nodes
//	      function dragmove(d) {
//	        d3.select(this)
//	          .attr("transform",
//	                "translate("
//	                   + d.x + ","
//	                   + (d.y = Math.max(
//	                      0, Math.min(height - d.dy, d3.event.y))
//	                     ) + ")");
//	        sankey.relayout();
//	        link.attr("d", sankey.link() );
//	      }
	};
	
	this.createSankey = function(containerId, configSankey, dataSankey) {

		// to prevent NaN value, related https://github.com/d3/d3-sankey/issues/39
		var _safeValueToLink = function(v) { return Math.max(v, Number.MIN_VALUE); }

	    var _dataSankey = {
	        nodes: [],
	        links: []
	    };

	    //load data
	    dataSankey.nodes.map(function(d) {
	        _dataSankey.nodes.push({
	            name: d.name,
	            color: d.color,
	            id: d.id
	        });
	    });
	    dataSankey.links.map(function(l) {
	        _dataSankey.links.push({
	            source: l.source,
	            target: l.target,
	            id: l.id,
	            value: _safeValueToLink(l.value)
	        });
	    });

	    //var _dataSankey = Object.assign({}, dataSankey);

	    var _updateLinksId = function(linkData) {
	        for (var i = 0; i < linkData.length; i++)
	            if (linkData[i].id == undefined)
	                linkData[i].id = linkData[i].source + " -> " + linkData[i].target;
	    };
	    //update links id
	    _updateLinksId(_dataSankey.links);

	    //removing old svg and tips
	    d3.select('.d3-tip-nodes').remove();
	    d3.select('.d3-tip').remove();
	    d3.select(containerId + ' svg').remove()

	    var container = d3.select(containerId);

	    function _getDimensions(containerId, margin) {
//	        var bbox = container.node().getBoundingClientRect();
//	    	var bbox = $(container.node())[0].getBoundingClientRect();
	    	var bbox = $(containerId);
	        return {
	            width: bbox.width() - margin.left - margin.right,
	            height: bbox.height() - margin.top - margin.bottom
	        };
	    }
	    var dimensions = _getDimensions(containerId, configSankey.margin);

	    var svg_base = container.append("svg")
	        .attr('width', dimensions.width + configSankey.margin.left + configSankey.margin.right)
	        .attr('height', dimensions.height + configSankey.margin.top + configSankey.margin.bottom)
	        .attr("class", "sk-svg")
        var zoomCnt = 0;
		function zoomable(){
			 var zoom = d3.zoom().on("zoom", function (d,zz) {
				 if(pressKey['z'] || pressKey['Z'])
						  d3.select('#'+self.itemid).select('g').attr("transform", function(){ 
								  if(zoomCnt==0){
										d3.event.transform.x = d3.event.sourceEvent.layerX
										d3.event.transform.y = d3.event.sourceEvent.layerY
										d3.event.transform.k =1;
								  }
								  if(d3.event.transform.k <= 1){
									zoomCnt++;
									d3.event.transform.x = 0
									d3.event.transform.y = 0
									d3.event.transform.k =1;
									zoomable();
									return "translate(" + configSankey.margin.left + "," + configSankey.margin.top + ")";
								  }
								  if(d3.event.transform.x ===0 && d3.event.transform.y ===0){
										d3.event.transform.x = d3.event.sourceEvent.layerX
										d3.event.transform.y = d3.event.sourceEvent.layerY
								   }
								   zoomCnt++
								return d3.event.transform;
							})
						})

			  d3.select('#'+self.itemid).select('svg').call(zoom)
		}
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}
	      
	    var svg = svg_base.append("g")
	        .attr('transform', "translate(" + configSankey.margin.left + "," + configSankey.margin.top + ")");

	    var sankey = d3.sankey()
	        .nodeWidth(15)
	        .nodePadding(10)
	        .extent([
	            [0, 0],
	            [dimensions.width, dimensions.height]
	        ]);

	    var path = d3.sankeyLinkHorizontal();

	    //Fonts
	    var _getFontSize = function(d) {
	        return configSankey.nodes.fontSize;
	    }; //For default
	    var _dynamicFontSize;
	    var _updateRangeFontData = function(d) {}; //For default
	    if (configSankey.nodes.dynamicSizeFontNode.enabled) {
	        _dynamicFontSize = d3.scaleLinear().range(
	            [configSankey.nodes.dynamicSizeFontNode.minSize,
	                configSankey.nodes.dynamicSizeFontNode.maxSize
	            ]);
	        _updateRangeFontData = function(nodeData) {
	            _dynamicFontSize.domain(d3.extent(nodeData, function(d) {
	                return d.value
	            }));
	        };
	        _getFontSize = function(d) {
	            return Math.floor(_dynamicFontSize(d.value));
	        };
	    }
		
		//options defaults for drag nodes
		var _nodes_draggableX = false;
		var _nodes_draggableY = true;
		
		if (configSankey.nodes.draggableX != undefined) _nodes_draggableX = configSankey.nodes.draggableX;
		if (configSankey.nodes.draggableY != undefined) _nodes_draggableY = configSankey.nodes.draggableY;

	    //Colors
	    //set color in nodes, case not exists
	    for (var i = 0; i < _dataSankey.nodes.length; i++)
	        if (_dataSankey.nodes[i].color == undefined)
	            _dataSankey.nodes[i].color = configSankey.nodes.colors(_dataSankey.nodes[i].name.replace(/ .*/, ""));

	    //Tooltip function:
	    //D3 sankey diagram with view options (Austin Czarnecki�s Block cc6371af0b726e61b9ab)
	    //https://bl.ocks.org/austinczarnecki/cc6371af0b726e61b9ab
	    var linkTooltipOffset = 65,
	        nodeTooltipOffset = 130;
	    var tipLinks = d3.tip().attr("class", "d3-tip").offset([-10, 0]);
	    var tipNodes = d3.tip().attr("class", "d3-tip d3-tip-nodes").offset([-10, 0]);

	    function _formatValueTooltip(val) {
	        if (configSankey.links.formatValue)
	            return configSankey.links.formatValue(val);
	        else
	            return val + ' ' + configSankey.links.unit;
	    }

	    tipLinks.html(function(d) {
	        var title, candidate;
	        if (_dataSankey.links.indexOf(d.source.name) > -1) {
	            candidate = d.source.name;
	            title = d.target.name;
	        } else {
	            candidate = d.target.name;
	            title = d.source.name;
	        }
	        var html = '<div class="table-wrapper">' +
	            '<center><h1>' + title + '</h1></center>' +
	            '<table>' +
	            '<tr>' +
	            '<td class="col-left">' + candidate + '</td>' +
	            '<td align="right">' + _formatValueTooltip(d.value) + '</td>' +
	            '</tr>' +
	            '</table>' +
	            '</div>';
	        return html;
	    });
//	    var topContentSVG = d3.select('.sk-svg').node().getBoundingClientRect().top;
	    var topContentSVG = $(d3.select('.sk-svg').node()).position().top;
	    tipLinks.move = function(event) {
	        tipLinks
	            .style("top", function() {
	                if (d3.event.pageY - topContentSVG - linkTooltipOffset >= 0)
	                    return (d3.event.pageY - linkTooltipOffset) + "px";
	                else
	                    return d3.event.pageY + 20 + "px";
	            })
	            .style("left", function() {
	                var left = (Math.max(d3.event.pageX - linkTooltipOffset, 10));
	                left = Math.min(left, window.innerWidth - d3.select('.d3-tip').node().getBoundingClientRect().width - 20)
	                return left + "px";
	            })
	    };

	    tipNodes.html(function(d) {
	        var nodeName = d.name;
	        var linksFrom = d.targetLinks; //invert for reference
	        var linksTo = d.sourceLinks;
	        var html;

	        html = '<div class="table-wrapper">' +
	            '<center><h1>' + nodeName + '</h1></center>' +
	            '<table>';
	        if (linksFrom.length > 0 & linksTo.length > 0) {
	            html += '<tr><td><h2>' + configSankey.tooltip.labelSource + '</h2></td><td></td></tr>'
	        }
	        for (i = 0; i < linksFrom.length; ++i) {
	            html += '<tr>' +
	                '<td class="col-left">' + linksFrom[i].source.name + '</td>' +
	                '<td align="right">' + _formatValueTooltip(linksFrom[i].value) + '</td>' +
	                '</tr>';
	        }
	        if (linksFrom.length > 0 & linksTo.length > 0) {
	            html += '<tr><td></td><td></td><tr><td></td><td></td> </tr><tr><td><h2>' + configSankey.tooltip.labelTarget + '</h2></td><td></td></tr>'
	        }
	        for (i = 0; i < linksTo.length; ++i) {
	            html += '<tr>' +
	                '<td class="col-left">' + linksTo[i].target.name + '</td>' +
	                '<td align="right">' + _formatValueTooltip(linksTo[i].value) + '</td>' +
	                '</tr>';
	        }
	        html += '</table></div>';
	        return html;
	    });
	    tipNodes.move = function(event) {
	        tipNodes.boxInfo = d3.select('.d3-tip-nodes').node().getBoundingClientRect();
	        tipNodes
	            .style("top",
	                function() {
	                    if ((d3.event.pageY - topContentSVG - tipNodes.boxInfo.height - 20) >= 0)
	                        return (d3.event.pageY - tipNodes.boxInfo.height - 20) + "px";
	                    else
	                        return d3.event.pageY + 20 + "px";
	                }
	            )
	            .style("left", function() {
	                var left = (Math.max(d3.event.pageX - nodeTooltipOffset, 10));
	                left = Math.min(left, window.innerWidth - d3.select('.d3-tip').node().getBoundingClientRect().width - 20)
	                return left + "px";
	            })
	    };

	    svg.call(tipLinks);
	    svg.call(tipNodes);
	    var _stopTooltips = function() {
	        if (tipLinks) tipLinks.hide();
	        if (tipNodes) tipNodes.hide();
	    };

	    //Load data
	    sankey(_dataSankey);

	    //update range font data
	    _updateRangeFontData(_dataSankey.nodes);


	    var link = svg.append("g").selectAll(".sk-link")
	        .data(_dataSankey.links, function(l) {
	            return l.id;
	        })
	        .enter().append("path")
	        .attr("class", "sk-link")
	        .attr("d", path)
	        .attr("filter", function(d){
	        	var _selectkey = d.source.name.split('-');
	        	var check = false;
	        	var selectedData = {};
	        	$.each(self.dimensions, function(_i, _ao) {
					$.each(self.filteredData, function(_index, _val) {		
						if(_val[_ao.name] === _selectkey[0]){
							selectedData[_ao.name] = _selectkey[0];
						}
					});
					for (var index = 0; index < self.trackingData.length; index++) {
						if (self.trackingData[index][_ao.name] && self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
							check = true;
						}
					}
				});
	        	
	        	return check? "true" : "false";
	        })
	        .attr("selectKey", function(d){ var selectKey = d.source.name.split('-');
	        return selectKey[0];})
	        .style("stroke", function(l) {
	            return l.source.color;
	        })
	        .style("stroke-width", function(l) {
	            return Math.max(1, l.width) + "px";
	        })
	        .sort(function(a, b) {
	            return b.width - a.width;
	        })
	        .on("click",function(d){
	        	mouseclick(d, this)
	        });
	    if (configSankey.tooltip.infoDiv)
	        link.on('mousemove', tipLinks.move).on('mouseover', tipLinks.show).on('mouseout', tipLinks.hide);
	    else
	        link.append("title").text(function(d) {
	            return d.source.name + " -> " + d.target.name + "\n" + _formatValueTooltip(d.value);
	        });

	    // the function for moving the nodes
	    function _dragmove(d) {
	        _stopTooltips();
			if (_nodes_draggableX && (d3.event.x < dimensions.width)) {
	            d.x0 = Math.max(0, Math.min(dimensions.width - sankey.nodeWidth(), d.x0 + d3.event.dx));
	            d.x1 = d.x0 + sankey.nodeWidth();
			}
			if (_nodes_draggableY && (d3.event.y < dimensions.height)) {
	            var heightNode = d.y1 - d.y0;
	            d.y0 = Math.max(0, Math.min(dimensions.height - (d.y1 - d.y0), d.y0 + d3.event.dy));
	            d.y1 = d.y0 + heightNode;
			}
	        d3.select(this).attr("transform", "translate(" + d.x0 + "," + d.y0 + ")");
	        sankey.update(_dataSankey);
	        link.attr("d", path);
	    }

	    function mouseclick(d, s){
			
			var selectKey = d.source.name.split('-');
             switch(self.IO.MasterFilterMode){
				case 'Multiple':
					var inArray = false;
					var selectedData = {};
					var key = d3.select(s).attr("selectKey");
					$.each(selectKey,function(_j,_selectkey){
						$.each(self.dimensions, function(_i, _ao) {
							$.each(self.filteredData, function(_index, _val) {		
								if(_val[_ao.name] === _selectkey.trim()){
									selectedData[_ao.name] = _selectkey.trim();
								}
							});
							for (var index = 0; index < self.trackingData.length; index++) {
								if (self.trackingData[index][_ao.name] && self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
									self.trackingData.splice(index, 1);
									index--;
									inArray = true;
									d3.selectAll('.sk-link[selectKey="'+key+'"]').style('stroke-opacity', "").attr("filter", "false");
								}
							}
						});

					});
					
					if (!inArray) {
						d3.selectAll('.sk-link[selectKey="'+key+'"]').style('stroke-opacity', 0.5).attr("filter", "true");
						self.trackingData.push(selectedData);
					}
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
				case 'Single':

					d3.selectAll('path.sk-link').style('stroke-opacity', "").attr("filter", "false");
					self.trackingData = [];
					var key = d3.select(s).attr("selectKey");
					var selectedData = {};
					$.each(selectKey,function(_j,_selectkey){
						$.each(self.dimensions, function(_i, _ao) {
							$.each(self.filteredData, function(_index, _val) {		
								if(_val[_ao.name] === _selectkey.trim()){
									self.trackingData = [];
									d3.selectAll('.sk-link[selectKey="'+key+'"]').style('stroke-opacity', 0.5).attr("filter", "true");
									selectedData[_ao.name] = _selectkey.trim();
									self.trackingData.push(selectedData);
								}
							});
						});
					});
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
			}
	    }

	    var node = svg.append("g").selectAll(".sk-node")
	        .data(_dataSankey.nodes, function(d) {
	            return d.name;
	        })
	        .enter().append("g")
	        .attr("class", "sk-node")
	        .attr("transform", function(d) {
	            return "translate(" + d.x0 + "," + d.y0 + ")";
	        })
	    if (configSankey.tooltip.infoDiv)
	        node
	        .on('mousemove', tipNodes.move)
	        .on('mouseover', function(d){tipNodes.show})
	        .on('mouseout', tipNodes.hide)
	    else
	        node.append("title").text(function(d) {
	            return d.name + "\n" + _formatValueTooltip(d.value);
	        });
	    //Drag nodes	
	    if (_nodes_draggableX || _nodes_draggableY)
	        node.call(d3.drag().subject(function(d) {
	            return d;
	        }).on("start", function(d) {
	            d3.event.sourceEvent.stopPropagation();
	            this.parentNode.appendChild(this);
	        }).on("drag", _dragmove));

	    node.append("rect")
	        .attr("height", function(d) {
	            return Math.abs((d.y1 - d.y0));
	        })
	        .attr("width", sankey.nodeWidth())
	        .style("fill", function(d) {
	            return d.color;
	        })
	        .style("stroke", function(d) {
	            return d3.rgb(d.color).darker(1.8);
	        });

	    node.append("text")
	        .attr("x", -6)
	        .attr("y", function(d) {
	            return (d.y1 - d.y0) / 2;
	        })
	        .attr("dy", ".35em")
	        .attr("text-anchor", "end")
	        .attr("transform", null)
	        .style("fill", function(d) {
	            return d3.rgb(d.color).darker(2.4);
	        })
	        .text(function(d) {
	            return d.name;
	        })
	        .style("font-size", function(d) {
	            return _getFontSize(d) + "px";
	        })
	        .style("font-family", self.meta.LayoutOption.Label.family)
	        .filter(function(d) {
	            return d.x0 < dimensions.width / 2;
	        })
	        .attr("x", 6 + sankey.nodeWidth())
	        .attr("text-anchor", "start");

	    //https://bl.ocks.org/syntagmatic/77c7f7e8802e8824eed473dd065c450b
	    var _updateLinksValues = function(dataUpdated) {
	        _stopTooltips();
	        sankey(dataUpdated);
	        sankey.update(dataUpdated);

	        //update range font data
	        _updateRangeFontData(dataUpdated.nodes);

	        svg.selectAll(".sk-link")
	            .data(dataUpdated.links, function(d) {
	                return d.id;
	            })
	            .sort(function(a, b) {
	                return b.width - a.width;
	            })
	            .transition()
	            .duration(1300)
	            .attr("d", path)
	            .style("stroke-width", function(l) {
	                return Math.max(1, l.width) + "px";
	            });

	        svg.selectAll(".sk-node")
	            .data(dataUpdated.nodes, function(d) {
	                return d.name;
	            })
	            .transition()
	            .duration(1300)
	            .attr("transform", function(d) {
	                return "translate(" + d.x0 + "," + d.y0 + ")";
	            });

	        svg.selectAll(".sk-node rect")
	            .transition()
	            .duration(1300)
	            .attr("height", function(d) {
	                return Math.abs((d.y1 - d.y0));
	            })
	            .on("click",function(d){alert('dddd')});

	        svg.selectAll(".sk-node text")
	            .transition()
	            .duration(1300)
	            .attr("y", function(d) {
	                return (d.y1 - d.y0) / 2;
	            })
	            .style("font-size", function(d) {
	                return _getFontSize(d) + "px";
	            }).style("font-family", self.meta.LayoutOption.Label.family);
	    };

		//Update value of links, for call the function '_updateLinksValues' transition values (old to new)
		//This function only update values from links
	    this.updateData = function(dataUpdated) {
	        for (var i = 0; i < dataUpdated.links.length; i++) {
	            var idLinkUpdate = dataUpdated.links[i].id || dataUpdated.links[i].source + " -> " + dataUpdated.links[i].target;
	            var linkToUpdate = _dataSankey.links.filter(function(l) {
	                return l.id == idLinkUpdate
	            })[0];
	            if (linkToUpdate) linkToUpdate.value = _safeValueToLink(dataUpdated.links[i].value);
	        }
	        _updateLinksValues(_dataSankey);
	    };

	    return this;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self,self.SankeyChart);
	}
	
	this.functionDo2 = function(_f) {		
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.SankeyChart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.SankeyChart['ShowCaption'] = false;
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
                            	
                            	self.SankeyChart['Name'] = newName;
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
				var chagePalette = self.SankeyChart.Palette;
				var firstPalette = self.SankeyChart.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.SankeyChart.Palette) != -1
										? self.SankeyChart.Palette
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
                                    self.SankeyChart.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.SankeyChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	self.SankeyChart.Palette = firstPalette;
                            chagePalette = firstPalette;
                            self.resize();
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.SankeyChart.Palette = chagePalette;
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
//				var chagePalette = self.SankeyChart.Palette;
//				var firstPalette = self.SankeyChart.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.SankeyChart.Palette) 
//										? self.SankeyChart.Palette
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
//                                    self.SankeyChart.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.SankeyChart.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.SankeyChart.Palette);
//                            chagePalette = firstPalette;
//                            self.SankeyChart.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.SankeyChart.Palette = chagePalette;
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

WISE.libs.Dashboard.SankeyChartFieldManager = function() {
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
