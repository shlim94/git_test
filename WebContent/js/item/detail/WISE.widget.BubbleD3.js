WISE.libs.Dashboard.item.BubbleD3Generator = function() {
	var self = this;

	this.type = 'BUBBLE_D3';

	this.dashboardid;
	this.itemid;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	this.dxItem;
	this.tempData;
	var dataMember;
	var Exprname;
	var FilterArray = [];
	
	
	this.customPalette = [];
	this.isCustomPalette = false;
	
	this.BubbleD3 = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	this.trackingData = [];
	this.tempTrackingData = [];
	
	//팔레트 
	this.customPalette = [];
	this.isCustomPalette = false;
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [];
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
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

	this.setTackingFlag = function(chk)	{
		this.tracked = chk;
	};

	this.setBubbleD3 = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.BubbleD3['ComponentName'] = this.ComponentName;
		this.BubbleD3['Name'] = this.Name;
		this.BubbleD3['DataSource'] = this.dataSourceId;

		this.BubbleD3['DataItems'] = this.fieldManager.DataItems;
		this.BubbleD3['Arguments'] = this.fieldManager.Arguments;
		this.BubbleD3['Values'] = this.fieldManager.Values;
		
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.BubbleD3;
		
		//초기 팔레트값 설정
		if (!(this.BubbleD3['Palette'])) {
//			this.Chart['Palette'] = 'Material';
			this.BubbleD3['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		if (this.BubbleD3.InteractivityOptions) {
			if (!(this.BubbleD3.InteractivityOptions.MasterFilterMode)) {
				this.BubbleD3.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BubbleD3.InteractivityOptions.TargetDimensions)) {
				this.BubbleD3.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BubbleD3.InteractivityOptions.IsDrillDownEnabled)) {
				this.BubbleD3.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.BubbleD3.InteractivityOptions.IgnoreMasterFilters)) {
				this.BubbleD3.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BubbleD3.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.BubbleD3.LayoutOption){
			this.BubbleD3.LayoutOption = {
					Label: {
						color: '#ffffff',
						family: 'Noto Sans KR'
					}
			}
		}
		
		if(!this.BubbleD3['ZoomAble']){
			this.BubbleD3.ZoomAble = 'none'
		}
		
		if (!(this.BubbleD3['TextFormat'])) {
			this.BubbleD3['TextFormat'] = 'Argument, Value'
		}
		
	};

	this.setBubbleD3forOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setBubbleD3();
		}
		else{
			this.BubbleD3 = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.BubbleD3['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.BubbleD3['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.BubbleD3['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.BubbleD3['Palette'])) {
			this.BubbleD3['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BubbleD3Option = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BUBBLE_D3_DATA_ELEMENT);
				
				$.each(BubbleD3Option,function(_i,_bubbled3Option){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _bubbled3Option.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _bubbled3Option.CTRL_NM;
					}
					if(self.BubbleD3.ComponentName == CtrlNM){
						self.BubbleD3['Palette'] = _bubbled3Option.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BubbleD3.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BubbleD3.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.BubbleD3.InteractivityOptions) {
			if (!(this.BubbleD3.InteractivityOptions.MasterFilterMode)) {
				this.BubbleD3.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BubbleD3.InteractivityOptions.TargetDimensions)) {
				this.BubbleD3.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BubbleD3.InteractivityOptions.IsDrillDownEnabled)) {
				this.BubbleD3.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.BubbleD3.InteractivityOptions.IgnoreMasterFilters)) {
				this.BubbleD3.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BubbleD3.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.BubbleD3.LayoutOption){
			this.BubbleD3.LayoutOption = {
					Label: {
						color: '#ffffff',
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.BubbleD3['ZoomAble']){
			this.BubbleD3.ZoomAble = 'none'
		}
		if (!(this.BubbleD3['TextFormat'])) {
			this.BubbleD3['TextFormat'] = 'Argument, Value'
		}
	}
	this.setBubbleD3ForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setBubbleD3();
		}
		else{
			this.BubbleD3 = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.BubbleD3['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.BubbleD3['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.BubbleD3['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.BubbleD3['Palette'])) {
			this.BubbleD3['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BubbleD3Option = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BUBBLE_D3_DATA_ELEMENT);
				
				$.each(BubbleD3Option,function(_i,_bubbled3Option){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _bubbled3Option.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _bubbled3Option.CTRL_NM;
//					}
					if(self.BubbleD3.ComponentName == CtrlNM){
						self.BubbleD3['Palette'] = _bubbled3Option.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BubbleD3.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BubbleD3.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.BubbleD3.InteractivityOptions) {
			if (!(this.BubbleD3.InteractivityOptions.MasterFilterMode)) {
				this.BubbleD3.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BubbleD3.InteractivityOptions.TargetDimensions)) {
				this.BubbleD3.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BubbleD3.InteractivityOptions.IsDrillDownEnabled)) {
				this.BubbleD3.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.BubbleD3.InteractivityOptions.IgnoreMasterFilters)) {
				this.BubbleD3.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BubbleD3.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if(!this.BubbleD3.LayoutOption){
			this.BubbleD3.LayoutOption = {
					Label: {
						color: '#ffffff',
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.BubbleD3['ZoomAble']){
			this.BubbleD3.ZoomAble = 'none'
		}
		if (!(this.BubbleD3['TextFormat'])) {
			this.BubbleD3['TextFormat'] = 'Argument, Value'
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
			self.setBubbleD3();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.BubbleD3);
			gDashboard.itemGenerateManager.generateItem(self, self.BubbleD3);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setBubbleD3forOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.BubbleD3);
			gDashboard.itemGenerateManager.generateItem(self, self.BubbleD3);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.BubbleD3)) {
			this.setBubbleD3ForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.BubbleD3);
			gDashboard.itemGenerateManager.generateItem(self, self.BubbleD3);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setBubbleD3ForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.BubbleD3);
			gDashboard.itemGenerateManager.generateItem(self, self.BubbleD3);
		}


		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
			topIconPanel.append(trackingDataContainerHtml);
		}

		var dxConfig = this.getDxItemConfig(this.meta);

		var measureKey = this.measures[0];
		
		
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var dimensions = [];
		dimensions = dimensions.concat(_.clone(this.dimensions));
		var measures = [];
		measures = measures.concat(_.clone(this.measures));
		var tempDataConfig;
		
		tempDataConfig = SQLikeUtil.fromJson(dimensions, measures, []);
		if(typeof self.dataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
			if(self.dataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
				tempDataConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
			}else{
				tempDataConfig.Where = [];
			}
		}else{
			tempDataConfig.Where = [];
        }
		if(self.meta.InteractivityOptions)
			if(self.meta.InteractivityOptions.IgnoreMasterFilters || self.meta.InteractivityOptions.MasterFilterMode !== "Off")
				tempDataConfig.Where = [];
		self.tempData = SQLikeUtil.doSqlLike(this.dataSourceId, tempDataConfig, self);
		self.currentMeasureName = measureKey.caption;
		self.trackingData = [];
		self.tempTrackingData = [];
		
		//2020.11.03 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('d3');
		self.fBubbleD3(_data, this.measures, this.dimensions, self.tempData);
		
//		self.currentMeasureName = measureKey.caption;
//		self.fBubbleD3(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
//		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
//		"instance");
		/*dogfoot d3 차트 기준 측정값 선택 오류 수정 shlim 20200701*/
		gDashboard.itemGenerateManager.renderButtons(self);
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
	};
	
	
	/*this.menuItemGenerate = function(){
		if($('#data').length > 0){
			$('#data').remove();
		}

		$('#menulist').removeClass('col-2');
		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//		$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
//		}

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

//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//		$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
//		}

		// initialize UI elements
		tabUi();
		designMenuUi();
		compMoreMenuUi();
	}*/
	
	//
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
//		if($('#data').length > 0){
//			$('#data').remove();
//		}
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
//		}
//		
//		if($('#design').length > 0){
//			$('#design').remove();
//		}
//		
////		if($('#designMenu').length == 0){
////			$('<li id="designMenu"><a href="#" class="lnb-link txt new"><span>'+ gMessage.get('WISE.message.page.widget.nav.design') +'</span></a></li>').insertBefore('#openReport');	
////		}
//		
////		$('#menulist').append($('<li id="design"><a href="#tab5primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.design') +'</a></li>'));
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
//		}
//		
//		//d3 속성 추가
//		$('#tab5primary').empty();
//		
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
//		$().appendTo($('#tab4primary'));
//		
//		// initialize UI elements
//		tabUi();
//		designMenuUi();
//		compMoreMenuUi();
//        $('.single-toggle-button').on('click', function(e) {
//            e.preventDefault();
//            $(this).toggleClass('on');
//        });
//        $('.multi-toggle-button').on('click', function(e) {
//            e.preventDefault();
//            var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
//            if ($(this)[0] !== currentlyOn[0]) {
//                currentlyOn.removeClass('on');
//            }
//            $(this).toggleClass('on');
//		});
//
//		// toggle 'on' status according to chart options
//		if (self.IO) {
//			if (self.IO['MasterFilterMode'] === 'Single') {
//				$('#singleMasterFilter').addClass('on');
//			} else if (self.IO['MasterFilterMode'] === 'Multiple') {
//				$('#multipleMasterFilter').addClass('on');
//			}
//			if (self.IO['IsDrillDownEnabled']) {
//				$('#drillDown').addClass('on');
//			}
//			if (self['isMasterFilterCrossDataSource']) {
//				$('#crossFilter').addClass('on');
//			}
//			if (self.IO['IgnoreMasterFilters']) {
//				$('#ignoreMasterFilter').addClass('on');
//			}
//			if (self.IO['TargetDimensions'] === 'Argument') {
//				$('#targetArgument').addClass('on');
//			} else if (self.IO['TargetDimensions'] === 'Series') {
//				$('#targetSeries').addClass('on');
//			}
//        }
//		
//		$('<div id="editPopup">').dxPopup({
//            height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('#tab5primary');
//		// settings popover
//		$('<div id="editPopover">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//		}).appendTo('#tab5primary');
//		
//		$('<div id="editPopup2">').dxPopup({
//			height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('body');
//		// settings popover
//		$('<div id="editPopover2">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//        }).appendTo('#tab4primary');
//		
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);	
//		});
//		
	}

	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if(gDashboard.reportType != 'AdHoc' || !(gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer')){
				if (self.dxItem) {
				    d3.selectAll('circle')
					.style("stroke-width", '')
					.style("stroke", '')
					.attr("filter", 'false');
				}
				self.trackingData = [];
				self.tempTrackingData = [];
				self.selectedPoint = undefined;	
			}
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
//			if($('#'+this.itemid+'editBubbleD3Popover').length == 0 ){
//				$('<div id="'+this.itemid+'editBubbleD3Popover">').dxPopover({
//					height: 'auto',
//					width: 'auto',
//					position: 'bottom',
//					visible: false
//				}).appendTo('#wrapper');
//			}
//			var p = $('#'+this.itemid+'editBubbleD3Popover').dxPopover('instance');
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
//						self.fBubbleD3(self.filteredData);
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
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		//2020.02.07 mksong sqllike 적용 dogfoot
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var dataSourceId = this.dataSourceId;
		/**
		 * 데이터 중복 제거 코드
		 */
		var ValueArray = new Array();
		var ValueArray2 = new Array();
		var FieldArray = new Array();
		var selectArray = new Array();

		var Dimension = WISE.util.Object.toArray(this.meta.DataItems.Dimension);
		var Measure =  WISE.util.Object.toArray(MeasureKey);
		
		$.each(this.measures,function(_i,_Mea){
			selectArray.push('|'+_Mea.summaryType+'|');
			selectArray.push(_Mea.name);
			//2020.02.05 mksong SQLLIKE doSqlLike BUBBLED3 적용 dogfoot
			selectArray.push('|as|');
			selectArray.push(_Mea.captionBySummaryType);
		})
		$.each(Dimension,function(_i,_Dim){
			if(_i == 0){
				selectArray.push(_Dim.DataMember);
				FieldArray.push(_Dim.DataMember);
				var sqlConfig ={};
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
				sqlConfig.GroupBy = FieldArray;
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				var queryData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, self);
				ValueArray.push(queryData);
			}else{
				selectArray.push(_Dim.DataMember);
				FieldArray.push(_Dim.DataMember);
				var sqlConfig ={};
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
				sqlConfig.GroupBy = FieldArray;
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				self.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, self); 
				self.csvData = self.filterdData;
				
				ValueArray2.push(self.filteredData);
			}
		});
		
		$.each(ValueArray[0],function(_i,_val){
			ValueArray[0][_i]["children"]= new Array();
			$.each(ValueArray2[0],function(_j,_val2){
				if(_val[Dimension[0].DataMember] == _val2[Dimension[0].DataMember] ){
					ValueArray[0][_i]["children"].push(_val2);
				}else{
					
				}
			});
		});

	
		/*$.each(Dimension,function(_i,_Dim){
			selectArray.push(_Dim.DataMember);
			FieldArray.push(_Dim.DataMember);
		});

		$.each(Measure,function(_i,_Mea){
			selectArray.push('|sum|');
			selectArray.push(_Mea.name);
		})

		var sqlConfig ={};
		sqlConfig.Select = selectArray;
		sqlConfig.From = _data;
		sqlConfig.GroupBy = FieldArray;
		ValueArray.push(SQLike.q(sqlConfig));*/

		/*var resultArr = new Array();
		$.each(ValueArray,function(_i,_e){
			$.each(_e,function(_item,_obj){
				var str = new Array();
				var object = new Object();
				$.each(Dimension,function(_i,_Dim){
					str.push(_obj[_Dim.DataMember]);
				});
				$.each(Measure,function(_i,_Mea){
					object['value'] = _obj['sum_'+_Mea.name];
				});
				$.each(str,function(_i,_keyval){
					object['name'+_i] = str[_i];
				});
				object['name'] = str.join(' - ');
				resultArr.push(object);
			})
		});*/
		return ValueArray;
	};
	
//	this.resize = function() {
//	/*dogfoot D3 버블차트 아이템 변경 shlim 20200629*/
////		self.fBubbleD3(self.filteredData, self.measures, self.dimensions, 
////							self.deleteDuplecateData(self.filteredData,self.measures[0]));
//		self.fBubbleD3(self.filteredData, self.measures, self.dimensions, self.tempData);
//		d3.selectAll('circle[filter="true"]')
//		.style("stroke-width", '3')
//		.style("stroke", 'blue')
//		.attr('filter', "true");
//		
//		gProgressbar.hide();
//	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		/*dogfoot D3 버블차트 아이템 변경 shlim 20200629*/
		var dupledatacehck
		if(typeof self.resizeData != 'undefined'){
		    dupledatacehck = self.resizeData;
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
		    self.fBubbleD3(self.filteredData, self.measures, self.dimensions, dupledatacehck);
			d3.selectAll('circle[filter="true"]')
			.style("stroke-width", '3')
			.style("stroke", 'blue')
			.attr('filter', "true");
		}
		
		gProgressbar.hide();
	};
	/*dogfoot D3 버블차트 아이템 변경 shlim 20200629*/
	this.fBubbleD3 = function(jsonData, _measures, dimensions, dupleData) {
		/*dogfoot d3 차트 기준 측정값 선택 오류 수정 shlim 20200701*/
		var measures =  WISE.util.Object.toArray(_measures);
		if (!dupleData || ($.type(dupleData) === 'array' && dupleData.length === 0)
				|| (dupleData.length == 1 && dupleData[0].value == 0 && dupleData[0].name == "")
				|| (dupleData.length == 1 && (dupleData[measures[0].nameBySummaryType2] === 0 || dimensions.length === 0))) {
			$('#'+self.itemid + ' .nodata-layer').remove();
			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
			$("#" + self.itemid).children().css('display','none');
			$("#" + self.itemid).prepend(nodataHtml);
			if($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0){
				$("#" + self.itemid).height('100%');
				$("#" + self.itemid).width('100%');
			}
			$("#" + self.itemid).css('display', 'block');
			
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}

			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();	
				gDashboard.updateReportLog();
			}	
			return;
		}else{
			self.resizeData = dupleData;
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
		/*dogfoot d3 측정값 포멧 변경 기능 추가 shlim 20200828*/
		var Number = WISE.util.Number,
		labelFormat = 'Number',
		labelUnit = 'O',
		labelPrecision = 0,
		labelSeparator = true,
		labelSuffixEnabled = false,
		labelSuffix = {
			O: '',
			K: '천',
			M: '백만',
			B: '십억'
		};
		var NumericFormat;
		$.each(WISE.util.Object.toArray(self.DI.Measure),function(_i,_val){
			if(measures[0].uniqueName ===  _val.UniqueName){
				if(_val.NumericFormat){
				    NumericFormat = _val.NumericFormat;	
				}
			}
		});
		if(typeof NumericFormat != 'undefined'){
			labelFormat = NumericFormat.FormatType;
			labelUnit = NumericFormat.Unit;
			labelPrecision = NumericFormat.Precision;
			labelSeparator = NumericFormat.IncludeGroupSeparator;
			labelSuffixEnabled = NumericFormat.SuffixEnabled;
			labelSuffix =NumericFormat.Suffix;
		}
		
		   var w = $('#'+self.itemid).width();
		   var h = $('#'+self.itemid).height();
		   var currentTransform = [w / 2, h / 2, h];
		   
		   d3.select("#" + self.itemid).selectAll("svg").remove();
//				var paletteName = self.BubbleD3.Palette;
//				var color = getPaletteValue(paletteName);
		   		var color = gDashboard.d3Manager.getPalette(self);
		        //var color = d3.scaleOrdinal(d3.schemeCategory20);
		        
				var bubble = d3.pack(dupleData)
		            .size([w, h])
		            .padding(1.5);
		           

		        var svg = d3.select("#" + self.itemid).append("svg")
	            .attr("width", w)
	            .attr("height", h)
	            .attr("class", "mainBubbleSVG")
			   .append("g");

			   var zoomCnt = 0;
				function zoomable(){
					 var zoom = d3.zoom().on("zoom", function (d,zz) {
						 if(pressKey['z'] || pressKey['Z'])
							 d3.select('#'+self.itemid).select('g').attr("transform", function(){ 
								 return d3.event.transform;
							 })
						 else{
							// Move scrollbars.
							  const wrapper = $('#'+self.itemid);
							  if(pressKey['Shift'] && wrapper.css('overflow-x') != 'hidden')
							      wrapper.scrollLeft(wrapper.scrollLeft() + d3.event.sourceEvent.deltaY);
							  else if(wrapper.css('overflow-y') != 'hidden')
		                          wrapper.scrollTop(wrapper.scrollTop() + d3.event.sourceEvent.deltaY);
						 }
					 })

					  d3.select('#'+self.itemid).select('svg').call(zoom)
				}
				if(self.meta.ZoomAble != 'none'){
					zoomable();
				}
				
		        self.paletteData = self.tempData.map(function (val, index) {
		        	return val[self.dimensions[0].caption];
		        }).filter(function (val, index, arr) {
		        	return arr.indexOf(val) === index;
		        });
		        
		        var nodes = d3.hierarchy({children: dupleData})
		            .sum(function(d) {return d[measures[0].nameBySummaryType2]});     
		        
		        var node = svg.selectAll(".node")
		            .data(bubble(nodes).descendants())
		            .enter()
		            .filter(function(d){
		                return  !d.children
		            })
		            .append("g")
		            .attr("class", "node")
		            .attr("transform", function(d) {
		                return "translate(" + d.x + "," + d.y + ")";
		            })
                 .style("cursor", "pointer")
		            ;

		        node.append("title")
		            .text(function(d) {
		            	var titleName="";
		            	$.each(dimensions,function(_i,_Name){
                         titleName += " " + d.data[dimensions[_i].caption]
		            	})
		                return titleName + ": " + d.data[measures[0].nameBySummaryType2];
		            });
		        
		        var colCount = -1;
		        var deName="";
		        node.append("circle")
		            .attr("r", function(d) {
		                return d.r;
		            })
		            .style("fill", function(d,i) {
		            	if(deName != d.data[dimensions[0].caption]){
		            		colCount++;
		            	}else{
		            		
		            	}
		            	deName = d.data[dimensions[0].caption];
		            	if(colCount > color.length) colCount = 0;
		                return color[colCount];
		            })
		            .attr("filter", function(d){
		            	var inArray = false;
				    	  $.each(self.tempTrackingData, function(i, item){
				    		  var check = true;
				    		  $.each(item, function(name, value){
				    			  if(d.data[name] !== item[name]){
				    				  check = false;
				    				  return false;
				    			  }
				    		  });
				    		  
				    		  if(check) inArray = true;
				    	  })
				    	  return inArray? "true" : "false";
			    	  })
		            .on("mouseover", function() { 
		            	$(this).parent().find('text').attr('fill', "black");
		            	$(this).attr('cursor','pointer');
		            })
		            .on("mouseout", function() { $(this).parent().find('text').attr('fill', self.meta.LayoutOption.Label.color); })

		            .on("click", function(d){mouseclick(d.data,this)});


		        node.append("text")
		            .attr("dy", ".2em")
		            .style("text-anchor", "middle")
		            .html(function(d) {
		            	var titleName="";
		            	$.each(dimensions,function(_i,_Name){
                            titleName += " " + d.data[dimensions[_i].caption]
		            	})
		            	//titleName = titleName + " : " +Number.unit(d.data[[measures[0].nameBySummaryType2]], labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
		                return textFormat(titleName,"dim");
		            })
		            .attr("font-family", self.meta.LayoutOption.Label.family)
		            .attr("font-size", function(d){
		                return d.r/5;
		            })
		            .on("mouseover", function() { 
		            	$(this).parent().find('text').attr('fill', "black");
		            	$(this).attr('cursor','pointer');
		            })
		            .on("mouseout", function() { $(this).parent().find('text').attr('fill',  self.meta.LayoutOption.Label.color);})
		            .on("click", function(d){mouseclick(d.data,$(this).parent().find('circle')[0])})
		            .attr("fill",  self.meta.LayoutOption.Label.color);

		        node.append("text")
		            .attr("dy", "1.3em")
		            .style("text-anchor", "middle")
		            .text(function(d) {
		            	//return Number.unit(d.data[[measures[0].nameBySummaryType2]], labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled); 
		                return textFormat(d.data[[measures[0].nameBySummaryType2]],"mea");
		            })
		            .attr("font-family",  self.meta.LayoutOption.Label.family)
		            .attr("font-size", function(d){
		                return d.r/5;
		            })
		            .on("mouseover", function() { 
		            	$(this).parent().find('text').attr('fill', "black");
		            	$(this).attr('cursor','pointer');
		            })
		            .on("mouseout", function() { $(this).parent().find('text').attr('fill',  self.meta.LayoutOption.Label.color); })
		            .on("click", function(d){mouseclick(d.data,$(this).parent().find('circle')[0])})
		            .attr("fill",  self.meta.LayoutOption.Label.color);

		        d3.select(self.frameElement)
		            .style("height", h + "px");
		        
	        	function mouseclick(d,_this){
					
					var selectKey = d;
		             switch(self.IO.MasterFilterMode){
						case 'Multiple':
							var inArray = false;
							var selectedData = {};
							if(d3.select(_this).attr("filter") === "true"){
							
								d3.select(_this)
								.style("stroke-width", '')
								.style("stroke", '')
								.attr("filter", 'false');

							}else{

								d3.select(_this)
								.style("stroke-width", '3')
								.style("stroke", 'blue')
								.attr("filter", 'true');
							}
							var checkIndex = -1;
					    	  $.each(self.tempTrackingData, function(i, item){
					    		  var check = true;
					    		  $.each(item, function(name, value){
					    			  if(d[name] !== item[name]){
					    				  check = false;
					    				  return false;
					    			  }
					    		  });
					    		  
					    		  if(check) checkIndex = i;
					    	  })

					    	if(checkIndex > -1){
					    		self.tempTrackingData.splice(checkIndex, 1);
					    	}else{
					    		self.tempTrackingData.push(d);
					    	}
					    	
					    	
					    	self.trackingData = [];
							$.each(self.tempTrackingData, function(_j, data){
								$.each(self.dimensions, function(_i, _ao) {
					       			var inArray = false;
					       			var selectedData = {};
					       			selectedData[_ao.name] = data[_ao.name];
					       			for (var index = 0; index < self.trackingData.length; index++) {
					       				if (self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
					       					inArray = true;
					       				}
					       			}
					       			if (!inArray) {
					       				self.trackingData.push(selectedData);
					       			}
		
					       		});
					    	})
					    	/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
							if(WISE.Constants.editmode === "viewer"){
								gDashboard.itemGenerateManager.focusedItem = self;
							}
							gDashboard.filterData(self.itemid, self.trackingData);
							break;
						case 'Single':

							self.trackingData = [];
                            
                            if(d3.select(_this).attr("filter") === "true"){
								d3.selectAll('#'+self.itemid+' circle')
								.style("stroke-width", '')
								.style("stroke", '')
								.attr("filter", 'false');

							}else{
								d3.selectAll('#'+self.itemid+' circle')
								.style("stroke-width", '')
								.style("stroke", '')
								.attr("filter", 'false');

								d3.select(_this)
								.style("stroke-width", '3')
								.style("stroke", 'blue')
								.attr("filter", 'true');
								
								$.each(dimensions, function(_i, _ao) {
				       				var selectedData = {};
					       			selectedData[_ao.name] = d[_ao.name];
					       			self.trackingData.push(selectedData);
					       		});
					    		
					    		self.tempTrackingData = [d];
					        }

                            /*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
        					if(WISE.Constants.editmode === "viewer"){
        						gDashboard.itemGenerateManager.focusedItem = self;
        					}
							gDashboard.filterData(self.itemid, self.trackingData);
							break;
					}
			    }

			    function getNumeric(d){
					return Number.unit(d, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
				}
				function textFormat(d,type){
					  var textValue= ""

					  switch(self.meta.TextFormat){
						  case 'none': {
							  textValue ="";
							  break;
						  }
						  case 'Argument': {
							  textValue = type === 'dim' ? d : ""
							  break;
						  }
						  case 'Value': {
							  textValue = type === 'mea' ? getNumeric(d) : ""
							  break;
						  }
						  case 'Argument, Value': {

							  textValue = type === 'mea' ? getNumeric(d) : d;
							  break;
						  }
						  case 'Percent': {
		//				  	  var percent = d3v3.format(".1%")
		//				  	  var rePer = d.parent != null ? percent(d.value / d.parent.value): percent(1)
		//					  textValue = d.data.key+'  :  '+ rePer;
							  if(type === 'mea'){
								  textValue = parseInt((d/d3.sum(dupleData, function(_d){return _d[measures[0].nameBySummaryType2]}))*100) + '%';
							  }
							  
							  break;
						  }
						  case 'Value, Percent': {
							  if(type === 'mea'){
								  textValue = getNumeric(d) + '(' + parseInt((d/d3.sum(dupleData, function(_d){return _d[measures[0].nameBySummaryType2]}))*100) + '%)';
							  }
							  break;
						  }
						  case 'Argument, Percent': {
							  if(type === 'mea'){
								  textValue = parseInt((d/d3.sum(dupleData, function(_d){return _d[measures[0].nameBySummaryType2]}))*100) + '%';
							  }else{
								  textValue = d;
							  }
							  break;
						  }
						  case 'Argument, Value, Percent': {
							  if(type === 'mea'){
								  textValue = getNumeric(d) + '(' + parseInt((d/d3.sum(dupleData, function(_d){return _d[measures[0].nameBySummaryType2]}))*100) + '%)';
							  }else{
								  textValue = d;
							  }
							  break;
						  }

					  }
					  return textValue
				  }
		 
	};
	
	
//	this.fBubbleD3 = function(jsonData, measures, dimensions, dupleData) {
//		//2020.05.04 AJKIM 데이터 항목 없을 때 이미지 추가 DOGFOOT
//		$('#'+self.itemid + ' .nodata-layer').remove();
//		if (!dupleData || ($.type(dupleData[0]) === 'array' && dupleData[0].length === 0)) {
//			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
//			$("#" + self.itemid).children().css('display','none');
//			$("#" + self.itemid).prepend(nodataHtml);
//			$("#" + self.itemid).css('display', 'block');
//			gProgressbar.hide();
//			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
//				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
//			}
//
//			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
//				gProgressbar.setStopngoProgress(true);
//				gProgressbar.hide();		
//			}
//			return;
//		}
//			$("#" + self.itemid).children().css('display','block');
//		   var w = $('#'+self.itemid).width();
//		   var h = $('#'+self.itemid).height();
//		   var oR = 0;
//		   var nTop = 0;
//		   var nTopCount = 0;
//		   var nTopRow = 0;
//		   var datatest = this.meta;
//		   var demensionNm =  new Array();
//		   var valueName = new Array();
//		   /*var valueName = self.measures[0].nameBySummaryType;
//		   var valueName2 = self.measures[1].nameBySummaryType;*/
//		   var measuresln = self.measures.length;
//		   var clickYn = 0 ;
//		   $.each(self.measures,function(_i,_val){
//			   valueName.push(self.measures[_i].nameBySummaryType);
//		   });	
//		   $.each(dimensions,function(_i,_val){
//			   demensionNm.push(_val.name);
//		   });	
//		   
//		   
//		   d3.select("#" + self.itemid).selectAll("svg").remove();
//		   
//		   var svg = d3.select("#" + self.itemid).append("svg:svg")
//		        .attr("class", "mainBubbleSVG")
//		        .attr("width", w)
//		        .attr("height",h)
//		        .on("mouseleave", function() {return resetBubbles();});
//	
//	  $.each(dupleData,function(_i,root){
//		   if(_i == 0){
//			   var bubbleObj = svg.selectAll(".topBubble")
//	           .data(root)
//	           .enter().append("g")
//	           .attr("id", function(d,i) {return "topBubbleAndText_"+i;});
//			   
//			   nTop = root.length;
//			   
//			   if(h > w){
//				   nTopRow = 3;
//				   if(nTop < nTopRow){
//					   nTopCount = nTop;
//				   }else{
//					   nTopCount  = nTopRow;
//				   }
//				   oR = h/(1+3*nTopCount);
//			   }else{
//				   nTopRow = 4;
//				   if(nTop < nTopRow){
//					   nTopCount = nTop;
//				   }else{
//					   nTopCount  = nTopRow;
//				   }
//				   oR = w/(1+3*nTopCount); 
//			   }
//			   
//			   
////			   var colVals = d3.scale.category10();
//				var paletteName = self.BubbleD3.Palette;
//				var rgb = getPaletteValue(paletteName);
//			   
//		        bubbleObj.append("circle")
//		            .attr("class", "topBubble")
//		            .attr("id", function(d,i) {return "topBubble" + i;})
//		            .attr("r", function(d) { return oR; })
//		            .attr("cx", function(d, i) {
//		            		return oR*(3*(1+(i%nTopCount))-1);
//		            })
//		            .attr("cy", function(d, i) {
//		            	if(nTop<nTopRow){
//		            		return 	(h+oR)/2.5;
//		            	}else{
//		            		return ((50+oR)*(parseInt(i/nTopCount)+1+parseInt(i/nTopCount)))
//		            	}
//		            /*	if(i>=nTopCount){
//		            		return ((h+oR)/1.7)
//		            	}else{
//		            		if(nTop<=3){
//	            				return 	(h+oR)/2.7;
//		            		}else{
//		            			return 	(h+oR)/5.5;
//		            		}
//		            	}*/
//		            	
//		            })
//		            .style("fill", function(d,i) { return rgb[i]; }) // #1f77b4
//		            .style("opacity",0.3)
//		            .on("mouseover", function(d,i) {return activateBubble(d,i);});
//		        
//		        
//		        bubbleObj.append("text")
//	            .attr("class", "topBubbleText")
//	            .attr("x", function(d, i) {
//		            		return oR*(3*(1+(i%nTopCount))-1);
//	            	}
//	            )
//	            .attr("y", function(d, i) {
//	            	if(nTop<nTopRow){
//	            		return 	(h+oR)/2.5;
//	            	}else{
//	            		return ((50+oR)*(parseInt(i/nTopCount)+1+parseInt(i/nTopCount)))
//	            	}
//	            })
//		        .style("fill", function(d,i) { return rgb[i]; }) // #1f77b4
//		            .attr("font-size", gDashboard.fontManager.getFontSize(oR/(nTopCount+1), 'Item'))
//		            .attr("font-family", gDashboard.fontManager.getFontFamily('Item'))
//		            .attr("text-anchor", "middle")
//		        .attr("dominant-baseline", "middle")
//		        .attr("alignment-baseline", "middle")
//		            .text(function(d) {return d[demensionNm[_i]]})      
//		            .on("mouseover", function(d,i) {return activateBubble(d,i);});
//		        
//		        for(var iB = 0; iB < nTop; iB++)
//		        {
//		            var childBubbles = svg.selectAll(".childBubble" + iB)
//		                .data(root[iB].children)
//		                .enter().append("g");
//		                 
//		        //var nSubBubble = Math.floor(root.children[iB].children.length/2.0);   
//		             
//		            childBubbles.append("circle")
//		                .attr("class", "childBubble" + iB)
//		                .attr("id", function(d,i) {return "childBubble_" + iB + "sub_" + i;})
//		                .attr("r",  function(d) {return oR/3.0;})
////		                .attr("cx", function(d,i) {return (oR*(3*((iB%nTopCount)+1)-1) + oR*1.5*Math.cos((i-1)*45/180*3.1415926));})
//		                 .attr("cx", function(d,i) {return w * 3; })
//		                .attr("cy", function(d,i) {
//		                		/*if(iB>=nTopCount){
//				            			return ((h+oR)/1.7 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//		                		}else{
//		                			if(nTop<=3){
//		                				return ((h+oR)/2.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}else{
//				            			return ((h+oR)/5.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}
//		                		}*/
//		                		return h * 3;
//		                	}
//		                )
//		                .attr("cursor","pointer")
//		                .style("opacity",0.0)
//		                .style("fill", "#eee")
//			            .on("click", function(d,i) {
////			            	return alert("click");
//			            	return valueBubble(d,i);
//			            })
//			            .append("svg:title");
//		            
//		            childBubbles.append("text")
//		                .attr("class", "childBubbleText" + iB)
////		                .attr("x", function(d,i) {return (oR*(3*((iB%nTopCount)+1)-1) + oR*1.5*Math.cos((i-1)*45/180*3.1415926));})
//		                .attr("x", function(d,i) {return w*3;})
//		                .attr("y", function(d,i) {
//			                	/*if(iB>=nTopCount){
//				            			return ((h+oR)/1.7 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//			                	}else{
//			                		if(nTop<=3){
//		                				return ((h+oR)/2.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}else{
//				            			return ((h+oR)/5.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}
//			                	}*/
//		                	return h*3;
//		                	}
//		                )
//		                .style("opacity",0.0)
//		                .attr("text-anchor", "middle")
//		                .style("fill", function(d,i) { return rgb[iB]; }) // #1f77b4
//		                .attr("font-size", gDashboard.fontManager.getFontSize(oR/(nTopCount*2), 'Item'))
//			            .attr("font-family", gDashboard.fontManager.getFontFamily('Item'))
//		                .attr("cursor","pointer")
//		                .attr("dominant-baseline", "middle")
//		                .attr("alignment-baseline", "middle")
////		                .text(function(d) {return "합계 : "+Math.round(d[valueName])});
//		                .text(function(d) {return d[demensionNm[_i+1]]});
////		                .on("click", function(d,i) {return valueBubble(d,i);});
//		               
//		            
//		        }
//		   }
//		  
//		});
//	   
//		 
//	    /*d3.json("../data/main_bubble.json", function(error, root) {
//
//	     
//	        var bubbleObj = svg.selectAll(".topBubble")
//	                .data(root.children)
//	                .enter().append("g")
//	                .attr("id", function(d,i) {return "topBubbleAndText_" + i});
//	             
//
//	        
//	        nTop = root.children.length;
//	        
//	      
//	        nTopCount = nTop;
//	        
//	        
//	        oR = w/(1+3*nTopCount);  
//		 
//		         
//		        var rgb = d3.scale.category10();
//		        bubbleObj.append("circle")
//		            .attr("class", "topBubble")
//		            .attr("id", function(d,i) {return "topBubble" + i;})
//		            .attr("r", function(d) { return oR; })
//		            .attr("cx", function(d, i) {
//		            		return oR*(3*(1+(i%nTopCount))-1);
//		            })
//		            .attr("cy", function(d, i) {
//		            	if(i>=nTopCount){
//		            		return ((h+oR)/1.7)
//		            	}else{
//		            		if(nTop<=3){
//	            				return 	(h+oR)/2.5;
//		            		}else{
//		            			return 	(h+oR)/5.5;
//		            		}
//		            	}
//		            	
//		            })
//		            .style("fill", function(d,i) { return rgb(i); }) // #1f77b4
//		        .style("opacity",0.3)
//		            .on("mouseover", function(d,i) {return activateBubble(d,i);});
//		        
//		        count = 0;
//		             
//		        bubbleObj.append("text")
//		            .attr("class", "topBubbleText")
//		            .attr("x", function(d, i) {
//			            		return oR*(3*(1+(i%nTopCount))-1);
//		            	}
//		            )
//		            .attr("y", function(d, i) {
//		            	if(i>=nTopCount){
//		            			return ((h+oR)/1.7)
//		            	}else{
//		            		if(nTop<=3){
//	            				return 	(h+oR)/2.5;
//		            		}else{
//		            			return 	(h+oR)/5.5;
//		            		}
//		            	}
//		            })
//		        .style("fill", function(d,i) { return rgb(i); }) // #1f77b4
//		            .attr("font-size", 26)
//		            .attr("text-anchor", "middle")
//		        .attr("dominant-baseline", "middle")
//		        .attr("alignment-baseline", "middle")
//		            .text(function(d) {return d.name})      
//		            .on("mouseover", function(d,i) {return activateBubble(d,i);});
//		        
//		        count = 0;
//		         
//		        for(var iB = 0; iB < nTop; iB++)
//		        {
//		            var childBubbles = svg.selectAll(".childBubble" + iB)
//		                .data(root.children[iB].children)
//		                .enter().append("g");
//		                 
//		        //var nSubBubble = Math.floor(root.children[iB].children.length/2.0);   
//		             
//		            childBubbles.append("circle")
//		                .attr("class", "childBubble" + iB)
//		                .attr("id", function(d,i) {return "childBubble_" + iB + "sub_" + i;})
//		                .attr("r",  function(d) {return oR/3.0;})
//		                .attr("cx", function(d,i) {return (oR*(3*((iB%nTopCount)+1)-1) + oR*1.5*Math.cos((i-1)*45/180*3.1415926));})
//		                .attr("cy", function(d,i) {
//		                		if(iB>=nTopCount){
//				            			return ((h+oR)/1.7 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//		                		}else{
//		                			if(nTop<=3){
//		                				return ((h+oR)/2.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}else{
//				            			return ((h+oR)/5.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}
//		                		}
//		                	}
//		                )
//		                .attr("cursor","pointer")
//		                .style("opacity",0.0)
//		                .style("fill", "#eee")
//		                .on("click", function(d,i) {
//		                window.open(d.address);                 
//		              })
//		            .on("mouseover", function(d,i) {
//		              //window.alert("say something");
//		              var noteText = "";
//		              if (d.note == null || d.note == "") {
//		                noteText = d.address;
//		              } else {
//		                noteText = d.note;
//		              }
//		              d3.select("#bubbleItemNote").text(noteText);
//		              })
//		            .append("svg:title")
//		            .text(function(d) { return d.address; });   
//		 
//		            childBubbles.append("text")
//		                .attr("class", "childBubbleText" + iB)
//		                .attr("x", function(d,i) {return (oR*(3*((iB%nTopCount)+1)-1) + oR*1.5*Math.cos((i-1)*45/180*3.1415926));})
//		                .attr("y", function(d,i) {
//			                	if(iB>=nTopCount){
//				            			return ((h+oR)/1.7 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//			                	}else{
//			                		if(nTop<=3){
//		                				return ((h+oR)/2.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}else{
//				            			return ((h+oR)/5.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}
//			                	}
//		                	}
//		                )
//		                .style("opacity",0.0)
//		                .attr("text-anchor", "middle")
//		            .style("fill", function(d,i) { return rgb(iB); }) // #1f77b4
//		                .attr("font-size", 5)
//		                .attr("cursor","pointer")
//		                .attr("dominant-baseline", "middle")
//		            .attr("alignment-baseline", "middle")
//		                .text(function(d) {return d.name})      
//		                .on("click", function(d,i) {
//		                window.open(d.address);
//		                }); 
//		 
//		        }
//		 
//		         
//		    }); //data binding 부분
//*/		 
//		    resetBubbles = function () {
//
//		      w = $('#'+self.itemid).width();
//		     
//		      h = $('#'+self.itemid).height();
//		      
//		      if(h > w){
//				   nTopRow = 3;
//				   if(nTop < nTopRow){
//					   nTopCount = nTop;
//				   }else{
//					   nTopCount  = nTopRow;
//				   }
//				   oR = h/(1+3*nTopCount);
//			   }else{
//				   nTopRow = 4;
//				   if(nTop < nTopRow){
//					   nTopCount = nTop;
//				   }else{
//					   nTopCount  = nTopRow;
//				   }
//				   oR = w/(1+3*nTopCount); 
//			   }
//		 
//		           
//		      svg.attr("width", w);
//		      svg.attr("height",h);       
//		       
//		      
//		       
//		      var t = svg.transition()
//		          .duration(650);
//		         
//		        t.selectAll(".topBubble")
//		            .attr("r", function(d) { return oR; })
//		            .attr("cx", function(d, i) {
//		            	return oR*(3*(1+(i%nTopCount))-1);}
//		            )
//		            .attr("cy", function(d, i) { 
//			            	if(nTop<nTopRow){
//			            		return 	(h+oR)/2.5;
//			            	}else{
//			            		return ((50+oR)*(parseInt(i/nTopCount)+1+parseInt(i/nTopCount)))
//			            	}
//		            	}
//		            )
//		            .style("opacity", function(d,ii){
//		                    return 0.3;             
//		            });
//		 
//		        t.selectAll(".topBubbleText")
//		        .attr("font-size", gDashboard.fontManager.getFontSize(oR/(nTopCount+1), 'Item'))
//	            .attr("font-family", gDashboard.fontManager.getFontFamily('Item'))
//		            .attr("x", function(d, i) {
//		            	return oR*(3*(1+(i%nTopCount))-1);
//		            	}
//		            )
//		            .attr("y", function(d, i) { 
//		            	if(nTop<nTopRow){
//		            		return 	(h+oR)/2.5;
//		            	}else{
//		            		return ((50+oR)*(parseInt(i/nTopCount)+1+parseInt(i/nTopCount)))
//		            	}
//	            	})
//	            	.style("opacity", function(d,ii){
//		                    return 1.0;             
//		            });
//		     
//		      for(var k = 0; k < nTop; k++) 
//		      {
//		        t.selectAll(".childBubbleText" + k)
////		                .attr("x", function(d,i) {return (oR*(3*((k%nTopCount)+1)-1) + oR*1.5*Math.cos((i-1)*45/180*3.1415926));})
//		        		.attr("x", function(d,i) {return w*3})
//		                .attr("y", function(d,i) {
//		                		/*if(k>=nTopCount){
//				            			return ((h+oR)/1.7 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//		                		}else{
//		                			if(nTop<=3){
//		                				return ((h+oR)/2.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}else{
//				            			return ((h+oR)/5.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}
//		                		}*/
//		                	return h*3;
//		                	}
//		                )
//		                .attr("font-size", gDashboard.fontManager.getFontSize(6, 'Item'))
//			            .attr("font-family", gDashboard.fontManager.getFontFamily('Item'))
//		                .style("opacity",0.0)
//		                .text(function(d) {return d[demensionNm[1]]});
//		 
//		        t.selectAll(".childBubble" + k)
//		                .attr("r",  function(d) {return oR/3.0;})
//		            .style("opacity",0.0)
////		                .attr("cx", function(d,i) {return (oR*(3*((k%nTopCount)+1)-1) + oR*1.5*Math.cos((i-1)*45/180*3.1415926));})
//		                .attr("cx", function(d,i) {return w*3;})
//		                .attr("cy", function(d,i) {
//		                		/*if(k>=nTopCount){
//				            			return ((h+oR)/1.7 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//		                		}else{
//		                			if(nTop<=3){
//		                				return ((h+oR)/2.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}else{
//				            			return ((h+oR)/5.5 +        oR*1.5*Math.sin((i-1)*45/180*3.1415926));
//				            		}
//		                		}*/
//			                	return h*3;
//		                	}
//		                );
//		                     
//		      }   
//		    }
//		    
//		    function valueBubble(d,i) {
//		    	
//
//		    	var t = svg.transition()
//                .duration(d3.event.altKey ? 7500 : 350);
//		    	
//		    	if(clickYn == valueName.length){
//		    		for(var k = 0; k < nTop; k++) 
//		            {
//		    			t.selectAll(".childBubbleText" + k)
//			 			.text(function(d) {return d[demensionNm[1]]});
//		            }
//		    		clickYn = 0;
//		    	}else{
//		    		$.each(valueName,function(_i,_val){
//		    			if(clickYn == _i){
//		    			for(var k = 0; k < nTop; k++) 
//				            {
//			    		 			t.selectAll(".childBubbleText" + k)
//				    		 			
//				                    .text(function(d) {
//				                    	return  measures[_i].name +" : " +Math.round(d[_val]);
//				                    }); 
//				            }
//		    			}else{
//		    				
//		    			}
//		 		   });
//		    	   clickYn ++;
//		    	}
//		    	
//		    	
//		    }
//		    
//		         
//		         
//		        function activateBubble(d,i) {
//		            // increase this bubble and decrease others
//		        	w = $('#'+self.itemid).width();
//		 		     
//				    h = $('#'+self.itemid).height();
//		            var t = svg.transition()
//		                .duration(d3.event.altKey ? 7500 : 350);
//		     
//		            t.selectAll(".topBubble")
//		                .attr("cx", function(d,ii){
//		                    if(i == ii) {
//		                        // Nothing to change
//		                        return w/4;
////		                        return oR*(3*(1+(ii%5))-1) - 0.6*oR*((ii%5)-1);
//		                    } else {
//		                        // Push away a little bit
//		                        if(ii < i){
//		                            // left side
//		                            return oR*0.6*(3*(1+(ii%nTopCount))-1);
//		                        } else {
//		                            // right side
//		                            return w*3;
//		                            /*return oR*(nTop*3+1) - oR*0.6*(3*(nTop-(ii%5))-1);*/
//		                        }
//		                    }               
//		                })
//		                .attr("cy", function(d,ii){
//		                    if(i == ii) {
//		                        // Nothing to change
//		                        return h/2;
////		                        return oR*(3*(1+(ii%5))-1) - 0.6*oR*((ii%5)-1);
//		                    } else {
//		                    	return h*3;
//		                    }               
//		                })
//		                .attr("r", function(d, ii) { 
//		                    if(i == ii)
//		                        return (h >= w)?(h/7):(w/7);
//		                    else
//		                        return oR*0.6;
//		                    })
//		                .style("opacity", function(d,ii){
//		                    if(i == ii) {
//		                        // Nothing to change
//		                        return 0.5;
////		                        return oR*(3*(1+(ii%5))-1) - 0.6*oR*((ii%5)-1);
//		                    } else {
//		                       return 0.0;
//		                    }               
//		                });
//		                     
//		            t.selectAll(".topBubbleText")
//		                .attr("x", function(d,ii){
//		                    if(i == ii) {
//		                        // Nothing to change
//		                        return w/4;
////		                        return oR*(3*(1+(ii%5))-1) - 0.6*oR*((ii%5)-1);
//		                    } else {
//		                        // Push away a little bit
//		                        if(ii < i){
//		                            // left side
//		                            return oR*0.6*(3*(1+(ii%nTopCount))-1);
//		                        } else {
//		                            // right side
//		                            return w*3;
////		                            return oR*(nTop*3+1) - oR*0.6*(3*(nTop-ii)-1);
//		                        }
//		                    }               
//		                })
//		                 .attr("y", function(d,ii){
//		                    if(i == ii) {
//		                        // Nothing to change
//		                        return h/2;
////		                        return oR*(3*(1+(ii%5))-1) - 0.6*oR*((ii%5)-1);
//		                    } else {
//		                    	return h*3;
//		                    }               
//		                })
//		                .attr("font-size", function(d,ii){
//		                    if(i == ii)
//		                        return  gDashboard.fontManager.getFontSize((w/7)/(nTopCount+1)*1.3, 'Item');
//		                    else
//		                        return gDashboard.fontManager.getFontSize((w/7)/nTopCount*0.6, 'Item');              
//		                })
//		                .style("font-family", gDashboard.fontManager.getFontFamily('Item'))
//		                .style("opacity", function(d,ii){
//		                    if(i == ii) {
//		                        // Nothing to change
//		                        return 1.0;
////		                        return oR*(3*(1+(ii%5))-1) - 0.6*oR*((ii%5)-1);
//		                    } else {
//		                       return 0.0;
//		                    }               
//		                });
//		     
//		            var signSide = -1;
//		            var hCount;
//		            var wCount;
//		            var hLeng;
//		            for(var k = 0; k < nTop; k++) 
//		            {
//		            	wCount = 0;
//		            	hCount = 0;
//		            	if(h>=w){
//		            		hLeng = h/3;
//		            	}else{
//		            		hLeng = h/4;
//		            	}
//		            	
//		                signSide = 1;
//		                if(k < nTop/2) signSide = 1;
//		                t.selectAll(".childBubbleText" + k)
//		                    .attr("x", function(d,i) {
//			                    	/*if(h >= w){
//			                    		return ((w/1.5) + signSide*(h/10)*(2+parseInt(i/10))*Math.cos((i-1)*36/180*3.1415926));
//			                    	}else{
//			                    		return ((w/1.5) + signSide*(w/10)*(2+parseInt(i/10))*Math.cos((i-1)*36/180*3.1415926));
//			                    	}*/
//		                    		
//			                    	wCount++;
//			                    	if(wCount >= 5){
//			                    		wCount = 1;
//			                    	}
//									return (w/2.5) + wCount*w/8;
//									
//		                    	}
//		                    )
//		                    .attr("y", function(d,i) {
//									/*if(h >= w){
//										return ((h/2) + signSide*(h/10)*(2+parseInt(i/10))*Math.sin((i-1)*36/180*3.1415926));
//									}else{
//										return ((h/2) + signSide*(w/10)*(2+parseInt(i/10))*Math.sin((i-1)*36/180*3.1415926));
//									}  
//		                    		*/
//			                    	hCount++;
//		                    		if(hCount >= 5){
//										
//										hLeng = hLeng + w/7; 
//										hCount = 1;
//										return hLeng;
//		                    		}else{
//		                    			return	hLeng;			
//		                    		}
//		                    		
//		                    	}
//		                    )
//		                    .attr("font-size", function(){
//		                            return gDashboard.fontManager.getFontSize((oR/7), 'Item');
//		                        })
//	                        .style("font-family", gDashboard.fontManager.getFontFamily('Item'))
//		                    .style("opacity",function(){
//		                            return (k==i)?1:0;
//		                        });
//		                  
//		                
//		                wCount = 0;
//		            	hCount = 0;
//		            	if(h>=w){
//		            		hLeng = h/3;
//		            	}else{
//		            		hLeng = h/4;
//		            	}
//		                t.selectAll(".childBubble" + k)
//		                    .attr("cx", function(d,i) {
//			                    	/*if(h >= w){
//			                    		return ((w/1.5) + signSide*(h/10)*(2+parseInt(i/10))*Math.cos((i-1)*36/180*3.1415926));
//			                    	}else{
//			                    		return ((w/1.5) + signSide*(w/10)*(2+parseInt(i/10))*Math.cos((i-1)*36/180*3.1415926));
//			                    	}*/
//			                    	
//			                    	wCount++;
//			                    	if(wCount >= 5){
//			                    		wCount = 1;
//			                    	}
//									return (w/2.5) + wCount*w/8;
//		                    	}
//		                    )
//		                    .attr("cy", function(d,i) {
//		                    		/*if(h >= w){
//		                    			return ((h/2) + signSide*(h/10)*(2+parseInt(i/10))*Math.sin((i-1)*36/180*3.1415926));
//		                    		}else{
//		                    			return ((h/2) + signSide*(w/10)*(2+parseInt(i/10))*Math.sin((i-1)*36/180*3.1415926));
//		                    		} */    
//			                    	hCount++;
//		                    		if(hCount >= 5){
//										
//										hLeng = hLeng + w/7; 
//										hCount = 1;
//										return hLeng;
//		                    		}else{
//		                    			return	hLeng;			
//		                    		}
//		                    	}
//		                    )
//		                    .attr("r", function(){
//		                    	if (k==i){
//		                    		return (h >= w)?((h/12)*0.55):((w/12)*0.55);
//		                    	}else{
//		                    		return (oR/3.0); 
//		                    	}
//		                                          
//		                    })
//		                    .style("opacity", function(){
//		                            return (k==i)?1:0;                  
//		                        }); 
//		            }                   
//		        }
//		      
//		     
//		    window.onresize = resetBubbles;
//		 
//	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.BubbleD3);
	}
	
	this.functionDo2 = function(_f) {		
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.BubbleD3['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.BubbleD3['ShowCaption'] = false;
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
                            	
                            	self.BubbleD3['Name'] = newName;
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
				var chagePalette = self.BubbleD3.Palette;
				var firstPalette = self.BubbleD3.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.BubbleD3.Palette) != -1
										? self.BubbleD3.Palette
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
//                                    self.dxItem.option('palette', self.customPalette);
                                    self.resize();
								} else {
                                    self.isCustomPalette = false;
                                    /*self.dxItem.option('palette', e.value);*/
                                    self.BubbleD3.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.BubbleD3.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.BubbleD3.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.BubbleD3.Palette = chagePalette;
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
//				var chagePalette = self.BubbleD3.Palette;
//				var firstPalette = self.BubbleD3.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.BubbleD3.Palette) 
//										? self.BubbleD3.Palette
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
//                                    self.BubbleD3.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.BubbleD3.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.BubbleD3.Palette);
//                            chagePalette = firstPalette;
//                            self.BubbleD3.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.BubbleD3.Palette = chagePalette;
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
WISE.libs.Dashboard.BubbleD3FieldManager = function() {
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
		//var NumericFormat = {'ForMatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};

		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('uni_nm');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText; 
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText; 
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
//				dataItem['NumericFormat'] = NumericFormat;
				dataItem['NumericFormat'] = $(_fieldlist[i]).data('formatOptions');
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
