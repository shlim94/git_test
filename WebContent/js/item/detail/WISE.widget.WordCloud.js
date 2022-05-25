WISE.libs.Dashboard.item.WordCloud = function() {
	var self = this;

	this.type = 'WORD_CLOUD';

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
	this.trackingData = [];
	this.tempTrackingData = [];
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";

	this.WordCloud = [];
	this.fieldManager;
	this.currentMeasureName = "";
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [];
	this.customPalette = [];
	this.isCustomPalette = false;
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
						var text = '<b>' + _pointInfo.node.data.name + '</b>' + '<br/>' +"<b>" +self.currentMeasureName+"</b> : " +WISE.util.Number.unit(_pointInfo.value,'O',0);
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

	this.setWordCloud = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.WordCloud['ComponentName'] = this.ComponentName;
		this.WordCloud['Name'] = this.Name;
		this.WordCloud['DataSource'] = this.dataSourceId;

		this.WordCloud['DataItems'] = this.fieldManager.DataItems;
		this.WordCloud['Arguments'] = this.fieldManager.Arguments;
		this.WordCloud['Values'] = this.fieldManager.Values;
		if (!(this.WordCloud['Palette'])) {
			this.WordCloud['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		if (this.WordCloud.InteractivityOptions) {
			if (!(this.WordCloud.InteractivityOptions.MasterFilterMode)) {
				this.WordCloud.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.WordCloud.InteractivityOptions.TargetDimensions)) {
				this.WordCloud.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.WordCloud.InteractivityOptions.IsDrillDownEnabled)) {
				this.WordCloud.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.WordCloud.InteractivityOptions.IgnoreMasterFilters)) {
				this.WordCloud.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.WordCloud.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.WordCloud.LayoutOption){
			this.WordCloud.LayoutOption = {
					Label : {
						family: 'Impact'
					}
			}
		}
		
		if(!this.WordCloud['ZoomAble']){
			this.WordCloud.ZoomAble = 'none'
		}
		
		this.meta = this.WordCloud;
	};

	this.setWordCloudforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setWordCloud();
		}
		else{
			this.WordCloud = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.WordCloud['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.WordCloud['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.WordCloud['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		if (!(this.WordCloud['Palette'])) {
			this.WordCloud['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BubbleD3Option = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WORD_CLOUD_DATA_ELEMENT);
				
				$.each(BubbleD3Option,function(_i,_bubbled3Option){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _bubbled3Option.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _bubbled3Option.CTRL_NM;
//					}
					if(self.WordCloud.ComponentName == CtrlNM){
						self.WordCloud['Palette'] = _bubbled3Option.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.WordCloud.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.WordCloud.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.WordCloud.InteractivityOptions) {
			if (!(this.WordCloud.InteractivityOptions.MasterFilterMode)) {
				this.WordCloud.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.WordCloud.InteractivityOptions.TargetDimensions)) {
				this.WordCloud.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.WordCloud.InteractivityOptions.IsDrillDownEnabled)) {
				this.WordCloud.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.WordCloud.InteractivityOptions.IgnoreMasterFilters)) {
				this.WordCloud.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.WordCloud.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if(!this.WordCloud.LayoutOption){
			this.WordCloud.LayoutOption = {
					Label : {
						family: 'Impact'
					}
			}
		}
		if(!this.WordCloud['ZoomAble']){
			this.WordCloud.ZoomAble = 'none'
		}
	}
	
	this.setWordCloudForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setWordCloud();
		}
		else{
			this.WordCloud = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.WordCloud['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.WordCloud['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.WordCloud['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		if (!(this.WordCloud['Palette'])) {
			this.WordCloud['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BubbleD3Option = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WORD_CLOUD_DATA_ELEMENT);
				
				$.each(BubbleD3Option,function(_i,_bubbled3Option){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _bubbled3Option.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _bubbled3Option.CTRL_NM;
//					}
					if(self.WordCloud.ComponentName == CtrlNM){
						self.WordCloud['Palette'] = _bubbled3Option.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.WordCloud.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.WordCloud.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.WordCloud.InteractivityOptions) {
			if (!(this.WordCloud.InteractivityOptions.MasterFilterMode)) {
				this.WordCloud.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.WordCloud.InteractivityOptions.TargetDimensions)) {
				this.WordCloud.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.WordCloud.InteractivityOptions.IsDrillDownEnabled)) {
				this.WordCloud.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.WordCloud.InteractivityOptions.IgnoreMasterFilters)) {
				this.WordCloud.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.WordCloud.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.WordCloud.LayoutOption){
			this.WordCloud.LayoutOption = {
					Label : {
						family: 'Impact'
					}
			}
		}
		if(!this.WordCloud['ZoomAble']){
			this.WordCloud.ZoomAble = 'none'
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
			self.setWordCloud();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.WordCloud);
			gDashboard.itemGenerateManager.generateItem(self, self.WordCloud);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setWordCloudforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.WordCloud);
			gDashboard.itemGenerateManager.generateItem(self, self.WordCloud);
		}else if(self.meta && $.isEmptyObject(self.WordCloud)) {
			this.setWordCloudForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.WordCloud);
			gDashboard.itemGenerateManager.generateItem(self, self.WordCloud);
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
//		self.currentMeasureName = measureKey.caption;
		self.trackingData = [];
		self.tempTrackingData = [];
		self.currentMeasureName = WISE.util.Object.toArray(measureKey)[0].caption;
		
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fWordCloudCoordinates2(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name + ' - ' + self.currentMeasureName);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		
		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
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
//		$('#tab5primary').empty();
//		
//		$('<li class="slide-ui-item"><a id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="customPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_editColor.png" alt=""><span>색상 편집</span></a></li>').appendTo($('#tab5primary'));
//		
//		menuItemSlideUi();
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
		
	}

	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if(gDashboard.reportType != 'AdHoc' || !(gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer')){
				if (self.dxItem) {
					d3.selectAll('text')
			    	.style("stroke", "none")
			    	.style("text-decoration", 'none')
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
//			var page = window.location.pathname.split('/');
//			if (page[page.length - 1] == 'viewer.do') {
//				if($('#'+this.itemid+'editWordCloudPopover').length == 0 ){
//					$('<div id="'+this.itemid+'editWordCloudPopover">').dxPopover({
//						height: 'auto',
//						width: 'auto',
//						position: 'bottom',
//						visible: false
//					}).appendTo('#wrap');
//				}
//			}else{
//				if($('#'+this.itemid+'editWordCloudPopover').length == 0 ){
//					$('<div id="'+this.itemid+'editWordCloudPopover">').dxPopover({
//						height: 'auto',
//						width: 'auto',
//						position: 'bottom',
//						visible: false
//					}).appendTo('#wrapper');
//				}
//			}
//			
//			var p = $('#'+this.itemid+'editWordCloudPopover').dxPopover('instance');
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
//						$('#' + self.itemid + '_title > .lm_title').text(self.Name + ' - ' + selectedMeasure.caption);
//						var dxConfig = self.getDxItemConfig(self.meta);
//						self.currentMeasureName = selectedMeasure.caption;
//						dxConfig.dataSource = self.deleteDuplecateData(self.filteredData,selectedMeasure);
//						self.fWordCloudCoordinates2(self.filteredData);
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
		//2020.02.07 mksong sqllike 적용 dogfoot
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
			selectArray.push('|'+_Mea.summaryType+'|');
			selectArray.push(_Mea.name);
			//2020.02.07 mksong sqllike 적용 dogfoot
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
			sqlConfig.OrderBy.push(_d.DataMember);
		});
		
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		self.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, self);
		self.csvData = self.filteredData;
		ValueArray.push(self.filteredData);

		var resultArr = new Array();
		$.each(ValueArray,function(_i,_e){
			$.each(_e,function(_item,_obj){
				var str = new Array();
				var object = new Object();
				$.each(Dimension,function(_i,_Dim){
					str.push(_obj[_Dim.DataMember]);
				});
				$.each(Measure,function(_i,_Mea){
					object['value'] = _obj[_Mea.summaryType + '_' + _Mea.caption];
				});

				object['name'] = str.join(' - ');
				resultArr.push(object);
			})
		});
		return resultArr;
	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		if(typeof self.resizeData != 'undefined'){
			if($('#'+self.itemid).length === 0)return;
			var selectedMeasure;
			var targetPanelId;
			$.each(self.dimensions,function(_i,_dim){
				targetPanelId = _dim
			});
			
			$.each(self.measures,function(_i,_mea){
				if(_mea.uniqueName == targetPanelId){
					selectedMeasure = _mea;
					return false;
				}
			});
			
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fWordCloudCoordinates2(self.filteredData, self.measures, self.dimensions, self.resizeData);
			$.each(d3.selectAll('text[filter="true"]')._groups[0], function(i, d) {
				var strokeWidth = $(d).css("font-size").slice(0, -2) * 1 / 15 - 1

                if(strokeWidth < 1) strokeWidth = 1;
				$(d).css("stroke", $(d).css("fill")).css("stroke-width", strokeWidth).css("text-decoration", 'underline').attr("filter", 'true')
			});
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		if($('#'+self.itemid).length === 0)return;
//		var selectedMeasure;
//		var targetPanelId;
//		$.each(self.dimensions,function(_i,_dim){
//			targetPanelId = _dim
//		});
//		
//		$.each(self.measures,function(_i,_mea){
//			if(_mea.uniqueName == targetPanelId){
//				selectedMeasure = _mea;
//				return false;
//			}
//		});
//		self.fWordCloudCoordinates2(self.filteredData, self.measures, self.dimensions, self.deleteDuplecateData(self.filteredData,self.measures));
//		d3.selectAll('text[filter="true"]')
//		.style("text-shadow", '-1px 0 blue, 0 1px blue, 1px 0 blue, 0 -1px blue')
//		.attr("filter", 'true');
//		
//		gProgressbar.hide();
//	};

	this.fWordCloudCoordinates2 = function(jsonData, measures, dimensions, dupleData) {

		if (!dupleData || ($.type(dupleData) === 'array' && dupleData.length === 0)
				|| (dupleData.length == 1 && dupleData[0].value == 0 && dupleData[0].name == "")) {
			$('#'+self.itemid + ' .nodata-layer').remove();
			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
			$("#" + self.itemid).children().css('display','none');
			$("#" + self.itemid).prepend(nodataHtml);
			if($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0){
				$("#" + self.itemid).height('100%');
				$("#" + self.itemid).width('100%');
			}
			$("#" + self.itemid).css('display', 'block');

			return;
		}else{
			self.resizeData = dupleData;
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
		
		d3.select("#" + self.itemid).selectAll("svg").remove();
		
		
		var width = $('#'+self.itemid).width() ;
		var height = $('#'+self.itemid).height() ;
		var calSize = width > height ? width : height;
        dupleData = dupleData.sort(function(a, b) { return b.value - a.value });
        if(dupleData.length>60){
        	dupleData = dupleData.slice(0,60);
        }
        
		var max_freq = dupleData[0].value;

		function search(nameKey, myArray){
			for (var i=0; i < myArray.length; i++) {
				if (myArray[i].name === nameKey) {
					return myArray[i].value;
				}
			}
		}



	    	  
	   	//key 와 value 값을 array 형태로 만들어서 넣어줘야 한다.

	       var svg_location = "#" + self.itemid;
	       var fill = d3.scale.category20();
	       var word_entries = dupleData;
	        
//170 -> 10 
//170 -> 100
	        
			var max_freq = dupleData[0].value;
			var colorz = gDashboard.d3Manager.getPalette(self);
			self.paletteData = dupleData.map(function (val, index) {
				return val.name;
			}).filter(function (val, index, arr) {
				return arr.indexOf(val) === index;
			});              
            
            function search(nameKey, myArray){
				for (var i=0; i < myArray.length; i++) {
					if (myArray[i].name === nameKey) {
						return myArray[i].value;
					}
				}
			}
            
            var resultObject = search("마티즈", dupleData);
			var leaders = dupleData
			  .map(function(d) {
				return {
				  text: d.name,
//				  size: 5 + (search(d.name, dupleData)/ max_freq) * 0.9 * 50
				  size: (calSize/90 + (search(d.name, dupleData)/ max_freq) * 0.9 * 70) <= calSize/90 ? calSize/90 : (calSize/90 + (search(d.name, dupleData)/ max_freq) * 0.9 * 70) <= calSize/25 ? (calSize/90 + (search(d.name, dupleData)/ max_freq) * 0.9 * 70) : calSize/25
				};
			  })
			  .sort(function(a, b) {
				return d3.descending(a.size, b.size)
			  });

			var leaderScale = d3.scale.linear()
	           .domain([0, d3.max(word_entries, function(d) {
	              return d.value;
	            })
	           ])
	           .range([1,(width+height)]);

			leaderScale.domain([d3.min(leaders, function(d) {
				return d.size;
			  }),
			  d3.max(leaders, function(d) {
				return d.size;
			  })
			]);
			

			
			

				
			// Next you need to use the layout script to calculate the placement, rotation and size of each word:
			var cloud = d3.layout.cloud().size([width, height])
			  .words(leaders)
			  .padding(10)
			  .rotate(function() {
				 return ~~(Math.random() * 2) * (Math.random()*90);
			  })
			  //.font("맑은 고딕")
			  .fontSize(function(d) {
				return d.size;
			  })
			  .on("end", drawCloud)
			  .start();
			  
			function drawCloud(dupleData) {
			  var colLen = 0;
			   d3.select('#'+self.itemid).append("svg")
				.attr("width", width)
				.attr("height", height)
				.attr("text-align", "center")
				.append("g")
				.style("width", width*2)
				.style("height", height*2)
				.attr("transform", "translate(" + [(width >> 1), height >> 1.5] + ")")
				.selectAll("text")
				.data(dupleData)
				.enter().append("text")
				.style("font-size", function(d) {
				  return d.size + "px";
				})
				.style("font-family", self.meta.LayoutOption.Label.family)
				.style("fill", function(d, i) {
					if(colLen>(colorz.length-1))colLen=0;
					var recol = colorz[colLen];
					colLen++;
					return recol;
//				  return fill(i);
				})
				.attr("text-anchor", "middle")
				.attr("transform", function(d) {
				  return "translate(" + [d.x, d.y] + ")rotate(" + d.rotate + ")";
				})
				.text(function(d) {
				  return d.text;
				})
		         .attr("filter", function(d){
		        	 for (var index = 0; index < self.tempTrackingData.length; index++) {
			    			var check = 0;
		       				$.each(self.dimensions, function(i, dim){
		       					if(self.tempTrackingData[index][dim.name] === d.text.split(" - ")[i])
		       						check++;
		       				})
		       				if(check === self.dimensions.length){
		       					return "true";
		       				}
		       			}
			    	  return "false";
			      })
				.text(function(d) {
				  return d.text;
				})
				.on("mouseover", function() { 
		            	$(this).attr('cursor','pointer');
		         })
				.on("click", function(d) {

				     mouseclick(d,this);
				});
                
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

				function zoomToFitBounds() {

					  var X0 = d3.min( dupleData, function (d) {
						return d.x - (d.width/2);
					  }),
						X1 = d3.max( dupleData, function (d) {
						  return d.x + (d.width/2);
						});

					  var Y0 = d3.min( dupleData, function (d) {
						  return d.y - (d.height/2);
						}),
						Y1 = d3.max( dupleData, function (d) {
						  return d.y + (d.height/2);
						});

					  var scaleX = (X1 - X0) / (width);
					  var scaleY = (Y1 - Y0) / (height);

					  var scale = 1 / Math.max(scaleX, scaleY);

					  var translateX = Math.abs(X0) * scale;
					  var translateY = Math.abs(Y0) * scale;

					  d3.select('#'+self.itemid).select("g").attr("transform", "translate(" +
						translateX + "," + (translateY+20) + ")" +
						" scale(" + scale + ")");
				}

				zoomToFitBounds();
        
			}

			// set the viewbox to content bounding box (zooming in on the content, effectively trimming whitespace)

			var svg = document.getElementsByTagName("svg")[0];

	        
        	function mouseclick(d,_this){
				
        		switch(self.IO.MasterFilterMode){
				case 'Multiple':
					if(d3.select(_this).attr("filter") === "true"){
						
						d3.select(_this)
				    	.style("stroke", "none")
				    	.style("text-decoration", 'none')
						.attr("filter", 'false');

						for (var index = 0; index < self.tempTrackingData.length; index++) {
							var check = 0;
							$.each(self.dimensions, function(i, dim){
								if(self.tempTrackingData[index][dim.name] === d.text.split(" - ")[i])
									check++;
							})
							if(check === self.dimensions.length){
								self.tempTrackingData.splice(index, 1);
								index--;
							}
						}
						
			    	}else{
			    		
			    		d3.select(_this)
				    	.style("stroke", d3.select(_this).style("fill"))
				    	.style("stroke-width", strokeWidth)
				    	.style("text-decoration", 'underline')
						.attr("filter", 'true');

						tempSelectedData = {}
						$.each(self.dimensions, function(i, dim){
							tempSelectedData[dim.name] = d.text.split(" - ")[i]
						})
						self.tempTrackingData.push(tempSelectedData);
			    	}

			    	self.trackingData = [];
		    	
					$.each(self.dimensions, function(i, dim){
						var unique = self.tempTrackingData.map(function(val, index){
							return val[dim.name];
						}).filter(function(val, index, arr){
							return arr.indexOf(val) === index;
						});

						for(var j = 0; j < unique.length; j++){
							var selectedData = {};
							selectedData[dim.name] = unique[j]
							self.trackingData.push(selectedData);
						}
					})
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
				case 'Single':

					//self.selectedPoint = _e.target;
					self.trackingData = [];
					
					if(d3.select(_this).attr("filter") === "true"){
			    		d3.selectAll('text')
				    	.style("stroke", "none")
				    	.style("text-decoration", 'none')
						.attr("filter", 'false');
			    		
			    	}else{
			    		d3.selectAll('text')
				    	.style("stroke", "none")
				    	.style("text-decoration", 'none')
						.attr("filter", 'false');
						
			    		var strokeWidth = d3.select(_this).style("font-size").slice(0, -2) * 1 / 15 - 1

                        if(strokeWidth < 1) strokeWidth = 1;
						d3.select(_this)
				    	.style("stroke", d3.select(_this).style("fill"))
				    	.style("stroke-width", strokeWidth)
				    	.style("text-decoration", 'underline')
						.attr("filter", 'true');
						
						var tempSelectedData = {};
						$.each(self.dimensions, function(i, dim){
							var selectedData = {};
							selectedData[dim.name] = d.text.split(" - ")[i]
							tempSelectedData[dim.name] = d.text.split(" - ")[i]
							self.trackingData.push(selectedData);
						})

						self.tempTrackingData = [tempSelectedData];
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
		
		
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self,self.WordCloud);
	}
	
	this.functionDo2 = function(_f) {		
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title').parent();
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.WordCloud['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.WordCloud['ShowCaption'] = false;
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
                            	
                            	self.WordCloud['Name'] = newName;
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
				
				if ((self.customPalette && self.customPalette.length > 0)) {
					paletteCollection.push('Custom');
					paletteCollection2.push('사용자 정의 테마');
				}
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chagePalette = self.WordCloud.Palette;
				var firstPalette = self.WordCloud.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.WordCloud.Palette) != -1
										? self.WordCloud.Palette
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
                                    self.dxItem.option('palette', self.customPalette);
//                                    self.resize();
								} else {
                                    self.isCustomPalette = false;
                                    /*self.dxItem.option('palette', e.value);*/
                                    self.isCustomPalette = false;
                                    self.dxItem.option('palette', paletteObject2[e.value]);
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.WordCloud.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.WordCloud.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.WordCloud.Palette = chagePalette;
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
//				var chagePalette = self.WordCloud.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.WordCloud.Palette) 
//										? self.WordCloud.Palette
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
//                                    self.dxItem.option('palette', self.customPalette);
//								} else {
//                                    self.isCustomPalette = false;
//                                    self.dxItem.option('palette', e.value);
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.WordCloud.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.WordCloud.Palette);
//                            chagePalette = self.WordCloud.Palette;
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.WordCloud.Palette = chagePalette;
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

WISE.libs.Dashboard.WordCloudFieldManager = function() {
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
		var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};

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
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
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