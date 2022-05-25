WISE.libs.Dashboard.item.RectangularAreaChartGenerator = function() {
	var self = this;

	this.type = 'RECTANGULAR_ARAREA_CHART';

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

	this.RectangularAreaChart = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
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
	
	this.trackingData = [];
	this.tempTrakcingData = [];
	
	/**
	 * @param _item:
	 *            meta objectz
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
				palette: _item['Palette'],
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

	this.setRectangularAreaChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.RectangularAreaChart['ComponentName'] = this.ComponentName;
		this.RectangularAreaChart['Name'] = this.Name;
		this.RectangularAreaChart['DataSource'] = this.dataSourceId;

		this.RectangularAreaChart['DataItems'] = this.fieldManager.DataItems;
		this.RectangularAreaChart['Arguments'] = this.fieldManager.Arguments;
		this.RectangularAreaChart['Values'] = this.fieldManager.Values;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.RectangularAreaChart;
		if (!(this.RectangularAreaChart['Palette'])) {
			this.RectangularAreaChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		if (!(this.RectangularAreaChart['Legend'])) {
			this.RectangularAreaChart['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		if (this.RectangularAreaChart.InteractivityOptions) {
			if (!(this.RectangularAreaChart.InteractivityOptions.MasterFilterMode)) {
				this.RectangularAreaChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.TargetDimensions)) {
				this.RectangularAreaChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.RectangularAreaChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.RectangularAreaChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.RectangularAreaChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.RectangularAreaChart.LayoutOption){
			this.RectangularAreaChart.LayoutOption = {
					Legend : {
						size : 12,
						family: "맑은 고딕",
						color: "#000000"
					},
					Label : {
						size : 14,
						color: '#ffffff',
						family: "맑은 고딕"
					}
			}
		}
		if(!this.RectangularAreaChart['ZoomAble']){
			this.RectangularAreaChart.ZoomAble = 'none'
		}

		if (!(this.RectangularAreaChart['TextFormat'])) {
			this.RectangularAreaChart['TextFormat'] = 'Argument, Value'
		}
	};

	this.setRectangularAreaChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setRectangularAreaChart();
		}
		else{
			this.RectangularAreaChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.RectangularAreaChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.RectangularAreaChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.RectangularAreaChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.RectangularAreaChart['Palette'])) {
			this.RectangularAreaChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var RectangularAreaChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.RECTANGULAR_ARAREA_CHART_DATA_ELEMENT);
				
				$.each(RectangularAreaChartOption,function(_i,_RectangularAreaChartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _RectangularAreaChartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _RectangularAreaChartOption.CTRL_NM;
					}
					if(self.RectangularAreaChart.ComponentName == CtrlNM){
						self.RectangularAreaChart['Palette'] = _RectangularAreaChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.RectangularAreaChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.RectangularAreaChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.RectangularAreaChart.InteractivityOptions) {
			if (!(this.RectangularAreaChart.InteractivityOptions.MasterFilterMode)) {
				this.RectangularAreaChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.TargetDimensions)) {
				this.RectangularAreaChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.RectangularAreaChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.RectangularAreaChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.RectangularAreaChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.RectangularAreaChart['Legend'])) {
			this.RectangularAreaChart['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.RectangularAreaChart.LayoutOption){
			this.RectangularAreaChart.LayoutOption = {
					Legend : {
						size : 12,
						family: "맑은 고딕",
						color: "#000000"
					},
					Label : {
						size : 14,
						color: '#ffffff',
						family: "맑은 고딕"
					}
			}
		}
		
		if(!this.RectangularAreaChart['ZoomAble']){
			this.RectangularAreaChart.ZoomAble = 'none'
		}
		if (!(this.RectangularAreaChart['TextFormat'])) {
			this.RectangularAreaChart['TextFormat'] = 'Argument, Value'
		}
	}
	this.setRectangularAreaChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setRectangularAreaChart();
		}
		else{
			this.RectangularAreaChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.RectangularAreaChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.RectangularAreaChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.RectangularAreaChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.RectangularAreaChart['Palette'])) {
			this.RectangularAreaChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var RectangularAreaChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.RECTANGULAR_ARAREA_CHART_DATA_ELEMENT);
				
				$.each(RectangularAreaChartOption,function(_i,_RectangularAreaChartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _RectangularAreaChartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _RectangularAreaChartOption.CTRL_NM;
//					}
					if(self.RectangularAreaChart.ComponentName == CtrlNM){
						self.RectangularAreaChart['Palette'] = _RectangularAreaChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.RectangularAreaChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.RectangularAreaChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (this.RectangularAreaChart.InteractivityOptions) {
			if (!(this.RectangularAreaChart.InteractivityOptions.MasterFilterMode)) {
				this.RectangularAreaChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.TargetDimensions)) {
				this.RectangularAreaChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.RectangularAreaChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.RectangularAreaChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.RectangularAreaChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.RectangularAreaChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.RectangularAreaChart['Legend'])) {
			this.RectangularAreaChart['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.RectangularAreaChart.LayoutOption){
			this.RectangularAreaChart.LayoutOption = {
					Legend : {
						size : 12,
						family: "맑은 고딕",
						color: "#000000"
					},
					Label : {
						size : 14,
						color: '#ffffff',
						family: "맑은 고딕"
					}
			}
		}
		
		if(!this.RectangularAreaChart['ZoomAble']){
			this.RectangularAreaChart.ZoomAble = 'none'
		}
		if (!(this.RectangularAreaChart['TextFormat'])) {
			this.RectangularAreaChart['TextFormat'] = 'Argument, Value'
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
			self.setRectangularAreaChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.RectangularAreaChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RectangularAreaChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setRectangularAreaChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.RectangularAreaChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RectangularAreaChart);
		}
		//d3 뷰어모드 임성현
		else if(self.meta && $.isEmptyObject(self.RectangularAreaChart)) {
			this.setRectangularAreaChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.RectangularAreaChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RectangularAreaChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setRectangularAreaChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.RectangularAreaChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RectangularAreaChart);
		}

		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
			topIconPanel.append(trackingDataContainerHtml);
		}

		var dxConfig = this.getDxItemConfig(this.meta);

		this.calculatedFields = [];
		/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
		this.calculateCaption;
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[this.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(self.measures,function(_i,_measure){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_measure != undefined){
							if(field.Name == _measure.name){
								self.calculatedFields.push(_measure);
								self.calculateCaption = _measure.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.measures,function(_k, _measure){
											if(_tempDataField == _measure.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								self.measures.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
												captionBySummaryType: "sum_"+_tempDataField,
												currencyCulture: undefined,
												format: "fixedPoint",
												formatType: "Number",
												includeGroupSeparator: true,
												name: _tempDataField,
												nameBySummaryType: "sum("+_tempDataField+")",
												nameBySummaryType2: "sum_"+_tempDataField,
												precision: 0,
												rawCaption: _tempDataField,
												suffix: {
													B: "십억",
													K: "천",
													M: "백만",
													O: ""
												},
												suffixEnabled: false,
												summaryType: "sum",
												type: "measure",
												unit: "Ones",
												tempdata: true
										}
										self.measures.push(dataMember);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
					/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
					$.each(self.dimensions,function(_i,_dimension){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_dimension != undefined){
							if(field.Name == _dimension.name){
								self.calculatedFields.push(_dimension);
								self.calculateCaption = _dimension.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.dimensions,function(_k, _dimension2){
											if(_tempDataField == _dimension2.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								self.dimensions.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
												captionBySummaryType: _tempDataField,
												currencyCulture: undefined,
												includeGroupSeparator: true,
												name: _tempDataField,
												precision: 0,
												rawCaption: _tempDataField,
												suffixEnabled: false,
												type: "dimension",
												tempdata: true,
												nameBySummaryType: "min("+_tempDataField+")",
												nameBySummaryType2: "min_"+_tempDataField
										}
										self.dimensions.push(dataMember);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
				});
			}
		}
		
		var measureKey = this.measures[0];
		self.currentMeasureName = measureKey.caption;
		self.trackingData = [];
		self.tempTrackingData = [];
		
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fRectangularAreaChartCoordinates2(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
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
//		
//		$('<li class="slide-ui-item"><a id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		
//		menuItemSlideUi();
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
//		$('.single-toggle-button').on('click', function(e) {
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
					.style("fill", self.meta.LayoutOption.Legend.color)
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
//			if($('#'+this.itemid+'editRectangularAreaChartPopover').length == 0 ){
//				$('<div id="'+this.itemid+'editRectangularAreaChartPopover">').dxPopover({
//					height: 'auto',
//					width: 'auto',
//					position: 'bottom',
//					visible: false
//				}).appendTo('#wrapper');
//			}
//			var p = $('#'+this.itemid+'editRectangularAreaChartPopover').dxPopover('instance');
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
//						self.fRectangularAreaChartCoordinates2(self.filteredData);
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
		self.selectedMeasure = MeasureKey;
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	this.deleteDuplecateData2 = function(_data,MeasureKey){
		//2020.02.07 mksong sqllike 적용 dogfoot
		self.selectedMeasure = MeasureKey;
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
			sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
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
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fRectangularAreaChartCoordinates2(self.filteredData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('text[filter="true"]')
			.style("fill", 'blue').attr('filter', "true");
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		self.fRectangularAreaChartCoordinates2(self.filteredData, self.measures, self.dimensions, 
//				self.deleteDuplecateData(self.filteredData,self.measures[0]));
//		d3.selectAll('text[filter="true"]')
//		.style("fill", 'blue').attr('filter', "true");
//		gProgressbar.hide();
//	};

	this.fRectangularAreaChartCoordinates2 = function(jsonData, measures, dimensions, dupleData) {
		
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
		
		function StringBuilder(value)
		{
		    this.strings = new Array("");
		    this.append(value);
		}

		// Appends the given value to the end of this instance.
		StringBuilder.prototype.append = function (value)
		{
		    if (value)
		    {
		        this.strings.push(value);
		    }
		}

		// Clears the string buffer
		StringBuilder.prototype.clear = function ()
		{
		    this.strings.length = 1;
		}

		// Converts this instance to a String.
		StringBuilder.prototype.toString = function ()
		{
		    return this.strings.join("");
		}
		
		var sb     = null;
		var traits = [self.currentMeasureName];
//		$.each(measures, function(_i, _o) {
//			traits.push(_o.name)
//		});

		var species = [];
		$.each(dimensions,function(_i, _o){
			species.push(_o.name)
		});

		var dupleDatas = [];
		$.each(dupleData,function(_i, _o){
			dupleDatas.push(_o.name)
		});
		
		// var data1 = [{value: "42", label: "parturient montes"}, {value: "69", label: "id, mollis nec"}, {value: "29", label: "lacus. Ut"}, {value: "52", label: "a ultricies adipiscing"}];
		
		var json = [];
		var jsonList = null;
		var temp = 0;
		var getName = null;
		var compareCount = dimensions.length;
		var comparejsonCount = dupleData.length;
		var JSONDATA = null;
		
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
		$.each(self.DI.Measure,function(_i,_val){
			if(self.selectedMeasure[0].uniqueName ===  _val.UniqueName){
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
		
		d4.select("#" + self.itemid).selectAll("svg").remove();
		

		var margin = {top: 30, right: 120, bottom: 0, left: 120},
	    width = $('#'+self.itemid).width() * 90 / 100,
	    height = $('#'+self.itemid).height() * 90 / 100;
		
		function rectangularAreaChartDefaultSettings(){
		    return {
		        expandFromLeft: true, // Areas expand from left to right.
		        expandFromTop: false, // Areas expand from top to bottom.
		        animate: false, // Controls animation when chart loads.
		        animateDuration: 2000, // The duration of the animation when the chart loads.
		        animateDelay: 0, // The delay between the chart loading and the actual load animation starting.
		        animateDelayBetweenBoxes: 0, // Adds a delay between box expansions during the load animation.
		        colorsScale: d4.schemeCategory20b, // The color scale to use for the chart areas.
		        textColorScale: d4.scale.ordinal().range(["#fff"]), // The color scale to use for the chart text.
		        textPadding: {top: 0, bottom: 0, left: 3, right: 3}, // Category text padding.
		        maxValue: -1, // The charts maximum value. If this value is greater than the largest value displayed on the chart, this will cause the largest chart value to take up less area than the maximum height and width of the chart.
		        labelAlignDiagonal: false, // Aligns the category label text to the charts diagonal.
		        valueTextAlignDiagonal: false, // Aligns the value text to the charts diagonal.
		        displayValueText: true, // Display the value text.
		        valueTextPadding: {top: 0, bottom: 0, left: 3, right: 3}, // Value text padding.
		        valueTextCountUp: true // Causes the value text to count up from 0 during the chart load animation.
		    };
		}
		/*
		 * Data must be a an array of json objects formatted:
		 * [{value: 123, label: "Category 1", valuePrefix: "Some Prefix ", valueSuffix: " things"}, {value: 23, label: "Category 2", valuePrefix: "Some Prefix ", valueSuffix: " things"}]
		 * value and label are required.
		 * valuePrefix and valueSuffix are optional.
		 */
		function loadRectangularAreaChart(elementId, data, settings,w,h){
		    var dataSorter = function(a, b) {
		        return a.value - b.value;
		    };
		    var valueFormatter = function(d, overrideValue){
		        var valueText = d.valuePrefix? d.valuePrefix : "";
		        valueText += overrideValue != null? overrideValue : d.value;
		        valueText += d.valueSuffix? d.valueSuffix : "";
		        return valueText;
		    };
		    if(settings == null) settings = rectangularAreaChartDefaultSettings();
		    
//		    var paletteName = self.RectangularAreaChart.Palette;
//			var rgb = getPaletteValue(paletteName);
		    
		    var rgb = gDashboard.d3Manager.getPalette(self);

		   var xLeng = ($('#'+self.itemid).width() - w) / 2;
			var hLeng = ($('#'+self.itemid).height() - h) / 2;
		    var svg = d4.select("#" + elementId).append("svg").attr("width",w).attr("height",h)
		    .attr("style", "position: relative; left:"+xLeng+"px; top:"+hLeng+"px;").append('g')

            var zoomCnt = 0;
			function zoomable(){
				 var zoom = d4.behavior.zoom().on("zoom", function (d,zz) {
					 if(pressKey['z'] || pressKey['Z'])
								d4.select("#" + self.itemid).select('g').attr("transform", function(){

									if(zoomCnt==0){
										d4.event.translate[0] = d4.event.sourceEvent.layerX
										d4.event.translate[1] = d4.event.sourceEvent.layerY
										d4.event.scale =1;
									}
									if(d4.event.translate[0] ===0 && d4.event.translate[1] ===0){
										d4.event.translate[0] = d4.event.sourceEvent.layerX
										d4.event.translate[1] = d4.event.sourceEvent.layerY
									}
									zoomCnt++
									return "translate(" + d4.event.translate + ")scale(" + d4.event.scale + ")"
								})
							})

				  d4.select('#'+self.itemid).select('svg').call(zoom)
			}
			if(self.meta.ZoomAble != 'none'){
				zoomable();
			}
		    
		    var dummyText = svg.append("text")
		        .attr("class", "rectangularAreaChartText")
		        .text("   ");
		    if(dummyText.node()==null) return;
		    var textHeight = dummyText.node().getBBox().height;
		    // Sort the data so that boxes are drawn in the right order.
		    data.sort(dataSorter);
		    data.reverse();
		    self.paletteData = [];
		    $.each(data, function(i, item){
		    	self.paletteData.push(item.label);
		    })
		    var dataMax = Math.max(data[0].value, settings.maxValue);
		    var width = parseInt(w);
		    var height = parseInt(h);
		    // Scales for the height and width of the boxes.
		    var sizeScaleWidth = d4.scale.sqrt().range([0, width]).domain([0, dataMax]);
		    var sizeScaleHeight = d4.scale.sqrt().range([0, height]).domain([0, dataMax]);
		    var line = d4.svg.line()
		        .x(function(d){return d.x;})
		        .y(function(d){return d.y;});
		    // Each box is in it's own group and the animation is done by moving the group.
		    var boxGroup = svg.selectAll("g")
		        .data(data).enter()
		        .append("g")
		        .attr("transform", function(d){
		            if(settings.animate) {
		                var x = settings.expandFromLeft ? sizeScaleWidth(d.value) * -1 : width;
		                var y = settings.expandFromTop ? sizeScaleHeight(d.value) * -1 : height;
		                if(self.meta['Legend'].Visible){
			                if(self.meta['Legend'].Position.indexOf("TopCenter") > -1){
			                	y += 40;
			                	x += 50;
			                }else if(self.meta['Legend'].Position.indexOf("BottomCenter") > -1){
			                	y -= 30;
			                	x += 50;
			                }
		                }
		                return "translate(" + x + "," + y + ")";
		            } else {
		                var x = settings.expandFromLeft? 0 : width - sizeScaleWidth(d.value) + 100 * (self.meta['Legend'].Position.indexOf("Left") > -1 && self.meta['Legend'].Visible);
		                var y = settings.expandFromTop? 0 : height - sizeScaleHeight(d.value);
		                if(self.meta['Legend'].Visible){
			                if(self.meta['Legend'].Position.indexOf("TopCenter") > -1){
			                	y += 40;
			                	x += 50;
			                }else if(self.meta['Legend'].Position.indexOf("BottomCenter") > -1){
			                	y -= 30;
			                	x += 50;
			                }
		                }else{
		                	x += 50;
		                }
		                return "translate(" + x + "," + y + ")";
		            }
		        })
		        // A clip path is necessary to cut off text so that it doesn't get drawn outside the box during the loading animation.
		        .attr("clip-path", function(d,i) { return "url(#" + elementId + "ClipPath" + i + ")"; });
		    // The box clip area.
		    boxGroup.append("defs")
		        .append("clipPath")
		        .attr("id", function(d,i) { return elementId + "ClipPath" + i; })
		        .append("rect")
		        .attr("width", function(d) { return sizeScaleWidth(d.value) - 100 * ((self.meta['Legend'].Position.indexOf("Center") === -1 && self.meta['Legend'].Visible) || !self.meta['Legend'].Visible); })
		        .attr("height", function(d) { return sizeScaleHeight(d.value) - 45 * (self.meta['Legend'].Position.indexOf("TopCenter") > -1 && self.meta['Legend'].Visible); });
		    // The box.
		    var rgbLen = -1;
		    
		    boxGroup.append("rect")
		        .attr("width", function(d) { return sizeScaleWidth(d.value) - 100 * ((self.meta['Legend'].Position.indexOf("Center") === -1 && self.meta['Legend'].Visible) || !self.meta['Legend'].Visible); })
		        .attr("height", function(d) { return sizeScaleHeight(d.value) - 45 * (self.meta['Legend'].Position.indexOf("TopCenter") > -1 && self.meta['Legend'].Visible); })
		        .style("fill", function(d,i) { 
		        	rgbLen++;
		        	if(rgb[rgbLen] == undefined){
		        		rgbLen = 0;
		        	}
		        	return rgb[rgbLen]; 
		        })
		        .append("title")
		        .text(function(d) {/* return d.label + " (" + valueFormatter(d) + ")";*/return "" });
		    
		    // Animate the box.
		    if(settings.animate){
		        boxGroup.transition()
		            .delay(function (d, i) { return settings.animateDelay + (settings.animateDelayBetweenBoxes * i); })
		            .duration(settings.animateDuration)
		            .attr("transform", function(d){
		                var x = settings.expandFromLeft? 0 : width - sizeScaleWidth(d.value);
		                var y = settings.expandFromTop? 0 : height - sizeScaleHeight(d.value);
		                return "translate(" + x + "," + y + ")"
		            });
		    }
		    // Add a path to attach the category label text to.
		    boxGroup.append("path")
		        .attr("id", function(d,i) { return elementId + "HozPath" + i; }).style("font-size",self.meta.LayoutOption.Label.size+'px').style("font-family", self.meta.LayoutOption.Label.family)
		        .attr("d", function(d,i) {
		            var textX1, textX2, textY;
		            if(settings.labelAlignDiagonal){
		                textX1 = settings.textPadding.left;
		                textX2 = sizeScaleWidth(d.value) - settings.textPadding.right ;
		            } else {
		                if(settings.expandFromLeft){
		                    textX1 = settings.textPadding.left;
		                    textX2 = sizeScaleWidth(d.value) * 2 + settings.textPadding.left ;
		                } else {
		                    textX1 = sizeScaleWidth(d.value) * -1 - settings.textPadding.right - (width/2);
		                    textX2 = sizeScaleWidth(d.value) - settings.textPadding.right - (width/2);
		                }
		            }
		            textY = settings.expandFromTop? sizeScaleHeight(d.value) - settings.textPadding.bottom - textHeight/4 : textHeight + settings.textPadding.top;
		            if(self.meta['Legend'].Position.indexOf("TopCenter") > -1 && self.meta['Legend'].Visible) textY -= 50; 
		            return line([{x: textX1, y: textY}, {x: textX2, y: textY}]);
		        });
		    // Set up the label text location.
		    var labelStartOffset, labelEndOffset, labelTextAnchor;
		    if(settings.labelAlignDiagonal){
		        if(settings.expandFromLeft){
		            labelStartOffset = "100%";
		            labelTextAnchor = "end";
		        } else {
		            labelStartOffset = "0%";
		            labelTextAnchor = "start";
		        }
		    } else {
		        if(settings.expandFromLeft){
		            labelStartOffset = "50%";
		            labelEndOffset = "0%";
		            labelTextAnchor = "start";
		        } else {
		            labelStartOffset = "50%";
		            labelEndOffset = "100%";
		            labelTextAnchor = "end";
		        }
		    }
		    if(settings.animate == false && settings.labelAlignDiagonal == false){
		        labelStartOffset = labelEndOffset;
		    }
		    // Add the category label text.
		    var labelPath = boxGroup.append("text")
		        .attr("class", "rectangularAreaChartText")
		        .style("fill", function(d) { return settings.textColorScale(d.label); })
		        .attr("id", function(d,i) { return elementId + "LabelText" + i; })
		        .append("textPath").style("font-size",self.meta.LayoutOption.Label.size+'px')
		        .style("font-family", self.meta.LayoutOption.Label.family)
		        .style("fill", self.meta.LayoutOption.Label.color)
		        .attr("startOffset", labelStartOffset)
		        .style("text-anchor", labelTextAnchor)
		        .attr("xlink:href", function(d,i) { return "#" + elementId + "HozPath" + i; })
		        .text(function(d) { /*return d.label;*/ return ""; });
		    if(settings.animate && settings.labelAlignDiagonal == false){
		        labelPath.transition()
		            .delay(function (d, i) { return settings.animateDelay + (settings.animateDelayBetweenBoxes * i); })
		            .duration(settings.animateDuration)
		            .attr("startOffset", labelEndOffset);
		    }
		    if(settings.displayValueText){
		        // Add a path to attach the value text to.
		        boxGroup.append("path")
		            .attr("d", function(d) {
		                var textX, textY1, textY2;
		                if(settings.valueTextAlignDiagonal){
		                    textY1 = settings.expandFromLeft? sizeScaleHeight(d.value) - settings.valueTextPadding.left : settings.valueTextPadding.left;
		                    textY2 = settings.expandFromLeft? settings.valueTextPadding.right : sizeScaleHeight(d.value) - settings.valueTextPadding.right;
		                } else {
		                    if(settings.expandFromLeft) {
		                        if(settings.expandFromTop){
		                            textY1 = sizeScaleHeight(d.value) * 2 + settings.valueTextPadding.right;
		                            textY2 = settings.valueTextPadding.right;
		                        } else {
		                            textY1 = sizeScaleHeight(d.value) - settings.valueTextPadding.left;
		                            textY2 = sizeScaleHeight(d.value) * -1 - settings.valueTextPadding.left;
		                        }
		                    } else {
		                        if(settings.expandFromTop){
		                            textY1 = settings.valueTextPadding.left;
		                            textY2 = sizeScaleHeight(d.value) * 2 + settings.valueTextPadding.left;
		                        } else {
		                            textY1 = sizeScaleHeight(d.value) * -1 - settings.valueTextPadding.right;
		                            textY2 = sizeScaleHeight(d.value) - settings.valueTextPadding.right;
		                        }
		                    }
		                }
		                textX = settings.expandFromLeft? sizeScaleWidth(d.value) - settings.valueTextPadding.bottom - textHeight/4 : textHeight/4 + settings.valueTextPadding.bottom;
		                if(self.meta['Legend'].Position.indexOf("TopCenter") > -1 && self.meta['Legend'].Visible){
		                	textY1 -= 45; 
		                	textY2 -= 45; 
		                }
		                return line([{x: textX, y: textY1}, {x: textX, y: textY2}]);
		            })
		            .attr("id", function(d,i) { return elementId + "VertPath" + i; });
		        // Set up the value text location.
		        var valueTextStartOffset, valueTextEndOffset, valueTextTextAnchor;
		        if(settings.valueTextAlignDiagonal) {
		            if((settings.expandFromLeft && settings.expandFromTop) ||
		                (settings.expandFromLeft == false && settings.expandFromTop == false)) {
		                valueTextStartOffset = "0%";
		                valueTextTextAnchor = "start";
		            } else {
		                valueTextStartOffset = "100%";
		                valueTextTextAnchor = "end";
		            }
		        } else {
		            if((settings.expandFromLeft && settings.expandFromTop) ||
		                (settings.expandFromLeft == false && settings.expandFromTop == false)){
		                valueTextStartOffset = "50%";
		                valueTextEndOffset = "100%";
		                valueTextTextAnchor = "end";
		            } else {
		                valueTextStartOffset = "50%";
		                valueTextEndOffset = "0%";
		                valueTextTextAnchor = "start";
		            }
		        }
		        if(settings.animate == false && settings.valueTextAlignDiagonal == false){
		            valueTextStartOffset = valueTextEndOffset;
		        }
		        // Add the value text.
		        var valuePath = boxGroup.append("text")
		            .attr("class", "rectangularAreaChartText")
		            .style("fill", function(d) { return settings.textColorScale(d.label); })
		            .append("textPath").style("font-size",self.meta.LayoutOption.Label.size+'px')
			        .style("font-family", self.meta.LayoutOption.Label.family)
			        .style("fill", self.meta.LayoutOption.Label.color)
		            .attr("startOffset", valueTextStartOffset)
		            .style("text-anchor", valueTextTextAnchor)
		            .attr("xlink:href", function(d,i) { return "#" + elementId + "VertPath" + i; });
		        var valueText = valuePath.append("tspan") // A tspan is necessary so that we can animate both the movement of the text and it's counting up from 0.
		            .text(function(d) { return textFormat(d)});
//		        	.text(function(d) { return settings.animate&&settings.valueTextCountUp? valueFormatter(d, 0) : valueFormatter(d); });
		        
		        // Animate the text movement.
		        if(settings.animate && settings.valueTextAlignDiagonal == false) {
		            valuePath.transition()
		                .delay(function (d, i) { return settings.animateDelay + (settings.animateDelayBetweenBoxes * i); })
		                .duration(settings.animateDuration)
		                .attr("startOffset", valueTextEndOffset);
		        }
		        // Animate the value counting up from 0.
		        if(settings.animate && settings.valueTextCountUp){
		            valueText.transition()
		                .delay(function (d, i) { return settings.animateDelay + (settings.animateDelayBetweenBoxes * i); })
		                .duration(settings.animateDuration * 1.25)
		                .tween("text", function(d){
		                    var i = d4.interpolate(this.textContent, d.value);
		                    return function(t) { this.textContent = valueFormatter(d, Math.round(i(t))); }
		                });
		        }
		    }
		    
		    
		    if(self.meta['Legend'].Visible){
		    	var legend;
		    	if(self.meta['Legend'].Position.indexOf("Left") > -1){
		    		legend = svg.append("g")
					  .attr("class", "legend")
						//.attr("x", w - 65)
						//.attr("y", 50)
					  .attr("height", 100)
					  .attr("width", 100).style("font-size",self.meta.LayoutOption.Legend.size+'px')
				        .style("font-family", self.meta.LayoutOption.Legend.family)
				        .style("fill", self.meta.LayoutOption.Legend.color)
					.attr('transform', 'translate(-' + (w - 65) + ',20)')  
		    	}else{
			    		legend = svg.append("g")
						  .attr("class", "legend")
							//.attr("x", w - 65)
							//.attr("y", 50)
						  .attr("height", 100)
						  .attr("width", 100).style("font-size",self.meta.LayoutOption.Legend.size+'px')
					        .style("font-family", self.meta.LayoutOption.Legend.family)
					        .style("fill", self.meta.LayoutOption.Legend.color)
						.attr('transform', 'translate(-10,20)')  
		    	}
		    	
				
				var rgbLen = -1;
				if(self.meta['Legend'].Position.indexOf("Center") > -1 && self.meta['Legend'].Visible){
					var y = self.meta['Legend'].Position.indexOf("Bottom") > -1? h - 39 : 0;
					
					legend.selectAll('rect')
					  .data(data)
					  .enter()
					  .append("rect")
					  .attr("x", function(d, i){  return i *  (width/data.length) + 40;})
					  .attr("y", y)
					  .attr("width", 10)
					  .attr("height", 10).style("font-size",self.meta.LayoutOption.Legend.size+'px')
				        .style("font-family", self.meta.LayoutOption.Legend.family)
				        .style("fill", self.meta.LayoutOption.Legend.color)
					  .style("fill", function(d, i) { 
					
						rgbLen++;
						if(rgb[rgbLen] == undefined){
							rgbLen = 0;
						}
						return rgb[rgbLen];
					  })

					legend.selectAll('text')
					  .data(data)
					  .enter()
					  .append("text")
					  .attr("x", function(d, i){  return i *  (width/data.length) + 50;})
					  .attr("y", y + 9)
					  .style("font-size",self.meta.LayoutOption.Legend.size+'px')
					  .style("font-family", self.meta.LayoutOption.Legend.family)
					  .style("fill", self.meta.LayoutOption.Legend.color)
					  .text(function(d) {
						return d.label;
					  })
					  .on("click", function(d){mouseclick(d, this)})
					  .on("mouseover", function() { 
		            	$(this).attr('cursor','pointer');
					  });
				}else{
					legend.selectAll('rect')
					  .data(data)
					  .enter()
					  .append("rect")
					  .attr("x", w - 65)
					  .attr("y", function(d, i){ return i *  (height/data.length) - 9;})
					  .attr("width", 10)
					  .attr("height", 10).style("font-size",self.meta.LayoutOption.Legend.size+'px')
				        .style("font-family", self.meta.LayoutOption.Legend.family)
					  .style("fill", function(d, i) { 
					
						rgbLen++;
						if(rgb[rgbLen] == undefined){
							rgbLen = 0;
						}
						return rgb[rgbLen];
					  })

					legend.selectAll('text')
					  .data(data)
					  .enter()
					  .append("text")
					  .attr("x", w - 50)
					  .attr("y", function(d, i){  return i *  (height/data.length);})
					  .style("font-size",self.meta.LayoutOption.Legend.size+'px')
					  .style("font-family", self.meta.LayoutOption.Legend.family)
					  .style("fill", self.meta.LayoutOption.Legend.color)
					  .text(function(d) {
						return d.label;
					  })
					  .attr("filter", function(d){
						  for (var index = 0; index < self.tempTrackingData.length; index++) {
				    			var check = 0;
			       				$.each(self.dimensions, function(i, dim){
			       					if(self.tempTrackingData[index][dim.name] === d.label.split(" - ")[i])
			       						check++;
			       				})
			       				if(check === self.dimensions.length){
			       					return "true";
			       				}
			       			}
				    	  return "false";
					  })
					  .on("click", function(d){mouseclick(d,this)})
					  .on("mouseover", function() { 
		            	$(this).attr('cursor','pointer');
					  });
				}
				 
		    }
		}

		function getNumeric(d){
        	return Number.unit(d, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
        }
        function textFormat(d){
			  var textValue= ""
		
			  switch(self.meta.TextFormat){
				  case 'none': {
					  textValue ="";
					  break;
				  }
				  case 'Argument': {
				  	  textValue = d.label;
					  break;
				  }
				  case 'Value': {
				
				  	  textValue = getNumeric(d.value)
					  break;
				  }
				  case 'Argument, Value': {
					 
				  	  textValue = d.label +' : '+ getNumeric(d.value);
				  	  
					  break;
				  }
				  case 'Percent': {
//				  	  var percent = d3v3.format(".1%")
//				  	  var rePer = d.parent != null ? percent(d.value / d.parent.value): percent(1)
//					  textValue = d.data.key+'  :  '+ rePer;
					 
				  	  textValue = parseInt((d.value/d4.sum(dupleData, function(_d){return _d.value}))*100) + '%';
					  break;
				  }
				  case 'Value, Percent': {
					  textValue = getNumeric(d.value) + '(' +parseInt((d.value/d4.sum(dupleData, function(_d){return _d.value}))*100) + '%' + ')';
					  break;
				  }
				  case 'Argument, Percent': {
					  textValue = d.label + '(' +parseInt((d.value/d4.sum(dupleData, function(_d){return _d.value}))*100) + '%' + ')';
					  break;
				  }
				  case 'Argument, Value, Percent': {
					  textValue = d.label +' : '+ getNumeric(d.value)  + '(' +parseInt((d.value/d4.sum(dupleData, function(_d){return _d.value}))*100) + '%' + ')';
					  break;
				  }
				  
			  }
			  return textValue
		  }
		
		function mouseclick(d,_this){
             switch(self.IO.MasterFilterMode){
				case 'Multiple':
					var inArray = false;
					var selectedData = {};
					if(d3.select(_this).attr("filter") === "true"){
						d3.select(_this)
						.style("fill", self.meta.LayoutOption.Legend.color)
						.attr("filter", 'false');
						
						for (var index = 0; index < self.tempTrackingData.length; index++) {
							var check = 0;
							$.each(self.dimensions, function(i, dim){
								if(self.tempTrackingData[index][dim.name] === d.label.split(" - ")[i])
									check++;
							})
							if(check === self.dimensions.length){
								self.tempTrackingData.splice(index, 1);
								index--;
							}
						}

					}else{
						d3.select(_this)
						.style("fill", 'blue')
						.attr("filter", 'true');
						
						tempSelectedData = {}
						$.each(self.dimensions, function(i, dim){
							tempSelectedData[dim.name] = d.label.split(" - ")[i]
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
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
				case 'Single':
                
					self.trackingData = [];
                    
                    if(d3.select(_this).attr("filter") === "true"){
						d3.selectAll('text')
						.style("fill", self.meta.LayoutOption.Legend.color)
						.attr("filter", 'false');

					}else{
						d3.selectAll('text')
						.style("fill", self.meta.LayoutOption.Legend.color)
						.attr("filter", 'false');

						d3.select(_this)
						//.style("text-shadow", '-1px 0 blue, 0 1px blue, 1px 0 blue, 0 -1px blue')
						.style("fill", 'blue')
						.attr("filter", 'true');
						var selectedData = {};
						var tempSelectedData = {};
						$.each(self.dimensions, function(i, dim){
							var selectedData = {};
							selectedData[dim.name] = d.label.split(" - ")[i]
							tempSelectedData[dim.name] = d.label.split(" - ")[i]
							self.trackingData.push(selectedData);
						})

						self.tempTrackingData.push(tempSelectedData);
						
					}
                    /*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
                    gDashboard.filterData(self.itemid, self.trackingData);
					break;
					
			}
	    }
		var imsi = 0;
		 
		traits.forEach(function(d){
			json = [];

			/*
			dupleData.forEach(function(p){
				sb = new StringBuilder();
				
				for(var count = 0; count<compareCount; count++){
					if(count == compareCount-1){
						sb.append(p[species[count]]);
					}
					else{
						sb.append(p[species[count]]);
						sb.append(" - ");
					}
				}
				getName = sb.toString();
				if(json[getName]!= null){
					json[getName] = json[getName]+p[d];
				}
				else{
					json[getName] = p[d];
				}
				//json[getName] = temp + p[d];
				//temp = json[getName];
			
			
			});
			*/
			jsonList = new Array();
			for(var jsoncount = 0; jsoncount < comparejsonCount; jsoncount++){
				var data = new Object() ;

				//data.value = json[dupleDatas[jsoncount]];
				data.value = dupleData[jsoncount].value;
				data.label = dupleData[jsoncount].name;

				jsonList.push(data);
			}
			if(traits.length == 2){
				if(imsi == 0){
					 var config1 = rectangularAreaChartDefaultSettings();
					    config1.expandFromLeft = false;
//					    config1.colorsScale = d4.scale.category20b();
					    config1.maxValue = 100;
					    loadRectangularAreaChart(self.itemid, jsonList, config1,width,height);
					    imsi++;
				}
				else if(imsi == 1){
					 var config2 = rectangularAreaChartDefaultSettings();
					     config2.expandFromLeft = false;
//					     config2.colorsScale = d4.scale.ordinal().range(["#fc8d59","#ffffbf","#91bfdb"]);
					     config2.maxValue = 100;
					     loadRectangularAreaChart(self.itemid, jsonList, config2,width,height);
					     imsi++;
				}
			}
			else{
				 var config1 = rectangularAreaChartDefaultSettings();
				    config1.expandFromLeft = false;
//				    config1.colorsScale = d4.scale.category20b();
				    config1.maxValue = 100;
				    loadRectangularAreaChart(self.itemid, jsonList, config1,width,height);
				    imsi++;
			}
			
			
		});
		
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self,self.RectangularAreaChart);
	}
	
	this.functionDo2 = function(_f) {			
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.RectangularAreaChart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.RectangularAreaChart['ShowCaption'] = false;
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
                            	
                            	self.RectangularAreaChart['Name'] = newName;
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
				var chagePalette = self.RectangularAreaChart.Palette;
				var firstPalette = self.RectangularAreaChart.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.RectangularAreaChart.Palette) != -1
										? self.RectangularAreaChart.Palette
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
                                    self.RectangularAreaChart.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.RectangularAreaChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.RectangularAreaChart.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.RectangularAreaChart.Palette = chagePalette;
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
//				var chagePalette = self.RectangularAreaChart.Palette;
//				var firstPalette = self.RectangularAreaChart.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.RectangularAreaChart.Palette) 
//										? self.RectangularAreaChart.Palette
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
//                                    self.RectangularAreaChart.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.RectangularAreaChart.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.RectangularAreaChart.Palette);
//                            chagePalette = firstPalette;
//                            self.RectangularAreaChart.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.RectangularAreaChart.Palette = chagePalette;
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

WISE.libs.Dashboard.RectangularAreaChartFieldManager = function() {
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
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = $(_fieldlist[i]).data('formatOptions');
//				dataItem['NumericFormat'] = NumericFormat;
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
