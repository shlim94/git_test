WISE.libs.Dashboard.item.HeatMap2Generator = function() {
	var self = this;

	this.type = 'HEATMAP2';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	this.HiddenMeasures = [];
	
	var dataMember;
	var Exprname;
	var FilterArray = [];
	
	this.HeatMap2 = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
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
	this.tempTrackingData = [];
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
//				.toArray(_item.DataItems.Dimension) : [];

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
	
	this.setHeatMap2 = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.HeatMap2['ComponentName'] = this.ComponentName;
		this.HeatMap2['Name'] = this.Name;
		this.HeatMap2['DataSource'] = this.dataSourceId;
		
		this.HeatMap2['DataItems'] = this.fieldManager.DataItems;
		this.HeatMap2['Arguments'] = this.fieldManager.Arguments;
		this.HeatMap2['Values'] = this.fieldManager.Values;
		this.HeatMap2.HiddenMeasures = self.fieldManager.HiddenMeasures;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.HeatMap2;
		
		if (!(this.HeatMap2['Palette'])) {
			this.HeatMap2['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HeatMap2.InteractivityOptions) {
			if (!(this.HeatMap2.InteractivityOptions.MasterFilterMode)) {
				this.HeatMap2.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HeatMap2.InteractivityOptions.TargetDimensions)) {
				this.HeatMap2.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HeatMap2.InteractivityOptions.IgnoreMasterFilters)) {
				this.HeatMap2.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HeatMap2.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.HeatMap2.Legend){
			this.HeatMap2.Legend = {
					Position : gDashboard.reportType === "StaticAnalysis" ? "TopRightVertical" : "BottomCenterHorizontal",
					Visible : true
			}
		}
		
		if(!this.HeatMap2.LayoutOption){
			this.HeatMap2.LayoutOption = {
					Legend : {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 12
					},
					AxisX : {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 12
					},
			}
		}
		if(!this.HeatMap2['ZoomAble']){
			this.HeatMap2.ZoomAble = 'none'
		}
		
		if (!(this.HeatMap2['TextFormat'])) {
			this.HeatMap2['TextFormat'] = 'Argument, Value'
		}
	};
	
	this.setHeatMap2forOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setHeatMap2();
		}
		else{
			this.HeatMap2 = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.HeatMap2['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.HeatMap2['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.HeatMap2['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.HeatMap2.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.HeatMap2['Palette'])) {
			this.HeatMap2['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var HeatMap2Option = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.HEATMAP2_DATA_ELEMENT);
				
				$.each(HeatMap2Option,function(_i,_HeatMap2Option){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _HeatMap2Option.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _HeatMap2Option.CTRL_NM;
					}
					if(self.HeatMap2.ComponentName == CtrlNM){
						self.HeatMap2['Palette'] = _HeatMap2Option.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.HeatMap2.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.HeatMap2.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HeatMap2.InteractivityOptions) {
			if (!(this.HeatMap2.InteractivityOptions.MasterFilterMode)) {
				this.HeatMap2.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HeatMap2.InteractivityOptions.TargetDimensions)) {
				this.HeatMap2.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HeatMap2.InteractivityOptions.IgnoreMasterFilters)) {
				this.HeatMap2.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HeatMap2.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		if(!this.HeatMap2.Legend){
			this.HeatMap2.Legend = {
					Position : gDashboard.reportType === "StaticAnalysis" ? "TopRightVertical" : "BottomCenterHorizontal",
					Visible : true
			}
		}
		
		if(!this.HeatMap2.LayoutOption){
			this.HeatMap2.LayoutOption = {
					Legend : {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 12
					},
					AxisX : {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 12
					},
			}
		}
		if(!this.HeatMap2['ZoomAble']){
			this.HeatMap2.ZoomAble = 'none'
		}
		
		if (!(this.HeatMap2['TextFormat'])) {
			this.HeatMap2['TextFormat'] = 'Argument, Value'
		}
	}
	
	this.setHeatMap2ForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setHeatMap2();
		}
		else{
			this.HeatMap2 = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.HeatMap2['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.HeatMap2['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.HeatMap2['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.HeatMap2.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.HeatMap2['Palette'])) {
			this.HeatMap2['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var HeatMap2Option = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.HEATMAP2_DATA_ELEMENT);
				
				$.each(HeatMap2Option,function(_i,_HeatMap2Option){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _HeatMap2Option.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _HeatMap2Option.CTRL_NM;
//					}
					if(self.HeatMap2.ComponentName == CtrlNM){
						self.HeatMap2['Palette'] = _HeatMap2Option.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.HeatMap2.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.HeatMap2.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HeatMap2.InteractivityOptions) {
			if (!(this.HeatMap2.InteractivityOptions.MasterFilterMode)) {
				this.HeatMap2.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HeatMap2.InteractivityOptions.TargetDimensions)) {
				this.HeatMap2.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HeatMap2.InteractivityOptions.IgnoreMasterFilters)) {
				this.HeatMap2.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HeatMap2.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.HeatMap2.Legend){
			this.HeatMap2.Legend = {
					Position : gDashboard.reportType === "StaticAnalysis" ? "TopRightVertical" : "BottomCenterHorizontal",
					Visible : true
			}
		}
		
		if(!this.HeatMap2.LayoutOption){
			this.HeatMap2.LayoutOption = {
					Legend : {
						family: 'Noto Sans KR',
						size: 12
					},
					AxisX : {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 12
					},
			}
		}
		if(!this.HeatMap2['ZoomAble']){
			this.HeatMap2.ZoomAble = 'none'
		}
		
		if (!(this.HeatMap2['TextFormat'])) {
			this.HeatMap2['TextFormat'] = 'Argument, Value'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		//2020.02.04 mksong SQLLIKE doSqlLike 히트맵 적용 dogfoot
//		if (!this.tracked) {
//			this.globalData = _.clone(_data);
//			this.filteredData = _.clone(_data);
//		}
//		if ($.type(this.child) === 'object' && this.dxItem) {
//			this.dxItem = undefined;
//			this.layoutManager.createItemLayer(this.itemid);
//		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setHeatMap2();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.HeatMap2);
			gDashboard.itemGenerateManager.generateItem(self, self.HeatMap2);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setHeatMap2forOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.HeatMap2);
			gDashboard.itemGenerateManager.generateItem(self, self.HeatMap2);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.HeatMap2)) {
			this.setHeatMap2ForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.HeatMap2);
			gDashboard.itemGenerateManager.generateItem(self, self.HeatMap2);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setHeatMap2ForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.HeatMap2);
			gDashboard.itemGenerateManager.generateItem(self, self.HeatMap2);
		}

		
		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_sigma.png" alt="기준 측정값 변경"></li>';
			topIconPanel.append(trackingDataContainerHtml);
		}
		
		gDashboard.itemGenerateManager.renderButtons(self);
		
//		gDashboard.itemGenerateManager.generateDxItem(self, _data);
		
		var dxConfig = this.getDxItemConfig(this.meta);
		
		this.calculatedFields = [];
		this.tempMeasureFields = [];
		/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
		this.tempDimensionFields = [];
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
										self.tempMeasureFields.push(self.measures.length-1);
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
										self.tempDimensionFields.push(self.dimensions.length-1);
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
		if(self.currentMeasureName === ""){
			self.currentMeasureName = measureKey.caption;
		}else{
			$.each(self.measures, function(i, measure){
				if(measure.caption === self.currentMeasureName){
					measureKey = measure;
					return false;
				}
			})
			/*dogfoot d3 차트 기준 측정값 선택 오류 수정 shlim 20200701*/
			if(self.measures.length == 1){
				self.currentMeasureName = self.measures[0].caption;
			}
		}
		
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		/*dogfoot 통계 히트맵 안타도록 수정 shlim 20201109*/
		if(gDashboard.reportType !== 'StaticAnalysis'){
			self.fHeatMap2(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
		}
		
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
//		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
//				"instance");
//		gDashboard.itemGenerateManager.renderButtons(self);
		
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
		
//		if($('#tab5primary').length == 0){
//			$('.menu-comp').append('<div  class="slide-ui"><ul id="tab5primary" class="lnb-lst-tab" style="margin-top:10px;"></ul></div>');	
//		}
		if($('#tab5primary').length == 0){
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
////		if($('#tab5primary').length == 0){
////			$('.menu-comp').append('<div  class="slide-ui"><ul id="tab5primary" class="lnb-lst-tab" style="margin-top:10px;"></ul></div>');	
////		}
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');	
//		}
//		//임성현 주임 d3 속성 추가
//		$('#tab5primary').empty();
//		$('<li class="slide-ui-item"><a id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		
//		menuItemSlideUi();
//		//임성현 주임 d3 속성 추가
//		
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
//		}
//		
//		// initialize UI elements
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
			if (self.dxItem){
				d3.selectAll('#' + self.itemid + " .heatmap2rect").attr("class", "heatmap2rect").attr('filter', "false");
			}
			self.trackingData = [];
			self.tempTrackingData = [];
			self.selectedPoint = undefined;	
			if(self.IO.MasterFilterMode !== "Off"){
				d3.selectAll('#' + self.itemid + " .heatmap2rect").style("cursor", "pointer");
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
//			if($('#'+this.itemid+'editHeatMap2Popover').length == 0 ){
//				$('<div id="'+this.itemid+'editHeatMap2Popover">').dxPopover({
//					height: 'auto',
//					width: 'auto',
//					position: 'bottom',
//					visible: false
//				}).appendTo('#wrapper');
//			}
//			var p = $('#'+this.itemid+'editHeatMap2Popover').dxPopover('instance');
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
//						self.fHeatMap2(self.filteredData);
////						self.dxItem = $("#" + self.itemid).dxTreeMap(dxConfig).dxTreeMap(
////								"instance");
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
		/*dogfoot d3 측정값 포멧 변경 기능 추가 shlim 20200828*/
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
			//2020.02.04 mksong SQLLIKE doSqlLike 히트맵 적용 dogfoot
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
		
		//2020.02.04 mksong SQLLIKE doSqlLike 히트맵 적용 dogfoot
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		self.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, self);
//		ValueArray.push(SQLike.q(sqlConfig));
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
					//2020.02.04 mksong SQLLIKE doSqlLike 히트맵 적용 dogfoot
					object['value'] = _obj[_Mea.captionBySummaryType];
				});
				
				object['name'] = str.join(' - ');
				resultArr.push(object);
			})
		});
		return resultArr;
	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/
		if(typeof self.resizeData != 'undefined'){
			var measureKey = self.measures[0];
			$.each(self.measures, function(i, measure){
				if(measure.caption === self.currentMeasureName){
					measureKey = measure;
					return false;
				}
			});
			
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fHeatMap2(self.filteredData, self.measures, self.dimensions, 
					self.resizeData);
		
			d3.selectAll('#'+self.itemid+' .heatmap2rect[filter="true"]').attr("class", "heatmap2rect heatmap2-selected")
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/
//		if(self.filteredData != undefined){
//			var measureKey = self.measures[0];
//			$.each(self.measures, function(i, measure){
//				if(measure.caption === self.currentMeasureName){
//					measureKey = measure;
//					return false;
//				}
//			})
//			self.fHeatMap2(self.filteredData, self.measures, self.dimensions, 
//					self.deleteDuplecateData(self.filteredData, measureKey));
//			
//			d3.selectAll('rect[filter="true"]').style("stroke", "black")
//			.style("opacity", 0.8)
//		}
//		gProgressbar.hide();
//	};
	
	 this.fHeatMap2 = function(jsonData, measures, dimensions, dupleData){
			if(!dupleData && jsonData){
				var measureKey = self.measures[0];
				$.each(self.measures, function(i, measure){
					if(measure.caption === self.currentMeasureName){
						measureKey = measure;
						return false;
					}
				})
				dupleData = self.deleteDuplecateData(self.filteredData, measureKey)
			}
			if (!dupleData.data || ($.type(dupleData.data) === 'array' && dupleData.data.length === 0)
					|| (dupleData.data.length == 1 && dupleData.data[0].value == 0 && dupleData.data[0].name == "")
					|| (dupleData.data.length == 1 && (dupleData.data[measures[0].nameBySummaryType2] === 0 || dimensions.length === 0))) {
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
					gProgressbar.hide();	
					gDashboard.updateReportLog();
				}
				
				return;
			}else{
				self.resizeData = dupleData;
				$('#'+self.itemid + ' .nodata-layer').remove();
				$("#" + self.itemid).children().css('display','block');
			}
			 
			$("#"+self.itemid).empty();
			
			
			
			var dimx = [];
			var dimy = [];
			
			$.each(dupleData.dimX, function(_i, _o) {
				dimx.push(_o.dimension || _o);
			});
			$.each(dupleData.dimY, function(_i, _o) {
				dimy.push(_o.dimension || _o);
			});
			
//			var sortX = self.filteredData.sort(function(a, b) {
//				if(self.dimensions[0].sortByMeasure){
//					var sortByMeasure = self.dimensions[0].sortByMeasure;
//					if(self.dimensions[0].sortOrder === 'asc' || self.dimensions[0].sortOrder === 'ascending'){
//						 return a[sortByMeasure] < b[sortByMeasure] ? -1 : a[sortByMeasure] > b[sortByMeasure] ? 1 : 0;
//					}else{
//						return a[sortByMeasure] > b[sortByMeasure] ? -1 : a[sortByMeasure] < b[sortByMeasure] ? 1 : 0;
//					}
//				}else{
//					if(self.dimensions[0].sortOrder === 'asc' || self.dimensions[0].sortOrder === 'ascending'){
//						 return a[self.dimensions[0].name] < b[self.dimensions[0].name] ? -1 : a[self.dimensions[0].name] > b[self.dimensions[0].name] ? 1 : 0;
//					}else{
//						return a[self.dimensions[0].name] > b[self.dimensions[0].name] ? -1 : a[self.dimensions[0].name] < b[self.dimensions[0].name] ? 1 : 0;
//					}
//				}
//			});
			
			
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
			$.each(self.DI.Measure,function(_i,_val){
				if(self.selectedMeasure.uniqueName ===  _val.UniqueName){
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
			
			self.paletteData = ["낮은 값", "높은 값"];
			
//			dimx = dimx.reduce(function(a,b){if(a.indexOf(b)<0)a.push(b);return a;},[]);
//			dimy = dimy.reduce(function(a,b){if(a.indexOf(b)<0)a.push(b);return a;},[]);
			if(gDashboard.reportType == "StaticAnalysis"){
				dimy = dimx
				$.each(dimx,function(_i,_dim){
					var addObject = new Object();
					addObject['값'] = 1;
					addObject['변수'] = _dim;
					addObject['구분변수'] = _dim;
					self.filteredData.push(addObject);
                    
                    /*dogfoot 통계 히트맵 오류 수정  shlim 20201109*/
                    addObject = new Object();
					addObject['value'] = 1;
					addObject['name'] = _dim + " - "+ _dim;
					dupleData.data.push(addObject);
				})

				labelPrecision = 3;
			}
			
			if(!measures)
				measures = self.measures;
			if(!dimensions)
				dimensions = self.dimensions;
			
			
			var mea;
			$.each(measures, function(_i, _o) {
				if(_o.caption === self.currentMeasureName){
					mea = _o.captionBySummaryType;
					return false;
				}
			});
			
			var values = [];
			
			self.filteredData.forEach(function (item) {
			    values.push(item[mea]);
			});

			var rgb = gDashboard.d3Manager.getPalette(self);
			 var legendPosition = self.meta.Legend.Position.indexOf("TopCenter") >= 0? 'Top' : self.meta.Legend.Position.indexOf("BottomCenter") >= 0? 'Bottom' : self.meta.Legend.Position.indexOf("Left") >= 0? 'Left' : 'Right'; 
			var margin = {top: 50, right: 50, bottom: 50, left: 100, top2 : 160},
			width = $('#'+self.itemid).width(),
			height = $('#'+self.itemid).height();
			if(self.meta.Legend.Visible){
				if(legendPosition === "Top"){
					margin = {top: 70, right: 50, bottom: 30, left: 100, top2 : 160}
				}
				else if(legendPosition === "Left"){
					 margin = {top: 50, right: 50, bottom: 30, left: 200, top2 : 160}
				}
				else if(legendPosition === "Right"){
					 margin = {top: 50, right: 150, bottom: 30, left: 100, top2 : 160}
				}

			}else {
				margin = {top: 50, right: 50, bottom: 30, left: 100, top2 : 160}
			}

			
			var w = width - margin.left - margin.right;
//			var h = height - margin.left - margin.right;
			var h = height - margin.top - margin.bottom; 
			gridSizeW = Math.floor(w / dimx.length );
			gridSizeH = Math.floor(h / dimy.length );

			
//			var color = d3.scaleSequential()
//			  .domain([0, d3.max(dupleData, function(d){ return d.value})])
//			  .interpolator(d3.interpolateViridis)
			var color = d3.scaleLinear()
				.domain([d3.min(dupleData.data, function(d){ return d.value}), d3.max(dupleData.data, function(d){ return d.value})])
			  .range([rgb[0], rgb[1]])
			  
			  
			  if(self.meta.Legend.Visible){
				  var legendBarHeight = 10
				  
					 
					
					var legendPos = "0, " + (h - legendBarHeight);
					var axisPos = "0, " + (h + legendBarHeight);
					
					/*dogfoot 통계 히트맵 변경  shlim 20201109*/
					if(gDashboard.reportType == "StaticAnalysis"){
						axisPos = "0, " + (h + legendBarHeight + legendBarHeight);
					}
					
					
					if(legendPosition === "Top"){
						var legendPos = "0, " + (-60 - legendBarHeight);
						var axisPos = "0, " + (-60 + legendBarHeight);
					}else if(legendPosition === "Left"){
						var legendPos = "-10, 0"
						var axisPos = "-120, 0"
					}else if(legendPosition === "Right"){
						var legendPos = "-10, 0"
						var axisPos = (w + legendBarHeight + 100)+", 0"
					}
					
					if(legendPosition === "Top" || legendPosition === "Bottom"){
						var axisBottom = function(g) {
							  g.classed("axis axis--bottom", true)
							  .attr("transform", 'translate('+ axisPos+')')
							  .call(d3.axisBottom(axisScale)
							    .ticks(width / 100)
							    .tickFormat(function(d){
							    	return Number.unit(d, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
							    })
							    .tickSize(legendBarHeight))
							  .select(".domain")
							  .remove()
							}
						
						 var legend = function(g) {
							  g.attr("transform", 'translate('+ legendPos +')')
							  .append("rect")
							    .attr("width", w)
							    .attr("height", legendBarHeight)
							    .style("fill", "url(#linear-gradient"+self.itemid+")")
							  
							  g.call(axisBottom)
							}
						
						 
						 
						axisScale = d3.scaleLinear()
						  .domain(color.domain())
						  .range([0, w])
					}else{
						var axisBottom = function(g) {
							  g.classed("axis axis--bottom", true)
							  .attr("transform", 'translate('+ axisPos+')')
							  .call(d3.axisLeft(axisScale)
							    .ticks(height / 100)
							    .tickFormat(function(d){
							    	return Number.unit(d, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
							    })
							    .tickSize(legendBarHeight))
							  .select(".domain")
							  .remove()
							}
						
						 var legend = function(g) {
							  g
							  .append("rect")
							  .attr("transform", 'translate('+ legendPos +')')
							    .attr("width", legendBarHeight)
							    .attr("height", h)
							    .style("fill", "url(#linear-gradient"+self.itemid+")")
							  
							  g.call(axisBottom)
							}
						
						 
						 
						axisScale = d3.scaleLinear()
						  .domain(color.domain())
						  .range([h, 0])
					}
			  }
			 
			  
			  var tooltip = d3.select("#"+self.itemid)
		    .append("div")
		      .style("opacity", 0)
		      .attr("class", "scatter-plot-tooltip")
		      .style("background-color", "black")
		      .style("border-radius", "5px")
		      .style("padding", "10px")
		      .style("color", "white")

		  // -2- Create 3 functions to show / update (when mouse move but
			// stay on same circle) / hide the tooltip
		  var showTooltip = function(d) {
			
		    var valobject = {};
			valobject['label']="";
            $.each(self.dimensions,function(_i,_data){
                valobject['label'] += d[_data.name] + " - ";
            }) 
            valobject['label'] = valobject['label'] + self.currentMeasureName;
            valobject['value'] = d[mea]
//			var tooltipHtml = self.currentMeasureName + " : " + Number.unit(d[self.measures[0].nameBySummaryType], labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
            var tooltipHtml = textFormat(valobject);
		    tooltip
		      .transition()
		      .duration(200)
		    tooltip
		      .style("opacity", 1)
		      .html(tooltipHtml)
		      .style("left", (d3.mouse(this)[0] + margin.left) + "px")
		      .style("top", (d3.mouse(this)[1] - 20) + "px")
		  }
		  var moveTooltip = function(d) {
		    tooltip
		      .style("left", (d3.mouse(this)[0]+margin.left) + "px")
		      .style("top", (d3.mouse(this)[1] - 20) + "px")
		  }
		  var hideTooltip = function(d) {
		    tooltip
		      .transition()
		      .duration(200)
		      .style("opacity", 0)
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
						 
					  	  textValue = d.label +' : '+ getNumeric(d.value) ;
					  	  
						  break;
					  }
					  case 'Percent': {
//					  	  var percent = d3v3.format(".1%")
//					  	  var rePer = d.parent != null ? percent(d.value / d.parent.value): percent(1)
//						  textValue = d.data.key+'  :  '+ rePer;
						 
					  	  textValue = ((d.value/d3.sum(dupleData.data, function(_d){return _d.value}))*100).toFixed(2) + '%';
						  break;
					  }
					  case 'Value, Percent': {
						  textValue = getNumeric(d.value) + '(' + ((d.value/d3.sum(dupleData.data, function(_d){return _d.value}))*100).toFixed(2) + '%)';
						  break;
					  }
					  case 'Argument, Percent': {
					  	  textValue = d.label +' : '+ ((d.value/d3.sum(dupleData.data, function(_d){return _d.value}))*100).toFixed(2) + '%';
						  break;
					  }
					  case 'Argument, Value, Percent': {
						  textValue = d.label +' : '+ getNumeric(d.value) + '(' + ((d.value/d3.sum(dupleData.data, function(_d){return _d.value}))*100).toFixed(2) + '%)';
						  break;
					  }
					  
				  }
				  return textValue
			  }

		  
			var chart = function(){
				  var svg = d3.select("#"+self.itemid).append('svg').attr("height", height).attr("width", width)
				    .classed("crashes-heatmap", true)

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
												return 'translate(' + margin.left + ', ' + margin.top +')';
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
				  
				  // code credit: https://observablehq.com/@tmcw/d3-scalesequential-continuous-color-legend-example
				  // and: https://www.visualcinnamon.com/2016/05/smooth-color-legend-d3-svg-gradient.html
				  var defs = svg.append("defs");
				  var linearGradient = defs.append("linearGradient")
				      .attr("id", "linear-gradient"+self.itemid);
				  
				  
				  if(legendPosition === 'Left' || legendPosition === 'Right'){
					  linearGradient.attr("gradientTransform", "rotate(100)");
					  linearGradient.selectAll("stop")
					    .data(color.ticks().reverse().map(function(t, i, n){return { offset: (100*i/n.length)+'%', color: color(t) }}))
					    .enter().append("stop")
					    .attr("offset", function(d) { return d.offset})
					    .attr("stop-color", function(d) {return d.color });
				  }else{
					  linearGradient.selectAll("stop")
					    .data(color.ticks().map(function(t, i, n){return { offset: (100*i/n.length)+'%', color: color(t) }}))
					    .enter().append("stop")
					    .attr("offset", function(d) { return d.offset})
					    .attr("stop-color", function(d) {return d.color });
				  }
				  
				  
				  var g = svg.append("g")
				    .attr("transform", 'translate(' + margin.left + ', ' + margin.top +')')
				  
				  g.selectAll("rect")
				    .data(self.filteredData)
				    .enter().append("rect")
				      .attr("class", "heatmap2rect")
				      .attr("x", function(d){return dimx.indexOf(d[self.dimensions[0].name]) * gridSizeW})
				      .attr("y", function(d){return dimy.indexOf(d[dimensions[1].name]) * gridSizeH})
				      .attr("rx", 4)
				      .attr("ry", 4)
				      .style("stroke", "#DDD")
				      .style("stroke-width", 1.5)
				      .style("stroke-location", "inner")
				      .attr("width", gridSizeW)
				      .attr("height", gridSizeH)
				      .attr("fill", function(d){ return color(d[self.measures[0].nameBySummaryType])})
//				      .attr("stroke", "#e2e2e2")
				      .style("cursor", function(d){
				    	  if(self.IO.MasterFilterMode !== "Off"){
								return "pointer"
							}
				    	  return "";
				      })
				      .attr("filter", function(d){
				    	  var inArray = false;
				    	  $.each(self.tempTrackingData, function(i, item){
				    		  var check = true;
				    		  $.each(item, function(name, value){
				    			  if(d[name] !== item[name]){
				    				  check = false;
				    				  return false;
				    			  }
				    		  });
				    		  
				    		  if(check) inArray = true;
				    	  })
				    	  return inArray? "true" : "false";})
				      .on("mouseover", showTooltip )
				    .on("mousemove", moveTooltip )
				    .on("mouseleave", hideTooltip )
				    .on("click", function(d){
						switch(self.meta.InteractivityOptions.MasterFilterMode){
				    		case 'Single':
				    			self.trackingData = [];
				    			if(d3.select(this).attr("filter") === "true"){
				    				d3.selectAll('#' + self.itemid + " .heatmap2rect").attr("class", "heatmap2rect").attr('filter', "false");
						    	}else{
						    		//선택 모두 해제
					    			d3.selectAll('#' + self.itemid + " .heatmap2rect").attr("class", "heatmap2rect").attr('filter', "false")
									
						    		d3.select(this)
							    	.attr("class", "heatmap2rect heatmap2-selected")
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
					       		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				           		gDashboard.filterData(self.itemid, self.trackingData);
				    		break;
					    	case 'Multiple':
						    	if(d3.select(this).attr("filter") === "true"){
						    		d3.select(this)
									.attr("class", "heatmap2rect")
									.attr("filter", 'false');
						    	}else{
						    		d3.select(this)
							    	.attr("class", "heatmap2rect heatmap2-selected")
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
					       		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				           		gDashboard.filterData(self.itemid, self.trackingData);
					    	break;
						}
				    })
//				    .append("title")
//				      .text(d => d.value)
				      
				  
				  g.selectAll(".dimy")
				    .data(dimy)
				    .enter().append("text")
				      .text(function(d){ return d })
				      .classed("day", true)
				      .attr("x", 0)
				      .attr("y", function(d, i) { return i * gridSizeH })
				      .style("text-anchor", "end")
				      .attr("transform", "translate(-6," + gridSizeH / 1.7 + ")")
				      .style("font-size", self.meta.LayoutOption.AxisY.size+'px')
				        .style("font-family", self.meta.LayoutOption.AxisY.family)
				        .style("fill", self.meta.LayoutOption.AxisY.color)
				        .style("stroke", self.meta.LayoutOption.AxisY.color)
				  
				  g.selectAll(".dimx")
				    .data(dimx)
				    .enter().append("text")
				      .text(function(d){ return d })
				      .classed("hour", true)
				      .attr("x", function(d, i) { return i * gridSizeW })
//				      .attr("y", 0)
				      .attr("y", function(d, i) { return gDashboard.reportType == "StaticAnalysis" ? dimx.length * gridSizeH + 20 : 0})
				      .style("text-anchor", "middle")
				      .attr("transform", "translate(" + gridSizeW / 2 + ", -6)")
				      .style("font-size", self.meta.LayoutOption.AxisX.size+'px')
				        .style("font-family", self.meta.LayoutOption.AxisX.family)
				        .style("fill", self.meta.LayoutOption.AxisX.color)
				   /*dogfoot 통계 히트맵 추가 shlim 20201109*/     
				   if(gDashboard.reportType == "StaticAnalysis"){
					   g.selectAll(".dimtext")
					    .data(self.filteredData)
					    .enter().append("text")
					      .text(function(d){ return getNumeric(d['값']) })
					      .classed("ddd", true)
					      .attr("x", function(d){return dimx.indexOf(d[self.dimensions[0].name]) * gridSizeW})
					      .attr("y", function(d){return dimy.indexOf(d[dimensions[1].name]) * gridSizeH})
					      .style("text-anchor", "middle")
					      .attr("transform", "translate(" + gridSizeW / 2 + ", "+ gridSizeH / 1.7 +")")
					      .style("font-size", self.meta.LayoutOption.AxisY.size+'px')
					        .style("font-family", self.meta.LayoutOption.AxisY.family)
					        .style("fill", self.meta.LayoutOption.AxisY.color)
					        .style("stroke", self.meta.LayoutOption.AxisY.color)     

				   }
				   
				  if(self.meta.Legend.Visible)
					  g.append("g").classed("legend", true)
					  	.call(legend)
				    
				  d3.selectAll("#"+self.itemid+' .legend text')
				  .style("font-size", self.meta.LayoutOption.Legend.size+'px')
				        .style("font-family", self.meta.LayoutOption.Legend.family)
				        .style("fill", self.meta.LayoutOption.Legend.color)
				    
				  
				  return svg.node();
			}
			
			chart()
	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self);
	}
	
	this.functionDo2 = function(_f) {		
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.HeatMap2['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.HeatMap2['ShowCaption'] = false;
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
                            	
                            	self.HeatMap2['Name'] = newName;
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
				var chagePalette = self.HeatMap2.Palette;
				var firstPalette = self.HeatMap2.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.HeatMap2.Palette) != -1
										? self.HeatMap2.Palette
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
                                    self.HeatMap2.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.HeatMap2.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.HeatMap2.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.HeatMap2.Palette = chagePalette;
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
//				var chagePalette = self.HeatMap2.Palette;
//				var firstPalette = self.HeatMap2.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.HeatMap2.Palette) 
//										? self.HeatMap2.Palette
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
//                                    self.HeatMap2.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.HeatMap2.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
////                            self.dxItem.option('palette', self.HeatMap2.Palette);
//                            chagePalette = firstPalette;
//                            self.HeatMap2.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.HeatMap2.Palette = chagePalette;
//					}
//                });
//                p.option('visible', !(p.option('visible')));
//				break;
//			}
			default: break;
		}
	}

};


WISE.libs.Dashboard.HeatMap2FieldManager = function() {
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
		//var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
		
		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
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
				//dataItem['NumericFormat'] = NumericFormat;
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
	
	this.setHiddenMeasuresByField = function(_hiddenMeasure){
	 	this.HiddenMeasures = {'Measure' : []};
	 	_.each(_hiddenMeasure,function(_a){
	 		var Value = {'UniqueName' : _a.uniqueName};
	 		self.HiddenMeasures['Measure'].push(Value);
	 	})
	 	return self.HiddenMeasures;
	 };
};
