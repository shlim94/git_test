WISE.libs.Dashboard.item.BubblePackChartGenerator = function() {
	var self = this;

	this.type = 'BUBBLE_PACK_CHART';

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
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";

	this.BubblePackChart = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	//임성현 팔레트 
	this.customPalette = [];
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [];
	this.isCustomPalette = false;
	
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
				palette: _item['Palette'],
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

	this.setBubblePackChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.BubblePackChart['ComponentName'] = this.ComponentName;
		this.BubblePackChart['Name'] = this.Name;
		this.BubblePackChart['DataSource'] = this.dataSourceId;

		this.BubblePackChart['DataItems'] = this.fieldManager.DataItems;
		this.BubblePackChart['Arguments'] = this.fieldManager.Arguments;
		this.BubblePackChart['Values'] = this.fieldManager.Values;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.BubblePackChart;	
		
		// 임성현 초기 팔레트값 설정
		if (!(this.BubblePackChart['Palette'])) {
			this.BubblePackChart['Palette'] = 'default';
			
			if(gDashboard != undefined){
				var BubblePackChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BUBBLE_PACK_CHART_DATA_ELEMENT);
				
				$.each(BubblePackChartOption,function(_i,_bubblepackchartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _bubblepackchartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _bubblepackchartOption.CTRL_NM;
					}
					if(self.BubblePackChart.ComponentName == CtrlNM){
						self.BubblePackChart['Palette'] = _bubblepackchartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BubblePackChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BubblePackChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		if (!(this.BubblePackChart['Legend'])) {
			this.BubblePackChart['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if (!(this.BubblePackChart['TextFormat'])) {
			this.BubblePackChart['TextFormat'] = 'Argument, Value'
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.BubblePackChart.AxisY)) {
			this.BubblePackChart.AxisY = {
				FormatType: 'Number',
				Unit: 'Ones',
				ShowZero: true,
				Visible: true,
				SuffixEnabled: false,
				MeasureFormat: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				Separator: true
			};
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.BubblePackChart.InteractivityOptions) {
			if (!(this.BubblePackChart.InteractivityOptions.MasterFilterMode)) {
				this.BubblePackChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BubblePackChart.InteractivityOptions.TargetDimensions)) {
				this.BubblePackChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BubblePackChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.BubblePackChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BubblePackChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.BubblePackChart.LayoutOption){
			this.BubblePackChart.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 14
					},
			}
		}
		
		
	};

	this.setBubblePackChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setBubblePackChart();
		}
		else{
			this.BubblePackChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.BubblePackChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.BubblePackChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.BubblePackChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.BubblePackChart['Palette'])) {
			this.BubblePackChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BubblePackChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BUBBLE_PACK_CHART_DATA_ELEMENT);
				
				$.each(BubblePackChartOption,function(_i,_bubblepackchartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _bubblepackchartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _bubblepackchartOption.CTRL_NM;
					}
					if(self.BubblePackChart.ComponentName == CtrlNM){
						self.BubblePackChart['Palette'] = _bubblepackchartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BubblePackChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BubblePackChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		if (!(this.BubblePackChart['TextFormat'])) {
			this.BubblePackChart['TextFormat'] = 'Argument, Value'
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.BubblePackChart.AxisY)) {
			this.BubblePackChart.AxisY = {
				FormatType: 'Number',
				Unit: 'Ones',
				ShowZero: true,
				Visible: true,
				SuffixEnabled: false,
				MeasureFormat: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				Separator: true
			};
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.BubblePackChart.InteractivityOptions) {
			if (!(this.BubblePackChart.InteractivityOptions.MasterFilterMode)) {
				this.BubblePackChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BubblePackChart.InteractivityOptions.TargetDimensions)) {
				this.BubblePackChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BubblePackChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.BubblePackChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BubblePackChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.BubblePackChart.LayoutOption){
			this.BubblePackChart.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 14
					},
			}
		}
	}
	
	//d3 뷰어모드
	this.setBubblePackChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setBubblePackChart();
		}
		else{
			this.BubblePackChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.BubblePackChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.BubblePackChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.BubblePackChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.BubblePackChart['Palette'])) {
			this.BubblePackChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BubblePackChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BUBBLE_PACK_CHART_DATA_ELEMENT);
				
				$.each(BubblePackChartOption,function(_i,_bubblepackchartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _bubblepackchartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _bubblepackchartOption.CTRL_NM;
//					}
					if(self.BubblePackChart.ComponentName == CtrlNM){
						self.BubblePackChart['Palette'] = _bubblepackchartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BubblePackChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BubblePackChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.BubblePackChart.AxisY)) {
			this.BubblePackChart.AxisY = {
				FormatType: 'Number',
				Unit: 'Ones',
				ShowZero: true,
				Visible: true,
				SuffixEnabled: false,
				MeasureFormat: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				Separator: true
			};
		}
		
		if (!(this.BubblePackChart['TextFormat'])) {
			this.BubblePackChart['TextFormat'] = 'Argument, Value'
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.BubblePackChart.InteractivityOptions) {
			if (!(this.BubblePackChart.InteractivityOptions.MasterFilterMode)) {
				this.BubblePackChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BubblePackChart.InteractivityOptions.TargetDimensions)) {
				this.BubblePackChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BubblePackChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.BubblePackChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BubblePackChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.BubblePackChart.LayoutOption){
			this.BubblePackChart.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
						color: '#000000',
						size: 14
					},
			}
		}
	};

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
			self.setBubblePackChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.BubblePackChart);
			gDashboard.itemGenerateManager.generateItem(self, self.BubblePackChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setBubblePackChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.BubblePackChart);
			gDashboard.itemGenerateManager.generateItem(self, self.BubblePackChart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.BubblePackChart)) {
			this.setBubblePackChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.BubblePackChart);
			gDashboard.itemGenerateManager.generateItem(self, self.BubblePackChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setBubblePackChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.BubblePackChart);
			gDashboard.itemGenerateManager.generateItem(self, self.BubblePackChart);
		}

//		var buttonPanelId = this.itemid + '_topicon';
//		var topIconPanel = $('#' + buttonPanelId);
//		if($('#'+this.itemid + '_tracking_data_container').length == 0){
//			var trackingDataContainerId = this.itemid + '_tracking_data_container';
//			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
//			topIconPanel.append(trackingDataContainerHtml);
//		}

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

		/*dogfoot d3차트 수정 shlim 20200618*/
		var measureKey = this.measures;		
		var dupledatacehck = self.deleteDuplecateData(_data,measureKey);
		self.trackingData = [];
		//self.currentMeasureName = measureKey.caption;
		self.currentMeasureName = WISE.util.Object.toArray(measureKey)[0].caption;
		
		//2020.11.03 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('d3');
		self.fBubblePackChart(dupledatacehck, this.measures, this.dimensions, dupledatacehck);
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
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
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete" style="width:50%;"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
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
//		//임성현 주임 d3 속성 추가
//		$('#tab5primary').empty();
//		
//		$('<li class="slide-ui-item"><a id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		
//		menuItemSlideUi();
//		// 임성현 주임  d3 속성 추가
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
//		//d3 option 임성현
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);	
//		});
		
	}

	this.clearTrackingConditions = function() {
        if (self.IO && self.IO.MasterFilterMode) {
				if (self.dxItem) d3.select("#" + self.itemid).selectAll('circle').style('opacity', 1).attr("filter", "false");;
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
//			var page = window.location.pathname.split('/');
//			if (page[page.length - 1] == 'viewer.do') {
//				if($('#'+this.itemid+'editBubblePackChartPopover').length == 0 ){
//					$('<div id="'+this.itemid+'editBubblePackChartPopover">').dxPopover({
//					BubblePackChart 'auto',
//						width: 'auto',
//						position: 'bottom',
//						visible: false
//					}).appendTo('#wrap');
//				}
//			}else{
//				if($('#'+this.itemid+'editBubblePackChartPopover').length == 0 ){
//					$('<div id="'+this.itemid+'editBubblePackChartPopover">').dxPopover({
//						height: 'auto',
//						width: 'auto',
//						position: 'bottom',
//						visible: false
//					}).appendTo('#wrapper');
//				}
//			}
//			
//			var p = $('#'+this.itemid+'editBubblePackChartPopover').dxPopover('instance');
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
//						$('#' + self.itemid + '_title > .lm_title').L(self.Name);
//						var dxConfig = self.getDxItemConfig(self.meta);
//						self.currentMeasureName = selectedMeasure.caption;
//						dxConfig.dataSource = self.deleteDuplecateData(self.filteredData,selectedMeasure);
//						self.fBubblePackChart(self.filteredData);
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
		self.selectedMeasure = MeasureKey;
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
		self.csvData = self.filteredData;
		ValueArray.push(self.filteredData);
		var returnArray = [];

		 var first=[];
		first.push({items:self.filteredData});
		var queryData = first;
		
		//차원이 여러개일때 topN기능이 걸린 차원의 위치를 찾기위한 싸이클
		for(var i = 0; i < self.dimensions.length ; i++){
			if(i == 0){
                queryData = this.__getTopNData(queryData,self.dimensions,self.dimensions[i].name);
			}else{
				if(i == (self.dimensions.length-1)) break;
			    queryData = this.__getTopNData(queryData,self.dimensions,self.dimensions[i].name,self.dimensions[i-1].name);	
			}
		}
        var dimArray = {};
        var returedaraay = [];
        var dimVal2 = [];
        
        for(var i = self.dimensions.length -1; i >0  ; i--){
        	var testNM=[];
        	var zxtestNM={};
        	$.each(queryData,function(_index,_data){
        	   if(i == (self.dimensions.length -1)){
        	       var dimVal = _data.upperDim.slice(1,_data.upperDim.length).split(",");
				   var dimValz = _data.upperDim.slice(1,_data.upperDim.lastIndexOf(',')).split(",");
        	   }else{
        	   	   var dimVal = _data.upperDim.slice(0,_data.upperDim.length).split(",");
				   var dimValz = _data.upperDim.slice(0,_data.upperDim.lastIndexOf(',')).split(",");
        	   }
			   
			   if(i > 0){
				   var dimValName = dimVal[i-1];
			   }

			   if(i ==(self.dimensions.length -1)){
                   dimVal = dimVal.join(',')
				   dimValz = dimValz.join(',')
				   if(!zxtestNM[dimVal]){
					   zxtestNM[dimVal] = {'key':dimValName,'upperDim':dimValz,'items':[]};	
					   zxtestNM[dimVal].items = _data.items
				   }else{
						var jsonStr = '['+JSON.stringify(zxtestNM[dimVal].items).replaceAll('[','').replaceAll(']','') +','+JSON.stringify(_data.items).replaceAll('[','').replaceAll(']','')+']';

						zxtestNM[dimVal].items = JSON.parse(jsonStr)
				   }
			   }else{
			   	   dimVal = dimVal.join(',')
				   dimValz = dimValz.join(',')
				   if(!zxtestNM[dimVal]){
					   zxtestNM[dimVal] = {'key':dimValName,'upperDim':dimValz,'items':[]};	
					   zxtestNM[dimVal].items = [_data]
				   }else{
						var jsonStr = '['+JSON.stringify(zxtestNM[dimVal].items).slice(1,JSON.stringify(zxtestNM[dimVal].items).length-1) +','+JSON.stringify(_data)+']';

						zxtestNM[dimVal].items = JSON.parse(jsonStr)
				   }
			   }
			})
			var arrayzx = [];
			$.each(zxtestNM, function(_v,_z){
				
				arrayzx.push(_z)
			})
			queryData = arrayzx;
        }

		var jsonString = JSON.stringify(queryData);
        $.each(Measure,function(_i,_Mea){
			jsonString = jsonString.replaceAll(_Mea.captionBySummaryType,"value");
		});
        
        jsonString = jsonString.replaceAll('items','children');
        jsonString = jsonString.replaceAll(self.dimensions[self.dimensions.length-1].name,'key');
        var jsonData = {'name':'newone',children:[queryData]};
		var resultArr = {'key':'newone',children:JSON.parse(jsonString)}
		
		return resultArr;
	};
	
	String.prototype.replaceAll = function(org, dest) {
	    return this.split(org).join(dest);
	}
	
this.__getTopNData = function(queryData,dimensions,nowDim,preDim){
		
		
		var sumNm;
		$.each(self.measures,function(_index,_item){
			if(_item.name == self.topMember){
				sumNm = _item.nameBySummaryType;
			}
		})
		
		var topnData = [];
		var otherData =[];
		var topNarray = [];
		var topNresult = [];
		var TopNExecSyx;
		var sortTopNdata;
		var TopNotherData;
		var predim = '';
		var predimNm = '';
		
		$.each(queryData,function(_index,_e){
			if(_e.upperDim){
			    predim = _e.upperDim	
			}
			if(_e.dim){
			    predimNm = _e.dim	
			}
	        
			var ExecSyx = DevExpress.data.query(_e.items);
			ExecSyx = ExecSyx.groupBy(nowDim);
			topNarray = ExecSyx.toArray();
            $.each(topNarray, function(i, e) {
            	e['upperDim'] = predim.concat(",",e.key);
            	e['dim'] = predimNm.concat(",",nowDim);
				topnData.push(e);
			});
		})
        return topnData;
	}
	
	
//	this.resize = function() {
//		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/
//		var dupledatacehck = self.deleteDuplecateData(self.filteredData,self.measures);
//		self.fBubblePackChart(dupledatacehck, self.measures, self.dimensions, dupledatacehck);
//		gProgressbar.hide();
//	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/

		//2020.11.03 mksong resource Import 동적 구현 dogfoot
    	WISE.loadedSourceCheck('d3');
		
		var dupledatacehck
		if(typeof self.resizeData != 'undefined'){
		    dupledatacehck = self.resizeData;
		    self.fBubblePackChart(dupledatacehck, self.measures, self.dimensions, dupledatacehck);
		}
		d3.select("#" + self.itemid).selectAll('circle[filter="true"]').style('opacity', 1).attr("filter", "true");
		
		gProgressbar.hide();
	};
	
	
	this.fBubblePackChart = function(jsonData, measures, dimensions, dupleData) {
		
		var nodata = false;
		
		if (!dupleData || ($.type(dupleData) === 'array' && dupleData.length === 0)
				|| (dupleData.length == 1 && dupleData[0].value == 0 && dupleData[0].key == "")) {
			$('#'+self.itemid + ' .nodata-layer').remove();
			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
			$("#" + self.itemid).children().css('display','none');
			$("#" + self.itemid).prepend(nodataHtml);
			if($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0){
				$("#" + self.itemid).height('100%');
				$("#" + self.itemid).width('100%');
			}
			$("#" + self.itemid).css('display', 'block');

			nodata = true;
		}else{
			self.resizeData = dupleData;
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
		
		if(!jsonData || ($.type(jsonData) === 'array' && jsonData.length === 0)
				|| (dupleData.length == 1 && dupleData[0].value == 0 && dupleData[0].key == "")){
			
			if(nodata){
				if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
				}

				if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
					gProgressbar.hide();	
					gDashboard.updateReportLog();
				}
				return;
			}
		} else if(nodata){
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
		d3.select("#" + self.itemid).selectAll("svg").remove();
//        var width = $("#" + self.itemid).width()
//        var height = $("#" + self.itemid).height()
		
		//var data = {"name":"flare","children":[{"name":"analytics","children":[{"name":"cluster","children":[{"name":"AgglomerativeCluster","value":3938},{"name":"CommunityStructure","value":3812},{"name":"HierarchicalCluster","value":6714},{"name":"MergeEdge","value":743}]},{"name":"graph","children":[{"name":"BetweennessCentrality","value":3534},{"name":"LinkDistance","value":5731},{"name":"MaxFlowMinCut","value":7840},{"name":"ShortestPaths","value":5914},{"name":"SpanningTree","value":3416}]},{"name":"optimization","children":[{"name":"AspectRatioBanker","value":7074}]}]},{"name":"animate","children":[{"name":"Easing","value":17010},{"name":"FunctionSequence","value":5842},{"name":"interpolate","children":[{"name":"ArrayInterpolator","value":1983},{"name":"ColorInterpolator","value":2047},{"name":"DateInterpolator","value":1375},{"name":"Interpolator","value":8746},{"name":"MatrixInterpolator","value":2202},{"name":"NumberInterpolator","value":1382},{"name":"ObjectInterpolator","value":1629},{"name":"PointInterpolator","value":1675},{"name":"RectangleInterpolator","value":2042}]},{"name":"ISchedulable","value":1041},{"name":"Parallel","value":5176},{"name":"Pause","value":449},{"name":"Scheduler","value":5593},{"name":"Sequence","value":5534},{"name":"Transition","value":9201},{"name":"Transitioner","value":19975},{"name":"TransitionEvent","value":1116},{"name":"Tween","value":6006}]},{"name":"data","children":[{"name":"converters","children":[{"name":"Converters","value":721},{"name":"DelimitedTextConverter","value":4294},{"name":"GraphMLConverter","value":9800},{"name":"IDataConverter","value":1314},{"name":"JSONConverter","value":2220}]},{"name":"DataField","value":1759},{"name":"DataSchema","value":2165},{"name":"DataSet","value":586},{"name":"DataSource","value":3331},{"name":"DataTable","value":772},{"name":"DataUtil","value":3322}]},{"name":"display","children":[{"name":"DirtySprite","value":8833},{"name":"LineSprite","value":1732},{"name":"RectSprite","value":3623},{"name":"TextSprite","value":10066}]},{"name":"flex","children":[{"name":"FlareVis","value":4116}]},{"name":"physics","children":[{"name":"DragForce","value":1082},{"name":"GravityForce","value":1336},{"name":"IForce","value":319},{"name":"NBodyForce","value":10498},{"name":"Particle","value":2822},{"name":"Simulation","value":9983},{"name":"Spring","value":2213},{"name":"SpringForce","value":1681}]},{"name":"query","children":[{"name":"AggregateExpression","value":1616},{"name":"And","value":1027},{"name":"Arithmetic","value":3891},{"name":"Average","value":891},{"name":"BinaryExpression","value":2893},{"name":"Comparison","value":5103},{"name":"CompositeExpression","value":3677},{"name":"Count","value":781},{"name":"DateUtil","value":4141},{"name":"Distinct","value":933},{"name":"Expression","value":5130},{"name":"ExpressionIterator","value":3617},{"name":"Fn","value":3240},{"name":"If","value":2732},{"name":"IsA","value":2039},{"name":"Literal","value":1214},{"name":"Match","value":3748},{"name":"Maximum","value":843},{"name":"methods","children":[{"name":"add","value":593},{"name":"and","value":330},{"name":"average","value":287},{"name":"count","value":277},{"name":"distinct","value":292},{"name":"div","value":595},{"name":"eq","value":594},{"name":"fn","value":460},{"name":"gt","value":603},{"name":"gte","value":625},{"name":"iff","value":748},{"name":"isa","value":461},{"name":"lt","value":597},{"name":"lte","value":619},{"name":"max","value":283},{"name":"min","value":283},{"name":"mod","value":591},{"name":"mul","value":603},{"name":"neq","value":599},{"name":"not","value":386},{"name":"or","value":323},{"name":"orderby","value":307},{"name":"range","value":772},{"name":"select","value":296},{"name":"stddev","value":363},{"name":"sub","value":600},{"name":"sum","value":280},{"name":"update","value":307},{"name":"variance","value":335},{"name":"where","value":299},{"name":"xor","value":354},{"name":"_","value":264}]},{"name":"Minimum","value":843},{"name":"Not","value":1554},{"name":"Or","value":970},{"name":"Query","value":13896},{"name":"Range","value":1594},{"name":"StringUtil","value":4130},{"name":"Sum","value":791},{"name":"Variable","value":1124},{"name":"Variance","value":1876},{"name":"Xor","value":1101}]},{"name":"scale","children":[{"name":"IScaleMap","value":2105},{"name":"LinearScale","value":1316},{"name":"LogScale","value":3151},{"name":"OrdinalScale","value":3770},{"name":"QuantileScale","value":2435},{"name":"QuantitativeScale","value":4839},{"name":"RootScale","value":1756},{"name":"Scale","value":4268},{"name":"ScaleType","value":1821},{"name":"TimeScale","value":5833}]},{"name":"util","children":[{"name":"Arrays","value":8258},{"name":"Colors","value":10001},{"name":"Dates","value":8217},{"name":"Displays","value":12555},{"name":"Filter","value":2324},{"name":"Geometry","value":10993},{"name":"heap","children":[{"name":"FibonacciHeap","value":9354},{"name":"HeapNode","value":1233}]},{"name":"IEvaluable","value":335},{"name":"IPredicate","value":383},{"name":"IValueProxy","value":874},{"name":"math","children":[{"name":"DenseMatrix","value":3165},{"name":"IMatrix","value":2815},{"name":"SparseMatrix","value":3366}]},{"name":"Maths","value":17705},{"name":"Orientation","value":1486},{"name":"palette","children":[{"name":"ColorPalette","value":6367},{"name":"Palette","value":1229},{"name":"ShapePalette","value":2059},{"name":"SizePalette","value":2291}]},{"name":"Property","value":5559},{"name":"Shapes","value":19118},{"name":"Sort","value":6887},{"name":"Stats","value":6557},{"name":"Strings","value":22026}]},{"name":"vis","children":[{"name":"axis","children":[{"name":"Axes","value":1302},{"name":"Axis","value":24593},{"name":"AxisGridLine","value":652},{"name":"AxisLabel","value":636},{"name":"CartesianAxes","value":6703}]},{"name":"controls","children":[{"name":"AnchorControl","value":2138},{"name":"ClickControl","value":3824},{"name":"Control","value":1353},{"name":"ControlList","value":4665},{"name":"DragControl","value":2649},{"name":"ExpandControl","value":2832},{"name":"HoverControl","value":4896},{"name":"IControl","value":763},{"name":"PanZoomControl","value":5222},{"name":"SelectionControl","value":7862},{"name":"TooltipControl","value":8435}]},{"name":"data","children":[{"name":"Data","value":20544},{"name":"DataList","value":19788},{"name":"DataSprite","value":10349},{"name":"EdgeSprite","value":3301},{"name":"NodeSprite","value":19382},{"name":"render","children":[{"name":"ArrowType","value":698},{"name":"EdgeRenderer","value":5569},{"name":"IRenderer","value":353},{"name":"ShapeRenderer","value":2247}]},{"name":"ScaleBinding","value":11275},{"name":"Tree","value":7147},{"name":"TreeBuilder","value":9930}]},{"name":"events","children":[{"name":"DataEvent","value":2313},{"name":"SelectionEvent","value":1880},{"name":"TooltipEvent","value":1701},{"name":"VisualizationEvent","value":1117}]},{"name":"legend","children":[{"name":"Legend","value":20859},{"name":"LegendItem","value":4614},{"name":"LegendRange","value":10530}]},{"name":"operator","children":[{"name":"distortion","children":[{"name":"BifocalDistortion","value":4461},{"name":"Distortion","value":6314},{"name":"FisheyeDistortion","value":3444}]},{"name":"encoder","children":[{"name":"ColorEncoder","value":3179},{"name":"Encoder","value":4060},{"name":"PropertyEncoder","value":4138},{"name":"ShapeEncoder","value":1690},{"name":"SizeEncoder","value":1830}]},{"name":"filter","children":[{"name":"FisheyeTreeFilter","value":5219},{"name":"GraphDistanceFilter","value":3165},{"name":"VisibilityFilter","value":3509}]},{"name":"IOperator","value":1286},{"name":"label","children":[{"name":"Labeler","value":9956},{"name":"RadialLabeler","value":3899},{"name":"StackedAreaLabeler","value":3202}]},{"name":"layout","children":[{"name":"AxisLayout","value":6725},{"name":"BundledEdgeRouter","value":3727},{"name":"CircleLayout","value":9317},{"name":"CirclePackingLayout","value":12003},{"name":"DendrogramLayout","value":4853},{"name":"ForceDirectedLayout","value":8411},{"name":"IcicleTreeLayout","value":4864},{"name":"IndentedTreeLayout","value":3174},{"name":"Layout","value":7881},{"name":"NodeLinkTreeLayout","value":12870},{"name":"PieLayout","value":2728},{"name":"RadialTreeLayout","value":12348},{"name":"RandomLayout","value":870},{"name":"StackedAreaLayout","value":9121},{"name":"TreeMapLayout","value":9191}]},{"name":"Operator","value":2490},{"name":"OperatorList","value":5248},{"name":"OperatorSequence","value":4190},{"name":"OperatorSwitch","value":2581},{"name":"SortOperator","value":2023}]},{"name":"Visualization","value":16540}]}]};
//      
        
        self.paletteData = self.dimensions.map(function (val, index) {
			return self.dimensions[index].name;
		}).filter(function (val, index, arr) {
			return arr.indexOf(val) === index;
		});
        var data = dupleData;
        var svgWidth =  $('#'+self.itemid).width();
        var svgHeight = $('#'+self.itemid).height();
        var width = svgWidth;
		var height = svgHeight;
		width = width > height*1.9   ? height*1.5: width;
		var currentTransform = [width / 2, height / 2, height];
		var pack = function(data){
        	return	d3.pack()
					.size([width, height])
					.padding(3)
					(d3.hierarchy(data)
						.sum(function(d){ return d.value })
						.sort(function(a, b) { return b.value - a.value}))
        }
		
		var NumberF = WISE.util.Number,
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
		var selectmea = WISE.util.Object.toArray(self.selectedMeasure);
		var NumericFormat;
		$.each(WISE.util.Object.toArray(self.DI.Measure),function(_i,_val){
			if(selectmea[0].uniqueName ===  _val.UniqueName){
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
		var format = d3.format(",d");
		var colorF;
		if(self.BubblePackChart.Palette === 'default'){
		    colorF = d3vCal.scale.linear().range(['#bfbfbf','#838383','#4c4c4c','#000000'])
				.domain([0,self.paletteData.length-1])	
		}else{
		    var colorZ = gDashboard.d3Manager.getPalette(self);
		}
		
		var colorCircle = d3.scale.ordinal()
			.domain([0,1,2,3])
			.range(['#bfbfbf','#838383','#4c4c4c','#1c1c1c']);
		var color = d3.scaleLinear()
				.domain([0, 5])
				.range(["hsl(152,80%,80%)", "hsl(228,30%,40%)"])
				.interpolate(d3.interpolateHcl);

		const root = pack(data);
		  let focus = root;
		  let view;
		  var viewBox = [-(width/2),-(height/1.35), width, height*1.5].join(" ");
		  var svg = d3.select("#" + self.itemid).append("svg")
		  //.attr("viewBox", `-${width / 2} -${height / 2} ${width} ${height}`)
//			  .attr("viewBox", viewBox)
			  .attr("width", svgWidth)
	          .attr("height", svgHeight)
	          .style("align", 'center')
			  .style("display", "block")
			  .style("margin", "auto")
			  .style("cursor", "pointer")
			  .classed("no-select", true)
			  .on("dblclick", function(event,d,focus){
			  	if(self.zoomTrue){
			  	    zoom(d3.event, root)	
			  	}
				  
			  });
			  //.on("click", (event) => zoom(event, root));

		  const node = svg.append("g").attr("transform","translate("+svgWidth/2+","+svgHeight/2+")")
			.selectAll("circle")
			.data(root.descendants().slice(1))
			.enter().append('circle')
			//.join("circle")
			  .attr("fill", function(d){return d.children ? typeof colorF ==='undefined'? colorZ[d.depth - 1]:colorF(d.depth - 1) : 'white'})
			  //.attr("pointer-events", function(d){ return !d.children })
			  .on("mouseover", function() { d3.select(this).attr("stroke", "#000"); })
			  .on("mouseout", function() { d3.select(this).attr("stroke", null); })
			  .on("click", function(event, d){
				  mouseclick(event,this);
			  })
			  .on("dblclick", function(event, d){
				  if(focus!== event && event.children){
					  zoom(d3.event,event, d);
					  self.zoomTrue = true;
					  d3.event.stopPropagation();

				  }else{
				  	self.zoomTrue = false;
				  }
			  })
			  .attr("filter", function(d){
					var selectedData = {};
					var dimNm = d.data.dim ? d.data.dim : d.data[self.dimensions[self.dimensions.length-1].caption] ? self.dimensions[self.dimensions.length-1].caption : false;
						
					if(!dimNm) return;
					selectedData[dimNm] = d.data.key
					var inArray = false;
					for (var index = 0; index < self.trackingData.length; index++) {
						
						if (self.trackingData[index][dimNm] != undefined &&self.trackingData[index][dimNm] === selectedData[dimNm]) {
							inArray = true;
						}
						
					}

					return inArray? "true" : "false";
				})
			  
				
			node.append("title")
			  .text(function(d) {
			  	if(d.depth && d.depth > 1)
			  	    return self.dimensions[d.depth-2].caption
			  	});
			  //.on("click", (event, d) => focus !== d && (zoom(event, d), event.stopPropagation()));

		  const label = svg.append("g").attr("transform","translate("+svgWidth/2+","+svgHeight/2+")")
			  //.style("font", "20px sans-serif")
			  .style("font", function(event,d){
			  	 return d
			  })
			  .style("font-weight", "blod")
			  .attr("pointer-events", "none")
			  .attr("text-anchor", "middle")
			.selectAll("text")
			.data(root.descendants())
			.enter().append('text')
			  .style("fill-opacity", function(d){ return d.parent === root ? 1 : 0})
			  .style("font-weight", "blod")
			  .style("font-size", self.meta.LayoutOption.Label.size+'px')
			  .style('font-family', self.meta.LayoutOption.Label.family)
			  .style('fill', self.meta.LayoutOption.Label.color)
			  .style("display", function(d){ return d.parent === root ? "inline" : "none"})
			  .text(textFormat);

		  zoomTo([root.x, root.y, root.r * 4]);

		  function zoomTo(v) {
			const k = width / v[2];

			view = v;

			label.attr("transform", function(d){
//				return "translate("[(d.x - v[0]) * k,(d.y - v[1]) * k]+")"
				return "translate(" + [(d.x - v[0]) * k, (d.y - v[1]) * k] + ")";
//				return `translate(${(d.x - v[0]) * k},${(d.y - v[1]) * k})`
			});
			node.attr("transform", function(d) {
				var translate
//				return "translate("[(d.x - v[0]) * k,(d.y - v[1]) * k]+")"
				return "translate(" + [(d.x - v[0]) * k, (d.y - v[1]) * k] + ")";
//				return `translate(${(d.x - v[0]) * k},${(d.y - v[1]) * k})`
			});
			node.attr("r", function(d){return d.r * k});
		  }

		  function zoom(event, d,focus) {
			const focus0 = focus;

			focus = d;

			const transition = svg.transition()
				.duration(d3.event.altKey ? 7500 : 750)
				.tween("zoom", function(d){
				  const i = d3.interpolateZoom(view, [focus.x, focus.y, focus.r * 4]);
				  return function(t) { zoomTo(i(t))};
				});

			label
			  .filter(function(d) { return d.parent === focus || this.style.display === "inline"; })
			  .transition(transition)
				.style("fill-opacity", function(d){ return d.parent === focus ? 1 : 0})
				.on("start", function(d) { if (d.parent === focus) this.style.display = "inline"; })
				.on("end", function(d) { if (d.parent !== focus) this.style.display = "none"; });
		  }
		  
		  function textFormat(d){
			  var textValue=""
			  switch(self.meta.TextFormat){
				  case 'none': {
					  textValue ="";
					  break;
				  }
				  case 'Argument': {
					  textValue = d.data.key;
					  break;
				  }
				  case 'Value': {
					  textValue = NumberF.unit(d.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
					  break;
				  }
				  case 'Argument, Value': {
					  textValue = d.data.key+'  :  '+ NumberF.unit(d.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);	
					  break;
				  }
				  case 'Percent': {
				  	  var percent = d3v3.format(".1%")
				  	  var rePer = d.parent != null ? percent(d.value / d.parent.value): percent(1)
					  textValue = rePer;
//					  textValue = d.data.key+'  :  '+ d.value + '%';
					  break;
				  }
				  case 'Value, Percent': {
					  var percent = d3v3.format(".1%")
				  	  var rePer = d.parent != null ? percent(d.value / d.parent.value): percent(1)
					  var percentText = rePer;
					  textValue = NumberF.unit(d.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + '(' + percentText + ')';
					  break;
				  }
				  case 'Argument, Percent': {
					  var percent = d3v3.format(".1%")
				  	  var rePer = d.parent != null ? percent(d.value / d.parent.value): percent(1)
					  var percentText = rePer;
					  textValue = d.data.key+'  :  '+ percentText;	
					  break;
				  }
				  case 'Argument, Value, Percent': {
					  var percent = d3v3.format(".1%")
				  	  var rePer = d.parent != null ? percent(d.value / d.parent.value): percent(1)
					  var percentText = rePer;
					  textValue = d.data.key+'  :  '+ NumberF.unit(d.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)+ '(' + percentText + ')';	
					  break;
				  }
				  
			  }
			  return textValue
		  }

		  function mouseclick(d, s){
			
				var selectKey = d.data.key;

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

						var dimNm = d.data.dim ? d.data.dim : !d.children ? self.dimensions[self.dimensions.length-1].caption : false;
						
						if(!dimNm){
							d3.select("#" + self.itemid).selectAll('circle').style('opacity', 1).attr("filter", "false");
							self.trackingData = [];
							gDashboard.filterData(self.itemid, self.trackingData);
                            return;
						} 

						
						if(!(d.data.key === "undefined")){
							selectedData[dimNm] = d.data.key
							for (var index = 0; index < self.trackingData.length; index++) {
								
								if (self.trackingData[index][dimNm] != undefined && self.trackingData[index][dimNm] === selectedData[dimNm]) {
									self.trackingData.splice(index, 1);
									index--;
									inArray = true;
								}
								
							}
							
							if (!inArray) {

	                            d3.select("#" + self.itemid).selectAll('circle').style('opacity', 0.2);
	                            d3.select("#" + self.itemid).selectAll('circle[filter="true"]').style('opacity', 1).attr("filter", "true");
								
								
								d3.select(s).style('opacity', 1).attr("filter", "true");
								self.trackingData.push(selectedData);
							}else{
								d3.select(s).style('opacity', 0.2).attr("filter", "false");
								if(self.trackingData.length === 0)d3.select("#" + self.itemid).selectAll('circle').style('opacity', 1).attr("filter", "false");
							}
							/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
							if(WISE.Constants.editmode === "viewer"){
								gDashboard.itemGenerateManager.focusedItem = self;
							}
							/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
							gDashboard.filterData(self.itemid, self.trackingData);
						}
						
						
						
						break;
					case 'Single':
						d3.select("#" + self.itemid).selectAll('circle').style('opacity', 0.2).attr("filter", "false");
						//self.selectedPoint = _e.target;
						self.trackingData = [];
						d3.select(s).style('opacity', 1).attr("filter", "true");
	//					$.each(dimensions, function(_i, _ao) {
	//						
	//
	//					});
						var selectedData = {};
						var dimNm = d.data.dim ? d.data.dim : !d.children ? self.dimensions[self.dimensions.length-1].caption : false;
						
						if(!dimNm){
							d3.select("#" + self.itemid).selectAll('circle').style('opacity', 1).attr("filter", "false");
							self.trackingData = [];
							gDashboard.filterData(self.itemid, self.trackingData);
							return;
						} 
						
						if(!(d.data.key === "undefined")){
                            selectedData[dimNm] = d.data.key;
						    self.trackingData.push(selectedData);	
						}
//						selectedData[dimNm] = d.data.key;
//						self.trackingData.push(selectedData);
						
                        if(self.trackingData.length === 0)d3.select("#" + self.itemid).selectAll('circle').style('opacity', 1).attr("filter", "false");
                        /*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
    					if(WISE.Constants.editmode === "viewer"){
    						gDashboard.itemGenerateManager.focusedItem = self;
    					}
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, self.trackingData);
						break;
				}
			}
            //$('#'+self.itemid).append(svg.node());
		  return svg.node();
		
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self,self.BubblePackChart);
	}
	
	this.functionDo2 = function(_f) {			
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.BubblePackChart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.BubblePackChart['ShowCaption'] = false;
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
                            	
                            	self.BubblePackChart['Name'] = newName;
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
				var chagePalette = self.BubblePackChart.Palette;
				var firstPalette = self.BubblePackChart.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.BubblePackChart.Palette) != -1
										? self.BubblePackChart.Palette
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
                                    self.BubblePackChart.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.BubblePackChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.BubblePackChart.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.BubblePackChart.Palette = chagePalette;
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
//				var chagePalette = self.BubblePackChart.Palette;
//				var firstPalette = self.BubblePackChart.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.BubblePackChart.Palette) 
//										? self.BubblePackChart.Palette
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
//                                    self.BubblePackChart.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.BubblePackChart.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.BubblePackChart.Palette);
//                            chagePalette = firstPalette;
//                            self.BubblePackChart.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.BubblePackChart.Palette = chagePalette;
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

WISE.libs.Dashboard.BubblePackChartFieldManager = function() {
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
};
