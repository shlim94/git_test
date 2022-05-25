WISE.libs.Dashboard.item.HistogramChartGenerator = function() {
	var self = this;

	this.type = 'HISTOGRAM_CHART';

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
	this.HistogramChart = [];
	this.fieldManager;
	this.currentMeasureName = "";
	this.tempTrackingData = [];
	this.customPalette = [];
	this.isCustomPalette = false;
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [""];
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
	
	this.setHistogramChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.HistogramChart['ComponentName'] = this.ComponentName;
		this.HistogramChart['Name'] = this.Name;
		this.HistogramChart['DataSource'] = this.dataSourceId;
		
		this.HistogramChart['DataItems'] = this.fieldManager.DataItems;
		this.HistogramChart['Arguments'] = this.fieldManager.Arguments;
		this.HistogramChart['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.HistogramChart;
		
		if (!(this.HistogramChart['Palette'])) {
			this.HistogramChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HistogramChart.InteractivityOptions) {
			if (!(this.HistogramChart.InteractivityOptions.MasterFilterMode)) {
				this.HistogramChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HistogramChart.InteractivityOptions.TargetDimensions)) {
				this.HistogramChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HistogramChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.HistogramChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HistogramChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.HistogramChart['LayoutOption']){
			this.HistogramChart.LayoutOption = {
					AxisX: {
						color: '#000000',
						size: 8,
						family: 'Noto Sans KR'
					},
					AxisY: {
						color: '#000000',
						size: 8,
						family: 'Noto Sans KR'
					}
			}
		}
		
		if(!this.HistogramChart['LayoutOption'].AxisY){
			this.HistogramChart['LayoutOption'].AxisY = {
					color: '#000000',
					size: 8,
					family: 'Noto Sans KR'
			}
		}
		
		if(!this.HistogramChart['ZoomAble']){
			this.HistogramChart.ZoomAble = 'none'
		}
        
        if (!(this.HistogramChart['TextFormat'])) {
			this.HistogramChart['TextFormat'] = 'Value'
        }else if(this.HistogramChart['TextFormat'].indexOf("Argument") > -1){
			this.HistogramChart['TextFormat'] = 'Value'
		}
        
        if (!(this.HistogramChart.AxisY)) {
			this.HistogramChart.AxisY = {
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
		
		if (!(this.HistogramChart.AxisX)) {
			this.HistogramChart.AxisX = {
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

	};
	
	this.setHistogramChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setHistogramChart();
		}
		else{
			this.HistogramChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.HistogramChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.HistogramChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.HistogramChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.HistogramChart['Palette'])) {
			this.HistogramChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var HistogramChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.HISTOGRAM_CHART_DATA_ELEMENT);
				
				$.each(HistogramChartOption,function(_i,_HistogramChartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _HistogramChartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _HistogramChartOption.CTRL_NM;
					}
					if(self.HistogramChart.ComponentName == CtrlNM){
						self.HistogramChart['Palette'] = _HistogramChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.HistogramChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.HistogramChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HistogramChart.InteractivityOptions) {
			if (!(this.HistogramChart.InteractivityOptions.MasterFilterMode)) {
				this.HistogramChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HistogramChart.InteractivityOptions.TargetDimensions)) {
				this.HistogramChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HistogramChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.HistogramChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HistogramChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		if(!this.HistogramChart['LayoutOption']){
			this.HistogramChart.LayoutOption = {
					AxisX: {
						color: '#000000',
						size: 8,
						family: 'Noto Sans KR'
					},
					AxisY: {
						color: '#000000',
						size: 8,
						family: 'Noto Sans KR'
					}
			}
		}
		
		if (!(this.HistogramChart.AxisY)) {
			this.HistogramChart.AxisY = {
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
		
		if (!(this.HistogramChart.AxisX)) {
			this.HistogramChart.AxisX = {
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
		
		if(!this.HistogramChart['LayoutOption'].AxisY){
			this.HistogramChart['LayoutOption'].AxisY = {
					color: '#000000',
					size: 8,
					family: 'Noto Sans KR'
			}
		}
		if(!this.HistogramChart['ZoomAble']){
			this.HistogramChart.ZoomAble = 'none'
		}

		if (!(this.HistogramChart['TextFormat'])) {
			this.HistogramChart['TextFormat'] = 'Value'
		}else if(this.HistogramChart['TextFormat'].indexOf("Argument") > -1){
			this.HistogramChart['TextFormat'] = 'Value'
		}
	}
	
	this.setHistogramChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setHistogramChart();
		}
		else{
			this.HistogramChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.HistogramChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.HistogramChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.HistogramChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.HistogramChart['Palette'])) {
			this.HistogramChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var HistogramChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.HISTOGRAM_CHART_DATA_ELEMENT);
				
				$.each(HistogramChartOption,function(_i,_HistogramChartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _HistogramChartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _HistogramChartOption.CTRL_NM;
//					}
					if(self.HistogramChart.ComponentName == CtrlNM){
						self.HistogramChart['Palette'] = _HistogramChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.HistogramChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.HistogramChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HistogramChart.InteractivityOptions) {
			if (!(this.HistogramChart.InteractivityOptions.MasterFilterMode)) {
				this.HistogramChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HistogramChart.InteractivityOptions.TargetDimensions)) {
				this.HistogramChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HistogramChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.HistogramChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HistogramChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		if(!this.HistogramChart['LayoutOption']){
			this.HistogramChart.LayoutOption = {
					AxisX: {
						color: '#000000',
						size: 8,
						family: 'Noto Sans KR'
					},
					AxisY: {
						color: '#000000',
						size: 8,
						family: 'Noto Sans KR'
					}
			}
		}
		
		if(!this.HistogramChart['LayoutOption'].AxisY){
			this.HistogramChart['LayoutOption'].AxisY = {
					color: '#000000',
					size: 8,
					family: 'Noto Sans KR'
			}
		}
		if(!this.HistogramChart['ZoomAble']){
			this.HistogramChart.ZoomAble = 'none'
		}
		
		if (!(this.HistogramChart.AxisY)) {
			this.HistogramChart.AxisY = {
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
		
		if (!(this.HistogramChart.AxisX)) {
			this.HistogramChart.AxisX = {
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

		if (!(this.HistogramChart['TextFormat'])) {
			this.HistogramChart['TextFormat'] = 'Value'
		}else if(this.HistogramChart['TextFormat'].indexOf("Argument") > -1){
			this.HistogramChart['TextFormat'] = 'Value'
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
			self.setHistogramChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.HistogramChart);
			gDashboard.itemGenerateManager.generateItem(self, self.HistogramChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setHistogramChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.HistogramChart);
			gDashboard.itemGenerateManager.generateItem(self, self.HistogramChart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.HistogramChart)) {
			this.setHistogramChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.HistogramChart);
			gDashboard.itemGenerateManager.generateItem(self, self.HistogramChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setHistogramChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.HistogramChart);
			gDashboard.itemGenerateManager.generateItem(self, self.HistogramChart);
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
		
		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
				"instance");
		
		var measureKey = this.measures[0];
		self.currentMeasureName = measureKey.caption;
		
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fHistogramChart(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		
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
		
//		gDashboard.itemGenerateManager.generateDxItem(self, _data);
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
				d3.selectAll('#' + self.itemid + ' .bar rect').style("stroke", "none")
				.style("opacity", 1).attr("filter", "false");
			}
			self.trackingData = [];
			self.tempTrackingData = [];
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
//			if($('#'+this.itemid+'editHistogramChartPopover').length == 0 ){
//				$('<div id="'+this.itemid+'editHistogramChartPopover">').dxPopover({
//					height: 'auto',
//					width: 'auto',
//					position: 'bottom',
//					visible: false
//				}).appendTo('#wrapper');
//			}
//			var p = $('#'+this.itemid+'editHistogramChartPopover').dxPopover('instance');
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
//						self.fHistogramChart(self.filteredData);
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
		});
		//2020.02.07 mksong sqllike 적용 dogfoot
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
			self.fHistogramChart(self.filteredData, self.measures, self.dimensions, 
					self.resizeData);
			d3.selectAll("#"+self.itemid+' rect[filter="true"]').style("stroke", "black")
	        .style("opacity", 0.8);
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		if(self.filteredData != undefined){
//			self.fHistogramChart(self.filteredData, self.measures, self.dimensions, 
//					self.deleteDuplecateData(self.filteredData,self.measures[0]));
//		}
//		gProgressbar.hide();
//	};
	
	this.fHistogramChart = function(jsonData, measures, dimensions, dupleData) {
//		var paletteName = self.HistogramChart.Palette;
//		var rgb = getPaletteValue(paletteName);
		var rgb = gDashboard.d3Manager.getPalette(self);
		var values = [];
		
		//2020.05.04 AJKIM 데이터 항목 없을 때 이미지 추가 DOGFOOT
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		self.resizeData = dupleData;
		$.each(dupleData, function(_i, _o) {
			values.push(_o.value)
		});
		
//		$.each(jsonData, function(_i, _o) {
//			dataSet.push(_o[measures.name])
//		});

		d4.select("#" + self.itemid).selectAll("svg").remove();
		/*dogfoot d3 차트 툴팁 오류 수정 shlim 20200701*/
		d4.select("#" + self.itemid).selectAll("div").remove();
		/*dogfoot 히스토그램 툴팁 오류 수정 shlim 20200630*/
		var formatCount = d4.format(",.0f");
  		var svgWidth  = $('#'+self.itemid).width();
  		var svgHeight = $('#'+self.itemid).height()-70;
  		
  		var margin      = {top: 70, bottom: 30, left: 80, right: 20};
  		var width  = svgWidth - margin.left - margin.right;
  		var height = svgHeight - margin.top - margin.bottom;
        

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

  		// data
//    	dataSet = [70,60,75,70,80,85,66,65,73,73,74,64,77,71,63,55];
  		// xAxis
  		if(values.length <= 1){
  			var minca = [];
  			minca.push(0);
  		    var gxmin = d4.min(minca);	
  		}else{
  			var gxmin = d4.min(values);
  		}
//  		var gxmin = d4.min(values);
  		var gxmax = d4.max(values);
//  		var gxmin = 50;
//  		var gxmax = 90;
  		var x     = d3.scaleLinear().domain([gxmin,gxmax]).range([0, width]);
  		
  		var tickNumber = 1;
        var tick = 4;
  		for(var i = 0; i <= tickNumber; i++){
  			tick *= 2;
  		}
//  		var data = d4.layout.histogram().bins(x.ticks(20))(values);
  		var histogram = d4.layout.histogram()
		.value(function(d){
			return d.value;
		})
		.bins(x.ticks(tick));
  		
  		var data = histogram(dupleData);

  		var yMax = d4.max(data, function(d){return d.length});
		var yMin = d4.min(data, function(d){return d.length});
		var colorScale = d4.scale.linear().domain([yMin, yMax]).range([d4.rgb(rgb[0]).brighter(), d4.rgb(rgb[0]).darker()]);
  		// Histogram Interval Setting and Finding Data for Each Intersection
  		/*dogfoot 히스토그램 툴팁 오류 수정 shlim 20200630*/
//		var tooltip = d4.select("body").append("div")
//        .attr("class", "toolTip")
//        .style("display", "none");
  		// yAxis
//  		dataSet.forEach(function(d) {
//		jsonData.forEach(function(p) { p[d] = +p[d]; });
  		
  		var y = d4.scale.linear().domain([0, yMax]).range([height, 0]);

		var xAxis = d4.svg.axis().scale(x).orient("bottom").tickFormat(function(d){
			var NumericX = self.meta.AxisX;
			if(!NumericX.Visible)
				return '';
			return WISE.util.Number.unit(d, NumericX.FormatType, NumericX.Unit, NumericX.Precision, NumericX.Separator, undefined, NumericX.MeasureFormat, NumericX.SuffixEnabled);
		});
		
		var yAxis = d4.svg.axis().scale(y).orient("left").tickFormat(function(d){
			var NumericY = self.meta.AxisY;
			if(!NumericY.Visible)
				return '';
			return WISE.util.Number.unit(d, NumericY.FormatType, NumericY.Unit, NumericY.Precision, NumericY.Separator, undefined, NumericY.MeasureFormat, NumericY.SuffixEnabled);
		});
  		var svg = d4.select("#" + self.itemid).append("svg")
    				.attr("width", width + margin.left + margin.right)
    				.attr("height", height + margin.top + margin.bottom)
  					.append("g")
    				.attr("transform", "translate(" + margin.left + "," + margin.top + ")");
    	var zoomCnt = 0;
		function zoomable(){
			 var zoom = d4.behavior.zoom().on("zoom", function (d,zz) {
				 //dogfoot 히스토그램 줌인아웃 z 키 눌렀을 때 활성화 syjin 20210411
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
									return "translate(" + margin.left + "," + margin.top + ")";
								}
								if(d4.event.translate[0] ===0 && d4.event.translate[1] ===0){
									d4.event.translate[0] = d4.event.sourceEvent.layerX
									d4.event.translate[1] = d4.event.sourceEvent.layerY
								}
								zoomCnt++
								return "translate(" + d4.event.translate + ")scale(" + d4.event.scale + ")"
							})
				 }
						})

			  d4.select('#'+self.itemid).select('svg').call(zoom)
		}
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}
  		var bar = svg.selectAll(".bar")
			.data(data)
		  	.enter().append("g")
			.attr("class", "bar")
			.attr("transform", function(d) { return "translate(" + x(d.x) + "," + y(d.y) + ")"; });

		bar.append("rect")
			.attr("x", 1)
			.attr("width", (x(data[0].dx) - x(0)) - 1)
			.attr("height", function(d) { return height - y(d.y); })
			.attr("fill", function(d) { return colorScale(d.y) })
			.attr("filter", function(d){
				var inArray = false;
				for (var index = 0; index < self.tempTrackingData.length; index++) {
	    			if(d.length !== self.tempTrackingData[index].length) continue;
	    			
	    			var check = 0;
	    			for(var j = 0; j < d.length; j++){
	    				if(self.tempTrackingData[index].indexOf(d[j].name) > -1) check ++;
	    			}
	    			
	    			if(check === d.length){
	    				inArray = true;
	    				break;
	    			}
	   			}
				
				return inArray? "true" : "false";
			})
			/*dogfoot 히스토그램 툴팁 오류 수정 shlim 20200630*/
//			.on("mouseover", function(d) { tooltip.style("display", null); })
//        		 .on("mouseout",  function() { tooltip.style("display", "none"); })
//        		 .on("mousemove", function(d) {
//        		 tooltip.style("display", "block");
//                 tooltip.style("left", (d4.event.pageX/2) + "px");
//                 tooltip.style("top", (d4.event.pageY/2) + "px");
//                 if(d.length != null){
//                 	tooltip.text(d.length + "건");
//                 }
//           });

//		bar.append("text")
//			.attr("dy", ".75em")
//			.attr("y", -12)
//			.attr("x", (x(data[0].dx) - x(0)) / 2)
//			.attr("font-size", gDashboard.fontManager.getFontSize(12, 'Item'))
//			.attr("border","border")
//			.text(function(d) { return formatCount(d.y); });

		svg.append("g")
		.attr("class", "y axis")
		.attr("transform", "translate(0, 0)")
		.call(yAxis);
		
		svg.select(".y.axis")
		  .selectAll("text")
		  .style("margin", "0")
		  .style("font-size", self.meta.LayoutOption.AxisY.size+'px')
		  .style("fill", self.meta.LayoutOption.AxisY.color)
		  .style("font-family", self.meta.LayoutOption.AxisY.family)
		
		svg.append("g")
			.attr("class", "x axis")
			.attr("transform", "translate(0," + height + ")")
			.call(xAxis);

		svg.select(".x.axis")
		  .selectAll("text")
		  .style("margin", "0")
		  .style("font-size", self.meta.LayoutOption.AxisX.size+'px')
		  .style("fill", self.meta.LayoutOption.AxisX.color)
		  .style("font-family", self.meta.LayoutOption.AxisX.family)
  		
		// create a tooltip
		
		
		var tooltip = d4.select("#"+this.itemid)
		.append("div")
		.style("opacity", 0)
		.attr("class", "tooltip")
		.style("background-color", "white")
		.style("border", "solid")
		.style("border-width", "2px")
		.style("border-radius", "5px")
		.style("padding", "5px")
		.style("font-size", gDashboard.fontManager.getFontSize(12, 'Item'))
		.style("font-family", gDashboard.fontManager.getFontFamily('Item'));

		// Three function that change the tooltip when user hover / move / leave a cell
		var mouseover = function(d) {
			tooltip
			.style("opacity", 1)
			if(d3.select(this).attr("filter") !== "true"){
				d3.select(this)
		        .style("stroke", "black")
		        .style("opacity", 0.8)
			}

		};
		
		var mousemove = function(d) {
			tooltip
			//.html(self.currentMeasureName + " : " + d.y + " 건")
			.html(textFormat(d))
			.style("left", (d4.mouse(this)[0]) + "px")
			.style("top", (d4.mouse(this)[1]) + "px")
		};
		
		var mouseleave = function(d) {
			tooltip
			.style("opacity", 0)
			if(d3.select(this).attr("filter") !== "true"){
				d3.select(this)
				.style("stroke", "none")
				.style("opacity", 1)
			}
		};
		
		bar.selectAll("rect")
		.on("mouseover", mouseover)
		    .on("mousemove", mousemove)
		    .on("mouseleave", mouseleave)
		    .on("click", function(d){
		    	switch(self.meta.InteractivityOptions.MasterFilterMode){
	    		case 'Single':
	    			self.trackingData = [];
	    			self.tempTrackingData = [];
	    			if(d3.select(this).attr("filter") === "true"){
	    				d3.selectAll('#' + self.itemid + ' .bar rect')
						.style("stroke", "none")
						.style("opacity", 1)
						.attr("filter", "false");
			    	}else{
			    		//선택 모두 해제
			    		d3.selectAll('#' + self.itemid + ' .bar rect').style("stroke", "none")
						.style("opacity", 1)
						.attr("filter", "false");
						
			    		d3.select(this).style('stroke', 'black').style("stroke", "black")
				        .style("opacity", 0.8).attr("filter", "true");
			    		
			    		var tempSelectedData = [];
			    		for(var i = 0; i < d.length; i++){
			    			tempSelectedData.push(d[i].name)
			    		}
			    		
			    		self.tempTrackingData.push(tempSelectedData);
			    	}
	    			
	    			self.trackingData = [];
	    			
	    			var tempData = [];
			    	
	    			for(var k = 0; k < self.tempTrackingData.length; k++){
	    				for(var i = 0; i < self.tempTrackingData[k].length; i++){
	    					$.each(self.dimensions, function(j, dim){
			       				var selectedData = {};
				    			selectedData[dim.caption] = self.tempTrackingData[k][i].split(" - ")[j]
				    			tempData.push(selectedData);
			       			});
	    				}
	    			}
	    			
			    	$.each(self.dimensions, function(i, dim){
			    		var unique = tempData.map(function(val, index){
			    			return val[dim.caption];
			    		}).filter(function(val, index, arr){
			    			return arr.indexOf(val) === index && typeof val !== 'undefined';
			    		});
			    		
			    		for(var j = 0; j < unique.length; j++){
			    			var selectedData = {};
			    			selectedData[dim.caption] = unique[j]
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
		    	case 'Multiple':
			    	if(d3.select(this).attr("filter") === "true"){
			    		d3.select(this).style("stroke", "none")
						.style("opacity", 1)
						.attr("filter", "false");
			    		
			    		for (var index = 0; index < self.tempTrackingData.length; index++) {
			    			if(d.length !== self.tempTrackingData[index].length) continue;
			    			
			    			var check = 0;
			    			for(var j = 0; j < d.length; j++){
			    				if(self.tempTrackingData[index].indexOf(d[j].name) > -1) check ++;
			    			}
			    			
			    			if(check === d.length){
			    				self.tempTrackingData.splice(index, 1);
			    				index--;
			    				break;
			    			}
		       			}
			    	}else{
			    		d3.select(this).style("stroke", "black")
			    		        .style("opacity", 0.8).attr("filter", "true");
//			    		self.tempTrackingData.push(d.dimension.split(" - ")[i]);
			    		var tempSelectedData = [];
			    		for(var i = 0; i < d.length; i++){
			    			tempSelectedData.push(d[i].name)
			    		}
			    		
			    		self.tempTrackingData.push(tempSelectedData);
			    	}
			    	

	    			self.trackingData = [];
	    			
	    			var tempData = [];
			    	
	    			for(var k = 0; k < self.tempTrackingData.length; k++){
	    				for(var i = 0; i < self.tempTrackingData[k].length; i++){
	    					$.each(self.dimensions, function(j, dim){
			       				var selectedData = {};
				    			selectedData[dim.caption] = self.tempTrackingData[k][i].split(" - ")[j]
				    			tempData.push(selectedData);
			       			});
	    				}
	    			}
	    			
			    	$.each(self.dimensions, function(i, dim){
			    		var unique = tempData.map(function(val, index){
			    			return val[dim.caption];
			    		}).filter(function(val, index, arr){
			    			return arr.indexOf(val) === index && typeof val !== 'undefined';
			    		});
			    		
			    		for(var j = 0; j < unique.length; j++){
			    			var selectedData = {};
			    			selectedData[dim.caption] = unique[j]
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
	    	  }
		    })
  		// text in rect
//   		svgCanvas.append("g").selectAll("text")
//      			 .data(bins).enter().append("text").attr("class","text")
//      			 .attr("x", function(d) {return margin.left + x(d.x0) + (x(bins[0].x1)-x(bins[0].x0))/2;})
//      			 .attr("y", function(d) {return margin.top + y(d.length) + 15; })
//      			 .text(function(d) { return formatCount(d.length); })
//     	});

        function getNumeric(d){
        	return NumberF.unit(d,labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
        }
        function textFormat(d){
			  var textValue= self.currentMeasureName + " : " + d.y + " 건<br/>" 
			  var textList=[];
			  for(var i=0; i < d.y; i++){
				  textList.push(d[i]);
			  }
			  switch(self.meta.TextFormat){
			  case 'none': {
				  textValue ="";
				  break;
			  }
			  case 'Argument': {
				  $.each(textList,function(_i,_data){
					  if(_i === 10){
						  textValue = textValue.slice(0,-1);
						  textValue += ' . . . ';
						  return false;
					  }
					  textValue += ' [ '+ _data.name +' ] ,';

				  })
				  textValue = textValue.slice(0,-1);
				  break;
			  }
			  case 'Value': {
				  $.each(textList,function(_i,_data){
					  if(_i === 10){
						  textValue = textValue.slice(0,-1);
						  textValue += ' . . . ';
						  return false;
					  }
					  textValue += ' [ ' + getNumeric(_data.value) +' ] ,';
				  })
				  textValue = textValue.slice(0,-1);
				  break;
			  }
			  case 'Argument, Value': {
				  $.each(textList,function(_i,_data){
					  if(_i === 10){
						  textValue = textValue.slice(0,-1);
						  textValue += ' . . . ';
						  return false;
					  }
					  textValue += ' [ '+ _data.name +' : '+ getNumeric(_data.value) +' ] ,';

				  })
				  textValue = textValue.slice(0,-1);
				  break;
			  }
			  case 'Percent': {
//				  var percent = d3v3.format(".1%")
//				  var rePer = d.parent != null ? percent(d.value / d.parent.value): percent(1)
//				  textValue = d.data.key+'  :  '+ rePer;

				  textValue += (textList.length/dupleData.length)*100 + '%';
				  break;
			  }
			  case 'Value, Percent': {
				  textValue += (textList.length/dupleData.length)*100 + '%';
				  $.each(textList,function(_i,_data){
					  if(_i === 10){
						  textValue = textValue.slice(0,-1);
						  textValue += ' . . . ';
						  return false;
					  }
					  textValue += ' [ ' + getNumeric(_data.value) +' ] ,';
				  })
				  textValue = textValue.slice(0,-1);
				  break;
			  }
			  case 'Argument, Percent' : {
				  textValue += (textList.length/dupleData.length)*100 + '%';
				  $.each(textList,function(_i,_data){
					  if(_i === 10){
						  textValue = textValue.slice(0,-1);
						  textValue += ' . . . ';
						  return false;
					  }
					  textValue += ' [ '+ _data.name +' ] ,';
				  })
				  textValue = textValue.slice(0,-1);
				  break;
			  }
			  case 'Argument, Value, Percent' : {
				  textValue += (textList.length/dupleData.length)*100 + '%';
				  if(_i === 10){
					  textValue = textValue.slice(0,-1);
					  textValue += ' . . . ';
					  return false;
				  }
				  $.each(textList,function(_i,_data){
					  textValue += ' [ '+ _data.name +' : '+ getNumeric(_data.value) +' ] ,';
				  })
				  textValue = textValue.slice(0,-1);

				  break;
			  }
				  
			  }
			  return textValue
		  }

     	

	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
	
	this.functionDo2 = function(_f) {			
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.HistogramChart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.HistogramChart['ShowCaption'] = false;
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
                            	
                            	self.HistogramChart['Name'] = newName;
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
				var chagePalette = self.HistogramChart.Palette;
				var firstPalette = self.HistogramChart.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.HistogramChart.Palette) != -1
										? self.HistogramChart.Palette
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
                                    self.HistogramChart.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.HistogramChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.HistogramChart.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.HistogramChart.Palette = chagePalette;
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
//				var chagePalette = self.HistogramChart.Palette;
//				var firstPalette = self.HistogramChart.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.HistogramChart.Palette) 
//										? self.HistogramChart.Palette
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
//                                    self.HistogramChart.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.HistogramChart.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
////                            self.dxItem.option('palette', self.HistogramChart.Palette);
//                            chagePalette = firstPalette;
//                            self.HistogramChart.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.HistogramChart.Palette = chagePalette;
//					}
//                });
//                p.option('visible', !(p.option('visible')));
//				break;
//			}
			default: break;
		}
	}

};


WISE.libs.Dashboard.HistogramChartFieldManager = function() {
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
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
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
