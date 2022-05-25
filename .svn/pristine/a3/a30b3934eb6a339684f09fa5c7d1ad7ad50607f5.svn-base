WISE.libs.Dashboard.item.DivergingChartGenerator = function() {
	var self = this;

	this.type = 'DIVERGING_CHART';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	this.seriesDimensions = [];
	this.HiddenMeasures = [];
	
	var dataMember;
	var Exprname;
	var FilterArray = [];
	
	this.DivergingChart = [];
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
	
	this.setDivergingChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.DivergingChart['ComponentName'] = this.ComponentName;
		this.DivergingChart['Name'] = this.Name;
		this.DivergingChart['DataSource'] = this.dataSourceId;
		
		this.DivergingChart['DataItems'] = this.fieldManager.DataItems;
		this.DivergingChart['Arguments'] = this.fieldManager.Arguments;
		this.DivergingChart['Values'] = this.fieldManager.Values;
		this.DivergingChart['SeriesDimensions'] = this.fieldManager.SeriesDimensions;
		this.DivergingChart.HiddenMeasures = self.fieldManager.HiddenMeasures;
		this.seriesDimensions = this.fieldManager.seriesDimensions;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.DivergingChart;
		
		if (!(this.DivergingChart['Palette'])) {
			this.DivergingChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DivergingChart.InteractivityOptions) {
			if (!(this.DivergingChart.InteractivityOptions.MasterFilterMode)) {
				this.DivergingChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DivergingChart.InteractivityOptions.TargetDimensions)) {
				this.DivergingChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DivergingChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.DivergingChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DivergingChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.DivergingChart['Legend'])) {
			this.DivergingChart['Legend'] = {
					Visible : true,
					Position : "TopCenterHorizontal"
			}
		}
		if (!(this.DivergingChart.AxisX)) {
			this.DivergingChart.AxisX = {
				FormatType: 'Percent',
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
				Precision: 2,
				Separator: true
			};
		}
		
		if(!this.DivergingChart.LayoutOption){
			this.DivergingChart.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisX : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
//					Label: {
//						family: '맑은 고딕',
//						color: '#000000',
//						size: 20
//					}
			}
		}
		
		if(this.DivergingChart.LayoutOption.Label){
			delete this.DivergingChart.LayoutOption.Label
		}
		if(!this.DivergingChart['ZoomAble']){
			this.DivergingChart.ZoomAble = 'none'
		}
	};
	
	this.setDivergingChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setDivergingChart();
		}
		else{
			this.DivergingChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.DivergingChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.DivergingChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.DivergingChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.DivergingChart['SeriesDimensions'] = this.meta['SeriesDimensions'] = this.fieldManager.SeriesDimensions;
			this.DivergingChart.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.seriesDimensions = this.fieldManager.seriesDimensions;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.DivergingChart['Palette'])) {
			this.DivergingChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var DivergingChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DIVERGING_CHART_DATA_ELEMENT);
				
				$.each(DivergingChartOption,function(_i,_DivergingChartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _DivergingChartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _DivergingChartOption.CTRL_NM;
					}
					if(self.DivergingChart.ComponentName == CtrlNM){
						self.DivergingChart['Palette'] = _DivergingChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.DivergingChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.DivergingChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DivergingChart.InteractivityOptions) {
			if (!(this.DivergingChart.InteractivityOptions.MasterFilterMode)) {
				this.DivergingChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DivergingChart.InteractivityOptions.TargetDimensions)) {
				this.DivergingChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DivergingChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.DivergingChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DivergingChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.DivergingChart['Legend'])) {
			this.DivergingChart['Legend'] = {
					Visible : true,
					Position : "TopCenterHorizontal"
			}
		}
		if (!(this.DivergingChart.AxisX)) {
			this.DivergingChart.AxisX = {
				FormatType: 'Percent',
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
				Precision: 2,
				Separator: true
			};
		}
		
		if(!this.DivergingChart.LayoutOption){
			this.DivergingChart.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisX : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
//					Label: {
//						family: '맑은 고딕',
//						color: '#000000',
//						size: 20
//					}
			}
		}
		
		if(this.DivergingChart.LayoutOption.Label){
			delete this.DivergingChart.LayoutOption.Label
		}
		if(!this.DivergingChart['ZoomAble']){
			this.DivergingChart.ZoomAble = 'none'
		}
	}
	
	this.setDivergingChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setDivergingChart();
		}
		else{
			this.DivergingChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.DivergingChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.DivergingChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.DivergingChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.DivergingChart['SeriesDimensions'] = this.meta['SeriesDimensions'] = this.fieldManager.SeriesDimensions;
			this.DivergingChart.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.seriesDimensions = this.fieldManager.seriesDimensions;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.DivergingChart['Palette'])) {
			this.DivergingChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var DivergingChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DIVERGING_CHART_DATA_ELEMENT);
				
				$.each(DivergingChartOption,function(_i,_DivergingChartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _DivergingChartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _DivergingChartOption.CTRL_NM;
//					}
					if(self.DivergingChart.ComponentName == CtrlNM){
						self.DivergingChart['Palette'] = _DivergingChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.DivergingChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.DivergingChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DivergingChart.InteractivityOptions) {
			if (!(this.DivergingChart.InteractivityOptions.MasterFilterMode)) {
				this.DivergingChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DivergingChart.InteractivityOptions.TargetDimensions)) {
				this.DivergingChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DivergingChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.DivergingChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DivergingChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.DivergingChart['Legend'])) {
			this.DivergingChart['Legend'] = {
					Visible : true,
					Position : "TopCenterHorizontal"
			}
		}
		if (!(this.DivergingChart.AxisX)) {
			this.DivergingChart.AxisX = {
				FormatType: 'Percent',
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
				Precision: 2,
				Separator: true
			};
		}
		
		if(!this.DivergingChart.LayoutOption){
			this.DivergingChart.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisX : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
//					Label: {
//						family: '맑은 고딕',
//						color: '#000000',
//						size: 20
//					}
			}
		}
		
		if(this.DivergingChart.LayoutOption.Label){
			delete this.DivergingChart.LayoutOption.Label
		}
		if(!this.DivergingChart['ZoomAble']){
			this.DivergingChart.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setDivergingChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.DivergingChart);
			gDashboard.itemGenerateManager.generateItem(self, self.DivergingChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setDivergingChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.DivergingChart);
			gDashboard.itemGenerateManager.generateItem(self, self.DivergingChart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.DivergingChart)) {
			this.setDivergingChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.DivergingChart);
			gDashboard.itemGenerateManager.generateItem(self, self.DivergingChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setDivergingChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.DivergingChart);
			gDashboard.itemGenerateManager.generateItem(self, self.DivergingChart);
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
    	var measureCheck = false;
    	$.each(this.measures, function(i, mea){
    		if(self.currentMeasureName === mea.caption){
    			measureKey = mea;
    			measureCheck = true;
    			return false;
    		}
    	})
		if(!self.currentMeasureName || self.currentMeasureName === "" || !measureCheck)
			self.currentMeasureName = measureKey.caption;
    	
    	
    	self.tempTrackingData = [];
    	self.trackingData = [];
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fDivergingChart(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
		//2021.04.16 syjin 긍정 부긍정 불러오기 or 처음 조회시 아이템 안보이는 오류 수정 dogfoot
		//this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
		//		"instance");
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
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
	}
	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if (self.dxItem){
				d3.selectAll('#' + self.itemid + " rect").style("stroke", "none")
				.style("opacity", 1).attr('filter', "false");
			}
			self.trackingData = [];
			self.tempTrackingData = [];
			self.selectedPoint = undefined;	
		}
	};
	
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
	};
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		var dupledatacehck
		if(typeof self.resizeData != 'undefined'){
			dupledatacehck = self.resizeData;
			var measureKey = this.measures[0];
	    	var measureCheck = false;
	    	$.each(this.measures, function(i, mea){
	    		if(self.currentMeasureName === mea.caption){
	    			measureKey = mea;
	    			measureCheck = true;
	    			return false;
	    		}
	    	})
			if(!self.currentMeasureName || self.currentMeasureName === "" || !measureCheck)
				self.currentMeasureName = measureKey.caption;
	    	
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fDivergingChart(self.filteredData, self.measures, self.dimensions, dupledatacehck);
			
			d3.selectAll('#' + self.itemid + ' rect[filter="true"]').style("stroke", "black")
			.style("opacity", 0.8)
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		if(self.filteredData != undefined){
//			var measureKey = this.measures[0];
//			var measureCheck = false;
//			$.each(this.measures, function(i, mea){
//				if(self.currentMeasureName === mea.caption){
//					measureKey = mea;
//					measureCheck = true;
//					return false;
//				}
//			})
//			if(!self.currentMeasureName || self.currentMeasureName === "" || !measureCheck)
//				self.currentMeasureName = measureKey.caption;
//			
//			self.fDivergingChart(self.filteredData, self.measures, self.dimensions, 
//					self.deleteDuplecateData(self.filteredData, measureKey));
//			
//			d3.selectAll('rect[filter="true"]').style("stroke", "black")
//			.style("opacity", 0.8)
//		}
//		gProgressbar.hide();
//	};
	
	this.fDivergingChart = function(jsonData, measures, dimensions, dupleData) {
		
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		
		self.resizeData = dupleData;
		var svgWidth  = $('#'+self.itemid).width();
  		var svgHeight = $('#'+self.itemid).height();
  		var margin = ({top: 30, right: 30, bottom: 30, left: 30});
  		var width  = svgWidth - margin.left - margin.right;
  		var height = svgHeight - margin.top - margin.bottom;
		if(self.meta.Legend.Visible){
			if(self.meta.Legend.Position === 'TopLeftVertical'){
				margin.left = 150;
			}else if(self.meta.Legend.Position === 'TopRightVertical'){
				margin.right = 150;
			}
		}

		var formatValue = function(n) {
//		  var format = d3.format(data.format || "");
//		  return format(Math.abs(x));
			
			n = Math.abs(n);
			var result = n;
			if(self.DivergingChart.AxisX){
				var NumericX = self.meta.AxisX
				if(!NumericX.Visible){
					return '';
				}else{
				    return WISE.util.Number.unit(result, NumericX.FormatType, NumericX.Unit, NumericX.Precision, NumericX.Separator, undefined, NumericX.MeasureFormat, NumericX.SuffixEnabled);	
				}
		  	}
		}
		
		var formatValueTooltip = function(n) {
//			  var format = d3.format(data.format || "");
//			  return format(Math.abs(x));
			
			n = Math.abs(n);
			var result = n;
			if(self.DivergingChart.AxisX){
				var NumericX = self.meta.AxisX
				if(!NumericX.Visible){
					return '';
				}else{
				    return WISE.util.Number.unit(result, NumericX.FormatType, NumericX.Unit, NumericX.Precision, NumericX.Separator, undefined, NumericX.MeasureFormat, NumericX.SuffixEnabled);	
				}
		  	}
			}
		
		d3.select("#" + self.itemid).selectAll("svg").remove();
		var _data = _.cloneDeep(dupleData);
		
		
		var data = $.extend(_data, {
//			format: ".0%",
			negative: "← -",
		    positive: "+ →",
		    negatives: self.categoryData.negative,
		    positives: self.categoryData.positive
		});
        
		
		var chart = function() {
							
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
												return false;
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


				  var svg = d3.select("#" + self.itemid).append("svg").attr('class','svg'+self.itemid)
				      .attr("viewBox", [0, 0, svgWidth, svgHeight])
				      .append("g")
				      
			      if(self.meta.ZoomAble != 'none'){
					zoomable();
				  }
				  svg.append("g")
				    .selectAll("g")
				    .data(series).
				    enter().append('g')
				      .attr("fill", function(d){ return color(d.key) })
				    .selectAll("rect")
				    .data(function(d){
				    	return d.map(function(v){
				    		return $.extend(v, {key: d.key})
				    	})
				    })
				    .enter().append('rect')
				      .attr("x", function(d){ return x(d[0]) })
				      .attr("y", function(d) { return y(d.data[0])})
				      .attr("width", function(d) { return x(d[1]) - x(d[0]) })
				      .attr("height", y.bandwidth())
				      .attr("filter", function(d){ if(self.trackingData){
				    	  for (var index = 0; index < self.tempTrackingData.length; index++) {
				    			var check = 0;
			       				$.each(self.dimensions, function(i, dim){
			       					if(self.tempTrackingData[index][dim.caption] === d.data[0].split(' - ')[i])
			       						check++;
			       				})
			       				if(check === self.dimensions.length){
			       					return "true"
			       				}
			       			}
				    	  return "false"
				      }else return "false"}).attr("cursor", "pointer")
				      .on("click", function(d){ 
				    	  var _y = d3.select(this).attr('y')
				    	  switch(self.meta.InteractivityOptions.MasterFilterMode){
				    		case 'Single':
				    			self.trackingData = [];
				    			if(d3.select(this).attr("filter") === "true"){
				    				d3.selectAll('#' + self.itemid + " rect").style("stroke", "none")
									.style("opacity", 1).attr('filter', "false");
						    	}else{
						    		//선택 모두 해제
						    		d3.selectAll('#' + self.itemid + " rect").style("stroke", "none")
									.style("opacity", 1).attr('filter', "false");
									
						    		d3.selectAll('#' + self.itemid + ' rect[y="'+_y+'"]')
							    	.style("stroke", "black")
									.style("opacity", 0.8)
									.attr("filter", 'true');
						    		
//				       				var selectedData = {};
//					       			selectedData[self.dimensions[0].name] = d.data[0];
						    		var _s = {};
					       			$.each(self.dimensions, function(i, dim){
					       				var selectedData = {};
						    			selectedData[dim.caption] = d.data[0].split(' - ')[i];
						    			_s[dim.caption] = d.data[0].split(' - ')[i];
						    			self.trackingData.push(selectedData);
					       			})
					       			self.tempTrackingData = [_s];
					       			
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
						    		d3.selectAll('#' + self.itemid + ' rect[y="'+_y+'"]')
									.style("stroke", "none")
									.style("opacity", 1)
									.attr("filter", 'false');
						    		for (var index = 0; index < self.tempTrackingData.length; index++) {
						    			var check = 0;
					       				$.each(self.dimensions, function(i, dim){
					       					if(self.tempTrackingData[index][dim.caption] === d.data[0].split(' - ')[i])
					       						check++;
					       				})
					       				if(check === self.dimensions.length){
					       					self.tempTrackingData.splice(index, 1);
					       					index--;
					       				}
					       			}
						    	}else{
						    		d3.selectAll('rect[y="'+_y+'"]')
							    	.style("stroke", "black")
									.style("opacity", 0.8)
									.attr("filter", 'true');
						    		var selectedData = {};
						    		$.each(self.dimensions, function(i, dim){
						    			selectedData[dim.name] = d.data[0].split(' - ')[i]
				       				})
				       				self.tempTrackingData.push(selectedData);
						    	}
						    	
						    	self.trackingData = [];
						    	
						    	$.each(self.dimensions, function(i, dim){
						    		var unique = self.tempTrackingData.map(function(val, index){
						    			return val[dim.caption];
						    		}).filter(function(val, index, arr){
						    			return arr.indexOf(val) === index;
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
				    .append("title")
				      .text(function(d) {return d.data[0] + '\n' + formatValueTooltip(d.data[1].get(d.key)) + '\n' + d.key});

				  svg.append("g")
				      .call(xAxis);

				  svg.append("g")
				      .call(yAxis);

				  if(self.meta.Legend.Visible){

					  var startp = svg.append("g").attr("class", "legendbox").attr("id", "mylegendbox");
					  // this is not nice, we should calculate the bounding box and use that
					  var legend_tabs = [0, 120, 200, 375, 450];
					  var legend = startp.selectAll(".legend")
					  .data(color.domain().slice())
					  .enter().append("g")
					  .attr("class", "legend")
					  var maxIndex = -1;
					  if(self.meta.Legend.Position.indexOf("Center") > -1){
						  var xSize = svgWidth/color.domain().slice().length;
						  if(xSize < 55){
							  xSize = 50;
							  maxIndex = Math.floor((width - margin.left - margin.right) / xSize);
						  }
						  legend.attr("transform", function(d, i) { return "translate(" +  ( xSize * i + margin.left) + ",-45)"; });
					  }else{
						  var yCheck = Math.floor(height/50) - 1 < color.domain().slice().length;
						  if(yCheck){
							  maxIndex = Math.floor(height / 50) - 1;
						  }
						  legend.attr("transform", function(d, i) { return "translate("+ (self.meta.Legend.Position.indexOf("Left") > -1? 30 : svgWidth - 125) + ", "+ ( 50 * i) +")"; });
					  }


					  legend.append("rect")
					  .attr("x", 0)
					  .attr("width", 10)
					  .attr("height", 10)
					  .style("fill", function(d, i){
						  if(maxIndex === -1 || maxIndex > i)
							  return color(d);
						  else{
							  return d3.rgb(0, 0, 0, 0);
						  }
					  });

					  legend.append("text")
					  .attr("x", 22)
					  .attr("y", 5)
					  .attr("dy", ".35em")
					  .style("text-anchor", "begin")
					  .style("font" ,"9px sans-serif")
					  .text(function(d, i) {
						  if(maxIndex === -1 || maxIndex > i)
							  return d
							  else if(maxIndex === i){
								  return '. . .'
							  }else return '';

				      	});

					  d3.selectAll('#' + self.itemid + " .axis path")
					      .style("fill", "none")
					      .style("stroke", "#000")
					      .style("shape-rendering", "crispEdges")

					  d3.selectAll('#' + self.itemid + " .axis line")
					      .style("fill", "none")
					      .style("stroke", "#000")
					      .style("shape-rendering", "crispEdges")

					  var movesize = 0;
					  if(self.meta.Legend.Position.indexOf("Center") > -1){
						  movesize = width > 600? margin.left / 2 : 0;
					  }
					  var movesizeV = self.meta.Legend.Position.indexOf("Bottom") > -1? svgHeight + 20: 60;
					  d3.selectAll('#' + self.itemid + " .legendbox").attr("transform", "translate(" + movesize  + ","+ movesizeV +")");
				  }
				  
				  return svg.node();
			}
		
//		var signs = new Map([].concat(
//				  data.negatives.map(function(d) { return [d, +1] }),
//				  data.positives.map(function(d) { return [d, +1] })
//				));
		
		
//		var bias = d3.rollups(data, function (v) { return d3.sum(v, function(d){ return d.value * Math.min(0, 1)})},
//				function(d){ return d.name })
//		  .sort(function(a, b){d3.ascending(a[1], b[1])})
		
		var temp = {}
		$.each(data, function(i, d){
			temp[d.name] = 0;
		});
		
		var bias = [];
		
		$.each(temp, function(i, d){
			bias.push([i, d]);
		})
		
		bias = bias.sort(function(a, b){d3.ascending(a[1], b[1])});
		
		
		var seriesRollups = function(data){
			var temp = {};
			$.each(data, function(i, d){
				if(!temp[d.name]){
					temp[d.name] = new Map();
				}
				temp[d.name].set(d.category, d.value);
			})
			
			var result = [];
			$.each(temp, function(name, map){
				result.push([name, map]);
			})
			
			return result;
		}
		
		var series = d3.stack()
	    .keys([].concat(data.negatives.slice().reverse(), data.positives))
	    .value(function (d, category){ return 1 * (d[1].get(category) || 0)})
	    .offset(d3.stackOffsetDiverging)
	    (seriesRollups(data))
//	  (d3.rollups(data, function(data){ return d3.rollup(data, function(d){ return d[0].value}, function(d){ return d.category }) }, function(d) { return d.name }))
		
	    
	    var seriesFlat = function(){
			var result = [];
			for(var i = 0; i < series.length; i++){
				for(var j = 0; j < series[i].length; j++){
					result.push(series[i][j][0], series[i][j][1]);
				}
			}
			
			return result;
		}
		
		var xDomain = d3.extent(seriesFlat());
	    
		if(-xDomain[0] <= xDomain[1] / 8)
	        xDomain[0] = -xDomain[1] / 7
		var x = d3.scaleLinear()
//	    .domain(d3.extent(series.flat(2)))
		.domain(xDomain)
	    .rangeRound([margin.left, svgWidth - margin.right])
	    
	    var y = d3.scaleBand()
	    .domain(bias.map(function(d){ return d[0]}))
	    .rangeRound([margin.top + 30, svgHeight - margin.bottom])
	    .padding(2 / 33)
	    
	    var color = d3.scaleOrdinal()
	    .domain([].concat(data.negatives, data.positives))
	    .range(gDashboard.d3Manager.getPalette(self));
	    
	    var xAxis = function(g) {
	    	var d = g
			.attr("class", "box-x")
		    .attr("transform", 'translate(0,'+margin.top*2+')')

		    if(self.meta.AxisX.Visible){
		    	d.call(d3.axisTop(x)
		        .ticks(width / 80)
		        .tickFormat(formatValue)
		        .tickSizeOuter(0))
		        .call(function(g) {g.select(".domain").remove()})
		    }
		    
		    d.call(function(g){g.append("text")
		        .attr("x", x(0) + 20)
		        .attr("y", -20)
//		        .attr("fill", "currentColor")
		        .attr("text-anchor", "start")
		        .attr("label", "true")
		        .style("font-size", '20px')
		        .style("font-family",'맑은 고딕')
		        .style("fill", "black")
		        .text(data.positive)})
		    .call(function(g){ g.append("text")
		        .attr("x", x(0) - 20)
		        .attr("y", -20)
		        .attr("label", "true")
		        .attr("fill", "currentColor")
		        .attr("text-anchor", "end")
		        .style("font-size", '20px')
		        .style("font-family",'맑은 고딕')
		        .style("fill", "black")
		        .text(data.negative)})
		};
		var yAxis = function(g) {
			g
			.attr("class", "box-y")
		    .call(d3.axisLeft(y).tickSizeOuter(0))
		    .call(function(g) { g.selectAll(".tick").data(bias).attr("transform", function (d) { return 'translate('+x(d[1])+', '+(y(d[0]) + y.bandwidth() / 2) +')'})})
		    .call(function(g) { g.select(".domain").attr("transform", 'translate('+x(0)+', 0)')})      
		    
		}
		
		chart();
		
		d3.selectAll('#'+ self.itemid +' .box-x text:not([label])')
		.style("font-size", self.meta.LayoutOption.AxisX.size+'px')
        .style("font-family", self.meta.LayoutOption.AxisX.family)
        .style("fill", self.meta.LayoutOption.AxisX.color)
        
        d3.selectAll('#'+ self.itemid +" .box-y text")
		.style("font-size", self.meta.LayoutOption.AxisY.size+'px')
        .style("font-family", self.meta.LayoutOption.AxisY.family)
        .style("fill", self.meta.LayoutOption.AxisY.color)
		
		d3.selectAll('#' + self.itemid + " .legend text").style("font-size", self.meta.LayoutOption.Legend.size+'px')
        .style("font-family", self.meta.LayoutOption.Legend.family)
        .style("fill", self.meta.LayoutOption.Legend.color)
	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
};


WISE.libs.Dashboard.DivergingChartFieldManager = function() {
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
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
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
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
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
