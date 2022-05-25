WISE.libs.Dashboard.item.SynchronizedChartGenerator = function() {
	var self = this;

	this.type = 'SYNCHRONIZED_CHARTS';

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

	this.SynchronizedChart = [];
	this.fieldManager;
	this.currentMeasureName = "";

	this.customPalette = [];
	this.isCustomPalette = false;
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [""];
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

	this.setSynchronizedChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.SynchronizedChart['ComponentName'] = this.ComponentName;
		this.SynchronizedChart['Name'] = this.Name;
		this.SynchronizedChart['DataSource'] = this.dataSourceId;

		this.SynchronizedChart['DataItems'] = this.fieldManager.DataItems;
		this.SynchronizedChart['Arguments'] = this.fieldManager.Arguments;
		this.SynchronizedChart['Values'] = this.fieldManager.Values;
		this.SynchronizedChart.HiddenMeasures = self.fieldManager.HiddenMeasures;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.SynchronizedChart;

		if (!(this.SynchronizedChart['Palette'])) {
			this.SynchronizedChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.SynchronizedChart.InteractivityOptions) {
			if (!(this.SynchronizedChart.InteractivityOptions.MasterFilterMode)) {
				this.SynchronizedChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.SynchronizedChart.InteractivityOptions.TargetDimensions)) {
				this.SynchronizedChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.SynchronizedChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.SynchronizedChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.SynchronizedChart.InteractivityOptions = {
					MasterFilterMode: 'Off',
					TargetDimensions: 'Argument',
					IgnoreMasterFilters: false
			};
		}

		if (!(this.SynchronizedChart.AxisY)) {
			this.SynchronizedChart.AxisY = {
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

		if (!(this.SynchronizedChart.AxisX)) {
			this.SynchronizedChart.AxisX = {
				Overlapping: false
			};
		}

		if(!this.SynchronizedChart.LayoutOption){
			this.SynchronizedChart.LayoutOption = {
					Label : {
						family: '맑은 고딕',
						size: 14,
						color: '#000000'
					},
					Title : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
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
					}
			}
		}

		if(!this.SynchronizedChart['ZoomAble']){
			this.SynchronizedChart.ZoomAble = 'none'
		}

	};

	this.setSynchronizedChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setSynchronizedChart();
		}
		else{
			this.SynchronizedChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.SynchronizedChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.SynchronizedChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.SynchronizedChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.SynchronizedChart.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}

		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.SynchronizedChart['Palette'])) {
			this.SynchronizedChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;

			if(gDashboard != undefined){
				var SynchronizedChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SYNCHRONIZED_CHARTS_DATA_ELEMENT);

				$.each(SynchronizedChartOption,function(_i,_SynchronizedChartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _SynchronizedChartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _SynchronizedChartOption.CTRL_NM;
					}
					if(self.SynchronizedChart.ComponentName == CtrlNM){
						self.SynchronizedChart['Palette'] = _SynchronizedChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.SynchronizedChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.SynchronizedChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});

					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (!(this.SynchronizedChart.AxisY)) {
			this.SynchronizedChart.AxisY = {
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
		if (!(this.SynchronizedChart.AxisX)) {
			this.SynchronizedChart.AxisX = {
				Overlapping: false
			};
		}

		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.SynchronizedChart.InteractivityOptions) {
			if (!(this.SynchronizedChart.InteractivityOptions.MasterFilterMode)) {
				this.SynchronizedChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.SynchronizedChart.InteractivityOptions.TargetDimensions)) {
				this.SynchronizedChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.SynchronizedChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.SynchronizedChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.SynchronizedChart.InteractivityOptions = {
					MasterFilterMode: 'Off',
					TargetDimensions: 'Argument',
					IgnoreMasterFilters: false
			};
		}

		if(!this.SynchronizedChart.LayoutOption){
			this.SynchronizedChart.LayoutOption = {
					Label : {
						family: '맑은 고딕',
						size: 14,
						color: '#000000'
					},
					Title : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
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
					}
			}
		}
		if(!this.SynchronizedChart['ZoomAble']){
			this.SynchronizedChart.ZoomAble = 'none'
		}

	}

	this.setSynchronizedChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setSynchronizedChart();
		}
		else{
			this.SynchronizedChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.SynchronizedChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.SynchronizedChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.SynchronizedChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.SynchronizedChart.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}

		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.SynchronizedChart['Palette'])) {
			this.SynchronizedChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;

			if(gDashboard != undefined){
				var SynchronizedChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SYNCHRONIZED_CHARTS_DATA_ELEMENT);

				$.each(SynchronizedChartOption,function(_i,_SynchronizedChartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//					CtrlNM = _SynchronizedChartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
					CtrlNM = _SynchronizedChartOption.CTRL_NM;
//					}
					if(self.SynchronizedChart.ComponentName == CtrlNM){
						self.SynchronizedChart['Palette'] = _SynchronizedChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.SynchronizedChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.SynchronizedChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});

					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}

		if (!(this.SynchronizedChart.AxisY)) {
			this.SynchronizedChart.AxisY = {
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
		if (!(this.SynchronizedChart.AxisX)) {
			this.SynchronizedChart.AxisX = {
				Overlapping: false
			};
		}

		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.SynchronizedChart.InteractivityOptions) {
			if (!(this.SynchronizedChart.InteractivityOptions.MasterFilterMode)) {
				this.SynchronizedChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.SynchronizedChart.InteractivityOptions.TargetDimensions)) {
				this.SynchronizedChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.SynchronizedChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.SynchronizedChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.SynchronizedChart.InteractivityOptions = {
					MasterFilterMode: 'Off',
					TargetDimensions: 'Argument',
					IgnoreMasterFilters: false
			};
		}

		if(!this.SynchronizedChart.LayoutOption){
			this.SynchronizedChart.LayoutOption = {
					Label : {
						family: '맑은 고딕',
						size: 14,
						color: '#000000'
					},
					Title : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
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
					}
			}
		}
		if(!this.SynchronizedChart['ZoomAble']){
			this.SynchronizedChart.ZoomAble = 'none'
		}
	}

	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setSynchronizedChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.SynchronizedChart);
			gDashboard.itemGenerateManager.generateItem(self, self.SynchronizedChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setSynchronizedChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.SynchronizedChart);
			gDashboard.itemGenerateManager.generateItem(self, self.SynchronizedChart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.SynchronizedChart)) {
			this.setSynchronizedChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.SynchronizedChart);
			gDashboard.itemGenerateManager.generateItem(self, self.SynchronizedChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setSynchronizedChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.SynchronizedChart);
			gDashboard.itemGenerateManager.generateItem(self, self.SynchronizedChart);
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

		self.trackingData = [];
		self.tempTrackingData = [];

		//2020.11.03 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('d3');
		self.fSynchronizedChart(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,[]));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);

		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
		"instance");
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
				d3.selectAll('#' + self.itemid + ' .point').style("display", "none").attr("filter", "false");
			}
			self.trackingData = [];
			self.tempTrackingData = [];
		}
	};
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
	};

	this.deleteDuplecateData = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}

//	this.resize = function() {
//	if(self.filteredData){
//	self.fSynchronizedChart(self.filteredData, self.measures, self.dimensions, 
//	self.deleteDuplecateData(self.filteredData,self.measures[0]));
//	}

//	d3.selectAll('rect.box[filter="true"]').style('stroke-width', 2.5)
//	gProgressbar.hide();
//	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		var dupledatacheck
		if(typeof self.resizeData != 'undefined'){
			dupledatacheck = self.resizeData;
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
			WISE.loadedSourceCheck('d3');
			self.fSynchronizedChart(self.filteredData, self.measures, self.dimensions, 
					dupledatacheck);
			//		self.fParallelCoordinates2(self.filteredData, self.measures, self.dimensions, 
			//							self.deleteDuplecateData(self.filteredData,self.measures[0]));
			d3.selectAll('#' + self.itemid + ' .point[filter="true"]').style("display", 'block').attr("filter", "true");
		}

		gProgressbar.hide();
	};

	this.fSynchronizedChart = function(jsonData, measures, dimensions, dupleData) {
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;

		self.resizeData = dupleData;
		
		var dimensionNm = [];
		$.each(dupleData, function(i, data){
			if($.inArray(data['dimension'], dimensionNm) === -1) dimensionNm.push(data['dimension']);
		})

		self.paletteData = [];
		$.each(self.measures, function(i, _mea){
			self.paletteData.push(_mea.caption);
		})

		$('#'+self.itemid+ ' svg').remove();

		var svgWidth = $('#'+self.itemid).width(), svgHeight = $('#'+self.itemid).height();
		var margin = { top: 30, right: 30, bottom: 30, left: 130 };

		var minHeight = 150;
		var height = svgHeight;

		if(svgHeight > self.measures.length * minHeight){
			height = svgHeight / self.measures.length;
			$('#'+self.itemid).css("overflow-y", "hidden");
		} else{
			height = minHeight;
			svgHeight = minHeight * self.measures.length;
			$('#'+self.itemid).css("overflow-y", "auto");
		}

		var wrapper = d3.select("#"+self.itemid).append("svg").classed("syncchart", true).attr("width", svgWidth).attr("height", svgHeight).append("g");
		var palette = gDashboard.d3Manager.getPalette(self);
		var charts = [];
		$.each(self.measures, function(i, _mea){
			charts.push(renderChart(dupleData, _mea, svgWidth - margin.left - margin.right, height - margin.top - margin.bottom, {left : margin.left, top: height * i}, palette[i % palette.length]));
		})
		wrapper.append("rect")
		.attr("class", "overlay")
		.attr("width", svgWidth)
		.attr("height", svgHeight).style("fill", "none").style("pointer-event", "all")
		.on("mouseover", function() { d3.selectAll('#'+self.itemid + ' .focus').style("display", null); d3.selectAll('#'+self.itemid + ' .sync-value').style("display", null);  })
		.on("mouseout", function() {  d3.selectAll('#'+self.itemid + ' .focus').style("display", "none"); d3.selectAll('#'+self.itemid + ' .sync-value').style("display", "none");})
		.on("mousemove", mousemove).on("click", mouseclick);

		function mousemove() {
			var _this = this;
			$.each(charts, function(i, chart){
				var x = chart.x, y = chart.y, focus = chart.focus, tooltip = chart.tooltip;
				x.invert = (function(){
					var domain = x.domain()
					var range = x.range()
					var scale = d3.scaleQuantize().domain(range).range(domain)

					return function(x){
						return scale(x)
					}
				})()

//				bisectDate = d3.bisector(function(d) { return d.dimension; }).left;
				var x0 = x.invert(d3.mouse(_this)[0] - margin.left),
				i = dupleData.findIndex(function(d){return x0 == d.dimension})
//				d0 = dupleData[i - 1],
//				d1 = dupleData[i],
//				d = x0 - d0.date > d1.date - x0 ? d1 : d0;
				d = dupleData[i]
				focus.attr("transform", "translate(" + x(d.dimension) + "," + y(d[chart.measure.caption]) + ")");
				tooltip.text(d[chart.measure.caption]);
//				tooltip.attr("style", "left:" + (x(d.date) + 64) + "px;top:" + y(d.likes) + "px;");
//				tooltip.select(".tooltip-date").text(dateFormatter(d.date));
//				tooltip.select(".tooltip-likes").text(formatValue(d.likes));
			})
		}

		function mouseclick(){
			var _this = this;
			var x = charts[0].x;
			x.invert = (function(){
				var domain = x.domain()
				var range = x.range()
				var scale = d3.scaleQuantize().domain(range).range(domain)

				return function(x){
					return scale(x)
				}
			})()
			var x0 = x.invert(d3.mouse(_this)[0] - margin.left);
			var select = d3.select('#' + self.itemid + ' ._'+x0.replace(/(\s*)/g, ""));
			var selectPoint = d3.selectAll('#' + self.itemid + ' ._'+x0.replace(/(\s*)/g, ""));
			switch(self.meta.InteractivityOptions.MasterFilterMode){
				case 'Single':
					self.trackingData = [];
					self.tempTrackingData = [];
					if(select.attr("filter") === "true"){
						selectPoint.style("display", "none").attr("filter", "false");
					}else{
						//선택 모두 해제
						d3.selectAll('#' + self.itemid + ' .point').style("display", "none").attr("filter", "false");

						selectPoint.style("display", "block").attr("filter", "true");

						//	       				var selectedData = {};
						//		       			selectedData[self.dimensions[0].name] = d.data[0];
						var tempSelectedData = {};
						$.each(self.dimensions, function(i, dim){
							var selectedData = {};
							selectedData[dim.caption] = d.dimension.split(" - ")[i]
							tempSelectedData[dim.caption] = d.dimension.split(" - ")[i]
							self.trackingData.push(selectedData);
						})

						self.tempTrackingData.push(tempSelectedData);
					}
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
				case 'Multiple':
					if(select.attr("filter") === "true"){
						selectPoint.style("display", "none").attr("filter", "false");
						for (var index = 0; index < self.tempTrackingData.length; index++) {
							var check = 0;
							$.each(self.dimensions, function(i, dim){
								if(self.tempTrackingData[index][dim.caption] === d.dimension.split(" - ")[i])
									check++;
							})
							if(check === self.dimensions.length){
								self.tempTrackingData.splice(index, 1);
								index--;
							}
						} 
					}else{
						selectPoint.style("display", "block").attr("filter", "true");
						tempSelectedData = {}
						$.each(self.dimensions, function(i, dim){
							tempSelectedData[dim.caption] = d.dimension.split(" - ")[i]
						})
						self.tempTrackingData.push(tempSelectedData);
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
		}
		
		function tickFormat(n, format) {
			if(format){
				return WISE.util.Number.unit(n, format.FormatType, format.Unit, format.Precision, format.Separator, undefined, format.MeasureFormat, format.SuffixEnabled);	
			}
		}

		function renderChart(data, measure, width, height, position, color){
			var x = d3.scalePoint()
			.rangeRound([0, width]).domain(dimensionNm);

			var y = d3.scaleLinear()
			.range([height, 0]).domain(d3.extent(data, function(d) { return d[measure.caption]; }));

			var xAxis = d3.svg.axis()
			.scale(x)
			.orient("bottom")

			var yAxis = d3.svg.axis()
			.scale(y)
			.orient("left")

			var line = d3.svg.line()
			.x(function(d) { return x(d["dimension"]); })
			.y(function(d) { return y(d[measure.caption]); });

			var svg = wrapper.append("svg").attr("y", position.top )
			.attr("width", width + margin.left + margin.right)
			.attr("height", height + margin.top + margin.bottom)
			.attr("y", position.top)
			.append("g")
			.attr("transform", "translate(" + position.left + "," + (margin.top) + ")");
			
			function make_y_gridlines() {
				return d3.axisLeft(y)
				.ticks(5)
			}
			svg.append("g")
			.attr("class","sync-grid")
			.style("stroke-dasharray",("3,0"))
			.call(make_y_gridlines()
					.tickSize(-width)
					.tickFormat("")
			)
			d3.selectAll('.sync-grid line').attr("stroke", "lightgray").style("shape-rendering", "crispEdges")

			d3.selectAll('.sync-grid .domain').style("display", "none");


			svg.append("g")
			.attr("class", "x axis")
			.attr("transform", "translate(0," + height + ")")
			.call(d3.axisBottom(x));

			svg.append("g")
			.attr("class", "y axis")
			.call(d3.axisLeft(y).ticks(5).tickFormat(function(d) { return tickFormat(d, self.meta.AxisY); }))
			.append("text")
//			.attr("transform", "rotate(-90)")
			.attr("y", 6)
			.attr("x", 10)
			.attr("dy", ".71em")
			.style("text-anchor", "start")
			.text(measure.caption).style("font-family", self.meta.LayoutOption.Title.family)
			.style("font-size", self.meta.LayoutOption.Title.size+'px')
			.style("fill", self.meta.LayoutOption.Title.color);

			svg.append("path")
			.datum(data)
			.attr("class", "line")
			.attr("d", line).style("stroke", color).style("stroke-width", 2.5);

			svg.append('g')
				.selectAll("dot")
				.data(data)
				.enter()
				.append("circle")
				.style("fill", color)
				.style("stroke-width", 2)
				.style("stroke", "white")
				.attr("r", 6)
				.attr("cx", function (d) { return x(d.dimension); } )
				.attr("cy", function (d) { return y(d[measure.caption]); })
				.attr("class", function(d){ return '_'+d.dimension.replace(/(\s*)/g, "")+" point"})
				.style("display", "none")
				.attr("filter", function(d){
					for (var index = 0; index < self.tempTrackingData.length; index++) {
						var check = 0;
						$.each(self.dimensions, function(i, dim){
							if(self.tempTrackingData[index][dim.caption] === d.dimension.split(" - ")[i])
								check++;
						})
						if(check === self.dimensions.length){
							return "true";
						}
					}
					return "false";
				})

			var tooltip = svg.append("text").attr("y", 10).attr("x", width).style("text-anchor", "end").classed("sync-value", true)
				.style("font-family", self.meta.LayoutOption.Label.family)
				.style("font-size", self.meta.LayoutOption.Label.size+'px')
				.style("fill", self.meta.LayoutOption.Label.color);

			var focus = svg.append("g")
			.attr("class", "focus")
			.style("display", "none");

			focus.append("circle")
			.style("fill", color)
			.style("stroke-width", 2)
			.style("stroke", "white")
			.attr("r", 5);
			
			d3.selectAll('.syncchart path').style("fill", "none")

			return {x: x, y: y, focus: focus, measure: measure, tooltip: tooltip};
		}

		d3.selectAll('#'+ self.itemid +" .y .tick text")
		.style("font-family", self.meta.LayoutOption.AxisY.family)
		.style("font-size", self.meta.LayoutOption.AxisY.size+'px')
		.style("fill", self.meta.LayoutOption.AxisY.color)


		d3.selectAll('#'+ self.itemid +" .x .tick text")
		.style("font-family", self.meta.LayoutOption.AxisX.family)
		.style("font-size", self.meta.LayoutOption.AxisX.size+'px')
		.style("fill", self.meta.LayoutOption.AxisX.color)

		
		if(!self.meta.AxisX.Overlapping){
			$('#'+self.itemid).css("display", "block");
			d3.selectAll('#'+ self.itemid +" .x").each(function(){
				var prevX;
				d3.select(this).selectAll('.tick').each(function(){
					var currX = d3.select(this).attr("transform").substring(10, d3.select(this).attr("transform").indexOf(','))*1;
					if(typeof prevX === 'undefined'){
						prevX = currX + d3.select(this).select('text').node().getComputedTextLength() / 2;
					}else{
						var textSize = d3.select(this).select('text').node().getComputedTextLength();

						if(currX - textSize / 2 < prevX){
							d3.select(this).select('text').style('display', 'none');
						}else{
							prevX = currX + textSize / 2;
						}
					}
				})
			})
		}

	};

	function checkingItem(_data) {
		return !_data.items.length;
	};

	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
};


WISE.libs.Dashboard.SynchronizedChartFieldManager = function() {
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
