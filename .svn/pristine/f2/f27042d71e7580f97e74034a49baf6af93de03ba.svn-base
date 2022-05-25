WISE.libs.Dashboard.item.BoxPlotGenerator = function() {
	var self = this;

	this.type = 'BOX_PLOT';

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
	
	this.BoxPlot = [];
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
	
	this.setBoxPlot = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.BoxPlot['ComponentName'] = this.ComponentName;
		this.BoxPlot['Name'] = this.Name;
		this.BoxPlot['DataSource'] = this.dataSourceId;
		
		this.BoxPlot['DataItems'] = this.fieldManager.DataItems;
		this.BoxPlot['Arguments'] = this.fieldManager.Arguments;
		this.BoxPlot['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.BoxPlot;
		
		if (!(this.BoxPlot['Palette'])) {
			this.BoxPlot['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.BoxPlot.InteractivityOptions) {
			if (!(this.BoxPlot.InteractivityOptions.MasterFilterMode)) {
				this.BoxPlot.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BoxPlot.InteractivityOptions.TargetDimensions)) {
				this.BoxPlot.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BoxPlot.InteractivityOptions.IgnoreMasterFilters)) {
				this.BoxPlot.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BoxPlot.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.BoxPlot.AxisY)) {
			this.BoxPlot.AxisY = {
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
		
		if (!(this.BoxPlot.AxisX)) {
			this.BoxPlot.AxisX = {
				Overlapping: false
			};
		}
		
		if (!(this.BoxPlot.ExpandOption)) {
			this.BoxPlot.ExpandOption = {
				LabelOverlapping: false
			};
		}
		
		if (!(this.BoxPlot['Legend'])) {
			this.BoxPlot['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.BoxPlot.LayoutOption){
			this.BoxPlot.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
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
					Title: {
						family: '맑은 고딕',
						color: '#000000',
						size: 18
					},
					Label: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		
		if(!this.BoxPlot['ZoomAble']){
			this.BoxPlot.ZoomAble = 'none'
		}
		
	};
	
	this.setBoxPlotforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setBoxPlot();
		}
		else{
			this.BoxPlot = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.BoxPlot['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.BoxPlot['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.BoxPlot['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.BoxPlot['Palette'])) {
			this.BoxPlot['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BoxPlotOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BOX_PLOT_DATA_ELEMENT);
				
				$.each(BoxPlotOption,function(_i,_BoxPlotOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _BoxPlotOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _BoxPlotOption.CTRL_NM;
					}
					if(self.BoxPlot.ComponentName == CtrlNM){
						self.BoxPlot['Palette'] = _BoxPlotOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BoxPlot.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BoxPlot.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (!(this.BoxPlot.AxisY)) {
			this.BoxPlot.AxisY = {
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
		if (!(this.BoxPlot.AxisX)) {
			this.BoxPlot.AxisX = {
				Overlapping: false
			};
		}
		
		if (!(this.BoxPlot.ExpandOption)) {
			this.BoxPlot.ExpandOption = {
				LabelOverlapping: false
			};
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.BoxPlot.InteractivityOptions) {
			if (!(this.BoxPlot.InteractivityOptions.MasterFilterMode)) {
				this.BoxPlot.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BoxPlot.InteractivityOptions.TargetDimensions)) {
				this.BoxPlot.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BoxPlot.InteractivityOptions.IgnoreMasterFilters)) {
				this.BoxPlot.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BoxPlot.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.BoxPlot['Legend'])) {
			this.BoxPlot['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.BoxPlot.LayoutOption){
			this.BoxPlot.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
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
					Title: {
						family: '맑은 고딕',
						color: '#000000',
						size: 18
					},
					Label: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		if(!this.BoxPlot['ZoomAble']){
			this.BoxPlot.ZoomAble = 'none'
		}
		
	}
	
	this.setBoxPlotForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setBoxPlot();
		}
		else{
			this.BoxPlot = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.BoxPlot['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.BoxPlot['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.BoxPlot['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.BoxPlot['Palette'])) {
			this.BoxPlot['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var BoxPlotOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.BOX_PLOT_DATA_ELEMENT);
				
				$.each(BoxPlotOption,function(_i,_BoxPlotOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _BoxPlotOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _BoxPlotOption.CTRL_NM;
//					}
					if(self.BoxPlot.ComponentName == CtrlNM){
						self.BoxPlot['Palette'] = _BoxPlotOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.BoxPlot.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.BoxPlot.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		if (!(this.BoxPlot.AxisY)) {
			this.BoxPlot.AxisY = {
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
		if (!(this.BoxPlot.AxisX)) {
			this.BoxPlot.AxisX = {
				Overlapping: false
			};
		}
		
		if (!(this.BoxPlot.ExpandOption)) {
			this.BoxPlot.ExpandOption = {
				LabelOverlapping: false
			};
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.BoxPlot.InteractivityOptions) {
			if (!(this.BoxPlot.InteractivityOptions.MasterFilterMode)) {
				this.BoxPlot.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.BoxPlot.InteractivityOptions.TargetDimensions)) {
				this.BoxPlot.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.BoxPlot.InteractivityOptions.IgnoreMasterFilters)) {
				this.BoxPlot.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.BoxPlot.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.BoxPlot['Legend'])) {
			this.BoxPlot['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.BoxPlot.LayoutOption){
			this.BoxPlot.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
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
					Title: {
						family: '맑은 고딕',
						color: '#000000',
						size: 18
					},
					Label: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		if(!this.BoxPlot['ZoomAble']){
			this.BoxPlot.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setBoxPlot();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.BoxPlot);
			gDashboard.itemGenerateManager.generateItem(self, self.BoxPlot);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setBoxPlotforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.BoxPlot);
			gDashboard.itemGenerateManager.generateItem(self, self.BoxPlot);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.BoxPlot)) {
			this.setBoxPlotForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.BoxPlot);
			gDashboard.itemGenerateManager.generateItem(self, self.BoxPlot);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setBoxPlotForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.BoxPlot);
			gDashboard.itemGenerateManager.generateItem(self, self.BoxPlot);
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
//		if(!self.currentMeasureName || self.currentMeasureName === "" || !measureCheck)
//			self.currentMeasureName = measureKey.caption;
    	
		self.currentMeasureName = measureKey.caption;
		self.trackingData = [];
		self.tempTrackingData = [];

		//2020.11.03 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('d3');
		self.fBoxPlot(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		
		//2021.04.16 syjin 박스플롯 불러오기 or 처음 조회시 아이템 안보이는 오류 수정 dogfoot
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
				d3.selectAll('#' + self.itemid + ' rect.box').style('stroke-width', '').attr("filter", "false");
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
//		if(self.filteredData){
//			self.fBoxPlot(self.filteredData, self.measures, self.dimensions, 
//					self.deleteDuplecateData(self.filteredData,self.measures[0]));
//		}
//		
//		d3.selectAll('rect.box[filter="true"]').style('stroke-width', 2.5)
//		gProgressbar.hide();
//	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		var dupledatacehck
		if(typeof self.resizeData != 'undefined'){
		    dupledatacehck = self.resizeData;
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
		    self.fBoxPlot(self.filteredData, self.measures, self.dimensions, 
		    		dupledatacehck);
	//		self.fParallelCoordinates2(self.filteredData, self.measures, self.dimensions, 
	//							self.deleteDuplecateData(self.filteredData,self.measures[0]));
		    d3.selectAll('#' + self.itemid + ' rect.box[filter="true"]').style('stroke-width', 2.5)
		}
		
		gProgressbar.hide();
	};
	
	var box = function() {
		  var width = 1,
		      height = 1,
		      duration = 0,
		      domain = null,
		      value = Number,
		      whiskers = boxWhiskers,
		      quartiles = boxQuartiles,
			  showLabels = true, // whether or not to show text labels
			  numBars = 4,
			  curBar = 1,
		      tickFormat = null;

		  // For each small multiple…
		  function box(g) {
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
					if(self.currentMeasureName ===  _val.Name){
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
				
		    g.each(function(data, i) {
		      //d = d.map(value).sort(d3.ascending);
			  //var boxIndex = data[0];
			  //var boxIndex = 1;
			  var d = data[1].sort(d3.ascending);
			  
			 // console.log(boxIndex); 
			  //console.log(d); 
			  
		      var g = d3.select(this),
		          n = d.length,
		          min = d[0],
		          max = d[n - 1];

		      // Compute quartiles. Must return exactly 3 elements.
		      var quartileData = d.quartiles = quartiles(d);

		      // Compute whiskers. Must return exactly 2 elements, or null.
		      var whiskerIndices = whiskers && whiskers.call(this, d, i),
		          whiskerData = whiskerIndices && whiskerIndices.map(function(i) { return d[i]; });

		      // Compute outliers. If no whiskers are specified, all data are "outliers".
		      // We compute the outliers as indices, so that we can join across transitions!
		      var outlierIndices = whiskerIndices
		          ? d3.range(0, whiskerIndices[0]).concat(d3.range(whiskerIndices[1] + 1, n))
		          : d3.range(n);

		      // Compute the new x-scale.
		      var x1 = d3.scale.linear()
		          .domain(domain && domain.call(this, d, i) || [min, max])
		          .range([height, 0]);

		      // Retrieve the old x-scale, if this is an update.
		      var x0 = this.__chart__ || d3.scale.linear()
		          .domain([0, Infinity])
				 // .domain([0, max])
		          .range(x1.range());

		      // Stash the new scale.
		      this.__chart__ = x1;

		      // Note: the box, median, and box tick elements are fixed in number,
		      // so we only have to handle enter and update. In contrast, the outliers
		      // and other elements are variable, so we need to exit them! Variable
		      // elements also fade in and out.

		      // Update center line: the vertical line spanning the whiskers.
		      var center = g.selectAll("line.center")
		          .data(whiskerData ? [whiskerData] : []);

			 //vertical line
		      center.enter().insert("line", "rect").attr("cursor", "pointer")
		          .attr("class", "center")
		          .attr("x1", width / 2)
		          .attr("y1", function(d) { return x0(d[0]); })
		          .attr("x2", width / 2)
		          .attr("y2", function(d) { return x0(d[1]); })
		          .style("opacity", 1e-6)
		        .transition()
		          .duration(duration)
		          .style("opacity", 1)
		          .attr("y1", function(d) { return x1(d[0]); })
		          .attr("y2", function(d) { return x1(d[1]); });

		      center.transition()
		          .duration(duration)
		          .style("opacity", 1)
		          .attr("y1", function(d) { return x1(d[0]); })
		          .attr("y2", function(d) { return x1(d[1]); });

		      center.exit().transition()
		          .duration(duration)
		          .style("opacity", 1e-6)
		          .attr("y1", function(d) { return x1(d[0]); })
		          .attr("y2", function(d) { return x1(d[1]); })
		          .remove();

		      // Update innerquartile box.
		      var box = g.selectAll("rect.box")
		          .data([quartileData]);

		      var palette = gDashboard.d3Manager.getPalette(self);
		      var myColor = d3.scaleOrdinal().domain(self.paletteData).range(palette);
		      
		      box.enter().append("rect")
		          .attr("class", "box")
		          .attr("x", 0)
		          .attr("y", function(d) { return x0(d[2]); })
		          .style("fill", myColor(data[0]))
		          .attr("filter", function(d){ if(self.trackingData){
			    	  for (var index = 0; index < self.tempTrackingData.length; index++) {
			    			var check = 0;
		       				$.each(self.dimensions, function(i, dim){
		       					if(self.tempTrackingData[index][dim.caption] === data[0].split(' - ')[i])
		       						check++;
		       				})
		       				if(check === self.dimensions.length){
		       					return "true"
		       				}
		       			}
			    	  return "false"
			      }else return "false"})
  		          .on("click", function(d){
//  		        	d3.select(this).style('stroke-width', '2.5').attr("filter", "true");
//  		        	d3.selectAll('rect.box').style('stroke-width', '').attr("filter", "false");
//		        	  d3.select('rect.box').style('stroke-width', '2.5')
  		        	
  		        	switch(self.meta.InteractivityOptions.MasterFilterMode){
			    		case 'Single':
			    			self.trackingData = [];
			    			if(d3.select(this).attr("filter") === "true"){
			    				d3.selectAll('#' + self.itemid + ' rect.box').style('stroke-width', '').attr("filter", "false");
					    	}else{
					    		//선택 모두 해제
					    		d3.selectAll('#' + self.itemid + ' rect.box').style('stroke-width', '').attr("filter", "false");
								
					    		d3.select(this).style('stroke-width', '2.5').attr("filter", "true");
					    		
//			       				var selectedData = {};
//				       			selectedData[self.DI.Dimension[0].DataMember] = data[0];
//					    		
//				       			self.trackingData.push(selectedData);
					    		
					    		var _s = {};
				       			$.each(self.dimensions, function(i, dim){
				       				var selectedData = {};
					    			selectedData[dim.caption] = data[0].split(' - ')[i];
					    			_s[dim.caption] = data[0].split(' - ')[i];
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
					    		d3.select(this).style('stroke-width', '').attr("filter", "false");
//					    		var inArray = false;
//					    		for (var index = 0; index < self.trackingData.length; index++) {
//			       					if(self.trackingData[index][self.DI.Dimension[0].DataMember] === data[0]){
//			       						self.trackingData.splice(index, 1);
//				       					index--;
//				       					break;
//			       					}
//				       			}
					    		
					    		for (var index = 0; index < self.tempTrackingData.length; index++) {
					    			var check = 0;
				       				$.each(self.dimensions, function(i, dim){
				       					if(self.tempTrackingData[index][dim.caption] === data[0].split(' - ')[i])
				       						check++;
				       				})
				       				if(check === self.dimensions.length){
				       					self.tempTrackingData.splice(index, 1);
				       					index--;
				       				}
				       			}
					    	}else{
					    		d3.select(this).style('stroke-width', '2.5').attr("filter", "true");
//					    		var selectedData = {};
//				    			selectedData[self.DI.Dimension[0].DataMember] = data[0]
//					    		self.trackingData.push(selectedData);
					    		
					    		var selectedData = {};
					    		$.each(self.dimensions, function(i, dim){
					    			selectedData[dim.name] = data[0].split(' - ')[i]
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
		          .attr("width", width)
		          .attr("height", function(d) { return x0(d[0]) - x0(d[2]); })
		        .transition()
		          .duration(duration)
		          .attr("y", function(d) { return x1(d[2]); })
		          .attr("height", function(d) { return x1(d[0]) - x1(d[2]); })

		      box.transition()
		          .duration(duration)
		          .attr("y", function(d) { return x1(d[2]); })
		          .attr("height", function(d) { return x1(d[0]) - x1(d[2]); });

		      // Update median line.
		      var medianLine = g.selectAll("line.median")
		          .data([quartileData[1]]);

		      medianLine.enter().append("line")
		          .attr("class", "median")
		          .attr("x1", 0)
		          .attr("y1", x0)
		          .attr("x2", width)
		          .attr("y2", x0)
		        .transition()
		          .duration(duration)
		          .attr("y1", x1)
		          .attr("y2", x1);

		      medianLine.transition()
		          .duration(duration)
		          .attr("y1", x1)
		          .attr("y2", x1);

		      // Update whiskers.
		      var whisker = g.selectAll("line.whisker")
		          .data(whiskerData || []);

		      whisker.enter().insert("line", "circle, text")
		          .attr("class", "whisker")
		          .attr("x1", 0)
		          .attr("y1", x0)
		          .attr("x2", 0 + width)
		          .attr("y2", x0)
		          .style("opacity", 1e-6)
		        .transition()
		          .duration(duration)
		          .attr("y1", x1)
		          .attr("y2", x1)
		          .style("opacity", 1);

		      whisker.transition()
		          .duration(duration)
		          .attr("y1", x1)
		          .attr("y2", x1)
		          .style("opacity", 1);

		      whisker.exit().transition()
		          .duration(duration)
		          .attr("y1", x1)
		          .attr("y2", x1)
		          .style("opacity", 1e-6)
		          .remove();

		      // Update outliers.
		      var outlier = g.selectAll("circle.outlier")
		          .data(outlierIndices);

		      outlier.enter().insert("circle", "text")
		      .attr("class", "outlier")
		      .attr("r", 5)
		      .attr("cx", width / 2)
		      .attr("cy", function(i) { return x0(d[i]); })
		      .style("opacity", 1e-6)
		      .transition()
		      .duration(duration)
		      .attr("cy", function(i) { return x1(d[i]); })
		      .style("opacity", 1);

		      outlier.transition()
		      .duration(duration)
		      .attr("cy", function(i) { return x1(d[i]); })
		      .style("opacity", 1);

		      outlier.exit().transition()
		      .duration(duration)
		      .attr("cy", function(i) { return x1(d[i]); })
		      .style("opacity", 1e-6)
		      .remove();

		      // Compute the tick format.
//		      var format = tickFormat || x1.tickFormat(8);
		      var format = function(d){
		    	  return WISE.util.Number.unit(d, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
		      }

		      // Update box ticks.
		      var boxTick = g.selectAll("text.box")
		      .data(quartileData);

		      var transform = g.attr("transform");
		      transform = transform.replace("translate(", "");
		      transform = transform.replace(")", "");
		      transform = transform.split(",");
		      var x = transform[0] * 1;
		      var y = transform[1] * 1;

		      var margin = $('#' + self.itemid + ' g').attr("transform");
		      margin = margin.replace("translate(", "");
		      margin = margin.replace(")", "");
		      margin = margin.split(",");
		      //dogfoot 박스플롯 줌인 줌 아웃 텍스트는 적용이 안되었던 오류 수정 20210412 syjin
		      var marginX = margin[0] * 0;

		      if(showLabels == true) {
		    	  var marginY = margin[1] * 0;
//		    	  boxTick.enter()
		    	      	  
		    	  $.each(quartileData, function(i, d){
		    		  //dogfoot 박스플롯 줌인 줌 아웃 텍스트는 적용이 안되었던 오류 수정 20210412 syjin
		    		  d3.select('#'+self.itemid+' svg>g').append("text")
		    		  //d3.select("#"+self.itemid).append("text")
		    		  .attr("class", "box box-label")
		    		  .attr("dy", ".3em")
		    		  .attr("dx", function() { return (i & 1 ? 6 : -6) })
		    		  .attr("x", function() { return (i & 1 ?  + width : 0) + x + marginX})
		    		  .attr("y", function() {return  (x0(d)? x0(d):0) + y})
		    		  .attr("text-anchor", function() { return i & 1 ? "start" : "end"; })
		    		  .text(function(){ return format(d) }).attr("font-family", self.meta.LayoutOption.Label.family)
		    		  .attr("font-size", self.meta.LayoutOption.Label.family)
		    		  .style("fill", self.meta.LayoutOption.Label.color)
		    		  .transition()
		    		  .duration(duration)
		    		  .attr("y", function() {return (x1(d)? x1(d):0) + y + marginY});
		    	  })
		      }

		      boxTick.transition()
		      .duration(duration)
		      .text(format)
		      .attr("y", x1);

		      // Update whisker ticks. These are handled separately from the box
		      // ticks because they may or may not exist, and we want don't want
		      // to join box ticks pre-transition with whisker ticks post-.
		      var whiskerTick = g.selectAll("text.whisker")
		      .data(whiskerData || []);
		      if(showLabels == true) {
		    	  
		    	  $.each(whiskerData || [], function(i, d){
		    		  //dogfoot 박스플롯 줌인 줌 아웃 텍스트는 적용이 안되었던 오류 수정 20210412 syjin
		    		  d3.select('#'+self.itemid+' svg>g').append("text")
		    		  .attr("class", "whisker box-label")
		    		  .attr("dy", ".3em")
		    		  .attr("dx", 6)
		    		  .attr("x", width + x + marginX)
		    		  .attr("y", function(){ return  (x0(d)? x0(d):0) + y + marginY})
		    		  .text(function() { return format(d)})
		    		  .style("opacity", 1e-6)
		    		  .transition()
		    		  .duration(duration)
		    		  .attr("y", function(){ return  (x1(d)? x1(d):0) + y + marginY})
		    		  .style("opacity", 1);
		    	  })


		      }
		      whiskerTick.transition()
		      .duration(duration)
		      .text(format)
		      .attr("y", x1)
		      .style("opacity", 1);

		      whiskerTick.exit().transition()
		      .duration(duration)
		      .attr("y", x1)
		      .style("opacity", 1e-6)
		      .remove();
		    });
		  }

		  box.width = function(x) {
		    if (!arguments.length) return width;
		    width = x;
		    return box;
		  };

		  box.height = function(x) {
		    if (!arguments.length) return height;
		    height = x;
		    return box;
		  };

		  box.tickFormat = function(x) {
		    if (!arguments.length) return tickFormat;
		    tickFormat = x;
		    return box;
		  };

		  box.duration = function(x) {
		    if (!arguments.length) return duration;
		    duration = x;
		    return box;
		  };

		  box.domain = function(x) {
		    if (!arguments.length) return domain;
		    domain = x == null ? x : d3.functor(x);
		    return box;
		  };

		  box.value = function(x) {
		    if (!arguments.length) return value;
		    value = x;
		    return box;
		  };

		  box.whiskers = function(x) {
		    if (!arguments.length) return whiskers;
		    whiskers = x;
		    return box;
		  };
		  
		  box.showLabels = function(x) {
		    if (!arguments.length) return showLabels;
		    showLabels = x;
		    return box;
		  };

		  box.quartiles = function(x) {
		    if (!arguments.length) return quartiles;
		    quartiles = x;
		    return box;
		  };

		  return box;
		};

		function boxWhiskers(d) {
		  return [0, d.length - 1];
		}

		function boxQuartiles(d) {
			var q1, q3;

			function getMedian(_d){
				var check = _d.length % 2 === 0;
				if(check){
					return {
						result : (_d[_d.length / 2] * 1 + _d[_d.length / 2 - 1] * 1) / 2,
						check : true,
						index : _d.length / 2
					}
				}
				else{
					return {
						result : (_d[Math.round(_d.length / 2) - 1] * 1),
						check : false,
						index : Math.round(_d.length / 2) - 1
					}
				}
			}



			var median = getMedian(d);

			if(median.check){
				q1 = getMedian(d.slice(0, median.index));
				q3 = getMedian(d.slice(median.index));
			}else{
				q1 = getMedian(d.slice(0, median.index));
				q3 = getMedian(d.slice(median.index + 1));
			}


			return [
				q1.result,
				median.result,
				q3.result
				];
//			return [
//	d3.quantile(d, .25),
//d3.quantile(d, .5),
//d3.quantile(d, .75)
//];
		}
	
	this.fBoxPlot = function(jsonData, measures, dimensions, dupleData) {
		var labels = true; // show the text labels beside individual boxplots?

		if(!dupleData || dupleData.result.length <= 1 && ((dupleData.result && dupleData.result[0][1].length <= 1) || !dupleData.result)) {
			WISE.alert("박스 플롯은 두개 이상의 데이터가 필요합니다.");
			dupleData = null;
		}
		self.resizeData = dupleData;
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		
		$('#'+self.itemid+ ' svg').remove();
		var margin = {top: 30, right: 0, bottom: 30, left: 120};
		if(self.meta.Legend.Visible){
			if(self.meta.Legend.Position === "TopRightVertical"){
				margin.right = 150;
			}else if(self.meta.Legend.Position === 'TopLeftVertical'){
				margin.left = 250;
			}else if(self.meta.Legend.Position === 'TopCenterHorizontal'){
				margin.top = 50;
			}else{
				margin.bottom = 50;
			}
		}
		var svgWidth = $('#'+self.itemid).width();
		var svgHeight = $('#'+self.itemid).height();
		var  width = svgWidth - margin.left - margin.right;
		var height = svgHeight - margin.top - margin.bottom - 50;
			
		var min = Infinity,
		    max = -Infinity;
		
		var chart = box()
		.whiskers(iqr(1.5))
		.height(height)	
		.domain([min, max])
		.showLabels(labels);
		
//		var csv = [{"Q1": 20000, "Q2" : 15000, "Q3": 8000, "Q4" : 20000},
//			{"Q1": 2879, "Q2" : 9323, "Q3": 3294, "Q4" : 5629},
//			{"Q1": 5070, "Q2" : 9395, "Q3": 17633, "Q4" : 5752},
//			{"Q1": 7343, "Q2" : 8675, "Q3": 12121, "Q4" : 7557},
//			{"Q1": 9136, "Q2" : 5354, "Q3": 4319, "Q4" : 5152},
//			{"Q1": 7943, "Q2" : 6725, "Q3": 18712, "Q4" : 5116},
//			{"Q1": 10546, "Q2" : 10899, "Q3": 17270, "Q4" : 5828},
//			{"Q1": 9385, "Q2" : 9365, "Q3": 13676, "Q4" : 6014},
//			{"Q1": 8669, "Q2" : 8238, "Q3": 6587, "Q4" : 5995},
//			{"Q1": 4000, "Q2" : 7446, "Q3": 16754, "Q4" : 8905},
//		]
		
//		var data = [];
//		data[0] = [];
//		data[1] = [];
//		data[2] = [];
//		data[3] = [];
//		// add more rows if your csv file has more columns
//
//		// add here the header of the csv file
//		data[0][0] = "Q1";
//		data[1][0] = "Q2";
//		data[2][0] = "Q3";
//		data[3][0] = "Q4";
//		// add more rows if your csv file has more columns
//
//		data[0][1] = [];
//		data[1][1] = [];
//		data[2][1] = [];
//		data[3][1] = [];
	  
//		csv.forEach(function(x) {
//			var v1 = Math.floor(x.Q1),
//				v2 = Math.floor(x.Q2),
//				v3 = Math.floor(x.Q3),
//				v4 = Math.floor(x.Q4);
//				// add more variables if your csv file has more columns
//				
//			var rowMax = Math.max(v1, Math.max(v2, Math.max(v3,v4)));
//			var rowMin = Math.min(v1, Math.min(v2, Math.min(v3,v4)));
//
//			data[0][1].push(v1);
//			data[1][1].push(v2);
//			data[2][1].push(v3);
//			data[3][1].push(v4);
//			 // add more rows if your csv file has more columns
//			 
//			if (rowMax > max) max = rowMax;
//			if (rowMin < min) min = rowMin;	
//		});
		
		min = dupleData.min;
		max = dupleData.max;
		
		data = _.cloneDeep(dupleData.result)
		var chart = box()
		.whiskers(iqr(1.5))
		.height(height)	
		.domain([min, max])
		.showLabels(labels);
        var zoomCnt = 0;
		function zoomable(){
			 var zoom = d3.zoom().on("zoom", function (d,zz) {
				 if(pressKey['z'] || pressKey['Z']){
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
							 return "translate(" + margin.left + "," + margin.top + ")";
						 }
						 if(d3.event.transform.x ===0 && d3.event.transform.y ===0){
							 d3.event.transform.x = d3.event.sourceEvent.layerX
							 d3.event.transform.y = d3.event.sourceEvent.layerY
						 }
						 zoomCnt++
						 return d3.event.transform;
					 })
// 					 d3.select('#'+self.itemid).select('svg>g:nth-child(2)').attr("transform", function(){ 
// 						 if(zoomCnt==0){
// 							 d3.event.transform.x = d3.event.sourceEvent.layerX
// 							 d3.event.transform.y = d3.event.sourceEvent.layerY
// 							 d3.event.transform.k =1;
// 						 }else{
// 						 	d3.event.transform.x -= margin.left;
// 							d3.event.transform.y -= margin.top;
// 						 }
// 						 if(d3.event.transform.k <= 1){
// 							 zoomCnt++;
// 							 d3.event.transform.x = 0;
// 							 d3.event.transform.y = 0;
// 							 d3.event.transform.k =1;
// 							 zoomable();
// 							 return "translate(" + 0 + "," + 0 + ")";
// 							// return "translate(" + margin.left + "," + margin.top + ")";
// 						 }
// 						 if(d3.event.transform.x ===0 && d3.event.transform.y ===0){
// 							 d3.event.transform.x = d3.event.sourceEvent.layerX;
// 							 d3.event.transform.y = d3.event.sourceEvent.layerY;
// 						 }
// 						 zoomCnt++
// 						 return d3.event.transform;
// 					 });
					 
				 }else{
						// Move scrollbars.
					  var wrapper = $('#'+self.itemid);
					  if(pressKey['Shift'] && wrapper.css('overflow-x') != 'hidden')
					      wrapper.scrollLeft(wrapper.scrollLeft() + d3.event.sourceEvent.deltaY);
					  else if(wrapper.css('overflow-y') != 'hidden')
                         wrapper.scrollTop(wrapper.scrollTop() + d3.event.sourceEvent.deltaY);
				 }
				 
			 })

			  d3.select('#'+self.itemid).select('svg').call(zoom)
		}
       
		
		var svg = d3.select("#" + self.itemid).append("svg")
			.attr("width", svgWidth)
			.attr("height", svgHeight)
			.attr("class", "box")   
			.append("g")
			.attr("transform", "translate(" + margin.left + "," + margin.top + ")");
		
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}

		var _data = data.map(function(d) { return d[0] } )
		_data.push("     ");
		_data.unshift(" ");
		// the x-axis
		var x = d3.scale.ordinal()	   
			.domain(_data)
			.rangeRoundBands([-50, width + 50], 0.7, 0.3);	
		var xAxis = d3.axisBottom()
			.scale(x);
//			.orient("bottom");
	
		function formatY(n) {
			n = Math.round(n);
			var result = n;
			if(self.BoxPlot.AxisY){
				var NumericY = self.meta.AxisY
				if(!NumericY.Visible){
					return '';
				}else{
				    return WISE.util.Number.unit(result, NumericY.FormatType, NumericY.Unit, NumericY.Precision, NumericY.Separator, undefined, NumericY.MeasureFormat, NumericY.SuffixEnabled);	
				}
		  	}
		}
		// the y-axis
		var y = d3.scaleLinear()
			.domain([min, max])
			.range([height + margin.top, 0 + margin.top]);
		
		var yAxis = d3.axisLeft().tickFormat(function(d) { return formatY(d); })
	    .scale(y)
//	    .orient("left");
	
		// draw the boxplots	
		svg.selectAll(".box")	   
	      .data(data)
		  .enter().append("g")
			.attr("transform", function(d) { return "translate(" +  (x(d[0]) - x.rangeBand()/2)  + "," + margin.top + ")"; } )
	      .call(chart.width(x.rangeBand())); 
		
		      
		// add a title
		svg.append("text")
	        .attr("x", (width / 2))             
	        .attr("y", 0 + (margin.top / 2))
	        .attr("text-anchor", "middle")  
	        .attr("font-size", self.meta.LayoutOption.Title.size * 1 + 2)
	        .attr("font-family", self.meta.LayoutOption.Title.family)
	        .style("fill", self.meta.LayoutOption.Title.color)
	        //.style("text-decoration", "underline")  
	        .text(self.currentMeasureName);
	 
		 // draw y axis
		svg.append("g")
	        .attr("class", "y axis")
	        .call(yAxis)
			.append("text") // and text1
//			  .attr("transform", "rotate(-90)")
			  .attr("y", 6)
			  .attr("dy", ".71em")
			  .style("text-anchor", "end")
			  .text(self.meta.AxisY.Title? self.meta.AxisY.Title : self.currentMeasureName)
			  .attr("font-size", self.meta.LayoutOption.AxisY.size * 1 + 2)
		      .attr("font-family", self.meta.LayoutOption.AxisY.family)
	      	  .style("fill", self.meta.LayoutOption.AxisY.color)
//			  .attr("style", gDashboard.fontManager.getCustomFontStringForItem(16))
//			  .style("font-family", gDashboard.fontManager.getFontFamily("Item"))
//		    	.style("font-size", gDashboard.fontManager.getFontSizeNumber(16, "Item"));		
		
		// draw x axis	
		svg.append("g")
	      .attr("class", "x axis")
	      .attr("transform", "translate(0," + (height  + margin.top + 10) + ")")
	      .call(xAxis)
		  .append("text")             // text label for the x axis
	        .attr("x", (width / 2) )
	        .attr("y",  10 )
			.attr("dy", ".71em")
	        .style("text-anchor", "middle")
	        	.attr("font-size", self.meta.LayoutOption.AxisX.size * 1 + 2)
		      .attr("font-family", self.meta.LayoutOption.AxisX.family)
	      	  .style("fill", self.meta.LayoutOption.AxisX.color)
		
        if(self.meta.Legend.Visible){
        	var size = 20
        	var xPos = width + 150;

        	if(self.meta.Legend.Position.indexOf("Bottom") > -1){
		    	xPos = height + 90;
		    }
		    else if(self.meta.Legend.Position === "TopLeftVertical"){
		    	xPos = 30
		    }else if(self.meta.Legend.Position.indexOf("Right") === -1){
		    	xPos = 10;
		    }

        	var colors = {};
        	var palette = gDashboard.d3Manager.getPalette(self);

        	for(var i = 0; i < self.paletteData.length; i++){
        		colors[self.paletteData[i]] = palette[i%palette.length];
        	}
        	if(self.meta.Legend.Position.indexOf("Center") > -1){
        		 var beforeLegend;
                 var beforeTranslateX;
                 var legendWidthArr = [];
                 var endIndex = -1;
        		// Add labels beside legend dots
        		$('#'+self.itemid).css('display', 'block')
        		d3.select("#"+self.itemid + ' svg').selectAll("mylabels")
        		.data(self.paletteData)
        		.enter()
        		.append("text")
        		.attr("y", xPos+ size*.8)
        		.style("fill", function(d){return colors[d]})
        		.text(function(d){return d})
        		.style("font-family", self.meta.LayoutOption.Legend.family)
        		.style("font-size", self.meta.LayoutOption.Legend.size+'px')
        		.attr("text-anchor", "left")
        		.style("alignment-baseline", "middle")
        		.attr("x", function(d,i){
                    var translateX, beforeLegendWidth;
        			
                    if(beforeLegend != undefined){

                        beforeLegendWidth = d3.select(beforeLegend).node().getComputedTextLength() + 30;
                        translateX = beforeTranslateX + beforeLegendWidth + 20/2;

                        if(translateX + d3.select(this).node().getComputedTextLength() > width){
                        	legendWidthArr.push(2000);
                    	if(endIndex === -1){
                    		endIndex = i;
                    		d3.select(this).text(". . .");
                    		return translateX;
                    	}
                    	
                    	return 2000;
                    }
                    }else{
                        beforeTranslateX = 40;
                        translateX = 40;
                    }
                    
                    beforeLegend = this;
                    beforeTranslateX = translateX;
                    legendWidthArr.push(translateX);
                    return translateX; 
        		})

			d3.select("#"+self.itemid + ' svg').selectAll("myrect")
        		.data(self.paletteData)
        		.enter()
        		.append("circle")
        		.attr("cx", function(d,i){return legendWidthArr[i] - 15})
        		.attr("cy", xPos+ size*.75)
        		.attr("r", 7)
        		.style("stroke", "none")
        		.style("fill", function(d){ return colors[d]})


        	}else{
//	        		d3.select("#"+self.itemid + ' svg').selectAll("myrect")
//	        		.data(self.paletteData.slice(0, 10))
//	        		.enter()
//	        		.append("circle")
//	        		.attr("cx", xPos)
//	        		.attr("cy", function(d,i){ return 40 + i*(size+5)})
//	        		.attr("r", 7)
//	        		.style("fill", function(d){ return colors[d]})

//	        		// Add labels beside legend dots
//	        		d3.select("#"+self.itemid + ' svg').selectAll("mylabels")
//	        		.data(self.paletteData.slice(0, 11))
//	        		.enter()
//	        		.append("text")
//	        		.attr("x", xPos+ size*.8)
//	        		.attr("y", function(d,i){ return 30 + i * (size + 5) + (size/2)})
//	        		.style("fill", function(d){ return self.paletteData.length > 10 && self.paletteData[10] === d ? 'black' : colors[d]})
//	        		.text(function(d){ return self.paletteData.length > 10 && self.paletteData[10] === d ? '. . .' : d})
//	        		.attr("font-family", gDashboard.fontManager.getFontFamily("Item"))
//	        		.attr("font-size", gDashboard.fontManager.getFontSizeNumber(12, "Item"))
//	        		.attr("text-anchor", "left")
//	        		.style("alignment-baseline", "middle")

        		d3.select("#"+self.itemid + ' svg').selectAll("myrect")
        		.data(self.paletteData)
        		.enter()
        		.append("circle")
        		.attr("cx", xPos)
        		.attr("cy", function(d,i){ return 50 + i*(size+5)})
        		.attr("r", 7)
        		.style("stroke", "none")
        		.style("fill", function(d){ return colors[d]})

        		$('#'+self.itemid).css('display', 'block');
        		// Add labels beside legend dots
        		d3.select("#"+self.itemid + ' svg').selectAll("mylabels")
        		.data(self.paletteData)
        		.enter()
        		.append("text")
        		.attr("x", xPos+ size*.8)
        		.attr("y", function(d,i){ return 40 + i * (size + 5) + (size/2)})
        		.style("fill", function(d){ return colors[d]})
        		.text(function(d){ return (self.paletteData.length === 1 && self.paletteData[0] === "") ? self.measures[0].caption :d})
        		.attr("font-family", self.meta.LayoutOption.Legend.family)
        		.attr("font-size", self.meta.LayoutOption.Legend.size+'px')
        		.attr("text-anchor", "left")
        		.style("alignment-baseline", "middle")
        		.each(wrap).append('title').text(function(d){ return d; });
        	}
        }

		function wrap() {
			var s = d3.select(this),
			textLength = s.node().getComputedTextLength(),
			text = s.text();
			while (textLength > (100) && text.length > 0) {
				text = text.slice(0, -1);
				s.text(text + '...');
				textLength = s.node().getComputedTextLength();
			}
		} 
		
		d3.selectAll('#'+ self.itemid +" .y .tick text")
			.style("font-family", self.meta.LayoutOption.AxisY.family)
	    	.style("font-size", self.meta.LayoutOption.AxisY.size+'px')
	    	.style("fill", self.meta.LayoutOption.AxisY.color)
	    	
			    	
    	d3.selectAll('#'+ self.itemid +" .x .tick text")
			.style("font-family", self.meta.LayoutOption.AxisX.family)
	    	.style("font-size", self.meta.LayoutOption.AxisX.size+'px')
	    	.style("fill", self.meta.LayoutOption.AxisX.color)
	    	
    	if(!self.BoxPlot.AxisX.Overlapping){
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
		
		if(!self.BoxPlot.ExpandOption.LabelOverlapping){
			setTimeout(function(){
	        	d3.selectAll("#"+self.itemid + " .box-label")
				   .each(function() {
					 var that = this,
						 a = this.getBoundingClientRect();
					 d3.selectAll("#"+self.itemid + " .box-label")
						.each(function() {
						  if(this != that) {
							var b = this.getBoundingClientRect();
							if((Math.abs(a.left - b.left) * 2 < (a.width + b.width)) &&
	                           (Math.abs(a.top - b.top) * 2 < (a.height + b.height))){
							  d3.select(this).attr("y", (d3.select(this).attr("y")*1) + (a.top + a.height) - b.top)
							}
						  }
						});
				   });
	        }, 1) 
		}
	    	
//		.style("font-size", gDashboard.fontManager.getFontSizeNumber(12, "Item")).style("font-family", gDashboard.fontManager.getFontFamily("Item"));
		d3.selectAll('#'+ self.itemid +" .whisker").style("font-family", self.meta.LayoutOption.Label.family)
    	.style("font-size", self.meta.LayoutOption.Label.size+'px')
    	.style("fill", self.meta.LayoutOption.Label.color)
    	
    	d3.selectAll('#'+ self.itemid +" text.box").style("font-family", self.meta.LayoutOption.Label.family)
    	.style("font-size", self.meta.LayoutOption.Label.size+'px')
    	.style("fill", self.meta.LayoutOption.Label.color)
    	
//		.style("font-size", gDashboard.fontManager.getFontSizeNumber(12, "Item")).style("font-family", gDashboard.fontManager.getFontFamily("Item"));
	};
	
	
	// Returns a function to compute the interquartile range.
	function iqr(k) {
	  return function(d, i) {
	    var q1 = d.quartiles[0],
	        q3 = d.quartiles[2],
	        iqr = (q3 - q1) * k,
	        i = -1,
	        j = d.length;
	    while (d[++i] < q1 - iqr);
	    while (d[--j] > q3 + iqr);
	    return [i, j];
	  };
	}
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
};


WISE.libs.Dashboard.BoxPlotFieldManager = function() {
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
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
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
