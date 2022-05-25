WISE.libs.Dashboard.item.HistoryTimelineGenerator = function() {
	var self = this;

	this.type = 'HISTORY_TIMELINE';

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
	
	this.HistoryTimeline = [];
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
	
	this.setHistoryTimeline = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.HistoryTimeline['ComponentName'] = this.ComponentName;
		this.HistoryTimeline['Name'] = this.Name;
		this.HistoryTimeline['DataSource'] = this.dataSourceId;
		
		this.HistoryTimeline['DataItems'] = this.fieldManager.DataItems;
		this.HistoryTimeline['Arguments'] = this.fieldManager.Arguments;
		this.HistoryTimeline['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.HistoryTimeline.HiddenMeasures = self.fieldManager.HiddenMeasures;
		
		this.meta = this.HistoryTimeline;
		
		if (!(this.HistoryTimeline['Palette'])) {
			this.HistoryTimeline['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HistoryTimeline.InteractivityOptions) {
			if (!(this.HistoryTimeline.InteractivityOptions.MasterFilterMode)) {
				this.HistoryTimeline.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HistoryTimeline.InteractivityOptions.TargetDimensions)) {
				this.HistoryTimeline.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HistoryTimeline.InteractivityOptions.IgnoreMasterFilters)) {
				this.HistoryTimeline.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HistoryTimeline.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.HistoryTimeline['Legend'])) {
			this.HistoryTimeline['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}

		
		if(!this.HistoryTimeline.LayoutOption){
			this.HistoryTimeline.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#ffffff',
						size: 12
					},
					AxisX: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		if(!this.HistoryTimeline['ZoomAble']){
			this.HistoryTimeline.ZoomAble = 'none'
		}
	};
	
	this.setHistoryTimelineforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setHistoryTimeline();
		}
		else{
			this.HistoryTimeline = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.HistoryTimeline['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.HistoryTimeline['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.HistoryTimeline['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.HistoryTimeline.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.HistoryTimeline['Palette'])) {
			this.HistoryTimeline['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var HistoryTimelineOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.HISTORY_TIMELINE_DATA_ELEMENT);
				
				$.each(HistoryTimelineOption,function(_i,_HistoryTimelineOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _HistoryTimelineOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _HistoryTimelineOption.CTRL_NM;
					}
					if(self.HistoryTimeline.ComponentName == CtrlNM){
						self.HistoryTimeline['Palette'] = _HistoryTimelineOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.HistoryTimeline.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.HistoryTimeline.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HistoryTimeline.InteractivityOptions) {
			if (!(this.HistoryTimeline.InteractivityOptions.MasterFilterMode)) {
				this.HistoryTimeline.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HistoryTimeline.InteractivityOptions.TargetDimensions)) {
				this.HistoryTimeline.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HistoryTimeline.InteractivityOptions.IgnoreMasterFilters)) {
				this.HistoryTimeline.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HistoryTimeline.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.HistoryTimeline['Legend'])) {
			this.HistoryTimeline['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}

		
		if(!this.HistoryTimeline.LayoutOption){
			this.HistoryTimeline.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#ffffff',
						size: 12
					},
					AxisX: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		if(!this.HistoryTimeline['ZoomAble']){
			this.HistoryTimeline.ZoomAble = 'none'
		}
	}
	
	this.setHistoryTimelineForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setHistoryTimeline();
		}
		else{
			this.HistoryTimeline = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.HistoryTimeline['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.HistoryTimeline['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.HistoryTimeline['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.HistoryTimeline.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.HistoryTimeline['Palette'])) {
			this.HistoryTimeline['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var HistoryTimelineOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.HISTORY_TIMELINE_DATA_ELEMENT);
				
				$.each(HistoryTimelineOption,function(_i,_HistoryTimelineOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _HistoryTimelineOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _HistoryTimelineOption.CTRL_NM;
//					}
					if(self.HistoryTimeline.ComponentName == CtrlNM){
						self.HistoryTimeline['Palette'] = _HistoryTimelineOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.HistoryTimeline.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.HistoryTimeline.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.HistoryTimeline.InteractivityOptions) {
			if (!(this.HistoryTimeline.InteractivityOptions.MasterFilterMode)) {
				this.HistoryTimeline.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.HistoryTimeline.InteractivityOptions.TargetDimensions)) {
				this.HistoryTimeline.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.HistoryTimeline.InteractivityOptions.IgnoreMasterFilters)) {
				this.HistoryTimeline.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.HistoryTimeline.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.HistoryTimeline['Legend'])) {
			this.HistoryTimeline['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}

		
		if(!this.HistoryTimeline.LayoutOption){
			this.HistoryTimeline.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#ffffff',
						size: 12
					},
					AxisX: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		if(!this.HistoryTimeline['ZoomAble']){
			this.HistoryTimeline.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setHistoryTimeline();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.HistoryTimeline);
			gDashboard.itemGenerateManager.generateItem(self, self.HistoryTimeline);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setHistoryTimelineforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.HistoryTimeline);
			gDashboard.itemGenerateManager.generateItem(self, self.HistoryTimeline);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.HistoryTimeline)) {
			this.setHistoryTimelineForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.HistoryTimeline);
			gDashboard.itemGenerateManager.generateItem(self, self.HistoryTimeline);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setHistoryTimelineForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.HistoryTimeline);
			gDashboard.itemGenerateManager.generateItem(self, self.HistoryTimeline);
		}

		self.tempTrackingData = [];
		
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
//								self.dimensions.splice(_i,1);
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
										self.dimensions[_i]=dataMember;
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
		if(measureKey){
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
		}

    	//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fHistoryTimeline(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
//		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
//		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
//				"instance");
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
				d3.selectAll('#' + self.itemid + ' .legend text').style('text-decoration', 'none').attr("filter", "false");
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
		if(typeof self.resizeData != 'undefined'){
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fHistoryTimeline(self.filteredData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('#' + self.itemid + ' .legend text[filter="true"]').style("text-decoration", 'underline').attr("filter", "true");
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		
//		self.fHistoryTimeline(self.filteredData, self.measures, self.dimensions, 
//				self.deleteDuplecateData(self.filteredData));
//		d3.selectAll('.bubbles[filter="true"]').style('stroke', 'black').style('stroke-width', 2).style('stroke-opacity', 0.7).attr("filter", "true");
//		gProgressbar.hide();
//	};
	
	this.fHistoryTimeline = function(jsonData, measures, dimensions, dupleData) {
		
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		self.resizeData = dupleData;
		d3.select("#"+self.itemid).selectAll('svg').remove();
		d3.select("#"+self.itemid).selectAll('div').remove();
		d3.select(".d3timeline-tooltip").remove();
//		// set the dimensions and margins of the graph
//		var margin = {top: 60, right: 50, bottom: 60, left: 100};
//		if(self.meta.Legend.Position === "LeftOuter" && self.meta.Legend.Visible){
//			margin.left = 200;
//		}else if(self.meta.Legend.Position === 'RightOuter' && self.meta.Legend.Visible){
//			margin.right = 150;
//		}else if(self.meta.Legend.Position.indexOf("Bottom") > -1 && self.meta.Legend.Visible){
//			margin.bottom = 120;
//		}else if(self.meta.Legend.Visible){
//			margin.top = 100;
//		}

		var margin = ({top: 30, right: 20, bottom: 30, left: 20});
		
		if(self.meta.Legend.Visible){
			if(self.meta.Legend.Position.indexOf("Bottom") > -1){
				margin.bottom = 70;
			}else if(self.meta.Legend.Position.indexOf("Left") > -1){
				margin.left = 70;
			}else if(self.meta.Legend.Position.indexOf("Right") > -1){
				margin.right = 70;
			}else if(self.meta.Legend.Position.indexOf("Top") > -1){
				margin.top = 70;
			}
		}
		
		var	svgWidth = $("#"+self.itemid).width(),
		svgHeight = $("#"+self.itemid).height(),
		width = svgWidth - margin.left - margin.right,
		height = svgHeight - margin.top - margin.bottom;
		
		var dimensions = ({
		  dataLength: dupleData.length,
		  barHeight: 20,
		  barPadding: 10,
		  width: width,
		  get height() {
		    return (this.dataLength * (this.barHeight + this.barPadding)) + (margin.top + this.barPadding) + margin.bottom
		  }
		});
		
		var parseTime = d3.timeParse("%Y-%m-%d");
		
		var data = dupleData.map(function(d) {
			return {name: d.dimension, dob: parseTime(d.startValue), dod: parseTime(d.endValue), start: d.start, end: d.end}
		}).sort(function(a, b){return d3.ascending(a.dob, b.dob)});

		var palette = gDashboard.d3Manager.getPalette(self);
		var color = d3.scaleOrdinal()
	    .domain(self.paletteData)
	    .range(palette);
		// create the svg
		var svg = d3.select("#"+self.itemid)
		.style("overflow-y", "auto")
		.style("overflow-x", "hidden")
		.append('svg')
		.style("position", svgHeight < dimensions.height? "block" : "absolute")
		.style("top", "50%")
		.style("margin-top", (svgHeight < dimensions.height? 0 : -dimensions.height/2) + 'px')
		.attr("width", svgWidth)
		.attr("height", dimensions.height).append('g');

		var x = d3.scaleTime()
	      .domain([d3.min(data, function(d){return d.dob}), d3.max(data, function(d){return d.dod})])
	      .range([margin.left, dimensions.width - margin.right]);
		
		var y = d3.scaleBand()
	      .range([0,dimensions.height - margin.bottom - margin.top]);
		// moving reference line
		var line = svg.append("line").attr("y1", margin.top).attr("y2", dimensions.height-margin.bottom).attr("stroke", "rgba(128,0,0,0.33333)").style("pointer-events","none").style("display", "none");

		svg.on("mousemove", function(d) {
			var x = d3.mouse(this)[0];
			if(x > margin.left && x < width - margin.right + margin.left){
                line.style("display", "block");
				line.attr("transform", 'translate('+ x +', 0)');
			}
		})

		svg.on("mouseout", function(d){
			line.style("display", "none");
		})

		// set up tooltip
		var tooltip = d3.select("body")
		.append("div")
		.attr("class", "d3timeline-tooltip")
		.style("position", "absolute")
		.style("left", '0px')
		.style("top", '0px')
		.style("opacity", 0);

		var formatCheck = data[data.length - 1].dod.getYear() - data[0].dob.getYear();
		
		function format(d){
			if(formatCheck <= 1){
				return d3.timeFormat("%Y %b")(d);
			}
            if(formatCheck <= 2){
            	if(d.getMonth() === 0)
            	    return d3.timeFormat("%Y")(d);
            	return d3.timeFormat("%B")(d);
            }else
                return d3.timeFormat("%Y")(d);
		}
		
		// top axis
		svg.append("g")
		.call(d3.axisTop(x).tickFormat(format))
		.attr("font-size", 8)
		.attr("font-family", "-apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif")
		.attr("transform", 'translate(' + margin.left + ', ' + margin.top + ')');

		// bottom axis
		svg.append("g")
		.call(d3.axisBottom(x).tickFormat(format))
		.attr("font-size", 8)
		.attr("font-family", "-apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif")
		.attr("transform", 'translate(' + margin.left + ', ' + (dimensions.height - margin.bottom) +')');

		// gridlines
		svg.append("g")
		.call(d3.axisTop(x)
				.tickFormat("")
				.tickSize(-(dimensions.height - margin.top - margin.bottom))
		)
		.attr("transform", 'translate(' + margin.left + ', ' + margin.top + ')')
		.attr("stroke-width", "1px")
		.attr("opacity", "0.125");

		// plot the data
		svg.append("g")
		.selectAll("rect")
		.data(data)
		.enter()
		.append("rect")
		.attr("class", "writer")
		.attr("x", function(d, i) {return x(d.dob) + margin.left})
		.attr("y", function(d, i) {return ((margin.top + dimensions.barPadding) + (i * (dimensions.barHeight + dimensions.barPadding)))})
		.attr("width", function(d, i) {return (d.dod ? x(d.dod) : x(today)) - x(d.dob)})
		.attr("height", dimensions.barHeight)
		.attr("fill", function(d){ return color(d.name)});

		// add labels
		svg.append("g")
		.selectAll("text")
		.data(data)
		.enter()
		.append("text")
		.text(function(d) {return d.name})
		.attr("class", "writer")
		.attr("fill", "#ffffff")
		.attr("x", function(d, i) {return x(d.dob) + margin.left + (dimensions.barPadding * 0.66667)})
		.attr("y", function(d, i) {return ((margin.top + 23.5) + (i * (dimensions.barHeight + dimensions.barPadding)))});

		svg.selectAll(".writer")
		.on("mouseover", function(d) {
			tooltip.transition()		
			.duration(200)		
			.style("opacity", 1);
			tooltip.html('<b>'+ d.name +'</b><br>'+ self.dimensions[0].caption+': '+ d.dob.toLocaleDateString()+ ' <br>'+ self.dimensions[1].caption+': '+ (d.dod ? d.dod.toLocaleDateString() : "-"))
			.style("top", (d3.event.pageY - 10)+"px").style("left",(d3.event.pageX + 10)+"px");
		})
		.on("mouseout", function(d) {		
			tooltip.transition()		
			.duration(200)		
			.style("opacity", 0);	
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
		
		d3.selectAll('#'+ self.itemid +" .tick text")
	    .attr("font-size", self.meta.LayoutOption.AxisX.size+'px')
	    .attr("font-family", self.meta.LayoutOption.AxisX.family)
	  	.style("fill", self.meta.LayoutOption.AxisX.color)
	  	
	  	d3.selectAll('#'+ self.itemid +" text.writer")
	    .attr("font-size", self.meta.LayoutOption.Label.size+'px')
	    .attr("font-family", self.meta.LayoutOption.Label.family)
	  	.style("fill", self.meta.LayoutOption.Label.color)
			
	  	if(self.meta.Legend.Visible){

			  var startp = svg.append("g").attr("class", "legendbox").attr("id", "mylegendbox");
			  // this is not nice, we should calculate the bounding box and use that
			  var legend_tabs = [0, 120, 200, 375, 450];
			  var legend = startp.selectAll(".legend")
			      .data(color.domain().slice())
			    .enter().append("g")
			      .attr("class", "legend")
			  if(self.meta.Legend.Position.indexOf("Center") > -1){
				  legend.attr("transform", function(d, i) { return "translate(" +  ( svgWidth/color.domain().slice().length * i + margin.left) + ",-45)"; });
			  }else{
				  legend.attr("transform", function(d, i) { return "translate("+ (self.meta.Legend.Position.indexOf("Left") > -1? 5 : svgWidth - 120) + ", "+ ( 30 * i) +")"; });
			  }
			      

			  legend.append("rect")
			      .attr("x", 0)
			      .attr("width", 10)
			      .attr("height", 10)
			      .style("fill", color);

			  legend.append("text")
			      .attr("x", 22)
			      .attr("y", 5)
			      .attr("dy", ".35em")
			      .style("text-anchor", "begin")
			      .style("font-size" , self.meta.LayoutOption.Legend.size + 'px')
			      .style("font-family" , self.meta.LayoutOption.Legend.family)
			      .style("fill" , self.meta.LayoutOption.Legend.color)
			      .text(function(d) { return d })
			      .attr("cursor", "pointer")
			      .attr("filter", function(d){
			    	  for (var index = 0; index < self.tempTrackingData.length; index++) {
			    			var check = 0;
		       				$.each(self.dimensions.slice(2), function(i, dim){
		       					if(self.tempTrackingData[index][dim.caption] === d.split(" - ")[i])
		       						check++;
		       				})
		       				if(check === self.dimensions.length - 2){
		       					return "true";
		       				}
		       			}
			    	  return "false";
			      }) .on("click", function(d){
				    	switch(self.meta.InteractivityOptions.MasterFilterMode){
			    		case 'Single':
			    			self.trackingData = [];
			    			self.tempTrackingData = [];
			    			if(d3.select(this).attr("filter") === "true"){
			    				d3.selectAll('#' + self.itemid + ' .legend text').style('text-decoration', 'none').attr("filter", "false");
					    	}else{
					    		//선택 모두 해제
					    		d3.selectAll('#' + self.itemid + ' .legend text').style('text-decoration', 'none').attr("filter", "false");
								
					    		d3.select(this).style("text-decoration", 'underline').attr("filter", "true");
					    		
//			       				var selectedData = {};
//				       			selectedData[self.dimensions[0].name] = d.data[0];
					    		var tempSelectedData = {};
				       			$.each(self.dimensions.slice(2), function(i, dim){
				       				var selectedData = {};
					    			selectedData[dim.caption] = d.split(" - ")[i]
					    			tempSelectedData[dim.caption] = d.split(" - ")[i]
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
					    	if(d3.select(this).attr("filter") === "true"){
					    		d3.select(this).style("text-decoration", 'underline').style('text-decoration', 'none').attr("filter", "false");
					    		for (var index = 0; index < self.tempTrackingData.length; index++) {
					    			var check = 0;
				       				$.each(self.dimensions.slice(2), function(i, dim){
				       					if(self.tempTrackingData[index][dim.caption] === d.split(" - ")[i])
				       						check++;
				       				})
				       				if(check === self.dimensions.length - 2){
				       					self.tempTrackingData.splice(index, 1);
				       					index--;
				       				}
				       			}
					    	}else{
					    		d3.select(this).style("text-decoration", 'underline').attr("filter", "true");
//					    		self.tempTrackingData.push(d.dimension.split(" - ")[i]);
					    		tempSelectedData = {}
					    		$.each(self.dimensions.slice(2), function(i, dim){
					    			tempSelectedData[dim.caption] = d.split(" - ")[i]
				       			})
				       			self.tempTrackingData.push(tempSelectedData);
					    	}
					    	
					    	self.trackingData = [];
					    	
					    	$.each(self.dimensions.slice(2), function(i, dim){
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

			  var movesize = 0;
			  var movesizeV =  self.meta.Legend.Position.indexOf("Bottom") > -1? dimensions.height + 20: 60;
			  d3.selectAll('#' + self.itemid + " .legendbox").attr("transform", "translate(" + movesize  + ","+ movesizeV +")");
		  }
	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
};


WISE.libs.Dashboard.HistoryTimelineFieldManager = function() {
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
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
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
