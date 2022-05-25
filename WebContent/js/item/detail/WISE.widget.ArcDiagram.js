WISE.libs.Dashboard.item.ArcDiagramGenerator = function() {
	var self = this;

	this.type = 'ARC_DIAGRAM';

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
	
	this.ArcDiagram = [];
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
	
	this.setArcDiagram = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.ArcDiagram['ComponentName'] = this.ComponentName;
		this.ArcDiagram['Name'] = this.Name;
		this.ArcDiagram['DataSource'] = this.dataSourceId;
		
		this.ArcDiagram['DataItems'] = this.fieldManager.DataItems;
		this.ArcDiagram['Arguments'] = this.fieldManager.Arguments;
		this.ArcDiagram['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.ArcDiagram.HiddenMeasures = self.fieldManager.HiddenMeasures;
		
		this.meta = this.ArcDiagram;
		
		if (!(this.ArcDiagram['Palette'])) {
			this.ArcDiagram['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ArcDiagram.InteractivityOptions) {
			if (!(this.ArcDiagram.InteractivityOptions.MasterFilterMode)) {
				this.ArcDiagram.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ArcDiagram.InteractivityOptions.TargetDimensions)) {
				this.ArcDiagram.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ArcDiagram.InteractivityOptions.IgnoreMasterFilters)) {
				this.ArcDiagram.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ArcDiagram.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ArcDiagram['Legend'])) {
			this.ArcDiagram['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!(this.ArcDiagram.Round)){
			this.ArcDiagram.Round = {
					Min: 5,
					Max: 20
			}
		}
		
		if(!this.ArcDiagram.LayoutOption){
			this.ArcDiagram.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
			}
		}
		
		if(!this.ArcDiagram['ZoomAble']){
			this.ArcDiagram.ZoomAble = 'none'
		}
		
		if(!this.ArcDiagram['Rotated']){
			this.ArcDiagram.Rotated = 'Horizontal'
		}
	};
	
	this.setArcDiagramforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setArcDiagram();
		}
		else{
			this.ArcDiagram = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.ArcDiagram['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.ArcDiagram['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.ArcDiagram['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.ArcDiagram.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.ArcDiagram['Palette'])) {
			this.ArcDiagram['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var ArcDiagramOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.ARC_DIAGRAM_DATA_ELEMENT);
				
				$.each(ArcDiagramOption,function(_i,_ArcDiagramOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _ArcDiagramOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _ArcDiagramOption.CTRL_NM;
					}
					if(self.ArcDiagram.ComponentName == CtrlNM){
						self.ArcDiagram['Palette'] = _ArcDiagramOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.ArcDiagram.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.ArcDiagram.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ArcDiagram.InteractivityOptions) {
			if (!(this.ArcDiagram.InteractivityOptions.MasterFilterMode)) {
				this.ArcDiagram.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ArcDiagram.InteractivityOptions.TargetDimensions)) {
				this.ArcDiagram.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ArcDiagram.InteractivityOptions.IgnoreMasterFilters)) {
				this.ArcDiagram.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ArcDiagram.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ArcDiagram['Legend'])) {
			this.ArcDiagram['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!(this.ArcDiagram.Round)){
			this.ArcDiagram.Round = {
					Min: 5,
					Max: 20
			}
		}
		
		if(!this.ArcDiagram.LayoutOption){
			this.ArcDiagram.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
			}
		}
		
		if(!this.ArcDiagram['ZoomAble']){
			this.ArcDiagram.ZoomAble = 'none'
		}
		
		if(!this.ArcDiagram['Rotated']){
			this.ArcDiagram.Rotated = 'Horizontal'
		}
	}
	
	this.setArcDiagramForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setArcDiagram();
		}
		else{
			this.ArcDiagram = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.ArcDiagram['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.ArcDiagram['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.ArcDiagram['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.ArcDiagram.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.ArcDiagram['Palette'])) {
			this.ArcDiagram['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var ArcDiagramOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.ARC_DIAGRAM_DATA_ELEMENT);
				
				$.each(ArcDiagramOption,function(_i,_ArcDiagramOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _ArcDiagramOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _ArcDiagramOption.CTRL_NM;
//					}
					if(self.ArcDiagram.ComponentName == CtrlNM){
						self.ArcDiagram['Palette'] = _ArcDiagramOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.ArcDiagram.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.ArcDiagram.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ArcDiagram.InteractivityOptions) {
			if (!(this.ArcDiagram.InteractivityOptions.MasterFilterMode)) {
				this.ArcDiagram.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ArcDiagram.InteractivityOptions.TargetDimensions)) {
				this.ArcDiagram.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ArcDiagram.InteractivityOptions.IgnoreMasterFilters)) {
				this.ArcDiagram.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ArcDiagram.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ArcDiagram['Legend'])) {
			this.ArcDiagram['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!(this.ArcDiagram.Round)){
			this.ArcDiagram.Round = {
					Min: 5,
					Max: 20
			}
		}
		
		if(!this.ArcDiagram.LayoutOption){
			this.ArcDiagram.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
			}
		}
		
		if(!this.ArcDiagram['ZoomAble']){
			this.ArcDiagram.ZoomAble = 'none'
		}
		
		if(!this.ArcDiagram['Rotated']){
			this.ArcDiagram.Rotated = 'Horizontal'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setArcDiagram();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.ArcDiagram);
			gDashboard.itemGenerateManager.generateItem(self, self.ArcDiagram);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setArcDiagramforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.ArcDiagram);
			gDashboard.itemGenerateManager.generateItem(self, self.ArcDiagram);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.ArcDiagram)) {
			this.setArcDiagramForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.ArcDiagram);
			gDashboard.itemGenerateManager.generateItem(self, self.ArcDiagram);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setArcDiagramForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.ArcDiagram);
			gDashboard.itemGenerateManager.generateItem(self, self.ArcDiagram);
		}

		self.trackingData = [];
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

		//2020.11.03 mksong resource Import 동적 구현 dogfoot
    	WISE.loadedSourceCheck('d3');
		self.fArcDiagram(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
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
				d3.selectAll('#' + self.itemid + ' circle').attr('r', 5.555 ).attr("filter", "false");
			}
			self.trackingData = [];
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
			self.fArcDiagram(self.filteredData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('#' + self.itemid + ' circle[filter="true"]').attr("r", 10)
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		
//		self.fArcDiagram(self.filteredData, self.measures, self.dimensions, 
//				self.deleteDuplecateData(self.filteredData));
//		d3.selectAll('.bubbles[filter="true"]').style('stroke', 'black').style('stroke-width', 2).style('stroke-opacity', 0.7).attr("filter", "true");
//		gProgressbar.hide();
//	};
	
	this.fArcDiagram = function(jsonData, measures, dimensions, dupleData) {
		
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		self.resizeData = dupleData;
		d3.select("#"+self.itemid).selectAll('svg').remove();
		d3.select("#"+self.itemid).selectAll('div').remove();
		
		var data = dupleData;

		var svgWidth = $("#"+self.itemid).width();
		var svgHeight= $("#"+self.itemid).height();
		
		var margin = {top: 0, right: 30, bottom: 50, left: 60};
		
		if(self.meta.Legend.Visible){
			if(self.meta.Legend.Position.indexOf("Bottom") > -1){
				margin.bottom = 70;
			}else if(self.meta.Legend.Position.indexOf("Left") > -1){
				margin.left = 150;
			}else if(self.meta.Legend.Position.indexOf("Right") > -1){
				margin.right = 120;
			}else if(self.meta.Legend.Position.indexOf("Top") > -1){
				margin.top = 30;
			}
		}
		 
		if(self.meta.Rotated === 'Horizontal'){
			if(data.nodes.length * 30 < $("#"+self.itemid).width()){
				$("#"+self.itemid).css("overflow-y", "hidden");
				$("#"+self.itemid).css("overflow-x", "hidden");
			}else{
				svgWidth = data.nodes.length * 30;
				$("#"+self.itemid).css("overflow-y", "hidden");
				$("#"+self.itemid).css("overflow-x", "auto");
			}
		}else{
			margin.top = 30;
			margin.bottom = 30;
			
			if(self.meta.Legend.Position.indexOf("Bottom") > -1){
				margin.bottom = 70;
			}else if(self.meta.Legend.Position.indexOf("Left") > -1){
				margin.left = 150;
			}else if(self.meta.Legend.Position.indexOf("Right") > -1){
				margin.right = 120;
			}else if(self.meta.Legend.Position.indexOf("Top") > -1){
				margin.top = 50;
			}
			if(data.nodes.length * 25 < $("#"+self.itemid).height()){
				$("#"+self.itemid).css("overflow-y", "hidden");
				$("#"+self.itemid).css("overflow-x", "hidden");
			}else{
				svgHeight = data.nodes.length * 25;
				$("#"+self.itemid).css("overflow-y", "auto");
				$("#"+self.itemid).css("overflow-x", "hidden");
			}
		}
		
		
		var width = svgWidth - margin.left - margin.right,
		height = svgHeight - margin.top - margin.bottom;
		// append the svg object to the body of the page
		var svg = d3.select("#"+self.itemid).append("div").classed("scrollbar", true)
		.append("svg")
		.attr("width", width + margin.left + margin.right)
		.attr("height", height + margin.top + margin.bottom)
		.append("g")
		.attr("transform",
				"translate(" + margin.left + "," + margin.top + ")");
		data.nodes.sort(function(a,b) { return a.group - b.group});
		
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
				 }else{
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
		// List of node names
		var allNodes = data.nodes.map(function(d){return d.id})

		// List of groups
		var allGroups = data.nodes.map(function(d){return d.group})
		allGroups = allGroups.reduce(function(acc,curr,index){
			acc.indexOf(curr) > -1 ? acc : acc.push(curr);
			return acc;
		},[]);

		// A color scale for groups:
		var color = d3.scaleOrdinal()
		.domain(allGroups)
		.range(gDashboard.d3Manager.getPalette(self));

		// A linear scale for node size
		var size = d3.scaleLinear()
		.domain([1,10])
		.range([2,10]);

		// A linear scale to position the nodes on the X axis
		var x = d3.scalePoint()
		.range([0, width])
		.domain(allNodes)
		
		var y = d3.scalePoint()	
	    .range([0, height])	
	    .domain(allNodes)

		// In my input data, links are provided between nodes -id-, NOT between node names.
		// So I have to do a link between this id and the name
		var idToNode = {};
		data.nodes.forEach(function (n) {
			idToNode[n.id] = n;
		});

		// Add the links
		var links = svg
		.selectAll('mylinks')
		.data(data.links)
		.enter()
		.append('path')
		.attr('d', function (d) {
			if(self.meta.Rotated === 'Horizontal'){
				start = x(idToNode[d.source].id)    // X position of start node on the X axis
				end = x(idToNode[d.target].id)      // X position of end node
				var pHeight = (start - end)/2 > height -80? height - 80: (start - end)/2;
				if(start - end < 0)
				     pHeight = (start - end)/2 < -height + 80? - height + 80 : (start - end)/2;
				return ['M', start, height-30,    // the arc starts at the coordinate x=start, y=height-30 (where the starting node is)
					'A',                            // This means we're gonna build an elliptical arc
					(start - end)/2, ',',    // Next 2 lines are the coordinates of the inflexion point. Height of this point is proportional with start - end distance
					pHeight ,
					0, 0, ',',
					start < end ? 1 : 0, end, ',', height-30] // We always want the arc on top. So if end is before start, putting 0 here turn the arc upside down.
				.join(' ');
			}else{
				start = y(idToNode[d.source].id)    // X position of start node on the X axis
				end = y(idToNode[d.target].id)      // X position of end node
				var i = width / 350;
				if( i < 1) i = 1;
				var pWidth = (start - end)/2 * i > width -80? width - 80: (start - end)/2  * i;
				if(start - end < 0)
				     pWidth = (start - end)/2 * i < -width + 80? - width + 80 : (start - end)/2  * i;

				return ['M', 25, start,    // the arc starts at the coordinate x=start, y=height-30 (where the starting node is)
					'A',                            // This means we're gonna build an elliptical arc
					pWidth, ',',    // Next 2 lines are the coordinates of the inflexion point. Height of this point is proportional with start - end distance
					(start - end)/2 ,
					0, 0, ',',
					start < end ? 1 : 0, 25, ',', end] // We always want the arc on top. So if end is before start, putting 0 here turn the arc upside down.
				.join(' ');

			}
		})
		.style("fill", "none")
		.attr("stroke", "grey")
		.style("stroke-width", 1)

		// Add the circle for the nodes
		var nodes = svg
		.selectAll("mynodes")
		.data(data.nodes)
		.enter()
		.append("circle")
		.attr("r", function(d){ return(5)})
		.style("fill", function(d){ return color(d.group)})
		.attr("stroke", "white")
		.attr("cursor", "pointer")
		
		if(self.meta.Rotated === 'Horizontal'){
			nodes
			.attr("cx", function(d){ return(x(d.id))})
			.attr("cy", height-30)
		}else{
			nodes
			.attr("cy", function(d){ return(y(d.id))})
			.attr("cx", 30)
		}

		// And give them a label
		var labels = svg
		.selectAll("mylabels")
		.data(data.nodes)
		.enter()
		.append("text")
		.attr("x", 0)
		.attr("y", 0)
		.text(function(d){ return(d.id)} )
		.style("text-anchor", "end")
		.style("font-size" , self.meta.LayoutOption.Label.size + 'px')
		.style("font-family" , self.meta.LayoutOption.Label.family)
		.style("fill" , self.meta.LayoutOption.Label.color)
		
		if(self.meta.Rotated === 'Horizontal'){
			labels
			.attr("transform", function(d){ return( "translate(" + (x(d.id)) + "," + (height-15) + ")rotate(-45)")})
		}else{
			labels
			.attr("transform", function(d){ return( "translate(" + (20) + "," + (y(d.id) + 5) + ")")})
		}

		// Add the highlighting functionality
		nodes
		.attr("filter", function(d){
			var inArray = false;
			var selectedData = {};
			selectedData[self.dimensions[d.group].name] = d.id;
			for (var index = 0; index < self.trackingData.length; index++) {
				if (self.trackingData[index][self.dimensions[d.group].name] && self.trackingData[index][self.dimensions[d.group].name] === selectedData[self.dimensions[d.group].name]) {
					inArray = true;
					break;
				}
			}
			return inArray? "true" : "false";
		})
		.on("click", function(d){
            switch(self.meta.InteractivityOptions.MasterFilterMode){
				case 'Multiple':
					var inArray = false;
					var selectedData = {};
					selectedData[self.dimensions[d.group].name] = d.id;
					if(d3.select(this).attr("filter") === 'true'){
						d3.select(this).attr("r", 5).attr("filter", "false");
						for (var index = 0; index < self.trackingData.length; index++) {
							if (self.trackingData[index][self.dimensions[d.group].name] && self.trackingData[index][self.dimensions[d.group].name] === selectedData[self.dimensions[d.group].name]) {
								self.trackingData.splice(index, 1);
								index--;
								inArray = true;
								break;
							}
						}
					}else{
						d3.select(this).attr("r", 10).attr("filter", "true");
						var selectedData = {};
						selectedData[self.dimensions[d.group].name] = d.id;
						
						self.trackingData.push(selectedData);
					}
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
				case 'Single':

					self.trackingData = [];
					if(d3.select(this).attr("filter") === 'true'){
						d3.selectAll('#'+self.itemid + ' circle').attr("r", 5).attr("filter", "false");
						self.trackingData = [];
					}else{
						d3.selectAll('#'+self.itemid + ' circle').attr("r", 5).attr("filter", "false");
						d3.select(this).attr("r", 10).attr("filter", "true");
						var selectedData = {};
						selectedData[self.dimensions[d.group].name] = d.id;
						
						self.trackingData = [selectedData];
					}
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
			}
		})
		.on('mouseover', function (d) {
			// Highlight the nodes: every node is green except of him
			nodes
			.style('opacity', .2)
			d3.select(this)
			.style('opacity', 1)
			// Highlight the connections
			links
			.style('stroke', function (link_d) { return link_d.source === d.id || link_d.target === d.id ? color(d.group) : '#b8b8b8';})
			.style('stroke-opacity', function (link_d) { return link_d.source === d.id || link_d.target === d.id ? 1 : .2;})
			.style('stroke-width', function (link_d) { return link_d.source === d.id || link_d.target === d.id ? 2 : 1;})
//			labels
//			.style("font-size", function(label_d){ return label_d.id === d.id ? self.meta.LayoutOption.Label.size : 5 } )
//			.attr("y", function(label_d){ return label_d.id === d.id ? 10 : 0 } )

		})
		.on('mouseout', function (d) {
			nodes.style('opacity', 1)
			links
			.style('stroke', 'grey')
			.style('stroke-opacity', .8)
			.style('stroke-width', '1')
//			labels
//			.style("font-size", self.meta.LayoutOption.Label.size)

		})
		
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
				  legend.attr("transform", function(d, i) { return "translate("+ (self.meta.Legend.Position.indexOf("Left") > -1? -130 : svgWidth - 160) + ", "+ ( 50 * i) +")"; });
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
			      .text(function(d) { return self.dimensions[d].caption; });

			  var movesize = 0;
			  var movesizeV = 30;
			  if(self.meta.Rotated === 'Vertical'){
					if(self.meta.Legend.Position.indexOf("Center") === -1)
				  	    movesizeV = -20;
					else
				  	    movesizeV = self.meta.Legend.Position.indexOf("Bottom") > -1? svgHeight - 30: 10;
			  }else{
			  	movesizeV = self.meta.Legend.Position.indexOf("Bottom") > -1? svgHeight + 20: 30;
			  }
			  d3.selectAll('#' + self.itemid + " .legendbox").attr("transform", "translate(" + movesize  + ","+ movesizeV +")");
		  }
		

		  d3.selectAll('#' + self.itemid + " .axis path")
		      .style("fill", "none")
		      .style("stroke", "#000")
		      .style("shape-rendering", "crispEdges")

		  d3.selectAll('#' + self.itemid + " .axis line")
		      .style("fill", "none")
		      .style("stroke", "#000")
		      .style("shape-rendering", "crispEdges")
	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
};


WISE.libs.Dashboard.ArcDiagramFieldManager = function() {
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
