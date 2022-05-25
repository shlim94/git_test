WISE.libs.Dashboard.item.DependencyWheelGenerator = function() {
	var self = this;

	this.type = 'DEPENDENCY_WHEEL';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	this.resizeData = [];
	this.trackingData = [];
	
	var dataMember;
	var Exprname;
	var FilterArray = [];
	
	this.DependencyWheel = [];
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
	
	this.setDependencyWheel = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.DependencyWheel['ComponentName'] = this.ComponentName;
		this.DependencyWheel['Name'] = this.Name;
		this.DependencyWheel['DataSource'] = this.dataSourceId;
		
		this.DependencyWheel['DataItems'] = this.fieldManager.DataItems;
		this.DependencyWheel['Arguments'] = this.fieldManager.Arguments;
		this.DependencyWheel['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.DependencyWheel;
		
		if (!(this.DependencyWheel['Palette'])) {
			this.DependencyWheel['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DependencyWheel.InteractivityOptions) {
			if (!(this.DependencyWheel.InteractivityOptions.MasterFilterMode)) {
				this.DependencyWheel.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DependencyWheel.InteractivityOptions.TargetDimensions)) {
				this.DependencyWheel.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DependencyWheel.InteractivityOptions.IgnoreMasterFilters)) {
				this.DependencyWheel.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DependencyWheel.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.DependencyWheel.LayoutOption){
			this.DependencyWheel.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.DependencyWheel['ZoomAble']){
			this.DependencyWheel.ZoomAble = 'none'
		}
	};
	
	this.setDependencyWheelforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setDependencyWheel();
		}
		else{
			this.DependencyWheel = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.DependencyWheel['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.DependencyWheel['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.DependencyWheel['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.DependencyWheel['Palette'])) {
			this.DependencyWheel['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var DependencyWheelOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DEPENDENCY_WHEEL_DATA_ELEMENT);
				
				$.each(DependencyWheelOption,function(_i,_DependencyWheelOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _DependencyWheelOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _DependencyWheelOption.CTRL_NM;
					}
					if(self.DependencyWheel.ComponentName == CtrlNM){
						self.DependencyWheel['Palette'] = _DependencyWheelOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.DependencyWheel.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.DependencyWheel.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DependencyWheel.InteractivityOptions) {
			if (!(this.DependencyWheel.InteractivityOptions.MasterFilterMode)) {
				this.DependencyWheel.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DependencyWheel.InteractivityOptions.TargetDimensions)) {
				this.DependencyWheel.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DependencyWheel.InteractivityOptions.IgnoreMasterFilters)) {
				this.DependencyWheel.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DependencyWheel.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.DependencyWheel.LayoutOption){
			this.DependencyWheel.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.DependencyWheel['ZoomAble']){
			this.DependencyWheel.ZoomAble = 'none'
		}
	}
	
	this.setDependencyWheelForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setDependencyWheel();
		}
		else{
			this.DependencyWheel = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.DependencyWheel['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.DependencyWheel['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.DependencyWheel['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.DependencyWheel['Palette'])) {
			this.DependencyWheel['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var DependencyWheelOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DEPENDENCY_WHEEL_DATA_ELEMENT);
				
				$.each(DependencyWheelOption,function(_i,_DependencyWheelOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _DependencyWheelOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _DependencyWheelOption.CTRL_NM;
//					}
					if(self.DependencyWheel.ComponentName == CtrlNM){
						self.DependencyWheel['Palette'] = _DependencyWheelOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.DependencyWheel.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.DependencyWheel.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DependencyWheel.InteractivityOptions) {
			if (!(this.DependencyWheel.InteractivityOptions.MasterFilterMode)) {
				this.DependencyWheel.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DependencyWheel.InteractivityOptions.TargetDimensions)) {
				this.DependencyWheel.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DependencyWheel.InteractivityOptions.IgnoreMasterFilters)) {
				this.DependencyWheel.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DependencyWheel.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.DependencyWheel.LayoutOption){
			this.DependencyWheel.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.DependencyWheel['ZoomAble']){
			this.DependencyWheel.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setDependencyWheel();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.DependencyWheel);
			gDashboard.itemGenerateManager.generateItem(self, self.DependencyWheel);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setDependencyWheelforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.DependencyWheel);
			gDashboard.itemGenerateManager.generateItem(self, self.DependencyWheel);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.DependencyWheel)) {
			this.setDependencyWheelForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.DependencyWheel);
			gDashboard.itemGenerateManager.generateItem(self, self.DependencyWheel);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setDependencyWheelForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.DependencyWheel);
			gDashboard.itemGenerateManager.generateItem(self, self.DependencyWheel);
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
		
//		var measureKey = this.measures[0];
//		self.currentMeasureName = measureKey.caption;

		//2020.11.03 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('d3');
		self.fDependencyWheel(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,[]));
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
			d3.selectAll('#' + self.itemid + ' text').style('stroke', 'none').style("fill", self.meta.LayoutOption.Label.color).style('font-weight', '').attr("filter", "false");
			self.trackingData = [];
		}
	};
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
	};
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	
	this.resize = function() {
		if(self.resizeData.length > 0){
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fDependencyWheel(self.filteredData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('#' + self.itemid + ' text[filter="true"]').style('font-weight', 600).style("fill", "blue").style('stroke-opacity', 0.1).style('stroke', 'black').style('stroke-width', 5)
		}
		gProgressbar.hide();
	};
	
	var dependencyWheel = function(options) {
		  var svgHeight = $('#'+self.itemid).height();
		  var svgWidth = $('#'+self.itemid).width();
		  var width = $('#'+self.itemid).height() >  $('#'+self.itemid).width()?  $('#'+self.itemid).width() : $('#'+self.itemid).height();
		  var x = svgWidth / 2 - width / 2;
		  var y = svgHeight / 2 - width / 2;
		  var margin = 100;
		  var padding = 0.02;
          var zoom = d3.zoom().on("zoom", function (d,zz) {
        	  if(pressKey['z'] || pressKey['Z'])
						  d3.select("#" + self.itemid).select('g').attr("transform", function(){
									if(d3.event.transform.k === 1){
										return "translate(" + (width / 2) + "," + (svgHeight / 2) + ")";
									}
									if(d3.event.transform.x ===0 && d3.event.transform.y ===0){
										d3.event.transform.x = xLeng
										d3.event.transform.y = hLeng
									}
									return d3.event.transform;
						  })
	                })
		  function chart(selection) {
		    selection.each(function(data) {

		      var matrix = data.matrix;
		      var packageNames = data.packageNames;
		      var radius = width / 2 - margin;

		      // create the layout
		      var chord = d3.chord()
		        .padAngle(padding)
		        .sortSubgroups(d3.descending);

		      // Select the svg element, if it exists.
		      //var svg = d3.select(this).selectAll("svg");

		      // Otherwise, create the skeletal chart.
		      var gEnter = d3.select('#' + self.itemid).select("svg")
		      .data([data])
		      .attr("width", svgWidth)
		      .attr("height", svgHeight)
		      .attr("x", x)
		      .attr("y", y)
		      .attr("class", "dependencyWheel")
		      .append("g")
		      .attr("transform", "translate(" + (svgWidth / 2) + "," + (svgHeight / 2) + ")");

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
											return "translate(" + (svgWidth / 2) + "," + (svgHeight / 2) + ")";
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

		      var arc = d3.arc()
		        .innerRadius(radius)
		        .outerRadius(radius + 20);

		      var palette = gDashboard.d3Manager.getPalette(self);
		      
		      
		      var fill = function(d) {
//		        if (d.index === 0) return '#ccc';
//		        return "hsl(" + parseInt(((packageNames[d.index][0].charCodeAt() - 97) / 26) * 360, 10) + ",90%,70%)";
		    	return palette[d.index%palette.length];
		      };

		      // Returns an event handler for fading a given chord group.
		      var fade = function(opacity) {
		        return function(g, i) {
		          gEnter.selectAll(".chord")
		              .filter(function(d) {
		                return d.source.index != i && d.target.index != i;
		              })
		            .transition()
		              .style("opacity", opacity);
		          var groups = [];
		          gEnter.selectAll(".chord")
		              .filter(function(d) {
		                if (d.source.index == i) {
		                  groups.push(d.target.index);
		                }
		                if (d.target.index == i) {
		                  groups.push(d.source.index);
		                }
		              });
		          groups.push(i);
		          var length = groups.length;
		          gEnter.selectAll('.group')
		              .filter(function(d) {
		                for (var i = 0; i < length; i++) {
		                  if(groups[i] == d.index) return false;
		                }
		                return true;
		              })
		              .transition()
		                .style("opacity", opacity);
		        };
		      };

		      var chordResult = chord(matrix);

		      var rootGroup = chordResult.groups[0];
		      var rotation = - (rootGroup.endAngle - rootGroup.startAngle) / 2 * (180 / Math.PI);

		      var g = gEnter.selectAll("g.group")
		        .data(chordResult.groups)
		        .enter().append("svg:g")
		        .attr("class", "group")
		        .attr("transform", function(d) {
		          return "rotate(" + rotation + ")";
		        });

		      g.append("svg:path")
		        .style("fill", fill)
		        .style("stroke", fill)
		        .attr("d", arc)
		        .style("cursor", "pointer")
		        .on("mouseover", fade(0.1))
		        .on("mouseout", fade(1));

		      g.append("svg:text")
		        .each(function(d) { d.angle = (d.startAngle + d.endAngle) / 2; })
		        .attr("dy", ".35em")
		        .attr("text-anchor", function(d) { return d.angle > Math.PI ? "end" : null; })
		        .attr("transform", function(d) {
		          return "rotate(" + (d.angle * 180 / Math.PI - 90) + ")" +
		            "translate(" + (radius + 26) + ")" +
		            (d.angle > Math.PI ? "rotate(180)" : "");
		        })
		        .style("cursor", "pointer")
		        .text(function(d) { return packageNames[d.index]; })
		        .style("font-family", self.meta.LayoutOption.Label.family)
		        .style("font-size", self.meta.LayoutOption.Label.size+'px')
		        .style("fill", self.meta.LayoutOption.Label.color)
		        .attr("filter", function(d){
		        	var selectKey = packageNames[d.index];
		        	var selectedData = {};
		        	var inArray = false;
		        	$.each(self.dimensions, function(_i, _ao) {
						$.each(self.csvData, function(_index, _val) {		
							if(_val[_ao.name] === selectKey){
								selectedData[_ao.name] = selectKey;
								return false;
							}
						});
						for (var index = 0; index < self.trackingData.length; index++) {
							if (self.trackingData[index][_ao.name] && self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
								inArray = true;
								break;
							}
						}
						
						if(inArray) return false;
					});
		        	
		        	if(inArray) return "true";
		        	return "false";
		        }).attr("cursor", "pointer")
		        .on("click", function(d){
//		        	d3.select(this).style("fill", "blue")
		        	
		        	var selectKey = packageNames[d.index];
		             switch(self.IO.MasterFilterMode){
						case 'Multiple':
							var inArray = false;
							var selectedData = {};
							$.each(self.dimensions, function(_i, _ao) {
								$.each(self.csvData, function(_index, _val) {		
									if(_val[_ao.name] === selectKey){
										selectedData[_ao.name] = selectKey;
									}
									if(_ao.name === selectKey){
										inArray = true;
									}
								});
								for (var index = 0; index < self.trackingData.length; index++) {
									if (self.trackingData[index][_ao.name] && self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
										self.trackingData.splice(index, 1);
										index--;
										inArray = true;
									}
								}
							});

							
							if (!inArray) {
								d3.select(this).style('font-weight', 600).style("fill", "blue").style('stroke-opacity', 0.1).style('stroke', 'black').style('stroke-width', 5).attr("filter", "ture");
								self.trackingData.push(selectedData);
							}else{
								d3.select(this).style('font-weight', '').style("fill", self.meta.LayoutOption.Label.color).style('stroke', 'none').attr("filter", "false");
							}
							/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
    						if(WISE.Constants.editmode === "viewer"){
    							gDashboard.itemGenerateManager.focusedItem = self;
    						}
							gDashboard.filterData(self.itemid, self.trackingData);
							break;
						case 'Single':

							self.trackingData = [];
							d3.selectAll('#' + self.itemid + ' text').style('stroke', 'none').style("fill", self.meta.LayoutOption.Label.color).style('font-weight', '').attr("filter", "false");
							d3.select(this).style('font-weight', 600).style("fill", "blue").style('stroke-opacity', 0.1).style('stroke', 'black').style('stroke-width', 5).attr("filter", "ture");
							var selectedData = {};
							$.each(self.dimensions, function(_i, _ao) {
								$.each(self.csvData, function(_index, _val) {		
									if(_val[_ao.name] === selectKey){
										self.trackingData = [];

										selectedData[_ao.name] = selectKey;
										self.trackingData.push(selectedData);
									}
								});
							});
							/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
    						if(WISE.Constants.editmode === "viewer"){
    							gDashboard.itemGenerateManager.focusedItem = self;
    						}
							gDashboard.filterData(self.itemid, self.trackingData);
							break;
					}
		        })
		        .on("mouseover", fade(0.1))
		        .on("mouseout", fade(1));

		      gEnter.selectAll("path.chord")
		          .data(chordResult)
		          .enter().append("svg:path")
		          .attr("class", "chord")
		          .style("stroke", function(d) { return d3.rgb(fill(d.source)).darker(); })
		          .style("fill", function(d) { return fill(d.source); })
		          .attr("d", d3.ribbon().radius(radius))
		          .attr("transform", function(d) {
		            return "rotate(" + rotation + ")";
		          })
		          .style("opacity", 1);
		    });
		  }

		  chart.width = function(value) {
		    if (!arguments.length) return width;
		    width = value;
		    return chart;
		  };

		  chart.margin = function(value) {
		    if (!arguments.length) return margin;
		    margin = value;
		    return chart;
		  };

		  chart.padding = function(value) {
		    if (!arguments.length) return padding;
		    padding = value;
		    return chart;
		  };

		  return chart;
		};
		
		
	
	this.fDependencyWheel = function(jsonData, measures, dimensions, dupleData) {
		
		if (!Array.prototype.flatMap) {
		    Object.defineProperty(Array.prototype, 'flatMap', {
		        value: function(callback, thisArg) {
		            var self = thisArg || this;
		            if (self === null) {
		                throw new TypeError( 'Array.prototype.flatMap ' +
		                'called on null or undefined' );
		            }
		            if (typeof callback !== 'function') {
		                throw new TypeError( callback +
		                ' is not a function');
		            }

		            var list = [];

		            // 1. Let O be ? ToObject(this value).
		            var o = Object(self);

		            // 2. Let len be ? ToLength(? Get(O, "length")).
		            var len = o.length >>> 0;

		            for (var k = 0; k < len; ++k) {
		                if (k in o) {
		                    var part_list = callback.call(self, o[k], k, o);
		                    list = list.concat(part_list);
		                }
		            }

		            return list;
		        }
		    });
		}
		
//		if (!Array.from) {
//			  Array.from = (function () {
//			    var toStr = Object.prototype.toString;
//			    var isCallable = function (fn) {
//			      return typeof fn === 'function' || toStr.call(fn) === '[object Function]';
//			    };
//			    var toInteger = function (value) {
//			      var number = Number(value);
//			      if (isNaN(number)) { return 0; }
//			      if (number === 0 || !isFinite(number)) { return number; }
//			      return (number > 0 ? 1 : -1) * Math.floor(Math.abs(number));
//			    };
//			    var maxSafeInteger = Math.pow(2, 53) - 1;
//			    var toLength = function (value) {
//			      var len = toInteger(value);
//			      return Math.min(Math.max(len, 0), maxSafeInteger);
//			    };
//
//			    // The length property of the from method is 1.
//			    return function from(arrayLike/*, mapFn, thisArg */) {
//			      // 1. Let C be the this value.
//			      var C = this;
//
//			      // 2. Let items be ToObject(arrayLike).
//			      var items = Object(arrayLike);
//
//			      // 3. ReturnIfAbrupt(items).
//			      if (arrayLike == null) {
//			        throw new TypeError("Array.from requires an array-like object - not null or undefined");
//			      }
//
//			      // 4. If mapfn is undefined, then let mapping be false.
//			      var mapFn = arguments.length > 1 ? arguments[1] : void undefined;
//			      var T;
//			      if (typeof mapFn !== 'undefined') {
//			        // 5. else
//			        // 5. a If IsCallable(mapfn) is false, throw a TypeError exception.
//			        if (!isCallable(mapFn)) {
//			          throw new TypeError('Array.from: when provided, the second argument must be a function');
//			        }
//
//			        // 5. b. If thisArg was supplied, let T be thisArg; else let T be undefined.
//			        if (arguments.length > 2) {
//			          T = arguments[2];
//			        }
//			      }
//
//			      // 10. Let lenValue be Get(items, "length").
//			      // 11. Let len be ToLength(lenValue).
//			      var len = toLength(items.length);
//
//			      // 13. If IsConstructor(C) is true, then
//			      // 13. a. Let A be the result of calling the [[Construct]] internal method of C with an argument list containing the single item len.
//			      // 14. a. Else, Let A be ArrayCreate(len).
//			      var A = isCallable(C) ? Object(new C(len)) : new Array(len);
//
//			      // 16. Let k be 0.
//			      var k = 0;
//			      // 17. Repeat, while k < len… (also steps a - h)
//			      var kValue;
//			      while (k < len) {
//			        kValue = items[k];
//			        if (mapFn) {
//			          A[k] = typeof T === 'undefined' ? mapFn(kValue, k) : mapFn.call(T, kValue, k);
//			        } else {
//			          A[k] = kValue;
//			        }
//			        k += 1;
//			      }
//			      // 18. Let putStatus be Put(A, "length", len, true).
//			      A.length = len;
//			      // 20. Return A.
//			      return A;
//			    };
//			  }());
//			}
		
		if (!Array.prototype.fill) {
			  Object.defineProperty(Array.prototype, 'fill', {
			    value: function(value) {

			      // Steps 1-2.
			      if (this == null) {
			        throw new TypeError('this is null or not defined');
			      }

			      var O = Object(this);

			      // Steps 3-5.
			      var len = O.length >>> 0;

			      // Steps 6-7.
			      var start = arguments[1];
			      var relativeStart = start >> 0;

			      // Step 8.
			      var k = relativeStart < 0 ?
			        Math.max(len + relativeStart, 0) :
			        Math.min(relativeStart, len);

			      // Steps 9-10.
			      var end = arguments[2];
			      var relativeEnd = end === undefined ?
			        len : end >> 0;

			      // Step 11.
			      var final = relativeEnd < 0 ?
			        Math.max(len + relativeEnd, 0) :
			        Math.min(relativeEnd, len);

			      // Step 12.
			      while (k < final) {
			        O[k] = value;
			        k++;
			      }

			      // Step 13.
			      return O;
			    }
			  });
			}
		
		function arrayFrom(arr, callbackFn, thisArg)
		{
		    //if you need you can uncomment the following line
		    //if(!arr || typeof arr == 'function')throw new Error('This function requires an array-like object - not null, undefined or a function');

		    var arNew = [],
		        k = [], // used for convert Set to an Array
		        i = 0;

		    //if you do not need a Set object support then
		    //you can comment or delete the following if statement
		    if(window.Set && arr instanceof Set)
		    {
		        //we use forEach from Set object
		        arr.forEach(function(v){k.push(v)});
		        arr = k
		    }

		    for(; i < (arr.length || arr.size); i++)
		        arNew[i] = callbackFn
		            ? callbackFn.call(thisArg, arr[i], i, arr)
		            : arr[i];

		    return arNew
		}
		
		self.resizeData = dupleData;
		var data = arrayFrom(dupleData.flatMap(function (d) { return d.imports.map(function(target){ return [d.name, target]})}),
		  function(d){
			var a ={
					source: d[0],
					target: d[1],
					value: d.length
			}
			return a}, function(link){return link.join()});
		
//		var data = [].forEach.call(dupleData.flatMap(function (d) { return d.imports.map(function(target){ return [d.name, target]})}), function(d) {
//			var a ={
//					source: d[0],
//					target: d[1],
//					value: d.length
//			}
//			return a
//		}, function(link){return link.join()});
//		  .values());
		 
	var arr = data.flatMap(function(d){return [d.source, d.target]} );
	  names = arrayFrom(arr.filter(function(item, index) { return arr.indexOf(item) === index})).sort(d3.ascending)
	
	  self.paletteData = names;
	  matrix = function() {
//		  var index = new Map(names.map(function (name, i) { return [name, i] }));
		  var matrix = arrayFrom(names, function() { return new Array(names.length).fill(0) });
		  for (var i = 0; i < data.length; i++) {
			  var source = data[i].source;
			  var target = data[i].target;
			  var value = data[i].value;
			  matrix[names.indexOf(source)][names.indexOf(target)] += value;
		  }
		  return matrix;
		}
	  
	  var matrixData = {
		 packageNames: names,
		 matrix: matrix()
	  }
		  
		var chart = dependencyWheel();
	  
	  	$('#'+self.itemid+' svg').remove();
		d3.select('#' + self.itemid).append('svg').attr("height", $('#'+self.itemid).height()).attr("width", $('#'+self.itemid).width())
		  .datum(matrixData)
		  .call(chart);
	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self);
	}
};


WISE.libs.Dashboard.DependencyWheelFieldManager = function() {
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
				dataItem['Name'] = $(_fieldlist[i]).attr('UNI_NM');
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
