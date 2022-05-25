WISE.libs.Dashboard.item.SequencesSunburstGenerator = function() {
	var self = this;

	this.type = 'SEQUENCES_SUNBURST';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	this.trackingData = [];
	this.resizeData = [];
	this.paletteData = [];
	
	var dataMember;
	var Exprname;
	var FilterArray = [];
	
	this.SequencesSunburst = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	this.customPalette = [];
	this.isCustomPalette = false;
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
	
	this.setSequencesSunburst = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.SequencesSunburst['ComponentName'] = this.ComponentName;
		this.SequencesSunburst['Name'] = this.Name;
		this.SequencesSunburst['DataSource'] = this.dataSourceId;
		
		this.SequencesSunburst['DataItems'] = this.fieldManager.DataItems;
		this.SequencesSunburst['Arguments'] = this.fieldManager.Arguments;
		this.SequencesSunburst['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.SequencesSunburst;
		
		if (!(this.SequencesSunburst['Palette'])) {
			this.SequencesSunburst['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.SequencesSunburst.InteractivityOptions) {
			if (!(this.SequencesSunburst.InteractivityOptions.MasterFilterMode)) {
				this.SequencesSunburst.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.SequencesSunburst.InteractivityOptions.TargetDimensions)) {
				this.SequencesSunburst.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.SequencesSunburst.InteractivityOptions.IgnoreMasterFilters)) {
				this.SequencesSunburst.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.SequencesSunburst.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.SequencesSunburst['Legend'])) {
			this.SequencesSunburst['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if (!(this.SequencesSunburst['TextFormat'])) {
			this.SequencesSunburst['TextFormat'] = 'Argument, Value'
		}
		
		if(!this.SequencesSunburst.LayoutOption){
			this.SequencesSunburst.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
						color: '#555555'
					},
					Legend : {
						family: '맑은 고딕',
						size: 12
					}
			}
		}
		if(!this.SequencesSunburst['ZoomAble']){
			this.SequencesSunburst.ZoomAble = 'none'
		}
	};
	
	this.setSequencesSunburstforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setSequencesSunburst();
		}
		else{
			this.SequencesSunburst = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.SequencesSunburst['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.SequencesSunburst['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.SequencesSunburst['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.SequencesSunburst['Palette'])) {
			this.SequencesSunburst['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var SequencesSunburstOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SEQUENCES_SUNBURST_DATA_ELEMENT);
				
				$.each(SequencesSunburstOption,function(_i,_SequencesSunburstOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _SequencesSunburstOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _SequencesSunburstOption.CTRL_NM;
					}
					if(self.SequencesSunburst.ComponentName == CtrlNM){
						self.SequencesSunburst['Palette'] = _SequencesSunburstOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.SequencesSunburst.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.SequencesSunburst.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (!(this.SequencesSunburst['Legend'])) {
			this.SequencesSunburst['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if (!(this.SequencesSunburst['TextFormat'])) {
			this.SequencesSunburst['TextFormat'] = 'Argument, Value'
		}
		
		if(!this.SequencesSunburst.LayoutOption){
			this.SequencesSunburst.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
						color: '#555555'
					},
					Legend : {
						family: '맑은 고딕',
						size: 12
					}
			}
		}
		if(!this.SequencesSunburst['ZoomAble']){
			this.SequencesSunburst.ZoomAble = 'none'
		}
	}
	
	this.setSequencesSunburstForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setSequencesSunburst();
		}
		else{
			this.SequencesSunburst = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.SequencesSunburst['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.SequencesSunburst['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.SequencesSunburst['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.SequencesSunburst['Palette'])) {
			this.SequencesSunburst['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var SequencesSunburstOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SEQUENCES_SUNBURST_DATA_ELEMENT);
				
				$.each(SequencesSunburstOption,function(_i,_SequencesSunburstOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _SequencesSunburstOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _SequencesSunburstOption.CTRL_NM;
//					}
					if(self.SequencesSunburst.ComponentName == CtrlNM){
						self.SequencesSunburst['Palette'] = _SequencesSunburstOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.SequencesSunburst.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.SequencesSunburst.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (!(this.SequencesSunburst['Legend'])) {
			this.SequencesSunburst['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if (!(this.SequencesSunburst['TextFormat'])) {
			this.SequencesSunburst['TextFormat'] = 'Argument, Value'
		}
		
		if(!this.SequencesSunburst.LayoutOption){
			this.SequencesSunburst.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
						color: '#555555'
					},
					Legend : {
						family: '맑은 고딕',
						size: 12
					}
			}
		}
		if(!this.SequencesSunburst['ZoomAble']){
			this.SequencesSunburst.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setSequencesSunburst();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.SequencesSunburst);
			gDashboard.itemGenerateManager.generateItem(self, self.SequencesSunburst);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setSequencesSunburstforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.SequencesSunburst);
			gDashboard.itemGenerateManager.generateItem(self, self.SequencesSunburst);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.SequencesSunburst)) {
			this.setSequencesSunburstForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.SequencesSunburst);
			gDashboard.itemGenerateManager.generateItem(self, self.SequencesSunburst);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setSequencesSunburstForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.SequencesSunburst);
			gDashboard.itemGenerateManager.generateItem(self, self.SequencesSunburst);
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
		
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fSequencesSunburst(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
		self.trackingData = [];
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
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
	}
	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			d3.selectAll('#'+self.itemid+" .sunburst_container path").style("stroke", "white").style("stroke-width", 1).attr("filter", false);
			self.trackingData = [];
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
			self.fSequencesSunburst(self.filteredData, self.measures, self.dimensions, 
					self.resizeData);
			d3.selectAll('#'+self.itemid+' .sunburst_container path[filter="true"').style("stroke", "blue").style("stroke-width", 3)
		}
		gProgressbar.hide();
	};
	
	this.fSequencesSunburst = function(jsonData, measures, dimensions, dupleData) {
		$('#'+self.itemid+' svg').remove();
		$('#'+self.itemid+' div').remove();
		if(!$('#'+self.itemid).hasClass('sunburst_chart'))
			$('#'+self.itemid).addClass('sunburst_chart')
		if(gDashboard.itemGenerateManager.noDataCheck(self.filteredData, self)) return;
		self.resizeData = dupleData;
		self.paletteData = dupleData.names;
		var data = dupleData.data;
		var mapper = dupleData.nameMapper;
		
		// Dimensions of sunburst.
		var width = $('#'+self.itemid).width();
		var height = $('#'+self.itemid).height();
		var radius = Math.min(width, height) / 2 - 60;

		// Breadcrumb dimensions: width, height, spacing, width of tip/tail.
		var b = {
		  w: 120, h: 30, s: 3, t: 10
		};

		// Mapping of step names to colors.
		var colors = {};
		var palette = gDashboard.d3Manager.getPalette(self);
		
		for(var i = 0; i < self.paletteData.length; i++){
			colors[self.paletteData[i]] = palette[i%palette.length];
		}

		// Total size of all segments; we set this later, after loading the data.
		var totalSize = 0; 

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
									return "translate(" + width / 2 + "," + height / 2 + ")";
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
		

		var vis = d3.select("#"+self.itemid).append("svg:svg")
		    .attr("width", width)
		    .attr("height", height)
		    .append("svg:g")
		    .attr("class", "sunburst_container")
		    .attr("transform", "translate(" + width / 2 + "," + height / 2 + ")");
        
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}
		
		$('#'+self.itemid).append($('<div class="sunburst_main"><div class="sunburst_sequence"></div>'
				+'<div class="sunburst_chart"><div class="sunburst_explanation style="visibility: hidden;"><span class="sunburst_.percentage"></span></div></div> </div>'))
		var partition = d3.partition()
		    .size([2 * Math.PI, radius * radius]);

		var arc = d3.arc()
		    .startAngle(function(d) { return d.x0; })
		    .endAngle(function(d) { return d.x1; })
		    .innerRadius(function(d) { return Math.sqrt(d.y0); })
		    .outerRadius(function(d) { return Math.sqrt(d.y1); });

		// Use d3.text and d3.csvParseRows so that we do not need to have a header
		// row, and can receive the csv as an array of arrays.
		d3.text(createVisualization(data));

		// Main function to draw and set up the visualization, once we have the data.
		function createVisualization(json) {

		  // Basic setup of page elements.
		  initializeBreadcrumbTrail();
//		  drawLegend();
		  d3.select("#"+self.itemid + " .sunburst_togglelegend").on("click", toggleLegend);

		  // Bounding circle underneath the sunburst, to make it easier to detect
		  // when the mouse leaves the parent g.
		  vis.append("svg:circle")
		  .attr("r", radius)
		  .style("opacity", 0);

		  // Turn the data into a d3 hierarchy and calculate the sums.
		  var root = d3.hierarchy(json)
		  .sum(function(d) { return d.size; })
		  .sort(function(a, b) { return b.value - a.value; });

		  // For efficiency, filter nodes to keep only those large enough to see.
		  var nodes = partition(root).descendants()
		  .filter(function(d) {
			  return (d.x1 - d.x0 > 0.005); // 0.005 radians = 0.29 degrees
		  });

		  var path = vis.data([json]).selectAll("path")
		  .data(nodes)
		  .enter().append('g')

		  path.append("svg:path")
		  .attr("display", function(d) { return d.depth ? null : "none"; })
		  .attr("d", arc)
		  .attr("fill-rule", "evenodd")
		  .attr("filter", function(d){
			  var dim = mapper[d.data.name];
			  for(var i = 0; i < self.trackingData.length; i++){
				  if(self.trackingData[i][dim] === d.data.name){
					  return "true";
				  }
			  }
			  return "false";
		  })
		  .style("fill", function(d) { return colors[d.data.name]; })
		  .style("opacity", 1)
		  .attr("cursor", "pointer")
		  .on("mouseover", mouseover).on("click", mouseclick);
//		  개발예정 라벨 추가
//		  path.append("text")
//		  .text(function(d) { return d.depth === 0? '' : d.data.name})
//		  .classed("label", true)
//		  .attr("x", function(d) { return d.x; })
//		  .attr("text-anchor", "middle")
//		  // translate to the desired point and set the rotation
//		  .attr("transform", function(d) {
//			  if (d.depth > 0) {
//				  return "translate(" + arc.centroid(d) + ")" +
//				  "rotate(" + getAngle(d) + ")";
//			  }  else {
//				  return null;
//			  }
//		  })
//		  .attr("dx", "6") // margin
//		  .attr("dy", ".35em") // vertical-align
//		  .attr("pointer-events", "none");

		  function getAngle(d) {
			  // Offset the angle by 90 deg since the '0' degree axis for arc is Y axis, while
			  // for text it is the X axis.
			  var thetaDeg = (180 / Math.PI * (arc.startAngle()(d) + arc.endAngle()(d)) / 2 - 90);
			  // If we are rotating the text by more than 90 deg, then "flip" it.
			  // This is why "text-anchor", "middle" is important, otherwise, this "flip" would
			  // a little harder.
			  return (thetaDeg > 90) ? thetaDeg - 180 : thetaDeg;
		  }

		  // Add the mouseleave handler to the bounding circle.
		  d3.select("#" + self.itemid + " .sunburst_container").on("mouseleave", mouseleave);
		  d3.select("#" + self.itemid + " .sunburst_container").append("text").attr("class", "sunburst_percentage").style("font-size", "2em").attr("fill", self.meta.LayoutOption.Label.color).style('font-family', self.meta.LayoutOption.Label.family).attr("y", 10);
		  d3.select("#" + self.itemid + " .sunburst_container").append("text").attr("class", "sunburst_text").style("font-size", "1.5em").attr("fill", self.meta.LayoutOption.Label.color).style('font-family', self.meta.LayoutOption.Label.family).attr("y", -30);
		  
		  if(self.meta.Legend.Visible){
			  var size = 20
			    var xPos = width - 100;
			    
			    if(self.meta.Legend.Position.indexOf("Bottom") > -1){
			    	xPos = height - 50;
			    }
			    else if(self.meta.Legend.Position !== "TopRightVertical"){
			    	xPos = 30
			    }

			    if(self.meta.Legend.Position.indexOf("Center") > -1){
				    var maxIndex = Math.floor((width - 60)/120);
				    d3.select("#"+self.itemid + ' svg').selectAll("myrect")
				      .data(self.paletteData.slice(0, maxIndex))
				      .enter()
				      .append("circle")
				        .attr("cx", function(d,i){ return 20 + i*(size+100)})
				        .attr("cy", xPos+ size*.75)
				        .attr("r", 7)
				        .style("fill", function(d){ return colors[d]})

				    // Add labels beside legend dots
				    d3.select("#"+self.itemid + ' svg').selectAll("mylabels")
				      .data(self.paletteData.slice(0, maxIndex+1))
				      .enter()
				      .append("text")
				        .attr("x", function(d,i){ return 30 + i * (size + 100) + (size/2)})
				        .attr("y", xPos+ size*.8)
				        .style("fill", function(d){ return self.paletteData.length > maxIndex && self.paletteData[maxIndex] === d ? 'black' : colors[d]})
				        .text(function(d){ return self.paletteData.length > maxIndex && self.paletteData[maxIndex] === d ? '. . .' : d})
				       .style("font-size", self.meta.LayoutOption.Legend.size+'px')
				       .style('font-family', self.meta.LayoutOption.Legend.family)
				        .attr("text-anchor", "left")
				        .style("alignment-baseline", "middle")

			    }else{
			    	var maxIndex = Math.floor((height - 60)/25);
			    	d3.select("#"+self.itemid + ' svg').selectAll("myrect")
				      .data(self.paletteData.slice(0, maxIndex))
				      .enter()
				      .append("circle")
				        .attr("cx", xPos)
				        .attr("cy", function(d,i){ return 40 + i*(size+5)})
				        .attr("r", 7)
				        .style("fill", function(d){ return colors[d]})

				    // Add labels beside legend dots
				    d3.select("#"+self.itemid + ' svg').selectAll("mylabels")
				      .data(self.paletteData.slice(0, maxIndex + 1))
				      .enter()
				      .append("text")
				        .attr("x", xPos+ size*.8)
				        .attr("y", function(d,i){ return 30 + i * (size + 5) + (size/2)})
				        .style("fill", function(d){ return self.paletteData.length > 10 && self.paletteData[maxIndex] === d ? 'black' : colors[d]})
				        .text(function(d){ return self.paletteData.length > 10 && self.paletteData[maxIndex] === d ? '. . .' : d})
				        .style("font-size", self.meta.LayoutOption.Legend.size+'px')
				        .style('font-family', self.meta.LayoutOption.Legend.family)
				        .attr("text-anchor", "left")
				        .style("alignment-baseline", "middle")
			    	
//			    	d3.select("#"+self.itemid + ' svg').selectAll("myrect")
//				      .data(self.paletteData)
//				      .enter()
//				      .append("circle")
//				        .attr("cx", xPos)
//				        .attr("cy", function(d,i){ return 50 + i*(size+5)})
//				        .attr("r", 7)
//				        .style("fill", function(d){ return colors[d]})
//
//				    // Add labels beside legend dots
//				    d3.select("#"+self.itemid + ' svg').selectAll("mylabels")
//				      .data(self.paletteData)
//				      .enter()
//				      .append("text")
//				        .attr("x", xPos+ size*.8)
//				        .attr("y", function(d,i){ return 40 + i * (size + 5) + (size/2)})
//				        .style("fill", function(d){ return colors[d]})
//				        .text(function(d){ return d})
//				        .style("font-size", self.meta.LayoutOption.Legend.size+'px')
//				       .style('font-family', self.meta.LayoutOption.Legend.family)
//				        .attr("text-anchor", "left")
//				        .style("alignment-baseline", "middle")
			    }
		  }
		  // Get total size of the tree = value of root node from partition.
		  totalSize = path.datum().value;
		 };

		 function mouseclick(d){
			 var select = function(s) {
				 d3.select(s).style("stroke", "blue").style("stroke-width", 3).attr("filter", true);
			 }
			 
			 var unselect = function(s) {
				 d3.select(s).style("stroke", "white").style("stroke-width", 1).attr("filter", false);
			 }
			 
			 var unselectAll = function() {
				 d3.selectAll('#'+self.itemid+" .sunburst_container path").style("stroke", "white").style("stroke-width", 1).attr("filter", false);
			 }
			 
			 var dim = mapper[d.data.name];
			 var selectKey = d.data.name;
			 switch(self.IO.MasterFilterMode){
				 case 'Multiple':
					 var inArray = false;
					 var selectedData = {};
					 selectedData[dim] = selectKey;
					 if(d3.select(this).attr("filter") === "true"){
						 unselect(this);
					 }else{
						select(this);
					 }
					 for (var index = 0; index < self.trackingData.length; index++) {
						 if (self.trackingData[index][dim]!=undefined && self.trackingData[index][dim] === selectKey) {
							 self.trackingData.splice(index, 1);
							 index--;
							 inArray = true;
						 }
					 }
	
					 if (!inArray) {
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
	
					 if(d3.select(this).attr("filter") === "true"){
						 unselect(this);
					 }else{
						 unselectAll();
						 select(this);
	
						 var selectedData = {};
						 selectedData[dim] = selectKey;
						 
						 self.trackingData = [];
						 self.trackingData.push(selectedData);
					 }
					 /*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
	
					 gDashboard.filterData(self.itemid, self.trackingData);
				 break;
			 }
		 }
		// Fade all but the current sequence, and show it in the breadcrumb trail.
		 function mouseover(d) {

			 var labelFormat = 'Number',
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


			 if (self.meta.DataItems.Measure.length == 1) {
				 if(self.meta.DataItems.Measure[0].NumericFormat != undefined){
					 labelFormat = typeof self.meta.DataItems.Measure[0].NumericFormat.FormatType == 'undefined' ? labelFormat : self.meta.DataItems.Measure[0].NumericFormat.FormatType;
					 labelUnit = typeof self.meta.DataItems.Measure[0].NumericFormat.Unit == 'undefined'? labelUnit : self.meta.DataItems.Measure[0].NumericFormat.Unit;
					 labelPrecision = typeof self.meta.DataItems.Measure[0].NumericFormat.Precision == 'undefined' ? labelPrecision : self.meta.DataItems.Measure[0].NumericFormat.Precision;
					 labelSeparator = typeof self.meta.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator == 'undefined' ? labelSeparator : self.meta.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator;
					 labelSuffixEnabled = typeof self.meta.DataItems.Measure[0].NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : self.meta.DataItems.Measure[0].NumericFormat.SuffixEnabled;
					 labelSuffix = typeof self.meta.DataItems.Measure[0].NumericFormat.Suffix == 'undefined' ? labelSuffix : self.meta.DataItems.Measure[0].NumericFormat.Suffix;
				 }
			 } else {
				 $.each(self.meta.DataItems.Measure, function(i,k) {
					 if (self.currentMeasureName===k.Name) {
						 labelFormat = typeof k.NumericFormat.FormatType == 'undefined' ? '' : k.NumericFormat.FormatType;
						 labelUnit = typeof k.NumericFormat.Unit == 'undefined'? undefined : k.NumericFormat.Unit.substring(0,1);
						 labelPrecision = typeof k.NumericFormat.Precision == 'undefined' ? 2 : k.NumericFormat.Precision;
						 labelSeparator = typeof k.NumericFormat.IncludeGroupSeparator == 'undefined' ? true : k.NumericFormat.IncludeGroupSeparator;
						 labelSuffixEnabled = typeof k.NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : k.NumericFormat.SuffixEnabled;
						 labelSuffix = typeof k.NumericFormat.Suffix == 'undefined' ? labelSuffix : k.NumericFormat.Suffix;
						 return false;
					 }
				 });
			 }

			 var NumberF = WISE.util.Number;

			 var textValue="";
			 var textValue2 = "";

			 var sequenceArray = d.ancestors().reverse();
			 sequenceArray.shift(); // remove root node from the array

			 switch(self.meta.TextFormat){
			 case 'none': {
				 textValue ="";
				 break;
			 }
			 case 'Argument': {
				 $.each(sequenceArray, function(i, data){
					 if(textValue === "")
						 textValue += data.data.name;
					 else
						 textValue += ("-"+data.data.name);
				 });
				 break;
			 }
			 case 'Value': {
				 textValue = NumberF.unit(d.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
				 break;
			 }
			 case 'Argument, Value': {
				 $.each(sequenceArray, function(i, data){
					 if(textValue2 === "")
						 textValue2 += data.data.name;
					 else
						 textValue2 += ("-"+data.data.name);
				 });
				 textValue = NumberF.unit(d.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);	
				 break;
			 }
			 case 'Percent': {
				 var percentage = (100 * d.value / totalSize).toPrecision(3);
				 var textValue = percentage + "%";
				 if (percentage < 0.1) {
					 textValue = "< 0.1%";
				 }

				 break;
			 }
			 case 'Argument, Value, Percent': {
				 $.each(sequenceArray, function(i, data){
					 if(textValue2 === "")
						 textValue2 += data.data.name;
					 else
						 textValue2 += ("-"+data.data.name);
				 });
				 
				 var percentage = (100 * d.value / totalSize).toPrecision(3);
				 var textValue = percentage + "%";
				 if (percentage < 0.1) {
					 textValue = "< 0.1%";
				 }
				 
				 textValue = NumberF.unit(d.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + '(' + textValue + ')';	
				 break;
			 }
			 case 'Value, Percent': {
				 var percentage = (100 * d.value / totalSize).toPrecision(3);
				 var textValue = percentage + "%";
				 if (percentage < 0.1) {
					 textValue = "< 0.1%";
				 }
				 
				 textValue = NumberF.unit(d.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + '(' + textValue + ')';	

				  break;
			  }
			  case 'Argument, Percent': {
				  $.each(sequenceArray, function(i, data){
					  if(textValue2 === "")
						  textValue2 += data.data.name;
					  else
						  textValue2 += ("-"+data.data.name);
				  });

				  var percentage = (100 * d.value / totalSize).toPrecision(3);
				  var textValue = percentage + "%";
				  if (percentage < 0.1) {
					  textValue = "< 0.1%";
				  }

				  break;
			  }


			 }

			 d3.select("#" + self.itemid + " .sunburst_percentage")
			 .text(textValue);

			 d3.select("#" + self.itemid + " .sunburst_text")
			 .text(textValue2);

			 var textWidth = d3.select('.sunburst_percentage').node().getComputedTextLength();
			 d3.select("#" + self.itemid + " .sunburst_percentage").attr("x", -(textWidth / 2));
			 
			 textWidth = d3.select('.sunburst_text').node().getComputedTextLength();
			 d3.select("#" + self.itemid + " .sunburst_text").attr("x", -(textWidth / 2));

			 d3.select("#" + self.itemid + " .sunburst_explanation")
			 .style("visibility", "");

			 updateBreadcrumbs(sequenceArray, textValue);

			 // Fade all the segments.
			 d3.selectAll("#"+self.itemid+" path")
			 .style("opacity", 0.3);

			 // Then highlight only those that are an ancestor of the current segment.
			 vis.selectAll("#"+self.itemid+" path")
			 .filter(function(node) {
				 return (sequenceArray.indexOf(node) >= 0);
			 })
			 .style("opacity", 1);
		 }

		 // Restore everything to full opacity when moving off the visualization.
		 function mouseleave(d) {

			 // Hide the breadcrumb trail
			 d3.select("#" + self.itemid + " .sunburst_trail")
			 .style("visibility", "hidden");

			 // Deactivate all segments during transition.
			 d3.selectAll("#"+self.itemid+" path").on("mouseover", null);

			 d3.select("#" + self.itemid + " .sunburst_percentage").text("");
			 d3.select("#" + self.itemid + " .sunburst_text").text("");

			 // Transition each segment to full opacity and then reactivate it.
			 d3.selectAll("#"+self.itemid+" path")
			 .transition()
			 .duration(1000)
			 .style("opacity", 1)
			 .on("end", function() {
				 d3.select(this).on("mouseover", mouseover);
			 });

			 d3.select("#" + self.itemid + " .sunburst_explanation")
			 .style("visibility", "hidden");
		 }

		 function initializeBreadcrumbTrail() {
			 // Add the svg area.
			 var trail = d3.select("#" + self.itemid + " .sunburst_sequence").append("svg:svg")
			 .attr("width", width)
			 .attr("height", 50)
			 .attr("class", "sunburst_trail");
			 // Add the label at the end, for the percentage.
			 trail.append("svg:text")
			 .attr("class", "sunburst_endlabel")
			 .style("fill", self.meta.LayoutOption.Label.color)
			 .style('font-family', self.meta.LayoutOption.Label.family)
		 }

		 // Generate a string that describes the points of a breadcrumb polygon.
		 function breadcrumbPoints(d, i) {
			 var points = [];
			 points.push("0,0");
			 points.push(b.w + ",0");
			 points.push(b.w + b.t + "," + (b.h / 2));
			 points.push(b.w + "," + b.h);
			 points.push("0," + b.h);
			 if (i > 0) { // Leftmost breadcrumb; don't include 6th vertex.
				 points.push(b.t + "," + (b.h / 2));
			 }
			 return points.join(" ");
		 }

		 // Update the breadcrumb trail to show the current sequence and percentage.
		 function updateBreadcrumbs(nodeArray, percentageString) {

			 // Data join; key function combines name and depth (= position in sequence).
			 var trail = d3.select("#" + self.itemid + " .sunburst_trail")
			 .selectAll("g")
			 .data(nodeArray, function(d) { return d.data.name + d.depth; });

			 // Remove exiting nodes.
			 trail.exit().remove();

			 // Add breadcrumb and label for entering nodes.
			 var entering = trail.enter().append("svg:g");

			 entering.append("svg:polygon")
			 .attr("points", breadcrumbPoints)
			 .style("fill", function(d) { return colors[d.data.name]; });

			 entering.append("svg:text")
			 .attr("x", (b.w + b.t) / 2)
			 .attr("y", b.h / 2)
			 .attr("dy", "0.35em")
			 .attr("text-anchor", "middle")
			 .text(function(d) { return d.data.name.length > 10? d.data.name.slice(0, 9) + "..." : d.data.name });

			 // Merge enter and update selections; set position for all nodes.
			 entering.merge(trail).attr("transform", function(d, i) {
				 return "translate(" + i * (b.w + b.s) + ", 0)";
			 });

			 // Now move and update the percentage at the end.
			 d3.select("#" + self.itemid + " .sunburst_trail").select("#" + self.itemid + " .sunburst_endlabel")
			 .attr("x", (nodeArray.length + 0.5) * (b.w + b.s) + 30)
			 .attr("y", b.h / 2)
			 .attr("dy", "0.35em")
			 .attr("text-anchor", "middle")
			 .text(percentageString);

			 // Make the breadcrumb trail visible, if it's hidden.
			 d3.select("#" + self.itemid + " .sunburst_trail")
			 .style("visibility", "");

		 }

//		function drawLegend() {
//
//		  // Dimensions of legend item: width, height, spacing, radius of rounded rect.
//		  var li = {
//		    w: 75, h: 30, s: 3, r: 3
//		  };
//
//		  var legend = d3.select("#" + self.itemid + " .sunburst_legend").append("svg:svg")
//		      .attr("width", li.w)
//		      .attr("height", d3.keys(colors).length * (li.h + li.s));
//
//		  var g = legend.selectAll("g")
//		      .data(d3.entries(colors))
//		      .enter().append("svg:g")
//		      .attr("transform", function(d, i) {
//		              return "translate(0," + i * (li.h + li.s) + ")";
//		           });
//
//		  g.append("svg:rect")
//		      .attr("rx", li.r)
//		      .attr("ry", li.r)
//		      .attr("width", li.w)
//		      .attr("height", li.h)
//		      .style("fill", function(d) { return d.value; });
//
//		  g.append("svg:text")
//		      .attr("x", li.w / 2)
//		      .attr("y", li.h / 2)
//		      .attr("dy", "0.35em")
//		      .attr("text-anchor", "middle")
//		      .text(function(d) { return d.key; });
//		}

		function toggleLegend() {
		  var legend = d3.select("#" + self.itemid + " .sunburst_legend");
		  if (legend.style("visibility") == "hidden") {
		    legend.style("visibility", "");
		  } else {
		    legend.style("visibility", "hidden");
		  }
		}
	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self);
	}
};


WISE.libs.Dashboard.SequencesSunburstFieldManager = function() {
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
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
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
