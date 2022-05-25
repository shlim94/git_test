WISE.libs.Dashboard.item.RadialTidyTreeGenerator = function() {
	var self = this;

	this.type = 'RADIAL_TIDY_TREE';

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
	
	this.RadialTidyTree = [];
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
	
	this.setRadialTidyTree = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.RadialTidyTree['ComponentName'] = this.ComponentName;
		this.RadialTidyTree['Name'] = this.Name;
		this.RadialTidyTree['DataSource'] = this.dataSourceId;
		
		this.RadialTidyTree['DataItems'] = this.fieldManager.DataItems;
		this.RadialTidyTree['Arguments'] = this.fieldManager.Arguments;
		this.RadialTidyTree['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.RadialTidyTree.HiddenMeasures = self.fieldManager.HiddenMeasures;
		
		this.meta = this.RadialTidyTree;
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.RadialTidyTree.InteractivityOptions) {
			if (!(this.RadialTidyTree.InteractivityOptions.MasterFilterMode)) {
				this.RadialTidyTree.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.RadialTidyTree.InteractivityOptions.TargetDimensions)) {
				this.RadialTidyTree.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.RadialTidyTree.InteractivityOptions.IgnoreMasterFilters)) {
				this.RadialTidyTree.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.RadialTidyTree.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.RadialTidyTree.LayoutOption){
			this.RadialTidyTree.LayoutOption = {
					Label : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
					}
			}
		}
		if(!this.RadialTidyTree['ZoomAble']){
			this.RadialTidyTree.ZoomAble = 'none'
		}
	};
	
	this.setRadialTidyTreeforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setRadialTidyTree();
		}
		else{
			this.RadialTidyTree = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.RadialTidyTree['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.RadialTidyTree['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.RadialTidyTree['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.RadialTidyTree.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.RadialTidyTree.InteractivityOptions) {
			if (!(this.RadialTidyTree.InteractivityOptions.MasterFilterMode)) {
				this.RadialTidyTree.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.RadialTidyTree.InteractivityOptions.TargetDimensions)) {
				this.RadialTidyTree.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.RadialTidyTree.InteractivityOptions.IgnoreMasterFilters)) {
				this.RadialTidyTree.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.RadialTidyTree.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.RadialTidyTree.LayoutOption){
			this.RadialTidyTree.LayoutOption = {
					Label : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
					}
			}
		}
		if(!this.RadialTidyTree['ZoomAble']){
			this.RadialTidyTree.ZoomAble = 'none'
		}
	}
	
	this.setRadialTidyTreeForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setRadialTidyTree();
		}
		else{
			this.RadialTidyTree = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.RadialTidyTree['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.RadialTidyTree['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.RadialTidyTree['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.RadialTidyTree.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		if(!this.RadialTidyTree.LayoutOption){
			this.RadialTidyTree.LayoutOption = {
					Label : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
					}
			}
		}
		if(!this.RadialTidyTree['ZoomAble']){
			this.RadialTidyTree.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setRadialTidyTree();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.RadialTidyTree);
			gDashboard.itemGenerateManager.generateItem(self, self.RadialTidyTree);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setRadialTidyTreeforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.RadialTidyTree);
			gDashboard.itemGenerateManager.generateItem(self, self.RadialTidyTree);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.RadialTidyTree)) {
			this.setRadialTidyTreeForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.RadialTidyTree);
			gDashboard.itemGenerateManager.generateItem(self, self.RadialTidyTree);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setRadialTidyTreeForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.RadialTidyTree);
			gDashboard.itemGenerateManager.generateItem(self, self.RadialTidyTree);
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
		self.fRadialTidyTree(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
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
				d3.selectAll('#'+self.itemid + ' circle').attr("r", 2.5).style('stroke', 'none').style('fill', '').attr("filter", "false");
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
			self.fRadialTidyTree(self.filteredData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('#' + self.itemid + ' circle[filter="true"]').style("fill", "white").attr("r", 4).style("stroke", "steelblue").style("stroke-width", "2");
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		
//		self.fRadialTidyTree(self.filteredData, self.measures, self.dimensions, 
//				self.deleteDuplecateData(self.filteredData));
//		d3.selectAll('.bubbles[filter="true"]').style('stroke', 'black').style('stroke-width', 2).style('stroke-opacity', 0.7).attr("filter", "true");
//		gProgressbar.hide();
//	};
	
	this.fRadialTidyTree = function(jsonData, measures, dimensions, dupleData) {
		
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		self.resizeData = dupleData;
		d3.select("#"+self.itemid).selectAll('svg').remove();
		d3.select("#"+self.itemid).selectAll('div').remove();


		var	width = $("#"+self.itemid).width(),
		height = $("#"+self.itemid).height()

		// append the svg object to the body of the page
		var svg = d3.select("#"+self.itemid)
		.append("svg")
		.attr("width", width)
		.attr("height", height);

		var g = svg.append("g").attr("transform", "translate(" + (width / 2 ) + "," + (height / 2) + ")");

		var stratify = d3.stratify()
		.parentId(function(d) { return d.id.substring(0, d.id.lastIndexOf(";")); });

		var tree = d3.tree()
		.size([360, width < height? width / 2.5 : height / 2.5])
		.separation(function(a, b) { return (a.parent == b.parent ? 1 : 2) / a.depth; });

		var root = tree(stratify(dupleData));

		var link = g.selectAll(".link")
		.data(root.descendants().slice(1))
		.enter().append("path")
		.attr("class", "link")
		.attr("d", function(d) {
			return "M" + project(d.x, d.y)
			+ "C" + project(d.x, (d.y + d.parent.y) / 2)
			+ " " + project(d.parent.x, (d.y + d.parent.y) / 2)
			+ " " + project(d.parent.x, d.parent.y);
		});



		var node = g.selectAll(".node")
		.data(root.descendants())
		.enter().append("g")
		.attr("class", function(d) { return "node" + (d.children ? " node--internal" : " node--leaf"); })
		.attr("transform", function(d) { return "translate(" + project(d.x, d.y) + ")"; });

		node.append("circle")
		.attr("cursor", "pointer")
		.attr("r", 2.5)
		.attr("class", function(d){ return '_'+d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length) })
		.attr("filter", function(d){
			var inArray = false;
			if(d.depth != 0){
				var selectedData = {};
				selectedData[self.dimensions[d.depth - 1].name] = d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length);
				for (var index = 0; index < self.trackingData.length; index++) {
					if (self.trackingData[index][self.dimensions[d.depth - 1].name] && self.trackingData[index][self.dimensions[d.depth - 1].name] === selectedData[self.dimensions[d.depth - 1].name]) {
						inArray = true;
						break;
					}
				}
			}
			return inArray? "true" : "false";
		})
		.on("click", function(d){
            switch(self.meta.InteractivityOptions.MasterFilterMode){
				case 'Multiple':
					var inArray = false;
					var selectedData = {};
					selectedData[self.dimensions[d.depth - 1].name] = d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length);
					if(d3.select('._'+d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length)).attr("filter") === 'true'){
						d3.selectAll('._'+d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length)).style('stroke', 'none').attr("r", 2.5).style('fill', '').attr("filter", "false")
						for (var index = 0; index < self.trackingData.length; index++) {
							if (self.trackingData[index][self.dimensions[d.depth - 1].name] && self.trackingData[index][self.dimensions[d.depth - 1].name] === selectedData[self.dimensions[d.depth - 1].name]) {
								self.trackingData.splice(index, 1);
								index--;
								inArray = true;
								break;
							}
						}
					}else{
						d3.selectAll('._'+d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length)).style("fill", "white").attr("r", 4).style("stroke", "steelblue").style("stroke-width", "2").attr("filter", "true");
						var selectedData = {};
						selectedData[self.dimensions[d.depth - 1].name] = d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length);
						
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
					if(d3.select('._'+d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length)).attr("filter") === 'true'){
						d3.selectAll('#'+self.itemid + ' circle').style('stroke', 'none').attr("r", 2.5).style('fill', '').attr("filter", "false");
						self.trackingData = [];
					}else{
						d3.selectAll('#'+self.itemid + ' circle').style('stroke', 'none').attr("r", 2.5).style('fill', '').attr("filter", "false");
						d3.selectAll('._'+d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length)).style("fill", "white").attr("r", 4).style("stroke", "steelblue").style("stroke-width", "2").attr("filter", "true");
						var selectedData = {};
						selectedData[self.dimensions[d.depth - 1].name] = d.id.slice(d.id.lastIndexOf(';') + 1, d.id.length);
						
						self.trackingData = [selectedData];
					}
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
			}
		});

		node.append("text")
		.attr("dy", ".31em")
		.attr("x", function(d) { return d.x < 180 === !d.children ? 6 : -6; })
		.style("text-anchor", function(d) { return d.x < 180 === !d.children ? "start" : "end"; })
		.attr("transform", function(d) { return "rotate(" + (d.x < 180 ? d.x - 90 : d.x + 90) + ")"; })
		.style("fill",  self.RadialTidyTree.LayoutOption.Label.color)
		.style("font-size", self.RadialTidyTree.LayoutOption.Label.size + 'px')
		.style("font-family", self.RadialTidyTree.LayoutOption.Label.family)
		.text(function(d) { return d.id.substring(d.id.lastIndexOf(";") + 1); });

		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}

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
					if(d3.event.transform.k < 1){
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

		function project(x, y) {
			var angle = (x - 90) / 180 * Math.PI, radius = y;
			return [radius * Math.cos(angle), radius * Math.sin(angle)];
		}
	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	};
};


WISE.libs.Dashboard.RadialTidyTreeFieldManager = function() {
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
