WISE.libs.Dashboard.item.GeoPointMapGenerator = function(_mapType) {
	var self = this;
	
	this.type = 'GEOPOINT_MAP';
	this.mapType = _mapType;
	
	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	
	this.dimensions = [];
	this.measures = [];
	this.values = [];
	this.tracked;
	
	this.arguments = []; // pie map
	this.weight = {}; // bubble map
	this.value = {}; // geo point map
	this.paletteArray = ['#19CC7F','#FF8E60','#36AACE','#8C68C3','#67BF58','#FFDD74','#417CD9','#FF5D6A','#198AB8','#E26E4A'];
	this.latitude = {};
	this.longitude = {};
	this.coordinates = []; // longitude, latitude
	this.maxGroupCount;
	this.tooltipDimensions = [];
	this.tooltipMeasures = [];
	this.items;
	this.shapeTitleAttributeName;
	
	this.legend = {map:undefined, weight: undefined};
	
	this.panelManager;
	
	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	};
	
	/**
	 * @param _map: meta object
	 */
	this.getDxItemConfig = function(_map) {
		var viewArea = _map['ViewArea'];
		/* marker-layer definition */
		this.commonMarkerLayer = {
			type: 'marker',
			name: 'markerLayer',
			data: [],
			label: {
			    enabled: true,
			    dataField: 'text',
			    font: {
					color: '#000',
					weight: 500,
					size: 14
				}
			}
		};
		this.geoPointMarkerLayer = {
			elementType: 'dot',
			dataField: 'value',
			size: 15
		};
		this.bubbleMarkerLayer = {
			elementType: 'bubble',
			palette:'Default',
//			opacity: 0.8,
			dataField: 'value',
//			size: undefined,
			colorGroups: [],
			colorGroupingField: '',
			customize: function(elements) {

                for (var i = 0; i < elements.length; i++) {
					elements[i].applySettings({ borderWidth: 1});
					elements[i].applySettings({ borderColor: '#ffffff' }); 
                }
        	}
		};
		this.pieMarkerLayer = {
			elementType: 'pie',
			dataField: 'values',
			palette:'Default',
			customize: function(elements) {
                for (var i = 0; i < elements.length; i++) {
					elements[i].applySettings({ borderWidth: 1});
					elements[i].applySettings({ borderColor: '#ffffff' }); 
                }
        	}
		};
		
		/* legend definition */
		this.bubbleMapLegend = {
			source: { layer: "markerLayer", grouping: "size" },
			markerType: "circle",
			orientation: 'vertical',
			customizeText: function (_arg) {
				return _arg.start + " to " + _arg.end;
			}
		};
		this.bubbleColorMapLegend = {
			source: { layer: "markerLayer", grouping: "color" },
			orientation: ((this.legend.Orientation || '').toLowerCase() || 'vertical'),
			markerType: "circle",
			customizeText : function(_arg){
				return _arg.start;
			}
		};
		
		this.pieMapLegend = {
			source: { layer: "markerLayer", grouping: "color" },
			orientation: ((this.legend.map.Orientation || '').toLowerCase() || 'vertical'),
			markerType: "circle"
		};
		
		this.pieWeightMapLegend = {
			source: { layer: "markerLayer", grouping: "size" },
			markerType: "circle",
			orientation: 'vertical'
		};
		
		this.bubbleColorMapLegend = WISE.libs.Dashboard.item.MapGenerator.setLegendPostion(this.bubbleColorMapLegend, this.legend.Position);
		this.bubbleMapLegend = WISE.libs.Dashboard.item.MapGenerator.setLegendPostion(this.bubbleMapLegend, this.legend.weight.Position);
		this.pieMapLegend = WISE.libs.Dashboard.item.MapGenerator.setLegendPostion(this.pieMapLegend, this.legend.map.Position);
		this.pieWeightMapLegend = WISE.libs.Dashboard.item.MapGenerator.setLegendPostion(this.pieWeightMapLegend, this.legend.map.Position);
		
		var OverrideExtend = WISE.util.Object.overrideExtend;
		OverrideExtend(this.geoPointMarkerLayer, _.clone(this.commonMarkerLayer));
		OverrideExtend(this.bubbleMarkerLayer, _.clone(this.geoPointMarkerLayer));
		OverrideExtend(this.pieMarkerLayer, _.clone(this.commonMarkerLayer));
		// map definition
		var dxConfigs = {
			background: {
				borderColor: 'white'
			},
			layers: [{
				type: 'area',
				name: 'areaLayer',
				hoverEnabled: true,
				data: '',
				label: {
					enabled: this.shapeTitleAttributeName ? true : false,
					dataField: this.shapeTitleAttributeName
				}
			}],
//			center: [viewArea['CenterPointLongitude'], viewArea['CenterPointLatitude']],
//			bounds: [viewArea['LeftLongitude'], viewArea['TopLatitude'], viewArea['RightLongitude'], viewArea['BottomLatitude']],
			
			center: [Number(viewArea['CenterPointLongitude']), Number(viewArea['CenterPointLatitude'])],
			bounds: [Number(viewArea['LeftLongitude']), Number(viewArea['TopLatitude']), Number(viewArea['RightLongitude']), Number(viewArea['BottomLatitude'])],
			controlBar: {
			    enabled: false
		    },
		    wheelEnabled: _map['LockNavigation'],
		    panningEnabled: _map['LockNavigation'],
		    loadingIndicator: {
		    	show: true,
		    	backgroundColor: '#ededed',
		    	text: gMessage.get('WISE.message.page.common.loding')
		    },
		    legends:[],
			tooltip: {
				enabled: true,
				customizeTooltip: function (_marker) {
					if (_marker.layer.type === 'marker') {
						return {html: this.attribute('tooltipHtml')};
					}
					return '';
				}
			}
		};
		
		return dxConfigs;
	};
	
	/** @Override */
	this.generate = function(_map) {
//		var itemid = _map['ComponentName'] + '_item';
//		this.itemid = itemid;
		
		this.meta = _map;
		this.dataSourceId = _map['DataSource'];
		
		this.customShapefile = _map['CustomShapefile'];
		this.shapefileArea = _map['ShapefileArea'];
		this.shapeTitleAttributeName = _map['ShapeTitleAttributeName'];
		
		if (this.customShapefile) {
			this.shapelocation = WISE.Constants.context + WISE.Constants.shapeLocation + this.customShapefile['Data']['wiseShapeFileName'];
//			alert('wiseShapeFileName : ' + this.shapelocation);
		}
		
		this.DI = _map.DataItems;
		this.V = WISE.util.Object.toArray((_map['Values'] && _map['Values']['Value']) || []);
		this.A = WISE.util.Object.toArray((_map['Argument']) || []);
		this.W = (_map['Weight'] || {});
		this.V1 = (_map['Value'] || {});
		this.LATI = (_map['Latitude'] || {});
		this.LONGI = (_map['Longitude'] || {});
		this.TTD = WISE.util.Object.toArray((_map['TooltipDimensions'] && _map['TooltipDimensions']['TooltipDimension']) || []);
		this.TTM = WISE.util.Object.toArray((_map['TooltipMeasures'] && _map['TooltipMeasures']['TooltipMeasure']) || []);
		
		this.LGDM = (_map['MapLegend'] || {});
		this.LGDW = (_map['WeightedLegend'] || {});
		
		this.DU = WISE.libs.Dashboard.item.DataUtility;
		this.CU = WISE.libs.Dashboard.item.ChartUtility;
		this.CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
		
		this.SQLike = WISE.libs.Dashboard.Query.likeSql;
		
		this.panelManager = new WISE.libs.Dashboard.item.MapGenerator.PanelManager();
		this.panelManager.itemid = this.itemid;
		
		this.shapeTitleAttributeName = _map['ShapeTitleAttributeName'];
		
		// latitute setting 
		this.latitude = this.DU.getDataMember(this.LATI['UniqueName'], this.DI, this.dimensions);
		
		// longitude setting 
		this.longitude = this.DU.getDataMember(this.LONGI['UniqueName'], this.DI, this.dimensions);
		
		// longitude, latitute
		this.coordinates = [this.longitude, this.latitude];
		
		// tooltip dimensions
		this.tooltipDimensions = [];
		$.each(this.TTD, function(_i0, _a0) {
			var uniqueName = _a0['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			
			self.tooltipDimensions.push(dataMember);
		});
		
		// tooltip measures
		this.tooltipMeasures = [];
		$.each(this.TTM, function(_i0, _a0) {
			var uniqueName = _a0['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			
			self.tooltipMeasures.push(dataMember);
		});
		
		switch(self.mapType) {
		case 'GeoPointMap':
			this.value = this.DU.getDataMember(this.V1['UniqueName'], this.DI, this.dimensions, this.measures);
			this.values = [this.value];
			break;
		case 'BubbleMap':
			this.weight = this.DU.getDataMember(this.W['UniqueName'], this.DI, this.dimensions, this.measures);
			this.values = [this.weight];
			break;
		case 'PieMap':
			// arguments setting 
			this.arguments = [];
			$.each(this.A, function(_i0, _a0) {
				var uniqueName = _a0['UniqueName'];
				var dataMember = self.DU.getDataMember(uniqueName, self.DI, self.dimensions);
				self.arguments.push(dataMember);
				// self.values = self.CU.Series.Fn.getValues(self.V, self.DI, self.dimensions, self.measures);
			});
			
			self.values = self.CU.Series.Fn.getValues(self.V, self.DI, self.dimensions, self.measures);
			break;
		}
		
		// legend
		this.legend = {
			map: this.LGDM,
			weight: this.LGDW
		};

		// setting pie-chart top-icon
		this.renderButtons(this.itemid);
		
		this.panelManager.makePanel(this.values, this.arguments);
		
		// to display no-data text
		if (!this.CUSTOMIZED.get('searchOnStart','Config')) {
			this.bindData([]); 
		}
	};
	
	/** @Override */
	this.bindData = function(_data, _ativePanelId) {
		if (!this.tracked) {
			this.globalData = _.clone(_data);
			this.filteredData = _.clone(_data);
		}
		
		$("#" + this.itemid).empty();
		
		if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
			var nodataHtml = '<div class="nodata-layer"></div>';
			$("#" + this.itemid).empty().append(nodataHtml);
		}
		else {
			this.renderMap(_data, _ativePanelId);
		}
	};
	
	this.renderMap = function(_data, _ativePanelId) {
		this.panelManager.empty();
		this.panelManager.makePanel(this.values, this.arguments);

		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		var argumentDistinct = this.SQLike.fromJson(this.arguments, [], this.filteredData);
		var coordinateDistinct = this.SQLike.fromJson(this.coordinates, [], this.filteredData);
		// var data = this.SQLike.fromJson(this.dimensions, this.measures, this.filteredData);

		var longitudeName = self.coordinates[0].name;
		var latitudeName = self.coordinates[1].name;
		
		var tooltipFirstColumnStyle = 'font-weight:bold; padding-right:5px; text-align:right;';
		//generate map chart
		self.maxGroupCount = this.panelManager.valuePanel.length;
		
		$.each(this.panelManager.valuePanel, function(_pn, _ovp) {
			var markerLayer, dxConfigs = self.getDxItemConfig(self.meta);
			
			switch(self.mapType) {
			case 'GeoPointMap':
			case 'BubbleMap':
				if (self.mapType === 'GeoPointMap') {
					markerLayer = _.clone(self.geoPointMarkerLayer);
				}
				else {
					markerLayer = _.clone(self.bubbleMarkerLayer);
					if(self.meta.MapLegend.Visible){
						dxConfigs.legends.push(self.bubbleColorMapLegend)
					}
					if (self.legend.weight && self.legend.weight.Visible) {
//						WISE.util.Object.overrideExtend(legend, self.bubbleMapLegend);
						var colorGroupArray = self.gradientValue(_data, self.meta, self.values[0].name);
						
						dxConfigs.legends.push(self.bubbleMapLegend);
					}
					
				}
				$.each(coordinateDistinct, function(_i0, _d0) {
					var markerValues, dimensions = self.dimensions, measures = self.measures;

					if ($.type(self.tooltipDimensions) === 'array' && self.tooltipDimensions.length > 0) {
						dimensions = dimensions.concat(self.tooltipDimensions);	
					}
					if ($.type(self.tooltipMeasures) === 'array' && self.tooltipMeasures.length > 0) {
						measures = measures.concat(self.tooltipMeasures);	
					}

					/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
					gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
					markerValues = self.SQLike.fromJson(dimensions, measures, self.filteredData, {where: function() {return this[longitudeName] == _d0[longitudeName] && this[latitudeName] == _d0[latitudeName];}});
					var valueObject = self.values[0] || {summaryType:'',name:'',caption:''};
					var tooltipHtml = '<table>', tooltipMeasureHtml = '';
					var value = markerValues[0][valueObject.summaryType + '_' + valueObject.name];
					
					$.each(self.tooltipDimensions, function(_i1, _d1) {
						tooltipHtml += '<tr><td style="' + tooltipFirstColumnStyle + '">' + _d1.caption + ':</td><td style="text-align:right;">' + $.number(markerValues[0][_d1.name]) + '</td></tr>';
					});
						
					tooltipHtml += '<tr><td colspan="2" style="height:5px;"></td></tr>';
					tooltipHtml += '<tr><td style="' + tooltipFirstColumnStyle + '">' + valueObject.caption + ':</td><td style="text-align:right;">' + $.number(value,1) + '</td></tr>';
					tooltipHtml += '</talble>';
					
					$.each(self.tooltipMeasures, function(_i2, _d2) {
						tooltipHtml += '<tr><td style="' + tooltipFirstColumnStyle + '">' + _d2.caption + ':</td><td style="text-align:right;">' + $.number(markerValues[0][_d2.nameBySummaryType]) + '</td></tr>';
					});
					
					var markerData = {
						coordinates:[_d0[longitudeName], _d0[latitudeName]],
						attributes: {
							tooltipHtml: tooltipHtml,
							text: self.mapType === 'GeoPointMap' ? value : undefined,
							value: value
						},
					
					};
					
					markerLayer.data.push(markerData);
				}); // end of $.each
				
				var sizeGroup = new Array();
				var minVal = self.getJSONArrayMin(_data,self.values[0].name)[self.values[0].name];
				var maxVal = self.getJSONArrayMax(_data,self.values[0].name)[self.values[0].name];
				var gap = Number(((maxVal-minVal)/3).toFixed(2));
				sizeGroup.push(0);
				sizeGroup.push(minVal);
				for(var i=0;i<3;i++){
					minVal += gap;
					sizeGroup.push(Math.round(minVal));
				}
				markerLayer.sizeGroups = sizeGroup;

				markerLayer.colorGroups= colorGroupArray;
				
				if(typeof self.meta.GradientPalette != 'undefined'){
					var startColor = self.getHexColor(self.meta.GradientPalette.StartColor);
					var endColor = self.getHexColor(self.meta.GradientPalette.EndColor);
					markerLayer.palette = [startColor,endColor];
				}
				markerLayer.colorGroupingField= 'value';
				dxConfigs.layers.push(markerLayer);
				break;
			case 'PieMap':
				markerLayer = _.clone(self.pieMarkerLayer);
				
				var legendTextArray = [];
				var argumentsName = self.arguments.length === 1 ? self.arguments[0].name : '';
				var Grouping = self.getGroups(argumentsName,_data);
				
				if(argumentsName){
					var colorgroup = [];
					for(var i=0; i<=Grouping.length;++i){
						colorgroup.push(i);
					}
					markerLayer.elementType = "bubble";
					markerLayer.colorGroupingField= argumentsName+'_groupIndex';
					markerLayer.colorGroups = colorgroup;
					markerLayer.palette= self.paletteArray;
					
					var sizeGroup = new Array();
					var minVal = self.getJSONArrayMin(_data,self.values[0].name)[self.values[0].name];
					var maxVal = self.getJSONArrayMax(_data,self.values[0].name)[self.values[0].name];
					var gap = Number(((maxVal-minVal)/3).toFixed(2));
					sizeGroup.push(0);
					sizeGroup.push(minVal);
					for(var i=0;i<3;i++){
						minVal += gap;
						sizeGroup.push(Math.round(minVal));
					}
					markerLayer.data =  {
		                    type: 'FeatureCollection'
	                };
					markerLayer.sizeGroups = sizeGroup;
				}
				
				var markerData = [];
				$.each(coordinateDistinct, function(_i0, _d0) {
					// var markerValues = self.SQLike.fromJson('*', [], data, {where: function() {return this[longitudeName] == _d0[longitudeName] && this[latitudeName] == _d0[latitudeName];}});
					var markerValues, dimensions = self.dimensions, measures = self.measures;
					if ($.type(self.tooltipDimensions) === 'array' && self.tooltipDimensions.length > 0) {
						dimensions = dimensions.concat(self.tooltipDimensions);	
					}
					if ($.type(self.tooltipMeasures) === 'array' && self.tooltipMeasures.length > 0) {
						measures = measures.concat(self.tooltipMeasures);	
					}
					/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
					gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
					markerValues = self.SQLike.fromJson(dimensions, measures, self.filteredData, {where: function() {return this[longitudeName] == _d0[longitudeName] && this[latitudeName] == _d0[latitudeName];}});
					
					var tooltipDimensValue = {}, values = [],texts = {};	
					var valueHtml = '', tooltipHtml = '<table>', tooltipMeasureHtml = '';
					$.each(markerValues, function(_i1, _d1) {
						
						if (_i1 === 0) {
							$.each(self.tooltipDimensions, function(_i2, _d2) {
								tooltipHtml += '<tr><td style="' + tooltipFirstColumnStyle + '">' + _d2.caption + ':</td><td style="text-align:right;">' + $.number(_d1[_d2.name]) + '</td></tr>';
							});
						}
						
						var val, valueText;
						if (argumentsName) {
							val = _d1[_ovp.value.summaryType + '_' + _ovp.value.name];
							values.push(val);
							valueText = _d1[argumentsName];
							valueHtml += '<tr><td style="' + tooltipFirstColumnStyle + '">' + valueText + ':</td><td style="text-align:right;">' + $.number(val,1) + '</td></tr>';

							/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
							gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
							var colorGroups = self.SQLike.fromJson(self.arguments, [], self.filteredData,[]);
							
							if(legendTextArray.length == 0){
								$.each(colorGroups,function(_i,_e){
									
									legendTextArray.push(_e[argumentsName]);
								});
								legendTextArray.push('endString');
							}
							$.each(Grouping,function(_i,_gro){
								if(_gro['name'] == _d1[argumentsName]){
									texts = _d1;
									texts[argumentsName+'_groupIndex'] = _i;
									return false;
								}
							});
							tooltipHtml += '<tr><td colspan="2" style="height:5px;"></td></tr>';
							tooltipHtml += valueHtml;
							tooltipHtml += '<tr><td colspan="2" style="height:5px;"></td></tr>';
							tooltipHtml += tooltipMeasureHtml;
							tooltipHtml += '</talble>';
							_d1['tooltipHtml'] = tooltipHtml;
							_d1['values'] = values;
							markerData.push(self.createFeature(_d1));
						}
						else {
							$.each(self.values, function(_i3, _vd3) {
								val = _d1[_vd3.summaryType + '_' + _vd3.name];
								values.push(val);
								
								valueHtml += '<tr><td style="' + tooltipFirstColumnStyle + '">' + _vd3.caption + ':</td><td style="text-align:right;">' + $.number(val,1) + '</td></tr>';
								
								if (_i0 === 0) {
									legendTextArray.push(_vd3.caption);
								}
							});
							tooltipHtml += '<tr><td colspan="2" style="height:5px;"></td></tr>';
							tooltipHtml += valueHtml;
							tooltipHtml += '<tr><td colspan="2" style="height:5px;"></td></tr>';
							tooltipHtml += tooltipMeasureHtml;
							tooltipHtml += '</talble>';
						}
						
						// tooltip measures
						$.each(self.tooltipMeasures, function(_i4, _d4) {
							if (tooltipDimensValue[_d4.name] === undefined) tooltipDimensValue[_d4.name] = 0;
							tooltipDimensValue[_d4.name] += _d1[_d4.nameBySummaryType];
						});
						if (_i1 === (markerValues.length - 1)) {
							$.each(self.tooltipMeasures, function(_i4, _d4) {
								tooltipMeasureHtml += '<tr><td style="' + tooltiFirstColumnStyle + '">' + _d4.caption + ':</td><td style="text-align:right;">' + $.number(tooltipDimensValue[_d4.name]) + '</td></tr>';
							});
							// reset
							tooltipDimensValue = 0;
						}
					});
					if(argumentsName){
						markerLayer.data['features'] = markerData;
					}
					else{
						markerData = {
							coordinates: [_d0[longitudeName], _d0[latitudeName]],
							attributes:{
								tooltipHtml: tooltipHtml,
								values: values,
							}
						};
						markerLayer.data.push(markerData);
					}
				}); // end of $.each(coordinateDistinct)
				
				/* legend */
				if (self.legend.map && self.legend.map.Visible) {
					if(argumentsName){
						var legend = {customizeText: function (_arg) {
							var group = Grouping[_arg.start];  
							return group.name;
						}};
					}
					else{
						var legend = {customizeText: function (_arg) {
							return legendTextArray[_arg.index];
						}};
					}
					// extend parent object
					WISE.util.Object.overrideExtend(legend, self.pieMapLegend);
					
					dxConfigs.legends.push(legend);
				}
				if(self.legend.weight && self.legend.weight.Visible){
					if(argumentsName){
						dxConfigs.legends.push(self.bubbleMapLegend);
					}
				}
				dxConfigs.layers.push(markerLayer);
				break;
			} // end of switch(self.mapType)
			
			// instance map
			var areaLayer = dxConfigs.layers[0];
			var parseSources = { shp: self._base64ToArrayBuffer(self.meta.CustomShapefile.Data.ShapeData), dbf: self._base64ToArrayBuffer(self.meta.CustomShapefile.Data.AttributeData)},
		    parseOptions = { precision: 2 },
		    data = DevExpress.viz.vectormaputils.parse(parseSources, parseOptions);
			areaLayer.data = data;
//			switch(self.shapefileArea) {
//			case 'Europe':
//				areaLayer.data = DevExpress.viz.map.sources.europe;
//				break;
//			case 'Asia':
//				dxConfigs.zoomFactor = 1.41; 
//				dxConfigs.center = [117.993, 57.500]; 
//				dxConfigs.bounds = [-180, 85, 180, -60]; 
//				areaLayer.data = DevExpress.viz.map.sources.world;
//				break;
//			case 'NorthAmerica':
//				dxConfigs.zoomFactor = 1.45; 
//				dxConfigs.center = [-109.971, 64.990]; 
//				dxConfigs.bounds = [-180, 85, 180, -60]; 
//				areaLayer.data = DevExpress.viz.map.sources.world;
//				break;
//			case 'SouthAmerica':
//				dxConfigs.zoomFactor = 3.00; 
//				dxConfigs.center = [-69.995, -26.998]; 
//				dxConfigs.bounds = [-180, 85, 180, -60]; 
//				areaLayer.data = DevExpress.viz.map.sources.world;
//				break;
//			case 'Africa':
//				areaLayer.data = DevExpress.viz.map.sources.africa;
//				break;
//			case 'USA':
//				dxConfigs.zoomFactor = 0.5;
//				areaLayer.data = DevExpress.viz.map.sources.usa;
//				break;
//			case 'Canada':
//				areaLayer.data = DevExpress.viz.map.sources.canada;
//				break;
//			default:
//				if (self.customShapefile) {
//					dxConfigs.bounds[0] = dxConfigs.bounds[0] - 5;
//					dxConfigs.bounds[1] = dxConfigs.bounds[1] + 0.5;
//					
//					if (self.CUSTOMIZED.get('useShapeFile')) {
//						_ovp.useShapeFile = true;
//						_ovp.shapelocation = self.shapelocation;
//					} else {
////						areaLayer.data = map_south_korea;
//						areaLayer.data = WISE.Constants.context+'/resources/mapdata/state.geojson';
//					}
//					
//				} else {
//					dxConfigs.zoomFactor = 1.00;
//					dxConfigs.center = [0.000, 46.036];
//					dxConfigs.bounds = [-180, 85, 180, -60]; 
//					areaLayer.data = DevExpress.viz.map.sources.world;
//				}
//			}
			
			_ovp.dxConfigs = dxConfigs;
		}); // end of $.each(this.panelManager.valuePanel)
		
		if (!_ativePanelId) {
			// 맨 처음 value-panel만 active 시킨다.
			$.each(this.panelManager.valuePanel, function(_pn, _ovp) {
				_ativePanelId = _pn;
				return false;
			});
		}
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		self.panelManager.activeValuePanel(_ativePanelId);
	};
	
	this.renderButtons = function(_itemid) {
		var buttonPanerlId = _itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanerlId);
		
		if (this.values && this.values.length > 1) {
			// value-panel selection
			var valueListId = _itemid + '_topicon_vl';
			var popoverid = _itemid + '_topicon_vl_popover';
			
			var listHtml = '<li><a id="' + valueListId + '" href="#"><img src="' + WISE.Constants.context + '/images/cont_box_icon_layer.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer.png\'" alt="Select Panel" title="Select Panel"></a></li>';
			topIconPanel.append(listHtml);
			
			var popoverHtml = '<div id="' + popoverid + '"><ul style="width: 150px">';
			$.each(this.values, function(_i, _vo) {
				popoverHtml += '<li style="clear: both; cursor: pointer;" data-key="' + (self.itemid + '_' + _vo.uniqueName) + '">' + _vo.caption + '</li>';
			});
			popoverHtml += '</ul></div>';
			$('body').append(popoverHtml);
			
			var popover = $("#" + popoverid).dxPopover({
				target: "#" + valueListId,
				position: "bottom",	
				shading: false,
				shadingColor: "rgba(0, 0, 0, 0.5)"
			}).dxPopover("instance");

			$("#" + valueListId).click(function() {popover.show();});
			
			$('#' + popoverid).on('click', function(_e) {
				popover.hide();
				
				var targetPanelId = _e.target.getAttribute('data-key');
				self.panelManager.activeValuePanel(targetPanelId);
			});
		}
	};
	this._base64ToArrayBuffer = function(base64) {
		var binary_string;
		if(WISE.Constants.browser =='IE7' || WISE.Constants.browser =='IE8' || WISE.Constants.browser =='IE9'){
			binary_string = atob(base64);
		}
		else{
			binary_string = window.atob(base64);
		}
		var len = binary_string.length;
		var bytes = new Uint8Array( len );
		for (var i = 0; i < len; i++)        {
		    bytes[i] = binary_string.charCodeAt(i);
		}
		return bytes.buffer;
	}
	this.getJSONArrayMax = function(arr, prop) {
	    var max;
	    for (var i=0 ; i<arr.length ; i++) {
	        if (!max || parseInt(arr[i][prop]) > parseInt(max[prop]))
	            max = arr[i];
	    }
	    return max;
	};
	this.getJSONArrayMin = function(arr, prop) {
	    var min;
	    for (var i=arr.length ; i>0 ; i--) {
	        if (!min || parseInt(arr[i][prop]) < parseInt(min[prop]))
	            min = arr[i];
	    }
	    return min;
	};
	this.gradientValue = function(_data,meta,colNm){
		var valueRange = {}; 



		var RangeStop, returnGroup = new Array();
		if(typeof meta.CustomScale == 'undefined'){// %단위 & RangeStop 10
			RangeStop = [0,10,20,30,40,50,60,70,80,90];
			var maxJson = (self.getJSONArrayMax(_data,colNm)),minJson = (self.getJSONArrayMin(_data,colNm));
			var minVal = minJson[colNm], gap = maxJson[colNm] - minJson[colNm];

			returnGroup.push(minVal);
			for(var i=1;i<RangeStop.length;i++){
				returnGroup.push(Math.round(minVal+gap*(RangeStop[i]/100)));
			}
			returnGroup.push(maxJson[colNm]);
		
		}
		else if(typeof meta.CustomScale.PercentScale != 'undefined'){
			RangeStop = meta.CustomScale.RangeStop;
			if(meta.CustomScale.PercentScale == 'true'){ // %단위 & RangeStop 랜덤
//				var maxJson = (self.getJSONArrayMax(_data,colNm)),minJson = (self.getJSONArrayMin(_data,colNm));
//				var minVal = minJson[colNm], gap = maxJson[colNm] - minJson[colNm];

				
			}
			else{ //절대 단위 & RangeStop 랜덤
				RangeStop.push(self.CUSTOMIZED.get('rangeStopMaxValue'));
				returnGroup = RangeStop;
				
			}
			
		}
		

		return returnGroup;
	};
	this.getHexColor = function(number){
	    return "#"+((number)>>>0).toString(16).slice(-6);
	};
	
	this.getGroups = function(name, items) {
	     var counts = {},
	         groups = [],
	         indexes = {},
	         othersCount = 0,
	     othersGroupName = 'Others';
	     
	     // Get the count of each different value
		for (var i = 0; i < items.length; ++i) {
		     var item = items[i],
		         value = item[name];
		     counts[value] = (counts[value] | 0) + 1;
		 }
	 
		 // Convert the counts into a groups array
		 for (var key in counts) {
		     if ( counts.hasOwnProperty(key) ) {
		         groups.push({
		             name: key,
		             count: counts[key]
		         });
		     }
		 }
	 
		 // Sort by count, then by name
		 groups.sort(function(a, b) { return (b.count - a.count) || (( a.name < b.name ) ? -1 : 1 ); });
	 
		 // Consolidate groups with lesser items
		 if (self.maxGroupCount && groups.length > self.maxGroupCount) {
		     for (var i = self.maxGroupCount - 1; i < groups.length; ++i) {
		         othersCount = othersCount + groups[i].count;
		     }
		     groups = groups.slice(0, self.maxGroupCount - 1);
		 }
		 
		 // Sort by name if configured
//		 if (sortAlphabetically) {
//		     groups.sort(function(a, b) { return ( a.name < b.name ) ? -1 : 1 ; }); // At this point there shouldn't be different groups with the same name.
//		 }
		
		 // Create group indexes dictionary for easier access on next step
		 for (var i = 0; i < groups.length; ++i) {
		     indexes[groups[i].name] = i;
		 }
		 
		 // Assign the group index and label to each item
		 for (var i = 0; i < items.length; ++i) {
			     var item = items[i],
			         value = item[name],
			         label = value,
			         index = indexes[value];
			     
			     // Index won't exist for groups consolidated
			 if (index === null || typeof(index) === 'undefined') {
				 index = groups.length;
				 label = othersGroupName + '\n(' + label + ')'
			 }
		
			 item[name + '_groupIndex'] = index;
			 item[name + '_label'] = label;
		 }
		
		 // If there are consolidated groups add the group at the end
		     if (othersCount > 0) {
		         groups.push({
		             name: othersGroupName,
		             count: othersCount
		         });
		     }
		     
		 return groups;
	};
	self.createFeature = function(properties) {
        return {
            type: 'Feature',
            geometry: {
                type: 'Polygon',
                coordinates: [properties[self.coordinates[0].name], properties[self.coordinates[1].name]]
            },
            properties: properties
        }
    }
}