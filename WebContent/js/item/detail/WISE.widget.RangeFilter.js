WISE.libs.Dashboard.item.RangeFilterGenerator = function() {
	var self = this;

	this.type = 'RANGE_FILTER';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	this.dimensions = [];
	this.measures = [];
	
	this.arguments = [];
	this.seriesDimensions = [];
	/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
	this.dxItemBasten = [];
	
	this.selectedChartType;
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	var filterArray = new Array();
	var filterArray2 = new Array();
	/**
	 * @param _item:
	 *            meta object
	 */
	this.getDxItemConfig = function(_item) {
		this.seriresType = _item['Series']['Simple']['SeriesType'];
		var dxConfigs = {
			dataSource:'datasource',
			chart: {
				commonSeriesSettings:{
					type : this.seriresType,
					argumentsField : "arg",
				},
				series : []
			},
			onValueChanged:function(_e){
				var filterjson;
				filterArray = new Array();
				$.each(self.arguments,function(_i,_js){
					$.each(_e.value,function(_j,_val){
						filterjson = new Object();
						filterjson[_js.name] = _val;
						filterArray.push(filterjson);
					})
				});
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				gDashboard.filterData(self.itemid, filterArray);
			}
		};
//		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
//		var CustomConfigs = $.extend({}, Configurations);
//		$.extend(CustomConfigs, dxConfigs);
		return dxConfigs;
	};

	/** @Override */
	this.generate = function(_range, _options) {
		if(_options && _options.containerid){
			this.itemid = _options.containerid;
		}
		this.meta = _range;
		this.dataSourceId = _range['DataSource'];
		
		this.DI = _range.DataItems;
		this.S = WISE.util.Object.toArray((_range.Series) || []);
		this.A = WISE.util.Object.toArray((_range.Argument) || []);
		this.SD = WISE.util.Object.toArray((_range.SeriesDimensions && _range.SeriesDimensions.SeriesDimension)||[]);
		this.M = WISE.util.Object.toArray(this.DI['Measure']);
		
		this.DU = WISE.libs.Dashboard.item.DataUtility;
		this.CU = WISE.libs.Dashboard.item.ChartUtility;
		
		this.arguments = [];
		$.each(this.A, function(_i,_a){
			var uniqueName = _a['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI, self.dimensions);
			self.arguments.push(dataMember);
		});
		
		this.measures = [];
		$.each(this.M, function(_i,_m){
			var uniqueName = _m['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			self.measures.push(dataMember);
		});
		this.seriesDimensions = this.CU.Series.Fn.getSeriesDimensions(this.SD,this.DI);
		this.renderType = this.getRenderType();
	};
	
	this.getRenderType = function(){
		if(this.seriesDimensions.length ===0){
			return 'ARGUMENTS-ONLY';
		}
		else if(this.seriesDimensions.length > 0){
			return 'ARGUMENTS-AND-SERIESDIMENSIONS';
		}
		else{
			return undefined;

		}
	}
	
	this.getChartData = function(seriesType){
		var SQLLike =  WISE.libs.Dashboard.Query.likeSql;
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		
		var dimensions = [];
		dimensions = dimensions.concat(_.clone(this.seriesDimensions));
		dimensions = dimensions.concat(_.clone(this.dimensions));
		
		var queryData = SQLLike.fromJson(dimensions, this.measures, this.filteredData);
		switch(this.renderType){
		case 'ARGUMENTS-ONLY':
			_.each(queryData,function(_data){
				var argArray = [];
				_.each(self.arguments,function(_arg){
					argArray.push(_data[_arg.name]);
				});
				_data['arg'] = argArray.reverse().join('<br/>');
			});
			break;
		case 'ARGUMENTS-AND-SERIESDIMENSIONS':
			var dataset = [];
			var seriesDimensionColumnNames = [];
			var orderBy = [];
			orderBy = orderBy.concat(self.arguments);
			orderBy = orderBy.concat(self.seriesDimensions);
			
			queryData = SQLLike.fromJson('*',[],queryData,{orderBy:orderBy});
			_.each(queryData,function(_e){
				var column = [];
				_.each(self.seriesDimensions, function(_se){
					column.push(_e[_se.name]);
				});
				seriesDimensionColumnNames.push(column.join('-'));
			});
			
			_.each(queryData,function(_e){
				var column = [];
				_.each(self.seriesDimensions,function(_se){
					column.push(_e[_se.name]);
				});
				
				var argName = [];
				_.each(self.arguments,function(_arg){
					argName.push(_e[_arg.name]);
				});
				
				var subDataSet = [];
				_.each(self.measures,function(_m){
					var columnNamePrefix = column.join('-');
					
					var d = {};
					d['arg'] = argName.reverse().join('<br/>');
					d[columnNamePrefix + '-' + _m.caption] = _e[_m.nameBySummaryType];
					subDataSet.push(d);
				});
				var rowData = {};
				_.each(subDataSet,function(_dao){
					$.each(_dao,function(_k,_do){
						if(!rowData[_k])
							rowData[_k] = _dao[_k];
					});
				});
				dataset.push(rowData);
			});
			
			queryData = {seriesDimensionColumnNames : seriesDimensionColumnNames, data:dataset};
			break;
		}
		return queryData;
	}
	
	/** @Override */
	this.bindData = function(_data,_options) {
		if (!this.tracked) {
			this.globalData = _.clone(_data);
			this.filteredData = _.clone(_data);
		}
//		$("#"+this.itemid).empty();
		
		if(!_data || (_data.length === 0)){
//			var nodataHtml = '<div class="nodata-layer"></div>';
//			$("#" + this.itemid).empty().append(nodataHtml);
		}
		else{
//			$("#"+this.itemid).children().remove();
			this.renderChart(_data,_options);
		}
	};
	this.renderChart = function(_data,_options){
		
		if(this.selectedChartType){
			_options = !_options ? {} : _options;
			_options.seriesType = this.selectedChartType
		}
		var queriedData, seriesDimensionColumnNames;
		var dataset = this.getChartData();
		if ($.type(dataset) === 'array') {
			queriedData = dataset;
		}
		else {
			queriedData = dataset.data;
			seriesDimensionColumnNames = dataset.seriesDimensionColumnNames;
		}
		
		
		var dxConfigs = this.getDxItemConfig(this.meta);
		
		$.each(self.measures,function(_i,_js){
			var checkArr = new Array();
			var inputtingArr = new Array();
			if(typeof seriesDimensionColumnNames != 'undefined'){
				$.each(seriesDimensionColumnNames,function(_j,_SDCN){
					var currentValueFieldName = _SDCN+"-"+_js.caption;
					if($.inArray(currentValueFieldName,checkArr) ==-1){
						checkArr.push(currentValueFieldName);
					}
				});
				$.each(checkArr,function(_i,_value){
					var checkObj = new Object();
					checkObj.valueField = _value
					inputtingArr.push(checkObj);
				})
			}
			else{
				var checkObj = new Object();
				checkObj.valueField = _js.nameBySummaryType;
				inputtingArr.push(checkObj); 
			}
			dxConfigs.chart.series = inputtingArr;
		});
		
		dxConfigs.dataSource = queriedData;
		this.dxItem = $("#" + this.itemid).dxRangeSelector(dxConfigs).dxRangeSelector('instance');
	};
};
