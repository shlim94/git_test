/**
 * 2020.08.10 MKSON DOGFOOT
 * 모든 D3아이템의 공통 부분은 이곳에서 관리
 */

WISE.libs.Dashboard.item.D3Manager = function() {
	var self = this;
	
	//data 조회 하는 부분
	this.getDataSource = function(_d3Item, _type, _options){
		//_options { data, measureKey }
		var _data = _options.data;
		var MeasureKey = _options.measerKey;
		
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var dataSourceId = _d3Item.dataSourceId;
		var result = '';
		
		var ValueArray = new Array();
		var FieldArray = new Array();
		var selectArray = new Array();
		
		var Dimension = _d3Item.meta.DataItems.Dimension? WISE.util.Object.toArray(_d3Item.meta.DataItems.Dimension) : [];
		var setDimension = function(_dimension){
			$.each(_dimension,function(_i,_Dim){
				selectArray.push(_Dim.DataMember);
				FieldArray.push(_Dim.DataMember);
			});
		};
		
		var setDimensionNoMeta = function(_dimension){
			$.each(_dimension,function(_i,_Dim){
				selectArray.push(_Dim.name);
				FieldArray.push(_Dim.name);
			});
		};
		
		var setMeasure = function(_measure){
			$.each(_measure,function(_i,_Mea){
				selectArray.push('|'+_Mea.summaryType+'|');
				selectArray.push(_Mea.name);
				//2020.02.07 mksong sqllike 적용 dogfoot
				selectArray.push('|as|');
				selectArray.push(_Mea.captionBySummaryType);
			});
		};
		
		var setHiddenMeasure = function(_hiddenMeasure){
			$.each(_hiddenMeasure,function(_i,_hm){
				if(_dim.sortByMeasure){
					selectArray.push('|'+_hm.summaryType+'|');
					selectArray.push(_hm.name);
					//2020.02.07 mksong sqllike 적용 dogfoot
					selectArray.push('|as|');
					selectArray.push(_hm.name);
				}
			});
		};
		
		var setSqlConfigWhere = function(_sqlConfig){
			 /*dogfoot 데이터 집합이 같을 때만 where 절 추가 shlim 20200619*/
			if(typeof _d3Item.dataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
				if(_d3Item.dataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
					_sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				}else{
					_sqlConfig.Where = [];
				}
			}else{
				_sqlConfig.Where = [];
	        }
			
			if(_d3Item.meta.InteractivityOptions)
				if(_d3Item.meta.InteractivityOptions.IgnoreMasterFilters || _d3Item.meta.InteractivityOptions.MasterFilterMode !== "Off")
					_sqlConfig.Where = [];
		};
		
		var setMeasureNoSummary = function(_measure){
			$.each(_measure,function(_i,_mea){
				selectArray.push(_mea.name);
				FieldArray.push(_mea.name);
			});
		}
		
		
		
		switch(_type){
			case 'WATERFALL_CHART':
			case 'RECTANGULAR_ARAREA_CHART':
			case 'WORD_CLOUD':
			case 'PARALLEL_COORDINATE':
			case 'WORD_CLOUD_V2':
			case 'DENDROGRAM_BAR_CHART':
				/**
				 * 데이터 중복 제거 코드
				 */
				var Measure =  WISE.util.Object.toArray(MeasureKey);
				_d3Item.selectedMeasure = Measure
				
				setDimension(Dimension);
				setMeasure(Measure);
				//2020.02.07 mksong sqllike 적용 dogfoot
				var sqlConfig ={};
				
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
	//			sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _d3Item.filteredData;
				ValueArray.push(_d3Item.filteredData);
				
				var resultArr = new Array();
				$.each(ValueArray,function(_i,_e){
					$.each(_e,function(_item,_obj){
						var str = new Array();
						var object = new Object();
						$.each(Dimension,function(_i,_Dim){
							str.push(_obj[_Dim.DataMember]);
						});
						$.each(Measure,function(_i,_Mea){
							if(_Mea.captionBySummaryType){
								object['value'] = _obj[_Mea.captionBySummaryType];
							}else{
								object['value'] = _obj[_Mea.summaryType + '_'+ _Mea.caption];
							}
						});
						
						object['name'] = str.join(' - ');
						resultArr.push(object);
					})
				});
				result = resultArr;
				break;
			case 'HEATMAP':
			case 'HEATMAP2':
				var Measure =  WISE.util.Object.toArray(MeasureKey);
				_d3Item.selectedMeasure = Measure
				
				setDimension(Dimension);
				$.each(Measure,function(_i,_Mea){
					selectArray.push('|'+_Mea.summaryType+'|');
					selectArray.push(_Mea.name);
					//2020.02.07 mksong sqllike 적용 dogfoot
					selectArray.push('|as|');
					selectArray.push(_Mea.captionBySummaryType);
					
					selectArray.push('|'+_Mea.summaryType+'|');
					selectArray.push(_Mea.name);
					//2020.02.07 mksong sqllike 적용 dogfoot
					selectArray.push('|as|');
					selectArray.push(_Mea.name);
				});
				setHiddenMeasure(_d3Item.HiddenMeasure);
				//2020.02.07 mksong sqllike 적용 dogfoot
				var sqlConfig ={};
				
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
	//			sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;
//				sqlConfig.OrderBy = [_d3Item.dimensions[0].sortByMeasure? _d3Item.dimensions[0].sortByMeasure :  _d3Item.dimensions[0].name, '|'+_d3Item.dimensions[0].sortOrder+'|']
//				sqlConfig.OrderBy.push(_d3Item.dimensions[1].sortByMeasure? _d3Item.dimensions[1].sortByMeasure :  _d3Item.dimensions[1].name, '|'+_d3Item.dimensions[1].sortOrder+'|');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _d3Item.filteredData;
				ValueArray.push(_d3Item.filteredData);
				
				var resultArr = new Array();
				$.each(ValueArray,function(_i,_e){
					$.each(_e,function(_item,_obj){
						var str = new Array();
						var object = new Object();
						$.each(Dimension,function(_i,_Dim){
							str.push(_obj[_Dim.DataMember]);
						});
						$.each(Measure,function(_i,_Mea){
							if(_Mea.captionBySummaryType){
								object['value'] = _obj[_Mea.captionBySummaryType];
							}else{
								object['value'] = _obj[_Mea.summaryType + '_'+ _Mea.caption];
							}
						});
						
						object['name'] = str.join(' - ');
						resultArr.push(object);
					})
				});
				
				var dimX = SQLikeUtil.doSqlLike(_d3Item.dataSourceId, {
					'GroupBy' : [_d3Item.dimensions[0].name],
					'Select' : [_d3Item.dimensions[0].name, '|as|', 'dimension', '|min|', _d3Item.dimensions[0].sortByMeasure? _d3Item.dimensions[0].sortByMeasure : MeasureKey.name, '|as|', 'value'],
					'OrderBy' : [_d3Item.dimensions[0].sortByMeasure?"value" : _d3Item.dimensions[0].name, '|'+_d3Item.dimensions[0].sortOrder+'|'],
					'Where' : sqlConfig.Where
					}, _d3Item)

				var dimY = SQLikeUtil.doSqlLike(_d3Item.dataSourceId, {
					'GroupBy' : [_d3Item.dimensions[1].name],
					'Select' : [_d3Item.dimensions[1].name, '|as|', 'dimension', '|min|', _d3Item.dimensions[1].sortByMeasure? _d3Item.dimensions[1].sortByMeasure : MeasureKey.name, '|as|', 'value'],
					'OrderBy' : [_d3Item.dimensions[1].sortByMeasure?"value" : _d3Item.dimensions[1].name, '|'+_d3Item.dimensions[1].sortOrder+'|'],
					'Where' : sqlConfig.Where
					}, _d3Item)
					
				result = {
					data : resultArr,
					dimX : dimX,
					dimY : dimY
				};
				break;
			case 'HISTOGRAM_CHART':
				var Measure =  WISE.util.Object.toArray(MeasureKey);
				_d3Item.selectedMeasure = Measure;
				
				setMeasureNoSummary(Measure);
				
				//2020.02.07 mksong sqllike 적용 dogfoot
				var sqlConfig ={};
				 /*dogfoot 데이터 집합이 같을 때만 where 절 추가 shlim 20200619*/
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
	//			sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
//				sqlConfig.GroupBy = FieldArray;
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _d3Item.filteredData;
				ValueArray.push(_d3Item.filteredData);
				
				var resultArr = new Array();
				$.each(ValueArray,function(_i,_e){
					$.each(_e,function(_item,_obj){
						var str = new Array();
						var object = new Object();
						$.each(Measure,function(_i,_Mea){
								object['value'] = _obj[_Mea.name];
						});
						resultArr.push(object);
					})
				});
				result = resultArr;
				break;
			case 'BUBBLE_D3':
			case 'FORCEDIRECT':
			case 'FORCEDIRECTEXPAND':
				var ValueArray2 = new Array();	
//				var Measure =  WISE.util.Object.toArray(MeasureKey);	
//					
//				$.each(_d3Item.measures,function(_i,_Mea){	
//					if(_type === 'BUBBLE_D3')
//						selectArray.push('|'+_Mea.summaryType+'|');
//					else
//						selectArray.push('|sum|');
//					selectArray.push(_Mea.name);	
//					//2020.02.05 mksong SQLLIKE doSqlLike ForceDirect 적용 dogfoot	
//					selectArray.push('|as|');	
//					selectArray.push(_Mea.captionBySummaryType);	
//				})	
				$.each(Dimension,function(_i,_Dim){	
					if(_i == 0){	
						selectArray.push(_Dim.DataMember);	
						FieldArray.push(_Dim.DataMember);	
						var sqlConfig ={};	
						sqlConfig.Select = selectArray;	
						sqlConfig.From = _data;	
						sqlConfig.GroupBy = FieldArray;	
						setSqlConfigWhere(sqlConfig);
						/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */	
						//var queryData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, self.cubeQuery);	
						//ValueArray.push(queryData);	
						_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item); 	
						_d3Item.csvData = _d3Item.filterdData;	
						ValueArray.push(_d3Item.filteredData);					
					}else{	
						selectArray.push(_Dim.DataMember);	
						FieldArray.push(_Dim.DataMember);	
						var sqlConfig ={};	
						sqlConfig.Select = selectArray;	
						sqlConfig.From = _data;	
						sqlConfig.GroupBy = FieldArray;	
						setSqlConfigWhere(sqlConfig);
						/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */	
						_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item); 	
						_d3Item.csvData = _d3Item.filterdData;	
						ValueArray2.push(_d3Item.filteredData);	
					}	
				});	
					
				$.each(ValueArray[0],function(_i,_val){	
					ValueArray[0][_i]["children"]= new Array();	
					$.each(ValueArray2[0],function(_j,_val2){	
						if(_val[Dimension[0].DataMember] == _val2[Dimension[0].DataMember] ){	
							ValueArray[0][_i]["children"].push(_val2);	
						}else{	
								
						}	
					});	
				});	
				result = ValueArray;
				break;
			case 'SYNCHRONIZED_CHARTS':
				var tempResultConfig = SQLikeUtil.fromJsonForCaptionBySummaryType(_d3Item.dimensions, _d3Item.measures.concat(_d3Item.HiddenMeasures), [], { orderBy: _d3Item.dimensions });
				setSqlConfigWhere(tempResultConfig);
				
				var tempResult = SQLikeUtil.doSqlLike(_d3Item.dataSourceId, tempResultConfig, _d3Item);

				_d3Item.filteredData = tempResult;
				_d3Item.csvData = _d3Item.filteredData;
				
				var resultArr = [];
				$.each(_d3Item.filteredData, function(i, data){
					var tempData = {};
					$.each(_d3Item.measures, function(_j, _mea){
						tempData[_mea.caption] = data[_mea.captionBySummaryType];
					});

					var dimNames = [];
					for(var k = 0; k < _d3Item.dimensions.length; k++){
						dimNames.push(data[_d3Item.dimensions[k].caption]);
					}
					tempData['dimension'] = dimNames.join(' - ');
					resultArr.push(tempData);
				})
				
				result = resultArr;
				
				break;
			case 'SCATTER_PLOT' :
			case 'SCATTER_PLOT2' :
			case 'COORDINATE_LINE':
			case 'COORDINATE_DOT':
				var tempResultConfig = SQLikeUtil.fromJsonForCaptionBySummaryType(_d3Item.dimensions, _d3Item.measures, [], { orderBy: _d3Item.dimensions });
				setSqlConfigWhere(tempResultConfig);
				
				var dimNames = [];
				var check = false;
				tempResultConfig.Select = [];
				
				$.each(_d3Item.dimensions, function(i, dim){
					if(dimNames.indexOf(dim.caption) > -1){
						return true;
					}else{
						dimNames.push(dim.caption);
						tempResultConfig.Select.push(dim.name, '|as|', dim.caption);
					}
				})
				
				var meaNames = [];
				$.each(_d3Item.measures, function(i, mea){
					if(meaNames.indexOf(mea.caption) > -1){
						return true;
					}else{
						meaNames.push(mea.caption);
						tempResultConfig.Select.push('|'+mea.summaryType+'|', mea.name, '|as|', mea.caption);
					}
				})
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				/* DOGFOOT mksong 2020-08-06 카드 오타 및 마스터필터 무시 오류 수정 */
				var tempResult = SQLikeUtil.doSqlLike(_d3Item.dataSourceId, tempResultConfig, _d3Item);

				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = tempResult;
				_d3Item.csvData = _d3Item.filteredData;
				
				if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && _d3Item.calculatedFields.length > 0) {
					var fieldList = gDashboard.customFieldManager.fieldInfo[_d3Item.dataSourceId];
					if (fieldList) {
						fieldList.forEach(function(field) {
							gDashboard.customFieldManager.addCustomFieldsToDataSource(field, _d3Item.filteredData);
						});
					}
				}
				
				var resultArr = [];
//				console.log(tempResult);
				if(gDashboard.reportType != 'StaticAnalysis'){
                    $.each(_d3Item.filteredData, function(i, data){
						var tempData = {};
						tempData[_d3Item.dimensions[0].caption] = data[_d3Item.dimensions[0].caption];
						tempData[_d3Item.dimensions[1].caption] = data[_d3Item.dimensions[1].caption];
						if(_d3Item.measures.length > 0)
							tempData[_d3Item.measures[0].captionBySummaryType] = data[_d3Item.measures[0].caption];
						var dimNames = [];
						for(var i = 2; i < _d3Item.dimensions.length; i++){
							dimNames.push(data[_d3Item.dimensions[i].caption]);
						}
						tempData['dimension'] = dimNames.join(' - ');
						resultArr.push(tempData);
					})
                }else{
                	$.each(_d3Item.dimensions,function(_j,_dim){
                		if(_dim.Container){
                			
                		}
                	})
                	 $.each(_d3Item.filteredData, function(i, data){
                 		$.each(_d3Item.dimensions,function(_j,_dim){
                 			if(_j != 0){
                 				var tempData = {};
          						tempData[_d3Item.dimensions[0].caption] = data[_d3Item.dimensions[0].caption];
          						tempData[_d3Item.dimensions[1].caption] = data[_dim.caption];
          						
          						if(_d3Item.measures.length > 0)
          							tempData[_d3Item.measures[0].captionBySummaryType] = data[_d3Item.measures[0].caption];
          						var dimNames = [];
          						
          						dimNames.push(_dim.caption);
          						
          						tempData['dimension'] = dimNames.join(' - ');
          						tempData['dimensionNm'] = _dim.caption;
          						resultArr.push(tempData);
                 			}
                 		})
  					})
                }
				
				result = resultArr;
				break;
			case 'SCATTER_PLOT_MATRIX':
//				var tempResultConfig = SQLikeUtil.fromJsonForCaptionBySummaryType(_d3Item.dimensions, _d3Item.measures, [], { orderBy: _d3Item.dimensions });
//				setSqlConfigWhere(tempResultConfig);
				
				$.each(_d3Item.dimensions,function(_i,_dim){
//					selectArray.push('|'+_Mea.summaryType+'|');
					selectArray.push(_dim.name);
					selectArray.push('|as|');
					selectArray.push(_dim.caption);
					FieldArray.push(_dim.name);
				});
				
				
				$.each(_d3Item.measures, function(i, mea){
					for(var j = 0; j < tempResultConfig.Select.length; j++){
						if(mea.captionBySummaryType === tempResultConfig.Select[j]){
							tempResultConfig.Select[j] = mea.caption;
						}
					}
					for(var j = 0; j < tempResultConfig.OrderBy.length; j++){
						if(mea.captionBySummaryType === tempResultConfig.OrderBy[j]){
							tempResultConfig.OrderBy[j] = mea.caption;
						}
					}
				})
				
				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
	//			sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;

				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				/* DOGFOOT mksong 2020-08-06 카드 오타 및 마스터필터 무시 오류 수정 */
				var tempResult = SQLikeUtil.doSqlLike(_d3Item.dataSourceId, sqlConfig, _d3Item);

				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = tempResult;
				_d3Item.csvData = _d3Item.filteredData;
				
				if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && _d3Item.calculatedFields.length > 0) {
					var fieldList = gDashboard.customFieldManager.fieldInfo[_d3Item.dataSourceId];
					if (fieldList) {
						fieldList.forEach(function(field) {
							gDashboard.customFieldManager.addCustomFieldsToDataSource(field, _d3Item.filteredData);
						});
					}
				}
				
				var resultArr = [];
				_d3Item.paletteData = [];
//				console.log(tempResult);
				 if(gDashboard.reportType != "StaticAnalysis"){
	                	$.each(_d3Item.filteredData, function(i, data){
							var tempData = {};
							tempData[_d3Item.dimensions[0].caption] = data[_d3Item.dimensions[0].caption];
							tempData[_d3Item.dimensions[1].caption] = data[_d3Item.dimensions[1].caption];
							tempData[_d3Item.dimensions[2].caption] = data[_d3Item.dimensions[2].caption];
							tempData[_d3Item.dimensions[3].caption] = data[_d3Item.dimensions[3].caption];
							var dimNames = [];
							for(var i = 4; i < _d3Item.dimensions.length; i++){
								dimNames.push(data[_d3Item.dimensions[i].caption]);
							}
							tempData['dimension'] = dimNames.join(' - ');
							if(_d3Item.paletteData.indexOf(tempData['dimension']) === -1) _d3Item.paletteData.push(tempData.dimension); 
							resultArr.push(tempData);
						})
	                }else{
	                	$.each(_d3Item.filteredData, function(i, data){
							var tempData = {};
							$.each(_d3Item.dimensions,function(_j,_dimData){
								tempData[_dimData.caption] = data[_dimData.caption];
							})
							var dimNames = [];
							for(var i = 0; i < _d3Item.dimensions.length; i++){
								dimNames.push(data[_d3Item.dimensions[i].caption]);
							}
							tempData['dimension'] = dimNames.join(' - ');
							if(_d3Item.paletteData.indexOf(tempData['dimension']) === -1) _d3Item.paletteData.push(tempData.dimension); 
							resultArr.push(tempData);
						})
	                }
				
				result = resultArr;
				break;
			case 'SEQUENCES_SUNBURST' :
//				var Dimension = WISE.util.Object.toArray(this.meta.DataItems.Dimension);
				var Measure =  WISE.util.Object.toArray(MeasureKey);
				
				setDimension(Dimension);
				setMeasure(Measure);
				//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.OrderBy = [];
				$.each(_d3Item.dimensions, function(_i, _d) {
					
					if(_d.sortByMeasure){
						$.each(Measure,function(_i,_Mea){
							if(_Mea.name === _d.sortByMeasure){
								if(sqlConfig.OrderBy.indexOf(_Mea.captionBySummaryType) === -1)
									sqlConfig.OrderBy.push(_Mea.captionBySummaryType);
								return false;
							}
						});
					}else
						sqlConfig.OrderBy.push(_d.name);
					
					sqlConfig.OrderBy.push('|'+_d.sortOrder+'|');
				});
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;

				if(self.IO) {
					if(_d3Item.IO.IgnoreMasterFilters){
						sqlConfig.Where = [];
						sqlConfig.From = [];
					}
				}
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
//				_d3Item.filteredData = gDashboard.itemGenerateManager.doQueryCSVData(self, {'measureKey' : MeasureKey, 'data' : data});
				_d3Item.csvData = _d3Item.filteredData;
//				self.initDrillDownData(_d3Item.filteredData);
							
//				ValueArray.push(SQLike.q(sqlConfig));
				ValueArray.push(_d3Item.filteredData);
				
				var root = {"name": "root", "children": []};
				var names = [];
				var mapper = {};
				var sum = 0;
				for(var i = 0; i< _d3Item.filteredData.length; i++){
					var parts = [];
					$.each(_d3Item.dimensions, function(index, dim){
						parts.push(_d3Item.filteredData[i][dim.name]);
						if(names.indexOf(_d3Item.filteredData[i][dim.name]) < 0){
							names.push(_d3Item.filteredData[i][dim.name]);
							mapper[_d3Item.filteredData[i][dim.name]] = dim.name;
						}
					})
					var size = _d3Item.filteredData[i][Measure[0].captionBySummaryType];
					sum += size;
					if(isNaN(size))
						continue;
					
					var currentNode = root;
					
					for (var j = 0; j < parts.length; j++) {
						var children = currentNode["children"];
						var nodeName = parts[j];
						var childNode;
						if (j + 1 < parts.length) {
							// Not yet at the end of the sequence; move down the tree.
							var foundChild = false;
							for (var k = 0; k < children.length; k++) {
								if (children[k]["name"] == nodeName) {
									childNode = children[k];
									foundChild = true;
									break;
								}
							}
							// If we don't already have a child node for this branch, create it.
							if (!foundChild) {
								childNode = {"name": nodeName, "children": []};
								children.push(childNode);
							}
							currentNode = childNode;
						} else {
							// Reached the end of the sequence; create a leaf node.
							childNode = {"name": nodeName, "size": size};
							children.push(childNode);
						}
					}
				}
				result = {
						data : root,
						names : names,
						nameMapper : mapper,
						sum : sum
				}
				break;
			case 'HIERARCHICAL_EDGE':
			case 'DEPENDENCY_WHEEL' :
				/**
				 * 데이터 중복 제거 코드
				 */

				var Dimension = WISE.util.Object.toArray(_d3Item.meta.DataItems.Dimension);

				setDimension(Dimension);

				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;
				
				sqlConfig.OrderBy = [];
				$.each(Dimension, function(_i, _d) {
					//2020.02.07 mksong sqllike 적용 dogfoot
					sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
				});
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _.cloneDeep(_d3Item.filteredData);
				var newData = [];

				$.each(Dimension, function(_ii, dim) {
					newData.push({name: dim.Name, imports: []});
					$.each(_d3Item.filteredData, function(_i, data) {
						var duple = true;
						$.each(newData, function(_iii, newdata) {
							if(newdata.name == data[dim.Name]) {
								duple = false;
							}
							
							for(var key in data) {
								if(key == dim.Name && newdata.name == key) {
									if(data[key] && data[key] != "") {
										newdata.imports.push(data[key]);
									}
								}
							}
						});
						if(data[dim.Name] != "" && duple) {
							newData.push({name: data[dim.Name], imports: []});
						}
					});
				});
				
				$.each(Dimension, function(_ii, dim) {
					$.each(_d3Item.filteredData, function(_i, data) {
						$.each(newData, function(_ii, newdata) {
							if(data[dim.Name] == newdata.name) {
								for(var key in data) {
									if(data[key] && data[key] != "" && key != newdata.name) {
										newdata.imports.push(data[key]);
									}
								}
							}
						});
					});
				});
				
				_d3Item.filteredData = newData;
				result = _d3Item.filteredData;
				break;
			case 'SANKEY_CHART':
			case 'BIPARTITE_CHART':

				var Dimension = WISE.util.Object.toArray(_d3Item.meta.DataItems.Dimension);
				var Measure =  WISE.util.Object.toArray(MeasureKey);

				setDimension(Dimension);

//				$.each(Measure,function(_i,_Mea){
//					selectArray.push('|sum|');
//					selectArray.push(_Mea.name);
//					selectArray.push('|as|');
//					selectArray.push(_Mea.captionBySummaryType);			
//				});

				var sqlConfig = {};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;
				
				sqlConfig.OrderBy = [];
				$.each(Dimension, function(_i, _d) {
					//2020.02.07 mksong sqllike 적용 dogfoot
					sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
				});
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				ValueArray.push(_d3Item.filteredData);

				var resultArr = [];
				if(_type === 'SANKEY_CHART'){
					$.each(ValueArray,function(_i,_e){
						$.each(_e,function(_item,_obj){
							var valArray = new Array();
							var linkIndex = 0; 
							$.each(_.keys(_obj),function(_index, _key){
								if(_index != _.keys(_obj).length-1){
									var linkObject = {"source":_obj[_key],"target":_obj[_.keys(_obj)[_index+1]], "value":1};
									resultArr.push(linkObject);
								}
							});
							
//							if(Measure.length == 0){
//								valArray.push(1);
//							}else{
//								$.each(Measure,function(_i,_Mea){
//									valArray.push(_obj[_Mea.captionBySummaryType]);
//								});	
//							}
						});
					});
					
//					$.each(ValueArray,function(_i,_e){
//						$.each(_e,function(_item,_obj){
//							var valArray = new Array();
//							var object = new Object();
//							$.each(Dimension,function(_i,_Dim){
//								valArray.push(_obj[_Dim.DataMember]);
//							});
//							if(Measure.length == 0){
//								valArray.push(1);	
//							}else{
//								$.each(Measure,function(_i,_Mea){
//									valArray.push(_obj[_Mea.captionBySummaryType]);
//								});	
//							}
//							resultArr.push(valArray);
//						})
//					});
				} else {
					$.each(ValueArray,function(_i,_e){
						$.each(_e,function(_item,_obj){
							var valArray = new Array();
							var object = new Object();
							$.each(Dimension,function(_i,_Dim){
								valArray.push(_obj[_Dim.DataMember]);
							});
							if(Measure.length == 0){
								valArray.push(1);	
							}else{
								$.each(Measure,function(_i,_Mea){
									valArray.push(_obj[_Mea.captionBySummaryType]);
								});	
							}
							resultArr.push(valArray);
						})
					});
				}

				result = resultArr;
				break;
			case 'DIVERGING_CHART':
				var Dimension = WISE.util.Object.toArray(_d3Item.meta.DataItems.Dimension);
				var Measure =  WISE.util.Object.toArray(MeasureKey);
				
				setDimensionNoMeta(_d3Item.dimensions.concat(_d3Item.seriesDimensions));
				
				var tMeasure = _d3Item.measures.concat(_d3Item.HiddenMeasures);

				for(var i = 0; i < tMeasure.length; i++){
					var _Mea = tMeasure[i];
					selectArray.push('|'+_Mea.summaryType+'|');
					selectArray.push(_Mea.name);
					//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
					selectArray.push('|as|');
					if(_d3Item.calculateCaption){
						if(typeof _d3Item.calculateCaption === "string"){
							if(_Mea.caption === _d3Item.calculateCaption){
								selectArray.push(_Mea.name);
								continue;
							}
						}else{
							for(var i = 0; i < _d3Item.calculationCaption.length; i++){
								if(_Mea.caption === _d3Item.calculateCaption[i]){
									selectArray.push(_Mea.name);
									continue;
								}
							}
						}
						selectArray.push(_Mea.captionBySummaryType);
					}else{
						selectArray.push(_Mea.captionBySummaryType);
					}
				}
				//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
				sqlConfig.OrderBy = [];
				$.each(_d3Item.dimensions, function(_i, _d) {
					
					if(_d.sortByMeasure){
						for(var i = 0; i < tMeasure.length; i++){
							var _Mea = tMeasure[i];
							if(_Mea.name === _d.sortByMeasure){
								if(sqlConfig.OrderBy.indexOf(_Mea.captionBySummaryType) === -1)
									sqlConfig.OrderBy.push(_Mea.captionBySummaryType);
								return false;
							}
						}
					}else
						sqlConfig.OrderBy.push(_d.name);
					
					sqlConfig.OrderBy.push('|'+_d.sortOrder+'|');
				});
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;

//				if(_d3Item.IO) {
//					if(_d3Item.IO.IgnoreMasterFilters){
//						sqlConfig.Where = [];
//						sqlConfig.From = [];
//					}
//				}
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(_d3Item.dataSourceId, sqlConfig, _d3Item);
				if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && _d3Item.calculatedFields.length > 0) {
					var fieldList = gDashboard.customFieldManager.fieldInfo[_d3Item.dataSourceId];
					if (fieldList) {
						fieldList.forEach(function(field) {
							gDashboard.customFieldManager.addCustomFieldsToDataSource(field, _d3Item.filteredData);
						});
					}
				}
//				_d3Item.filteredData = gDashboard.itemGenerateManager.doQueryCSVData(_d3Item, {'measureKey' : MeasureKey, 'data' : data});
				 var measures = _d3Item.measures.concat(_d3Item.HiddenMeasures);
                var sortByMeasure = null;
                if(_d3Item.seriesDimensions[0].sortByMeasure){
                	$.each(measures, function(i, _mea){
                        if(_mea.name ===  _d3Item.seriesDimensions[0].sortByMeasure){
                        	sortByMeasure = _mea;
                        	return false;
                        }
					})
                }
                var _categoryData = SQLikeUtil.doSqlLike(_d3Item.dataSourceId, {
					'GroupBy' : [_d3Item.seriesDimensions[0].name],
					'Select' : [_d3Item.seriesDimensions[0].name, '|as|', 'category', '|'+ (sortByMeasure? sortByMeasure.summaryType : MeasureKey.summaryType) +'|', _d3Item.seriesDimensions[0].sortByMeasure? _d3Item.seriesDimensions[0].sortByMeasure : MeasureKey.name, '|as|', 'value'],
					'OrderBy' : [_d3Item.seriesDimensions[0].sortByMeasure?"value" : _d3Item.seriesDimensions[0].name, '|'+_d3Item.seriesDimensions[0].sortOrder+'|'],
					'Where' : sqlConfig.Where
					}, _d3Item)
				_d3Item.csvData = _d3Item.filteredData;
				
				_d3Item.paletteData = [];
				_d3Item.categoryData = {
						negative: [],
						positive: []
				}
				
				$.each(_categoryData, function(i, data){
					if(data.value < 0){
						_d3Item.categoryData.negative.push(data.category);
					}else{
						_d3Item.categoryData.positive.push(data.category);
					}
					_d3Item.paletteData.push(data.category);
				});
				
				//2020.05.04 AJKIM 데이터 항목 없을 때 이미지 추가 DOGFOOT
				if(gDashboard.itemGenerateManager.noDataCheck(_d3Item.csvData, _d3Item)) return;
				if((_d3Item.filteredData = gDashboard.itemGenerateManager.checkFilteredData(_d3Item.filteredData, _d3Item).items()).length === 0) return;

				ValueArray.push(_d3Item.filteredData);
				
				var resultArr = new Array();
				var isZeroValueCheck = false;
				var zeroValueQuantity = 0;
				$.each(ValueArray,function(_i,_e){
					$.each(_e,function(_item,_obj){
						var str = new Array();
						var object = new Object();
						$.each(_d3Item.dimensions,function(_i,_Dim){
							str.push(_obj[_Dim.name]);
						});
						$.each(Measure,function(_i,_Mea){
							//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
							object['value'] =  _obj[_Mea.caption] || _obj[_Mea.captionBySummaryType];
							if(object['value'] == 0){
								zeroValueQuantity++;
							}
						});
						
						object['name'] = str.join(' - ');
						object['category'] = _obj[_d3Item.seriesDimensions[0].name];
						resultArr.push(object);
					});
				});
				
				result = resultArr;
				break;
			case 'BUBBLE_PACK_CHART':
				_d3Item.selectedMeasure=[];
				_d3Item.selectedMeasure = MeasureKey;
				/**
				 * 데이터 중복 제거 코드
				 */
				var Dimension = WISE.util.Object.toArray(_d3Item.meta.DataItems.Dimension);
				var Measure =  WISE.util.Object.toArray(MeasureKey);

				setDimension(Dimension);
				setMeasure(Measure);

				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;
				
				sqlConfig.OrderBy = [];
				$.each(Dimension, function(_i, _d) {
					//2020.02.07 mksong sqllike 적용 dogfoot
					sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
				});
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(_d3Item.dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _d3Item.filteredData;
				ValueArray.push(_d3Item.filteredData);
				var returnArray = [];

				 var first=[];
				first.push({items:_d3Item.filteredData});
				var queryData = first;
				
				//차원이 여러개일때 topN기능이 걸린 차원의 위치를 찾기위한 싸이클
				for(var i = 0; i < _d3Item.dimensions.length ; i++){
					if(i == 0){
		                queryData = _d3Item.__getTopNData(queryData,self.dimensions,_d3Item.dimensions[i].name);
					}else{
						if(i == (_d3Item.dimensions.length-1)) break;
					    queryData = _d3Item.__getTopNData(queryData,_d3Item.dimensions,_d3Item.dimensions[i].name,_d3Item.dimensions[i-1].name);	
					}
				}
		        var dimArray = {};
		        var returedaraay = [];
		        var dimVal2 = [];
		        
		        for(var i = _d3Item.dimensions.length -1; i >0  ; i--){
		        	var testNM=[];
		        	var zxtestNM={};
		        	$.each(queryData,function(_index,_data){
		        	   if(i == (_d3Item.dimensions.length -1)){
		        	       var dimVal = _data.upperDim.slice(1,_data.upperDim.length).split(",");
						   var dimValz = _data.upperDim.slice(1,_data.upperDim.lastIndexOf(',')).split(",");
						   var dimNm = _data.dim.slice(1,_data.dim.lastIndexOf(',')).split(",");
		        	   }else{
		        	   	   var dimVal = _data.upperDim.slice(0,_data.upperDim.length).split(",");
						   var dimValz = _data.upperDim.slice(0,_data.upperDim.lastIndexOf(',')).split(",");
						   var dimNm = _data.dim.slice(0,_data.dim.lastIndexOf(',')).split(",");
						   
		        	   }
					   //var dimNm = _data.dim ? _data.dim : _d3Item.dimensions[_d3Item.dimensions.length-1].caption
					   if(i > 0){
						   var dimValName = dimVal[i-1];
					   }
                        
					   if(i ==(_d3Item.dimensions.length -1)){
		                   dimVal = dimVal.join(',')
						   dimValz = dimValz.join(',')
						   if(!zxtestNM[dimVal]){
							   zxtestNM[dimVal] = {'key':dimValName,'upperDim':dimValz,'items':[],'dim':_d3Item.dimensions[i-1].name};	
							   zxtestNM[dimVal].items = _data.items
						   }else{
								var jsonStr = '['+JSON.stringify(zxtestNM[dimVal].items).replaceAll('[','').replaceAll(']','') +','+JSON.stringify(_data.items).replaceAll('[','').replaceAll(']','')+']';

								zxtestNM[dimVal].items = JSON.parse(jsonStr)
						   }
					   }else{
					   	   dimVal = dimVal.join(',')
						   dimValz = dimValz.join(',')
						   if(!zxtestNM[dimVal]){
							   zxtestNM[dimVal] = {'key':dimValName,'upperDim':dimValz,'items':[],'dim':_d3Item.dimensions[i-1].name};	
							   zxtestNM[dimVal].items = [_data]
						   }else{
								var jsonStr = '['+JSON.stringify(zxtestNM[dimVal].items).slice(1,JSON.stringify(zxtestNM[dimVal].items).length-1) +','+JSON.stringify(_data)+']';

								zxtestNM[dimVal].items = JSON.parse(jsonStr)
						   }
					   }
					})
					var arrayzx = [];
					$.each(zxtestNM, function(_v,_z){
						
						arrayzx.push(_z)
					})
					queryData = arrayzx;
		        }

				var jsonString = JSON.stringify(queryData);
		        $.each(Measure,function(_i,_Mea){
					jsonString = jsonString.replaceAll(Measure[0].captionBySummaryType,"value");
				});
		        
		        jsonString = jsonString.replaceAll('items','children');
		        jsonString = jsonString.replaceAll(_d3Item.dimensions[_d3Item.dimensions.length-1].name,'key');
		        var jsonData = {'name':'newone',children:[queryData]};
				var resultArr = {'key':'zero',children:[{'key':'전체',children:JSON.parse(jsonString)}]};
				
				result = resultArr;
			break;
			case 'BOX_PLOT':
				var Measure =  WISE.util.Object.toArray(MeasureKey);
			
				$.each(Dimension,function(_i,_Dim){
					selectArray.push(_Dim.DataMember);
					FieldArray.push(_Dim.DataMember);
				});
				
				$.each(Measure,function(_i,_Mea){
//					selectArray.push('|'+_Mea.summaryType+'|');
					selectArray.push(_Mea.name);
					//2020.02.07 mksong sqllike 적용 dogfoot
					selectArray.push('|as|');
					selectArray.push(_Mea.captionBySummaryType);
					FieldArray.push(_Mea.name);
				});
				//2020.02.07 mksong sqllike 적용 dogfoot
				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
	//			sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _d3Item.filteredData;
				ValueArray.push(_d3Item.filteredData);
				
				var rowMin = null;
				var rowMax = null;
				
				var tempData = {};
				var resultArr = new Array();
				_d3Item.paletteData = [];
				$.each(ValueArray,function(_i,_e){
					$.each(_e,function(_item,_obj){
						var dimNames = [];
						$.each(Dimension, function(i, _dim){
							dimNames.push(_obj[_dim.DataMember]);
						})
						var dimName = dimNames.join(' - ')
						if(!tempData[dimName]){
							tempData[dimName] = [];
							_d3Item.paletteData.push(dimName);
						}
						
						tempData[dimName].push(_obj[Measure[0].captionBySummaryType]);
						if(_obj[Measure[0].captionBySummaryType] < rowMin || !rowMin){
							rowMin = _obj[Measure[0].captionBySummaryType]
						}
						
						if(_obj[Measure[0].captionBySummaryType] > rowMax || !rowMax){
							rowMax = _obj[Measure[0].captionBySummaryType]
						}
					})
				});
				
				$.each(tempData, function(name, value){
					var tempArr = new Array();
					tempArr.push(name);
					tempArr.push(value);
					resultArr.push(tempArr);
				})
				result = {
					result : resultArr,
					min : rowMin,
					max : rowMax
				}
			break;
			case 'LIQUID_FILL_GAUGE':
				var Measure =  WISE.util.Object.toArray(MeasureKey);
				
				setDimension(Dimension);
				setMeasure(Measure);
				//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.OrderBy = [];
				$.each(_d3Item.dimensions, function(_i, _d) {
					
					if(_d.sortByMeasure){
						$.each(Measure,function(_i,_Mea){
							if(_Mea.name === _d.sortByMeasure){
								if(sqlConfig.OrderBy.indexOf(_Mea.captionBySummaryType) === -1)
									sqlConfig.OrderBy.push(_Mea.captionBySummaryType);
								return false;
							}
						});
					}else
						sqlConfig.OrderBy.push(_d.name);
					
					sqlConfig.OrderBy.push('|'+_d.sortOrder+'|');
				});
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;

				if(self.IO) {
					if(_d3Item.IO.IgnoreMasterFilters){
						sqlConfig.Where = [];
						sqlConfig.From = [];
					}
				}
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
//				_d3Item.filteredData = gDashboard.itemGenerateManager.doQueryCSVData(self, {'measureKey' : MeasureKey, 'data' : data});
				self.csvData = _d3Item.filteredData;
//				self.initDrillDownData(_d3Item.filteredData);
							
//				ValueArray.push(SQLike.q(sqlConfig));
				ValueArray.push(_d3Item.filteredData);
				
				var resultArr = new Array();
				var totalValue = 0;
				_d3Item.paletteData = [];
				$.each(ValueArray,function(_i,_e){
					$.each(_e,function(_item,_obj){
						var str = new Array();
						var object = new Object();
						$.each(Dimension,function(_i,_Dim){
							str.push(_obj[_Dim.DataMember]);
						});
						$.each(Measure,function(_i,_Mea){
							//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
							object['value'] = _obj[_Mea.captionBySummaryType];
							totalValue += object['value'];
						});
						
//						object['name'] = str.join(' - ');
						//2020.05.26 MKSONG 연세대 트리맵 노드별 이름에 측정값 캡션 추가 DOGFOOT
						object['name'] = str.join(' - ');
						if(object['name'] === "")
							object['name'] = Measure[0].caption;
//						else
//							object['name'] += (' - ' + Measure[0].caption);
						resultArr.push(object);
						_d3Item.paletteData.push(object['name']);
					});
					
					$.each(resultArr, function(i, result){
						result.pValue = result.value / totalValue * 100;
					})
					
					result = resultArr;
				});
			break;
			case 'RADIAL_TIDY_TREE':
				_d3Item.selectedMeasure = WISE.util.Object.toArray(MeasureKey);
				
				setDimension(Dimension);
				
				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;
				
				sqlConfig.OrderBy = [];
				$.each(Dimension, function(_i, _d) {
					//2020.02.07 mksong sqllike 적용 dogfoot
					sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
				});
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _d3Item.filteredData;
				ValueArray.push(_d3Item.filteredData);
				
				var resultArr = new Array();
				var parentArr = ['start'];
				$.each(_d3Item.filteredData, function(_i, _d){
					var str = ['start'];
					for(var j = 0; j < Dimension.length; j++){
						if(j < Dimension.length){
							parentArr.push(str.join(';'));
						}
						str.push(_d[Dimension[j].DataMember]);
					}
					resultArr.push({id: str.join(";"), value : 0});
				});
				
				parentArr = parentArr.filter(function(a, i, self){
					return self.indexOf(a) === i;
				});
				
				for(var i = parentArr.length - 1; i >= 0; i--){
					resultArr.unshift({id: parentArr[i], value: 0});
				}
				
				resultArr.columns=['id', 'value'];
				result = resultArr;
				
			break;
			case 'ARC_DIAGRAM':
				
				setDimensionNoMeta(_d3Item.dimensions);
				
				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = FieldArray;
				
				sqlConfig.OrderBy = [];
				$.each(Dimension, function(_i, _d) {
					//2020.02.07 mksong sqllike 적용 dogfoot
					sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
				});
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _d3Item.filteredData;
				ValueArray.push(_d3Item.filteredData);
				
				var resultArr = {};
				var nodes = new Array();
				var links = new Array();
				var nodesJson = {};
				$.each(_d3Item.filteredData, function(_j, _d){
					$.each(_d3Item.dimensions, function(_i, _dim){
						nodesJson[_d[_dim.name]] = _i;
						var linkJson = {};
						if(_i + 1 !== _d3Item.dimensions.length){
							linkJson.target = _d[_dim.name] + "";
							linkJson.source = _d[_d3Item.dimensions[_i + 1].name] + "";
							linkJson.value = 0;
							links.push(linkJson);
						}else{
							linkJson.target = _d[_dim.name] + "";
							linkJson.source = _d[_d3Item.dimensions[0].name] + "";
							linkJson.value = 0;
							links.push(linkJson);
						}
					})
				});
				
				_d3Item.paletteData = [];
				for(var i = 0; i < _d3Item.dimensions.length; i++){
					_d3Item.paletteData.push(_d3Item.dimensions[i].caption);
				}
				
				$.each(nodesJson, function(i, node){
					nodes.push({id : i, group : node});
				})
				
				resultArr.nodes = nodes;
				resultArr.links = links;
				result = resultArr;
			break;
			case 'HISTORY_TIMELINE':
				
				setDimensionNoMeta(_d3Item.dimensions);
				
				var sqlConfig ={};
				setSqlConfigWhere(sqlConfig);
				
				sqlConfig.Select = selectArray;
				sqlConfig.From = _data;
				sqlConfig.GroupBy = FieldArray;
				
				sqlConfig.OrderBy = [];
				$.each(Dimension, function(_i, _d) {
					sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
				});
				
				_d3Item.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, _d3Item);
				_d3Item.csvData = _d3Item.filteredData;
				ValueArray.push(_d3Item.filteredData);
				
				var resultArr = new Array();
				
				_d3Item.paletteData = [];
				$.each(_d3Item.filteredData, function(i, d){
					var resultJson;
					
					var startValue = self.getTimelineDate(d[_d3Item.dimensions[0].name]+"");
					var endValue = self.getTimelineDate(d[_d3Item.dimensions[1].name]+"")
					
					if(startValue && endValue){
						resultJson = { 
								start : d[_d3Item.dimensions[0].name]+"",
								end : d[_d3Item.dimensions[1].name]+"",
								startValue : self.getTimelineDate(d[_d3Item.dimensions[0].name]+""),
								endValue : self.getTimelineDate(d[_d3Item.dimensions[1].name]+"")
						};
					}else{
						return;
					}
					
					var str = [];
					for(var j = 2; j < _d3Item.dimensions.length; j++){
						str.push(d[_d3Item.dimensions[j].name]);
					}
					str = str.join(' - ');
					resultJson.dimension = str;
					
					if(_d3Item.paletteData.indexOf(str) === -1){
						_d3Item.paletteData.push(str);
					}
					
					resultArr.push(resultJson);
				})
				
				result = resultArr;
				break;
	}
		
		return result;
	};
	
	this.getTimelineDate = function(data){
		var replaceVal = data.replace(/(\s*)/g, "");
		
		if(replaceVal.indexOf('년') > -1){
			replaceVal = replaceVal.replace('년','-');
		}
		if(replaceVal.indexOf('월') > -1){
			replaceVal = replaceVal.replace('월','-');
		}
		if(replaceVal.indexOf('일') > -1){
			replaceVal = replaceVal.replace('일','');
		}

		if(replaceVal.indexOf('-') === -1){
			if(replaceVal.length === 8)replaceVal = replaceVal.slice(0,4)+"-"+replaceVal.slice(4,6)+"-"+replaceVal.slice(6,8)
			
		}
		
		var datacheck = self.checkDataTodate(replaceVal);
		if(datacheck){
//            self.yearOptionData[replaceVal.slice(0,4)] = Number(replaceVal.slice(0,4));
//            var dt;
//            dt = moment(replaceVal, format.toLocaleUpperCase());
//			
//			dateVal = dt.toDate();

			return replaceVal;
		
		}else{
			WISE.alert('날짜(yyyymmdd) 형식의 데이터를 넣어 주세요!');
			gProgressbar.hide();
		}
		
		return false;
	}
	
	this.checkDataTodate = function(_data){
        var check = false;
		var re;
		if(!check){
			re = /[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])/; 
			check = re.test(_data);
			if(check)self.formatDate = 'yyyy-mm-dd';
			self.scope = 'days'
		} 
        
        return check;

	}
	
	this.__getTopNData = function(queryData,dimensions,nowDim,preDim,lastDim){
		
		
		var sumNm = self.selectedMeasure[0].nameBySummaryType;

		
		var topnData = [];
		var otherData =[];
		var topNarray = [];
		var topNresult = [];
		var TopNExecSyx;
		var sortTopNdata;
		var TopNotherData;
		var predim = '';
		var colLen = 0;
		$.each(queryData,function(_index,_e){
			if(_e.id){
			    predim = _e.id	
			}
	        
			var ExecSyx = DevExpress.data.query(_e.items);
			var sumValArray = ExecSyx.groupBy(nowDim)
			          .select(function(dataItem) {  
						var resultItem = null;  
						DevExpress.data.query(dataItem.items)  
						.sum(sumNm)  
						.done(function(result) {  
							resultItem = {  
								key : dataItem.key,
								value: result  
							}  
						});  
						return resultItem;  
					}).toArray();
			ExecSyx = ExecSyx.groupBy(nowDim);
			topNarray = ExecSyx.toArray();
            $.each(topNarray, function(i, e) {
                if(predim === ""){
                	predim = "start";
                	var reval;
                	reval = sumValArray.reduce(function(accumulator, currentValue, currentIndex, array) {
                	  var objectCk = typeof accumulator === "object" ? accumulator.value : accumulator
					  return objectCk + currentValue.value;
					});
                	self.returnData.push({'id':'start','value':reval});
                    e['id'] = predim.concat(";",e.key);
                }else{
                	e['id'] = predim.concat(";",e.key);
                }
            	
				topnData.push(e);
				if(lastDim == (self.dimensions.length-1)){
					var colorz = gDashboard.d3Manager.getPalette(self);
					if(colLen>(colorz.length-1))colLen=0;
					
					if(self.paletteData.length>0){

						colLen =  self.paletteData.indexOf(e.key) === -1 ?  colLen : self.paletteData.indexOf(e.key) > colorz.length? colLen: self.paletteData.indexOf(e.key);
						self.returnData.push({'id':e['id'],'value':e['items'][0][sumNm],'color':colorz[colLen]});
						self.xAxisData.push({'id':e['id'],'value':e['items'][0][sumNm],'color':colorz[colLen]});
						colLen++;	
					}else{
						if(colLen>(colorz.length-1))colLen=0;
						self.returnData.push({'id':e['id'],'value':e['items'][0][sumNm],'color':colorz[colLen]});
						self.xAxisData.push({'id':e['id'],'value':e['items'][0][sumNm],'color':colorz[colLen]});
						colLen++;
					}
					
                    
				}else{
					var reval;
                    $.each(sumValArray,function(_j,_value){
                    	if(e.key === _value.key){
                            reval = _value.value
                    	}
                    	
                    });
					
				    self.returnData.push({'id':e['id'],'value':reval});
				}
				colLen++;
			});
		})
        return topnData;
	}
	
	/*dogfoot Y축 설정 추가 shlim 20200831*/
	this.functionDo = function(_f, _d3Item,_d3Chart) {		
		switch(_f) {
			case 'captionVisible': {
				var titleBar = $('#' + _d3Item.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					_d3Item.meta['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					_d3Item.meta['ShowCaption'] = false;
				}
				break;
			}
			// edit chart title
			case 'editName': {
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '이름 편집',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize title input box
						contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + _d3Item.itemid + '_titleInput">');
                        var html = '<div class="modal-footer" style="padding-bottom:0px;">';
						html += '<div class="row center">';
						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
						html += '</div>';
						html += '</div>';
						html += '</div>';
						contentElement.append(html);
                        
                        $('#' + _d3Item.itemid + '_titleInput').dxTextBox({
							text: $('#' + _d3Item.itemid + '_title').text()
                        });
                                                
                        // confirm and cancel
						$('#ok-hide').on('click', function() {
                            var newName = $('#' + _d3Item.itemid + '_titleInput').dxTextBox('instance').option('text');
                            if(newName.trim() == '') {
                            	WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                            	$('#' + _d3Item.itemid + '_titleInput').dxTextBox('instance').option('value', _d3Item.Name);
                            } else {
                            	/* DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류 수정  20191223 */
                            	
//                            	var goldenLayout = gDashboard.goldenLayoutManager;
//                            	goldenLayout.changeTitle(_d3Item.itemid, newName, goldenLayout.canvasLayout.root.contentItems);
                            	
                            	var ele = $('#' + _d3Item.itemid + '_title');
                            	ele.attr( 'title', newName)
                                ele.find( '.lm_title' ).html(newName);
                            	
                            	_d3Item.meta['Name'] = newName;
                            	_d3Item.Name = newName;
                            	p.hide();
                            }
						});
						$('#close').on('click', function() {
							p.hide();
						});
					}
				});
				// show popup
				p.show();
				break;
			}
			/*dogfoot d3 Y축 설정 팝업 화면 추가 shlim 20200828*/
			case 'editAxisY': {
				if (!(_d3Chart)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: 'Y축 설정',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						var example = 1234567890.123;
						var initialized = false;

						// initialize template
						var html = 	'<div id="' + _d3Item.itemid + '_yOptions"></div>' +
									'<textarea id="exampleText" style="width: 100%; height: 50px; text-align: center; font-size: 1.5em;" disabled></textarea>' +
									'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
						contentElement.append(html);

						// edit Y axis measures
						var optionsForm = $('#' + _d3Item.itemid + '_yOptions').dxForm({
							items: [
								{
									dataField: '포맷 형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Auto', 'General', 'Number', 'Currency', 'Scientific', 'Percent'],
										value: _d3Chart.AxisY.FormatType,
										onValueChanged: function(e) {
											if (e.value === 'Auto' || e.value === 'General') {
												optionsForm.getEditor('단위').option('disabled', true);
												optionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
												optionsForm.getEditor('O').option('disabled', true);
												optionsForm.getEditor('K').option('disabled', true);
												optionsForm.getEditor('M').option('disabled', true);
												optionsForm.getEditor('B').option('disabled', true);
												optionsForm.getEditor('정도').option('disabled', true);
												optionsForm.getEditor('그룹 구분 포함').option('disabled', true);
											} else if (e.value === 'Scientific' || e.value === 'Percent') {
												optionsForm.getEditor('단위').option('disabled', true);
												optionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
												optionsForm.getEditor('O').option('disabled', true);
												optionsForm.getEditor('K').option('disabled', true);
												optionsForm.getEditor('M').option('disabled', true);
												optionsForm.getEditor('B').option('disabled', true);
												optionsForm.getEditor('정도').option('disabled', false);
												optionsForm.getEditor('그룹 구분 포함').option('disabled', true);
											} else {
												optionsForm.getEditor('단위').option('disabled', false);
												optionsForm.getEditor('사용자 지정 접미사').option('disabled', false);
												if (optionsForm.getEditor('사용자 지정 접미사').option('value')) {
													optionsForm.getEditor('O').option('disabled', false);
													optionsForm.getEditor('K').option('disabled', false);
													optionsForm.getEditor('M').option('disabled', false);
													optionsForm.getEditor('B').option('disabled', false);	
												}
												optionsForm.getEditor('정도').option('disabled', false);
												optionsForm.getEditor('그룹 구분 포함').option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '단위',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
										value: _d3Chart.AxisY.Unit,
										onInitialized: function(e) {
											var formatType = _d3Chart.AxisY.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: 'Y축 표시',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: _d3Chart.AxisY.Visible
									}
								},
								{
									dataField: '사용자 정의 텍스트',
									editorType: 'dxTextBox',
									editorOptions: {
										value: _d3Chart.AxisY.Title? _d3Chart.AxisY.Title: '',
										onInitialized: function(e) {
											if (_d3Item.type === 'HISTOGRAM_CHART' || _d3Item.type === 'SCATTER_PLOT_MATRIX' || _d3Item.type === 'WATERFALL_CHART') {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '사용자 지정 접미사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: _d3Chart.AxisY.SuffixEnabled,
										onInitialized: function(e) {
											var formatType = _d3Chart.AxisY.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											if (e.value) {
												optionsForm.getEditor('O').option('disabled', false);
												optionsForm.getEditor('K').option('disabled', false);
												optionsForm.getEditor('M').option('disabled', false);
												optionsForm.getEditor('B').option('disabled', false);
											} else {
												optionsForm.getEditor('O').option('disabled', true);
												optionsForm.getEditor('K').option('disabled', true);
												optionsForm.getEditor('M').option('disabled', true);
												optionsForm.getEditor('B').option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'O',
									editorType: 'dxTextBox',
									editorOptions: {
										value: _d3Chart.AxisY.MeasureFormat.O,
										onInitialized: function(e) {
											var formatType = _d3Chart.AxisY.FormatType;
											var suffixEnabled = _d3Chart.AxisY.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: 'K',
									editorType: 'dxTextBox',
									editorOptions: {
										value: _d3Chart.AxisY.MeasureFormat.K,
										onInitialized: function(e) {
											var formatType = _d3Chart.AxisY.FormatType;
											var suffixEnabled = _d3Chart.AxisY.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: 'M',
									editorType: 'dxTextBox',
									editorOptions: {
										value: _d3Chart.AxisY.MeasureFormat.M,
										onInitialized: function(e) {
											var formatType = _d3Chart.AxisY.FormatType;
											var suffixEnabled = _d3Chart.AxisY.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: 'B',
									editorType: 'dxTextBox',
									editorOptions: {
										value: _d3Chart.AxisY.MeasureFormat.B,
										onInitialized: function(e) {
											var formatType = _d3Chart.AxisY.FormatType;
											var suffixEnabled = _d3Chart.AxisY.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '정도',
									editorType: 'dxNumberBox',
									editorOptions: {
										step: 1,
										min: 0,
										max: 5,
										showSpinButtons: true,
										value: _d3Chart.AxisY.Precision,
										onInitialized: function(e) {
											var formatType = _d3Chart.AxisY.FormatType;
											if (formatType === 'Auto' || formatType === 'General') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
									}
								},
								{
									dataField: '그룹 구분 포함',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: _d3Chart.AxisY.Separator,
										onInitialized: function(e) {
											var formatType = _d3Chart.AxisY.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
									}
								}
							],
							onContentReady: function(form) {
								if (!initialized) {
									initialized = true;
									function updateExample(e) {
										var formData = e.component.option('formData');
										var type = formData['포맷 형식'];
										var	unit = formData['단위'];
										var precision = formData['정도'];
										var separator = formData['그룹 구분 포함'];
										var prefix = undefined;
										var suffix = {
											O: formData['O'],
											K: formData['K'],
											M: formData['M'],
											B: formData['B']	
										};
										var suffixEnabled = formData['사용자 지정 접미사'];
										$('#exampleText').val(WISE.util.Number.unit(example, type, unit, precision, separator, prefix, suffix, suffixEnabled));
									}
									updateExample(form);
									form.component.option('onFieldDataChanged', updateExample);
								}
							}
						}).dxForm('instance');

						// confirm and cancel
						$('#ok-hide').off('click').on('click', function() {
							var formData = optionsForm.option('formData');
							var formatType = formData['포맷 형식'];
							var	unit = formData['단위'];
							var showZero = formData['항상 제로 수준 표시'];
							var visible = formData['Y축 표시'];
							var title = formData['사용자 정의 텍스트'];
							var suffixEnabled = formData['사용자 지정 접미사'];
							var suffix = {
								O: formData['O'],
								K: formData['K'],
								M: formData['M'],
								B: formData['B']	
							};
							var precision = formData['정도'];
							var separator = formData['그룹 구분 포함'];
							_d3Chart.AxisY.FormatType = formatType;
							_d3Chart.AxisY.Unit = unit;
							_d3Chart.AxisY.Visible = visible;
                            _d3Chart.AxisY.Title = title;
                            /* DOGFOOT ktkang Y축 이름 저장 오류 수정  20200130 */
                            _d3Chart.AxisY.TitleRename = true;
							_d3Chart.AxisY.SuffixEnabled = suffixEnabled;
							_d3Chart.AxisY.MeasureFormat = suffix;
							_d3Chart.AxisY.Precision = precision;
							_d3Chart.AxisY.Separator = separator;
							// _d3Item.dxItem.option('valueAxis[0].title.text', _d3Chart.AxisY.Title);
							// for (var i = 0; i < _d3Item.dxItem.option('valueAxis').length; i++) {
							// 	_d3Item.dxItem.option('valueAxis[' + i + '].label.visible', _d3Chart.AxisY.Visible);
							// 	// if Y axis is not visible, hide title
							// 	var title = _d3Item.dxItem.option('valueAxis[' + i + '].title.text');
							// 	_d3Item.dxItem.option('valueAxis[' + i + '].title.text', _d3Chart.AxisY.Visible ? title : '');
							// 	_d3Item.dxItem.option('valueAxis[' + i + '].label.customizeText', function(e) {
							// 		return WISE.util.Number.unit(e.value, formatType, unit, precision, separator, undefined, suffix, suffixEnabled);
							// 	});
							// 	_d3Item.dxItem.option('valueAxis[' + i + '].label.showZero', _d3Chart.AxisY.ShowZero);
							// }
							//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
							_d3Item.functionBinddata = true;
							_d3Item.bindData(_d3Item.globalData, true);
                            p.hide();
						});
						$('#close').off('click').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			/*dogfoot d3 X축 설정 팝업 화면 추가 ajkim 20200903*/
			case 'editAxisX': {
				if (!(_d3Chart)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				if(_d3Item.type === 'BOX_PLOT' || _d3Item.type === 'SYNCHRONIZED_CHARTS'){
					p.option({
						title: 'X축 설정',
						onContentReady: function() {
							gDashboard.fontManager.setFontConfigForOption('editPopup');
						},
						contentTemplate: function(contentElement) {
							var example = 1234567890.123;
							var initialized = false;

							// initialize template
							var html = 	'<div id="' + _d3Item.itemid + '_xOptions"></div>' +
										'<div style="padding-bottom:20px;"></div>' +
										'<div class="modal-footer" style="padding-bottom:0px;">' +
											'<div class="row center">' +
												'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
												'<a id="close" href="#" class="btn neutral close">취소</a>' +
											'</div>' +
										'</div>';
							contentElement.append(html);

							var xItem = [{
									dataField: '라벨 겹침',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: typeof _d3Chart.AxisX.Overlapping ==='undefined'? false : _d3Chart.AxisX.Overlapping
									}
								}];
								
							// edit X axis measures
							var optionsForm = $('#' + _d3Item.itemid + '_xOptions').dxForm({
								items: xItem,
							}).dxForm('instance');

							// confirm and cancel
							$('#ok-hide').off('click').on('click', function() {
								var formData = optionsForm.option('formData');
								var overlapping = formData['라벨 겹침'];
								
								_d3Chart.AxisX.Overlapping = overlapping
								_d3Item.functionBinddata = true;
								_d3Item.bindData(_d3Item.globalData, true);
	                            p.hide();
							});
							$('#close').off('click').on('click', function() {
								p.hide();
							});
						}
					});
					p.show();
					break;
				}
				p.option({
					title: 'X축 설정',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						var example = 1234567890.123;
						var initialized = false;

						// initialize template
						var html = 	'<div id="' + _d3Item.itemid + '_xOptions"></div>' +
									'<textarea id="exampleText" style="width: 100%; height: 50px; text-align: center; font-size: 1.5em;" disabled></textarea>' +
									'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
						contentElement.append(html);

						var xItem = [
							{
								dataField: '포맷 형식',
								editorType: 'dxSelectBox',
								editorOptions: {
									items: ['Auto', 'General', 'Number', 'Currency', 'Scientific', 'Percent'],
									value: _d3Chart.AxisX.FormatType,
									onValueChanged: function(e) {
										if (e.value === 'Auto' || e.value === 'General') {
											optionsForm.getEditor('단위').option('disabled', true);
											optionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
											optionsForm.getEditor('O').option('disabled', true);
											optionsForm.getEditor('K').option('disabled', true);
											optionsForm.getEditor('M').option('disabled', true);
											optionsForm.getEditor('B').option('disabled', true);
											optionsForm.getEditor('정도').option('disabled', true);
											optionsForm.getEditor('그룹 구분 포함').option('disabled', true);
										} else if (e.value === 'Scientific' || e.value === 'Percent') {
											optionsForm.getEditor('단위').option('disabled', true);
											optionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
											optionsForm.getEditor('O').option('disabled', true);
											optionsForm.getEditor('K').option('disabled', true);
											optionsForm.getEditor('M').option('disabled', true);
											optionsForm.getEditor('B').option('disabled', true);
											optionsForm.getEditor('정도').option('disabled', false);
											optionsForm.getEditor('그룹 구분 포함').option('disabled', true);
										} else {
											optionsForm.getEditor('단위').option('disabled', false);
											optionsForm.getEditor('사용자 지정 접미사').option('disabled', false);
											if (optionsForm.getEditor('사용자 지정 접미사').option('value')) {
												optionsForm.getEditor('O').option('disabled', false);
												optionsForm.getEditor('K').option('disabled', false);
												optionsForm.getEditor('M').option('disabled', false);
												optionsForm.getEditor('B').option('disabled', false);	
											}
											optionsForm.getEditor('정도').option('disabled', false);
											optionsForm.getEditor('그룹 구분 포함').option('disabled', false);
										}
									}
								}
							},
							{
								dataField: '단위',
								editorType: 'dxSelectBox',
								editorOptions: {
									items: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
									value: _d3Chart.AxisX.Unit,
									onInitialized: function(e) {
										var formatType = _d3Chart.AxisX.FormatType;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: 'X축 표시',
								editorType: 'dxCheckBox',
								editorOptions: {
									value: _d3Chart.AxisX.Visible
								}
							},
							{
								dataField: '사용자 정의 텍스트',
								editorType: 'dxTextBox',
								editorOptions: {
									value: _d3Chart.AxisX.Title? _d3Chart.AxisX.Title : '',
									onInitialized : function(e) {
										if (_d3Item.type === "DIVERGING_CHART" || _d3Item.type === 'HISTOGRAM_CHART' || _d3Item.type === 'SCATTER_PLOT_MATRIX') {
											e.component.option('disabled', true);
											e.component.option('value', '');
										}
									}
								}
							},
							{
								dataField: '사용자 지정 접미사',
								editorType: 'dxCheckBox',
								editorOptions: {
									value: _d3Chart.AxisX.SuffixEnabled,
									onInitialized: function(e) {
										var formatType = _d3Chart.AxisX.FormatType;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									},
									onValueChanged: function(e) {
										if (e.value) {
											optionsForm.getEditor('O').option('disabled', false);
											optionsForm.getEditor('K').option('disabled', false);
											optionsForm.getEditor('M').option('disabled', false);
											optionsForm.getEditor('B').option('disabled', false);
										} else {
											optionsForm.getEditor('O').option('disabled', true);
											optionsForm.getEditor('K').option('disabled', true);
											optionsForm.getEditor('M').option('disabled', true);
											optionsForm.getEditor('B').option('disabled', true);
										}
									}
								}
							},
							{
								dataField: 'O',
								editorType: 'dxTextBox',
								editorOptions: {
									value: _d3Chart.AxisX.MeasureFormat.O,
									onInitialized: function(e) {
										var formatType = _d3Chart.AxisX.FormatType;
										var suffixEnabled = _d3Chart.AxisX.SuffixEnabled;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: 'K',
								editorType: 'dxTextBox',
								editorOptions: {
									value: _d3Chart.AxisX.MeasureFormat.K,
									onInitialized: function(e) {
										var formatType = _d3Chart.AxisX.FormatType;
										var suffixEnabled = _d3Chart.AxisX.SuffixEnabled;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: 'M',
								editorType: 'dxTextBox',
								editorOptions: {
									value: _d3Chart.AxisX.MeasureFormat.M,
									onInitialized: function(e) {
										var formatType = _d3Chart.AxisX.FormatType;
										var suffixEnabled = _d3Chart.AxisX.SuffixEnabled;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: 'B',
								editorType: 'dxTextBox',
								editorOptions: {
									value: _d3Chart.AxisX.MeasureFormat.B,
									onInitialized: function(e) {
										var formatType = _d3Chart.AxisX.FormatType;
										var suffixEnabled = _d3Chart.AxisX.SuffixEnabled;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: '정도',
								editorType: 'dxNumberBox',
								editorOptions: {
									step: 1,
									min: 0,
									max: 5,
									showSpinButtons: true,
									value: _d3Chart.AxisX.Precision,
									onInitialized: function(e) {
										var formatType = _d3Chart.AxisX.FormatType;
										if (formatType === 'Auto' || formatType === 'General') {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									},
								}
							},
							{
								dataField: '그룹 구분 포함',
								editorType: 'dxCheckBox',
								editorOptions: {
									value: _d3Chart.AxisX.Separator,
									onInitialized: function(e) {
										var formatType = _d3Chart.AxisX.FormatType;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									},
								}
							}
						]
						
						if(_d3Item.type === 'SCATTER_PLOT_MATRIX'){
							xItem.splice(2, 0, ({
								dataField: '라벨 겹침',
								editorType: 'dxCheckBox',
								editorOptions: {
									value: typeof _d3Chart.AxisX.Overlapping ==='undefined'? false : _d3Chart.AxisX.Overlapping
								}
							}))
							
						}
						// edit X axis measures
						var optionsForm = $('#' + _d3Item.itemid + '_xOptions').dxForm({
							items: xItem,
							onContentReady: function(form) {
								if (!initialized) {
									initialized = true;
									function updateExample(e) {
										var formData = e.component.option('formData');
										var type = formData['포맷 형식'];
										var	unit = formData['단위'];
										var precision = formData['정도'];
										var separator = formData['그룹 구분 포함'];
										var prefix = undefined;
										var suffix = {
											O: formData['O'],
											K: formData['K'],
											M: formData['M'],
											B: formData['B']	
										};
										var suffixEnabled = formData['사용자 지정 접미사'];
										$('#exampleText').val(WISE.util.Number.unit(example, type, unit, precision, separator, prefix, suffix, suffixEnabled));
									}
									updateExample(form);
									form.component.option('onFieldDataChanged', updateExample);
								}
							}
						}).dxForm('instance');

						// confirm and cancel
						$('#ok-hide').off('click').on('click', function() {
							var formData = optionsForm.option('formData');
							var formatType = formData['포맷 형식'];
							var	unit = formData['단위'];
							var showZero = formData['항상 제로 수준 표시'];
							var visible = formData['X축 표시'];
							var title = formData['사용자 정의 텍스트'];
							var suffixEnabled = formData['사용자 지정 접미사'];
							var suffix = {
								O: formData['O'],
								K: formData['K'],
								M: formData['M'],
								B: formData['B']	
							};
							var precision = formData['정도'];
							var separator = formData['그룹 구분 포함'];
							var overlapping = formData['라벨 겹침'];
							_d3Chart.AxisX.FormatType = formatType;
							_d3Chart.AxisX.Unit = unit;
							_d3Chart.AxisX.Visible = visible;
                            _d3Chart.AxisX.Title = title;
                            /* DOGFOOT ktkang Y축 이름 저장 오류 수정  20200130 */
                            _d3Chart.AxisX.TitleRename = true;
							_d3Chart.AxisX.SuffixEnabled = suffixEnabled;
							_d3Chart.AxisX.MeasureFormat = suffix;
							_d3Chart.AxisX.Precision = precision;
							_d3Chart.AxisX.Separator = separator;
							if(typeof overlapping !== 'undefined'){
								_d3Chart.AxisX.Overlapping = overlapping
							}
							_d3Item.functionBinddata = true;
							_d3Item.bindData(_d3Item.globalData, true);
                            p.hide();
						});
						$('#close').off('click').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			
			case 'editExpandOption': {
				if (!(_d3Chart)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '추가 설정',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize template
						var html = 	'<div id="' + _d3Item.itemid + '_xOptions"></div>' +
									'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
						contentElement.append(html);

						var xItem = [{
								dataField: '라벨 겹침',
								editorType: 'dxCheckBox',
								editorOptions: {
									value: typeof _d3Chart.ExpandOption.LabelOverlapping ==='undefined'? false : _d3Chart.ExpandOption.LabelOverlapping
								}
							}];
							
						// edit X axis measures
						var optionsForm = $('#' + _d3Item.itemid + '_xOptions').dxForm({
							items: xItem,
						}).dxForm('instance');

						// confirm and cancel
						$('#ok-hide').off('click').on('click', function() {
							var formData = optionsForm.option('formData');
							var overlapping = formData['라벨 겹침'];
							
							_d3Chart.ExpandOption.LabelOverlapping = overlapping
							_d3Item.functionBinddata = true;
							_d3Item.bindData(_d3Item.globalData, true);
                            p.hide();
						});
						$('#close').off('click').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			/* DOGFOOT AJKIM 20201214 액체게이지 콘텐츠 배열 기능 추가 */
			case 'editArrange': {
				if (!(_d3Chart)) {
					break;
				}
				var contentColumnCount = _d3Chart.ContentOption.ContentColumnCount;
				var contentAutoColumn = _d3Chart.ContentOption.ContentAutoColumn;
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '콘텐츠 배열',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize template
						contentElement.append(	'<div id="' + self.itemid + '_contentArrangementMode"></div>' +
												'<div style="padding-bottom:20px;"></div>' +
												'<div class="modal-footer" style="padding-bottom:0px;">' +
													'<div class="row center">' +
														'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
														'<a id="close" href="#" class="btn neutral close">취소</a>' +
													'</div>' +
												'</div>');
						
						// initialize components
						var arrangeForm = $('#' + self.itemid + '_contentArrangementMode').dxForm({
							items: [
								{
									dataField: '컬럼 개수 자동 지정',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: contentAutoColumn,
										onValueChanged : function(e){
											arrangeForm.option('items')[0].editorOptions['value'] = e.value;
											if(!e.value){
												arrangeForm.option('items')[1].editorOptions['disabled'] = false;
											}else{
												arrangeForm.option('items')[1].editorOptions['disabled'] = true;
											}
											arrangeForm.repaint();
										}
									}
								},
								{
									dataField: '컬럼 개수',
									editorType: 'dxNumberBox',
									editorOptions: {
										disabled : contentAutoColumn? true : false,
										value: contentColumnCount == undefined ? 5 : contentColumnCount,
										min : 0
									}
								}
							]
						}).dxForm('instance');
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
							var formData = arrangeForm.option('formData');
							_d3Chart.ContentOption.ContentAutoColumn = formData['컬럼 개수 자동 지정'];
							_d3Chart.ContentOption.ContentColumnCount = formData['컬럼 개수'];
							//2020.08.05 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
							self.functionBinddata = true;
							_d3Item.resize();
							p.hide();
						});
						contentElement.find('#close').on('click', function() {
							p.hide();
						});
					}
				});
				// show popup
				p.show();
				break;
			}
			// edit color scheme
			case 'editPalette': {
				if (!(_d3Item.dxItem)) {
					break;
				}
				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office'];
				//2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 DOGFOOT
				var paletteCollection2 = ['밝음', '발광체', '바다', '파스텔', '부드러움', '연한 파스텔', '나무', '포도', 
					'단색', '우주', '진보라', '안개숲', '연파랑', '기본값', '사무실 테마'];
				var paletteObject = {
						'Bright':'밝음',
						'Harmony Light':'발광체',
						'Ocean':'바다',
						'Pastel':'파스텔',
						'Soft':'부드러움',
						'Soft Pastel':'연한 파스텔',
						'Vintage':'나무',
						'Violet':'포도',
						'Carmine':'단색',
						'Dark Moon':'우주',
						'Dark Violet':'진보라',
						'Green Mist':'안개숲',
						'Soft Blue':'연파랑',
						'Material':'기본값',
						'Office':'사무실 테마',
						'Custom':'사용자 정의 테마',
					};
				var paletteObject2 = {
					'밝음':'Bright',
					'발광체':'Harmony Light',
					'바다':'Ocean',
					'파스텔':'Pastel',
					'부드러움':'Soft',
					'연한 파스텔':'Soft Pastel',
					'나무':'Vintage',
					'포도':'Violet',
					'단색':'Carmine',
					'우주':'Dark Moon',
					'진보라':'Dark Violet',
					'안개숲':'Green Mist',
					'연파랑':'Soft Blue',
					'기본값':'Material',
					'사무실 테마':'Office',
					'사용자 정의 테마':'Custom',
				};
				
				if (_d3Item.customPalette.length > 0) {
					paletteCollection.push('Custom');
					paletteCollection2.push('사용자 정의 테마');
				}
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chagePalette = _d3Item.meta.Palette;
				var firstPalette = _d3Item.meta.Palette;
				p.option({
                    target: '#editPalette',
                    onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // create html layout
                        var html = 	'<div id="' + _d3Item.itemid + '_paletteBox"></div>' +
								 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="save-ok" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="save-cancel" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        var select = $('#' + _d3Item.itemid + '_paletteBox');
                        // palette select
                        var originalPalette = paletteCollection.indexOf(_d3Item.meta.Palette) != -1
										? _d3Item.meta.Palette
										: 'Custom';
						select.dxSelectBox({
                            width: 400,
                            items: paletteCollection2,
                            itemTemplate: function(data) {
                                var html = $('<div />');
                                $('<p />').text(data).css({
                                    display: 'inline-block',
                                    float: 'left'
                                }).appendTo(html);
                                var itemPalette = data === '사용자 정의 테마'
										? _d3Item.customPalette 
										: DevExpress.viz.getPalette(paletteObject2[data]).simpleSet;
                                for (var i = 5; i >= 0; i--) {
                                    $('<div />').css({
                                        backgroundColor: itemPalette[i],
                                        height: 30,
                                        width: 30,
                                        display: 'inline-block',
                                        float: 'right'
                                    }).appendTo(html);
                                }
                                return html;
                            },
							value: paletteObject[originalPalette],
							onValueChanged: function(e) {
								if (e.value == '사용자 정의 테마') {
                                    _d3Item.isCustomPalette = true;
                                    /*_d3Item.dxItem.option('palette', _d3Item.customPalette);*/
                                    if(_d3Item.type === 'DENDROGRAM_BAR_CHART'){
                                        _d3Item.bindData();
                                    }else{
                                        _d3Item.resize();	
                                    }
                                    
								} else {
                                    _d3Item.isCustomPalette = false;
                                    _d3Item.meta.Palette = paletteObject2[e.value];
                                    if(_d3Item.type === 'DENDROGRAM_BAR_CHART'){
                                        _d3Item.bindData();
                                    }else{
                                        _d3Item.resize();	
                                    }
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                        	if(paletteObject2[select.dxSelectBox('instance').option('value')] != 'Custom'){
                                _d3Item.meta.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];	
                                chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                        	}
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	_d3Item.meta.Palette = firstPalette;
                            chagePalette = firstPalette;
                            _d3Item.resize();
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 _d3Item.meta.Palette = chagePalette;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
			case 'customPalette':
				self.setCustomPalette(_d3Item);
				break;
			case 'editLegend': {
				if (!(_d3Item.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
                    target: '#editLegend',
					contentTemplate: function(contentElement) {
						if(_d3Item.type.indexOf('FORCEDIRECT') > -1){
							$(	'<div id="' + _d3Item.itemid + '_toggleLegend" style="width:130px;"></div>' +
									'<div style="height: auto; width: 150px;">' +
										'<ul class="add-item-body icon-radio-list" style="display:block;">'+ 
											'<li >'+ 
												'<a  href="#" class="select-position" data-position="outside" data-description="TopLeftHorizontal">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHLeftTop.png" alt="">' +
												'</a>' + 
											'</li>' + 
											'<li>' + 
												'<a  href="#" class="select-position" data-position="outside" data-description="TopCenterHorizontal">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHCenterTop.png" alt="">' +
												'</a>' + 
											'</li>' +  
											'<li>' + 
												'<a  href="#" class="select-position" data-position="outside" data-description="TopRightHorizontal">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHRightTop.png" alt="">' +
												'</a>' + 
											'</li>' + 
											'<li >'+ 
												'<a  href="#" class="select-position" data-position="outside" data-description="BottomLeftHorizontal">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHLeftBottom.png" alt="">' +
												'</a>' + 
											'</li>' + 
											'<li>' + 
												'<a  href="#" class="select-position" data-position="outside" data-description="BottomCenterHorizontal">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHCenterBottom.png" alt="">' +
												'</a>' + 
											'</li>' +  
											'<li>' + 
												'<a  href="#" class="select-position" data-position="outside" data-description="BottomRightHorizontal">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHRightBottom.png" alt="">' +
												'</a>' + 
											'</li>' + 
										'</ul>' + 
									'</div>'							
								).appendTo(contentElement);
						} else if(_d3Item.type.indexOf('SCATTER_PLOT') > -1 && _d3Item.type !== 'SCATTER_PLOT_MATRIX'){
							$(	'<div id="' + _d3Item.itemid + '_toggleLegend" style="width:130px;"></div>' +
									'<div style="height: auto; width: 150px;">' +
										'<ul class="add-item-body icon-radio-list" style="display:block;">'+ 
											'<li>' + 
												'<a  href="#" class="select-position" data-description="LeftInner">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideVLeftTop.png" alt="">' +
												'</a>' + 
											'</li>' +  
											'<li>' + 
												'<a  href="#" class="select-position" data-description="RightInner">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideVRightTop.png" alt="">' +
												'</a>' + 
											'</li>' +  
											'<li>' + 
												'<a  href="#" class="select-position" data-description="RightOuter">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVRightTop.png" alt="">' +
												'</a>' + 
											'</li>' +  
											'<li>' + 
												'<a  href="#" class="select-position" data-description="LeftOuter">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVLeftTop.png" alt="">' +
												'</a>' + 
											'</li>' + 
											'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="TopCenterHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHCenterTop.png" alt="">' +
											'</a>' + 
											'</li>' +
											'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="BottomCenterHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHCenterBottom.png" alt="">' +
											'</a>' + 
										'</li>' +  
										'</ul>' + 
									'</div>'							
								).appendTo(contentElement);
						} else{
							$(	'<div id="' + _d3Item.itemid + '_toggleLegend" style="width:130px;"></div>' +
									'<div style="height: auto; width: 150px;">' +
										'<ul class="add-item-body icon-radio-list" style="display:block;">'+ 
											'<li>' + 
												'<a  href="#" class="select-position" data-position="outside" data-description="TopCenterHorizontal">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHCenterTop.png" alt="">' +
												'</a>' + 
											'</li>' +  
											'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="BottomCenterHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHCenterBottom.png" alt="">' +
											'</a>' + 
											'</li>' +  
											'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="TopLeftVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVLeftTop.png" alt="">' +
											'</a>' + 
											'</li>' + 
											'<li>' + 
												'<a  href="#" class="select-position" data-position="outside" data-description="TopRightVertical">' +
													'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVRightTop.png" alt="">' +
												'</a>' + 
											'</li>' + 
										'</ul>' + 
									'</div>'							
								).appendTo(contentElement);
						}
							
//						}
						/* DOGFOOT hsshim 2020-02-06 끝 */
						// toggle legend visibility
						$('#' + _d3Item.itemid + '_toggleLegend').dxButton({
                            text: '범례 표시',
							onClick: function() {
								_d3Item.meta.Legend.Visible = !_d3Item.meta.Legend.Visible;
								/*dogfoot 통계 구분 shlim 20201109*/
								if(gDashboard.reportType === 'StaticAnalysis'){
									_d3Item.resize();
								}else{
									_d3Item.bindData();
								}
							}
                        });
                        
						$.each($('.select-position'), function(index, position) {
							if (_d3Item.meta.Legend.Position) {
								if (_d3Item.meta.Legend.Position === $(position).data('description')){
										$(position).addClass('on');
									return false;
								}
							}
						});
						
						$('.select-position').off('click').on('click', function(e) {
                            $('.select-position.on').removeClass('on');
							$(this).addClass('on');
							var newDescription = $(this).data('description');
							_d3Item.meta.Legend.Position = newDescription;
							/*dogfoot 통계 구분 shlim 20201109*/
							if(gDashboard.reportType === 'StaticAnalysis'){
								_d3Item.resize();
							}else{
								_d3Item.bindData();
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
				
			}
			case 'singleMasterFilter': {
				if (!(_d3Item.dxItem)) {
					break;
				}
				gProgressbar.show();
				/* DOGFOOT 20201021 ajkim setTimeout 제거*/
				_d3Item.functionBinddata = true;
				_d3Item.trackingClearId = _d3Item.itemid + '_topicon_tracking_clear';
				// toggle off
				if (_d3Item.meta.InteractivityOptions.MasterFilterMode === 'Single') {
					$('#' + _d3Item.trackingClearId).addClass('invisible');
					_d3Item.meta.InteractivityOptions.MasterFilterMode = 'Off';
					_d3Item.clearTrackingConditions();
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
					var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
					if(reTrackItem){
						gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
					}else{
						gDashboard.filterData(_d3Item.itemid, _d3Item.trackingData);	
					}
				// toggle on
				} else {
					$('#' + _d3Item.trackingClearId).removeClass('invisible');
					_d3Item.meta.InteractivityOptions.MasterFilterMode = 'Single';
					_d3Item.meta.InteractivityOptions.MasterFilterMode = 'Single';
					
					// Only one master filter can be on. Turn off master filters on other items.
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
						/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
						if(gDashboard.getLayoutType() == "Container"){
							var ContainerList = gDashboard.setContainerList(_d3Item);            	

							$.each(ContainerList,function(_l,_con){
								if (_con.DashboardItem == item.ComponentName) {
									if (item.ComponentName !== _d3Item.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
										$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
										item.meta.InteractivityOptions.MasterFilterMode = 'Off';
										item.meta.InteractivityOptions.MasterFilterMode = 'Off';
										/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
										gDashboard.filterData(item.itemid, []);
									}
								}
							})

						}else{
							if (item.ComponentName !== _d3Item.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
								$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
								item.meta.InteractivityOptions.MasterFilterMode = 'Off';
								item.meta.InteractivityOptions.MasterFilterMode = 'Off';
								/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
								gDashboard.filterData(item.itemid, []);
							}
						}
					});
					_d3Item.clearTrackingConditions();
					// 첫번째 요소 선택 버튼 비활성화
//						_d3Item.selectFirstPoint();
					gProgressbar.hide();
				}
				break;
			}
			// toggle multiple master filter mode
			case 'multipleMasterFilter': {
				if (!(_d3Item.dxItem)) {
					break;
				}
				gProgressbar.show();
				/* DOGFOOT 20201021 ajkim setTimeout 제거*/
				_d3Item.functionBinddata = true;
				// Both master filter and drill-down cannot be active at the same time. Turn drill-down off.
				if (_d3Item.meta.InteractivityOptions.IsDrillDownEnabled) {
					_d3Item.terminateDrillDownOperation();
				}
				if (_d3Item.meta.InteractivityOptions.MasterFilterMode === 'Multiple') {
					$('#' + _d3Item.trackingClearId).addClass('invisible');
					_d3Item.meta.InteractivityOptions.MasterFilterMode = 'Off';
					_d3Item.clearTrackingConditions();

					var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
					if(reTrackItem){
						gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
					}else{
						gDashboard.filterData(_d3Item.itemid, _d3Item.trackingData);	
					}
				} else {
					$('#' + _d3Item.trackingClearId).removeClass('invisible');
					_d3Item.meta.InteractivityOptions.MasterFilterMode = 'Multiple';
					// Only one master filter can be on. Turn off master filters on other items.
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
						/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
						if(gDashboard.getLayoutType() == "Container"){
							var ContainerList = gDashboard.setContainerList(_d3Item);            	

							$.each(ContainerList,function(_l,_con){
								if (_con.DashboardItem == item.ComponentName) {
									if (item.ComponentName !== _d3Item.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
										$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
										item.meta.InteractivityOptions.MasterFilterMode = 'Off';
										/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
										gDashboard.filterData(item.itemid, []);
									}
								}
							})

						}else{
							if (item.ComponentName !== _d3Item.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
								$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
								item.meta.InteractivityOptions.MasterFilterMode = 'Off';
								/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
								gDashboard.filterData(item.itemid, []);
							}
						}
					});
					_d3Item.clearTrackingConditions();
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
//						_d3Item.selectFirstPoint();
				}
				
				gProgressbar.hide();
				break;
			}
			case 'ignoreMasterFilter': {								
				if (!(_d3Item.dxItem)) {
					break;
				}
				_d3Item.meta.InteractivityOptions.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
				_d3Item.tracked = !_d3Item.meta.InteractivityOptions.IgnoreMasterFilters;
				gProgressbar.show();
				/* DOGFOOT 20201021 ajkim setTimeout 제거*/
				if (_d3Item.meta.InteractivityOptions.IgnoreMasterFilters) {
					//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
					_d3Item.functionBinddata = true;
					_d3Item.bindData(_d3Item.globalData, true);
				} else {
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
						if (item.ComponentName !== _d3Item.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
							_d3Item.doTrackingCondition(item.itemid, item);
							return false;
						}
					});
				}
				gProgressbar.hide();
				break;
			}
			case 'editTextFormat': {
				if (!(_d3Item.dxItem)) {
					break;
				}
				var textCollection = ["none",'Argument', 'Value','Percent','Argument, Value', 'Value, Percent', 'Argument, Percent', 'Argument, Value, Percent'];
				var textCollection2 = ["없음",'인수', '값', '%','인수 및 값','값 및 %', '인수 및 %', '인수, 값 및 %'];
				
				if(_d3Item.type === 'HISTOGRAM_CHART'){
					textCollection = ["none",'Value','Percent', 'Value, Percent'];
					textCollection2 = ["없음", '값', '%','값 및 %'];
						
				}
				
//				if(_d3Item.type === 'SEQUENCES_SUNBURST' || _d3Item.type === 'LIQUID_FILL_GAUGE'){
//					textCollection.push("Argument, Value, Percent")
//					textCollection2.push("인수, 값 및 %");
//				}
				var textObject = {
						'none':'없음',
						'Argument':'인수',
						'Value':'값',
						'Percent':'%',
						'Argument, Value':'인수 및 값',
						'Value, Percent' : '값 및 %',
						'Argument, Percent' : '인수 및 %',
						"Argument, Value, Percent" : '인수, 값 및 %'
					};
				var textObject2 = {
						'없음':'none',
						'인수':'Argument',
						'값':'Value',
						'%':'Percent',
						'인수 및 값':'Argument, Value',
						'값 및 %' : 'Value, Percent',
						'인수 및 %' : 'Argument, Percent',
						'인수, 값 및 %' : "Argument, Value, Percent"
				    };
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chageTextFormat = _d3Item.meta.TextFormat;
				var firstTextFormat = _d3Item.meta.TextFormat;
				p.option({
                    target: '#editTextFormat',
                    onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // create html layout
                        var html = 	'<div id="' + _d3Item.itemid + '_textBox"></div>' +
								 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="save-ok" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="save-cancel" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        var select = $('#' + _d3Item.itemid + '_textBox');
                        // palette select
                        var originaltextFormat = textCollection.indexOf(_d3Item.meta.TextFormat) != -1
										? _d3Item.meta.TextFormat
										: 'none';
						select.dxSelectBox({
                            width: 300,
                            items: textCollection2,
                            itemTemplate: function(data) {
                                var html = $('<div />');
                                $('<p />').text(data).css({
                                    display: 'inline-block',
                                    float: 'center'
                                }).appendTo(html);
                                
                                return html;
                            },
							value: textObject[originaltextFormat],
							onValueChanged: function(e) {
								_d3Item.meta.TextFormat = textObject2[e.value];
                                if(_d3Item.type === 'DENDROGRAM_BAR_CHART'){
                                    _d3Item.bindData();
                                }else{
                                    _d3Item.resize();	
                                }
                                chageTextFormat = textObject2[e.value];
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            _d3Item.meta.TextFormat = textObject2[select.dxSelectBox('instance').option('value')];
                            chageTextFormat = textObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	_d3Item.meta.TextFormat = firstTextFormat;
                        	chageTextFormat = firstTextFormat;
                            _d3Item.resize();
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 _d3Item.meta.TextFormat = chageTextFormat;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
			
			case 'editAxisZ': {
				if (!(_d3Item.dxItem)) {
					break;
				}
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chageValue = _d3Item.meta.Round;
				var firstValue = _.cloneDeep(_d3Item.meta.Round);
				p.option({
                    target: '#editAxisZ',
                    onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // create html layout
                        var html = 	'<p>최소 크기: </p>' +
									'<div id="' + _d3Item.itemid + '_roundMin"></div>' +
									'<p>최대 크기: </p>' +
									'<div id="' + _d3Item.itemid + '_roundMax"></div>'+
								 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="save-ok" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="save-cancel" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        
                        if(_d3Item.type === 'SCATTER_PLOT' || _d3Item.type === 'SCATTER_PLOT_MATRIX'){
                        	$('#' + _d3Item.itemid + '_roundMax').css("display", 'none');
                        	contentElement.find('p:last').remove();
                        	
                        }
                        
                        var min =  $('#' + _d3Item.itemid + '_roundMin').dxNumberBox({
							showSpinButtons: true,
							width: 300,
							min: 0,
							/* DOGFOOT mksong 2020-08-10 카드 폭 예시카드 반영 */
							value: _d3Item.meta.Round.Min,
							onValueChanged : function(_e){
								_d3Item.meta.Round.Min = _e.value;
								if(max && _e.value > max.option('value'))
									   max.option('value',  min.option('value'))
								_d3Item.resize();
							}
						}).dxNumberBox('instance');
						
						var max =  $('#' + _d3Item.itemid + '_roundMax').dxNumberBox({
							showSpinButtons: true,
							min: min.option('value'),
							width: 300,
							/* DOGFOOT mksong 2020-08-10 카드 폭 예시카드 반영 */
							value : _d3Item.meta.Round.Max,
							onValueChanged : function(_e){
								if(_e.value < min.option('value'))
								    _e.component.option('value',  min.option('value'))
								_d3Item.meta.Round.Max = _e.value;
								_d3Item.resize();
							}
						}).dxNumberBox('instance');
						
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            _d3Item.meta.Round = {
                            		Min : min.option('value'),
                            		Max : max.option('value')
                            }
                            chageValue = {
                            		Min : min.option('value'),
                            		Max : max.option('value')
                            }
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	_d3Item.meta.Round = firstValue;
                        	chageValue = firstValue;
                            _d3Item.resize();
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 _d3Item.meta.TextFormat = chageTextFormat;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
			case 'editLayout':
				self.editLayout(_d3Item);
				break;
				
			case 'editZoom':
				if (!(_d3Item.dxItem)) {
					return;
				}
                var mapping = {
                    'ON': 'zoomInOut',
                    'OFF': 'none',
                    'zoomInOut': 'ON',
                    'none': 'OFF'
                };
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#editZoom',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        contentElement.empty();
						contentElement.append('<div id="' + _d3Item.itemid + '_editZoom">');
						$('#' + _d3Item.itemid + '_editZoom').dxRadioGroup({
							dataSource: ['ON','OFF'],
                            value: mapping[_d3Item.meta['ZoomAble']],
                            width: 120,
							onValueChanged: function(e) {
								_d3Item.meta['ZoomAble'] = mapping[e.value];
								_d3Item.resize();
							}
						});
						contentElement.append('<br/><a style="color:#666666; font-size:12px">[z+(스크롤 or 드래그)]을 사용하여 차트를 확대합니다.</a>')
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			case 'rotation':
				if (!(_d3Item.dxItem)) {
					return;
				}
                var mapping = {
                    '가로': 'Horizontal',
                    '세로': 'Vertical',
                    'Vertical': '세로',
                    'Horizontal': '가로'
                };
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#rotation',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        contentElement.empty();
						contentElement.append('<div id="' + _d3Item.itemid + '_editRotation">');
						$('#' + _d3Item.itemid + '_editRotation').dxRadioGroup({
							dataSource: ['가로','세로'],
                            value: mapping[_d3Item.meta['Rotated']],
                            width: 120,
							onValueChanged: function(e) {
								_d3Item.meta['Rotated'] = mapping[e.value];
								_d3Item.resize();
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			default: break;
		}
	};

	
	this.editLayout = function(_d3Item){
		if (!(_d3Item.dxItem)) {
			return;
		}
//		var sparklineOptions = self.meta.Card.SparklineOptions;
		var p = $('#editPopup').dxPopup('instance');
		p.option({
			title: '레이아웃 옵션',
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForOption('editPopup');
			},
			contentTemplate: function(contentElement) {
				// initialize template
				contentElement.append(	'<div id="' + _d3Item.itemid + '_layoutOptions"></div>' +
										'<div style="padding-bottom:20px;"></div>' +
										'<div class="modal-footer" style="padding-bottom:0px;">' +
											'<div class="row center">' +
												'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
												'<a id="close" href="#" class="btn neutral close">취소</a>' +
											'</div>' +
										'</div>');

				var layoutOptionHtml = '<div class="modal-article">';
				
				if(_d3Item.meta.LayoutOption.Title){
					layoutOptionHtml += ('<div class="add-item">' +
							'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">타이틀 설정</a>' +
							'<ul class="add-item-body">' +
								'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
								'<table>' +
									'<tr>' +
										'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
										'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
											'<select style="width:130px !important;" id="d3-title-font-setting">' +
									        '<option value="Basic">기본</option>' +
									        '<option value="Noto Sans KR">Noto Sans KR</option>' +
									        '<option value="Nanum Square">Nanum Square</option>' +
//									        '<option value="Roboto">Roboto</option>' +
									        '<option value="Georgia, serif">Georgia</option>' +
									        '<option value="sans-serif">sans-serif</option>' +
									        '<option value="monospace">monospace</option>' +
									        '<option value="cursive">cursive</option>' +
									        '<option value="Impact">Impact</option>' +
								         	'<option value="맑은 고딕">맑은 고딕</option>' +
								         	'<option value="굴림">굴림</option>' +
										'</select>' +
										'</td>' +
										'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="d3-title-fontsize-setting" style="width:55px"></td>' +
										'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
											'<div id="d3-title-color-setting">' +
											'</div>' +
										'</td>' +
									'</tr>' +
								'</table>' +
								'</div>' +
							'</ul>' +
						'</div>');
				}
				
				if(_d3Item.meta.LayoutOption.AxisX){
					layoutOptionHtml += ('<div class="add-item">' +
							'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">x축 설정</a>' +
							'<ul class="add-item-body">' +
								'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
								'<table>' +
									'<tr>' +
										'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
										'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
											'<select style="width:130px !important;" id="d3-x-font-setting">' +
									        '<option value="Basic">기본</option>' +
									        '<option value="Noto Sans KR">Noto Sans KR</option>' +
									        '<option value="Nanum Square">Nanum Square</option>' +
//									        '<option value="Roboto">Roboto</option>' +
									        '<option value="Georgia, serif">Georgia</option>' +
									        '<option value="sans-serif">sans-serif</option>' +
									        '<option value="monospace">monospace</option>' +
									        '<option value="cursive">cursive</option>' +
									        '<option value="Impact">Impact</option>' +
								         	'<option value="맑은 고딕">맑은 고딕</option>' +
								         	'<option value="굴림">굴림</option>' +
										'</select>' +
										'</td>' +
										'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="d3-x-fontsize-setting" style="width:55px"></td>' +
										'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
											'<div id="d3-x-color-setting">' +
											'</div>' +
										'</td>' +
									'</tr>' +
								'</table>' +
								'</div>' +
							'</ul>' +
						'</div>')
				}
				if(_d3Item.meta.LayoutOption.AxisY){
					layoutOptionHtml += ('<div class="add-item">' +
					'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">y축 설정</a>' +
					'<ul class="add-item-body">' +
						'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
						'<table>' +
							'<tr>' +
								'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
								'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
									'<select style="width:130px !important;" id="d3-y-font-setting">' +
							        '<option value="Basic">기본</option>' +
							        '<option value="Noto Sans KR">Noto Sans KR</option>' +
							        '<option value="Nanum Square">Nanum Square</option>' +
//							        '<option value="Roboto">Roboto</option>' +
							        '<option value="Georgia, serif">Georgia</option>' +
							        '<option value="sans-serif">sans-serif</option>' +
							        '<option value="monospace">monospace</option>' +
							        '<option value="cursive">cursive</option>' +
							        '<option value="Impact">Impact</option>' +
						         	'<option value="맑은 고딕">맑은 고딕</option>' +
						         	'<option value="굴림">굴림</option>' +
								'</select>' +
								'</td>' +
								'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="d3-y-fontsize-setting" style="width:55px"></td>' +
								'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
									'<div id="d3-y-color-setting">' +
									'</div>' +
								'</td>' +
							'</tr>' +
						'</table>' +
						'</div>' +
					'</ul>' +
				'</div>')
				}
				
				if(_d3Item.meta.LayoutOption.Label){
					layoutOptionHtml += ('<div class="add-item">' +
							'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">라벨 설정</a>' +
							'<ul class="add-item-body">' +
								'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
								'<table>' +
									'<tr>' +
										'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
										'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
											'<select style="width:130px !important;" id="d3-label-font-setting">' +
									        '<option value="Basic">기본</option>' +
									        '<option value="Noto Sans KR">Noto Sans KR</option>' +
									        '<option value="Nanum Square">Nanum Square</option>' +
//									        '<option value="Roboto">Roboto</option>' +
									        '<option value="Georgia, serif">Georgia</option>' +
									        '<option value="sans-serif">sans-serif</option>' +
									        '<option value="monospace">monospace</option>' +
									        '<option value="cursive">cursive</option>' +
									        '<option value="Impact">Impact</option>' +
								         	'<option value="맑은 고딕">맑은 고딕</option>' +
								         	'<option value="굴림">굴림</option>' +
										'</select>' +
										'</td>' +
										'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="d3-label-fontsize-setting" style="width:55px"></td>' +
										'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
											'<div id="d3-label-color-setting">' +
											'</div>' +
										'</td>' +
									'</tr>' +
								'</table>' +
								'</div>' +
							'</ul>' +
						'</div>');
				}
				
				
				if(_d3Item.meta.LayoutOption.Legend){
					layoutOptionHtml += (
							'<div class="add-item">' +
							'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">범례 설정</a>' +
							'<ul class="add-item-body">' +
								'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
								'<table>' +
									'<tr>' +
										'<th class="left" style="width:100px !important;padding-right: 8px !important;">글꼴</th>' +
										'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
											'<select style="width:130px !important;" id="d3-legend-font-setting">' +
									        '<option value="Basic">기본</option>' +
									        '<option value="Noto Sans KR">Noto Sans KR</option>' +
									        '<option value="Nanum Square">Nanum Square</option>' +
//									        '<option value="Roboto">Roboto</option>' +
									        '<option value="Georgia, serif">Georgia</option>' +
									        '<option value="sans-serif">sans-serif</option>' +
									        '<option value="monospace">monospace</option>' +
									        '<option value="cursive">cursive</option>' +
									        '<option value="Impact">Impact</option>' +
								         	'<option value="맑은 고딕">맑은 고딕</option>' +
								         	'<option value="굴림">굴림</option>' +
										'</select>' +
										'</td>' +
										'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="d3-legend-fontsize-setting" style="width:55px"></td>' +
										'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
										'<div id="d3-legend-color-setting">' +
										'</div>' +
									'</td>' +
									'</tr>' +
								'</table>' +
								'</div>' +
							'</ul>' +
						'</div>')
					
				}
				
				if(_d3Item.meta.LayoutOption.Circle && _d3Item.paletteData){
					layoutOptionHtml += (
							'<div class="add-item">' +
							'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6" title="0 입력시 기본값 적용">원 크기 설정</a>' +
							'<ul class="add-item-body">' +
								'<div class="tbl data-form preferences-tbl" style="max-height: 300px">' +
								'<table>');
					
					
					$.each(_d3Item.paletteData, function(i, color){
						layoutOptionHtml += (
						        '<tr>' +
								'<th class="left" style="width:100px !important;padding-right: 8px !important;">' + color + '</th>' +
								'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="d3-circle-size-setting-'+i+'" style="width:55px"></td>' +
								'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
								'<div id="d3-legend-color-setting">' +
								'</div>' +
								'</td>' +
								'</tr>'
						);
					});
										
									
									
					layoutOptionHtml += (
								'</table>' +
								'</div>' +
							'</ul>' +
						'</div>')
					
				}
				
				
				
			
			
		
																	
				layoutOptionHtml += '</div>'
				
				
				$('#' + _d3Item.itemid + '_layoutOptions').append(layoutOptionHtml);
									
											
				$(".add-item-head").click(function(e){
					if($(e.target).hasClass("on")){
						$(e.target).removeClass("on");
						$(e.target).addClass("off");
					}else{
						$(e.target).removeClass("off");
						$(e.target).addClass("on");
					}
				});
				
				// setting Value
				if(_d3Item.meta.LayoutOption.AxisX){
					if(_d3Item.meta.LayoutOption.AxisX.color){
						$("#d3-x-color-setting").dxColorBox({
							value : _d3Item.meta.LayoutOption.AxisX.color
						})
					}
					$("#d3-x-font-setting").val(_d3Item.meta.LayoutOption.AxisX.family)
					if(_d3Item.meta.LayoutOption.AxisX.size){
						$("#d3-x-fontsize-setting").val(_d3Item.meta.LayoutOption.AxisX.size)
					}else{
						$("#d3-x-fontsize-setting").parent().remove();
					}
				}
				if(_d3Item.meta.LayoutOption.Label){
					if(_d3Item.meta.LayoutOption.Label.color){
						$("#d3-label-color-setting").dxColorBox({
							value : _d3Item.meta.LayoutOption.Label.color
						})
					}
					$("#d3-label-font-setting").val(_d3Item.meta.LayoutOption.Label.family)
					if(_d3Item.meta.LayoutOption.Label.size){
						$("#d3-label-fontsize-setting").val(_d3Item.meta.LayoutOption.Label.size)
					}else{
						$("#d3-label-fontsize-setting").parent().remove();
					}
				}
				if(_d3Item.meta.LayoutOption.AxisY){
					if(_d3Item.meta.LayoutOption.AxisY.color){
						$("#d3-y-color-setting").dxColorBox({
							value : _d3Item.meta.LayoutOption.AxisY.color
						})
					}
					$("#d3-y-font-setting").val(_d3Item.meta.LayoutOption.AxisY.family)
					if(_d3Item.meta.LayoutOption.AxisY.size){
						$("#d3-y-fontsize-setting").val(_d3Item.meta.LayoutOption.AxisY.size)
					}else{
						$("#d3-y-fontsize-setting").parent().remove();
					}
				}
				if(_d3Item.meta.LayoutOption.Legend){
					if(_d3Item.meta.LayoutOption.Legend.color){
						$("#d3-legend-color-setting").dxColorBox({
							value : _d3Item.meta.LayoutOption.Legend.color
						})
					}
					$("#d3-legend-font-setting").val(_d3Item.meta.LayoutOption.Legend.family)
					if(_d3Item.meta.LayoutOption.Legend.size){
						$("#d3-legend-fontsize-setting").val(_d3Item.meta.LayoutOption.Legend.size)
					}else{
						$("#d3-legend-fontsize-setting").parent().remove();
					}
				}
				if(_d3Item.meta.LayoutOption.Title){
					if(_d3Item.meta.LayoutOption.Title.color){
						$("#d3-title-color-setting").dxColorBox({
							value : _d3Item.meta.LayoutOption.Title.color
						})
					}
					$("#d3-title-font-setting").val(_d3Item.meta.LayoutOption.Title.family)
					if(_d3Item.meta.LayoutOption.Title.size){
						$("#d3-title-fontsize-setting").val(_d3Item.meta.LayoutOption.Title.size)
					}else{
						$("#d3-title-fontsize-setting").parent().remove();
					}
				}
				if(_d3Item.meta.LayoutOption.Circle){
					for(var i = 0; i < _d3Item.meta.LayoutOption.Circle.length; i++){
						$("#d3-circle-size-setting-"+i).val(_d3Item.meta.LayoutOption.Circle[i]);
					}
				}
				
				
                                        
                // confirm and cancel
				contentElement.find('#ok-hide').on('click', function() {
					// setting Value
					if(_d3Item.meta.LayoutOption.AxisX){
						if(_d3Item.meta.LayoutOption.AxisX.color){
							_d3Item.meta.LayoutOption.AxisX.color = $("#d3-x-color-setting").dxColorBox('instance').option('value');
						}
						_d3Item.meta.LayoutOption.AxisX.family = $("#d3-x-font-setting").val()
						if(_d3Item.meta.LayoutOption.AxisX.size){
							_d3Item.meta.LayoutOption.AxisX.size = $("#d3-x-fontsize-setting").val()
						}
					}
					if(_d3Item.meta.LayoutOption.Label){
						if(_d3Item.meta.LayoutOption.Label.color){
							_d3Item.meta.LayoutOption.Label.color = $("#d3-label-color-setting").dxColorBox('instance').option('value');
						}
						_d3Item.meta.LayoutOption.Label.family = $("#d3-label-font-setting").val()
						if(_d3Item.meta.LayoutOption.Label.size){
							_d3Item.meta.LayoutOption.Label.size = $("#d3-label-fontsize-setting").val()
						}
					}
					if(_d3Item.meta.LayoutOption.AxisY){
						if(_d3Item.meta.LayoutOption.AxisY.color){
							_d3Item.meta.LayoutOption.AxisY.color = $("#d3-y-color-setting").dxColorBox('instance').option('value');
						}
						_d3Item.meta.LayoutOption.AxisY.family = $("#d3-y-font-setting").val()
						if(_d3Item.meta.LayoutOption.AxisY.size){
							_d3Item.meta.LayoutOption.AxisY.size = $("#d3-y-fontsize-setting").val()
						}
					}
					if(_d3Item.meta.LayoutOption.Legend){
						if(_d3Item.meta.LayoutOption.Legend.color){
							_d3Item.meta.LayoutOption.Legend.color = $("#d3-legend-color-setting").dxColorBox('instance').option('value');
						}
						_d3Item.meta.LayoutOption.Legend.family = $("#d3-legend-font-setting").val()
						if(_d3Item.meta.LayoutOption.Legend.size){
							_d3Item.meta.LayoutOption.Legend.size = $("#d3-legend-fontsize-setting").val()
						}
					}
					if(_d3Item.meta.LayoutOption.Title){
						if(_d3Item.meta.LayoutOption.Title.color){
							_d3Item.meta.LayoutOption.Title.color = $("#d3-title-color-setting").dxColorBox('instance').option('value');
						}
						_d3Item.meta.LayoutOption.Title.family = $("#d3-title-font-setting").val()
						if(_d3Item.meta.LayoutOption.Title.size){
							_d3Item.meta.LayoutOption.Title.size = $("#d3-title-fontsize-setting").val()
						}
					}
					if(_d3Item.meta.LayoutOption.Circle){
						for(var i = 0; i < _d3Item.meta.LayoutOption.Circle.length; i++){
							_d3Item.meta.LayoutOption.Circle[i] = $("#d3-circle-size-setting-"+i).val();
						}
					}
					_d3Item.resize();
					p.hide();
				});
				contentElement.find('#close').on('click', function() {
					p.hide();
				});
			}
		});
		// show popup
		p.show();
	}
	// 사용자정의팔레트 세팅
	this.setCustomPalette = function(_d3Item){
		if (!(_d3Item.dxItem)) {
			return;
		}
		var p = $('#editPopup').dxPopup('instance');
		
		function rgbToHex ( rgb){
	        var toHex = function( string ){ 
	                string = parseInt( string, 10 ).toString( 16 ); 
	                string = ( string.length === 1 ) ? "0" + string : string; 

	                return string; 
	        }; 

	        var r = toHex( rgb.r ); 
	        var g = toHex( rgb.g ); 
	        var b = toHex( rgb.b ); 

	        var hexType = "#" + r + g + b; 

	        return hexType; 
		}

		p.option({
			title: '색상 편집',
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForOption('editPopup');
			},
			contentTemplate: function(contentElement) {
                var colorContainer = $('<div id="colorContainer"></div>');
                var names = [];
                
            	 $.each(_d3Item.paletteData, function(index, name) {
            		 colorContainer.append('<p>' + name
								+ '</p><div id="' + _d3Item.itemid + '_itemsColor' + index + '"></div>');
            	 });
                
                colorContainer.dxScrollView({
                    height: 600,
                    width: '100%'
                }).appendTo(contentElement);
				var html = 	'<div style="padding-bottom:20px;"></div>' +
							'<div class="modal-footer" style="padding-bottom:0px;">' +
								'<div class="row center">' +
									'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
									'<a id="close" href="#" class="btn neutral close">취소</a>' +
								'</div>' +
							'</div>';
				contentElement.append(html);

				 $.each(_d3Item.paletteData, function(index, data) {
					 var color;
					 var palette = _d3Item.meta.Palette;
					 if(typeof palette === "string" && palette !='default'){
	                    palette = getPaletteValue(palette)
					 }
					 if(palette =='default'){
					 	palette = ['#bfbfbf','#838383','#4c4c4c','#1c1c1c'];
					 }
					
					
					 color = palette[index % palette.length];
					 if(typeof color !== 'string')
						 color = rgbToHex(color);
					 $('#' + _d3Item.itemid + '_itemsColor' + index).dxColorBox({
						value: color
					 });
                });

                // confirm and cancel
				$('#ok-hide').on('click', function() {
                    var newPalette = [];
                    $.each(_d3Item.paletteData, function(index, item) {
                        newPalette[index] = $('#' + _d3Item.itemid + '_itemsColor' + index).dxColorBox('instance').option('value');
                    });
                    
                    _d3Item.meta['Palette'] = newPalette;
                    if(_d3Item.type === 'DENDROGRAM_BAR_CHART'){
                        _d3Item.bindData();
                    }else{
                        _d3Item.resize();	
                    }
                    _d3Item.customPalette = newPalette;
                    _d3Item.isCustomPalette = true;
                    p.hide();
				});
				$('#close').on('click', function() {
					p.hide();
				});
			}
		});
		p.show();
	};
	
	this.getPalette = function(_d3Item){
		var palette = _d3Item.meta.Palette
		if(typeof palette === "string")
			return getPaletteValue(palette);
		else{
			var result = [];
			$.each(palette, function(_i, _color){
				var color = gDashboard.itemColorManager.hexToRgb(_color);
				result.push(d3.rgb(color.r, color.g, color.b));
			});
			return result;
		}
	}
};