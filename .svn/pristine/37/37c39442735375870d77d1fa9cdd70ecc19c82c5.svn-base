/**
 * 
 */

WISE.libs.Dashboard.Query = {
	likeSql: {
		/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
		fromJson: function(_dimensions, _measures, _data, _option, _itemtype, _orderKey) {
			var comwhere = new Array();
			var casewhere = new Array();
			var maxcol = new Array();
			var sqlConfig = {};
			var selectDistinct = [];
			
			/*dogfoot 데이터 집합이 같을 때만 where 절 추가 추가 동작 통일화 shlim 20200619*/
			if(typeof gDashboard.itemGenerateManager.itemDataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
				if(gDashboard.itemGenerateManager.itemDataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
					sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				}else{
					/*dogfoot 교차데이터 소스 필터링 설정 시 마스터필터 조건 절 추가 shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						if(gDashboard.itemGenerateManager.focusedItem){
							if(gDashboard.itemGenerateManager.focusedItem.IsMasterFilterCrossDataSource){
		                        sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
							}else{
							    sqlConfig.Where = [];	
							}
						}else{
						    sqlConfig.Where = [];	
						}
					}else{
						if(gDashboard.itemGenerateManager.focusedItem.IsMasterFilterCrossDataSource){
	                        sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
						}else{
						    sqlConfig.Where = [];	
						}
					}
				}
			}else{
				sqlConfig.Where = [];
			}
			
			
			if ($.type(_dimensions) === 'string' && _dimensions === '*') {
				sqlConfig.Select = ['*'];
				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				
				if(_option && _option.where) {
					sqlConfig.Where = _option.where;
				}
				
				if (_option && _option.orderBy) {
					sqlConfig.OrderBy = [];
					$.each(_option.orderBy, function(_i, _d) {
						if(_d.nameBySummaryType != undefined){
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
							sqlConfig.OrderBy.push(_d.name);
//							sqlConfig.OrderBy.push(_d.caption);
//							sqlConfig.OrderBy.push(_d.nameBySummaryType);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}
						else{
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
							sqlConfig.OrderBy.push(_d.name);
//							sqlConfig.OrderBy.push(_d.caption);
//							sqlConfig.OrderBy.push(_d.name || _d);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}
					});
				}
			}
			else if (_dimensions.length > 0 && (!_measures || _measures.length == 0)) {
			//2020.01.30 mksong SQLLIKE DISTINCT 오류 수정 dogfoot
				sqlConfig.Select = [];
//				sqlConfig.SelectDistinct = [];
				$.each(_dimensions, function(_i, _d) {
					sqlConfig.isDiscountQuery = true;
					sqlConfig.Select.push(_d.name);
					//2020.01.31 MKSONG ALIAS 기능 수정 DOGFOOT
					sqlConfig.Select.push('|as|');
//					sqlConfig.Select.push(_d.name);
					sqlConfig.Select.push(_d.caption);
//					sqlConfig.SelectDistinct.push(_d.name);
				});
				
				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.OrderBy = [];
				/*dogfoot 일반 그리드 차원만 올렸을때 무한로딩 수정 shlim 20210728*/
				sqlConfig.GroupBy = [];
				$.each(_dimensions, function(_i, _d) {
					sqlConfig.GroupBy.push(_d.name);
					if(typeof _orderKey != 'undefined' && _orderKey.length > 0) {
						$.each(_orderKey, function(_ordi, _ordkey) {
							if((_d.CubeUniqueName == _ordkey.logicalColumnName || _d.uniqueName == _ordkey.uniqueName) && sqlConfig.OrderBy.indexOf(_ordkey.orderByCaption) == -1) {
								if(sqlConfig.GroupBy.indexOf(_ordkey.orderByCaption) == -1) {
									sqlConfig.GroupBy.push(_ordkey.orderByCaption);
								}
								var sortOrder = _d.sortOrder || 'asc';
								sqlConfig.OrderBy.push(_ordkey.orderByCaption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');

								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');

								if(typeof _itemtype != 'undefined' && _itemtype == 'PIVOT_GRID' && sqlConfig.Select.indexOf(_ordkey.orderByCaption) == -1){
									sqlConfig.Select.push(_ordkey.orderByCaption);
									sqlConfig.Select.push('|as|');
									//						sqlConfig.Select.push(_d.name);
									sqlConfig.Select.push(_ordkey.orderByCaption);	
								}
							}
						});
					} else if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
						var dimensionOrder = true;
						$.each(gDashboard.datasetMaster.state.fields[gDashboard.itemGenerateManager.itemDataSourceId], function(_ii, _ee) {
							if(_ee.CAPTION == 'S_' + _d.caption) {
                                /*dogfoot 쿼리 직접입력 정렬 오류 수정 shlim 20210728*/
                                sqlConfig.Select.push(_ee.CAPTION);
								sqlConfig.Select.push('|as|');
								//						sqlConfig.Select.push(_d.name);
								sqlConfig.Select.push(_ee.CAPTION);

								sqlConfig.GroupBy.push(_ee.CAPTION);
								var sortOrder = _d.sortOrder || 'asc';
								sqlConfig.OrderBy.push(_ee.CAPTION);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');

								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');

								dimensionOrder = false;
							}
						});

						if(dimensionOrder) {
							var sortOrder = _d.sortOrder || 'asc';
							sqlConfig.OrderBy.push(_d.caption);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}
					}
					/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
					else if(typeof _d.tempdata == 'undefined') {
						var sortOrder = _d.sortOrder || 'asc';
						//2020.01.30 mksong sqlike config 수정 dogfoot
//						sqlConfig.OrderBy.push(_d.name);
						sqlConfig.OrderBy.push(_d.caption);
						sqlConfig.OrderBy.push('|' + sortOrder + '|');
					}
//					sqlConfig.OrderBy.push(_d.name);
//					var sortOrder = _d.sortOrder || 'asc';
//					sqlConfig.OrderBy.push('|' + sortOrder + '|');
				});
				if(!gDashboard.gridDownloadNonCustomFiled){
					if(typeof gDashboard.customFieldManager.fieldNameList != 'undefined') {
						if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
							$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
								if(sqlConfig.Select.indexOf(_d) == -1) {
									sqlConfig.Select.push('|sum|');
									sqlConfig.Select.push(_d);
									sqlConfig.Select.push('|as|');
									sqlConfig.Select.push('sum_' + _d);
								}
							});
						} else {
							$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
								if(sqlConfig.Select.indexOf(_d) == -1) {
									sqlConfig.Select.push('|sum|');
									sqlConfig.Select.push(_d);
									sqlConfig.Select.push('|as|');
									sqlConfig.Select.push(_d);
								}
							});
						}
					}
				}
			}
			else {
				sqlConfig.Select = [];
				
				$.each(_dimensions, function(_i, _d) {
					if(_d.name == undefined) return;
					
					sqlConfig.Select.push(_d.name);
					//2020.01.31 MKSONG ALIAS 기능 수정 DOGFOOT
					sqlConfig.Select.push('|as|');
//					sqlConfig.Select.push(_d.name);
					sqlConfig.Select.push(_d.caption);
				});
				$.each(_measures, function(_i, _d) {
					var summaryType = _d.summaryType || 'sum';
					if(gDashboard.analysisType !== undefined) summaryType = ''; //통계분석
					
					if(summaryType == '') {
						sqlConfig.Select.push(_d.name);
						//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
						sqlConfig.Select.push('|as|');
						/* DOGFOOT ktkang 데이터그리드 사용자정의데이터 오류 수정  20200705 */
						if(_d.tempdata && _itemtype == 'DATA_GRID') {
							sqlConfig.Select.push(_d.name);
						} else if(_d.tempdata && _itemtype == 'SIMPLE_CHART') {
							sqlConfig.Select.push(_d.nameBySummaryType2);
						} else {
							sqlConfig.Select.push(_d.nameBySummaryType);
						}
					} else if (_d.summaryType === 'countdistinct') {
						var distinctCount = function(_columName, _data, _dimensions) {
							return function() {
								var rowData = this, whereClause = [];
								$.each(_dimensions, function(_xx, _oo) {
									whereClause.push('this["'+_oo.name+'"] == rowData["'+_oo.name+'"]');
								});
								
								var sc = {
									'Select': [_columName],
									'From': _data,
									'Where':gDashboard.itemGenerateManager.sqlConfigWhere,
									'GroupBy': [_columName]
								};
								if (whereClause.length > 0) {
									sc.Where = function(_a) {
										return eval(whereClause.join(' && '));
									};
								}
//								if(_option && _option.where) { // 16.01.28 제거
//									sc.Where = _option.where;
//								}
								return SQLike.q(sc).length;
							};
						};
						
						//2020.01.30 mksong SQLLIKE DISTINCT 오류 수정 dogfoot
						sqlConfig.isDiscountQuery = true;
						sqlConfig.Select.push('|' + summaryType + '|');
						sqlConfig.Select.push(_d.name);
						sqlConfig.Select.push('|as|');
						sqlConfig.Select.push(_d.nameBySummaryType);
//						sqlConfig.Select.push(_d.captionBySummaryType);
						
//						sqlConfig.SelectDistinct.push(distinctCount(_d.name, _data, _dimensions));
//						selectDistinct.push('|count|');
//						selectDistinct.push(_d.name);
//						selectDistinct.push('|as|');
//						selectDistinct.push(_d.nameBySummaryType);
					}
					else {
						if(!gDashboard.gridDownloadNonCustomFiled){
							sqlConfig.Select.push('|' + summaryType + '|');
							sqlConfig.Select.push(_d.name);
							//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
							sqlConfig.Select.push('|as|');
							/* DOGFOOT ktkang 데이터그리드 사용자정의데이터 오류 수정  20200705 */
							if(_d.tempdata && _itemtype == 'DATA_GRID') {
								sqlConfig.Select.push(_d.name);
							} else if(_d.tempdata && _itemtype == 'SIMPLE_CHART') {
								sqlConfig.Select.push(_d.nameBySummaryType2);
							} else {
								sqlConfig.Select.push(_d.nameBySummaryType);
							}
						}else{
							if(!(_d.tempdata && _itemtype == 'DATA_GRID')){
                                sqlConfig.Select.push('|' + summaryType + '|');
								sqlConfig.Select.push(_d.name);
								//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
								sqlConfig.Select.push('|as|');
								/* DOGFOOT ktkang 데이터그리드 사용자정의데이터 오류 수정  20200705 */
								if(_d.tempdata && _itemtype == 'SIMPLE_CHART') {
									sqlConfig.Select.push(_d.nameBySummaryType2);
								} else {
									sqlConfig.Select.push(_d.nameBySummaryType);
								}
							}
						}
						
						
//						sqlConfig.Select.push(_d.captionBySummaryType);
					}
				});
				if(!gDashboard.gridDownloadNonCustomFiled){
					//dogfoot 사용자정의데이터 사용하지 않은 보고서 열 때 차트 안나오는 오류 수정 20211221 syjin
					if(typeof gDashboard.customFieldManager.fieldNameList != 'undefined') {
						if(typeof gDashboard.customFieldBuffer != 'undefined'){
							if(typeof gDashboard.customFieldBuffer[gDashboard.reportUtility.reportInfo.ReportMasterInfo.id] != 'undefined'){
								if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
									$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
										if(sqlConfig.Select.indexOf(_d) == -1) {
											sqlConfig.Select.push('|sum|');
											sqlConfig.Select.push(_d);
											sqlConfig.Select.push('|as|');
											sqlConfig.Select.push('sum_' + _d);
										}
									});
								} else {
									$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
										if(sqlConfig.Select.indexOf(_d) == -1) {
											sqlConfig.Select.push('|sum|');
											sqlConfig.Select.push(_d);
											sqlConfig.Select.push('|as|');
											sqlConfig.Select.push(_d);
										}
									});
								}
							}
						}				
					}
				}
				

				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				
				if(_option && _option.where) {

					sqlConfig.Where = _option.where;
				}
				
				if (_dimensions && $.type(_dimensions) === 'array' && _dimensions.length > 0 && gDashboard.analysisType === undefined) {
					sqlConfig.GroupBy = [];
					
					sqlConfig.OrderBy = [];
					
					$.each(_dimensions, function(_i, _d) {
						if(_d.name == undefined) return;
						//2020.02.04 MKSONG ALIAS 기능 수정 DOGFOOT
						sqlConfig.GroupBy.push(_d.name);
//						sqlConfig.GroupBy.push(_d.name);
						
						/* goyong ktkang 본사적용 주제영역 정렬 오류 본사는 잘되면 패스  20210611 */
						//if(typeof gDashboard.itemGenerateManager.focusedItem != 'undefined'){
							//if(_d.sortByMeasure !== '' && $.type(_d.sortByMeasure) === 'string' && ((typeof gDashboard.itemGenerateManager.focusedItem != 'undefined' 
							//	&& gDashboard.itemGenerateManager.focusedItem.HiddenMeasures.length > 0) || !WISE.Context.isCubeReport))
							//{
							/* DOGFOOT syjin 뷰어에서 그리드 정렬 order by 절 생략 되는 부분 수정 20211130 */
							if(_d.sortByMeasure !== '' && $.type(_d.sortByMeasure) === 'string')
							{
								$.each(_measures, function(_i0, _d0) {
									var sortOrder = _d.sortOrder || 'asc';
									var find;
									if(_d0.name == _d.sortByMeasure)
									{
//										var sortOrder = _d.sortOrder || 'asc';
//										find = true;
										/*dogfoot orderby 설정 순서 변경 shlim 20200701*/
										sqlConfig.OrderBy.push(_d0.nameBySummaryType);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');	

									}
									/* DOGFOOT ktkang 정렬 순서 꼬이는 오류 수정  20200909 */
//									if(find){
//									//2020.01.30 mksong sqlike config 수정 dogfoot
////									sqlConfig.OrderBy.push(_d.name);
//									/*dogfoot orderby 설정 순서 변경 shlim 20200701*/
//									sqlConfig.OrderBy.push(_d.caption);
//									sqlConfig.OrderBy.push('|' + sortOrder + '|');	
//									}
								});

								$.each(_dimensions, function(_i0, _d0) {
									if(_d0.name == undefined) return;
									var sortOrder = _d.sortOrder || 'asc';
									var find;
									if(_d0.name == _d.sortByMeasure)
									{
										find = true;
										//2020.01.30 mksong sqlike config 수정 dogfoot
//										sqlConfig.OrderBy.push(_d0.nameBySummaryType);
										sqlConfig.OrderBy.push(_d0.caption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
									}
									if(find){
										//2020.01.30 mksong sqlike config 수정 dogfoot
//										sqlConfig.OrderBy.push(_d.name);
										sqlConfig.OrderBy.push(_d.caption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');	
									}
								});
								/* goyong ktkang 본사적용 주제영역 정렬 오류 본사는 잘되면 패스  20210611 */
							//}else if(_d.sortByMeasure !== undefined && ((typeof gDashboard.itemGenerateManager.focusedItem != 'undefined' 
							//	&& gDashboard.itemGenerateManager.focusedItem.HiddenMeasures.length > 0) || !WISE.Context.isCubeReport)){
							/* DOGFOOT syjin 뷰어에서 그리드 정렬 order by 절 생략 되는 부분 수정 20211130 */
							}else if(_d.sortByMeasure !== undefined){
								var sortOrder = _d.sortOrder || 'asc';
								//2020.01.30 mksong sqlike config 수정 dogfoot
//								sqlConfig.OrderBy.push(_d.name);
								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');
							}else{
								/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
								if(_orderKey && _orderKey.length > 0) {
									$.each(_orderKey, function(_ordi, _ordkey) {
										if(_d.CubeUniqueName == _ordkey.logicalColumnName || _d.uniqueName == _ordkey.uniqueName) {
											if(_d.CubeUniqueName == undefined) return; 
											if(sqlConfig.GroupBy.indexOf(_ordkey.orderByCaption) == -1) {
												sqlConfig.GroupBy.push(_ordkey.orderByCaption);
											}
											var sortOrder = _d.sortOrder || 'asc';
											sqlConfig.OrderBy.push(_ordkey.orderByCaption);
											sqlConfig.OrderBy.push('|' + sortOrder + '|');

											sqlConfig.OrderBy.push(_d.caption);
											sqlConfig.OrderBy.push('|' + sortOrder + '|');
										}
									});
								} else if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
									var dimensionOrder = true;
									$.each(gDashboard.datasetMaster.state.fields[gDashboard.itemGenerateManager.itemDataSourceId], function(_ii, _ee) {
										if(_ee.CAPTION == 'S_' + _d.caption) {
											/*dogfoot 쿼리 직접입력 정렬 오류 수정 shlim 20210728*/
											sqlConfig.Select.push(_ee.CAPTION);
											sqlConfig.Select.push('|as|');
											//						sqlConfig.Select.push(_d.name);
											sqlConfig.Select.push(_ee.CAPTION);
											sqlConfig.GroupBy.push(_ee.CAPTION);
											var sortOrder = _d.sortOrder || 'asc';
											sqlConfig.OrderBy.push(_ee.CAPTION);
											sqlConfig.OrderBy.push('|' + sortOrder + '|');

											sqlConfig.OrderBy.push(_d.caption);
											sqlConfig.OrderBy.push('|' + sortOrder + '|');

											dimensionOrder = false;
										}
									});

									if(dimensionOrder) {
										var sortOrder = _d.sortOrder || 'asc';
										sqlConfig.OrderBy.push(_d.caption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
									}
								}
								/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
								else if(typeof _d.tempdata == 'undefined') {
									var sortOrder = _d.sortOrder || 'asc';
									//2020.01.30 mksong sqlike config 수정 dogfoot
//									sqlConfig.OrderBy.push(_d.name);
									sqlConfig.OrderBy.push(_d.caption);
									sqlConfig.OrderBy.push('|' + sortOrder + '|');
								}
							}
						//}
					});
					
					if (!_option || !_option.exceptDimensionOrderBy) {
						$.each(_dimensions, function(_i, _d) {
							/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
							if(typeof _d.tempdata == 'undefined') {
								if(_d.name == undefined) return;
								var sortOrder = _d.sortOrder || 'asc';
								//2020.01.30 mksong sqlike config 수정 dogfoot
//								sqlConfig.OrderBy.push(_d.name);
								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');
							}
						});
					}
					
					if (_option && _option.orderBy) {
						//2020.10.21 MKSONG 데이터그리드 스파크라인 정렬 오류 수정 DOGFOOT
//						sqlConfig.OrderBy = sqlConfig.OrderBy || [];
						sqlConfig.OrderBy = [];
						
						$.each(_option.orderBy, function(_i, _d) {
							if(_d.caption == undefined) return;
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
//							sqlConfig.OrderBy.push(_d.name || _d);
//							sqlConfig.OrderBy.push(_d.name);
							sqlConfig.OrderBy.push(_d.caption);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						});
					}
				}
			}
			
			var brewer = function(_sqlikeData) {
				var basten = [];
				
				$.each(_sqlikeData, function(_i0, _d0) {
					var dataObj = {};
					
					$.each(_d0, function(_i1, _d1) {
						var key = _i1;
						if (key.indexOf('sum_') === 0) {
							key = key.replace(/sum_/, '');
						}
						else if (key.indexOf('count_') === 0) {
							key = key.replace(/count_/, '');
						}
						else if (key.indexOf('countdistinct_') === 0) {
							key = key.replace(/countdistinct_/, '');
						}
						else if (key.indexOf('min_') === 0) {
							key = key.replace(/min_/, '');
						}
						else if (key.indexOf('max_') === 0) {
							key = key.replace(/max_/, '');
						}
						else if (key.indexOf('avg_') === 0) {
							key = key.replace(/avg_/, '');
						}
						else {
							// do nothing...
						}
						
						dataObj[key] = _d1;
					});
					
					basten.push(dataObj);
				});
				
				return basten;
			};
			
			var replaceForCountDistinct = function(_sqlikeData,_sqlikeData2) {
				var basten = [];
				
				$.each(_sqlikeData2, function(_i0, _d0) {
					$.each(_sqlikeData, function(_i1, _d1){
						if(_i1 == _i0){
							var dataObj = {};
							dataObj = _d1;
							$.each(_d0, function(_i2, _d2) {
								var key = _i2;
								if (key.indexOf('countdistinct') >= 0) {
									key = key.replace(/count_countdistinct_/, 'countdistinct_');
									dataObj[key] = _d2;
								}
							});	
							basten.push(dataObj);
						}
					});
				});
				
				return basten;
			};
			
			var doPrecision = function(_measures, _sqlikeData) {
				
				var newData = [];
				$.each(_sqlikeData, function(_i0, _col) {
					
					var newCol = {};
					$.each(_col, function(_colnm, _val) {
						
						$.each(_measures, function(_i1, _m) {
							
							var precision = !_m.precision || _m.precision < 1 ? 0 : _m.precision;
							var mnm = _option && _option.doBrewer ? _m.name : ((_m.summaryType ? _m.summaryType + '_' : '') + _m.name);
							
							if (mnm == _colnm && $.type(_val) === 'number') {
						
//								if(_val == '1' && precision != 0)
//									_val = 0;
							//_val = $.number(_val, 5);
							//	_val = _val.toFixed(1);
							/*	if(_val.toString()=='Infinity')
								{
									_val = 0;
								}
								else
								{
									var _valTmp =(_val * 100).toFixed(precision);
									_val = Number(_valTmp);
								}*/
								
							}
							
//							var precision = !_m.precision || _m.precision < 1 ? 0 : _m.precision;
//							var mnm = _option && _option.doBrewer ? _m.name : ((_m.summaryType ? _m.summaryType + '_' : '') + _m.name);
//							
//							if (mnm == _colnm && $.type(_val) === 'number') {
//								_val = $.number(_val, precision);

//								_val = _val.replace(/,/g, '');
//								_val = Number(_val);

//							}
						});
						
						newCol[_colnm] = _val;
					});
					
					newData.push(newCol);
				});
				
				return newData;
			};
			
			var data;
			//2020.01.30 mksong sqlike config 수정 dogfoot
			if(selectDistinct.length != 0){
//				var data1 = SQLike.q(sqlConfig);
						
				sqlConfig.SelectDistinct = selectDistinct.concat(sqlConfig.Select);
				sqlConfig.Select = undefined;
				
//				var data2 = SQLike.q(sqlConfig);
				
//				data = replaceForCountDistinct(data1, data2);
			}else{
//				data = SQLike.q(sqlConfig);
			}
			
//			if(_option && _option.doBrewer) data = brewer(data);
//			if (_measures) data = doPrecision(_measures, data);
//			$.each(data,function(_i,_datas){
//				$.each(_measures, function(_i, _d) {
//					if(_datas[_d.nameBySummaryType] != undefined || _datas[_d.captionBySummaryType] != undefined){
//						var obj = _datas;
//						obj[_d.caption] = (obj[_d.nameBySummaryType] || obj[_d.captionBySummaryType]);
//						delete  obj[_d.nameBySummaryType];
//						delete  obj[_d.captionBySummaryType];
//					}
//				});
//			})
			var orderByFieldList = [];
			$.each(sqlConfig.OrderBy,function(_i,_orderBy){
				var checkDuplicate = false;
				$.each(orderByFieldList,function(_k,_orderByField){
					if(_orderBy == _orderByField){
						checkDuplicate = true;
					}
				});
				if(!checkDuplicate){
					if(_orderBy != '|asc|' && _orderBy != '|desc|'){
						orderByFieldList.push(_orderBy);
						orderByFieldList.push(sqlConfig.OrderBy[_i+1]);
					}
				}
			});
			sqlConfig.OrderBy = orderByFieldList;
			
			data = sqlConfig;
			//2020.01.30 mksong sqlike config 수정 끝 dogfoot
			return data;
		},
		/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
		fromJsonForCaptionBySummaryType: function(_dimensions, _measures, _data, _option, _itemtype, _orderKey) {
			var comwhere = new Array();
			var casewhere = new Array();
			var maxcol = new Array();
			var sqlConfig = {};
			var selectDistinct = [];
			
			/*dogfoot 데이터 집합이 같을 때만 where 절 추가 추가 동작 통일화 shlim 20200619*/
			if(typeof gDashboard.itemGenerateManager.itemDataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
				if(gDashboard.itemGenerateManager.itemDataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
					sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				}else{
					/*dogfoot 교차데이터 소스 필터링 설정 시 마스터필터 조건 절 추가 shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						if(gDashboard.itemGenerateManager.focusedItem){
							if(gDashboard.itemGenerateManager.focusedItem.IsMasterFilterCrossDataSource){
		                        sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
							}else{
							    sqlConfig.Where = [];	
							}
						}else{
						    sqlConfig.Where = [];	
						}
					}else{
						if(gDashboard.itemGenerateManager.focusedItem.IsMasterFilterCrossDataSource){
	                        sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
						}else{
						    sqlConfig.Where = [];	
						}
					}
				}
			}else{
				sqlConfig.Where = [];
			}
			
			
			if ($.type(_dimensions) === 'string' && _dimensions === '*') {
				sqlConfig.Select = ['*'];
				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				
				if(_option && _option.where) {
					sqlConfig.Where = _option.where;
				}
				
				if (_option && _option.orderBy) {
					sqlConfig.OrderBy = [];
					$.each(_option.orderBy, function(_i, _d) {
						if(_d.nameBySummaryType != undefined){
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
							sqlConfig.OrderBy.push(_d.name);
//							sqlConfig.OrderBy.push(_d.caption);
//							sqlConfig.OrderBy.push(_d.nameBySummaryType);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}
						else{
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
							sqlConfig.OrderBy.push(_d.name);
//							sqlConfig.OrderBy.push(_d.caption);
//							sqlConfig.OrderBy.push(_d.name || _d);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}
					});
				}
			}
			else if (_dimensions.length > 0 && (!_measures || _measures.length == 0)) {
			//2020.01.30 mksong SQLLIKE DISTINCT 오류 수정 dogfoot
				sqlConfig.Select = [];
//				sqlConfig.SelectDistinct = [];
				$.each(_dimensions, function(_i, _d) {
					sqlConfig.isDiscountQuery = true;
					sqlConfig.Select.push(_d.name);
					//2020.01.31 MKSONG ALIAS 기능 수정 DOGFOOT
					sqlConfig.Select.push('|as|');
//					sqlConfig.Select.push(_d.name);
					sqlConfig.Select.push(_d.caption);
//					sqlConfig.SelectDistinct.push(_d.name);
				});
				
				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.OrderBy = [];
				$.each(_dimensions, function(_i, _d) {
					//2020.01.30 mksong sqlike config 수정 dogfoot
//					sqlConfig.OrderBy.push(_d.name);
					sqlConfig.OrderBy.push(_d.caption);
					var sortOrder = _d.sortOrder || 'asc';
					sqlConfig.OrderBy.push('|' + sortOrder + '|');
//					sqlConfig.OrderBy.push(_d.name);
				});
				
				if(typeof gDashboard.customFieldManager.fieldNameList != 'undefined') {
					if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
						$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
							if(sqlConfig.Select.indexOf(_d) == -1) {
								sqlConfig.Select.push('|sum|');
								sqlConfig.Select.push(_d);
								sqlConfig.Select.push('|as|');
								sqlConfig.Select.push('sum_' + _d);
							}
						});
					} else {
						$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
							if(sqlConfig.Select.indexOf(_d) == -1) {
								sqlConfig.Select.push('|sum|');
								sqlConfig.Select.push(_d);
								sqlConfig.Select.push('|as|');
								sqlConfig.Select.push(_d);
							}
						});
					}
				}
			}
			else {
				sqlConfig.Select = [];
				
				$.each(_dimensions, function(_i, _d) {
					if(_d.name == undefined) return;
					
					sqlConfig.Select.push(_d.name);
					//2020.01.31 MKSONG ALIAS 기능 수정 DOGFOOT
					sqlConfig.Select.push('|as|');
//					sqlConfig.Select.push(_d.name);
					sqlConfig.Select.push(_d.caption);
				});
				$.each(_measures, function(_i, _d) {
					var summaryType = _d.summaryType || 'sum';
					
					if (_d.summaryType === 'countdistinct') {
						var distinctCount = function(_columName, _data, _dimensions) {
							return function() {
								var rowData = this, whereClause = [];
								$.each(_dimensions, function(_xx, _oo) {
									whereClause.push('this["'+_oo.name+'"] == rowData["'+_oo.name+'"]');
								});
								
								var sc = {
									'Select': [_columName],
									'From': _data,
									'Where':gDashboard.itemGenerateManager.sqlConfigWhere,
									'GroupBy': [_columName]
								};
								if (whereClause.length > 0) {
									sc.Where = function(_a) {
										return eval(whereClause.join(' && '));
									};
								}
//								if(_option && _option.where) { // 16.01.28 제거
//									sc.Where = _option.where;
//								}
								return SQLike.q(sc).length;
							};
						};
						
						//2020.01.30 mksong SQLLIKE DISTINCT 오류 수정 dogfoot
						sqlConfig.isDiscountQuery = true;
						sqlConfig.Select.push('|' + summaryType + '|');
						sqlConfig.Select.push(_d.name);
						sqlConfig.Select.push('|as|');
//						sqlConfig.Select.push(_d.nameBySummaryType);
						sqlConfig.Select.push(_d.captionBySummaryType);
						
//						sqlConfig.SelectDistinct.push(distinctCount(_d.name, _data, _dimensions));
//						selectDistinct.push('|count|');
//						selectDistinct.push(_d.name);
//						selectDistinct.push('|as|');
//						selectDistinct.push(_d.nameBySummaryType);
					}
					else {
						sqlConfig.Select.push('|' + summaryType + '|');
						sqlConfig.Select.push(_d.name);
						//2020.01.30 mksong SQLLIKE 오류 수정 dogfoot
						sqlConfig.Select.push('|as|');
						/* DOGFOOT ktkang 데이터그리드 사용자정의데이터 오류 수정  20200705 */
						if(_d.tempdata) {
							sqlConfig.Select.push(_d.caption);
						} else {
//							sqlConfig.Select.push(_d.nameBySummaryType);
							sqlConfig.Select.push(_d.captionBySummaryType);
						}
						
//						sqlConfig.Select.push(_d.captionBySummaryType);
					}
				});
				
				if(typeof gDashboard.customFieldManager.fieldNameList != 'undefined') {
					if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
						$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
							if(sqlConfig.Select.indexOf(_d) == -1) {
								sqlConfig.Select.push('|sum|');
								sqlConfig.Select.push(_d);
								sqlConfig.Select.push('|as|');
								sqlConfig.Select.push('sum_' + _d);
							}
						});
					} else {
						$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
							if(sqlConfig.Select.indexOf(_d) == -1) {
								sqlConfig.Select.push('|sum|');
								sqlConfig.Select.push(_d);
								sqlConfig.Select.push('|as|');
								sqlConfig.Select.push(_d);
							}
						});
					}
				}

				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				
				if(_option && _option.where) {

					sqlConfig.Where = _option.where;
				}
				
				if (_dimensions && $.type(_dimensions) === 'array' && _dimensions.length > 0) {
					sqlConfig.GroupBy = [];
					
					sqlConfig.OrderBy = [];
					
					$.each(_dimensions, function(_i, _d) {
						if(_d.name == undefined) return;
						//2020.02.04 MKSONG ALIAS 기능 수정 DOGFOOT
						sqlConfig.GroupBy.push(_d.name);
//						sqlConfig.GroupBy.push(_d.name);
						/* goyong ktkang 본사적용 주제영역 정렬 오류 본사는 잘되면 패스  20210611 */
						if(_d.sortByMeasure !== '' && $.type(_d.sortByMeasure) === 'string' && ((typeof gDashboard.itemGenerateManager.focusedItem != 'undefined' 
							&& gDashboard.itemGenerateManager.focusedItem.HiddenMeasures.length > 0) || !WISE.Context.isCubeReport))
						{
							$.each(_measures, function(_i0, _d0) {
								var sortOrder = _d.sortOrder || 'asc';
								var find;
								if(_d0.name == _d.sortByMeasure)
								{
//									var sortOrder = _d.sortOrder || 'asc';
									find = true;
									/*dogfoot orderby 설정 순서 변경 shlim 20200701*/
//									sqlConfig.OrderBy.push(_d0.nameBySummaryType);
									sqlConfig.OrderBy.push(_d0.captionBySummaryType);
									sqlConfig.OrderBy.push('|' + sortOrder + '|');	
									
								}
								/* DOGFOOT ktkang 정렬 순서 꼬이는 오류 수정  20200909 */
//								if(find){
//									//2020.01.30 mksong sqlike config 수정 dogfoot
////									sqlConfig.OrderBy.push(_d.name);
//									/*dogfoot orderby 설정 순서 변경 shlim 20200701*/
//									sqlConfig.OrderBy.push(_d.caption);
//									sqlConfig.OrderBy.push('|' + sortOrder + '|');	
//								}
							});
							
							$.each(_dimensions, function(_i0, _d0) {
								if(_d0.name == undefined) return;
								var sortOrder = _d.sortOrder || 'asc';
								var find;
								if(_d0.name == _d.sortByMeasure)
								{
									find = true;
									//2020.01.30 mksong sqlike config 수정 dogfoot
//									sqlConfig.OrderBy.push(_d0.nameBySummaryType);
									sqlConfig.OrderBy.push(_d0.caption);
									sqlConfig.OrderBy.push('|' + sortOrder + '|');
								}
								if(find){
									//2020.01.30 mksong sqlike config 수정 dogfoot
//									sqlConfig.OrderBy.push(_d.name);
									sqlConfig.OrderBy.push(_d.caption);
									sqlConfig.OrderBy.push('|' + sortOrder + '|');	
								}
							});
						/* goyong ktkang 본사적용 주제영역 정렬 오류 본사는 잘되면 패스  20210611 */
						}else if(_d.sortByMeasure !== undefined && ((typeof gDashboard.itemGenerateManager.focusedItem != 'undefined' 
							&& gDashboard.itemGenerateManager.focusedItem.HiddenMeasures.length > 0) || !WISE.Context.isCubeReport)){
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
//							sqlConfig.OrderBy.push(_d.name);
							sqlConfig.OrderBy.push(_d.caption);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}else{
							/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
							if(typeof _orderKey != 'undefined' && _orderKey.length > 0) {
								$.each(_orderKey, function(_ordi, _ordkey) {
									if((_d.CubeUniqueName == _ordkey.logicalColumnName || _d.uniqueName == _ordkey.uniqueName) && sqlConfig.OrderBy.indexOf(_ordkey.orderByCaption) == -1) {
										if(sqlConfig.GroupBy.indexOf(_ordkey.orderByCaption) == -1) {
											sqlConfig.GroupBy.push(_ordkey.orderByCaption);
										}
										var sortOrder = _d.sortOrder || 'asc';
										sqlConfig.OrderBy.push(_ordkey.orderByCaption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
										
										sqlConfig.OrderBy.push(_d.caption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
									}
								});
							} else if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
								var dimensionOrder = true;
								$.each(gDashboard.datasetMaster.state.fields[gDashboard.itemGenerateManager.itemDataSourceId], function(_ii, _ee) {
									if(_ee.CAPTION == 'S_' + _d.caption) {
										/*dogfoot 쿼리 직접입력 정렬 오류 수정 shlim 20210728*/
										sqlConfig.Select.push(_ee.CAPTION);
										sqlConfig.Select.push('|as|');
										//						sqlConfig.Select.push(_d.name);
										sqlConfig.Select.push(_ee.CAPTION);

										sqlConfig.GroupBy.push(_ee.CAPTION);
										var sortOrder = _d.sortOrder || 'asc';
										sqlConfig.OrderBy.push(_ee.CAPTION);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
										
										sqlConfig.OrderBy.push(_d.caption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
										
										dimensionOrder = false;
									}
								});
								
								if(dimensionOrder) {
									var sortOrder = _d.sortOrder || 'asc';
									sqlConfig.OrderBy.push(_d.caption);
									sqlConfig.OrderBy.push('|' + sortOrder + '|');
								}
							}
							/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
							if(typeof _d.tempdata == 'undefined') {
								var sortOrder = _d.sortOrder || 'asc';
								//2020.01.30 mksong sqlike config 수정 dogfoot
//								sqlConfig.OrderBy.push(_d.name);
								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');
							}
						}
					});
					
					if (!_option || !_option.exceptDimensionOrderBy) {
						$.each(_dimensions, function(_i, _d) {
							/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
							if(typeof _d.tempdata == 'undefined') {
								if(_d.name == undefined) return;
								var sortOrder = _d.sortOrder || 'asc';
								//2020.01.30 mksong sqlike config 수정 dogfoot
//								sqlConfig.OrderBy.push(_d.name);
								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');
							}
						});
					}
					
					if (_option && _option.orderBy) {
						sqlConfig.OrderBy = sqlConfig.OrderBy || [];
						
						$.each(_option.orderBy, function(_i, _d) {
							if(_d.caption == undefined) return;
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
//							sqlConfig.OrderBy.push(_d.name || _d);
//							sqlConfig.OrderBy.push(_d.name);
							sqlConfig.OrderBy.push(_d.caption);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						});
					}
				}
			}
			
			var brewer = function(_sqlikeData) {
				var basten = [];
				
				$.each(_sqlikeData, function(_i0, _d0) {
					var dataObj = {};
					
					$.each(_d0, function(_i1, _d1) {
						var key = _i1;
						if (key.indexOf('sum_') === 0) {
							key = key.replace(/sum_/, '');
						}
						else if (key.indexOf('count_') === 0) {
							key = key.replace(/count_/, '');
						}
						else if (key.indexOf('countdistinct_') === 0) {
							key = key.replace(/countdistinct_/, '');
						}
						else if (key.indexOf('min_') === 0) {
							key = key.replace(/min_/, '');
						}
						else if (key.indexOf('max_') === 0) {
							key = key.replace(/max_/, '');
						}
						else if (key.indexOf('avg_') === 0) {
							key = key.replace(/avg_/, '');
						}
						else {
							// do nothing...
						}
						
						dataObj[key] = _d1;
					});
					
					basten.push(dataObj);
				});
				
				return basten;
			};
			
			var replaceForCountDistinct = function(_sqlikeData,_sqlikeData2) {
				var basten = [];
				
				$.each(_sqlikeData2, function(_i0, _d0) {
					$.each(_sqlikeData, function(_i1, _d1){
						if(_i1 == _i0){
							var dataObj = {};
							dataObj = _d1;
							$.each(_d0, function(_i2, _d2) {
								var key = _i2;
								if (key.indexOf('countdistinct') >= 0) {
									key = key.replace(/count_countdistinct_/, 'countdistinct_');
									dataObj[key] = _d2;
								}
							});	
							basten.push(dataObj);
						}
					});
				});
				
				return basten;
			};
			
			var doPrecision = function(_measures, _sqlikeData) {
				
				var newData = [];
				$.each(_sqlikeData, function(_i0, _col) {
					
					var newCol = {};
					$.each(_col, function(_colnm, _val) {
						
						$.each(_measures, function(_i1, _m) {
							
							var precision = !_m.precision || _m.precision < 1 ? 0 : _m.precision;
							var mnm = _option && _option.doBrewer ? _m.name : ((_m.summaryType ? _m.summaryType + '_' : '') + _m.name);
							
							if (mnm == _colnm && $.type(_val) === 'number') {
						
//								if(_val == '1' && precision != 0)
//									_val = 0;
							//_val = $.number(_val, 5);
							//	_val = _val.toFixed(1);
							/*	if(_val.toString()=='Infinity')
								{
									_val = 0;
								}
								else
								{
									var _valTmp =(_val * 100).toFixed(precision);
									_val = Number(_valTmp);
								}*/
								
							}
							
//							var precision = !_m.precision || _m.precision < 1 ? 0 : _m.precision;
//							var mnm = _option && _option.doBrewer ? _m.name : ((_m.summaryType ? _m.summaryType + '_' : '') + _m.name);
//							
//							if (mnm == _colnm && $.type(_val) === 'number') {
//								_val = $.number(_val, precision);

//								_val = _val.replace(/,/g, '');
//								_val = Number(_val);

//							}
						});
						
						newCol[_colnm] = _val;
					});
					
					newData.push(newCol);
				});
				
				return newData;
			};
			
			var data;
			//2020.01.30 mksong sqlike config 수정 dogfoot
			if(selectDistinct.length != 0){
//				var data1 = SQLike.q(sqlConfig);
						
				sqlConfig.SelectDistinct = selectDistinct.concat(sqlConfig.Select);
				sqlConfig.Select = undefined;
				
//				var data2 = SQLike.q(sqlConfig);
				
//				data = replaceForCountDistinct(data1, data2);
			}else{
//				data = SQLike.q(sqlConfig);
			}
			
//			if(_option && _option.doBrewer) data = brewer(data);
//			if (_measures) data = doPrecision(_measures, data);
//			$.each(data,function(_i,_datas){
//				$.each(_measures, function(_i, _d) {
//					if(_datas[_d.nameBySummaryType] != undefined || _datas[_d.captionBySummaryType] != undefined){
//						var obj = _datas;
//						obj[_d.caption] = (obj[_d.nameBySummaryType] || obj[_d.captionBySummaryType]);
//						delete  obj[_d.nameBySummaryType];
//						delete  obj[_d.captionBySummaryType];
//					}
//				});
//			})
			var orderByFieldList = [];
			$.each(sqlConfig.OrderBy,function(_i,_orderBy){
				var checkDuplicate = false;
				$.each(orderByFieldList,function(_k,_orderByField){
					if(_orderBy == _orderByField){
						checkDuplicate = true;
					}
				});
				if(!checkDuplicate){
					if(_orderBy != '|asc|' && _orderBy != '|desc|'){
						orderByFieldList.push(_orderBy);
						orderByFieldList.push(sqlConfig.OrderBy[_i+1]);
					}
				}
			});
			sqlConfig.OrderBy = orderByFieldList;
			
			data = sqlConfig;
			//2020.01.30 mksong sqlike config 수정 끝 dogfoot
			return data;
		},
		/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
		/*dogfoot shlim 20210702*/
		fromJsonforNoSummaryType: function(_customFieldCheck, _dimensions, _measures, _data, _option, _itemtype, _orderKey,_itemtype) {
			var comwhere = new Array();
			var casewhere = new Array();
			var maxcol = new Array();
			var sqlConfig = {};
			var selectDistinct = [];
			/*dogfoot 데이터 집합이 같을 때만 where 절 추가 추가 동작 통일화 shlim 20200619*/
			if(typeof gDashboard.itemGenerateManager.itemDataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
				if(gDashboard.itemGenerateManager.itemDataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
					sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				}else{
					/*dogfoot 교차데이터 소스 필터링 설정 시 마스터필터 조건 절 추가 shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						if(gDashboard.itemGenerateManager.focusedItem){
							if(gDashboard.itemGenerateManager.focusedItem.IsMasterFilterCrossDataSource){
		                        sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
							}else{
							    sqlConfig.Where = [];	
							}
						}else{
						    sqlConfig.Where = [];	
						}
					}else{
						if(gDashboard.itemGenerateManager.focusedItem.IsMasterFilterCrossDataSource){
	                        sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
						}else{
						    sqlConfig.Where = [];	
						}
					}
				}
			}else{
				sqlConfig.Where = [];
			}
			
			if ($.type(_dimensions) === 'string' && _dimensions === '*') {
				sqlConfig.Select = ['*'];
				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				
				if(_option && _option.where) {
					sqlConfig.Where = _option.where;
				}
				
				if (_option && _option.orderBy) {
					sqlConfig.OrderBy = [];
					$.each(_option.orderBy, function(_i, _d) {
						if(_d.nameBySummaryType != undefined){
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
//							sqlConfig.OrderBy.push(_d.nameBySummaryType);
							sqlConfig.OrderBy.push(_d.name);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}
						else{
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
//							sqlConfig.OrderBy.push(_d.name || _d);
							sqlConfig.OrderBy.push(_d.name);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}
					});
				}
			}
			else if (_dimensions.length > 0 && (!_measures || _measures.length == 0)) {
				sqlConfig.Select = [];
//				sqlConfig.SelectDistinct = [];
				$.each(_dimensions, function(_i, _d) {
					sqlConfig.isDiscountQuery = true;
					sqlConfig.Select.push(_d.name);
					//2020.01.31 MKSONG ALIAS 기능 수정 DOGFOOT
					sqlConfig.Select.push('|as|');
//					sqlConfig.Select.push(_d.name);
                    if(_itemtype == 'PIVOT_GRID'){
                        sqlConfig.Select.push(_d.name);
                    }else {
                    	sqlConfig.Select.push(_d.caption);
                    }
					
//					sqlConfig.SelectDistinct.push(_d.name);
				});
				
				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				sqlConfig.GroupBy = [];
				sqlConfig.OrderBy = [];
				$.each(_dimensions, function(_i, _d) {
					sqlConfig.GroupBy.push(_d.name);
					if(typeof _orderKey != 'undefined' && _orderKey.length > 0) {
						$.each(_orderKey, function(_ordi, _ordkey) {
							if((_d.CubeUniqueName == _ordkey.logicalColumnName || _d.uniqueName == _ordkey.uniqueName) && sqlConfig.OrderBy.indexOf(_ordkey.orderByCaption) == -1) {
								if(sqlConfig.GroupBy.indexOf(_ordkey.orderByCaption) == -1) {
									sqlConfig.GroupBy.push(_ordkey.orderByCaption);
								}
								var sortOrder = _d.sortOrder || 'asc';
								sqlConfig.OrderBy.push(_ordkey.orderByCaption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');

								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');

								if(typeof _itemtype != 'undefined' && _itemtype == 'PIVOT_GRID' && sqlConfig.Select.indexOf(_ordkey.orderByCaption) == -1){
									sqlConfig.Select.push(_ordkey.orderByCaption);
									sqlConfig.Select.push('|as|');
									//						sqlConfig.Select.push(_d.name);
									sqlConfig.Select.push(_ordkey.orderByCaption);	
								}
							}
						});
					} else if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
						var dimensionOrder = true;
						$.each(gDashboard.datasetMaster.state.fields[gDashboard.itemGenerateManager.itemDataSourceId], function(_ii, _ee) {
							if(_ee.CAPTION == 'S_' + _d.caption) {
								/*dogfoot 쿼리 직접입력 정렬 오류 수정 shlim 20210728*/
								sqlConfig.Select.push(_ee.CAPTION);
								sqlConfig.Select.push('|as|');
								//						sqlConfig.Select.push(_d.name);
								sqlConfig.Select.push(_ee.CAPTION);
								sqlConfig.GroupBy.push(_ee.CAPTION);
								var sortOrder = _d.sortOrder || 'asc';
								sqlConfig.OrderBy.push(_ee.CAPTION);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');

								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');

								dimensionOrder = false;
							}
						});

						if(dimensionOrder) {
							var sortOrder = _d.sortOrder || 'asc';
							sqlConfig.OrderBy.push(_d.caption);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						}
					}
					/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
					else if(typeof _d.tempdata == 'undefined') {
						var sortOrder = _d.sortOrder || 'asc';
						//2020.01.30 mksong sqlike config 수정 dogfoot
//						sqlConfig.OrderBy.push(_d.name);
						sqlConfig.OrderBy.push(_d.caption);
						sqlConfig.OrderBy.push('|' + sortOrder + '|');
					}
//					sqlConfig.OrderBy.push(_d.name);
//					var sortOrder = _d.sortOrder || 'asc';
//					sqlConfig.OrderBy.push('|' + sortOrder + '|');
				});
				
				if(typeof gDashboard.customFieldManager.fieldNameList != 'undefined') {
					if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
						$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
							if(sqlConfig.Select.indexOf(_d) == -1) {
								if(userJsonObject.menuconfig.Menu.QRY_CASH_USE && gDashboard.reportType == 'AdHoc' && _itemtype == 'PIVOT_GRID'){
                                    sqlConfig.Select.push('|sum|');
									sqlConfig.Select.push(_d);
									sqlConfig.Select.push('|as|');
									sqlConfig.Select.push(_d);
								}else{
									sqlConfig.Select.push('|sum|');
									sqlConfig.Select.push(_d);
									sqlConfig.Select.push('|as|');
									sqlConfig.Select.push('sum_' + _d);
								}
							}
						});
					} else {
						$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
							if(sqlConfig.Select.indexOf(_d) == -1) {
								sqlConfig.Select.push('|sum|');
								sqlConfig.Select.push(_d);
								sqlConfig.Select.push('|as|');
								sqlConfig.Select.push(_d);
							}
						});
					}
				}
			}
			else {
				sqlConfig.Select = [];
				
				$.each(_dimensions, function(_i, _d) {
					sqlConfig.Select.push(_d.name);
					//2020.01.31 MKSONG ALIAS 기능 수정 DOGFOOT
					sqlConfig.Select.push('|as|');
//					sqlConfig.Select.push(_d.name);
					if(_itemtype == 'PIVOT_GRID'){
                        sqlConfig.Select.push(_d.name);
                    }else {
                    	sqlConfig.Select.push(_d.caption);
                    }
				});
				$.each(_measures, function(_i, _d) {
					if(_itemtype == 'PIVOT_GRID'){
						var customFields = false;
						if(typeof gDashboard.customFieldManager.fieldInfo[gDashboard.itemGenerateManager.itemDataSourceId] != 'undefined') {
							$.each(gDashboard.customFieldManager.fieldInfo[gDashboard.itemGenerateManager.itemDataSourceId], function(_ii, _dd) {
								if(_d.name == _dd.Name) {
									customFields = true;
									return false;
								}
							});
						}						
					}
					
					//dogfoot 20211216 SYJIN 사용자 정의 데이터 뒤의 필드들 0으로 나오는 현상 수정
					if(!customFields){											
						var summaryType = _d.summaryType || 'sum';
						
						if (_d.summaryType === 'countdistinct') {
							var distinctCount = function(_columName, _data, _dimensions) {
								return function() {
									var rowData = this, whereClause = [];
									$.each(_dimensions, function(_xx, _oo) {
										whereClause.push('this["'+_oo.name+'"] == rowData["'+_oo.name+'"]');
									});
									
									var sc = {
										'Select': [_columName],
										'From': _data,
										'Where':gDashboard.itemGenerateManager.sqlConfigWhere,
										'GroupBy': [_columName]
									};
									if (whereClause.length > 0) {
										sc.Where = function(_a) {
											return eval(whereClause.join(' && '));
										};
									}
									return SQLike.q(sc).length;
								};
							};
							//2020.01.30 mksong sqlike config 수정 dogfoot
							sqlConfig.isDiscountQuery = true;
							sqlConfig.Select.push('|' + summaryType + '|');
							sqlConfig.Select.push(_d.name);
							sqlConfig.Select.push('|as|');
	//						sqlConfig.Select.push(_d.name);
							if(_itemtype == 'PIVOT_GRID'){
								sqlConfig.Select.push(_d.name);
							}else {
								sqlConfig.Select.push(_d.caption);
							}
	
	//						selectDistinct.push('|count|');
	//						selectDistinct.push(_d.name);
	//						selectDistinct.push('|as|');
	//						// mksong 2019.12.20 고유카운트 오류 수정 dogfoot
	//						selectDistinct.push('distinct_'+_d.name);
						}
						else {
							sqlConfig.Select.push('|' + summaryType + '|');
							sqlConfig.Select.push(_d.name);
							sqlConfig.Select.push('|as|');
	//						sqlConfig.Select.push(_d.name);
							if(_itemtype == 'PIVOT_GRID'){
								sqlConfig.Select.push(_d.name);
							}else {
								sqlConfig.Select.push(_d.caption);
							}
						}
					
					}
				});
				
				if(_customFieldCheck && typeof gDashboard.customFieldManager.fieldNameList != 'undefined') {
					if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
						$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
							if(sqlConfig.Select.indexOf(_d) == -1) {
								if(userJsonObject.menuconfig.Menu.QRY_CASH_USE && gDashboard.reportType == 'AdHoc' && _itemtype == 'PIVOT_GRID'){
                                    sqlConfig.Select.push('|sum|');
									sqlConfig.Select.push(_d);
									sqlConfig.Select.push('|as|');
									sqlConfig.Select.push(_d);
								}else{
									sqlConfig.Select.push('|sum|');
									sqlConfig.Select.push(_d);
									sqlConfig.Select.push('|as|');
									sqlConfig.Select.push('sum_' + _d);
								}
							}
						});
					} else {
						$.each(gDashboard.customFieldManager.fieldNameList, function(_i, _d) {
							if(sqlConfig.Select.indexOf(_d) == -1) {
								sqlConfig.Select.push('|sum|');
								sqlConfig.Select.push(_d);
								sqlConfig.Select.push('|as|');
								sqlConfig.Select.push(_d);
							}
						});
					}
				}

				sqlConfig.From = _data;
				/*dogfoot 상단 부분에서 통일화 shlim 20200619*/
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
				
				if(_option && _option.where) {
					sqlConfig.Where = _option.where;
				}
				
				if (_dimensions && $.type(_dimensions) === 'array' && _dimensions.length > 0) {
					sqlConfig.GroupBy = [];
					
					sqlConfig.OrderBy = [];
					
					$.each(_dimensions, function(_i, _d) {
						//2020.02.04 MKSONG ALIAS 기능 수정 DOGFOOT
						sqlConfig.GroupBy.push(_d.name);
						/* goyong ktkang 본사적용 주제영역 정렬 오류 본사는 잘되면 패스  20210611 */
						if(_d.sortByMeasure !== '' && $.type(_d.sortByMeasure) === 'string' && ((typeof gDashboard.itemGenerateManager.focusedItem != 'undefined' 
							&& gDashboard.itemGenerateManager.focusedItem.HiddenMeasures.length > 0) || !WISE.Context.isCubeReport))
						{
							$.each(_measures, function(_i0, _d0) {
								var sortOrder = _d.sortOrder || 'asc';
								var find;
								if(_d0.name == _d.sortByMeasure)
								{
									find = true;
									/*dogfoot orderby 설정 순서 변경 shlim 20200701*/
									sqlConfig.OrderBy.push(_d0.caption);
									sqlConfig.OrderBy.push('|' + sortOrder + '|');
								}
								/* DOGFOOT ktkang 정렬 순서 꼬이는 오류 수정  20200909 */
//								if(find){
//
//									/*dogfoot orderby 설정 순서 변경 shlim 20200701*/
//									sqlConfig.OrderBy.push(_d.caption);
//									sqlConfig.OrderBy.push('|' + sortOrder + '|');
//								}
							});
							
							$.each(_dimensions, function(_i0, _d0) {
								/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
								if(typeof _d0.tempdata == 'undefined') {
									var sortOrder = _d.sortOrder || 'asc';
									var find;
									if(_d0.name == _d.sortByMeasure)
									{
										find = true;
										//2020.01.30 mksong sqlike config 수정 dogfoot
//										sqlConfig.OrderBy.push(_d0.nameBySummaryType);
										if(_itemtype == 'PIVOT_GRID'){
											sqlConfig.OrderBy.push(_d0.name);
										}else {
											sqlConfig.OrderBy.push(_d0.caption);
										}
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
									}
									if(find){
										//2020.01.30 mksong sqlike config 수정 dogfoot
//										sqlConfig.OrderBy.push(_d.name);
										if(_itemtype == 'PIVOT_GRID'){
											sqlConfig.OrderBy.push(_d.name);
										}else {
											sqlConfig.OrderBy.push(_d.caption);
										}
										sqlConfig.OrderBy.push('|' + sortOrder + '|');	
									}
								}
							});
						/* goyong ktkang 본사적용 주제영역 정렬 오류 본사는 잘되면 패스  20210611 */
						}else if(_d.sortByMeasure !== undefined && 
								((typeof gDashboard.itemGenerateManager.focusedItem != 'undefined' &&gDashboard.itemGenerateManager.focusedItem.HiddenMeasures.length > 0)
										|| !WISE.Context.isCubeReport)){
							/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
							if(typeof _d.tempdata == 'undefined') {
								var sortOrder = _d.sortOrder || 'asc';
								//2020.01.30 mksong sqlike config 수정 dogfoot
//								sqlConfig.OrderBy.push(_d.name);
								if(_itemtype == 'PIVOT_GRID'){
									sqlConfig.OrderBy.push(_d.name);
								}else {
									sqlConfig.OrderBy.push(_d.caption);
								}
								sqlConfig.OrderBy.push('|' + sortOrder + '|');
							}
						}else{
							/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
							if(typeof _orderKey != 'undefined' && _orderKey.length > 0) {
								$.each(_orderKey, function(_ordi, _ordkey) {
									if((_d.CubeUniqueName == _ordkey.logicalColumnName || _d.uniqueName == _ordkey.uniqueName) && sqlConfig.OrderBy.indexOf(_ordkey.orderByCaption) == -1) {
										if(sqlConfig.GroupBy.indexOf(_ordkey.orderByCaption) == -1) {
											sqlConfig.GroupBy.push(_ordkey.orderByCaption);
										}
										var sortOrder = _d.sortOrder || 'asc';
										sqlConfig.OrderBy.push(_ordkey.orderByCaption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
										
										sqlConfig.OrderBy.push(_d.caption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
										
										if(typeof _itemtype != 'undefined' && _itemtype == 'PIVOT_GRID' && sqlConfig.Select.indexOf(_ordkey.orderByCaption) == -1){
                                            sqlConfig.Select.push(_ordkey.orderByCaption);
											sqlConfig.Select.push('|as|');
					//						sqlConfig.Select.push(_d.name);
											sqlConfig.Select.push(_ordkey.orderByCaption);	
                                        }
									}
								});
							} else if(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.itemDataSourceId].DATASET_TYPE == "DataSetSQL") {
								var dimensionOrder = true;
								$.each(gDashboard.datasetMaster.state.fields[gDashboard.itemGenerateManager.itemDataSourceId], function(_ii, _ee) {
									if(_ee.CAPTION == 'S_' + _d.caption) {
										/*dogfoot 쿼리 직접입력 정렬 오류 수정 shlim 20210728*/
										sqlConfig.Select.push(_ee.CAPTION);
										sqlConfig.Select.push('|as|');
										//						sqlConfig.Select.push(_d.name);
										sqlConfig.Select.push(_ee.CAPTION);
										sqlConfig.GroupBy.push(_ee.CAPTION);
										var sortOrder = _d.sortOrder || 'asc';
										sqlConfig.OrderBy.push(_ee.CAPTION);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
										
										sqlConfig.OrderBy.push(_d.caption);
										sqlConfig.OrderBy.push('|' + sortOrder + '|');
										
										dimensionOrder = false;
									}
								});
								
								if(dimensionOrder) {
									var sortOrder = _d.sortOrder || 'asc';
									sqlConfig.OrderBy.push(_d.caption);
									sqlConfig.OrderBy.push('|' + sortOrder + '|');
								}
							}
							/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
							else if(typeof _d.tempdata == 'undefined') {
								var sortOrder = _d.sortOrder || 'asc';
								//2020.01.30 mksong sqlike config 수정 dogfoot
//								sqlConfig.OrderBy.push(_d.name);
								sqlConfig.OrderBy.push(_d.caption);
								sqlConfig.OrderBy.push('|' + sortOrder + '|');
							}
						}
					});
					
					if (!_option || !_option.exceptDimensionOrderBy) {
						$.each(_dimensions, function(_i, _d) {
							/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
							if(typeof _d.tempdata == 'undefined') {
								var sortOrder = _d.sortOrder || 'asc';
								//2020.01.30 mksong sqlike config 수정 dogfoot
//								sqlConfig.OrderBy.push(_d.name);
								if(_itemtype == 'PIVOT_GRID'){
									sqlConfig.OrderBy.push(_d.name);
								}else {
									sqlConfig.OrderBy.push(_d.caption);
								}
								sqlConfig.OrderBy.push('|' + sortOrder + '|');
							}
						});
					}
					
					if (_option && _option.orderBy) {
						sqlConfig.OrderBy = sqlConfig.OrderBy || [];
						
						$.each(_option.orderBy, function(_i, _d) {
							var sortOrder = _d.sortOrder || 'asc';
							//2020.01.30 mksong sqlike config 수정 dogfoot
//							sqlConfig.OrderBy.push(_d.name || _d);
							sqlConfig.OrderBy.push(_d.caption);
							sqlConfig.OrderBy.push('|' + sortOrder + '|');
						});
					}
				}
			}
			
			var brewer = function(_sqlikeData) {
				var basten = [];
				
				$.each(_sqlikeData, function(_i0, _d0) {
					var dataObj = {};
					
					$.each(_d0, function(_i1, _d1) {
						var key = _i1;
						if (key.indexOf('sum_') === 0) {
							key = key.replace(/sum_/, '');
						}
						else if (key.indexOf('count_') === 0) {
							key = key.replace(/count_/, '');
						}
						else if (key.indexOf('countdistinct_') === 0) {
							key = key.replace(/countdistinct_/, '');
						}
						else if (key.indexOf('min_') === 0) {
							key = key.replace(/min_/, '');
						}
						else if (key.indexOf('max_') === 0) {
							key = key.replace(/max_/, '');
						}
						else if (key.indexOf('avg_') === 0) {
							key = key.replace(/avg_/, '');
						}
						else {
							// do nothing...
						}
						
						dataObj[key] = _d1;
					});
					
					basten.push(dataObj);
				});
				
				return basten;
			};
			
			var replaceForCountDistinct = function(_sqlikeData,_sqlikeData2) {
				var basten = [];
				
				$.each(_sqlikeData2, function(_i0, _d0) {
					$.each(_sqlikeData, function(_i1, _d1){
						if(_i1 == _i0){
							var dataObj = {};
							dataObj = _d1;
							$.each(_d0, function(_i2, _d2) {
								var key = _i2;
								// mksong 2019.12.20 고유카운트 오류 수정 dogfoot
								if (key.indexOf('count_distinct_') >= 0) {
									key = key.replace(/count_distinct_/, 'countdistinct_');
									dataObj[key] = _d2;
								}
							});	
							basten.push(dataObj);
						}
					});
				});
				
				return basten;
			};
			
			var doPrecision = function(_measures, _sqlikeData) {
				
				var newData = [];
				$.each(_sqlikeData, function(_i0, _col) {
					
					var newCol = {};
					$.each(_col, function(_colnm, _val) {
						
						$.each(_measures, function(_i1, _m) {
							
							var precision = !_m.precision || _m.precision < 1 ? 0 : _m.precision;
							var mnm = _option && _option.doBrewer ? _m.name : ((_m.summaryType ? _m.summaryType + '_' : '') + _m.name);
							
							if (mnm == _colnm && $.type(_val) === 'number') {
							}
						});
						
						newCol[_colnm] = _val;
					});
					
					newData.push(newCol);
				});
				
				return newData;
			};
			
			var data;
			//2020.01.30 mksong sqlike config 수정 dogfoot
			if(selectDistinct.length != 0){
//				var data1 = SQLike.q(sqlConfig);
						
				sqlConfig.SelectDistinct = selectDistinct.concat(sqlConfig.Select);
				sqlConfig.Select = undefined;
				
//				var data2 = SQLike.q(sqlConfig);
				
//				data = replaceForCountDistinct(data1, data2);
			}else{
//				data = SQLike.q(sqlConfig);
			}
			
//			if(_option && _option.doBrewer) data = brewer(data);
//			if (_measures) data = doPrecision(_measures, data);
//			$.each(data,function(_i,_datas){
//				$.each(_measures, function(_i, _d) {
//					if(_datas[_d.nameBySummaryType] != undefined || _datas[_d.captionBySummaryType] != undefined){
//						var obj = _datas;
//						obj[_d.caption] = (obj[_d.nameBySummaryType] || obj[_d.captionBySummaryType]);
//						delete  obj[_d.nameBySummaryType];
//						delete  obj[_d.captionBySummaryType];
//					}
//				});
//			})
			var orderByFieldList = [];
			$.each(sqlConfig.OrderBy,function(_i,_orderBy){
				var checkDuplicate = false;
				$.each(orderByFieldList,function(_k,_orderByField){
					if(_orderBy == _orderByField){
						checkDuplicate = true;
					}
				});
				if(!checkDuplicate){
					if(_orderBy != '|asc|' && _orderBy != '|desc|'){
						orderByFieldList.push(_orderBy);
						orderByFieldList.push(sqlConfig.OrderBy[_i+1]);
					}
				}
			});
			sqlConfig.OrderBy = orderByFieldList;
			data = sqlConfig;
			//2020.01.30 mksong sqlike config 수정 끝 dogfoot
			return data;
		//2020.01.30 mksong SQLLIKE doSqlLike 함수 추가 dogfoot	
		},
		/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
		doSqlLike : function(_dataSourceId, _sqlConfig, self, _gridView){
			/* DOGFOOT ktkang 보고서 중단 기능 구현  20201006 */
			if(gDashboard.itemGenerateManager.dxItemBasten[0].itemid == self.itemid) {
				gDashboard.openCanceled = false;
			}
			
			if(_dataSourceId == undefined) return;
			var data;
			var datasets = gDashboard.datasetMaster.getState('DATASETS');
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			var query = "";
			if(typeof self.cubeQuery == 'undefined' || self.cubeQuery == '') {
				query = (!$.isEmptyObject(datasets) && !WISE.Context.isCubeReport) ? datasets[_dataSourceId].DATASET_QUERY : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].SQL_QUERY;
			} else {
				query = self.cubeQuery;
			}
			
			var useWithQuery = "Y";
            if(_gridView){
                useWithQuery = "N";
            }

			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			var dsnm = (!$.isEmptyObject(datasets)) ? datasets[_dataSourceId].DATASET_NM : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASET_NM;
			var param = {
//					'fields' : $.toJSON(this.dataSourceConfig.fields),
					'params': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues()),
					/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
					'sql_query' : Base64.encode(query),
					'ds_nm' : dsnm,
					'dsid' : (!$.isEmptyObject(datasets)) ? datasets[_dataSourceId].DATASRC_ID : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASRC_ID,
					'dstype' : (!$.isEmptyObject(datasets)) ? datasets[_dataSourceId].DATASRC_TYPE : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASRC_TYPE,
//					'reportId' : gDashboard.structure.ReportMasterInfo.id,
					'sqlConfig' : $.toJSON(_sqlConfig),
					'sqlTimeout':userJsonObject.searchLimitTime,
					/* DOGFOOT ktkang SQL 로그 추가  20200721 */
					'userId' : userJsonObject.userId,
					'reportType' : gDashboard.reportType,
					//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
					'inMemory': datasets[_dataSourceId].IN_MEMORY,
					'tbllist': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentTableList(dsnm)),
					'schedulePath' : gDashboard.schedulePath,
					/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
					'oldSchedule': userJsonObject.oldSchedule,
					'useWithQuery' : useWithQuery
			};
			
			/* DOGFOOT ktkang 보고서 중단 기능 구현  20201006 */
			if(userJsonObject.searchLimitTime > 0) {
				var setTime = userJsonObject.searchLimitTime * 1000;
				 
				setTimeout(function () {
					if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length) {
						gDashboard.openCanceled = false;
					} else {
						WISE.alert('진행 중인 작업이 취소되었거나 제한 시간 초과로 종료되었습니다.');
						gDashboard.openCanceled = true;
						   
						gProgressbar.hide();
						gDashboard.updateReportLog('99');
						$.ajax({
							type : 'post',
							cache : false,
							async: true,
							url : WISE.Constants.context + '/report/cancelqueries.do',
							complete: function(_e) {
								gProgressbar.cancelQuery();
//								gProgressbar.hide();
								return false;
							}
						});
						return false;
					}
				}, setTime);
			}
			
			/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
			console.log("-----------------------------------------------------------------------");
			window.endBeforQueryTime = window.performance.now();
			console.log(self.Name + " 아이템 생성 ~ 쿼리 날리기 전 소요시간: " + (window.endBeforQueryTime - window.startBeforQueryTime)+'ms');
			if(gDashboard.openCanceled == false) {
				$.ajax({
					method : 'POST',
					url: WISE.Constants.context + '/report/sqlLike.do', 
					data: param,
					/* DOGFOOT ktkang 작업 취소 가능하도록 수정  20201005 */
					async: false,
					beforeSend:function() {
						/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
						console.log("-----------------------------------------------------------------------");
						window.startQueryTime[self.itemid] = window.performance.now();
						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
						gProgressbar.show();
						$('#queryCancel').dxButton({
							text:"작업 취소",
							type:'default',
							onClick:function(_e){
								//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
								WISE.alert('진행 중인 작업이 취소되었거나 제한 시간 초과로 종료되었습니다.');
								gProgressbar.setStopngoProgress(true);
								gProgressbar.hide();
								gDashboard.openCanceled = true;
								gDashboard.updateReportLog('99');
								$.ajax({
									type : 'post',
									cache : false,
									async: true,
									url : WISE.Constants.context + '/report/cancelqueries.do',
									complete: function(_e) {
										gProgressbar.cancelQuery();
//										gProgressbar.hide();
										return false;
									}
								});
							}
						});
					},
					complete: function() {
						//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
//						gProgressbar.hide();
					},
					success: function(sqldata) {
						/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
						console.log("-----------------------------------------------------------------------");
						window.endQueryTime[self.itemid] = window.performance.now();
						console.log(self.Name+" 스크립트 쿼리 소요 시간 : " + (window.endQueryTime[self.itemid] - window.startQueryTime[self.itemid])+'ms');
						console.log(self.Name+" 서버 쿼리 소요 시간 : " + sqldata.Queries_Time +'ms');
						console.log("-----------------------------------------------------------------------");
						/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
						window.startDrawItemTime[self.itemid] = window.performance.now();
						
						if(gDashboard.openCanceled == false) {
							if(userJsonObject.searchLimitRow > 0) {
								if(typeof sqldata.data != 'undefined') {
									if(sqldata.data.length > userJsonObject.searchLimitRow){
										/* dogfoot 비정형 주제영역 데이터 row 건수 제한 팝업창 여러번 나오는 오류 수정  shlim 20210322 */
										if(gDashboard.searchLimitCount == 0){
											gDashboard.searchLimitCount++;
											var confirmValue;
											if(WISE.Constants.browser == 'IE11') {
												confirmValue = window.confirm("데이터 조회 건수가 많아 Chrome이나 MS Edge사용을 권장합니다. 계속 조회하시겠습니까? (필터를 변경 후 조회하시길 권장합니다.)");
											} else {
												confirmValue = window.confirm("데이터 조회 건수가 많아 브라우저 다운 현상이 발생할 수 있습니다. 계속 조회하시겠습니까? (필터를 변경 후 조회하시길 권장합니다.)");
											}
											if(!confirmValue){
												gProgressbar.hide();
												return false;
											}
										}
									}
								}
							}
							//2020.01.31 MKSONG 에러 ALERT 추가 위한 수정 DOGFOOT
							data = sqldata.data;
							/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
							if(typeof self != 'undefined') {
								$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
									if(_e.itemid == self.itemid) {
										self.showQuery = Base64.decode(sqldata.sql);
										_e.showQuery = Base64.decode(sqldata.sql);
									}
								});
							}
						}
					},
					error: function(error){
						gDashboard.updateReportLog('99');
						/* DOGFOOT ktkang 작업 취소 메세지 수정  20201005 */
						if(ajax_error_message(error).indexOf('Statement canceled') > -1 || ajax_error_message(error).indexOf('SQLTimeout') > -1
								|| ajax_error_message(error).indexOf('초과되었습니다') > -1 || ajax_error_message(error).indexOf('취소되었습니다') > -1
								|| ajax_error_message(error).indexOf('No result') > -1) {
						} else {
						}
//						WISE.alert('error'+ajax_error_message(error),'error');
						data = error.data;
						gProgressbar.hide();
					}
				});
					   
						 
			}
	  
			return data;
		//2020.02.04 mksong SQLLIKE doSqlLike 비동기, 동기 구분 dogfoot
		},
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		doSqlLikeAjax : function(_dataSourceId, _sqlConfig, self, _option, cubeQuery){
			/* DOGFOOT ktkang 보고서 중단 기능 구현  20201006 */
			/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
			if(self.isDownloadExpand || gDashboard.itemGenerateManager.dxItemBasten[0].itemid == self.itemid) {
				gDashboard.openCanceled = false;
			}
			
			if(_dataSourceId == undefined) return;
			var data;
			var datasets = gDashboard.datasetMaster.getState('DATASETS');
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			var query = "";
			if(typeof cubeQuery == 'undefined' || cubeQuery == '') {
				query = (!$.isEmptyObject(datasets) && !WISE.Context.isCubeReport) ? datasets[_dataSourceId].DATASET_QUERY : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].SQL_QUERY;
			} else {
				query = cubeQuery;
			}
			/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
//			var acync = true;
//			if(gDashboard.downloadFull) {
			/* DOGFOOT ktkang 그리드 페이징 오류 수정  20201015 */
			var	acync = true;
			if(userJsonObject.gridDataPaging === 'Y' && self.type == 'DATA_GRID'){
				acync = false;
			}
			acync = gDashboard.analysisType !== undefined ? false : true; //통계분석 동기
//			}
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			var dsnm = (!$.isEmptyObject(datasets)) ? datasets[_dataSourceId].DATASET_NM : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASET_NM;
			/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
			var nullDimension = [];
			var nullDimensionJson = {};
			if(self.type == 'PIVOT_GRID'){
				if(typeof self.Pivot['NullRemoveType'] != undefined && self.Pivot['NullRemoveType']) {
					if(self.Pivot['NullRemoveType'] == 'rowNullRemove') {
						$.each(self.rows, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					} else if(self.Pivot['NullRemoveType'] == 'colNullRemove') {
						$.each(self.columns, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					} else if(self.Pivot['NullRemoveType'] == 'allNullRemove') {
						$.each(self.rows, function(_i, _e) {
							nullDimension.push(_e.name);
						});
						$.each(self.columns, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					}
					if(nullDimension.length > 0) {
						nullDimensionJson[0] = self.Pivot['NullRemoveType'];
						$.each(nullDimension, function(_i, _e) {
							nullDimensionJson[_i+1] = _e;
						});
					}
				}
			}
			/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
			var params = $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues());
			if(self.isDownloadExpand)
				params =  $.toJSON(gDashboard.parameterBarDE.getKeyParamValues());
				
			/*dogfoot 비정형 피벗 조회 다운로드 기능 추가 shlim 20210728*/
			var forCountQuery= false;
			if(gDashboard.reportType =='AdHoc'){
				forCountQuery = true;
			}
			
			var param = {
//						'fields' : $.toJSON(this.dataSourceConfig.fields),
						'params' : params,
						/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
						'sql_query' : Base64.encode(query),
						'ds_nm' : dsnm,
						'dsid' : (!$.isEmptyObject(datasets)) ? datasets[_dataSourceId].DATASRC_ID : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASRC_ID,
						'dstype' : (!$.isEmptyObject(datasets)) ? datasets[_dataSourceId].DATASRC_TYPE : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASRC_TYPE,
//						'reportId' : gDashboard.structure.ReportMasterInfo.id,
						'sqlConfig' : $.toJSON(_sqlConfig),
						'sqlTimeout':userJsonObject.searchLimitTime,
						/* DOGFOOT ktkang SQL 로그 추가  20200721 */
						'fullQuery': gDashboard.downloadFull,
						'userId' : userJsonObject.userId,
						'reportType' : gDashboard.reportType,
						'tbllist': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentTableList(dsnm)),
						'nullDimension': $.toJSON(nullDimensionJson),
						/* DOGFOOT ktkang 스케줄링 오류 수정  20201007 */
						'schedulePath' : gDashboard.schedulePath,
						/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
						'oldSchedule': userJsonObject.oldSchedule,
						/*dogfoot 비정형 피벗 조회 다운로드 기능 추가 shlim 20210728*/
						'itemType' : self.type,
						'forCountQuery': forCountQuery,
			};
			/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
			console.log("-----------------------------------------------------------------------");
			window.endBeforQueryTime = window.performance.now();
			console.log(self.Name + " 아이템 생성 ~ 쿼리 날리기 전 소요시간 : " + (window.endBeforQueryTime - window.startBeforQueryTime)+'ms');
			if(gDashboard.openCanceled == false) {
				$.ajax({
					method : 'POST',
					url: WISE.Constants.context + '/report/sqlLike.do', 
					data: param,
					/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
					async: acync,
					beforeSend:function() {
						/*dogfoot 비정형 피벗 조회 다운로드 기능 추가 shlim 20210728*/
						gDashboard.confirmValueSqllike = false;
						console.log("-----------------------------------------------------------------------");
						window.startQueryTime[self.itemid] = window.performance.now();
						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
						gProgressbar.show();
						$('#queryCancel').dxButton({
							text:"작업 취소",
							type:'default',
							onClick:function(_e){
								//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
								WISE.alert('진행 중인 작업이 취소되었거나 제한 시간 초과로 종료되었습니다.');
								gProgressbar.setStopngoProgress(true);
								gProgressbar.hide();
								gDashboard.updateReportLog('99');
								gDashboard.openCanceled = true;
								$.ajax({
									type : 'post',
									cache : false,
									async: true,
									url : WISE.Constants.context + '/report/cancelqueries.do',
									complete: function(_e) {
										gProgressbar.cancelQuery();
//										gProgressbar.hide();
									}
								});
							}
						});
					},
					complete: function() {
						//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
//						gProgressbar.hide();
					},
					success: function(sqldata) {
						if(sqldata.sql){
							sqldata.sql = Base64.decode(sqldata.sql);
						}
						
						/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
						console.log("-----------------------------------------------------------------------");
						window.endQueryTime[self.itemid] = window.performance.now();
//						console.log("QueryTime 걸린시간 : " + (window.endQueryTime - window.startQueryTime)+'ms');
						console.log(self.Name + " 스크립트 쿼리 소요 시간 : " + (window.endQueryTime[self.itemid] - window.startQueryTime[self.itemid])+'ms');
						console.log(self.Name + " 서버 쿼리 소요 시간 : " + sqldata.Queries_Time +'ms');
						console.log("-----------------------------------------------------------------------");
						/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
						window.startDrawItemTime[self.itemid] = window.performance.now();
						if(gDashboard.openCanceled == false) {
							/*dogfoot 비정형 피벗 조회 다운로드 기능 추가 shlim 20210728*/
							if(sqldata.forCountQuery){
								if(sqldata.dataSizeOver && !gDashboard.confirmValue){
	                        		WISE.alert("데이터가 너무 많으니 엑셀로 전체 다운로드 받으시기 바랍니다.");
									gProgressbar.hide();
									return false;	
	                        	}
	                        	param.forCountQuery = false;
	                        	if(gDashboard.openCanceled == false) {
									$.ajax({
										method : 'POST',
										url: WISE.Constants.context + '/report/sqlLike.do', 
										data: param,
										/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
										async: acync,
										beforeSend:function() {
											/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
											gDashboard.confirmValueSqllike = false;
											console.log("-----------------------------------------------------------------------");
											window.startQueryTime[self.itemid] = window.performance.now();
											//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
											gProgressbar.show();
											$('#queryCancel').dxButton({
												text:"작업 취소",
												type:'default',
												onClick:function(_e){
													//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
													WISE.alert('진행 중인 작업이 취소되었거나 제한 시간 초과로 종료되었습니다.');
													gProgressbar.setStopngoProgress(true);
													gProgressbar.hide();
													gDashboard.updateReportLog('99');
													gDashboard.openCanceled = true;
													$.ajax({
														type : 'post',
														cache : false,
														async: true,
														url : WISE.Constants.context + '/report/cancelqueries.do',
														complete: function(_e) {
															gProgressbar.cancelQuery();
					//										gProgressbar.hide();
														}
													});
												}
											});
										},
										complete: function() {
											//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
					//						gProgressbar.hide();
										},
										success: function(sqldata) {
											if(gDashboard.openCanceled == false) {
												// 2020.01.16 mksong 데이터 건수 많을 경우 경고창 띄우기 dogfoot
												if (!sqldata || ($.type(sqldata.data) === 'array' && sqldata.data.length === 0)) {
													$('#'+self.itemid + ' .nodata-layer').remove();
													var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
													$("#" + self.itemid).children().css('display','none');
													$("#" + self.itemid).prepend(nodataHtml);
													if(($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0) && self.itemid.indexOf("gridDashboardItem") === -1){
														$("#" + self.itemid).height('100%');
														$("#" + self.itemid).width('100%');
													}
													$("#" + self.itemid).css('display', 'block');

													if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
														gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
													}

													if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
														gProgressbar.setStopngoProgress(true);
														gProgressbar.hide();	
														gDashboard.updateReportLog();
													}
													/*dogfoot shlim 20210419*/
													if(typeof self != 'undefined') {
														$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
															if(_e.itemid == self.itemid) {
																self.showQuery = sqldata.sql;
																_e.showQuery = sqldata.sql;
															}
														});
													}
												}else{
													$('#'+self.itemid + ' .nodata-layer').remove();
													if(self.itemid.indexOf("gridDashboardItem") === -1)
														$("#" + self.itemid).children().css('display','block');
													else
														$("#" + self.itemid).children().css('display','flex');
													_option(self,sqldata.data);
													/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
													if(typeof self != 'undefined') {
														$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
															if(_e.itemid == self.itemid) {
																self.showQuery = sqldata.sql;
																_e.showQuery = sqldata.sql;
															}
														});
													}
												}
											}
										},
										error: function(error){
											gDashboard.updateReportLog('99');
											/* DOGFOOT ktkang 작업 취소 메세지 수정  20201005 */
											if(ajax_error_message(error).indexOf('Statement canceled') > -1 || ajax_error_message(error).indexOf('SQLTimeout') > -1
													|| ajax_error_message(error).indexOf('초과되었습니다') > -1 || ajax_error_message(error).indexOf('취소되었습니다') > -1
													|| ajax_error_message(error).indexOf('No result') > -1) {
											} else {
											}
					//						WISE.alert('error'+ajax_error_message(error),'error');
											data = error.data;
											gProgressbar.hide();
										}
									});
								}
                            }else{
                            	if(userJsonObject.searchLimitRow > 0) {
    								if(typeof sqldata.data != 'undefined') {
    									if(sqldata.data.length > userJsonObject.searchLimitRow){
    										/* dogfoot 비정형 주제영역 데이터 row 건수 제한 팝업창 여러번 나오는 오류 수정  shlim 20210322 */
    										if(gDashboard.searchLimitCount == 0){
    											gDashboard.searchLimitCount++;
    											var confirmValue = window.confirm("데이터 조회 건수가 많아 브라우저 다운 현상이 발생할 수 있습니다. 계속 조회하시겠습니까? (필터를 변경 후 조회하시길 권장합니다.)");
    											if(!confirmValue){
    												gProgressbar.hide();
    												return false;
    											}
    										}
    									}
    								}
    							}
                            	if (!sqldata || ($.type(sqldata.data) === 'array' && sqldata.data.length === 0)) {
									$('#'+self.itemid + ' .nodata-layer').remove();
									var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
									$("#" + self.itemid).children().css('display','none');
									$("#" + self.itemid).prepend(nodataHtml);
									if(($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0) && self.itemid.indexOf("gridDashboardItem") === -1){
										$("#" + self.itemid).height('100%');
										$("#" + self.itemid).width('100%');
									}
									$("#" + self.itemid).css('opacity', '');
									$("#" + self.itemid).css('display', 'block');

									if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
										gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
									}

									if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
										gProgressbar.setStopngoProgress(true);
										gProgressbar.hide();	
										gDashboard.updateReportLog();
									} else if(gDashboard.hasTab && gDashboard.itemGenerateManager.viewedItemList.length > 0){
										gProgressbar.setStopngoProgress(true);
										gProgressbar.hide();	
										gDashboard.updateReportLog();
									}
									/*dogfoot shlim 20210419*/
									if(typeof self != 'undefined') {
										$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
											if(_e.itemid == self.itemid) {
												self.showQuery = sqldata.sql;
												_e.showQuery = sqldata.sql;
											}
										});
									}
								}else{
									$('#'+self.itemid + ' .nodata-layer').remove();
									if($("#" + self.itemid).children()){
										$("#" + self.itemid).children().css('display','block');
									}
//									if(self.itemid.indexOf("gridDashboardItem") === -1)
//										$("#" + self.itemid).children().css('display','block');
//									else
//										$("#" + self.itemid).children().css('display','flex');
									_option(self,sqldata.data);
									/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
									if(typeof self != 'undefined') {
										$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
											if(_e.itemid == self.itemid && sqldata.sql) {
												self.showQuery = sqldata.sql;
												_e.showQuery = sqldata.sql;
											}
										});
									}
								}
                            }
						}
					},
					error: function(error){
						gDashboard.updateReportLog('99');
						/* DOGFOOT ktkang 작업 취소 메세지 수정  20201005 */
						if(ajax_error_message(error).indexOf('Statement canceled') > -1 || ajax_error_message(error).indexOf('SQLTimeout') > -1
								|| ajax_error_message(error).indexOf('초과되었습니다') > -1 || ajax_error_message(error).indexOf('취소되었습니다') > -1
								|| ajax_error_message(error).indexOf('No result') > -1) {
						} else {
						}
						
						//20210723 AJKIM SQL 에러 로그 공개 추가 dogfoot
						if(userJsonObject.menuconfig.Menu.SQL_ERROR_LOG){
							if(typeof self != 'undefined') {
								$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
									if(_e.itemid == self.itemid) {
										self.showQuery = ajax_error_message(error);
										_e.showQuery = ajax_error_message(error);
									}
								});
							}
						}
//						WISE.alert('error'+ajax_error_message(error),'error');
						data = error.data;
						gProgressbar.hide();
					}
				});
			}
			/* DOGFOOT ktkang 보고서 중단 기능 구현  20201006 */
			if(userJsonObject.searchLimitTime > 0) {
				var setTime = userJsonObject.searchLimitTime * 1000;
				setTimeout(function () {
					if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length) {
						gDashboard.openCanceled = false;
					} else {
						WISE.alert('진행 중인 작업이 취소되었거나 제한 시간 초과로 종료되었습니다.');
						gDashboard.openCanceled = true;
						gProgressbar.hide();
						gDashboard.updateReportLog('99');
						$.ajax({
							type : 'post',
							cache : false,
							async: true,
							url : WISE.Constants.context + '/report/cancelqueries.do',
							complete: function(_e) {
								gProgressbar.cancelQuery();
//								gProgressbar.hide();
								return false;
							}
						});
						return false;
					}
				}, setTime);
					   
						 
			}
	  
		},
		doSqlLikeExcel : function(contentList, itemInstance, downloadType){
			/* DOGFOOT ktkang 대용량 다운로드 기능 구현  20200903 */
			/* DOGFOOT ajkim 엑셀 다운로드 하나 다운로드 할 때 전체 아이템 다 되는 오류 수정 20210311*/
			var _dwType = isNull(downloadType) ? 'xlsx' : downloadType;
			if(contentList == undefined) return;
			var data;
			var datasets = gDashboard.datasetMaster.getState('DATASETS');
			var grindNumber = 0;
			var downloadContentList = [];
			
			var setContentList = function(item){
				var gridJson = {};
				if(typeof item.cubeQuery == 'undefined' || item.cubeQuery == '') {
					gridJson.query = Base64.encode((!$.isEmptyObject(datasets) && !WISE.Context.isCubeReport) ? datasets[item.dataSourceId].DATASET_QUERY : gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].SQL_QUERY);
				} else {
					gridJson.query = Base64.encode(item.cubeQuery);
				}
				gridJson.dsid = (!$.isEmptyObject(datasets)) ? datasets[item.dataSourceId].DATASRC_ID : gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASRC_ID;
				gridJson.dstype = (!$.isEmptyObject(datasets)) ? datasets[item.dataSourceId].DATASRC_TYPE : gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASRC_TYPE;
				gridJson.dsnm = (!$.isEmptyObject(datasets)) ? datasets[item.dataSourceId].DATASET_NM : gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_NM;

				/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
				gridJson.sqlConfig = item.sqlConfig;

				// 20210906 sheet명 에러안나게(/ -> _ 처리)
				var itemNm = item.Name;
				itemNm = itemNm.replace(/\//g,'_');
				itemNm = itemNm.replace(/\\/g,'_');
				gridJson.item = itemNm;
				
				/* 2020.12.18 mksong 주택금융공사 정렬컬럼 피벗테이블 제외 dogfoot */
				gridJson.itemtype = item.type;
				gridJson.sortColumnCount = item.HiddenMeasures.length;
				if(item.type == 'PIVOT_GRID'){
					gridJson.cols = item.columns;
					gridJson.rows = item.rows;
					gridJson.totalView = {'ShowColumnTotals' : item.Pivot.ShowColumnTotals, 'ShowRowTotals': item.Pivot.ShowRowTotals, 
							'ShowColumnGrandTotals': item.Pivot.ShowColumnGrandTotals, 'ShowRowGrandTotals': item.Pivot.ShowRowGrandTotals};
					
					// 20210827 Measure가 뷰어에선 Array가 아니어서 다운로드 실패하는 에러 수정
					if (WISE.Constants.editmode == 'viewer') {
						var objJsonArr = new Array();
						if (!isNull(item.DI)) {
							if (!isNull(item.DI.Measure) && !Array.isArray(item.DI.Measure)) {
								objJsonArr.push(item.DI.Measure);
								item.DI.Measure = objJsonArr;
							}
						}
					}
					
					
					gridJson.dataItems = $.toJSON(item.DI);
					/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
					var nullDimension = [];
					var nullDimensionJson = {};
					if(typeof item.Pivot['NullRemoveType'] != undefined && item.Pivot['NullRemoveType']) {
						if(item.Pivot['NullRemoveType'] == 'rowNullRemove') {
							$.each(item.rows, function(_i, _e) {
								nullDimension.push(_e.name);
							});
						} else if(item.Pivot['NullRemoveType'] == 'colNullRemove') {
							$.each(item.columns, function(_i, _e) {
								nullDimension.push(_e.name);
							});
						} else if(item.Pivot['NullRemoveType'] == 'allNullRemove') {
							$.each(item.rows, function(_i, _e) {
								nullDimension.push(_e.name);
							});
							$.each(item.columns, function(_i, _e) {
								nullDimension.push(_e.name);
							});
						}
						if(nullDimension.length > 0) {
							nullDimensionJson[0] = item.Pivot['NullRemoveType'];
							$.each(nullDimension, function(_i, _e) {
								nullDimensionJson[_i + 1] = _e;
							});
						}
					}

					gridJson.nullDimension =  $.toJSON(nullDimensionJson);
					
					// 행/열번환 추가
					gridJson.colRowSwitch = item.meta.ColRowSwitch;

					contentList.push(gridJson);
					downloadContentList.push(gridJson);
				} else if(item.type == 'DATA_GRID'){
					var tempDI = {}
					if(!item.DI.Dimension.length){
                        tempDI.Dimension = [];
                        tempDI.Dimension.push(item.DI.Dimension)
                        item.DI.Dimension = tempDI.Dimension;
					}
					if(!item.DI.Measure.length){
                        tempDI.Measure = [];
                        tempDI.Measure.push(item.DI.Measure)
                        item.DI.Measure = tempDI.Measure;
					}
					gridJson.dataItems = $.toJSON(item.DI);
					gridJson.dataItems2 = $.toJSON(item.columns);
					/* ktkang 1013번 오류 수정  */
					if(userJsonObject.gridDataPaging === 'N'){
						gridJson.dataSource = $.toJSON(item.dxItem.option('dataSource')._items);
					}
					
					gridJson.headerList = item.headerList;
					gDashboard.gridDownloadNonCustomFiled = true;
					gDashboard.itemGenerateManager.itemDataSourceId = itemInstance.dataSourceId;
					var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
					var measures = [];
					measures = measures.concat(_.clone(item.measures));
					measures = measures.concat(_.clone(item.HiddenMeasures));
					gridJson.sqlConfig = SQLikeUtil.fromJson(item.dimensions, measures, undefined,undefined,item.type,undefined);
					gDashboard.gridDownloadNonCustomFiled = false;

					var udfGroups = [];
		
					// 사용자정의 데이터 저장
                    $.each(gDashboard.customFieldManager.fieldInfo[item.dataSourceId], function(i, udfField){
						var selectors = [];
						$.each(item.columns, function(j, dim){
							if(udfField.Expression.indexOf("["+dim.name+"]") > -1){
								selectors.push(dim.dataField);
							}
						})
						// PivotGrid의 "[순매출액]*2"과 같은 표현식을 "_fields['순매출액']*2" 포맷으로 변경
						var convertedExpr = udfField.Expression.replace(/\[([^\[\]\'\"]+)\]/g, "_fields['sum_$1']");
						udfGroups.push({name: udfField.Name, selectors: selectors, expression: convertedExpr});
					})
					
                    //udfGroups = [];
					gridJson.udfGroups = udfGroups
					contentList.push(gridJson);
					downloadContentList.push(gridJson);
				}
			}
			
			if(!itemInstance){
				$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i, _o){
					setContentList(_o)
				});
			}else{
				setContentList(itemInstance);
			}
			
			var reportName = gDashboard.reportUtility.reportInfo.ReportMasterInfo.name;
			
			if(contentList.length > 1){
            	reportName = reportName + (contentList.length - 1);
            }
			
   		   	reportName = reportName.replace(/\//g,'_');
   		   	reportName = reportName.replace(/\\/g,'_');
   		   	
   		   	if(gDashboard.reportUtility.reportInfo.ReportMasterInfo.name == ""){
   		   		reportName = "NewReport";
   		   	}
   		 
   			var param;
   			//2020.07.24 MKSONG 다운로드 필터조건 포함  뷰어 오류 수정 DOGFOOT
   			if(WISE.Constants.editmode == 'viewer'){
   				if(_.keys(gDashboard.viewerParameterBars[gDashboard.structure.ReportMasterInfo.id].state.paramValues).length != 0){
   					param = gDashboard.viewerParameterBars[gDashboard.structure.ReportMasterInfo.id].state.paramValues;
   				}
   			}else{
   				//2020.07.22 MKSONG 다운로드 필터조건 포함 DOGFOOT
   				if(_.keys(gDashboard.parameterFilterBar.state.paramValues).length != 0){
   					param = gDashboard.parameterFilterBar.state.paramValues;
   				}	
   			}
   	      	var paramItemsJsonArray = [];
   	      	if(param != undefined){
   	      		$.each(param,function(_key,_param){
   	      			paramItemsJsonArray.push({'key':_param.name,'value':_param.value});
   	      		});	
   	      	}
   		  	
   			var paramJsonArrayStr = JSON.stringify(paramItemsJsonArray);
   			//2020.07.22 MKSONG 다운로드 필터조건 포함 끝 DOGFOOT
   			if(!Array.isArray(JSON.parse(downloadContentList[0].dataItems).Measure)){
   				var temp = JSON.parse(downloadContentList[0].dataItems);
   				temp.Measure = WISE.util.Object.toArray(temp.Measure);

   				downloadContentList[0].dataItems = JSON.stringify(temp);
   			}
			var param = {
//					'fields' : $.toJSON(this.dataSourceConfig.fields),
					'params': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues()),
					'sqlTimeout':userJsonObject.searchLimitTime,
					'userId' : userJsonObject.userId,
					'userName' : userJsonObject.userNm,
					'reportType' : gDashboard.reportType,
					'contentList' : JSON.stringify(downloadContentList),
					'reportName' : reportName,
					'paramJsonArray': paramJsonArrayStr,
					'downloadType': _dwType,		// 다운로드타입 추가
					/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
          			'downloadFilter' : userJsonObject.downloadFilter
			};

			var fileData;
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/download/sqlLikeExcel.do', 
				data: param,
				async: false,
				beforeSend:function() {
					gProgressbar.show();
				},
				complete: function() {
//					gProgressbar.hide();
				},
				success: function(_data) {
					/* 2020.12.18 mksong 다운로드 실패 무한로드 오류 수정 dogfoot */
					if(_data.filePath){
						fileData = _data;
						_.each(downloadContentList, function(con) {
							con.uploadPath = fileData.filePath;
							con.fileName = fileData.fileName;
						});
					}else{
						gProgressbar.hide();
						WISE.alert('다운로드에 실패했습니다.');	
					}
				},
				error: function(error){
					gDashboard.updateReportLog('99');
					gProgressbar.hide();
					WISE.alert('error'+ajax_error_message(error),'error');
					data = error.data;
				}
			});

			if(itemInstance.type == 'DATA_GRID'){
			    return downloadContentList;	
			}else{
				return fileData;
			}
			
			
//			return new Promise(function (resolve, reject) {
//	            var xhttp = new XMLHttpRequest();
//	            xhttp.open("POST", WISE.Constants.context + '/report/sqlLikeExcel.do');
//				xhttp.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
//	            xhttp.responseType = 'blob';
//	            xhttp.send($.param(param));
//	            xhttp.onload = function() {
//	                if (this.status >= 200 && this.status < 300) {
//						resolve(xhttp.response);
//	                } else {
//						reject({
//							status: this.status,
//							status: xhttp.statusText
//						});
//					}
//	            };
//				xhttp.onerror = function() {
//					reject({
//						status: this.status,
//						status: xhttp.statusText
//					});
//				}
//			});
		},
		pivotGridSqlLikeExcel : function(contentList, itemInstance, downloadType){
			var _dwType = isNull(downloadType) ? 'xlsx' : downloadType;
			var data;
			var datasets = gDashboard.datasetMaster.getState('DATASETS');
			var grindNumber = 0;
			
			var setContentList = function(item){
				var gridJson = {};
				if(typeof item.cubeQuery == 'undefined' || item.cubeQuery == '') {
					gridJson.query = Base64.encode((!$.isEmptyObject(datasets) && !WISE.Context.isCubeReport) ? datasets[item.dataSourceId].DATASET_QUERY : gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].SQL_QUERY);
				} else {
					gridJson.query = Base64.encode(item.cubeQuery);
				}
				gridJson.dsid = (!$.isEmptyObject(datasets)) ? datasets[item.dataSourceId].DATASRC_ID : gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASRC_ID;
				gridJson.dstype = (!$.isEmptyObject(datasets)) ? datasets[item.dataSourceId].DATASRC_TYPE : gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASRC_TYPE;
				gridJson.dsnm = (!$.isEmptyObject(datasets)) ? datasets[item.dataSourceId].DATASET_NM : gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_NM;

				/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
				gridJson.sqlConfig = item.sqlConfig;

				// 20210906 sheet명 에러안나게(/ -> _ 처리)
				var itemNm = item.Name;
				itemNm = itemNm.replace(/\//g,'_');
				itemNm = itemNm.replace(/\\/g,'_');
				gridJson.item = itemNm;
				
				/* 2020.12.18 mksong 주택금융공사 정렬컬럼 피벗테이블 제외 dogfoot */
				gridJson.itemtype = item.type;
				gridJson.sortColumnCount = item.HiddenMeasures.length;
				gridJson.cols = item.columns;
				gridJson.rows = item.rows;
				gridJson.datafieldPosition = item.Pivot.DataFieldPosition;
				gridJson.totalView = {'ShowColumnTotals' : item.Pivot.ShowColumnTotals, 'ShowRowTotals': item.Pivot.ShowRowTotals, 
						'ShowColumnGrandTotals': item.Pivot.ShowColumnGrandTotals, 'ShowRowGrandTotals': item.Pivot.ShowRowGrandTotals};
				
				// 20210827 Measure가 뷰어에선 Array가 아니어서 다운로드 실패하는 에러 수정
				if (WISE.Constants.editmode == 'viewer') {
					var objJsonArr = new Array();
					if (!isNull(item.DI)) {
						if (!isNull(item.DI.Measure) && !Array.isArray(item.DI.Measure)) {
							objJsonArr.push(item.DI.Measure);
							item.DI.Measure = objJsonArr;
						}
					}
				}
				
				gridJson.dataItems = $.toJSON(item.DI);
				/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
				var nullDimension = [];
				var nullDimensionJson = {};
				if(typeof item.Pivot['NullRemoveType'] != undefined && item.Pivot['NullRemoveType']) {
					if(item.Pivot['NullRemoveType'] == 'rowNullRemove') {
						$.each(item.rows, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					} else if(item.Pivot['NullRemoveType'] == 'colNullRemove') {
						$.each(item.columns, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					} else if(item.Pivot['NullRemoveType'] == 'allNullRemove') {
						$.each(item.rows, function(_i, _e) {
							nullDimension.push(_e.name);
						});
						$.each(item.columns, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					}
					if(nullDimension.length > 0) {
						nullDimensionJson[0] = item.Pivot['NullRemoveType'];
						$.each(nullDimension, function(_i, _e) {
							nullDimensionJson[_i + 1] = _e;
						});
					}
				}

				gridJson.nullDimension =  $.toJSON(nullDimensionJson);
				
				// 행/열번환 추가
				gridJson.colRowSwitch = item.meta.ColRowSwitch;

				contentList.push(gridJson);
			}
			
			if(!itemInstance){
				$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i, _o){
					setContentList(_o)
				});
			}else{
				setContentList(itemInstance);
			}
			
			return contentList;

		},
		/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
		doSqlLikePaging : function(self, pagingSize, pagingStart){
			
			if(self.dataSourceId == undefined) return;
			var data;
			var datasets = gDashboard.datasetMaster.getState('DATASETS');
			var query = "";
			if(typeof self.cubeQuery == 'undefined' || self.cubeQuery == '') {
				query = (!$.isEmptyObject(datasets) && !WISE.Context.isCubeReport) ? datasets[self.dataSourceId].DATASET_QUERY : gDashboard.dataSourceManager.datasetInformation[self.dataSourceId].SQL_QUERY;
			} else {
				query = self.cubeQuery;
			}

				acync = false;

			var dsnm = (!$.isEmptyObject(datasets)) ? datasets[self.dataSourceId].DATASET_NM : gDashboard.dataSourceManager.datasetInformation[self.dataSourceId].DATASET_NM;
			var param = {
						'params': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues()),
						'sql_query' : Base64.encode(query),
						'ds_nm' : dsnm,
						'dsid' : (!$.isEmptyObject(datasets)) ? datasets[self.dataSourceId].DATASRC_ID : gDashboard.dataSourceManager.datasetInformation[self.dataSourceId].DATASRC_ID,
						'dstype' : (!$.isEmptyObject(datasets)) ? datasets[self.dataSourceId].DATASRC_TYPE : gDashboard.dataSourceManager.datasetInformation[self.dataSourceId].DATASRC_TYPE,
						'sqlConfig' : $.toJSON(self.sqlConfig),
						'sqlTimeout':userJsonObject.searchLimitTime,
						'fullQuery': gDashboard.downloadFull,
						'userId' : userJsonObject.userId,
						'reportType' : gDashboard.reportType,
						'tbllist': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentTableList(dsnm)),
						'pagingSize' : pagingSize,
						'pagingStart' : pagingStart
			};
			
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/report/sqlLikePaging.do', 
				data: param,
				async: acync,
				beforeSend:function() {
					gProgressbar.show();
				},
				complete: function() {
				},
				success: function(sqldata) {
					if (!sqldata || ($.type(sqldata.data) === 'array' && sqldata.data.length === 0)) {
						$('#'+self.itemid + ' .nodata-layer').remove();
						var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
						$("#" + self.itemid).children().css('display','none');
						$("#" + self.itemid).prepend(nodataHtml);
						if(($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0) && self.itemid.indexOf("gridDashboardItem") === -1){
							$("#" + self.itemid).height('100%');
							$("#" + self.itemid).width('100%');
						}
						$("#" + self.itemid).css('display', 'block');

						if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
							gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
						}

						if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
							gProgressbar.setStopngoProgress(true);
							gProgressbar.hide();
							gDashboard.updateReportLog();
						}
						/*dogfoot shlim 20210419*/
						if(typeof self != 'undefined') {
							$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
								if(_e.itemid == self.itemid) {
									self.showQuery = sqldata.sql;
									_e.showQuery = sqldata.sql;
								}
							});
						}
					}else{
						$('#'+self.itemid + ' .nodata-layer').remove();
						if(self.itemid.indexOf("gridDashboardItem") === -1)
							$("#" + self.itemid).children().css('display','block');
						else
							$("#" + self.itemid).children().css('display','flex');
						self.renderGrid(self,sqldata.data, sqldata.totalCount.totalCount);
						if(typeof self != 'undefined') {
							$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
								if(_e.itemid == self.itemid) {
									self.showQuery = sqldata.sql;
									_e.showQuery = sqldata.sql;
								}
							});
						}
						if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
							gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
						}

						if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
							gProgressbar.setStopngoProgress(true);
							gProgressbar.hide();
							gDashboard.updateReportLog();
						}
					}
				},
				error: function(error){
					gDashboard.updateReportLog('99');
					gProgressbar.hide();
					/* DOGFOOT ktkang 작업 취소 메세지 수정  20201005 */
					if(ajax_error_message(error).indexOf('Statement canceled') > -1 || ajax_error_message(error).indexOf('SQLTimeout') > -1
							|| ajax_error_message(error).indexOf('초과되었습니다') > -1 || ajax_error_message(error).indexOf('취소되었습니다') > -1
							|| ajax_error_message(error).indexOf('No result') > -1) {
						WISE.alert('진행 중인 작업이 취소되었거나 제한 시간 초과로 종료되었습니다.');
					} else {
						WISE.alert('쿼리가 부적합 합니다.','error');
					}
					//20210723 AJKIM SQL 에러 로그 공개 추가 dogfoot
					if(userJsonObject.menuconfig.Menu.SQL_ERROR_LOG){
						if(typeof self != 'undefined') {
							$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
								if(_e.itemid == self.itemid) {
									self.showQuery = ajax_error_message(error);
									_e.showQuery = ajax_error_message(error);
								}
							});
						}
					}
//					WISE.alert('error'+ajax_error_message(error),'error');
					data = error.data;
				}
			});
		},
		doSqlLikePaging : function(self, pagingSize, pagingStart){
			if(self.dataSourceId == undefined) return;
			var data;
			var datasets = gDashboard.datasetMaster.getState('DATASETS');
			var query = "";
			if(typeof self.cubeQuery == 'undefined' || self.cubeQuery == '') {
				query = (!$.isEmptyObject(datasets) && !WISE.Context.isCubeReport) ? datasets[self.dataSourceId].DATASET_QUERY : gDashboard.dataSourceManager.datasetInformation[self.dataSourceId].SQL_QUERY;
			} else {
				query = self.cubeQuery;
			}
			
			// 20210331 AJKIM 정렬기준항목 데이터 항목 중복시 오류 수정 dogfoot
			if(self.sqlConfig.OrderBy && self.sqlConfig.OrderBy.length > 0){
				var tempFieldList = [];
				var tempFieldQuan = {};
				$.each(self.sqlConfig.OrderBy, function(i, field){
					if(field.indexOf('|') == -1){
						if(tempFieldList.indexOf(field) >= 0){
							tempFieldQuan[field] ++;
							field = field + tempFieldQuan[field];
							isDuple = true;
						}else{
							tempFieldQuan[field] = 1;
							tempFieldList.push(field);
						}
					}
				});
				
				tempFieldList = [];
				tempFieldQuan = {};
				for(var i = 0; i < self.sqlConfig.Select.length; i++){
					if(self.sqlConfig.Select[i].indexOf('|') == -1 && (self.sqlConfig.Select[i-1] == '|as|')){
						if(tempFieldList.indexOf(self.sqlConfig.Select[i]) >= 0){
							tempFieldQuan[self.sqlConfig.Select[i]] ++;
							self.sqlConfig.Select[i] = self.sqlConfig.Select[i] + tempFieldQuan[self.sqlConfig.Select[i]];
							isDuple = true;
						}else{
							tempFieldQuan[self.sqlConfig.Select[i]] = 1;
							tempFieldList.push(self.sqlConfig.Select[i]);
						}
					}
				}
			}

			acync = false;

			var dsnm = (!$.isEmptyObject(datasets) && !$.isEmptyObject(datasets[self.dataSourceId])) ? datasets[self.dataSourceId].DATASET_NM : gDashboard.dataSourceManager.datasetInformation[self.dataSourceId].DATASET_NM;
			var param = {
						'params': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues()),
						'sql_query' : Base64.encode(query),
						'ds_nm' : dsnm,
						'dsid' : (!$.isEmptyObject(datasets) && !$.isEmptyObject(datasets[self.dataSourceId])) ? datasets[self.dataSourceId].DATASRC_ID : gDashboard.dataSourceManager.datasetInformation[self.dataSourceId].DATASRC_ID,
						'dstype' : (!$.isEmptyObject(datasets) && !$.isEmptyObject(datasets[self.dataSourceId])) ? datasets[self.dataSourceId].DATASRC_TYPE : gDashboard.dataSourceManager.datasetInformation[self.dataSourceId].DATASRC_TYPE,
						'sqlConfig' : $.toJSON(self.sqlConfig),
						'sqlTimeout':userJsonObject.searchLimitTime,
						'fullQuery': gDashboard.downloadFull,
						'userId' : userJsonObject.userId,
						'reportType' : gDashboard.reportType,
						//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
						'inMemory': datasets[self.dataSourceId].IN_MEMORY,
						'tbllist': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentTableList(dsnm)),
						'pagingSize' : pagingSize,
						'pagingStart' : pagingStart
			};
			
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/report/sqlLikePaging.do', 
				data: param,
				async: acync,
				beforeSend:function() {
					gProgressbar.show();
				},
				complete: function() {
				},
				success: function(sqldata) {
					if (!sqldata || ($.type(sqldata.data) === 'array' && sqldata.data.length === 0)) {
						$('#'+self.itemid + ' .nodata-layer').remove();
						var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
						$("#" + self.itemid).children().css('display','none');
						$("#" + self.itemid).prepend(nodataHtml);
						if(($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0) && self.itemid.indexOf("gridDashboardItem") === -1){
							$("#" + self.itemid).height('100%');
							$("#" + self.itemid).width('100%');
						}
						$("#" + self.itemid).css('display', 'block');

						if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
							gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
						}

						if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
							gProgressbar.setStopngoProgress(true);
							gProgressbar.hide();
							gDashboard.updateReportLog();
						}
					}else{
						//20210714 AJKIM 쿼리 암호화 dogfoot
						if(sqldata.sql)
							sqldata.sql = Base64.decode(sqldata.sql);
						
						$('#'+self.itemid + ' .nodata-layer').remove();
						if(self.itemid.indexOf("gridDashboardItem") === -1)
							$("#" + self.itemid).children().css('display','block');
						else
							$("#" + self.itemid).children().css('display','flex');
						self.renderGrid(self,sqldata.data, sqldata.totalCount.totalCount);
						if(typeof self != 'undefined') {
							$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
								if(_e.itemid == self.itemid) {
									self.showQuery = sqldata.sql;
									_e.showQuery = sqldata.sql;
								}
							});
						}
						if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
							gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
						}

						if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
							gProgressbar.setStopngoProgress(true);
							gProgressbar.hide();
							gDashboard.updateReportLog();
						}
					}
				},
				error: function(error){
					gDashboard.updateReportLog('99');
					gProgressbar.hide();
					/* DOGFOOT ktkang 작업 취소 메세지 수정  20201005 */
					if(ajax_error_message(error).indexOf('Statement canceled') > -1 || ajax_error_message(error).indexOf('SQLTimeout') > -1
							|| ajax_error_message(error).indexOf('초과되었습니다') > -1 || ajax_error_message(error).indexOf('취소되었습니다') > -1
							|| ajax_error_message(error).indexOf('No result') > -1) {
						WISE.alert('진행 중인 작업이 취소되었거나 제한 시간 초과로 종료되었습니다.','error');
					} else {
						WISE.alert('쿼리가 부적합 합니다.','error');
					}
					//20210723 AJKIM SQL 에러 로그 공개 추가 dogfoot
					if(userJsonObject.menuconfig.Menu.SQL_ERROR_LOG){
						if(typeof self != 'undefined') {
							$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
								if(_e.itemid == self.itemid) {
									self.showQuery = ajax_error_message(error);
									_e.showQuery = ajax_error_message(error);
								}
							});
						}
					}
//					WISE.alert('error'+ajax_error_message(error),'error');
					data = error.data;
					gProgressbar.setStopngoProgress(true);
					gProgressbar.hide();
				}
			});
		},
		getSqlLikeAjaxParam: function(_dataSourceId, _sqlConfig, self, cubeQuery){
			if(_dataSourceId == undefined) return;
			var data;
			var datasets = gDashboard.datasetMaster.getState('DATASETS');
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			var query = "";
			if(typeof cubeQuery == 'undefined' || cubeQuery == '') {
				query = (!$.isEmptyObject(datasets) && !WISE.Context.isCubeReport) ? datasets[_dataSourceId].DATASET_QUERY : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].SQL_QUERY;
			} else {
				query = cubeQuery;
			}
			/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
//			var acync = true;
//			if(gDashboard.downloadFull) {
			/* DOGFOOT ktkang 그리드 페이징 오류 수정  20201015 */
			var	acync = true;
			if(userJsonObject.gridDataPaging === 'Y' && self.type == 'DATA_GRID'){
				acync = false;
			}
			acync = gDashboard.analysisType !== undefined ? false : true; //통계분석 동기
//			}
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			var dsnm = (!$.isEmptyObject(datasets) && !$.isEmptyObject(datasets[_dataSourceId])) ? datasets[_dataSourceId].DATASET_NM : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASET_NM;
			/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
			var nullDimension = [];
			var nullDimensionJson = {};
			if(self.type == 'PIVOT_GRID'){
				if(typeof self.Pivot['NullRemoveType'] != undefined && self.Pivot['NullRemoveType']) {
					if(self.Pivot['NullRemoveType'] == 'rowNullRemove') {
						$.each(self.rows, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					} else if(self.Pivot['NullRemoveType'] == 'colNullRemove') {
						$.each(self.columns, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					} else if(self.Pivot['NullRemoveType'] == 'allNullRemove') {
						$.each(self.rows, function(_i, _e) {
							nullDimension.push(_e.name);
						});
						$.each(self.columns, function(_i, _e) {
							nullDimension.push(_e.name);
						});
					}
					if(nullDimension.length > 0) {
						nullDimensionJson[0] = self.Pivot['NullRemoveType'];
						$.each(nullDimension, function(_i, _e) {
							nullDimensionJson[_i+1] = _e;
						});
					}
				}
			}
			/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
			var params = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
				
			// 20210331 AJKIM 정렬기준항목 데이터 항목 중복시 오류 수정 dogfoot
			if(_sqlConfig.OrderBy && _sqlConfig.OrderBy.length > 0){
				var tempFieldList = [];
				var tempFieldQuan = {};
				$.each(_sqlConfig.OrderBy, function(i, field){
					if(field.indexOf('|') == -1){
						if(tempFieldList.indexOf(field) >= 0){
							tempFieldQuan[field] ++;
							field = field + tempFieldQuan[field];
							isDuple = true;
						}else{
							tempFieldQuan[field] = 1;
							tempFieldList.push(field);
						}
					}
				});
				
				tempFieldList = [];
				tempFieldQuan = {};
				for(var i = 0; i < _sqlConfig.Select.length; i++){
					if(_sqlConfig.Select[i].indexOf('|') == -1 && (_sqlConfig.Select[i-1] == '|as|')){
						if(tempFieldList.indexOf(_sqlConfig.Select[i]) >= 0){
							tempFieldQuan[_sqlConfig.Select[i]] ++;
							_sqlConfig.Select[i] = _sqlConfig.Select[i] + tempFieldQuan[_sqlConfig.Select[i]];
							isDuple = true;
						}else{
							tempFieldQuan[_sqlConfig.Select[i]] = 1;
							tempFieldList.push(_sqlConfig.Select[i]);
						}
					}
				}
			}
			
			var param = {
//						'fields' : $.toJSON(this.dataSourceConfig.fields),
						'params' : params,
						/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
						'sql_query' : Base64.encode(query),
						'ds_nm' : dsnm,
						'dsid' : (!$.isEmptyObject(datasets) && !$.isEmptyObject(datasets[_dataSourceId])) ? datasets[_dataSourceId].DATASRC_ID : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASRC_ID,
						'dstype' : (!$.isEmptyObject(datasets) && !$.isEmptyObject(datasets[_dataSourceId])) ? datasets[_dataSourceId].DATASRC_TYPE : gDashboard.dataSourceManager.datasetInformation[_dataSourceId].DATASRC_TYPE,
//						'reportId' : gDashboard.structure.ReportMasterInfo.id,
						'sqlConfig' : _sqlConfig,
						'sqlTimeout':userJsonObject.searchLimitTime,
						/* DOGFOOT ktkang SQL 로그 추가  20200721 */
						'fullQuery': gDashboard.downloadFull,
						'userId' : userJsonObject.userId,
						'reportType' : gDashboard.reportType,
						'tbllist': WISE.libs.Dashboard.item.DatasetUtility.getCurrentTableList(dsnm),
						'nullDimension': nullDimensionJson,
						/* DOGFOOT ktkang 스케줄링 오류 수정  20201007 */
						'schedulePath' : gDashboard.schedulePath,
						//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
						'inMemory': (!$.isEmptyObject(datasets) && !$.isEmptyObject(datasets[_dataSourceId])) ? datasets[_dataSourceId].IN_MEMORY : false,
						/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
						'oldSchedule': userJsonObject.oldSchedule,
						'itemType' : self.type
			};
			
			return param;
		}
	}
};