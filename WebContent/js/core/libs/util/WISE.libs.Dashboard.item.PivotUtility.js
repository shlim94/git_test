/** DataUtility */
WISE.libs.Dashboard.item.PivotUtility = {
	getRemoteOperationParameter: function(_pivot){
		// 피벗 세팅 시작
		if(_pivot.meta != undefined){
			_pivot.Pivot = _pivot.meta;
		}
		
		if(_pivot.fieldManager != null && _pivot.Pivot == undefined){
			_pivot.setPivot();
			gDashboard.itemGenerateManager.addParentItems(_pivot);
			gDashboard.itemGenerateManager.itemCustomize(_pivot,_pivot.Pivot);
			gDashboard.itemGenerateManager.generateItem(_pivot, _pivot.Pivot);
		}else if(_pivot.fieldManager != null && _pivot.Pivot){
			_pivot.setDataItems();
			if (_pivot.meta.InteractivityOptions == null) {
				_pivot.meta.InteractivityOptions = {
					MasterFilterMode: 'Off',
					IgnoreMasterFilters: false
				};
			}
			_pivot.queryState = false;
			gDashboard.itemGenerateManager.generateItem(_pivot, _pivot.meta);
		}
		else if(_pivot.fieldManager == null){
			_pivot.setDataItemsForViewer();
			gDashboard.itemGenerateManager.itemCustomize(_pivot,_pivot.meta);
			gDashboard.itemGenerateManager.generateItem(_pivot, _pivot.meta);
		}
				
		var dxConfig = _pivot.getDxItemConfig(_pivot.meta);
		var customFieldCheck = false;
		_pivot.dataFields = _pivot.dataFields.concat(_.clone(_pivot.HiddenMeasures));
		// 2021-08-10 jhseo 사용자 정의 데이터 넣었는지 체크
		if(typeof gDashboard.customFieldManager.fieldInfo !='undefined' && Object.keys(gDashboard.customFieldManager.fieldInfo)){
			$.each(gDashboard.customFieldManager.fieldInfo,function(_datasource,_dataField){
				if(_dataField.length > 0){
					for(var i=0; i<_pivot.dataFields.length; i++){
						for(var j=0; j<_dataField.length; j++){
							if(_pivot.dataFields[i].name == _dataField[j].Name){
								customFieldCheck = true;
								break;
							}
						}
					}
				}					
			});
		}
		_pivot.customFields = [];
		
		if(customFieldCheck && !($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[_pivot.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(_pivot.dataFields,function(_i,_dataField){
						if(field.Name == _dataField.name){
							_pivot.calculatedFields.push(_dataField);
							_pivot.calculateCaption = _dataField.name;
							var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
//							_pivot.dataFields.splice(_i,1);
							$.each(tempDataField, function(_index,_tempDataField){
								if(_pivot.dataSourceConfig.fields.map(function(d) {return d['caption']}).indexOf(_tempDataField) == -1) {  
									var fieldOption = {
											area: 'data',
											caption: _tempDataField,
											dataField: _tempDataField,
									        summaryType: 'sum',
									        UNI_NM: _tempDataField,
									        cubeUNI_NM: _tempDataField,
									        precision: 0,
									        precisionOption: '반올림',
									        DRAW_CHART:false,
									        visible:false,
									        isDelta:false,
									        customField: true,
									        format: "fixedPoint",
									        formatType: "Number",
											originsummaryType:'sum',
											customizeText: function(e) {
												if (userJsonObject.showNullValue && (e.valueText.indexOf("wise_null_value") > -1|| e.value == null || e.valueText == 'NaN')) {
													if(userJsonObject.nullValueString == 'nullValueString') {
														return 'null';
													} else {
														return userJsonObject.nullValueString;
													}
												} else {
													return WISE.util.Number.unit(e.value, 'Number', 'Ones', 0, true,
														undefined, '', false);
												}
											},
											calculateCustomSummary: function (options) {
								                if (options.summaryProcess == 'start') {
								                    options.totalValue = 0;
								                    options.sum2 = 0;
								                    options.n = 0;
								                }
								                if (options.summaryProcess == 'calculate') {
								                	if(options.value && !(typeof options.value == "string" && options.value.indexOf("wise_null_value") > -1))
								                        options.totalValue += options.value;
								                }
							                }
									}
									
									_pivot.customFields.push(fieldOption);
//										_pivot.dataSourceConfig.fields.push(fieldOption);
								}
								var dataMember = {
										UNI_NM: undefined,
										caption: _pivot.calculateCaption,
										captionBySummaryType: "sum_"+_tempDataField,
										currencyCulture: undefined,
										format: "fixedPoint",
										formatType: "Number",
										includeGroupSeparator: true,
										name: _tempDataField,
										nameBySummaryType: "sum("+_tempDataField+")",
										nameBySummaryType2: "sum_"+_tempDataField,
										precision: 0,
										precisionOption: '반올림',
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
								_pivot.dataFields.push(dataMember);
							});
						}
					});

					$.each(_pivot.columns,function(_i,_column){
						// 2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_column != undefined){
							if(field.Name == _column.name){
								_pivot.calculatedFields.push(_column);
								_pivot.calculateCaption = _column.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(_pivot.columns,function(_k, _column2){
											if(_tempDataField == _column2.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								_pivot.columns.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: _pivot.calculateCaption,
												captionBySummaryType: _tempDataField,
												currencyCulture: undefined,
												includeGroupSeparator: true,
												name: _tempDataField,
												precision: 0,
												precisionOption: '반올림',
												rawCaption: _tempDataField,
												suffixEnabled: false,
												type: "dimension",
												tempdata: true,
												nameBySummaryType: "min("+_tempDataField+")",
												nameBySummaryType2: "min_"+_tempDataField
										}
										_pivot.columns.push(dataMember);
									});
								}
							}
							// 2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});

					$.each(_pivot.rows,function(_i,_row){
						// 2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_row != undefined){
							if(field.Name == _row.name){
								_pivot.calculatedFields.push(_row);
								_pivot.calculateCaption = _row.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(_pivot.rows,function(_k, _row2){
											if(_tempDataField == _row2.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								_pivot.rows.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: _pivot.calculateCaption,
												captionBySummaryType: _tempDataField,
												currencyCulture: undefined,
												includeGroupSeparator: true,
												name: _tempDataField,
												precision: 0,
												precisionOption: '반올림',
												rawCaption: _tempDataField,
												suffixEnabled: false,
												type: "dimension",
												tempdata: true,
												nameBySummaryType: "min("+_tempDataField+")",
												nameBySummaryType2: "min_"+_tempDataField
										}
										_pivot.rows.push(dataMember);
									});
								}
							}
							// 2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
				});
			}
		}
		// 2020.02.04 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 수정 끝 dogfoot

		_pivot.dimensions = [];
		// 2020.03.25 수정자 : mksong 정렬순서 변경 DOGFOOT
		_pivot.dimensions = _pivot.dimensions.concat(_.clone(_pivot.columns));
		_pivot.dimensions = _pivot.dimensions.concat(_.clone(_pivot.rows));
		if(_pivot.HiddenDimensions){
		    _pivot.dimensions = _pivot.dimensions.concat(_.clone(_pivot.HiddenDimensions));	
		}
		
		var dataFieldsforSqlConfig = []
			
		$.each(_pivot.dataFields,function(_fIndex,_fValue){
			dataFieldsforSqlConfig.push(_fValue);
		})

		if(typeof gDashboard.customFieldManager.fieldInfo !='undefined' && Object.keys(gDashboard.customFieldManager.fieldInfo)){
			$.each(gDashboard.customFieldManager.fieldInfo,function(_datasource,_dataField){
				if(_dataField.length > 0){
					for(var i=0; i<dataFieldsforSqlConfig.length; i++){
						for(var j=0; j<_dataField.length; j++){
							if(dataFieldsforSqlConfig[i].name == _dataField[j].Name){
								dataFieldsforSqlConfig[i].tempdata = true;
								customFieldCheck = true;
								break;
							}
						}
					}
				}					
			});
		}

		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = _pivot.dataSourceId;
		/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
		var sqlConfig = SQLikeUtil.fromJsonforNoSummaryType(customFieldCheck, _pivot.dimensions,
				dataFieldsforSqlConfig.filter(function(data, i){
			   if(!data.tempdata) return true;
				}), null, undefined, undefined, _pivot.orderKey,_pivot.type);

        

		
		
		if(_pivot.IO.IgnoreMasterFilters && !_pivot.isAdhocItem){
			sqlConfig.Where = [];
			sqlConfig.From = [];
		}

		_pivot.sqlConfig = sqlConfig;
		
		var sqlLikeOption = SQLikeUtil.getSqlLikeAjaxParam(_pivot.dataSourceId, sqlConfig, _pivot, _pivot.cubeQuery);
		
		var dimList = _pivot.rows.concat(_pivot.columns);
		var fieldList = dimList.concat(_pivot.dataFields);
		var sortInfo = [];
		var udfGroups = [];
		
		// 사용자정의 데이터 저장
		$.each(gDashboard.customFieldManager.fieldInfo[_pivot.dataSourceId], function(i, udfField){
			var selectors = [];
			$.each(fieldList, function(j, dim){
				if(udfField.Expression.indexOf("["+dim.name+"]") > -1){
					selectors.push(dim.name);
				}
			})
			// PivotGrid의 "[순매출액]*2"과 같은 표현식을 "_fields['순매출액']*2" 포맷으로 변경
			var convertedExpr = udfField.Expression.replace(/\[([^\[\]\'\"]+)\]/g, "_fields['$1']");
			udfGroups.push({name: udfField.Name, selectors: selectors, expression: convertedExpr});
		})
		
// $.each(dimList, function(i, field){
// sortInfo.push({
// sortOrder: field.sortOrder,
// dataField: field.name,
// sortByField: field.sortByMeasure || field.name
// });
// })
		
        var hiddenFields = [];
		/* dogfoot 정렬 정보 추가 shlim 20210824 */
		$.each(dimList, function(i, field){
			var sortOrder="",dataField="",sortByField="";
			sortOrder = field.sortOrder;
			dataField = field.name;
			sortByField = field.name;
			hiddenFieldObject = null;
			// 주제영역에서 저장한 정렬 기준 항목
			if(_pivot.orderKey != undefined){
				$.each(_pivot.orderKey, function(j, orderKeyField){
					if(orderKeyField.columnCaption == field.name){
						sortByField = orderKeyField.orderByCaption.trim() || orderKeyField.orderBy.trim() 
						hiddenFieldObject = {summaryType: 'min', selector: sortByField,isSortSelector: "Y"}; 
					}
				})
			}else{
				$.each(gDashboard.datasetMaster.state.fields[gDashboard.itemGenerateManager.itemDataSourceId], function(_ii, _ee) {
					if(_ee.CAPTION == 'S_' + dataField) {
						sortByField = _ee.CAPTION;
						hiddenFieldObject = {summaryType: 'min', selector: sortByField,isSortSelector: "Y"};
					}
				});
			}
			
//			$.each(_pivot.dxItem.getDataSource()._fields,function(_sourceFieldIndex,_sourceField){
//				if(_sourceField.caption == dataField) {
//					if(_sourceField.sortOrder != "undefined"){
//					    sortOrder = _sourceField.sortOrder;	
//					}
//					return false;
//				}
//            })
			
			
			// 정렬기준항목이 설정도 최우선순위
			if(field.sortByMeasure){
				sortByField = field.sortByMeasure;
			}else{
				if(hiddenFieldObject != null){
					hiddenFields.push(hiddenFieldObject);
				}
			}
			
			
			
			sortInfo.push({
				sortOrder: sortOrder,
				dataField: dataField,
				sortByField: sortByField
			});
		})

		var customFieldDupleCheckArr = [];
		if(_pivot.customFields){
			$.each(_pivot.customFields, function(i, field) {
				if(customFieldDupleCheckArr.indexOf(field.dataField) == -1){
					hiddenFields.push({
						selector: field.dataField,
						summaryType: field.summaryType,
						isSortSelector: 'Y'
				    })
				    customFieldDupleCheckArr.push(field.dataField);
				}
				
			})
		}
		
		// 페이징 파라미터 rowGroup 처리
		var isPaging = userJsonObject.menuconfig.Menu.PIVOT_PAGING_OPTION && _pivot.Pivot.PagingOptions.PagingEnabled;
		// 비정형이면서 차트가 있으면 paging false
		if (gDashboard.reportType == 'AdHoc' && gDashboard.structure.Layout.indexOf('C') > -1) {
			isPaging = false;
		}
		
		var rowGroups = [];
		if (isPaging) {
			$.each(_pivot.rows, function(idx, row) {
				if(_pivot.optionFields && _pivot.optionFields.length > 0){
        			if(row.name == null){
    					
            		}
        			$.each(_pivot.optionFields, function(idx2, option){
    					if((row.name == option.FLD_NM ||row.name == option.dataField || row.cubeUniqueName == option.dataField || row.CubeUniqueName == option.dataField) && option.GRID_VISIBLE){
    						rowGroups.push({
    							selector: row.name
    						});
    						return false;
    					}
    				})
        		} else {
        			rowGroups.push({
						selector: row.name
					});
        		}
			});
			if(_pivot.curPageSize && _pivot.curPageSize == -1){
				_pivot.curPageSize = _pivot.Pivot.PagingOptions.PagingDefault;
			}
			// 페이지 사이즈 설정값으로 하자
			_pivot.curPageStart = _pivot.curPageIdx == 1 ? 0 : (_pivot.curPageIdx - 1) * _pivot.curPageSize; 
			_pivot.pivotGridPagingOpt = { offset: _pivot.curPageStart, limit: _pivot.curPageSize, rowGroups: rowGroups };
		}
		else {
			_pivot.pivotGridPagingOpt = {};

			$.each(_pivot.rows, function(idx, row) {
				if(_pivot.optionFields && _pivot.optionFields.length > 0){
					if(row.name == null){
    					_pivot.pivotGridPagingOpt.rowGroups.push({
							selector: null
						});
            		}
        			$.each(_pivot.optionFields, function(idx2, option){
    					if((row.name == option.FLD_NM || row.name == option.dataField || row.cubeUniqueName == option.datafield || row.CubeUniqueName == option.datafield) && option.GRID_VISIBLE){
    						rowGroups.push({
    							selector: row.name
    						});
    						return false;
    					}
    				})
        		} else {
        			rowGroups.push({
						selector: row.name
					});
        		}
			});

			_pivot.pivotGridPagingOpt = {rowGroups: rowGroups };
		}
		// 피벗 세팅 끝
		
		
		var rows = [];
		var columns = [];

		/*var rowGroups = [];
		if (isPaging) { 
			$.each(_pivot.rows, function(idx, row) {
				if(_pivot.optionFields && _pivot.optionFields.length > 0){
        			if(row.name == null){
    					rowGroups.push({
    						selector: null
    					});
            		}
        			$.each(_pivot.optionFields, function(idx2, option){
    					if((row.name == option.dataField || row.cubeUniqueName == option.datafield) && option.GRID_VISIBLE){
    						rowGroups.push({
    							selector: row.name
    						});
    						return false;
    					}
    				})
        		} else {
        			rowGroups.push({
						selector: row.name
					});
        		}
			});
			if(_pivot.curPageSize && _pivot.curPageSize == -1){
				_pivot.curPageSize = _pivot.Pivot.PagingOptions.PagingDefault;
			}
			// 페이지 사이즈 설정값으로 하자
			_pivot.curPageStart = _pivot.curPageIdx == 1 ? 0 : (_pivot.curPageIdx - 1) * _pivot.curPageSize; 
			_pivot.pivotGridPagingOpt = { offset: _pivot.curPageStart, limit: _pivot.curPageSize, rowGroups: rowGroups };
		}
		else {
			_pivot.pivotGridPagingOpt = {};
		}*/
		
		//group 구하기
		if(gDashboard.reportType == 'AdHoc'){
		    $.each(_pivot.rows, function(idx, row) {
		    	if(_pivot.optionFields && _pivot.optionFields.length > 0){
					$.each(_pivot.optionFields, function(idx2, option){
						if((row.name == option.FLD_NM || row.name == option.dataField || row.cubeUniqueName == option.dataField || row.CubeUniqueName == option.dataField) && option.GRID_VISIBLE){
							rows.push({
								selector: row.name,
								isExpanded: true
							});
							return false;
						}
					})
        		} else {
        			rows.push({
						selector: row.name,
						isExpanded: true
					});
        		}
				
			});

			$.each(_pivot.columns, function(idx, col) {
				if(_pivot.optionFields && _pivot.optionFields.length > 0){
					$.each(_pivot.optionFields, function(idx2, option){
						if((col.name == option.FLD_NM || col.name == option.dataField || col.cubeUniqueName == option.dataField || col.CubeUniqueName == option.dataField) && option.GRID_VISIBLE){
							columns.push({
								selector: col.name,
								isExpanded: true
							});
							return false;
						}
					})
				}else{
                    columns.push({
						selector: col.name,
						isExpanded: true
					});
				}
			});	
		}else{
			$.each(_pivot.rows, function(idx, row) {
				rows.push({
					selector: row.name,
					isExpanded: true
				});
			});

			$.each(_pivot.columns, function(idx, col) {
				columns.push({
					selector: col.name,
					isExpanded: true
				});
			});	
		}
		
		if(rows.length == 0 && columns.length == 0) {
			return {error: "필드가 없습니다."};
		}
		else if(rows.length == 0){
			rows.push({isExpanded:true});
            rowGroups.push({
				selector: ""
			});
		} 
		else if(columns.length == 0) {
			columns.push({isExpanded: false});
		}
		
		if(columns.length > 0){
            columns[columns.length - 1].isExpanded = false;
		}
		
		if(rows.length > 0){
			rows[rows.length -1].isExpanded = false;
		}
		
		
		
		var group = rows.concat(columns);
		//group 구하기 끝
		
		//groupSummary 구하기
		var data = [];
		if(gDashboard.reportType == 'AdHoc'){
			$.each(_pivot.dataFields, function(idx, mea) {
				if(_pivot.optionFields && _pivot.optionFields.length > 0){
                    $.each(_pivot.optionFields, function(idx2, option){
						if((mea.name == option.FLD_NM || mea.name == option.dataField || mea.cubeUniqueName == option.dataField || mea.CubeUniqueName == option.dataField) && option.GRID_VISIBLE){

							var tempedDataField = {};
							tempedDataField.selector = mea.name
							tempedDataField.summaryType = mea.summaryType
							data.push(tempedDataField);
							return false;
						}
					})
				}else{
					var tempedDataField = {};
					tempedDataField.selector = mea.name
					tempedDataField.summaryType = mea.summaryType
					data.push(tempedDataField);
				}
				
			});
		}else{
			$.each(_pivot.dataFields, function(idx, mea) {
					data.push({
						selector: mea.name,
						summaryType: mea.summaryType
					});
			});
		}		
		
		data = _.uniqBy(data,"selector");
		
		/*변동측정값 shlim*/
//		if(_pivot.deltaItems.length > 0){
//			$.each(_pivot.deltaItems,function(_deltaItemIndex,_deltaItemValue){
//				data.push({
//					selector : _deltaItemValue.BASE_UNI_NM,
//					summaryType : "sum"
//				})
//			})
//		}
		
		var groupSummary = data.concat(hiddenFields);
		$.each(groupSummary,function(_groupSummaryIndex,_groupSummaryValue){
			if(!_groupSummaryValue.isSortSelector){
				if(_pivot.formatFieldArray[_groupSummaryIndex]){
					_groupSummaryValue.precision = _pivot.formatFieldArray[_groupSummaryIndex].precision
					_groupSummaryValue.precisionOption = _pivot.formatFieldArray[_groupSummaryIndex].precisionOption
//					_groupSummaryValue.format = self.formatFieldArray[_groupSummaryIndex].format
//					_groupSummaryValue.formatType = self.formatFieldArray[_groupSummaryIndex].formatType
//					_groupSummaryValue.unit = self.formatFieldArray[_groupSummaryIndex].unit
//					_groupSummaryValue.includeGroupSeparator = self.formatFieldArray[_groupSummaryIndex].includeGroupSeparator
//					_groupSummaryValue.suffix = self.formatFieldArray[_groupSummaryIndex].suffix
//					_groupSummaryValue.suffixEnabled = self.formatFieldArray[_groupSummaryIndex].suffixEnabled
				}
			}
		})
		//groupSummary 구하기 끝
		
		//useWithQuery 구하기
		var useWithQuery = true;

		if(useWithQuery){
			$.each(_pivot.dataFields, function(i, field){
				if(field.summaryType != 'sum' && field.summaryType != 'custom'){
					useWithQuery = false;
					return false;
				}
			})
		}
		
		
		var reportLayout = {};
		if(WISE.Constants.editmode === 'viewer'){
			/*dogfoot 뷰어 레이아웃 값 없을때 오류 수정 shlim 20201008*/
			var reportLayoutCheck = typeof gDashboard.layoutConfig[WISE.Constants.pid] != 'undefined' && gDashboard.layoutConfig[WISE.Constants.pid] != "" && Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0 ?  true: false;

			if(reportLayoutCheck){
				if(typeof gDashboard.layoutConfig[WISE.Constants.pid]!='undefined' && gDashboard.layoutConfig[WISE.Constants.pid] !=""
					&& gDashboard.layoutConfig[WISE.Constants.pid] !="\"\"" && Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0){
                    reportLayout = gDashboard.layoutConfig[WISE.Constants.pid]
				}
			}else{
				if(typeof userJsonObject.layoutConfig != 'undefined' && userJsonObject.layoutConfig != ""){
                    reportLayout = userJsonObject.layoutConfig
				}
			}
		}else{
			var reportLayoutCheck = typeof gDashboard.layoutConfig != 'undefined' && gDashboard.layoutConfig != "" && Object.keys(gDashboard.layoutConfig).length != 0 ?  true: false;

			if(reportLayoutCheck){
				if(typeof gDashboard.layoutConfig != 'undefined' && gDashboard.layoutConfig != ""){
                    reportLayout = gDashboard.layoutConfig
				}
			}else{
				if(typeof userJsonObject.layoutConfig != 'undefined' && userJsonObject.layoutConfig != ""){
                    reportLayout = userJsonObject.layoutConfig
				}
			}
		}
		
	   var returnParams;
//	   if(_pivot.downloadParams){
//	       returnParams = _pivot.downloadParams;
//	   }else{
	       returnParams = {
				// Passing settings to the server
				paging: JSON.stringify(_pivot.pivotGridPagingOpt),
				group : group ? JSON.stringify(group) : "",
				filter : "",
				totalSummary : groupSummary ? JSON.stringify(groupSummary) : "",
				groupSummary : groupSummary ? JSON.stringify(groupSummary) : "",
				sqlLikeOption : JSON.stringify(sqlLikeOption),
				udfGroups : JSON.stringify(udfGroups),
				sortInfo : JSON.stringify(sortInfo),
				topBottom: JSON.stringify(_pivot.topBottomInfo),
				formatFieldArray : _pivot.formatFieldArray,
				useWithQuery: useWithQuery? 'Y' : 'N',
				reportLayout : reportLayout
		   }
//	   }
		
	   return returnParams
	},
	setPivotMeta: function(_pivot){
		// 피벗 세팅 시작
		if(_pivot.meta != undefined){
			_pivot.Pivot = _pivot.meta;
		}
		
		if(_pivot.fieldManager != null && _pivot.Pivot == undefined){
			_pivot.setPivot();
			gDashboard.itemGenerateManager.addParentItems(_pivot);
			gDashboard.itemGenerateManager.itemCustomize(_pivot,_pivot.Pivot);
			gDashboard.itemGenerateManager.generateItem(_pivot, _pivot.Pivot);
		}else if(_pivot.fieldManager != null && _pivot.Pivot){
			_pivot.setDataItems();
			if (_pivot.meta.InteractivityOptions == null) {
				_pivot.meta.InteractivityOptions = {
					MasterFilterMode: 'Off',
					IgnoreMasterFilters: false
				};
			}
			_pivot.queryState = false;
			gDashboard.itemGenerateManager.generateItem(_pivot, _pivot.meta);
		}
		else if(_pivot.fieldManager == null){
			_pivot.setDataItemsForViewer();
			gDashboard.itemGenerateManager.itemCustomize(_pivot,_pivot.meta);
			gDashboard.itemGenerateManager.generateItem(_pivot, _pivot.meta);
		}
	}


}