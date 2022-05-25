/**
 * 데이터집합 utility
 */
WISE.libs.Dashboard.item.DatasetUtility = {
	/**
     * Return param object that has a given map id.
	 * @param {string} mapid
     */
    generateParamObject: function(dsid, params) {
		var result = {};
		if (params.length > 0) {
			for (var i = 0; i < params.length; i++) {
				var paramName = params[i]['매개변수 명'];
				var param = gDashboard.parameterFilterBar.parameterInformation[paramName];
				if (param) {
					result[paramName] = _.clone(param);
				} else {
					result[paramName] = {
						DS_ID: dsid,
                        UNI_NM: paramName,
                        PARAM_NM: paramName,
                        PARAM_CAPTION: paramName.replace('@', ''),
                        DATA_TYPE: '',
                        PARAM_TYPE: '',
                        SEARCH_YN: 'N',
                        BIND_YN: 'N',
                        ORDER: params[i]['순서'],
                        WIDTH: 300,
                        VISIBLE: 'Y',
                        OPER: params[i]['조건'],
                        // "list" settings
                        DATASRC_TYPE: '',
                        DATASRC: '',
                        CAPTION_VALUE_ITEM: '',
                        KEY_VALUE_ITEM: '',
                        SORT_VALUE_ITEM: '',
                        SORT_TYPE: '',
                        DEFAULT_VALUE: '',
                        DEFAULT_VALUE_USE_SQL_SCRIPT: '',
                        MULTI_SEL: 'N',
                        ALL_YN : 'N',
                        WHERE_CLAUSE: '',
                        DEFAULT_VALUE_MAINTAIN: '',
                        // "between" settings
                        CAND_DEFAULT_TYPE: '',
                        /*dogfoot 캘린더 기간 설정 shlim 20210427*/
                        CAND_MAX_GAP:'0',
                        CAND_PERIOD_BASE: '',
                        CAND_PERIOD_VALUE: 0,
                        CAPTION_FORMAT: '',
                        HIDDEN_VALUE: '',
                        KEY_FORMAT: '',
                        RANGE_VALUE: '',
                        EDIT_YN: 'N',
                        LINE_BREAK: 'N',/*dogfoot shlim 20210415*/
                        RANGE_YN: 'N',
                        TYPE_CHANGE_YN: 'N'
					}
				}
			}
		}
		return result;
	},
	/**
     * Return param array that has a given datasource ID.
	 * @param {string} dsId
     */
    getParamByMapId: function(dsId) {
		var result = [];
		var datasets = gDashboard.datasetMaster.getState('DATASETS');
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		if (datasets[dsId] && typeof datasets[dsId].DATASET_QUERY != 'undefined'){
			/* DOGFOOT shlim 쿼리 매개변수 뒤에 붙는 특수문자 제거 20201216 */ 
			var matches = datasets[dsId].DATASET_QUERY.match(/@\S*/g);
			if (matches) {
				var matchesArray = [];
				$.each(matches, function(_i, _e) {
					//matchesArray.push(_e.toString().replace(/\(*\)*\,*\'*\"*/g, ''))
					//2020.12.31 mksong 쿼리 매개변수명, 붙은 경우 오류 수정 dogfoot
					var matchParam = _e.toString().replace(/\)/g, '');
					matchParam = matchParam.split(',')[0];
					matchesArray.push(matchParam.replace(/\(*\)*\,*\'*\"*/g, ''))
				});
				matchesArray = _.uniq(matchesArray);
				matchesArray.forEach(function(paramName) {
					var param = WISE.libs.Dashboard.item.DatasetUtility.getParamByParamName(paramName);
					if (param) {
						result.push(param);
					}
				});
			}
		}
        return result;
	},
	/**
     * Return param object that has a given parameter name.
     * @param {string} paramName 
     */
    getParamByParamName: function(paramName) {
		var params = gDashboard.datasetMaster.getState('PARAMS');
		var i = 0;
		while (i < params.length) {
			if (params[i].PARAM_NM === paramName) {
				return params[i];
			}
			i++;
		}
        return null;
	},
	/**
     * Return one of "In", "Between" and "Equals" according to param's prefixed string value.
     * @param {string} paramPrefixStr 
     */
    getParamType: function(paramPrefixStr) {
        switch (paramPrefixStr.toLowerCase()) {
            case 'in':
                return 'In';
            case 'between':
                return 'Between';
            default:
                return 'Equals';
        }
	},
	/**
	 * Return data row with paramName if it exists.
	 * Otherwise, return null.
	 * @param {object[]} data 
	 * @param {string} paramName 
	 */
	getParamInData : function(data, paramName) {
		for (var i = 0; i < data.length; i++) {
			if (data[i].PARAM_NM === paramName) {
				return data[i];
			}
		}
		return null;
	},
	/**
	 * Return a parameter information object grouped by parameter name.
	 * @param {object[]} params 
	 */
	generateNewParamValues: function(params) {
        var paramValues = {};
        params.forEach(function(param) {
			if (param.OPER === 'Between') {
				/* DOGFOOT ktkang 비트윈 달력 오류 수정  20200804 */
				var defaultValue = [];
				var defaultValue2 = param.DEFAULT_VALUE;
				if(param.DEFAULT_VALUE.toString() == "") {
					var periodBase = param['CAND_PERIOD_BASE'] ? param['CAND_PERIOD_BASE'].split(',') : ['DAY','DAY'];
					var periodValue = param['CAND_PERIOD_VALUE'] ? param['CAND_PERIOD_VALUE'].split(',') : [0,0];
					
					var formatString = param['KEY_FORMAT'];
					
					$.each(periodBase, function(_i, _e) {
						var dt = new Date();
						var varDate;
						
						switch(_e) {
						case 'YEAR':
							var yyyy;
							yyyy = dt.getFullYear() + Number(periodValue[_i]);	
							var mm = dt.getMonth();
							var dd = dt.getDate();
							varDate = new Date(yyyy, mm, dd);
							break;
						case 'MONTH':
							var yyyy = dt.getFullYear();
							var mm;
							mm = dt.getMonth();

							mm = mm + Number(periodValue[_i]);
							if (mm > 12) {
								yyyy = yyyy + parseInt(mm / 12, 10);
								mm = mm - 12;
							}
							var dd = dt.getDate();
							varDate = new Date(yyyy, mm,dd);
							break;
						default:
							var yyyy = dt.getFullYear();
							var mm = dt.getMonth()-1;
							var dd = dt.getDate() + Number(periodValue[_i]);		

							if(mm < 0 ) mm = 0;
								varDate = new Date(yyyy, mm, dd);
						}
						
						defaultValue.push(varDate);
					});
					defaultValue2 = [];
					defaultValue2.push(defaultValue[0].format(formatString));
					defaultValue2.push(defaultValue[1].format(formatString));
				}
				/* goyong ktkang 비트윈 리스트 오류 수정  20210527 */
				if(param.PARAM_TYPE == 'BETWEEN_LIST') {
					paramValues[param.PARAM_NM + '_fr'] = {
							uniqueName: param.PARAM_NM,
							name: param.PARAM_CAPTION + '_fr',
							paramName: param.PARAM_NM + '_fr',
							value: ['_EMPTY_VALUE_'],
							type: param.DATA_TYPE,
							defaultValue: defaultValue2,
							whereClause: param.WHERE_CLAUSE,
							parameterType: param.PARAM_TYPE,
							betweenCalendarValue: ['_EMPTY_VALUE_'],
							/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
							orgParamName: param.PARAM_NM,
							cubeUniqueName: param.UNI_NM,
							operation: param.OPER,
							captionName : param.CAPTION_VALUE_ITEM,
							keyName : param.KEY_VALUE_ITEM
					};
					paramValues[param.PARAM_NM + '_to'] = {
							uniqueName: param.PARAM_NM,
							name: param.PARAM_CAPTION + '_to',
							paramName: param.PARAM_NM + '_to',
							value: ['_EMPTY_VALUE_'],
							type: param.DATA_TYPE,
							defaultValue: defaultValue2,
							whereClause: param.WHERE_CLAUSE,
							parameterType: param.PARAM_TYPE,
							betweenCalendarValue: ['_EMPTY_VALUE_'],
							/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
							orgParamName: param.PARAM_NM,
							cubeUniqueName: param.UNI_NM,
							operation: param.OPER,
							captionName : param.CAPTION_VALUE_ITEM,
							keyName : param.KEY_VALUE_ITEM
					};
				} else {
					paramValues[param.PARAM_NM + '_fr'] = {
							uniqueName: param.PARAM_NM,
							name: param.PARAM_CAPTION + '_fr',
							paramName: param.PARAM_NM + '_fr',
							value: ['_EMPTY_VALUE_'],
							type: param.DATA_TYPE,
							defaultValue: defaultValue2,
							whereClause: param.WHERE_CLAUSE,
							parameterType: param.PARAM_TYPE,
							betweenCalendarValue: ['_EMPTY_VALUE_'],
							/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
							orgParamName: param.PARAM_NM,
							cubeUniqueName: param.UNI_NM,
							operation: param.OPER
					};
					paramValues[param.PARAM_NM + '_to'] = {
							uniqueName: param.PARAM_NM,
							name: param.PARAM_CAPTION + '_to',
							paramName: param.PARAM_NM + '_to',
							value: ['_EMPTY_VALUE_'],
							type: param.DATA_TYPE,
							defaultValue: defaultValue2,
							whereClause: param.WHERE_CLAUSE,
							parameterType: param.PARAM_TYPE,
							betweenCalendarValue: ['_EMPTY_VALUE_'],
							/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
							orgParamName: param.PARAM_NM,
							cubeUniqueName: param.UNI_NM,
							operation: param.OPER
					};
				}
			} else {
				if(param.PARAM_TYPE == 'CAND') {
					paramValues[param.PARAM_NM] = {
							uniqueName: param.PARAM_NM,
							name: param.PARAM_CAPTION,
							/*dogfoot 리스트 필터 쿼리일때 key caption 명 다르면 못찾는 오류 수정 shlim 20200728*/
							captionName : param.CAPTION_VALUE_ITEM,
							keyName : param.KEY_VALUE_ITEM,
							paramName: param.PARAM_NM,
							/*dogfoot 기본값 있는 보고서 불러올시 적용 안되는 오류 수정 shlim 20200716*/
							//2020.09.22 mksong dogfoot 연결보고서 캘린더 오류 수정
//						value: param.DEFAULT_VALUE_USE_SQL_SCRIPT =='N' && typeof param.DEFAULT_VALUE != "" && param.DEFAULT_VALUE != '[All]' ? [param.DEFAULT_VALUE]:['_EMPTY_VALUE_'],
							value: param.DEFAULT_VALUE,
							type: param.DATA_TYPE,
							defaultValue: param.DEFAULT_VALUE,
							whereClause: param.WHERE_CLAUSE,
							parameterType: param.PARAM_TYPE,
							betweenCalendarValue: ['_EMPTY_VALUE_'],
							/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
							orgParamName: param.PARAM_NM,
							cubeUniqueName: param.UNI_NM,
							operation: param.OPER
				};
				} else {
					paramValues[param.PARAM_NM] = {
							uniqueName: param.PARAM_NM,
							name: param.PARAM_CAPTION,
							/*dogfoot 리스트 필터 쿼리일때 key caption 명 다르면 못찾는 오류 수정 shlim 20200728*/
							captionName : param.CAPTION_VALUE_ITEM,
							keyName : param.KEY_VALUE_ITEM,
							paramName: param.PARAM_NM,
							/*dogfoot 기본값 있는 보고서 불러올시 적용 안되는 오류 수정 shlim 20200716*/
							//2020.09.22 mksong dogfoot 연결보고서 캘린더 오류 수정
//							value: param.DEFAULT_VALUE_USE_SQL_SCRIPT =='N' && typeof param.DEFAULT_VALUE != "" && param.DEFAULT_VALUE != '[All]' ? [param.DEFAULT_VALUE]:['_EMPTY_VALUE_'],
							value: param.DEFAULT_VALUE_USE_SQL_SCRIPT =='N' && typeof param.DEFAULT_VALUE != "" && param.DEFAULT_VALUE != '[All]' ? param.DEFAULT_VALUE:['_EMPTY_VALUE_'],
							type: param.DATA_TYPE,
							defaultValue: param.DEFAULT_VALUE,
							whereClause: param.WHERE_CLAUSE,
							parameterType: param.PARAM_TYPE,
							betweenCalendarValue: ['_EMPTY_VALUE_'],
							/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
							orgParamName: param.PARAM_NM,
							cubeUniqueName: param.UNI_NM,
							operation: param.OPER
						};
				}
			}
        });
        return paramValues;
	},
	/**
	 * Return an object version of given parameter array.
	 * If no argument is given, return an object version of params stored in DatasetMaster.
	 * @param {object} paramArray
	 */
	getParamObject: function(paramArray) {
		if ($.isPlainObject(paramArray)) {
			return _.cloneDeep(paramArray);
		}
		var result = {};
		var params = paramArray || gDashboard.datasetMaster.getState('PARAMS');
		params.forEach(function(param) {
			/* DOGFOOT ktkang 주제영역 필터 중복 오류 수정  20200705 */
			var paramId = param.UNI_NM == undefined ? param.PARAM_NM : param.UNI_NM;
			result[paramId] = param;
		});
		return result;
	},
	/**
	 * Return an array version of given parameter object.
	 * @param {object} paramObject
	 */
	getParamArray: function(paramObject) {
		if ($.isArray(paramObject)) {
			return _.cloneDeep(paramObject);
		}
		var result = [];
		$.each(paramObject, function(i, param) {
			/* dogfoot WHATIF 분석 매개변수 , 쿼리 매개변수 구분 shlim 20201022 */
			if(typeof param.CALC_PARAM_YN == "undefined"){
			    result.push(param);	
			}
		});
		return _.sortBy(result, 'ORDER');
	},
	/* dogfoot WHATIF 분석 매개변수 용 getArray 함수 추가 shlim 20201022 */
	getCalcParamArray: function(calcParamObject) {
		if ($.isArray(calcParamObject)) {
			return _.cloneDeep(calcParamObject);
		}
		var result = [];
		$.each(calcParamObject, function(i, param) {
			if(typeof param.CALC_PARAM_YN != "undefined"){
			    result.push(param);	
			}
		});
		return _.sortBy(result, 'ORDER');
	},
	/**
	 * Return an updated parameter list given updated dsId and data.
	 * @param {string} dsId
	 * @param {string} paramName 
	 */
	getUpdatedParameterList: function(dsId, updatedData) {
		var result = [];
		var datasets = gDashboard.datasetMaster.getState('DATASETS');
		result = updatedData;
		// datasets exist; update them accordingly
		if (!$.isEmptyObject(datasets)) {
			var resultSet = {};
			$.each(datasets, function(id) {
				if (id === dsId) {
					var formattedData = {};
					$.each(updatedData, function(i, param) {
						formattedData[param.PARAM_NM] = param;
					});
					$.extend(resultSet, formattedData);
				} else {
					var paramData = WISE.libs.Dashboard.item.DatasetUtility.getParamByMapId(id);
					$.each(paramData, function(i, param) {
						if (!resultSet[param.PARAM_NM]) {
							resultSet[param.PARAM_NM] = param;
						}
					});				
				}
			});
			$.each(resultSet, function(i, item) {
				result.push(item);
			});
		}
		return _.sortBy(_.uniq(result), 'ORDER');
	},
	/**
	 * Return true if dataset with name exists in DatasetMaster class.
	 * @param {object} dataset 
	 */
	datasetExists: function(dataset) {
		var found = false;
		$.each(gDashboard.datasetMaster.state.datasets, function(id, ds) {
			if (ds.mapid !== dataset.mapid && ds.DATASET_NM === dataset.DATASET_NM) {
				found = true;
				return false;
			}
		});
		return found;
	},
	/**
	 * Return a list of all existing dataset names.
	 */
	getDatasetNames: function() {
		var result = [];
		$.each(gDashboard.datasetMaster.state.datasets, function(id, dataset) {
			result.push(dataset.DATASET_NM);
		});
		return result;
	},
	/**
	 * Return a datasource id by its' dataset name.
	 * @param {string} datasetName 
	 */
	getMapIdByDatasetName: function(datasetName) {
		var result = null;
		$.each(gDashboard.datasetMaster.state.datasets, function(id, dataset) {
			if (dataset.DATASET_NM === datasetName) {
				result = id;
				return false;
			}
		});
		return result;
	},
	/**
	 * Return a datasource object for use with LAYOUT_XML
	 */
	getDatasourcesForLayoutXml: function() {
		var result = {
			DataSource: []
		};
		$.each(gDashboard.datasetMaster.getState('DATASETS'), function(id, dataset) {
			var fieldList = eval('gDashboard.customFieldManager.fieldInfo.'+id);
			if(!($.isEmptyObject(fieldList))) {
				result.DataSource.push({
					ComponentName: id,
					Name: dataset.DATASET_NM,
					CalculatedFields: {
						CalculatedField: fieldList
					}
				});
			} else {
				result.DataSource.push({
					ComponentName: id,
					Name: dataset.DATASET_NM
				});
			}
		});
		return result;
	},

	/**
	 * Generate info tree list for gDashboard.dataSetCreate class.
	 */
	generateInfoTreeList: function() {
		var result = {};
		$.each(gDashboard.datasetMaster.getState('FIELDS'), function(id, info) {
			//result[info.UNI_NM] = info;
			result[info[0].CAPTION] = info;
		});
		return result;
	},

	/**
	 * Generate lookup item info for gDashboard.dataSetCreate class.
	 */
	generateLookUpItems: function() {
		var result = [];
		$.each(gDashboard.datasetMaster.getState('DATASETS'), function(id, info) {
			result.push({
				mapid: id,
				DATASET_NM: info.DATASET_NM
			});
		});
		return result;
	},

	/**
	 * Generate param tree list info for gDashboard.dataSetCreate class.
	 */
	generateParamTreeList: function() {
		var result = {};
		$.each(gDashboard.datasetMaster.getState('DATASETS'), function(id, info) {
			/* DOGFOOT ktkang 매개변수 명이 한글 일 때 처리  20200706 */
			if(info.DATASET_QUERY) {
				var matches = info.DATASET_QUERY.match(/@\S*/g);
				if (matches) {
					var matchesArray = [];
					$.each(matches, function(_i, _e) {
						matchesArray.push(_e.toString().replace(/\)/g, ''))
					});
					result[id] = _.uniq(matchesArray);
				}
			}
		});
		return result;
	},

	/**
	 * Returns current parameter bar's stored values.
	 */
	getCurrentParamValues: function() {
		if (WISE.Constants.editmode === 'viewer') {
			var paramBar = gDashboard.viewerParameterBars[gDashboard.structure.ReportMasterInfo.id];
			if (paramBar) {
				return paramBar.getKeyParamValues();
			}

			return {};
		}
		
		return gDashboard.parameterFilterBar.getKeyParamValues();
	},

	/**
	 * Return a fake row of data using a dataset's metadata.
	 * @param {string} mapid 
	 */
	getMockData: function(mapid) {
		var result = [];
		var metadata = gDashboard.datasetMaster.getState('FIELDS')[mapid];
		if (metadata) {
			var data = {};
			for (var i = 1; i < metadata.length; i++) {
				if (metadata[i].DATA_TYPE === 'decimal') {
					data[metadata[i].UNI_NM] = Math.floor(Math.random() * Math.floor(100));
				} else {
					data[metadata[i].UNI_NM] = 'abc';
				}
			}
			result.push(data);
		}
		return result;
	},

	/**
	 * Return a "SELECT" clause list in DataSetDs format converted into DataSetCube format.
	 * @param {object[]} selectClauses
	 */
	convertSelectClauseToCubeFormat: function(selectClauses) {
		var result = [];
		WISE.util.Object.toArray(selectClauses).forEach(function(clause) {
			result.push({
				UNI_NM: clause.UNI_NM,
				CAPTION: clause.COL_CAPTION,
				DATA_TYPE: clause.DATA_TYPE.toUpperCase(),
				TYPE: clause.TYPE,
				ORDER: clause.ORDER,
			});
		});
		return result;
	},

	/**
	 * Return a "SELECT" clause list in DataSetCube format converted into DataSetDs format.
	 * @param {object[]} selectClauses
	 */
	convertSelectClauseToNonCubeFormat: function(selectClauses) {
		var result = [];
		var rx = /\[(.*)\].\[(.*)\]/;
		WISE.util.Object.toArray(selectClauses).forEach(function(clause) {
			var tblNm = '';
			var colNm = '';
			var matches = rx.exec(clause.UNI_NM);
			if (matches) {
				tblNm = matches[1];
				colNm = matches[2];
			}
			result.push({
				// TODO need to get aggregate type from database...
				UNI_NM: clause.UNI_NM,
				AGG: clause.DATA_TYPE.toUpperCase() === 'DECIMAL' ? 'Sum' : '',
				COL_NM: colNm,
				STRATIFIED_YN: false,
				COL_CAPTION: clause.CAPTION,
				DATA_TYPE: clause.DATA_TYPE.toLowerCase(),
				TBL_NM: tblNm,
				TBL_CAPTION: tblNm,
				TYPE: clause.TYPE,
				COL_EXPRESS: '',
				ORDER: clause.ORDER
			});
		});
		return result;
	},

	/**
	 * Return a "WHERE" clause list in DataSetDs format converted into DataSetCube format.
	 * @param {object[]} whereClauses
	 */
	convertWhereClauseToCubeFormat: function(whereClauses) {
		var result = [];
		WISE.util.Object.toArray(whereClauses).forEach(function(clause) {
			result.push({
				UNI_NM: clause.UNI_NM,
				CAPTION: clause.COL_CAPTION,
				OPER: clause.OPER,
				VALUES: clause.VALUES,
				VALUES_CAPTION: clause.VALUES_CAPTION,
				DATA_BIND_YN: clause.DATA_BIND_YN,
				AGG: clause.AGG,
				DATA_TYPE: clause.DATA_TYPE.toUpperCase(),
				PARAM_YN: clause.PARAM_YN,
				PARAM_NM: clause.PARAM_NM,
				TYPE: clause.TYPE,
				ORDER: clause.ORDER
			});
		});
		return result;
	},

	/**
	 * Return a "WHERE" clause list in DataSetCube format converted into DataSetDs format.
	 * @param {object[]} whereClauses
	 */
	convertWhereClauseToNonCubeFormat: function(whereClauses) {
		var result = [];
		var rx = /\[(.*)\].\[(.*)\]/;
		WISE.util.Object.toArray(whereClauses).forEach(function(clause) {
			var tblNm = '';
			var colNm = '';
			var matches = rx.exec(clause.UNI_NM);
			if (matches) {
				tblNm = matches[1];
				colNm = matches[2];
			}
			result.push({
				UNI_NM: clause.UNI_NM,
				COND_ID: 'A' + clause.ORDER,
				TBL_NM: tblNm,
				TBL_CAPTION: tblNm,
				COL_NM: colNm,
				COL_CAPTION: clause.CAPTION,
				OPER: clause.OPER,
				VALUES: clause.VALUES,
				VALUES_CAPTION: clause.VALUES_CAPTION,
				DATA_BIND_YN: clause.DATA_BIND_YN,
				AGG: clause.AGG,
				DATA_TYPE: clause.DATA_TYPE.toLowerCase(),
				PARAM_YN: clause.PARAM_YN,
				PARAM_NM: clause.PARAM_NM,
				TYPE: clause.TYPE,
				COL_EXPRESS: '',
				ORDER: clause.ORDER
			});
		});
		return result;
	},

	/**
	 * Return a "ORDER" clause list in DataSetDs format converted into DataSetCube format.
	 * @param {object[]} orderClauses
	 */
	convertOrderClauseToCubeFormat: function(orderClauses) {
		var result = [];
		WISE.util.Object.toArray(orderClauses).forEach(function(clause) {
			result.push({
				UNI_NM: clause.UNI_NM,
				CAPTION: clause.COL_CAPTION,
				SORT_TYPE: clause.SORT_TYPE,
				TYPE: clause.TYPE,
				ORDER: clause.ORDER,
			});
		});
		return result;
	},

	/**
	 * Return a "ORDER" clause list in DataSetCube format converted into DataSetDs format.
	 * @param {object[]} orderClauses
	 */
	convertOrderClauseToNonCubeFormat: function(orderClauses) {
		var result = [];
		var rx = /\[(.*)\].\[(.*)\]/;
		WISE.util.Object.toArray(orderClauses).forEach(function(clause) {
			var tblNm = '';
			var colNm = '';
			var matches = rx.exec(clause.UNI_NM);
			if (matches) {
				tblNm = matches[1];
				colNm = matches[2];
			}
			result.push({
				UNI_NM: clause.UNI_NM,
				TBL_NM: tblNm,
				TBL_CAPTION: tblNm,
				COL_NM: colNm,
				COL_CAPTION: clause.CAPTION,
				SORT_TYPE: clause.SORT_TYPE,
				TYPE: clause.TYPE,
				ORDER: clause.ORDER,
			});
		});
		return result;
	},

	/**
	 * Return a non-duplicate parameter for datasets made by table designer.
	 * @param whereClauses
	 */
	getWhereClauseId: function(whereClauses) {
		var highestNum = 0;
		var paramNames = _.map(whereClauses, function(val) {
			return '@' + val.COND_ID;
		});
		paramNames = paramNames.concat(
			_.map(gDashboard.datasetMaster.state.params, function(param) {
				return param.PARAM_NM;
			})
		);
		for (var i = 0; i < paramNames.length; i++) {
			var match = /^@A(\d*)$/.exec(paramNames[i]);
			if (match) {
				var paramNum = parseInt(match[1]);
				if (paramNum > highestNum) {
					highestNum = paramNum;
				}
			}
		}

		return 'A' + (highestNum + 1);
	},
	
	/**
	 * Return a non-duplicate parameter for calc parameter made by calc parameter handler
	 * @param calcParameterList
	 */
	/* dogfoot WHATIF 분석 매개변수 추가시 자동으로 ID 가져오는 부분 shlim 20201022 */
	getCalcParamId: function(calcParameterList) {
		var highestNum = 0;
		var paramNames = _.map(calcParameterList, function(val) {
			return val.PARAM_NM;
		});
		/* dogfoot WHATIF 데이터셋 매개변수와 중복되지 않도록 처리 shlim 20201022 */
		paramNames = paramNames.concat(
			_.map(gDashboard.datasetMaster.state.params, function(param) {
				return param.PARAM_NM;
			})
		);
		for (var i = 0; i < paramNames.length; i++) {
			var match = /^@A(\d*)$/.exec(paramNames[i]);
			if (match) {
				var paramNum = parseInt(match[1]);
				if (paramNum > highestNum) {
					highestNum = paramNum;
				}
			}
		}

		return 'A' + (highestNum + 1);
	},
	/**
	 * Returns current datasource id's stored values.
	 */
	getCurrentTableList: function(datasetName) {
		var result = [];
		$.each(gDashboard.datasetMaster.state.datasets, function(id, dataset) {
			if (dataset.DATASET_NM === datasetName && dataset.DATASET_TYPE === 'DataSetDs') {
				if($.isArray(dataset.SEL_CLAUSE)) {
					$.each(dataset.SEL_CLAUSE,function(i,d){
						result.push({
							dsid: d.DATASET_SRC||dataset.DATASET_SRC,
							tblnm: d.TBL_NM
						})
					});
				} else {
					result.push({
						dsid: dataset.SEL_CLAUSE.DATASET_SRC||dataset.DATASET_SRC,
						tblnm: dataset.SEL_CLAUSE.TBL_NM
					});
				}
				if($.isArray(dataset.FROM_CLAUSE)) {
					$.each(dataset.FROM_CLAUSE,function(i,d){
						result.push({
							dsid: d.FK_DATASET_SRC||dataset.DATASET_SRC,
							tblnm: d.FK_TBL_NM
						});
						result.push({
							dsid: d.PK_DATASET_SRC||dataset.DATASET_SRC,
							tblnm: d.PK_TBL_NM
						});
					});
				} else {
					result.push({
						dsid: dataset.FROM_CLAUSE.FK_DATASET_SRC||dataset.DATASET_SRC,
						tblnm: dataset.FROM_CLAUSE.FK_TBL_NM
					});
					result.push({
						dsid: dataset.FROM_CLAUSE.PK_DATASET_SRC||dataset.DATASET_SRC,
						tblnm: dataset.FROM_CLAUSE.PK_TBL_NM
					});
				}
				if($.isArray(dataset.WHERE_CLAUSE)) {
					$.each(dataset.WHERE_CLAUSE,function(i,d){
						result.push({
							dsid: d.DATASET_SRC||dataset.DATASET_SRC,
							tblnm: d.TBL_NM
						});
					});
				} else {
					result.push({
						dsid: dataset.WHERE_CLAUSE.DATASET_SRC||dataset.DATASET_SRC,
						tblnm: dataset.WHERE_CLAUSE.TBL_NM
					});
				}
				if($.isArray(dataset.ORDER_CLAUSE)) {
					$.each(dataset.ORDER_CLAUSE,function(i,d){
						result.push({
							dsid: d.DATASET_SRC||dataset.DATASET_SRC,
							tblnm: d.TBL_NM
						});
					});
				} else {
					result.push({
						dsid: dataset.ORDER_CLAUSE.DATASET_SRC||dataset.DATASET_SRC,
						tblnm: dataset.ORDER_CLAUSE.TBL_NM
					});
				}
				//delete duplication
				result = result.filter(function(arr, index, self){
					var findTblNm = _.findIndex(self,function(t){
						return t.dsid === arr.dsid && t.tblnm === arr.tblnm; 
					});
			    	return index === findTblNm;
				});
				return false;
			}
		});
		return result;
	},
			
}
