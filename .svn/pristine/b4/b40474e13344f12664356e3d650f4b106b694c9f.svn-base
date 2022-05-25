WISE.libs.Dashboard.ParameterQueryHandler = function() {
	var self = this;
	
	this.dataSources = {};
	this.parameterDataSet = {};
	this.parameterValues = {};
	
	this.elementBasket = [];
	
	this.setDataSourceInformations = function(_dataSources) {
		$.each(_dataSources, function(_i, _o) {
//			if (_o['DATASRC_TYPE'] === 'QUERY') {
				self.dataSources[_o['PARAM_NM']] = _o;
//			}
		});
		
		$.each(this.dataSources, function(_k0, _oe0) {
			var wiseVariables = _oe0['wiseVariables'];
			var variables = [];
			var datasources = _.clone(self.dataSources);
			
			$.each(datasources, function(_k1, _oe1) {
				var o = _.clone(_oe1);
				if ($.inArray(_k1, wiseVariables) != -1) {
					var dephaultValue = o['DEFAULT_VALUE'];
					$.each(WISE.Constants.conditions, function(_i, _v) {
						if (_v.key === o['PARAM_NM']) {
							dephaultValue = (_v.value + '').indexOf(',') > -1 ? (_v.value + '').split(',') : (_v.value + '');
							return false;
						}
					});
					if(o['PARAM_TYPE'] == 'CAND' && o['DEFAULT_VALUE'] == "[All]"){
						var DefaultDate = new Date();
						if(o['CAND_DEFAULT_TYPE'] == 'QUERY'){
							switch(_o['CAPTION_FORMAT']) {
							case 'yyyy':
							case 'yyyy년':
								DefaultDate = new Date(_o['DEFAULT_VALUE'].toString());
								break;
							case 'yyyyMM':
							case 'yyyy-MM':
							case 'yyyy년MM월':	
								DefaultDate = new Date(_o['DEFAULT_VALUE'].toString());
								break;
							case 'yyyy-MM-dd':
							case 'yyyy년MM월dd일':
								var parseDate = _o['DEFAULT_VALUE'].toString();
								var y =parseDate.substr(0,4),m = parseDate.substr(5,2)-1,d = parseDate.substr(8,2);
								DefaultDate = new Date(y,m,d);
								break;
							default:
								var parseDate = _o['DEFAULT_VALUE'].toString();
								var y =parseDate.substr(0,4),m = parseDate.substr(4,2)-1,d = parseDate.substr(6,2);
								DefaultDate = new Date(y,m,d);
								break;
							}
						}
						dephaultValue = DefaultDate.format(o['KEY_FORMAT']);
					}
					
					variables.push({
						name:_k1, 
						type: o['DATA_TYPE'], 
						defaultValue: dephaultValue,
						whereClause: o['WHERE_CLAUSE']
					});
				}
				//2020.02.12 mksong 비트윈 달력 파라미터 전달 오류 수정 dogfoot
				else{
					if (WISE.Constants.conditions.length != 0){
						$.each(WISE.Constants.conditions, function(_i, _v) {
							if (_v.key === _k0) {
								if(_oe0.OPER == "Between"){
									if(_v.value.indexOf(',')){
										_oe0.DEFAULT_VALUE = _v.value.split(',');
										_oe0.getDefault = true;
									}else{
										_oe0.DEFAULT_VALUE = _v.value;
									}
								}else{
									dephaultValue = _v.value;
									_oe0.DEFAULT_VALUE = _v.value;
								}
								return false;
							}
						});
						
					}
				}
			});
			_oe0.variables = variables;
		});
		
	};
	
	//2020.03.07 MKSONG 비동기 구현 위해 부분 함수 옵션으로 호출하도록 수정 DOGFOOT
	//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
	this.queryAll = function(_target, _parameterArray, queryView, _option, _editDataSet) {
		// @variable을 갖고 있지 않은 조회조건을 먼저 query
		if (_target === undefined) {
			if(_.keys(self.dataSources).length != 0){
				//2020.03.07 MKSONG 비동기 구현 위해 부분 함수 옵션으로 호출하도록 수정 DOGFOOT
				//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
				self.queryParameterAsynch(self.dataSources, _parameterArray, _target, queryView, _option, _editDataSet);	
			}
			else{
				if(WISE.Constants.editmode == 'designer'){
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
					if(WISE.Context.isCubeReport){
						if(_.keys(gDashboard.dataSetCreate.infoTreeList).length == 0){
							gDashboard.reportUtility.setDataSetInfo();
						}
					}else{
						gDashboard.reportUtility.setDataSetInfo();
					}
				}
			}
		} 
		else {
			var checkQueriedParameterName = []; // 쿼리된 item을 체크 하기 윈한 array
		
			// @variable을 갖고 있는 조회조건을 query
			$.each(this.dataSources, function(_k, _oe) {
				if ($.type(_oe.variables) === 'array' && _oe.variables.length > 0) {
					$.each(_oe.variables, function(_i0, _var) {
						var val = _.clone(_var);
						if(!self.parameterValues[val.name]) {
							
							self.parameterValues[val.name] = {
								value: [], 
								type: val.type, 
								defaultValue: val.defaultValue,
								whereClause: val.whereClause
							};
							
							if(val.defaultValue === '[All]') {
								/*var dataSet = self.parameterDataSet[val.name] || [];
								$.each(dataSet, function(_i1, _vo) {
									self.parameterValues[val.name].value.push(_vo.value || _vo.VALUE);
								});*/
								/* DOGFOOT ktkang [All] 일 경우 텍스트 전체로 나오도록 수정  20200705 */
								self.parameterValues[val.name].value = '전체';
							}
							else {
								if($.type(val.defaultValue) === 'array') {
									self.parameterValues[val.name].value = val.defaultValue;
								}
								else {
									self.parameterValues[val.name].value.push(val.defaultValue);
								}
								
							}
						} 
					});
					
					_oe.parameterValues = $.toJSON(self.parameterValues);
					var canQuery = false;
					$.each(_oe.variables, function(_i, _e) {
						if (_e.name == _target) {
							canQuery = true;
							return false;
						}
					})
					
					if (canQuery) {
						checkQueriedParameterName.push(_oe['PARAM_NM']);
						self.queryParameter(_oe);
						
					}
					
				}
			}); // end of @variable을 갖고 있는 조회조건을 query
			
			$.each(this.elementBasket, function(_i, _e) {
			
				var pid;
				if ($.type(_e) === 'string') {
					pid = _e.split(':')[0];
					var dxItem = _e.split(':')[1];
					_e = $('#' + pid)[dxItem]('instance');
				}
				
				var pnm = _e.option('wiseParamName');
				
				/* 쿼리된 item 아니면 데이터를 세팅하지 않는다. */
				if (checkQueriedParameterName.indexOf(pnm) == -1) {
					return true;
				}
				
				var KEY_COLUMN = _e.option('wiseKeyColumn');
				var CAPTION_COLUMN = _e.option('wiseCaptionColumn');
				var paramData = self.parameterDataSet[pnm];
				var comboData = $.map(paramData, function(_n, _i) {
					return _n[CAPTION_COLUMN]+'';
				});
	
				var dataSource = new DevExpress.data.DataSource({
					store: comboData,
					pageSize: self.CUSTOMIZED.get('datasource.list.pageSize')
				});
				
				_e.option('wiseQueriedData', comboData); // just for auto-complete
				_e.option('wiseParamData', paramData);
				var popoverid = pid + '_popover';
				var popover = $('#' + popoverid).dxList('instance');
				popover.option('dataSource', dataSource);
				//popover.selectAll();

				var defaultValue = self.dataSources[pnm].DEFAULT_VALUE;
				
				if(defaultValue){
					if(self.dataSources[pnm].MULTI_SEL === 'Y'){
						/* DOGFOOT ktkang [All] 일경우 전체 선택 되도록 수정  20200704 */
						if(defaultValue == '[All]') {
							popover.selectAll();
						} else {
							popover.selectItem(defaultValue);
						}
					}else{
						popover.selectItem(defaultValue[0]);
					}
					
				}
				
				/* combo textbox 초기화 */
				var selectedBasket = []; 
				$.each(dataSource.items(), function(_i, _v) {
					if (popover.isItemSelected(_v)) {
						selectedBasket.push(_v);
					}
				});
				if (selectedBasket.length == 0) {
					_e.option('value', '');
					WISE.libs.Dashboard.ConditionItem.selectedItems[pnm] = [];
				}
				else {
					_e.option('value', defaultValue);
					WISE.libs.Dashboard.ConditionItem.selectedItems[pnm] = defaultValue;
				}
			});
		}
	};

	//2020.03.06 mksong setCondition 함수화 dogfoot
	this.setCondition = function(_target){
		var checkQueriedParameterName = []; // 쿼리된 item을 체크 하기 윈한 array
		
		// @variable을 갖고 있는 조회조건을 query
		$.each(this.dataSources, function(_k, _oe) {
			if ($.type(_oe.variables) === 'array' && _oe.variables.length > 0) {
				$.each(_oe.variables, function(_i0, _var) {
					
					var val = _.clone(_var);
					if(!self.parameterValues[val.name]) {
						
						self.parameterValues[val.name] = {
							value: [], 
							type: val.type, 
							defaultValue: val.defaultValue,
							whereClause: val.whereClause
						};
						
						if(val.defaultValue === '[All]') {
							/*var dataSet = self.parameterDataSet[val.name] || [];
							$.each(dataSet, function(_i1, _vo) {
								self.parameterValues[val.name].value.push(_vo.value || _vo.VALUE);
							});*/
						}
						else {
							if($.type(val.defaultValue) === 'array') {
								self.parameterValues[val.name].value = val.defaultValue;
							}
							else {
								self.parameterValues[val.name].value.push(val.defaultValue);
							}
							
						}
					} 
				});
				
				_oe.parameterValues = $.toJSON(self.parameterValues);
				
				if (_target === undefined) {
					checkQueriedParameterName.push(_oe['PARAM_NM']);
					self.queryParameter(_oe);
				} 
				else {
					var canQuery = false;
					$.each(_oe.variables, function(_i, _e) {
						if (_e.name == _target) {
							canQuery = true;
							return false;
						}
					})
					
					if (canQuery) {
						checkQueriedParameterName.push(_oe['PARAM_NM']);
						self.queryParameter(_oe);
						
					}
//					else{

//					}
				}
				
			}
		}); // end of @variable을 갖고 있는 조회조건을 query
		
		$.each(this.elementBasket, function(_i, _e) {
			
			var pid;
			if ($.type(_e) === 'string') {
				pid = _e.split(':')[0];
				var dxItem = _e.split(':')[1];
				_e = $('#' + pid)[dxItem]('instance');
			}
			
			var pnm = _e.option('wiseParamName');
			
			/* 쿼리된 item 아니면 데이터를 세팅하지 않는다. */
			if (checkQueriedParameterName.indexOf(pnm) == -1) {
				return true;
			}
			
			var KEY_COLUMN = _e.option('wiseKeyColumn');
			var CAPTION_COLUMN = _e.option('wiseCaptionColumn');
			var paramData = self.parameterDataSet[pnm];
			var comboData = $.map(paramData, function(_n, _i) {
				return _n[CAPTION_COLUMN]+'';
			});

			var dataSource = new DevExpress.data.DataSource({
			    store: comboData,
			    pageSize: self.CUSTOMIZED.get('datasource.list.pageSize')
			});
			
			_e.option('wiseQueriedData', comboData); // just for auto-complete
			_e.option('wiseParamData', paramData);
			var popoverid = pid + '_popover';
			var popover = $('#' + popoverid).dxList('instance');
			popover.option('dataSource', dataSource);
			popover.selectAll();

			
			/* combo textbox 초기화 */
			var selectedBasket = []; 
	    	$.each(dataSource.items(), function(_i, _v) {
	    		if (popover.isItemSelected(_v)) {
	    			selectedBasket.push(_v);
	    		}
	    	});
	    	if (selectedBasket.length == 0) {
	    		_e.option('value', '');
				WISE.libs.Dashboard.ConditionItem.selectedItems[pnm] = [];
	    	}
	    	else {
	    		_e.option('value', selectedBasket.join(','));
				WISE.libs.Dashboard.ConditionItem.selectedItems[pnm] = selectedBasket;
	    	}
		});
	}
	
	//2020.03.06 mksong 필터 데이터 조회 비동기화 dogfoot
	//2020.03.07 MKSONG 비동기 구현 위해 부분 함수 옵션으로 호출하도록 수정 DOGFOOT
	//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
	this.queryParameterAsynch = function(_dataSources, _parameterArray, _target, queryView, _option, _editDataSet) {
		var checkValue = 0;
		var maxValue = _.keys(_dataSources).length;
		$.each(_dataSources, function(_k, _oe) {
			if (!_oe.variables || _oe.variables.length === 0) {
				var queryListTypeConditionData = function(_o, _callback) {
					var param = {};
					/* DOGFOOT ktkang 주제영역에서 필터 추가 시 프로그레스 바 오류 수정  20200308 */
					var cubeAddFilter = false;
					param.DS_ID = _o['DS_ID'];
					/* DOGFOOT ktkang 주제영역 필터 올리는 기능 오류 수정  20200212 */
					if(typeof _o['DS_TYPE'] != 'undefined' && _o['DS_TYPE'] != null) {
						param.DS_TYPE = _o['DS_TYPE'];
					/* DOGFOOT ktkang 주제영역 필터 올릴 때 데이터 타입 설정  20200309 */
					} else {
						param.DS_TYPE = _o['DATASRC_TYPE'];
					}
					param.PARAM_TYPE = _o['PARAM_TYPE'];
					param.DATASRC_TYPE = _o['DATASRC_TYPE'];
					param.DATASRC = _o['DATASRC'];
					param.KEY_VALUE_ITEM = _o['KEY_VALUE_ITEM'];
					param.CAPTION_VALUE_ITEM = _o['CAPTION_VALUE_ITEM'];
					param.SORT_TYPE = _o['SORT_TYPE'];
					param.parameterValues = _o['parameterValues'];
					param.LVL_QUERY = _o['CAND_PERIOD_VALUE'];
					param.SORT_VALUE_ITEM = _o['SORT_VALUE_ITEM'];
					param.tmp = _o;
					param.WHERE_CLAUSE = _o['WHERE_CLAUSE'];
					/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
					param.HIDDEN_VALUE = Base64.encode(_o['HIDDEN_VALUE']);
					param.DEFAULT_VALUE_USE_SQL_SCRIPT = _o['DEFAULT_VALUE_USE_SQL_SCRIPT'];
					/* DOGFOOT ktkang 주제영역 필터 데이터 권한 추가  20200806 */
					param.cubeId = 0;
					
					param.closYm = userJsonObject.closYm;
					param.userId = userJsonObject.userId;
					
					if(WISE.Context.isCubeReport) {
						$.each(gDashboard.datasetMaster.state.datasets, function(_i, _e) {
							param.cubeId = _e.DATASRC_ID;
						});
					}
						
					/* DOGFOOT ktkang 주제영역에서 필터 추가 시 프로그레스 바 오류 수정  20200308 */
					if(typeof _o['WISE_CUBE_UNI_NM'] != 'undefined') {
						cubeAddFilter = true;
					}
					
					var flag = false;
					var v = $.parseJSON(param.parameterValues || '{}');
					$.each(v, function(_k, _p) {
						flag = true;
						if(_p.value.length === 0) {
							_p.value.push('_EMPTY_VALUE_');
						}
					});
					
					if (flag) param.parameterValues = $.toJSON(v);
					
					$.ajax({
						cache: false,
						type: 'post',
						async: false,
						data: param,
						url: WISE.Constants.context + '/report/condition/queries.do',
						success: function(_data) {
							var ret = _data.data;
							self.parameterDataSet[_o['PARAM_NM']] = ret;
							
							if ($.type(_callback) === 'function') {
								_callback(ret, _o);
							}
							
							checkValue++;
							if(maxValue == checkValue){
								self.setCondition(_target);
								gDashboard.parameterFilterBar.setParameterArray(_parameterArray, queryView, _editDataSet);
								//2020.03.07 MKSONG 비동기 구현 위해 부분 함수 옵션으로 호출하도록 수정 DOGFOOT
								if(_option != undefined){
									_option();
								}
							}
							
							//기본값이 쿼리일경우 실행 후 결과를 DEFAULT_VALUE에 넣는다 
							if(param.DEFAULT_VALUE_USE_SQL_SCRIPT==='Y') {
								self.dataSources[_o['PARAM_NM']].DEFAULT_VALUE = _data.defaultValue
							}
						},
						error:function(error){

							WISE.alert('error'+ajax_error_message(error),'error');
							checkValue++;
							if(maxValue == checkValue){
								self.setCondition(_target);
								//2020.04.21 tbchoi 에러가 발생한 필터는 추가되지 않도록 삭제
								$.each(_parameterArray, function(_i, _d) {									
									if(_d.UNI_NM == _o.UNI_NM)
									_parameterArray.pop(_i);
									delete gDashboard.parameterFilterBar.parameterInformation[_o.UNI_NM];
								});								
								
								//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
								gDashboard.parameterFilterBar.setParameterArray(_parameterArray, queryView, _editDataSet);
								//2020.03.07 MKSONG 비동기 구현 위해 부분 함수 옵션으로 호출하도록 수정 DOGFOOT
								if(_option != undefined){
									_option();
								}
							}
//							WISE.alert(_data.responseJSON.message);
						}
					});
				};
				
				if ($.type(_oe) === 'object') {
					queryListTypeConditionData(_oe);
				}
				if ($.type(_oe) === 'array') {
					$.each(_oe, function(_i, _arr) {
						queryListTypeConditionData(_arr);
					})
				}		
			}else{
				checkValue++;
				if(maxValue == checkValue){
					self.setCondition(_target);
					//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
					gDashboard.parameterFilterBar.setParameterArray(_parameterArray, queryView, _editDataSet);
					//2020.03.07 MKSONG 비동기 구현 위해 부분 함수 옵션으로 호출하도록 수정 DOGFOOT
					if(_option != undefined){
						_option();
					}
				}
			}
		});
	};
	
	this.queryParameter = function(_o, _callback) {
		var queryListTypeConditionData = function(_o, _callback) {
			var param = {};
			/* DOGFOOT ktkang 주제영역에서 필터 추가 시 프로그레스 바 오류 수정  20200308 */
			var cubeAddFilter = false;
			param.DS_ID = _o['DS_ID'];
			/* DOGFOOT ktkang 주제영역 필터 올리는 기능 오류 수정  20200212 */
			if(typeof _o['DS_TYPE'] != 'undefined' && _o['DS_TYPE'] != null) {
				param.DS_TYPE = _o['DS_TYPE'];
			/* DOGFOOT ktkang 주제영역 필터 오류 수정  20200221 */
			} else {
				param.DS_TYPE = _o['DATASRC_TYPE'];
			}
			param.PARAM_TYPE = _o['PARAM_TYPE'];
			param.DATASRC_TYPE = _o['DATASRC_TYPE'];
			param.DATASRC = _o['DATASRC'];
			param.KEY_VALUE_ITEM = _o['KEY_VALUE_ITEM'];
			param.CAPTION_VALUE_ITEM = _o['CAPTION_VALUE_ITEM'];
			param.SORT_TYPE = _o['SORT_TYPE'];
			param.parameterValues = _o['parameterValues'];
			param.LVL_QUERY = _o['CAND_PERIOD_VALUE'];
			param.SORT_VALUE_ITEM = _o['SORT_VALUE_ITEM'];
			param.tmp = _o;
			param.WHERE_CLAUSE = _o['WHERE_CLAUSE'];
			/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
			param.HIDDEN_VALUE = Base64.encode(_o['HIDDEN_VALUE']);
			param.DEFAULT_VALUE_USE_SQL_SCRIPT = _o['DEFAULT_VALUE_USE_SQL_SCRIPT'];
			/* DOGFOOT ktkang 주제영역 필터 데이터 권한 추가  20200806 */
			param.cubeId = 0;
			
			param.closYm = userJsonObject.closYm;
			param.userId = userJsonObject.userId;
			
			if(WISE.Context.isCubeReport) {
				$.each(gDashboard.datasetMaster.state.datasets, function(_i, _e) {
					param.cubeId = _e.DATASRC_ID;
				});
			}
			
			/* DOGFOOT ktkang 주제영역에서 필터 추가 시 프로그레스 바 오류 수정  20200308 */
			if(typeof _o['WISE_CUBE_UNI_NM'] != 'undefined') {
				cubeAddFilter = true;
			}
			
			var flag = false;
			var v = $.parseJSON(param.parameterValues || '{}');
			$.each(v, function(_k, _p) {
				flag = true;
				if(_p.value.length === 0) {
					_p.value.push('_EMPTY_VALUE_');
				}
			});
			
			if (flag) param.parameterValues = $.toJSON(v);
			
			$.ajax({
				cache: false,
				type: 'post',
				async: false,
				data: param,
				url: WISE.Constants.context + '/report/condition/queries.do',
				success: function(_data) {
					var ret = _data.data;
					self.parameterDataSet[_o['PARAM_NM']] = ret;
					
					if ($.type(_callback) === 'function') {
						_callback(ret, _o);
					}
					
					//기본값이 쿼리일경우 실행 후 결과를 DEFAULT_VALUE에 넣는다 
					if(param.DEFAULT_VALUE_USE_SQL_SCRIPT==='Y') {
						self.dataSources[_o['PARAM_NM']].DEFAULT_VALUE = _data.defaultValue
					}
				},
				error:function(error){
					WISE.alert('error'+ajax_error_message(error),'error');
//					WISE.alert(_data.responseJSON.message);
				}
			});
		};
		
		if ($.type(_o) === 'object') {
			queryListTypeConditionData(_o, _callback);
		}
		if ($.type(_o) === 'array') {
			$.each(_o, function(_i, _oe) {
				queryListTypeConditionData(_oe);
			})
		}
	};
	
	this.setParameterValue = function(_param, _value) {
		var keyValues = [];
		if (self.parameterDataSet[_param.PARAM_NM]) {
			$.each(self.parameterDataSet[_param.PARAM_NM], function(i, val) {
				for (var j = 0; j < _value.length; j++) {
					if (_value[j] === val[_param.CAPTION_VALUE_ITEM]) {
						keyValues.push(val[_param.KEY_VALUE_ITEM]);
					} else if (_value[j] === val.CAPTION_VALUE) {
						keyValues.push(val.KEY_VALUE);
					}
				}
			});
		}
		if (!_.isEmpty(this.dataSources)) {
			if (!this.parameterValues[_param.PARAM_NM]) {
				var val = this.dataSources[_param.PARAM_NM];
				this.parameterValues[_param.PARAM_NM] = {
					value: [], 
					type: val['DATA_TYPE'], 
					defaultValue: val['DEFAULT_VALUE'], 
					whereClause: val['WHERE_CLAUSE']
				};
			}
			this.parameterValues[_param.PARAM_NM].value = keyValues;
		}
	};
};
