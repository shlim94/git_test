WISE.libs.Dashboard.QueryHandler = function() {
	var self = this;
	var dataSourceManager; // instance of WISE.libs.Dashboard.DataSourceManager
	var parameterFilterBar;

	this.dashboardid;

	this.init = function() {
		dataSourceManager = gDashboard.dataSourceManager;
		parameterFilterBar = gDashboard.parameterFilterBar;

	};
	this.resize = function() {

	}
	this.seachComplete = function() {

	};

	this.query = function(_itemGenerateManager, onlyQuery) {
		if (_.isEmpty(gDashboard.dataSourceManager.datasetInformation)) {
			WISE.alert('has no dataset information!');
			gProgressbar.hide();
			return;
		}

		var __CONFIG = WISE.widget.getCustom('common','Config');
		var manyDataMessageOnSearch = __CONFIG.message.search.manyData;

		var runQuery = true, hasEmptyValueOnListType = false;
		var condition = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
		if(gDashboard.isNewReport){
//			runQuery = false;
		}
		$.each(condition, function(_io, _co) {
			if (_co.mandatory) {
//				runQuery = false;
				WISE.alert(gMessage.get('WISE.message.page.condition.mandatory',[_co.name])); //은(는) 필수입력 항목 입니다.
				return false;
			}

			switch(_co.parameterType) {
			case 'CAND':
				if (_.indexOf(_co.value, 'null') > -1) {
//					runQuery = false;
					WISE.alert(gMessage.get('WISE.message.page.condition.date.invalid',[_co.name])); // 이(가) 날짜형식이 아닙니다.
					return false;
				}
				break;
			}

			if (manyDataMessageOnSearch && _co.parameterType === 'LIST') {
				if (_co.value.length == 1 && _co.value[0].indexOf("_EMPTY_VALUE_") > -1) {
					WISE.alert(gMessage.get('WISE.message.page.condition.mandatory',[_co.value]));
//					hasEmptyValueOnListType = true;
				}
			}

		});

//		if (runQuery) {
//			var performQuery = function() {
//				var queryComleteCount = 0;
//				var datasetCount = _.keys(dataSourceManager.datasetInformation).length;
//				$.each(_.keys(dataSourceManager.datasetInformation), function(_id, _ds) {
//					var datasetElement = dataSourceManager.datasetInformation[_ds];
//					var runnable = function() {
//						if (!datasetElement['mapid'] || datasetElement['mapid'] === 'undefined') {
//							queryComleteCount++;
//						}
//						else {
//							var param = {
//								'pid': WISE.Constants.pid,
//								'dsid': datasetElement['DATASRC_ID'],
//								'dstype' : datasetElement['DATASRC_TYPE'],
//								'mapid': _id,
//								'sqlid': datasetElement['wise_sql_id'],
//								'params': $.toJSON(condition),
//								'userId':userJsonObject.userId
//							};
//							$.ajax({
//								type : 'post',
//								data : param,
//								cache : false,
//								url : WISE.Constants.context + '/report/queries.do',
//								beforeSend: function() {
//									gProgressbar.show();
//								},
//								complete: function() {
//									if ((++queryComleteCount) === datasetCount) {
//										gProgressbar.hide();
//									}
//								},
//								success : function(_dataSet) {
//									_itemGenerateManager.bindData(_dataSet);
//								},
//								error : function(error){
//									WISE.alert('error'+ajax_error_message(error),'error');
//								}
//							});
//						}
//					}; // end of runnable
//
//					if (WISE.libs.Dashboard.Config.debug) {
//						runnable();
//					}
//					else {
//						try {
//							runnable();
//						}
//						catch (e) {
//							var msg = 'error occurred while querying UI data - ' + e.toString();
//							mst += ' - id : ' + datasetElement['DATASRC_ID'] + ', query : ' + datasetElement['DATASET_QUERY'] + ', params : ' + $.toJSON(condition);
//							throw {status: 500, msg: msg};
//						}
//					}
//
//				}); // end of $.each
//			}; // end of performQuery
//
//			if (hasEmptyValueOnListType) {
//				var options = {
//					buttons: {
//						confirm: {
//							id: 'confirm',
//							className: 'blue',
//							text: '확인',
//							action: function() {
//								Apprise('close');
//								performQuery();
//							}
//						},
//						cancel: {
//							id: 'cancel',
//							className: 'red',
//							text: '취소',
//							action: function() { Apprise('close'); }
//						}
//					}
//				};
//			    WISE.alert(gMessage.get('WISE.message.page.search.empty.list.value'), options);
//			}
//			else {
//				performQuery();
//			}
//
//		} // end of if (runQuery)
		if (runQuery) {
			var itemLength = gDashboard.itemGenerateManager.dxItemBasten.length;
			for(var i=0; i<itemLength; i++){
				var type = gDashboard.itemGenerateManager.dxItemBasten[i].type;
				if(type == 'PIVOT_GRID'){
					// jhseo 조회할때는 피벗그리드 페이지 인덱스가 1로 나오게 하기 위함
					gDashboard.itemGenerateManager.dxItemBasten[i].curPageIdx = 1;
					gDashboard.itemGenerateManager.isDirectExportBtn = false;			// 피벗그리드 데이터 그리드 다운로드 버튼 바로보기 초기화
				}
				else if(type == 'DATA_GRID'){
					gDashboard.itemGenerateManager.isDirectExportBtn = false;	
				}
			}
			
			/* DOGFOOT ktkang 쿼리 시작 시 로딩바  20200120 */
			gProgressbar.show();
			/* dogfoot 비정형 주제영역 데이터 row 건수 제한 팝업창 여러번 나오는 오류 수정  shlim 20210322 */
			gDashboard.searchLimitCount = 0;
			gDashboard.openCanceled = false;
			$('#queryCancel').dxButton({
				text:"작업 취소",
				type:'default',
				onClick:function(_e){
					//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
					gProgressbar.setStopngoProgress(true);
					gProgressbar.hide();
					$.ajax({
						type : 'post',
						cache : false,
						async: false,
						url : WISE.Constants.context + '/report/cancelqueries.do',
						complete: function(_e) {
							gProgressbar.cancelQuery();
//							gProgressbar.hide();
						}
					});
				}
			});
			/* 개발 cshan 1211
			 *  줄맞춤
			 *  */
			/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
			var cubeAdhocPerformQuery = function() {
				var DU = WISE.libs.Dashboard.item.DataUtility;
				var DCU = WISE.libs.Dashboard.item.DataCubeUtility;
				var ReportMeta = gDashboard.structure.ReportMasterInfo;
				var selectedDsId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByField();
				WISE.Context.isCubeReport = true;

				//2020.02.13 mksong 프로그레스바 작업취소 최적화 dogfoot
				gProgressbar.show();
				$('#queryCancel').dxButton({
					text:"작업 취소",
					type:'default',
					onClick:function(_e){
						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
						gProgressbar.setStopngoProgress(true);
						gProgressbar.hide();
						$.ajax({
							type : 'post',
							cache : false,
							async: false,
							url : WISE.Constants.context + '/report/cancelqueries.do',
							complete: function(_e) {
								gProgressbar.cancelQuery();
//								gProgressbar.hide();
							}
						});
					}
				});

				$.each(gDashboard.dataSourceManager.datasetInformation, function(dsId, ds) {
					var params = $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues());
					/* DOGFOOT ktkang 주제영역 비트윈달력 오류 수정  20200810 */
					var betweenParam = {};
					var paramName = '';
					var betweenValue = [];
					$.each(JSON.parse(params), function(_i, _e) {
						if(_e.operation == 'Between' && _e.name.indexOf('_fr')) {
							betweenParam[_e.uniqueName] = {
									uniqueName: _e.uniqueName,
									name: _e.name.replace('_fr', ''),
									/*dogfoot 리스트 필터 쿼리일때 key caption 명 다르면 못찾는 오류 수정 shlim 20200728*/
									captionName : _e.captionName,
									keyName : _e.keyName,
									paramName: _e.paramName.replace('_fr', ''),
									/*dogfoot 기본값 있는 보고서 불러올시 적용 안되는 오류 수정 shlim 20200716*/
									value: _e.value,
									type: _e.type,
									defaultValue: _e.defaultValue,
									whereClause: _e.whereClause,
									parameterType: _e.parameterType,
									betweenCalendarValue: _e.betweenCalendarValue,
									/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
									orgParamName: _e.orgParamName,
									cubeUniqueName: _e.cubeUniqueName,
									operation: _e.operation
							};
							betweenValue.push(_e.value);
							paramName = _e.uniqueName;
						} else if(_e.operation == 'Between' && _e.name.indexOf('_to')) {
							betweenValue.push(_e.value);
						} else {
							betweenParam[_e.uniqueName] = _e;
						}
					});
					if(paramName != '') {
						betweenParam[paramName].value = betweenValue;
						params = JSON.stringify(betweenParam);
					}
					var param = {
						dsid: ds.DATASRC_ID,
						dsnm: ds.DATASET_NM,
						dstype: 'CUBE',
						params: params,
						sqlTimeout: userJsonObject.searchLimitTime,
						skipQuery: "",
						schId: undefined,
						mapid: dsId,
						/* DOGFOOT ktkang SQL 로그 추가  20200721 */
						reportType: gDashboard.reportType,
						userId : userJsonObject.userId
					};
					var G = [];
					var R = [];
					var C = [];
					var D = [];
					var DS = [];
					var HD = [];
					var selected = {dim:[],mea:[]};
					// 조회
					if (gDashboard.queryByGeneratingSql) {
						gDashboard.fieldManager.getherFields(gDashboard.fieldManager);

						var DS;
						R = gDashboard.fieldManager['Rows'] ? gDashboard.fieldManager['Rows']['Row'] : [];
						C = gDashboard.fieldManager['Columns'] ? gDashboard.fieldManager['Columns']['Column'] : [];
						D = gDashboard.fieldManager['Values'] ? gDashboard.fieldManager['Values']['Value'] : [];
						//2020.02.13 mksong 비정형 주제영역 정렬 컬럼 추가 dogfoot
						HM = gDashboard.fieldManager['HiddenMeasures'] ? gDashboard.fieldManager['HiddenMeasures']['Measure'] : [];
						HD = gDashboard.fieldManager['HiddenMeasures'] ? gDashboard.fieldManager['HiddenMeasures']['Dimension'] : [];

						// rows
						_.each(R, function(_R) {
							selected.dim.push({uid:_R.cubeUniqueName});
						});

						// columns
						_.each(C, function(_C) {
							selected.dim.push({uid:_C.cubeUniqueName});
						});

						// datas
						_.each(D, function(_D) {
							selected.mea.push({uid:_D.cubeUniqueName});
						});

						/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */
						_.each(HM, function(_HM) {
							selected.mea.push({uid:_HM.cubeUniqueName});
						});

						/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */
						_.each(HD, function(_HD) {
							selected.dim.push({uid:_HD.cubeUniqueName});
						});
						
						var fields = new Array();
						var fieldNames = new Array();
						$.each(gDashboard.customFieldManager.fieldInfo[dsId], function(_ii, _custom) {
							fields = fields.concat(gDashboard.customFieldManager.trackingDatafields(_custom));
							fieldNames.push(_custom.Name);
						});
						
						var dupleFields = new Array();
						$.each(fields, function(key, value) {
							if($.inArray(value, dupleFields) === -1 && $.inArray(value, fieldNames) === -1) return dupleFields.push(value);
						});
						
						gDashboard.customFieldManager.fieldNameList = dupleFields;
						
						$.each(fields, function(_ii, _custom) {
							$.each(gDashboard.customFieldManager.originalFieldInfo, function(_iii, _ofi) {
								if(_ofi.CAPTION == _custom) {
									if(selected.mea.map(function(d) {return d['uid']}).indexOf(_ofi.CUBE_UNI_NM) == -1) {
										selected.mea.push({uid:_ofi.CUBE_UNI_NM});
									}
								}
							});
						});
					}
					// 불러오기
					else {
						/* DOGFOOT ktkang 주제영역 데이터 불러오기 기능 수정  20191212 */
						G = ReportMeta['reportJson']['GRID_ELEMENT'] ? WISE.util.Object.toArray(ReportMeta['reportJson']['GRID_ELEMENT']['GRID']) : [];
						R = ReportMeta['reportJson']['ROW_ELEMENT'] ? WISE.util.Object.toArray(ReportMeta['reportJson']['ROW_ELEMENT']['ROW']) : [];
						C = ReportMeta['reportJson']['COL_ELEMENT'] ? WISE.util.Object.toArray(ReportMeta['reportJson']['COL_ELEMENT']['COL']) : [];
						D = ReportMeta['reportJson']['DATA_ELEMENT'] ? WISE.util.Object.toArray(ReportMeta['reportJson']['DATA_ELEMENT']['DATA']) : [];
						DS = ReportMeta['reportJson']['DATASORT_ELEMENT'] ? WISE.util.Object.toArray(ReportMeta['reportJson']['DATASORT_ELEMENT']['DATA_SORT']) : [];
						// rows
						_.each(R, function(_R) {
							var member = DCU.getRowMember(_R, G);
							// _.each(DS, function(_DSR) {
							// 	if(_DSR['SORT_FIELD_NM'] === member['CAPTION'] )
							// 	{
							// 		if (_DSR['BASE_FIELD_NM'].lastIndexOf('_K') > -1)
							// 		{
							// 			selected.dim.push({uid: WISE.Context.isCubeReport ? (member.isCCF ? member['CAPTION'] : member['UNI_NM']) : member['CAPTION']});
							// 		}
							// 	}
							// });
//							if (member['VISIBLE'] === 'Y') {
								selected.dim.push({uid: WISE.Context.isCubeReport ? (member.isCCF ? member['CAPTION'] : member['UNI_NM']) : member['CAPTION']});
//							}
						});
						// columns
						_.each(C, function(_C) {
							var member = DCU.getColumnMember(_C, G);
//							if (member['VISIBLE'] === 'Y') {
								selected.dim.push({uid: WISE.Context.isCubeReport ? (member.isCCF ? member['CAPTION'] : member['UNI_NM']) : member['CAPTION']});
//							}
						});
						// datas
						_.each(D, function(_D) {
							var member = DCU.getDataMember(_D, G);
//							if (member['VISIBLE'] === 'Y') {
								if(!member['FLD_NM'].indexOf('DELTA') > -1 && member['UNI_NM'] != undefined){
									selected.mea.push({uid: WISE.Context.isCubeReport ? (member.isCCF ? member['CAPTION'] : member['UNI_NM']) : member['CAPTION']});
								}

//							}
						});

						/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */
						_.each(DS, function(_DS) {
							if((_DS.BASE_FIELD_NM != undefined && _DS.BASE_FIELD_NM != "") || (_DS.BASE_FLD_NM != undefined && _DS.BASE_FLD_NM != "")){
								var member = DCU.getCubeSortMember(_DS, G);
								selected.dim.push({uid: WISE.Context.isCubeReport ? member['UNI_NM'] : member['CAPTION']});
							}
						});

						var fields = new Array();
						var fieldNames = new Array();
						$.each(gDashboard.customFieldManager.fieldInfo[dsId], function(_ii, _custom) {
							fields = fields.concat(gDashboard.customFieldManager.trackingDatafields(_custom));
							fieldNames.push(_custom.Name);
						});
						
						var dupleFields = new Array();
						$.each(fields, function(key, value) {
							if($.inArray(value, dupleFields) === -1 && $.inArray(value, fieldNames) === -1) return dupleFields.push(value);
						});
						
						gDashboard.customFieldManager.fieldNameList = dupleFields;
						
						$.each(fields, function(_ii, _custom) {
							$.each(gDashboard.customFieldManager.originalFieldInfo, function(_iii, _ofi) {
								if(_ofi.CAPTION == _custom) {
									if(selected.mea.map(function(d) {return d['uid']}).indexOf(_ofi.CUBE_UNI_NM) == -1) {
										selected.mea.push({uid:_ofi.CUBE_UNI_NM});
									}
								}
							});
						});
						
						//중복제거
						selected.dim = _.uniqBy(selected.dim,'uid');
						selected.mea = _.uniqBy(selected.mea,'uid');

						var datafilterElements = ReportMeta['reportJson']['DATAFILTER_ELEMENT'];
						if (!_.isEmpty(datafilterElements)) {
							var dataFilters = WISE.util.Object.toArray(datafilterElements['DATA_FILTER']);
							param.filters = $.toJSON(dataFilters)
						}
						var subQueryElements = ReportMeta['reportJson']['SUBQUERY_ELEMENT'];
						if (!_.isEmpty(subQueryElements)) {
							var subQuery = WISE.util.Object.toArray(subQueryElements);
							param.subquery = $.toJSON(subQuery)
						}

						gDashboard.queryByGeneratingSql = false;
					}
					param.cols = $.toJSON(selected);

					if(onlyQuery){
                        param.onlyQuery = true;
					}else {
						param.onlyQuery = false;
					}

					/* DOGFOOT ktkang 주제영역 측정값 없을 시 조회 불가하도록 수정  20200308 */
					if(selected.mea.length < 1) {
						WISE.alert('측정값을 1개 이상 올려야 조회가 가능합니다.');
						gProgressbar.hide();
						return false;
					}
					// 쿼리
					
					if(!gDashboard.checkQueriesDoParamSame(WISE.Constants.pid,dsId,param)){
						gDashboard.setQueriesDoParam(WISE.Constants.pid,dsId,param);	
						$.ajax({
							type : 'post',
							data : param,
							/* DOGFOOT ktkang 작업 취소 기능 구현  20200923 */
							async: false,
							url : WISE.Constants.context + '/report/cube/queries.do',
							success : function(_dataSet) {
								gDashboard.queriesDoDataSet = _dataSet;
								/*dogfoot 비정형 주제영역 데이터 안가져오도록 수정 shlim 20210728*/
								// 2020.01.16 mksong 데이터 건수 많을 경우 경고창 띄우기 dogfoot
	//							if(userJsonObject.goyongList.indexOf(WISE.Constants.pid) < 0) {
	//								/*dogfoot 피벗그리드 조회후 다운로드 바로 되게 처리 shlim 20210727*/
	////								if(userJsonObject.searchLimitRow > 0 && _dataSet.dataLength > userJsonObject.searchLimitRow){
	//								if(_dataSet.dataLength >= 3000 || (userJsonObject.searchLimitRow > 0 && _dataSet.dataLength > userJsonObject.searchLimitRow)){
	//									/* dogfoot 비정형 주제영역 데이터 row 건수 제한 팝업창 여러번 나오는 오류 수정  shlim 20210322 */
	//									if(gDashboard.searchLimitCount == 0){
	//										gDashboard.searchLimitCount++;
	//										var confirmValue = window.confirm("데이터 조회 건수가 많아 브라우저 다운 현상이 발생할 수 있습니다. 계속 조회하시겠습니까? (필터를 변경 후 조회하시길 권장합니다.)");
	////										var confirmValue = window.confirm("데이터 조회 건수가 많아 브라우저에 부하가 발생 할 수 있습니다.\n 조회 후 다운로드를 진행 하시겠습니까?");
	//										if(!confirmValue){
	//											gProgressbar.hide();
	//											return false;
	//										}
	//									}
	//								}
	//							}
								/* DOGFOOT hsshim 2020-02-06 조회 할때마다 globalData가 overwrite 되게 수정 */
	//							if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && (typeof _itemGenerateManager.focusedItem.calculatedFields != 'undefined' && _itemGenerateManager.focusedItem.calculatedFields.length > 0)) {
	//								var fieldList = gDashboard.customFieldManager.fieldInfo[dsId];
	//								if (fieldList) {
	//									fieldList.forEach(function(field) {
	//										gDashboard.customFieldManager.addCustomFieldsToDataSource(field, _dataSet.data, _itemGenerateManager.focusedItem.calculatedFields);
	//									});
	//								}
	//							}
								/* DOGFOOT ktkang 주제영역 데이터 불러오기 기능 수정  20191212 */
								gDashboard.dataSourceManager.datasetInformation[dsId].data = _dataSet.data;
								gDashboard.dataSourceManager.datasetInformation[dsId].DATASRC_ID = _dataSet.dataSrcId;
								gDashboard.dataSourceManager.datasetInformation[dsId].DATASRC_TYPE = 'CUBE';
								gDashboard.dataSourceManager.datasetInformation[dsId].DATASET_TYPE = '';
								/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
								gDashboard.dataSourceManager.datasetInformation[dsId].SQL_QUERY = Base64.decode(_dataSet.sql);
								if(onlyQuery){
									gProgressbar.setStopngoProgress(true);
									gProgressbar.hide();
									return;
								}
								if (selectedDsId === dsId) {

									_itemGenerateManager.bindData(_dataSet, null, true);
									_itemGenerateManager.dxItemBasten[1].showQuery = Base64.decode(_dataSet.sql);

								}


								/* DOGFOOT hsshim 2020-02-06 끝 */
							},
							error:function(_response){

								WISE.alert('error'+ajax_error_message(_response),'error');
	//							if(_e.status == 930){
	//								WISE.alert('조회 시간이 초과되었거나 중단을 눌르셨습니다!', 'error');
	//							} else {
	//								WISE.alert('조회 실패 했습니다.', 'error');
	//							}
							},
							complete: function() {
								//gProgressbar.hide();
							}
						});
					}else{
						if (selectedDsId === dsId) {
                            if(onlyQuery){
								gProgressbar.setStopngoProgress(true);
								gProgressbar.hide();
								return;
							}
							_itemGenerateManager.bindData(gDashboard.queriesDoDataSet, null, true);
							//_itemGenerateManager.dxItemBasten[1].showQuery = Base64.decode(_dataSet.sql);
						}
					}
				});
			};
			/* DOGFOOT hsshim 2020-01-15 끝 */
			/* DOGFOOT ktkang 사용안하는 부분 주석  20200706 */
//			var cubePerformQuery = function(){
//				// 2020.01.16 mksong 작업 취소 문구 처음부터 보이도록 수정 dogfoot
//				/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
//				var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(gDashboard.structure.ReportMasterInfo.cube_nm);
//				/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
//				var params = $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues());
//				var param = {
//					/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
//					'query' : gDashboard.dataSourceManager.datasetInformation[dataSrcId].SQL_QUERY,
//					'dsid' : gDashboard.dataSourceManager.datasetInformation[dataSrcId].DATASRC_ID,
//					'dstype' : gDashboard.dataSourceManager.datasetInformation[dataSrcId].DATASRC_TYPE,
//					'params' : params,
//					'pid' : undefined,
//					'reportNm' : gDashboard.structure.ReportMasterInfo.name,
//					'skipQuery': "",
//					'schId' : undefined,
//					'subquery' : $.toJSON(gDashboard.structure.ReportMasterInfo.subquery.SUB_QUERY),
//					'userId' : userJsonObject.userId
//				}
//
//				$.ajax({
//					type : 'post',
//					data : param,
//					url : WISE.Constants.context + '/report/datasetcube/queries.do',
//					success : function(_dataSet) {
//						// 2020.01.16 mksong 데이터 건수 많을 경우 경고창 띄우기 dogfoot
//						if(userJsonObject.searchLimitRow > 0 && _dataSet.data.length > userJsonObject.searchLimitRow){
//							var confirmValue = window.confirm("데이터 조회 건수가 많아 브라우저 다운 현상이 발생할 수 있습니다. 계속 조회하시겠습니까? (필터를 변경 후 조회하시길 권장합니다.)");
//							if(!confirmValue){
//								gProgressbar.hide();
//								return false;
//							}
//						}
//						/* DOGFOOT hsshim 2020-02-06 조회 할때마다 globalData가 overwrite 되게 수정 */
//						if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
//							/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
//							var fieldList = gDashboard.customFieldManager.fieldInfo[dataSrcId];
//							if (fieldList) {
//								fieldList.forEach(function(field) {
//									gDashboard.customFieldManager.addCustomFieldsToDataSource(field, _dataSet.data);
//								});
//							}
//						}
//						/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
//                        gDashboard.dataSourceManager.datasetInformation[dataSrcId].data = _dataSet.data;
//						_itemGenerateManager.bindData(_dataSet, null, true);
//						gProgressbar.hide();
//						/* DOGFOOT hsshim 2020-02-06 끝 */
//					},
//					error:function(_e){
//						gProgressbar.hide();
//						WISE.alert('error'+ajax_error_message(_e),'error');
////						if(_e.status == 930){
////							var options = {
////								buttons: {
////									confirm: {
////										id: 'confirm',
////										className: 'blue',
////										text: '확인',
////										action: function() {
////											Apprise('close');
////											return false;
////										}
////									}
////								}
////							};
////							WISE.alert('조회 시간이 초과되었거나 중단을 눌르셨습니다!', options);
////						}
//					}
//				});
//			};
			/* DOGFOOT hsshim 200103
 			 * 스프레드 집합 조회 기능 개선
 			 */
			var spreadPerformQuery = function(_id, _ds) {

				$('#queryCancel').dxButton({
					//2019.12.26 mksong 취소 문구 수정 dogfoot
					text:"작업 취소",
					type:'default',
					onClick:function(_e){
						$.ajax({
							type : 'post',
							cache : false,
							async: false,
							url : WISE.Constants.context + '/report/cancelqueries.do',
							/* DOGFOOT hsshim 2020-02-13 최소시 조회 중지 전에 progressbar 없세게 수정 */
							beforeSend: function() {
								gProgressbar.cancelQuery();
								gProgressbar.hide();
							},
						});
					}
				});

				var datasetCount = _.keys(dataSourceManager.datasetInformation).length;
				if(datasetCount == 0){
					_itemGenerateManager.bindData([], null, false);
					return false;
				}

				/* DOGFOOT hsshim 2020-01-13 필요없는 스프레드 기능 제거 */
				var param = {
						'pid': WISE.Constants.pid,
						'dsid': _ds['DATASRC_ID'],
						'dstype' : _ds['DATASRC_TYPE'],
						'reportType' : gDashboard.reportType,
						'fldType' : (gDashboard.reportUtility.reportInfo) ? gDashboard.reportUtility.reportInfo.ReportMasterInfo.fld_type : gDashboard.structure.ReportMasterInfo.fld_type,
						'mapid': _id,
						'sqlid': _ds['wise_sql_id'],
						/* DOGFOOT ktkang 스프레드 시트 필터 오류 수정  20200703 */
						'params': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues()),
						'userId':userJsonObject.userId,
						/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
						/* DOGFOOT ajkim 쿼리 암호화 수정  20200730 */
						'sql_query_nosqlid': Base64.encode(_ds['DATASET_QUERY']||_ds['SQL_QUERY']),
						'sqlTimeout':userJsonObject.searchLimitTime,
						'tbllist': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentTableList(_ds['DATASET_NM'])),
						// 2021-07-16 yyb 조회 속도개선 관련 처리
						'rptNm': (gDashboard.reportUtility.reportInfo) ? gDashboard.reportUtility.reportInfo.ReportMasterInfo.name : gDashboard.structure.ReportMasterInfo.name
				};

				$.ajax({
					type : 'post',
					data : param,
					cache : false,
					async : false,
					url : WISE.Constants.context + '/report/queries.do',
					beforeSend: function() {
						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
						gProgressbar.show();
					},complete: function() {
//						if ((++queryComleteCount) === datasetCount) {
//						gProgressbar.hide();
//						}
					},
					success : function(_dataSet) {
							/* DOGFOOT hsshim 2020-02-06 조회 할때마다 globalData가 overwrite 되게 수정 */
							if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
								var fieldList = gDashboard.customFieldManager.fieldInfo[_dataSet.mapid];
								if (fieldList) {
									fieldList.forEach(function(field) {
										gDashboard.customFieldManager.addCustomFieldsToDataSource(field, _dataSet.data);
									});
								}
							}
							//console.log("_dataSet: ",_dataSet);
							gDashboard.dataSourceManager.datasetInformation[_id].data = _dataSet.data;

							var sheetID = gDashboard.dataSourceManager.datasetInformation[_id].SHEET_ID;
							var sheetNM = gDashboard.dataSourceManager.datasetInformation[_id].SHEET_NM;

							if(sheetID == undefined || sheetID == null){
								sheetID = 'Sheet1';
							}

							/*dogfoot 스프레드 시트 테이블 바인드 테스트 용 shlim 20200721*/
							if(gDashboard.queryHandler.spreadtable){
								/*dogfoot 엑셀 스프레드시트 저장불러오기 오류 수정 shlim 20201123*/
								if(sheetID !=""){
								    gDashboard.spreadsheetManager.bindSpreadJSTABLE(datasetCount, _dataSet.data, sheetID, sheetNM);
								}else{
									gProgressbar.hide();
								}
							}else{
								gDashboard.spreadsheetManager.bindSpreadJS(datasetCount, _dataSet.data, sheetID, sheetNM);
							}


					},
					error : function(_e){
						gProgressbar.hide();
						WISE.alert('error'+ajax_error_message(_e),'error');
//						if(_e.error !== undefined){
//							alert(_e.error);
//						}else{
//							alert('ERROR CODE : '+_e.responseJSON.code+'\n MESSAGE : '+_e.responseJSON.message);
//						}
					}
				});
			};
			/* DOGFOOT hsshim 200103 끝 */

			var performQuery = function(_id, _ds) {
				$('#queryCancel').dxButton({
					//2019.12.26 mksong 취소 문구 수정 dogfoot
					text:"작업 취소",
					type:'default',
					onClick:function(_e){
						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
						gProgressbar.setStopngoProgress(true);
						gProgressbar.hide();
						$.ajax({
							type : 'post',
							//2020.03.06 mksong 비동기화 dogfoot
							cache : true,
							async: false,
							url : WISE.Constants.context + '/report/cancelqueries.do',
							complete: function(_e) {
								gProgressbar.cancelQuery();
//								gProgressbar.hide();
							}
						});
					}
				});

				var queryComleteCount = 0;
				var datasetCount = _.keys(dataSourceManager.datasetInformation).length;
				if(datasetCount == 0){
					_itemGenerateManager.bindData([], null, false);
					return false;
				}
				var runnable = function() {

					// 2021-03-18 yyb 비정형일때 측정값 체크 수정
					if (gDashboard.reportType == 'AdHoc') {
						var index = gDashboard.fieldManager.index;
						var measures;
						if (gDashboard.fieldManager.panelManager['datafieldAdHocContentPanel' + index] !== undefined) {
							measures = gDashboard.fieldManager.panelManager['datafieldAdHocContentPanel' + index].children('ul.analysis-data');
						}
						if (isNull(measures) || measures.length < 1) {
							WISE.alert('측정값을 1개 이상 올려야 조회가 가능합니다.');
							gProgressbar.hide();
							return false;
						}
					}
					
					var fields = new Array();
					var fieldNames = new Array();
					$.each(gDashboard.customFieldManager.fieldInfo[_ds.mapid], function(_ii, _custom) {
						fields = fields.concat(gDashboard.customFieldManager.trackingDatafields(_custom));
						fieldNames.push(_custom.Name);
					});

					var dupleFields = new Array();
					$.each(fields, function(key, value) {
						if($.inArray(value, dupleFields) === -1 && $.inArray(value, fieldNames) === -1) return dupleFields.push(value);
					});

					gDashboard.customFieldManager.fieldNameList = dupleFields;
					
					if(_itemGenerateManager == undefined) return;

					if (!_id || _id === 'undefined') {
						queryComleteCount++;
					}
					else {
						/* DOGFOOT hsshim 2020-01-13 필요없는 스프레드 기능 제거 */
						var param = {
								'pid': WISE.Constants.pid,
								'dsid': _ds['DATASRC_ID'],
								'dstype': _ds['DATASRC_TYPE'],
								'dsnm': _ds['DATASET_NM'],
								'reportType': gDashboard.reportType,
								'fldType': gDashboard.structure.ReportMasterInfo.fld_type,
								'mapid': _id,
								'sqlid': _ds['wise_sql_id'],
								'params': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues()),
								'userId': userJsonObject.userId,
								/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
								'sql_query_nosqlid': Base64.encode(_ds['DATASET_QUERY']||_ds['SQL_QUERY']),
								'sqlTimeout':userJsonObject.searchLimitTime,
								'tbllist': $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentTableList(_ds['DATASET_NM']))
						};

						$.ajax({
							type : 'post',
							data : param,
							cache : true,
							url : WISE.Constants.context + '/report/queries.do',
							beforeSend: function() {
								//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
								gProgressbar.show(true);
							},
							complete: function() {
//										if ((++queryComleteCount) === datasetCount) {
//										gProgressbar.hide();
//										}
							},
							success : function(_dataSet) {
								// 2020.01.16 mksong 데이터 건수 많을 경우 경고창 띄우기 dogfoot
								/*
								if(userJsonObject.searchLimitRow > 0 && _dataSet.data.length > userJsonObject.searchLimitRow){
									var confirmValue = window.confirm("데이터 조회 건수가 많아 브라우저 다운 현상이 발생할 수 있습니다. 계속 조회하시겠습니까? (필터를 변경 후 조회하시길 권장합니다.)");
									if(!confirmValue){
										gProgressbar.hide();
										return false;
									}
								}
								*/
//								if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
//									var fieldList = gDashboard.customFieldManager.fieldInfo[_dataSet.mapid];
//									var overwrite = false;
//									if (fieldList) {
//										fieldList.forEach(function(field) {
//											gDashboard.customFieldManager.addCustomFieldsToDataSource(field, _dataSet.data);
//										});
//										overwrite = true;
//									}
//								}
//								gDashboard.dataSourceManager.datasetInformation[_id].data = _dataSet.data;
//								_itemGenerateManager.bindData(_dataSet, null, overwrite);
								if(onlyQuery){
									gProgressbar.setStopngoProgress(true);
									gProgressbar.hide();
									return;
								}
								gDashboard.itemGenerateManager.sqlConfigWhere = [];
								_itemGenerateManager.bindData(_dataSet, null, null);
								//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
//								gProgressbar.hide();
							},
							error : function(_e){
								gProgressbar.hide();
								WISE.alert('error'+ajax_error_message(_e),'error');
							}
						});
					}
				}; // end of runnable

				if (WISE.libs.Dashboard.Config.debug) {
					runnable();
				}
				else {
					try {
						runnable();
					}
					catch (e) {
						var msg = 'error occurred while querying UI data - ' + e.toString();
						msg += ' - id : ' + _ds['DATASRC_ID'] + ', query : ' + _ds['DATASET_QUERY'] + ', params : ' + $.toJSON(condition);
						throw {status: 500, msg: msg};
					}
				}

			}; // end of performQuery
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			var cubePerformQuery = function(){
				// 2020.01.16 mksong 작업 취소 문구 처음부터 보이도록 수정 dogfoot
				/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
				var DU = WISE.libs.Dashboard.item.DataUtility;
				var DCU = WISE.libs.Dashboard.item.DataCubeUtility;
				var ReportMeta = gDashboard.structure.ReportMasterInfo;
				var selectedDsId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByField();
				WISE.Context.isCubeReport = true;

				//2020.02.13 mksong 프로그레스바 작업취소 최적화 dogfoot
				//20210223 AJKIM cancelqueries.do 작동하지 않을 때 작업 취소 버튼 제거 DOGFOOT
				gProgressbar.show(true);

				//20200903 ajkim 주제영역 마스터 필터 오류 수정 dogfoot
				var trackingItems = [];
				$.each(_itemGenerateManager.dxItemBasten, function(_i, _item) {
					if(_item.type === "LISTBOX" || _item.type === "TREEVIEW" || _item.type === "COMBOBOX" || (_item.IO && _item.IO.MasterFilterMode !== "Off")){
						trackingItems.push(_item);
					}
				});
				$.each(_itemGenerateManager.dxItemBasten, function(_i, _item) {
					$.each(gDashboard.dataSourceManager.datasetInformation, function(dsId, ds) {
						/* DOGFOOT ktkang 텍스트 박스 무한로딩 오류 수정  20200717 */
						if(_item.dataSourceId != undefined && ds != undefined && !(_item.type == 'IMAGE' || (_item.type == 'TEXTBOX' && gDashboard.reportType != 'RAnalysis'))){
							if(_item.dataSourceId === dsId) {
								/* DOGFOOT ktkang 대시보드 주제영역 필터 부분 수정  20200706 */
								var params = $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues());
								/* DOGFOOT ktkang 주제영역 필터 유형 추가  20200806 */
								var betweenParam = {};
								var paramName = '';
								var betweenValue = [];
								$.each(JSON.parse(params), function(_i, _e) {
									if(_e.operation == 'Between' && _e.name.indexOf('_fr')) {
										betweenParam[_e.uniqueName] = {
												uniqueName: _e.uniqueName,
												name: _e.name.replace('_fr', ''),
												/*dogfoot 리스트 필터 쿼리일때 key caption 명 다르면 못찾는 오류 수정 shlim 20200728*/
												captionName : _e.captionName,
												keyName : _e.keyName,
												paramName: _e.paramName.replace('_fr', ''),
												/*dogfoot 기본값 있는 보고서 불러올시 적용 안되는 오류 수정 shlim 20200716*/
												value: _e.value,
												type: _e.type,
												defaultValue: _e.defaultValue,
												whereClause: _e.whereClause,
												parameterType: _e.parameterType,
												betweenCalendarValue: _e.betweenCalendarValue,
												/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
												orgParamName: _e.orgParamName,
												cubeUniqueName: _e.cubeUniqueName,
												operation: _e.operation
										};
										betweenValue.push(_e.value);
										paramName = _e.uniqueName;
									} else if(_e.operation == 'Between' && _e.name.indexOf('_to')) {
										betweenValue.push(_e.value);
										/* DOGFOOT ktkang 주제영역 비트윈달력 오류 수정  20200810 */
									} else {
										betweenParam[_e.uniqueName] = _e;
									}
								});
								if(paramName != '') {
									betweenParam[paramName].value = betweenValue;
									params = JSON.stringify(betweenParam);
								}
								var param = {
										dsid: ds.DATASRC_ID,
										dsnm: ds.DATASET_NM,
										dstype: 'CUBE',
										params: params,
										sqlTimeout: userJsonObject.searchLimitTime,
										skipQuery: "",
										schId: undefined,
										mapid: dsId,
										reportType: gDashboard.reportType
								};
								/* DOGFOOT ktkang 대시보드 주제영역 부분 추가  20200423 */

								if(gDashboard.isNewReport) {
									var DI = [];
									var HM = [];
									var selected = {dim:[],mea:[]};
									gDashboard.itemGenerateManager.getherFields(_item.fieldManager, _item.type, false);
									/* DOGFOOT ktkang 주제영역 대시보드 오류 수정  20200525 */
									DI = _item.fieldManager['DataItems'];
									/*dogfoot 20200511 정렬순서 항목 오류 수정 shlim*/
									if(WISE.Context.isCubeReport){
                                        HM = _item.fieldManager['HiddenMeasures'] ? _item.fieldManager['HiddenMeasures'] : [];
									}else{
									    HM = _item.fieldManager['hiddenMeasures'];
									}

									var dNameArr = [];
									if(typeof DI['Dimension'] != 'undefined' && DI['Dimension'].length > 0) {
										_.each(DI['Dimension'], function(_R) {
											selected.dim.push({uid:_R.CubeUniqueName});
											dNameArr.push(_R.CubeUniqueName);
										});
									}

									//20200903 ajkim 주제영역 마스터 필터 오류 수정 dogfoot
									/* DOGFOOT ktkang 주제영역 필터 아이템 오류 수정  20200910 */
									$.each(trackingItems, function(i, trackingItem){
										gDashboard.itemGenerateManager.getherFields(trackingItem.fieldManager, trackingItem.type, false);
										if(trackingItem.dataSourceId === _item.dataSourceId && trackingItem.fieldManager.DataItems){
											_.each(WISE.util.Object.toArray(trackingItem.fieldManager.DataItems['Dimension']), function(_R) {
												if(dNameArr.indexOf(_R.CubeUniqueName) === -1){
													selected.dim.push({uid:_R.CubeUniqueName});
													dNameArr.push(_R.CubeUniqueName);
												}
											})
										}
									});


									if(typeof DI['Measure'] != 'undefined' && DI['Measure'].length > 0) {
										_.each(DI['Measure'], function(_D) {
											selected.mea.push({uid:_D.CubeUniqueName});
										});
									}
									/* DOGFOOT ktkang 주제영역 대시보드 오류 수정  20200525 */
									if(typeof HM['Measure'] != 'undefined' && HM['Measure'].length > 0) {
										_.each(HM['Measure'], function(_HM) {
											selected.dim.push({uid:_HM.cubeUniqueName});
										});
									}
//									if(typeof HM['Measure'] != 'undefined' && HM['Measure'].length > 0) {
//										_.each(HM['Measure'], function(_HM) {
//											$.each(DI.Measure,function(_i,_val){
//												if(_HM.UniqueName == _val.UniqueName){
//											        selected.dim.push({uid:_val.CubeUniqueName});
//												}
//											})
//										});
//									}
								} else {
									var DI = [];
									var HM = [];
									var selected = {dim:[],mea:[]};
									/* DOGFOOT ktkang 주제영역 대시보드 오류 수정  20200525 */
									//20210420 AJKIM 뷰어 대시보드 데이터 항목 수정 추가 dogfoot
									if(WISE.Constants.editmode != 'viewer' || (WISE.Constants.editmode == 'viewer' && ((gDashboard.reportType == 'DashAny' && userJsonObject.menuconfig.Menu.DASH_DATA_FIELD) || gDashboard.reportType == 'DSViewer'))) {
										gDashboard.itemGenerateManager.getherFields(_item.fieldManager, _item.type, false);
									}

									if(typeof _item.fieldManager != 'undefined' && typeof _item.fieldManager.DataItems != 'undefined') {
										DI = _item.fieldManager.DataItems;
										/*dogfoot 정렬기준 항목 보고서 열기 오류 수정 shlim 20200715*/
										if(typeof _item.fieldManager.HiddenMeasures === 'undefined' ){
										    HM = _item.fieldManager.HiddenMeasures;
										}else{
											if(typeof _item.fieldManager.HiddenMeasures.Measure === 'undefined'){
												 HM = _item.fieldManager.HiddenMeasures;
											}else{
												HM = _item.fieldManager.HiddenMeasures.Measure;
											}
										}
									} else {
										DI = _item.DI;
										HM = _item.HM;
									}


									if(typeof DI != 'undefined') {
										var dNameArr = [];
										if(typeof DI['Dimension'] != 'undefined' && typeof DI['Dimension'].CubeUniqueName != 'undefined') {
											selected.dim.push({uid:DI['Dimension'].CubeUniqueName})
											dNameArr.push(DI['Dimension'].CubeUniqueName);
										} else if(typeof DI['Dimension'] != 'undefined' && DI['Dimension'].length > 0){
											_.each(DI['Dimension'], function(_R) {
												selected.dim.push({uid:_R.CubeUniqueName});
												dNameArr.push(_R.CubeUniqueName);
											});
										}

										//20200903 ajkim 주제영역 마스터 필터 오류 수정 dogfoot
										/* DOGFOOT ktkang 주제영역 필터 아이템 오류 수정  20200910 */
										//20210330 ajkim 주제영역 마스터 필터 뷰어 불러오기 수정 dogfoot
										//뷰어에서 주제영역 마스터필터 불러오기 수정 syjin 20211123
										$.each(trackingItems, function(i, trackingItem){
											if(WISE.Constants.editmode !== 'viewer'){
												gDashboard.itemGenerateManager.getherFields(trackingItem.fieldManager, trackingItem.type, false);
												if(trackingItem.dataSourceId === _item.dataSourceId && trackingItem.fieldManager.DataItems){
													_.each(WISE.util.Object.toArray(trackingItem.fieldManager.DataItems['Dimension']), function(_R) {
														if(dNameArr.indexOf(_R.CubeUniqueName) === -1){
															selected.dim.push({uid:_R.CubeUniqueName,uniqueName:_R.UniqueName});
															dNameArr.push(_R.CubeUniqueName);
														}
													})
												}
											}else{
												if(trackingItem.dataSourceId === _item.dataSourceId && trackingItem.DI){
													_.each(WISE.util.Object.toArray(trackingItem.DI['Dimension']), function(_R) {
														if(dNameArr.indexOf(_R.CubeUniqueName) === -1){
															selected.dim.push({uid:_R.CubeUniqueName,uniqueName:_R.UniqueName});
															dNameArr.push(_R.CubeUniqueName);
														}
													})
												}
											}
											
										});

										if(typeof DI['Measure'] != 'undefined' && typeof DI['Measure'].CubeUniqueName != 'undefined') {
											selected.mea.push({uid:DI['Measure'].CubeUniqueName})
										} else if(typeof DI['Measure'] != 'undefined' && DI['Measure'].length > 0){
											_.each(DI['Measure'], function(_D) {
												selected.mea.push({uid:_D.CubeUniqueName});
											});
										}
									}

									if(typeof HM != 'undefined' && HM.length > 0) {
										_.each(HM, function(_HM) {
										/* DOGFOOT ktkang 주제영역 정렬기준 항목 오류 수정  20201126 */
											if(typeof _HM.cubeUniqueName != 'undefined') {
												selected.dim.push({uid:_HM.cubeUniqueName});
											} else {
												_.each(DI['Dimension'], function(_R) {
													if(_R.UniqueName == _HM.UniqueName) {
														selected.dim.push({uid:_R.CubeUniqueName});
													}
												});
												_.each(DI['Measure'], function(_R) {
													if(_R.UniqueName == _HM.UniqueName) {
														selected.dim.push({uid:_R.CubeUniqueName});
													}
												});
											}
										});
									}
								}

								param.cols = $.toJSON(selected);

								if(selected.mea.length == 0) {
									if(_item.type == "STAR_CHART" || _item.type == "SIMPLE_CHART" || _item.type == "TREEMAP" || _item.type == "PIE_CHART") {
										WISE.alert('보고서 조회 오류<br>' + _item.Name + ' 아이템에 측정값 항목이 없습니다.');
										if(gDashboard.itemGenerateManager.viewedItemList.indexOf(_item.ComponentName) < 0 ){
											gDashboard.itemGenerateManager.viewedItemList.push(_item.ComponentName);
										}
										if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
											gProgressbar.hide();
											gDashboard.updateReportLog('99');
										}
										return false;
									}
								} else if((_item.type == "HEATMAP" || _item.type == 'HEATMAP2') && (selected.mea.length != 1 || selected.dim.length != 2) && gDashboard.reportType != 'StaticAnalysis') {
									WISE.alert('보고서 조회 오류<br>히트맵 아이템은 측정값 1개 차원이 2개 있어야 조회가 가능합니다.');
									gProgressbar.hide();
									gDashboard.updateReportLog('99');
									return false;
								}

								$.ajax({
									type : 'post',
									data : param,
									/* DOGFOOT ktkang 작업 취소 기능 구현  20200923 */
									async: false,
									url : WISE.Constants.context + '/report/cube/queries.do',
									success : function(_dataSet) {
										var param2 = {
												'pid': WISE.Constants.pid,
												'dsid': ds['DATASRC_ID'],
												'dstype' : ds['DATASRC_TYPE'],
												/* DOGFOOT ktkang 상세현황 자르기  20200123 */
												'dsnm': ds['DATASET_NM'],
												'reportType' : gDashboard.reportType,
												'fldType' : gDashboard.reportUtility.reportInfo.ReportMasterInfo.fld_type,
												'mapid': dsId,
												'sqlid': 0,
												/* DOGFOOT ktkang 대시보드 주제영역 필터 부분 수정  20200706 */
												'params': params,
												'userId':userJsonObject.userId,
												/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
												'sql_query_nosqlid': Base64.encode(_dataSet.sql),
												'sqlTimeout':userJsonObject.searchLimitTime
										};
										/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
										var sql = Base64.decode(_dataSet.sql);
										_item.cubeQuery = sql;
										/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
										if(WISE.Constants.editmode == 'viewer') {
											_item.orderKey = _dataSet.order_Key;
										} else {
											if(_item.fieldManager) {
												_item.fieldManager.orderKey = _dataSet.order_Key;
												_item.orderKey = _dataSet.order_Key;
											} else {
												_item.orderKey = _dataSet.order_Key;
											}
										}
										
										/* DOGFOOT ktkang 대시보드 주제영역 불러오기 오류 수정  20200707 */
										gDashboard.dataSourceManager.datasetInformation[dsId].DATASET_QUERY = sql;
										gDashboard.dataSourceManager.datasetInformation[dsId].SQL_QUERY = sql;

										if(onlyQuery){
											gProgressbar.setStopngoProgress(true);
											gProgressbar.hide();
											return;
										}
										
										_itemGenerateManager.customFieldCalculater
										.$calculate(param2)  // when useing jquery promise
										.then(
												function(_response) {
													var calculatedData = new Array();
													var resultData = new Array();
													_item.selectedChartType = undefined; // for ChartGenerator instance
													_item.tracked = false;
													gDashboard.itemGenerateManager.sqlConfigWhere = [];
													_item.bindData([], null, null);
												}
										);
									}
								});
							}
						} else if(_item.type == 'IMAGE' || _item.type == 'TEXTBOX') {
							_item.bindData([], null, null);
						} else if(_item.dataSorceId == undefined){
							gDashboard.itemGenerateManager.sqlConfigWhere = {};
							if(gDashboard.itemGenerateManager.viewedItemList.indexOf(_item.ComponentName) < 0 ){
								gDashboard.itemGenerateManager.viewedItemList.push(_item.ComponentName);
							}
							if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
								gProgressbar.hide();
								gDashboard.updateReportLog();
							}
							if(gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'RAnalysis') {
								_item.bindData([], null, null);
							}
						}
					});
				});
			};

			var countPerformQuery = function(searchCount) {
				// 2020.01.16 mksong 작업 취소 문구 처음부터 보이도록 수정 dogfoot
				var queryComleteCount = 0;
				var datasetCount = _.keys(dataSourceManager.datasetInformation).length;
				var popupFlag = true;

				$.each(dataSourceManager.datasetInformation, function(_id, _ds) {

					var runnable = function() {
						if (!_id || _id === 'undefined') {
							queryComleteCount++;
						}
						else {
							var param = {
									'pid': WISE.Constants.pid,
									'dsid': _ds['DATASRC_ID'],
									'dstype' : _ds['DATASRC_TYPE'],
									'reportType' : gDashboard.reportType,
									/* DOGFOOT ktkang 개인보고서 추가  20200107 */
									'fldType' : gDashboard.fldType,
									'mapid': _id,
									'sqlid': _ds['wise_sql_id'],
									/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
									'sql_query_nosqlid': Base64.encode(_ds['SQL_QUERY']),
									'params': $.toJSON(condition),
									'userId':userJsonObject.userId,
									'searchCount' : searchCount,
									'sqlTimeout':userJsonObject.searchLimitTime,
									'keyTime' : userJsonObject.reportTime,
									'reportNm' : gDashboard.structure.ReportMasterInfo.name
							};
							/* DOGFOOT ktkang 개발을 위한 카운트 쿼리 주석  20200113 */
//							$.ajax({
//								type : 'post',
//								data : param,
//								cache : false,
////								async : false,
//								url : WISE.Constants.context + '/report/countqueries.do',
//								beforeSend: function() {
//									gProgressbar.show();
//								},
//								complete: function() {
////									if ((++queryComleteCount) === datasetCount) {
////									performQuery();
////									}
//								},
//								success : function(_dataSet) {
//									gProgressbar.hide();
//									if((searchCount < _dataSet.data[0].ROW_COUNT) && popupFlag){
//										popupFlag = false;
//										var options = {
//												buttons: {
//													confirm: {
//														id: 'confirm',
//														className: 'blue',
//														text: '확인',
//														action: function() {
//															Apprise('close');
//															performQuery();
//															return false;
//														}
//													},
//													cancel: {
//														id: 'cancel',
//														className: 'red',
//														text: '취소',
//														action: function() { Apprise('close'); }
//													}
//												}
//										};
//										WISE.alert('조회건수('+_dataSet.data[0].ROW_COUNT+')가  설정 값('+searchCount+')보다 큽니다! 계속하시겠습니까?', options);
//									}else{
										gProgressbar.show();
										/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
										if(gDashboard.downloadFull) {
											if(_ds['DATASET_NM'].indexOf('상세현황') > -1){
												performQuery(_id, _ds);
											}
										} else {
											performQuery(_id, _ds);
										}
//									}
//								},
//								error : function(_e){
//									gProgressbar.hide();
//
//									var options = {
//											buttons: {
//												confirm: {
//													id: 'confirm',
//													className: 'blue',
//													text: '확인',
//													action: function() {
//														Apprise('close');
//														return false;
//													}
//												}
//											}
//									};
//									WISE.alert('조회 시간이 초과되었거나 중단을 누르셨습니다!', options);
//								}
//							});
						}
					}; // end of runnable

					if (WISE.libs.Dashboard.Config.debug) {
						runnable();
					}
					else {
						try {
							runnable();
						}
						catch (e) {
							var msg = 'error occurred while querying UI data - ' + e.toString();
							msg += ' - id : ' + _ds['DATASRC_ID'] + ', query : ' + _ds['DATASET_QUERY'] + ', params : ' + $.toJSON(condition);
							throw {status: 500, msg: msg};
						}
					}

				}); // end of $.each
			}; // end of countperformQuery

			if (hasEmptyValueOnListType) {
				// 2020.01.16 mksong confirm 기능 추가 dogfoot
				var options = {
					buttons: {
						confirm: {
							id: 'confirm',
							className: 'blue',
							text: '확인',
							action: function() {
								$AlertPopup.hide();
								performQuery();
							}
						},
						cancel: {
							id: 'cancel',
							className: 'negative',
							text: '취소',
							action: function() { $AlertPopup.hide(); }
						}
					}
				};
			    WISE.confirm(gMessage.get('WISE.message.page.search.empty.list.value'), options);
				// 2020.01.16 mksong confirm 기능 추가 수정 끝 dogfoot
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			} else if(WISE.Context.isCubeReport && gDashboard.reportType == 'AdHoc' && typeof gDashboard.structure.ReportMasterInfo.subquery == 'undefined') {
				cubeAdhocPerformQuery();
			} else if(WISE.Context.isCubeReport && (gDashboard.reportType == 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'RAnalysis')){/*dogfoot 통계 분석 추가 shlim 20201102*/
				cubePerformQuery();
			}
			else {
				//if(userJsonObject.searchLimitRow > 0){
				//	countPerformQuery(userJsonObject.searchLimitRow);
				//}
				/* DOGFOOT hsshim 200103
 				 * 스프레드 집합 조회 기능 개선
 				 */
				if (gDashboard.reportType === 'Spread' || gDashboard.reportType === 'Excel') {
					/*dogfoot 엑셀보고서 쿼리 버튼 클릭 시 프로그레스바 안나오는 오류 수정 shlim 20200716*/
					var dsCount = 0;
					$.each(dataSourceManager.datasetInformation, function(_id, _ds) {
						dsCount ++;
						setTimeout(function(){
							 gProgressbar.show();
							 if(_ds.SHEET_ID !== undefined) {
									spreadPerformQuery(_id, _ds);
								}else{
									gProgressbar.hide();
								}
						 }, 1000 * dsCount);

					});
				} else {
					$.each(dataSourceManager.datasetInformation, function(_id, _ds) {
						performQuery(_id, _ds);
					});
				}
			}

			//사용자정의데이타에 조회된 열만 검색되게 속성 추가
			if(WISE.Constants.editmode != 'viewer' || gDashboard.reportType == 'AdHoc'){
				if (gDashboard.reportType !== 'Spread' && gDashboard.reportType !== 'Excel') {
					$.each(gDashboard.fieldManager.stateFieldChooser.find('.analysis-data'), function(_i,_field){
						$(_field).children().attr('data-search-flag','Y');
					});
				}
			}
			
		}
		
//		else if(gDashboard.isNewReport){
//			var checkBindData = true;
//			$.each(_itemGenerateManager.dxItemBasten,function(_i,_item){
//				if(_item.dataSourceId == undefined){
//					checkBindData = false;
//				}
//			});
//			if(checkBindData){
//				$.each(_itemGenerateManager.dxItemBasten,function(_i,_item){
//					_item.queryState = true;
//					_itemGenerateManager.bindData(gDashboard.dataSourceManager.datasetInformation[_item.dataSourceId], condition);
//				});
//			}else{
//				WISE.alert("데이터 연결을 확인하세요.");
//			}
//
//		}
		
		
	}; // end of this.query
};