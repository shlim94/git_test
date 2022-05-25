WISE.libs.Dashboard.CustomFieldCalculater = function(_dataSources) {
	var self = this;
	var dataSources;
	
	this.type = 'CALCULATED_FILED';
	
	this.dashboardid;
	
	(function() {

	})();
	
	/** 
	 * using browser native promise object
	 * 
	 * @Param _dataSet 
	 * 		can not be cloned object for being shared by each component 
	 * */
	this.calculate = function(_dataSet) {
		return new Promise(function(_resolve, _reject) {
			_resolve(calculator(_dataSet));
		});
	};
	/** 
	 * using jquery promise
	 * 
	 * @Param _dataSet 
	 * 		can not be cloned object for being shared by each component 
	 * */
	this.$calculate = function(_dataSet) {
		return $.when(calculator(_dataSet));
	};
	
	this.calculateDeltaData = function(_dataSet,_delta) {
		return deltaDataCalculator(_dataSet,_delta);
	};
	
	var deltaDataCalculator = function(_dataSet,_delta) {
		var pluck = function() {
			var ToArray = WISE.util.Object.toArray;
			self.dataSetMeta = _dataSet.meta;
//			var deltaColumns = self.meta['REPORT_XML']['DELTAVALUE_ELEMENT'] ? ToArray(self.meta['REPORT_XML']['DELTAVALUE_ELEMENT']['DELTA_VALUE']) : [];
			var deltaColumns = _delta;
			return deltaColumns;
		};
		var fnPercentOfColumnGrandTotal = function(_c, _sourceColumnCaption) {
			_.each(_dataSet.data, function(_r) {
	    		_r[_c['CAPTION']] = 0; // dataset에 dummy data를 생성한다. (fieldmanager의 columnMeta를 생성하기 위한 더미데이터)
	    	});
		};
		
		var fnRankOfColumn = function(_c, _sourceColumnCaption,_col,_row,_val) {
			var colTmp = [];
			var rowTmp = [];
			var order = '';
			var UR = _dataSet.meta.Rows ? WISE.util.Object.toArray(_dataSet.meta.Rows.Row) : [];
			var UC = _dataSet.meta.Columns ? WISE.util.Object.toArray(_dataSet.meta.Columns.Column) : [];
			var UV = _dataSet.meta.Values ? WISE.util.Object.toArray(_dataSet.meta.Values.Value) : [];
			var concatDim = new Array();
			var concatMea = new Array();
//			var columnMeta = new Array();
			concatDim = $.merge(concatDim,_col);
			concatDim = $.merge(concatDim,_row);
			concatMea = $.merge(concatMea,_val);
			var columnMeta = {};
//			columnMeta = $.merge(columnMeta,concatDim);
//			columnMeta = $.merge(columnMeta,concatMea);
			
			$.each(concatDim,function(_i,_dim){
				columnMeta[_dim.name] = _dim;
			});
			$.each(concatMea, function(_i,_mea){
				columnMeta[_mea.name] = _mea;
			});
			
			//2020.03.10 MKSONG 변동측정값 열기준 오류 수정 DOGFOOT
//			var sortDataSet = WISE.libs.Dashboard.Query.likeSql.fromJson(concatDim,concatMea,_dataSet.data);
			var sortDataSet = _dataSet.data;
			
			$.each(sortDataSet,function(_i,_data){
				$.each(_data,function(_key,_value){
					$.each(_val,function(_i,_valueElement){
						if(_key === _valueElement.caption){
							var obj = _data;
							obj[_valueElement.name] = obj[_valueElement.caption];
//							delete obj[_valueElement.caption];
							//2020.03.10 MKSONG 변동측정값 열기준 오류 수정 끝 DOGFOOT
							return false;
						}
					});
				});
			});
			_dataSet.data = sortDataSet;
			$.each(columnMeta, function(_i,_r) {
				var index;
				for (var i = 0; i < _col.length; ++i) {
				    if (_col[i].uniqueName === _r.uniqueName) {
				        index = i;
				        break;
				    }
				}
				if(index != -1)
					colTmp.push(_col[index]);
				
				for (var i = 0; i < _row.length; ++i) {
				    if (_row[i].uniqueName === _r.uniqueName) {
				        index = i;
				        break;
				    }
				}
				if(index != -1)
					rowTmp.push(_row[index]);
			});
//			$.each(UC,function(_i,_uc){
//				var index;
//				for(var i =0;i<_col.length;++i){
//					if(_col[i].uniqueName === _uc['UniqueName']){
//						index = i;
//						break;
//					}
//				}
//				if(index != -1){
//					colTmp.push(_col[index]);
//				}
//			})
//			$.each(UR,function(_i,_ur){
//				var index;
//				for(var i =0;i<_row.length;++i){
//					if(_row[i].uniqueName === _ur['UniqueName']){
//						index = i;
//						break;
//					}
//				}
//				if(index != -1){
//					rowTmp.push(_col[index]);
//				}
//			})
			
			if(_c['DELTA_VALUE_TYPE'].indexOf("Largest To Smallest") == -1)
				order = '|asc|';
			else
				order = '|desc|';
			
			_col = colTmp;
			_row = rowTmp;
			
			var rowCount = 0, colCount = 0;
			_.each(_row, function(__row) {
				if(__row !== undefined) {
					rowCount++;
				}
			});
			_.each(_col, function(__col) {
				if(__col !== undefined) {
					colCount++;
				}
			});
			
			_.each(_dataSet.data, function(_r) {
				var data = _dataSet.data;
				
				if(_c['DELTA_VALUE_TYPE'] === 'Rank Row Largest To Smallest' || _c['DELTA_VALUE_TYPE'] === 'Rank Row Smallest To Largest')
				{
					if(rowCount == 0){
						_.each(_col, function(__col) {
							if(__col !== undefined) {
								if(columnMeta[__col.name] !== undefined)
								{
									data = SQLike.q({
										Select: ['*'],
										From: data,
//										Where: function(){
//											return this[__col.name] == _r[__col.name];
//										},
										OrderBy:[_sourceColumnCaption,order]
									});
								}
							}
						});
					}
					else{
						_.each(_row, function(__row) {
							if(__row !== undefined) {
								if(columnMeta[__row.name] !== undefined)
								{
//									if(colCount == 0){
//										data = SQLike.q({
//											Select: ['*'],
//											From: data,
//											OrderBy:[_sourceColumnCaption,order]
//										});
//									}else{
										data = SQLike.q({
											Select: ['*'],
											From: data,
											Where: function(){
												return this[__row.name] == _r[__row.name];
											},
											OrderBy:[_sourceColumnCaption,order]
										});
//									}
								}
							}
						});
					}
				}
				else
				{
					if(colCount ==0){
						_.each(_row, function(__row) {
							if(__row !== undefined) {
								if(columnMeta[__row.name] !== undefined)
								{
									data = SQLike.q({
										Select: ['*'],
										From: data,
										OrderBy:[_sourceColumnCaption,order]
									});
								}
							}
						});
					}else{
						_.each(_col, function(__col) {
							if(__col !== undefined) {
								if(columnMeta[__col.name] !== undefined)
								{
//									if(rowCount == 0){
//										data = SQLike.q({
//											Select: ['*'],
//											From: data,
//											OrderBy:[_sourceColumnCaption,order]
//										});
//									}
//									else{
										data = SQLike.q({
											Select: ['*'],
											From: data,
											Where: function(){
												return this[__col.name] == _r[__col.name];
											},
											OrderBy:[_sourceColumnCaption,order]
										});
//									}
								}
							}
						});
					}
					
				}
				 
				var index;
				for (var i = 0; i < data.length; ++i) {
				    if (data[i][_sourceColumnCaption] === _r[_sourceColumnCaption]) {
				        index = i;
				        break;
				    }
				}
				if(_r[_sourceColumnCaption])
	    		_r[_c['CAPTION']] = index + 1; // dataset에 dummy data를 생성한다. (fieldmanager의 columnMeta를 생성하기 위한 더미데이터)
	    	});
		};
		
		_.each(pluck(), function(_c) {
			var ToArray = WISE.util.Object.toArray;
			var sourceColumnCaption;
			var DU = WISE.libs.Dashboard.item.DataUtility;
			
//			var G = ToArray(gDashboard.structure['REPORT_XML']['GRID_ELEMENT']['GRID']);
//			var C = ToArray(gDashboard.structure['REPORT_XML']['COL_ELEMENT']['COL']);
//			var R = ToArray(gDashboard.structure['REPORT_XML']['ROW_ELEMENT']['ROW']);
			var D = _dataSet.meta.DataItems;
			var UR = _dataSet.meta.Rows ? WISE.util.Object.toArray(_dataSet.meta.Rows.Row) : [];
			var UC = _dataSet.meta.Columns ? WISE.util.Object.toArray(_dataSet.meta.Columns.Column) : [];
			var UV = _dataSet.meta.Values ? WISE.util.Object.toArray(_dataSet.meta.Values.Value) : [];
			var V = new Array(); 
			var C = new Array();
			var R = new Array();

			$.each(UV, function(_i,_v) {
				var dataMember = DU.getDataMember(_v['UniqueName'], D);
				if (_c['BASE_UNI_NM'] === dataMember['name']) {
					sourceColumnCaption = _c['BASE_UNI_NM'];
					return false;
				}
			});
			$.each(UC,function(_i,_c){
				var dataMember = DU.getDataMember(_c['UniqueName'], D);
				C.push(dataMember);
			});
			$.each(UR,function(_i,_r){
				var dataMember = DU.getDataMember(_r['UniqueName'], D);
				R.push(dataMember);
			});
			$.each(UV,function(_i,_v){
				var dataMember = DU.getDataMember(_v['UniqueName'], D);
				V.push(dataMember);
			});
			$.each(UV,function(_i,_v){
				var dataMember = DU.getDataMember(_v['UniqueName'], D);
				$.each(_delta,function(_j,_del){
					if(_del.BASE_UNI_NM === dataMember.name && _del.DELTA_VALUE_TYPE.indexOf("Rank") == -1){
						dataMember.name = _del['CAPTION'];
						dataMember.caption = _del['CAPTION'];
						dataMember.captionBySummaryType = _del['CAPTION']+"("+dataMember.summaryType+")";
						dataMember.nameBySummaryType = dataMember.summaryType+"_"+_del['CAPTION'];
						V.push(dataMember);
						return false;
					}
				});
				
				
			})
			switch(_c['DELTA_VALUE_TYPE']) {
			case 'Absolute Variation': // 변화량
			case 'Percent Variation': // 변화비율
			case 'Percent Of Column': // 열기준비율
			case 'Percent Of Row': // 행기준비율
			case 'Percent Of Column GrandTotal': // 열 총합계 기준비율
				fnPercentOfColumnGrandTotal(_c, sourceColumnCaption); break;
			case 'Percent Of Row GrandTotal': // 행 총합계 기준비율
			case 'Percent Of GrandTotal': // 총합계 기준비율
			case 'Rank Row Largest To Smallest':
			case 'Rank Row Smallest To Largest':
				fnRankOfColumn(_c, sourceColumnCaption,C,R,V);
				break;
			case 'Rank Column Largest To Smallest':
			case 'Rank Column Smallest To Largest':
				fnRankOfColumn(_c, sourceColumnCaption,C,R,V);
				break;
			default:
				fnPercentOfColumnGrandTotal(_c, sourceColumnCaption);
			};
		});
		
		return _dataSet;
	}
	
	
	var calculator = function(_dataSet) {
		/* DOGFOOT hsshim 1231
		 * 사용 불가 (사용자 정의 데이터의 최신 기능은 WISE.widget.CustomFieldManager.js에 있음)
		 */
		// var pluck = function(_id) {
		// 	var customColumn, ToArray = WISE.util.Object.toArray;
		// 	_.each(dataSources, function(_dataSource) {
		// 		if (_id === _dataSource['ComponentName']) {
		// 			customColumns = _dataSource['CalculatedFields'] ? ToArray(_dataSource['CalculatedFields']['CalculatedField']) : undefined;
		// 			return false;
		// 		}
		// 	});
		// 	return customColumns;
		// };
		
		// var id = _dataSet.mapid;
		// var data = _dataSet.data;
		// var customColumns = pluck(id);
			
		// if ($.type(customColumns) === 'array' && customColumns.length > 0) {
		// 	_.each(customColumns, function(_c) {
		// 		var name = _c['Name'];
		// 		var dataType = _c['DataType'];
		// 		var expression = _c['Expression'];
				
		// 		expression = WISE.util.String.allTrim(expression);
		// 		expression = expression.replace(/ToDecimal/g, 'Number');
		// 		expression = expression.replace(/ToDouble/g, 'Number');
		// 		expression = expression.replace(/ToFloat/g, 'Number');
		// 		expression = expression.replace(/ToInt/g, 'Number');
		// 		expression = expression.replace(/ToLong/g, 'Number');
		// 		expression = expression.replace(/Trim/g, 'WISE.util.String.trim');
		// 		expression = expression.replace(/Lower/g, 'WISE.util.String.toLowerCase');
		// 		expression = expression.replace(/Upper/g, 'WISE.util.String.toUpperCase');
		// 		expression = expression.replace(/Len/g, 'WISE.util.String.length');
		// 		expression = expression.replace(/\[/g, '<');
		// 		expression = expression.replace(/\]/g, '>');
				
		// 		var matcher, matchBox = [];
		// 		var regExp = /<.+?>/g;
		// 		while (matcher = regExp.exec(expression)) {
		// 			if (matcher.length > 0) {
		// 				matchBox.push(matcher[0].replace(/\</,'').replace(/\>/,''));
		// 			}
		// 		}
		// 		matchBox = _.intersection(matchBox, matchBox); // distinct element
				
		// 		_.each(data, function(_r) {
		// 			_.each(matchBox, function(_match) {
		// 				var regExp = new RegExp("<" + _match + ">","g");
		// 				expression = expression.replace(regExp, "_r." + _match);
		// 			});
		// 			_r[name] = eval(expression);
		// 			// return false;
		// 		});
		// 	});
		// }
		/* DOGFOOT hsshim 1231 끝 */
		
		return _dataSet;
	};
	
	// constructor
	(function(_dataSources) {
		dataSources = _dataSources;

	})(_dataSources);
};