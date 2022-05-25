/** DataUtility */
WISE.libs.Dashboard.item.DataUtility = {
	setPrecision: function(_member) {
		var fs = _member['FORMAT_STRING'];
		if(fs == 0)
			_member.precision = 1;
		else
			_member.precision = 0;
		 // set default
		
		
		if (!!fs && (fs.indexOf('.') > -1)) {
			var ps = fs.split('.');
			ps = ps[ps.length - 1];
			ps = ps.replace(/\'/g,'').replace(/\%/g,'');
			_member.precision = ps.length;
		}
		return _member;
	},
	setFormat: function(_member) {

		if (_member.type === 'measure') {
			var fs = _member['FORMAT_STRING'];
			if (!!fs && (fs.indexOf('%') > -1)) {
				_member.format = 'percent';
			}
			else {
				_member.format = 'fixedPoint';
			}
		}
		else {
			_member.format = undefined;
		}
		return _member;
	},
	setSummaryType: function(_member) {
		var fs = _member['FORMAT_TYPE'];
		if (_member.type === 'measure') {
			_member.summaryType = 'sum';
		}
		else {
			_member.summaryType = 'count';
		}
		return _member;
	},
	toDimension: function(_member) { // chart에서 사용됨
		return {
			type: 'dimension',
			name: _member['UNI_NM'],
			caption: _member['CAPTION'],
			sortOrder: _member.ssssss
		};
	},
	toMeasure: function(_member) { // chart에서 사용됨
		
		return {
			type: 'measure',
			name: _member['UNI_NM'],
			caption: _member['CAPTION'],
			summaryType: _member.summaryType,
			format: _member.format,
			format_string: _member['FORMAT_STRING'],
			precision: _member.precision,
			nameBySummaryType: _member.summaryType + '_' + _member['UNI_NM'],
			captionBySummaryType: _member.summaryType + '_' + _member['CAPTION']
		};
		
	},
	getMember: function(_o, _grids, _calcs, _deltas) {
		var member;
		_.each(_grids, function(_grid) {
			if (_o['UNI_NM'] === _grid['UNI_NM']) {
				member = $.extend({}, _o);
				$.extend(member, _grid);
				member.name = member.CAPTION;
				member.isCCF = _o['FORMAT_TYPE'] === 'Custom' && _grid['TYPE'] === 'USER'; // C/S
																							// 화면에서
																							// 추가된
																							// 계산필드
																							// (주제영역
																							// 계산필드
																							// 구분여부가
																							// 아님)
				member.isDTF = _o['FORMAT_TYPE'] === 'Custom' && _grid['TYPE'] === 'DELTA'; // C/S
																							// 화면에서
																							// 추가된
																							// delta
																							// field
				return false;
			}
		});
		
		if (_calcs && member) {
			_.each(_calcs, function(_calc) {
				if (_o['UNI_NM'] === _calc['FLD_NM']) {
					member.CAPTION = _calc['CAPTION'];
					member.name = member.CAPTION;
					return false;
				}
			});
		}
		if (_deltas && member) {
			_.each(_deltas, function(_delta) {
				if (_o['UNI_NM'] === _delta['FLD_NM']) {
					member.CAPTION = _delta['CAPTION'];
					member.name = member.CAPTION;
					return false;
				}
			});
		}
		return member;
	},
	getRowMember: function(_row, _grids, _rows) {
		var member = this.getMember(_row, _grids);
		if (!!member) member.type = 'dimension', (_rows||[]).push(member);
		return member;
	},
	getSortMember: function(_row, _grids, _rows) {
		var member = this.getMember(_row, _grids);
		if (!!member) member.type = 'dimension', (_rows||[]).push(member);
		return member;
	},
	getColumnMember: function(_column, _grids, _columns) {
		return this.getRowMember(_column, _grids, _columns);
	},
	getMeasureMember: function(_data, _grids, _measures) {
		var member = this.getMember(_data, _grids);
		if (!!member) member.type = 'measures', (_measures||[]).push(member);
		return member;
	},
	getDataMember: function(_uniqueName, _dataItems, _dimensions, _measures) {
		if ($.type(_uniqueName) === 'object') {
			_uniqueName = _uniqueName['UniqueName'];
		}
		
		var Dimension = {
			get: function(_D) {
				var dataMember = {};
				dataMember.type = 'dimension';
				dataMember.name = _D['DataMember'];
				dataMember.rawCaption = _D['Name'];
				dataMember.caption = _D['Name'] || _D['DataMember'];
				dataMember.UNI_NM = _D['UNI_NM'];
				//2020-01-14 LSH topN 차원값 설정
				dataMember.TopNEnabled = _D['TopNEnabled'];
				/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
				dataMember.TopNOrder = _D['TopNOrder'];
				dataMember.TopNCount = _D['TopNCount'];
				dataMember.TopNShowOthers = _D['TopNShowOthers'];
				dataMember.TopNMeasure = _D['TopNMeasure'];
				/*dogfoot 통계 분석 추가 shlim 20201103*/
				dataMember.ContainerType = typeof _D['ContainerType'] != 'undefined' ? _D['ContainerType'] : '';
				if (_D['SortOrder']) {
					dataMember.sortOrder = _D['SortOrder'].toLowerCase();
					dataMember.sortOrder = dataMember.sortOrder === 'descending' ? 'desc' : 'asc';
				}else{
					dataMember.sortOrder = 'asc';
				}
				/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */
				if(_D['SortByMeasure']) {
					dataMember.sortByMeasure = _D['SortByMeasure'];
				}
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(_D['CubeUniqueName']) {
					dataMember.CubeUniqueName = _D['CubeUniqueName'];
				}
					
				return dataMember;
			}	
		};
		var Measure = {
			get: function(_M) {
				var dataMember = {};
					
				// private function
				var getSummaryType = function(_summaryType) {
					var summaryType = (_summaryType || 'sum').toLowerCase();
					
					switch(summaryType) {
					case 'average':
						summaryType = 'avg'; break;
//					case 'countdistinct':
//						summaryType = 'count'; break;	
					case 'stddev':
					case 'stddevp':
					case 'var':
					case 'varp':
						summaryType = 'sum'; break;	
					}
					return summaryType;
				};
				var getNumericFormat = function(_numericFormat) { 
					
					var getUnit = function(_numericFormat, _defaultFormat) {

						var fmt, unit = (_numericFormat['Unit'] || 'Ones' ).toLowerCase();
						
						switch(unit) {
						case 'ones':
						case 'thousands':
						case 'millions':
						case 'billions':
							fmt = unit; break;
						default:
							// auto
							fmt = _defaultFormat;
						}
						
						return fmt;
					};
					var getPrecision = function(_numericFormat) {
						if (_numericFormat && (_numericFormat['Precision'] >= 0)) {
							return parseInt(_numericFormat['Precision'],10);
						}
						return 2;
					};
					
					if (_numericFormat) {
						var format = {};
						var precision, currencyCulture, currentcyCultureName = (_numericFormat['CurrencyCultureName'] || '' ).toLowerCase();
						var formatType = (_numericFormat['FormatType'] || 'Number').toLowerCase();
						
						switch(formatType) {
						case 'general':
							format = 'decimal';
							precision = 0;
							break;
						case 'number':
							format = getUnit(_numericFormat, 'ones');
//							if (format === 'fixedPoint') {
//								precision = 0;
//							}
//							else 
							if (format === 'ones') {
								format = 'fixedPoint';
								precision = getPrecision(_numericFormat);
							}
							else {
								precision = getPrecision(_numericFormat);
							}
							break;
						case 'currency': 
							/* 
							 * devextrem에서 currency는 C/S Dashboard의 ones, include group separtor가 default. 
							 * 따라서 auto, thousand... 등으로 바꾸게 되면 원화표시가 없어진다.
							 * */
							format = getUnit(_numericFormat, 'number');
							if (format === 'currency') {
								precision = 0;
							}
							else if (format === 'ones') {
								format = 'currency';
								precision = getPrecision(_numericFormat);
							}
							else {
								precision = getPrecision(_numericFormat);
								currencyCulture = 'krw';
							}
							break;
						case 'percent':
							format = 'percent'; 
							precision = getPrecision(_numericFormat);
							break;
						case 'scientific':
							format = 'exponential';
							precision = getPrecision(_numericFormat);
							break;
						default:
							// auto
//							format = '#,##0';
							precision = 0;
							format = {
								key : '#,##0',
								type : '#,##0',
							};
						}
						
						return {
							format: format,
							currencyCulture: currencyCulture,
							formatType: _numericFormat.FormatType,
							unit: _numericFormat.Unit, 
							precision: _numericFormat.Precision,
							precisionOption: _numericFormat.PrecisionOption || _numericFormat.precisionOption,
							includeGroupSeparator: _numericFormat.IncludeGroupSeparator,
							suffix: _numericFormat.Suffix,
							suffixEnabled: _numericFormat.SuffixEnabled
						}
					}
					else {
//						format = '#,##0';
						precision = 0;
						format = {
							key : '#,##0',
							type : '#,##0',
						};
						
						return {
							format: format,
							precision: 0
						}
					}
				};
				
				// make data member
				dataMember.type = 'measure';
				dataMember.name = _M['DataMember'];
				dataMember.rawCaption = _M['Name'];
				dataMember.summaryType = getSummaryType(_M['SummaryType']);
				dataMember.UNI_NM = _M['UNI_NM'];
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(_M['CubeUniqueName']) {
					dataMember.CubeUniqueName = _M['CubeUniqueName'];
				}
				
				var Format = getNumericFormat(_M['NumericFormat']);
				dataMember.format = Format.format;
				dataMember.currencyCulture = Format.currencyCulture;
				dataMember.formatType = Format.formatType;
				dataMember.unit = Format.unit;
				dataMember.precision = Format.precision;
				dataMember.precisionOption = Format.PrecisionOption || Format.precisionOption;
				dataMember.includeGroupSeparator = Format.includeGroupSeparator;
				dataMember.suffix = Format.suffix;
				dataMember.suffixEnabled = Format.suffixEnabled;
				// sparkline option
				dataMember.highlightstartendpoints = _M['Highlightstartendpoints'] == 'false' ? false : true;
				dataMember.highlightminmaxpoints = _M['Highlightminmaxpoints'] == 'false' ? false : true;
				/*dogfoot 통계 분석 추가 shlim 20201103*/
				dataMember.ContainerType = typeof _M['ContainerType'] != 'undefined' ? _M['ContainerType'] : '';

				
				//dataMember.nameBySummaryType = dataMember.summaryType + '_' + (_M['Name'] || _M['DataMember']);
				//2020.01.30 mksong sqlike config 수정 dogfoot
				dataMember.nameBySummaryType = dataMember.summaryType + '_' + _M['DataMember'];
//				dataMember.nameBySummaryType = dataMember.summaryType + '(' + _M['DataMember'] + ')';
				dataMember.nameBySummaryType2 = dataMember.summaryType + '_' + _M['DataMember'];
				
				/* caption */
				//dataMember.captionBySummaryType = _M['DataMember'] + '(' + dataMember.summaryType + ')';
//				dataMember.captionBySummaryType = (_M['Name'] || _M['DataMember']) + '(' + dataMember.summaryType + ')';
				dataMember.captionBySummaryType = dataMember.summaryType + '_' + (_M['Name'] || _M['DataMember']);
				dataMember.caption = _M['Name'] || dataMember.name;
				
//				alert($.toJSON(dataMember));
				return dataMember;
			}	
		}; // end of Measure
			
		var dataMember = {};
		
		$.each(_dataItems, function(_kb0, _ob0) {

			switch(_kb0) {
			case 'Dimension':
				var checker = true;
				$.each(WISE.util.Object.toArray(_ob0), function(_ic0, _oc0) {
					if (_oc0['UniqueName'] == _uniqueName) {
						dataMember = Dimension.get(_oc0);
						if(_oc0['SortByMeasure'])
						{
							$.each(_dataItems, function(_kb1, _ob1) {
//								if(_kb1 == 'Measure')
//								{
									$.each(WISE.util.Object.toArray(_ob1), function(_ic1, _oc1) {
										if (_oc1['UniqueName'] == _oc0['SortByMeasure']) {
											dataMember.sortByMeasure = _oc1['DataMember'];
										}
									});
//								}
								
							});
							
						}
						dataMember.uniqueName = _uniqueName;
						if(_dimensions) {
							var duplicateCheck = _dimensions.filter(function(dim) {
								return dim.uniqueName === _uniqueName;
							});
							if (duplicateCheck.length === 0) {
								_dimensions.push(dataMember);
							}
						}
						checker = false;
						return false;
					}
				});
				
				if (!checker) return false;
				
				break;
			case 'Measure':
				var checker = true;
				$.each(WISE.util.Object.toArray(_ob0), function(_ic0, _oc0) {

					if (_oc0['UniqueName'] == _uniqueName) {
						dataMember = Measure.get(_oc0);
						
						dataMember.uniqueName = _uniqueName;
//						dataMember.displayMode = _kb0;
						
						if(_measures) {
							var duplicateCheck = _measures.filter(function(mea) {
								return mea.uniqueName === _uniqueName;
							});
							if (duplicateCheck.length === 0) {
								_measures.push(dataMember);
							}
						}
						checker = false;
						return false;
					}
				});
				
				if (!checker) return false;

				break;
			}
		});
			
		return dataMember || '';
	} // end of getDataMember function	
	
	/**
	 * @Param _options: obeject
	 * 	value: number, absolute value
	 * 	subvalues: number, target value
	 * 	delta: object, delta options
	 * */
	,makeTextValueObjectOfDeltaOptions: function(value, subvalues, delta) {
		
		/** 
		 * @Param _av: number, absolute value
		 * @Param _tv: number, target value
		 * @Param _delta
		 * 	ValueType = "ActualValue", "AbsoluteVariation", "PercentVariation", "PercentOfTarget" - AbsoluteVariation
		 * 	ResultIndicationMode = "GreaterIsGood", "LessIsGood", "WarningIfGreater", "WarningIfLess", "NoIndication" - GreaterIsGood
		 * 	ResultIndicationThresholdType = "Absolute", "Percent" - Percent
		 * 	ResultIndicationThreshold = "50" - 0
		 * */
		var getValueTextStyle = function(_av, _tv, _delta) {
			var fontColor;
			var indicator = '';
			var valueText = '';
			var siglenValue = false;
			var u_pot; // percent of target (unmodified)
			var u_pvv; // percent variation (unmodified)
			
			if (_av === undefined || _tv === undefined) {
				fontColor = undefined;
				valueText = _av || _tv || Number(0);
				siglenValue = true;
			}
			else {
				var avv = _av - _tv; // absoulute variation value
				
				if (avv === 0) {
					fontColor = undefined; 
					valueText = avv;
					u_pot = 0;
					u_pvv = 1;
				}
				else {
					var deltaOpts = {
						'ValueType': 'AbsoluteVariation',
						'ResultIndicationMode': 'GreaterIsGood',
						'ResultIndicationThresholdType': 'Percent',
						'ResultIndicationThreshold': 0	
					};
					$.extend(deltaOpts, _delta);
					
					var pot = _av / _tv * 100; // percent of target
					var pvv = pot - 100; // percent variation
					u_pot = _av / _tv;
					u_pvv = (u_pot * 100 - 100) / 100;
					
					var threshold = true;
					switch(deltaOpts.ResultIndicationThresholdType) {
						case 'Absolute':
							if (deltaOpts.ResultIndicationMode === 'WarningIfGreater' || deltaOpts.ResultIndicationMode === 'WarningIfLess') {
								threshold = avv > Number(deltaOpts.ResultIndicationThreshold); 
							} else {
								threshold = Math.abs(avv) > Number(deltaOpts.ResultIndicationThreshold); 
							}
							break;
						default: // Percent
							if (deltaOpts.ResultIndicationMode === 'WarningIfGreater' || deltaOpts.ResultIndicationMode === 'WarningIfLess') {
								threshold = pvv > Number(deltaOpts.ResultIndicationThreshold); 
							} else {
								threshold = Math.abs(pvv) > Number(deltaOpts.ResultIndicationThreshold); 
							}
							break;
					}
					
					/* DOGFOOT hsshim 2020-02-03 델타 계산 해주는 기능 개선 */
					switch (deltaOpts.ResultIndicationMode) {
						case 'LessIsGood':
							var color = avv > 0 ? 'red' : 'green';
							var ind = avv > 0 ? '▲' : '▼';
							fontColor = threshold ? color : undefined;
							indicator = threshold ? ind : '';
							break;
						case 'WarningIfGreater':
							//2020.07.30 MKSONG DOGFOOT 그리드 델타 폰트 색상 수정
							fontColor = threshold ? 'orange' : 'gray';
							indicator = (threshold ? '●' : ''); 
							break;
						case 'WarningIfLess':
							/* DOGFOOT mksong 2020-08-05 폰트 컬러 그레이 추가 */
							fontColor = !threshold ? 'orange' : 'gray';
							indicator = (!threshold ? '●' : ''); 
							break;
						case 'NoIndication':
							fontColor = 'neutral'; 
							indicator = '';
							break;
						default: // GreaterIsGood
							var color = avv > 0 ? 'green' : 'red';
							var ind = avv > 0 ? '▲' : '▼';
							fontColor = threshold ? color : undefined;
							indicator = threshold ? ind : '';
							break;
					}

					var value;
					switch (deltaOpts.ValueType) {
						case 'ActualValue':
							value = $.number(_av);
//							fontColor = 'neutral';
							break;
						case 'PercentVariation':
							value = $.number(pvv,2) + '%';
							break;
						case 'PercentOfTarget':
							value = $.number(pot,2) + '%';
							break;
						default: // AbsoluteVariation
							value = $.number(avv);
							break;
					}
					
					if(ind == undefined){
						valueText = value;	
					}else{
						valueText = ind + ' ' + value;
					}
					
					/* DOGFOOT hsshim 2020-02-03 끝 */
				}
				
			} // end of if (_av === undefined || _tv === undefined)
			
			return {fc: fontColor, vt: valueText, ind: indicator, avv: avv, pvv: pvv, pot: pot, u_pvv: u_pvv, u_pot: u_pot, sg: siglenValue};
		};
		
		var targetValue = ($.type(subvalues) === 'array' && subvalues[0]);
		var valueTextObject = getValueTextStyle(value, targetValue, delta);
		
		return valueTextObject;
	} // end of makeTextValueObjectOfDeltaOptions
	,Delta: {
		getDeltaValueType: function(_c) {
			var type;
			switch(_c) {
			case 'Absolute Variation': // 변화량
				type = 'absoluteVariation'; break;
			case 'Percent Variation': // 변화비율
				type = 'percentVariation'; break;
			case 'Percent Of Column': // 열기준비율
				type = 'percentOfColumnTotal'; break;
			case 'Percent Of Row': // 행기준비율
				type = 'percentOfRowTotal'; break;
			case 'Percent Of Column GrandTotal': // 열 총합계 기준비율
				type = 'percentOfColumnGrandTotal'; break;
			case 'Percent Of Row GrandTotal': // 행 총합계 기준비율
				type = 'percentOfRowGrandTotal'; break;
			case 'Percent Of GrandTotal': // 총합계 기준비율
				type = 'percentOfGrandTotal'; break;
			};
			return type;
		}
	},//end of DeltaValueType
	AdHoc: {
		getSummaryType: function(number) {
			var result;
			switch(number) {
				case 0:
					result = 'count'; 
					break;
				case 1:
					result = 'sum'; 
					break;
				case 2:
					result = 'min'; 
					break;
				case 3:
					result = 'max'; 
					break;
				case 4:
					result = 'avg'; 
					break;
				/*dogfoot shlim  본사적용 필요 20210701*/
				case 5:
					result = 'countdistinct'; 
					break;
				default:
					result = 'sum';
					break;
			}
			return result;
		}
	}
}; // end of WISE.libs.Dashboard.item.DataUtility 
