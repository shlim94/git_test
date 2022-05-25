/** ChartUtility */
WISE.libs.Dashboard.item.ChartUtility = {
	Constants: {
		axis: {
			name: {
				DEFAULT: 'DEFAULT-AXIS-Y',
				INVISIBLE: 'INVISIBLE-AXIS-Y'
			}
		},
		arguments: {
			name: {
				SINGLE_ARGUMENT: 'SINGLE_ARGUMENT',
				SINGLE_ARGUMENT_VALUE: 'SINGLE_ARGUMENT_VALUE',
				MULTI_ARGUMENT: 'MULTI_ARGUMENT'
			}
		}
	},
	Legend: {
		get: function(_legend) {
			var legend = {}, position;
			
			if (_legend) {
				legend.visible = _legend['Visible'] === false ? false : true;
				legend.position = _legend['IsInsidePosition'] === true ? 'inside' : 'outside';
				
				if (_legend['IsInsidePosition'] === true) {
					position = _legend['InsidePosition'] ? _legend['InsidePosition'].toLowerCase() : '';
					legend.position = 'inside';
				} else {
					position = _legend['OutsidePosition'] ? _legend['OutsidePosition'].toLowerCase() : '';
					legend.position = 'outside';
				}
			}
			
			if (position) {
				// vertical-align
				if (position.indexOf('top') == 0) {
					legend.verticalAlignment = 'top';
				}
				else if (position.indexOf('bottom') == 0) {
					legend.verticalAlignment = 'bottom';
				}
				
				// horizontal-align
				if (position.indexOf('left') > 0) {
					legend.horizontalAlignment = 'left';
				}
				else if (position.indexOf('center') > 0) {
					legend.horizontalAlignment = 'center';
				}
				else if (position.indexOf('right') > 0) {
					legend.horizontalAlignment = 'right';
				}
				
				// orientation
				if (position.indexOf('horizontal') > 0) {
					legend.orientation = 'horizontal';
				}
				else {
					legend.orientation = 'vertical';
				}
				if(legend.verticalAlignment =='top')
				{
					legend.top = 15;
				}
				else{
					legend.bottom = 15;
				}
				if(legend.horizontalAlignment == 'left')
					legend.left = 15;
				else if (legend.horizontalAliginment == 'right')
					legend.right = 15;
				else{
					legend.left = 15;
					legend.right = 15;
				}
			} else {
				if(legend)
				{
					legend.orientation = 'horizontal';
					legend.verticalAlignment = 'top';
					legend.horizontalAlignment = 'right';
				}
				else
				{
					legend = {
						position: 'outside',
						orientation: 'horizontal',
						verticalAlignment: 'top',
						horizontalAlignment: 'right',
						visible:true
					};	
				}
			}
			
			return legend;
		},
		/* DOGFOOT hsshim 2020-02-06 비정형 범례 저장 오류 수정 */
		getAdhoc: function(_position) {
			var result;
			switch (_position) {
				case 'Top':
					result = 'TopLeftHorizontal';
					break;
				case 'Bottom':
					result = 'BottomLeftHorizontal';
					break;
				case 'Left':
					result = 'TopLeftVertical';
					break;
				case 'Right':
					result = 'TopRightVertical';
					break;
				/*dogfoot 차트 기본 범례 저장 불러오기 오류 수정 shlim 20200716*/
				case 'TopRightHorizontal':
					result = 'TopRightHorizontal';
					break;
				default:
					result = _position;
					break;
			}
			return result;
		},
		setAdhoc: function(_position) {
			var result;
			switch (_position) {
				case 'TopLeftHorizontal':
					result = 'Top';
					break;
				case 'BottomLeftHorizontal':
					result = 'Bottom';
					break;
				case 'TopLeftVertical':
					result = 'Left';
					break;
				case 'TopRightVertical':
					result = 'Right';
					break;
				/*dogfoot 차트 기본 범례 저장 불러오기 오류 수정 shlim 20200716*/
				case 'TopRightHorizontal':
					result = 'TopRightHorizontal';
					break;
					
				default:
					result = _position;
			}
			return result;
		}
		/* DOGFOOT hsshim 2020-02-06 비정형 범례 저장 오류 수정 끝 */
	},
	Series: {
		Fn: {
			getSeriesDimensions: function(_seriesDimensions, _dataItem) {
				var seriesDimensions = [];
				var DU = WISE.libs.Dashboard.item.DataUtility;
				
				$.each(_seriesDimensions, function(_i, _osd) {
					var dataMember = DU.getDataMember(_osd.UniqueName, _dataItem);
					seriesDimensions.push(dataMember);
				});
				
				return seriesDimensions;
			},
			getValues: function(_values, _dataItem, _dimesions, _measures) {
				var values = [];
				var DU = WISE.libs.Dashboard.item.DataUtility;
				
				$.each(_values, function(_i, _v) {
					var dataMember = DU.getDataMember(_v.UniqueName, _dataItem, _dimesions, _measures);
					values.push(dataMember);
				});
				
				return values;
			}
		},
		Label: {
			get: function(_pointLabelOptions, _dataMember, _format) {
				var label = {};
				var Number = WISE.util.Number;
				if (_pointLabelOptions) {
					var rotation;
					switch (_pointLabelOptions.Orientation) {
						case '':
							rotation = 0;
							break;
						case 'RotateLeft':
							rotation = 270;
							break;
						case 'RotateRight':
							rotation = 90;
							break;
						default:
							rotation = 0;
							break;
					}
					label = { 
						showForZeroValues: (_pointLabelOptions.ShowForZeroValues === undefined || _pointLabelOptions.ShowForZeroValues === false) ? false : true,
						position: (_pointLabelOptions.Position || 'outside').toLowerCase(),
						rotationAngle: rotation,
						backgroundColor: _pointLabelOptions.FillBackground ? undefined : 'none',
						border: {
							visible: _pointLabelOptions.ShowBorder
						}
					};
					
					label.format = _dataMember.format || undefined;
					label.precision = _dataMember.precision || undefined;
					label.precisionOption = _dataMember.precisionOption || undefined;
					if (_pointLabelOptions.ShowCustomTextColor) {
						label.font = {
							color: _pointLabelOptions.CustomTextColor
						};
					}
					
					var content = _pointLabelOptions.ContentType;
					if (content) {
						label.visible = content !== '';
						label.customizeText = function(_pointInfo) {
							var value = Number.unit(_pointInfo.value, _format.FormatType, _format.Unit, _format.Precision, _format.IncludeGroupSeparator, undefined, _format.Suffix, _format.SuffixEnabled,_format.Precision);
							var text;
							switch(content) {
								case '':
									text
								case 'Argument':
									text = _pointInfo.argumentText; 
									break;
								case 'SeriesName':
									text = _pointInfo.seriesName; 
									break;
								case 'Value':
									text = value;
									break;
								case 'Argument, SeriesName':
									text = _pointInfo.argumentText + ' (' + _pointInfo.seriesName + ')';
									break;
								case 'Argument, Value':
									text = '<b>' + _pointInfo.argumentText + ':</b> ' + value; 
									break;
								case 'SeriesName, Value':
									text = '<b>' + _pointInfo.seriesName + ':</b> ' + value;
									break;
								case 'Argument, SeriesName, Value':
									text = '<b>' + _pointInfo.argumentText + ' (' + _pointInfo.seriesName + '):</b> ' + value;
									break;
								default:
									text = value;
									break;
							}
							
							return text;
						};
					}
				}
				
				return label;
			}
		},
		AxisY: {
			set: function(_P, _plotOnSecondaryAxis, _dataMember, _SYA, _valueAxis, _secondaryAxisName, _paneName) {
				if (_plotOnSecondaryAxis) { 
					if (_SYA) {
						_SYA.label = {format: _dataMember.format || undefined};
					}
					else {
						var hasAlreadySecondaryAxis = function() {
							var checker = false;
							$.each(_valueAxis, function(_ii, _axis) {
								if (_axis.name == _secondaryAxisName) {
									checker = true;
									return false;
								}
							});
							return checker;
						}

						if (!hasAlreadySecondaryAxis()) {
							var secondaryAxis = {
								name: _secondaryAxisName + '',
								position: 'right',
								grid: {visible: true},
								title: _dataMember.name || 'Values',
								label: {format: _dataMember.format || undefined},
								valueType: 'numeric',
								visible: true
							};
							if (_P.length > 1) {
								secondaryAxis.pane = _paneName;
							}
							_valueAxis.push(secondaryAxis);
						}
					}
				}
			},
			getName: function(_plotOnSecondaryAxis, _chartAxisY, _chartAxisYName, _secondaryAxisName) {
				var axisName;
				var CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
				
				if (_plotOnSecondaryAxis) { 
					axisName = _secondaryAxisName;
				}
				else if (_chartAxisY) {
//					if (_chartAxisY && _chartAxisY['Visible'] === false) {
//						axisName = CTN.axis.name.INVISIBLE;
//					} 
//					else {
						axisName = _chartAxisYName;
//					}
				}
				else {
					axisName = CTN.axis.name.DEFAULT;
				}
				
				return axisName;
			}
		},
		Simple: {
			/*SERIES_TYPE: [
			    {name:'Bar',type:'bar',group:'Bar Series'},
			    {name:'Stacked Bar',type:'stackedbar',group:'Bar Series'},
			    {name:'Full-Stacked Bar',type:'fullstackedbar',group:'Bar Series'},
			    {name:'Point',type:'scatter',group:'Line Series'},
			    {name:'Line',type:'line',group:'Line Series'},
			    {name:'Stacked Line',type:'stackedline',group:'Line Series'},
			    {name:'Full-Stacked Line',type:'fullstackedline',group:'Line Series'},
			    {name:'Step Line',type:'stepline',group:'Line Series'},
			    {name:'Spline',type:'spline',group:'Line Series'},
			    {name:'Area',type:'area',group:'Area Series'},
			    {name:'Stacked Area',type:'stackedarea',group:'Area Series'},
			    {name:'Full-Stacked Area',type:'fullstackedarea',group:'Area Series'},
			    {name:'Step Area',type:'steparea',group:'Area Series'},
			    {name:'Spline Area',type:'splinearea',group:'Area Series'},
			    {name:'Stacked Spline Area',type:'stackedsplinearea',group:'Area Series'},
			    {name:'Full-Stacked Spline Area',type:'fullstackedsplinearea',group:'Area Series'}
			],*/
			SERIES_TYPE: [
			    {name:'바',type:'bar',group:'Bar Series'},
			    {name:'스택바',type:'stackedbar',group:'Bar Series'},
			    {name:'풀스택바',type:'fullstackedbar',group:'Bar Series'},
			    {name:'포인트',type:'scatter',group:'Line Series'},
			    {name:'라인',type:'line',group:'Line Series'},
			    {name:'스택라인',type:'stackedline',group:'Line Series'},
			    {name:'풀스택라인',type:'fullstackedline',group:'Line Series'},
			    {name:'스텝라인',type:'stepline',group:'Line Series'},
			    {name:'SP라인',type:'spline',group:'Line Series'},
			    {name:'에리어',type:'area',group:'Area Series'},
			    {name:'스택에리어',type:'stackedarea',group:'Area Series'},
			    {name:'풀스택에리어',type:'fullstackedarea',group:'Area Series'},
			    {name:'스텝에리어',type:'steparea',group:'Area Series'},
			    {name:'SP라인에리어',type:'splinearea',group:'Area Series'},
			    {name:'스텍SP라인에리어',type:'stackedsplinearea',group:'Area Series'},
			    {name:'풀스택SP라인에리어',type:'fullstackedsplinearea',group:'Area Series'}
			],
			getSeriesType: function(_type) {
				var type = (_type || '').toLowerCase();
				
				switch(type) {
				case 'point': 
					type = 'scatter'; break;
//				case 'stackedsplinearea': 
//					type = 'stackedarea'; 
//					WISE.libs.Dashboard.MessageHandler.info({msg: '지원하지 않는 차트 타입입니다. Stacked Area 타입으로 보여집니다.'});
//					break;
//				case 'fullstackedsplinearea': 
//					type = 'fullstackedarea';
//					WISE.libs.Dashboard.MessageHandler.info({msg: '지원하지 않는 차트 타입입니다. Full Stacked Area 타입으로 보여집니다.'});
//					break;
				}
				
				return type || 'bar';
			},
			getChartNumber:function(_num){
				var chartNumber = '';
				switch(_num) {
				case 'scatter': 
					chartNumber = 'point'; break;
				case 'fullstackedarea' :
					chartNumber = 16; break;
				case 'stackedarea' :
					chartNumber = 15; break;
				case 'splinearea' :
					chartNumber = 14; break;
				case 'area' :
					chartNumber = 13; break;
				case 'fullstackedbar' :
					chartNumber = 12; break;
				case 'stackedbar' :
					chartNumber = 11; break;
				case 'bar' :
					chartNumber = 10; break;
				case 'fullstackedbar' :
					chartNumber = 9; break;
				case 'stackedbar' :
					chartNumber = 8; break;
				case 'bar' :
					chartNumber = 7; break;
// case 'fastline' :
// chartNumber = 6; break;
				case 'stepline' :
					chartNumber = 5; break;
				case 'spline' :
					chartNumber = 4; break;
				case 'line' :
					chartNumber = 3; break;
				default :
					chartNumber = 10; break;
				}
				return chartNumber;
			},
			getChartName:function(_num){
				var chartName;
				switch(_num) {
					case 'point' : 
						chartName = 'Scatter'; break;
					case 16:
						chartName = 'FullStackedArea'; break;
					case 15:
						chartName = 'StackedArea'; break;
					case 14:
						chartName = 'SplineArea'; break;
					case 13:
						chartName = 'Area'; break;
					case 12:
						chartName = 'FullStackedBar'; break;
					case 11:
						chartName = 'StackedBar'; break;
					case 10:
						chartName = 'Bar'; break;
					case 9:
						chartName = 'FullStackedBar'; break;
					case 8:
						chartName = 'StackedBar'; break;
					case 7:
						chartName = 'Bar'; break;
					case 6:
						chartName = 'Line'; break;
					case 5:
						chartName = 'StepLine'; break;
					case 4:
						chartName = 'Spline'; break;
					case 3:
						chartName = 'Line'; break;
					default:
						chartName = 'Bar'; break;
				}
				return chartName;
			}
		}
	},
	/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
	Data: {
		/**
		 * Return DATA_ELEMENT object from CHART_XML that has CTRL_NM value of _uniqueName.
		 * If object does not exist, return an empty object.
		 * @param {Object} _chartXml CHART_XML schema. 
		 * @param {*} _uniqueName Unique CTRL_NM value.
		 */
		getDataElement: function(_chartXml, _uniqueName) {
			var result = {};
			$.each(WISE.util.Object.toArray(_chartXml.DATA_ELEMENT), function(i, dataElement) {
				if (dataElement.CTRL_NM === _uniqueName) {
					result = dataElement;
					return false;
				}
			});
			return result;
		}
	}
}; // end of WISE.libs.Dashboard.item.ChartUtility
