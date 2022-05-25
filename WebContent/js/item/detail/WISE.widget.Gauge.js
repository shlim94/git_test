/* DOGFOOT hsshim 2020-02-03 카드 적용 (전체 파일 수정) */
/**
 * Gauge widget generator class.
 */
WISE.libs.Dashboard.item.GaugeGenerator = function() {
	var self = this;
	this.type = 'GAUGE_CHART';
	
	this.dashboardid;
	this.itemid;
	this.dxItem = [];
	this.dataSourceId;
	
	this.dimensions = [];
	this.measures = [];
	
	this.Gauge = {};
	this.gaugeElements = [];
	this.seriesDimensions = [];
	
	this.scale;
	this.panelManager;
	this.gaugeTypeByContainerId = {};
	
	this.drillDownIndex; // must be number type
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	/**
	 * Get gauge dxItemConfig.
	 * 
	 * @param _gauge: meta object
	 * @param _osd: series data object {sn:'', d:[]}
	 * @param _ovp: value panel information object {sn:'', panel: ''}
	 * @param _pid: gauge panel container id
	 */
	this.getDxItemConfig = function(_gauge, _osd, _ovp, _pid) {
		/*
		 * CircularFull (default)
		 * CircularHalf
		 * CircularQuarterLeft
		 * CircularQuarterRight
		 * CircularThreeFourth
		 * LinearHorizontal
		 * LinearVertical
		 */
		var geometry = {};
		var title = {
			text: _gauge['ShowGaugeCaptions'] === false ? '' : _osd.t,
			subtitle: {
				text: _gauge['ShowGaugeCaptions'] === false ? '' : _osd.st
			}
		};
		switch(_gauge['ViewType']) {
		case 'CircularHalf':
			geometry.startAngle = 180;
			geometry.endAngle = 0;
			title.verticalAlignment = 'bottom';
			break;
		case 'CircularQuarterLeft':
			geometry.startAngle = 180;
			geometry.endAngle = 90;
			title.verticalAlignment = 'top';
			break;
		case 'CircularQuarterRight':
			geometry.startAngle = 90;
			geometry.endAngle = 0;
			title.verticalAlignment = 'top';
			break;
		case 'CircularThreeFourth':
			title.verticalAlignment = 'bottom';
			break;
		case 'LinearHorizontal':
			geometry.orientation = 'horizontal';
			break;
		case 'LinearVertical':
			geometry.orientation = 'vertical';
			break;
		default:
			geometry.startAngle = 270;
			geometry.endAngle = 270;
			title.verticalAlignment = 'bottom';
		}
		
//		title.verticalAlignment = 'top';
		
		var value = 0;
		var subValues = [];
		var gaugeData = WISE.util.Object.toArray(_osd.d);
		if (gaugeData.length === 1) {
			var DIO = gaugeData[0];
			if ( $.type(_ovp.sn) === 'string' || $.type(_ovp.sn)=== 'number') {
				value = DIO[_ovp.sn];
				if ( $.type(_ovp.ssn) === 'string' || $.type(_ovp.ssn)=== 'number') {
					subValues.push(DIO[_ovp.ssn]);
				}
			}
			else {
				if ( $.type(_ovp.ssn) === 'string' || $.type(_ovp.ssn)=== 'number') {
					value = DIO[_ovp.ssn];
				}
			}
		}
		else {
			WISE.alert('데이터가 없거나 1이상 입니다. 데이터건수[' + (_osd.d && _osd.d.length) + ']');
		}
		
		var scaleStartValue, scaleEndValue;
		if (_ovp.scale && $.type(_ovp.scale.min) === 'number') {
			scaleStartValue = parseInt(_ovp.scale.min,10);
			scaleStartValue = scaleStartValue - parseInt(scaleStartValue * 0.2, 10);
			if (scaleStartValue < 0) {
				scaleStartValue = 0;
			}
		}
		else {
			scaleStartValue = 0;
		}
		
		if (_ovp.scale && $.type(_ovp.scale.max) === 'number') {
			scaleEndValue = parseInt(parseInt(_ovp.scale.max,10) * 1.2, 10);
		}
		else {
			scaleEndValue = parseInt(parseInt(subValues[0] === undefined ? value : subValues[0],10) * 1.2, 10);
		}
		
		var remain = scaleEndValue % 10;
		if (remain> 0 ) {
			scaleEndValue += (10 - remain);
		}
		
		var tickInterval;
		if (scaleEndValue <= 20) {
			tickInterval = 2;
		}
		else if (scaleEndValue > 10 && scaleEndValue <= 20) {
			tickInterval = 4;
		}
		else if (scaleEndValue > 20 && scaleEndValue <= 30) {
			tickInterval = 5;
		}
		else {
			tickInterval = parseInt(scaleEndValue / 4, 10);
		}

		var dxConfigs = {
			title: title,
			// title and subtitle must be saved separately for show/hide caption functionality
			wiseTitle: _osd.t,
			wiseSubtitle: _osd.st,
			loadingIndicator: {
				text: gMessage.get('WISE.message.page.common.loding'),
				backgroundColor: '#eaeaea',
				font: {
					weight: 700
				},
				show: true
			},
			scale: {
	            startValue: scaleStartValue,
	            endValue: scaleEndValue,
	            tickInterval: tickInterval,
	            tick: {
	                visible: true,
	                color: 'black',
	                length: 10
	            },
	            label: {
	                indentFromTick: 0,
	                customizeText: function (arg) {
	                	var unit = scaleEndValue+'';
	                	var val = arg.value;
	                	if (unit.length > 10) {
	                		return WISE.util.Number.unit(val,'B');
	                	}
	                	else if (unit.length <= 10 && unit.length >= 7) {
	                		return WISE.util.Number.unit(val,'M');
	                	}
	                	else if (unit.length <= 7 && unit.length >= 4) {
	                		return WISE.util.Number.unit(val,'K');
	                	}
	                	else {
	                		return WISE.util.Number.unit(val);
	                	}
	                }
	            }
	        },
			value: value,
			valueIndicator: (geometry.orientation && {}) || {
	            type: 'twoColorNeedle',
	            color: 'gray',
	            secondColor: 'red',
	            width: 2,
	            spindleSize: 20,
	            spindleGapSize: 15
	        },
			subvalues: subValues,
			subvalueIndicator: {
				type: 'triangleMarker',
	            color: 'blue',
//	            length: 20,
	            offset: -25
			},
			tooltip: (WISE.Constants.browser === 'SAFARI' ? {} : {
		        enabled: true,
//		        format: 'percent',
		        precision: 2,
		        font: {
		            size: 20,
		            weight: 700
		        }
		    }),
			geometry: geometry,
	        redrawOnResize: true,
	        wiseGaugeType: ((_gauge['ViewType'] || '').indexOf('Linear') === 0 ? 'linear' : 'circular')
		};
		
		self.gaugeTypeByContainerId[_pid] = dxConfigs.wiseGaugeType;

		return dxConfigs;
	};
	
	/**
	 * @override
	 * Generate gauge widget metadata.
	 * 
	 * @param _gauge initial gauge metadata
	 * @param _options additional parameters for specific actions
	 */
	this.generate = function(_gauge, _options) {
		if (_options && _options.containerid) {
			self.itemid = _options.containerid;
		} 
		
		self.meta = _gauge;
		self.dataSourceId = _gauge['DataSource'];
		
		self.DI = _gauge.DataItems;
		self.GE = WISE.util.Object.toArray(_gauge.GaugeElement || []);
		self.SD = WISE.util.Object.toArray((_gauge.SeriesDimensions && _gauge.SeriesDimensions.SeriesDimension) || []);
		self.IO = _gauge.InteractivityOptions;
		
		self.DU = WISE.libs.Dashboard.item.DataUtility;
		self.CU = WISE.libs.Dashboard.item.ChartUtility;
		self.CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
		
		self.panelManager = new WISE.libs.Dashboard.item.GaugeGenerator.PanelManager();
		self.panelManager.itemid = self.itemid;
		
		// gauge element setting 
		self.gaugeElements = [];
		self.measures = [];
		self.dimensions = [];
		var seq = 0;
		$.each(self.GE, function(_i0, _a0) {
			var o = {wiseId: new Date().valueOf() + (seq++)};
			
			if ($.type(_a0['ActualValue']) === 'object') {
				var actualUniqueName = _a0['ActualValue']['UniqueName'];
				var actualDataMember = self.DU.getDataMember(actualUniqueName, self.DI, self.dimensions, self.measures);
				o.actual = actualDataMember;
			}
			
			if ($.type(_a0['TargetValue']) === 'object') {
				var targetUniqueName = _a0['TargetValue']['UniqueName'];
				var targetDataMember = self.DU.getDataMember(targetUniqueName, self.DI, self.dimensions, self.measures);
				o.target = targetDataMember;
			}
			
			/* DeltaOptions>> 
			 * ValueType = "ActualValue", "AbsoluteVariation", "PercentVariation", "PercentOfTarget" - AbsoluteVariation
			 * ResultIndicationMode = "GreaterIsGood", "LessIsGood", "WarningIfGreater", "WarningIfLess", "NoIndication" - GreaterIsGood
			 * ResultIndicationThresholdType = "Absolute", "Percent" - Percent
			 * ResultIndicationThreshold = "50" - 0
			 * */
			o.deltaOptions = _a0['DeltaOptions'];
			
			o.scale = {min: _a0.Minimum, max: _a0.Maximum};
	
			self.gaugeElements.push(o);
			
			if (self.IO && self.IO['IsDrillDownEnabled']) {
				self.drillDownIndex = 1;
				return false;
			}
		});
		
		// setting series-dimensions informations
		self.seriesDimensions = self.CU.Series.Fn.getSeriesDimensions(self.SD, self.DI);
		
		if (_gauge.Values && _gauge.Values.length > 0) {
			self.measures = _gauge.Values;
		}

		if (self.seriesDimensions.length > 0) {
			self.dimensions = self.dimensions.concat(self.seriesDimensions);
		}

		// setting gauge top-icon
		if (!self.initialized) {
			self.renderButtons(self.itemid);
			if($('#'+self.itemid+'_topicon').length != 0){
				self.initialized = true;	
			}else{
				self.initialized = false;
			}
		}
		
		// to display no-data text
		if (!self.CUSTOMIZED.get('searchOnStart','Config')) {
			self.bindData([]); 
		}
	};

	this.setTackingFlag = function(chk) {
		self.tracked = chk;
	};

	/**
	 * @override
	 * Link a dataset to gauge instance.
	 * @param _data query data in JSON format
	 */
	this.bindData = function(_data, _activePanelId) {
		self.gaugeTypeByContainerId = [];
		if (!self.tracked) {
			self.globalData = _.clone(_data);
			self.filteredData = _.clone(_data);
		}
		
		$("#" + self.itemid).empty();
		
		if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
			var nodataHtml = '<div class="nodata-layer"></div>';
			$("#" + self.itemid).empty().append(nodataHtml);
		}
		else {
			self.renderGauge(_data);
		}
	};

	/**
	 * Render gauge widget.
	 * @param {Object[]} _data Gauge widget data
	 * @param {boolean} _functionDo Iif true, skip loading fields and metadata
	 */
	this.renderGauge = function(_data, _functionDo) {
		self.dxItem = [];
		// Initialize fields and item options if _functionDo is false. Update GaugeGenerator instance.
		if (_functionDo) {
			this.generate(self.meta);
		} else if (self.fieldManager != null && gDashboard.isNewReport) { // 신규 생성
			self.setGauge('new');
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self, self.Gauge);
			self.generate(self.Gauge);
		}
		else if (self.fieldManager) { // 레포트 열기
			self.setGauge('open');
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self, self.Gauge);
			self.generate(self.Gauge);
		}
		else if (self.meta && $.isEmptyObject(self.Gauge)) {
			self.setGauge('view');
			gDashboard.itemGenerateManager.itemCustomize(self, self.Gauge);
			self.generate(self.Gauge);
		}
		self.panelManager.init();
		
		// if has series-dimensions, then add series-dimensions to self.dimesions
		var distinctDataBasten = [];
		if (self.seriesDimensions.length > 0) {
			self.dimensions = self.dimensions.concat(self.seriesDimensions);

			/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
			gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
			$.each(self.seriesDimensions, function(_i, _dim) {
				var distinctData = WISE.libs.Dashboard.Query.likeSql.fromJson([_dim], [], _data);
				distinctDataBasten.push(distinctData);
			});
		}
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		
		self.panelManager.distinctDataBasten = distinctDataBasten;
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		var noSeriesDimensionData = WISE.libs.Dashboard.Query.likeSql.fromJson(self.dimensions, self.measures, _data, {orderBy: self.measures});
		self.scale = self.panelManager.scale = self.getSeriesScale(noSeriesDimensionData, self.measures);
		self.panelManager.makePanel(self.gaugeElements, self.seriesDimensions, _data, self.dimensions, self.measures);
		
		// generate gauge
		if (self.seriesDimensions && self.seriesDimensions.length > 0) {
			$.each(self.panelManager.gaugePanel, function(_pn, _ovp) {
				$.each(self.panelManager.finalData, function(_i, _osd) {
					var pid = _pn + '_' + _i;
					var dxConfigs = self.getDxItemConfig(self.meta, _osd, _ovp, pid);
					var dxItem;
					switch(dxConfigs.wiseGaugeType) {
					case 'linear':
						dxItem = $('#' + pid).dxLinearGauge(dxConfigs).dxLinearGauge("instance");
						break;
					default:
						dxItem = $('#' + pid).dxCircularGauge(dxConfigs).dxCircularGauge("instance");
					}
					
					var deltaOptions = {
						value: dxConfigs.value,
						subvalues: dxConfigs.subvalues,
						delta: self.Gauge.GaugeElement.DeltaOptions
					};
					self.applyDeltaValue(pid, deltaOptions);

					self.dxItem.push(dxItem);
				});
			});
		} 
		else {
			$.each(self.panelManager.gaugePanel, function(_pn, _ovp) {
				$.each(self.gaugeElements, function(_i, _vo) {
					var seriesName, seriesValue, subSeriesValue;
					if (_vo.actual) {
						seriesName = _vo.actual.captionBySummaryType;
						seriesValue = _vo.actual.nameBySummaryType;
						if (_vo.target) {
							seriesName += ' vs ' + _vo.target.captionBySummaryType;
							subSeriesValue = _vo.target.nameBySummaryType;
						}
					}
					else {
						if (_vo.target) {
							seriesName = _vo.target.captionBySummaryType;
							seriesValue = _vo.target.nameBySummaryType;
						}
					}
					
					var pid = _pn + '_' + _i;
					var osd = {sn: seriesName, d: noSeriesDimensionData};
					var ovp = _ovp;
					ovp.sn = seriesValue;
					ovp.ssn = subSeriesValue;
					
					if ($.type(_vo.scale.max) === 'number' || $.type(_vo.scale.min) === 'number') {
						ovp.scale = _vo.scale;
					}
					
					var scale = (function(_s) {
						var s = {min:0,max:0};
						$.each(_s, function(_k,_oo) {
							if (s.min > _oo.min) {
								s.min = _oo.min;
							}
							if (s.max < _oo.max) {
								s.max = _oo.max;
							}
						}); 
						return s;
					})(self.scale);
					ovp.scale = scale;

					var dxConfigs = self.getDxItemConfig(self.meta, osd, ovp, pid);
					var dxItem;
					switch(dxConfigs.wiseGaugeType) {
					case 'linear':
						dxItem = $('#' + pid).dxLinearGauge(dxConfigs).dxLinearGauge("instance");
						break;
					default:
						dxItem = $('#' + pid).dxCircularGauge(dxConfigs).dxCircularGauge("instance");
					}
					var deltaOptions = {
						value: dxConfigs.value,
						subvalues: dxConfigs.subvalues,
						delta: self.Gauge.GaugeElement.DeltaOptions
					};
					self.applyDeltaValue(pid, deltaOptions);
					
					self.dxItem.push(dxItem);
				});
			});
		}
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
	};

	/**
	 * Create gauge meta.
	 * 
	 * @param {string} type Type of report meta to generate. (ie. "new", "open" or "view")
	 */
	this.setGauge = function(type) {
		// set field values
		if (type === 'new') {
			self.fieldManager.init();
			self.fieldManager.getherFields(self.fieldManager);
			self.Gauge.DataItems = self.fieldManager.DataItems;
			self.Gauge.Values = self.fieldManager.values;
			self.Gauge.SeriesDimensions = self.fieldManager.SeriesDimensions;
			if (typeof self.Gauge.GaugeElement === 'undefined') {
				self.Gauge.GaugeElement = {};
			}
			self.Gauge.GaugeElement.ActualValue = self.fieldManager.ActualValue;
			self.Gauge.GaugeElement.TargetValue = self.fieldManager.TargetValue;
		} else if (type === 'open') {
			// load initial meta
			if (typeof self.meta == 'undefined') {
				self.setGauge('new');
				return;
			}
			else {
				self.Gauge = self.meta;
			}
			if (!self.fieldManager.initialized) {
				// load CHART_XML options
				self.fieldManager.init();
				var webGaugeDataElement = {};
				var tempWCDE;
				if (typeof gDashboard.structure.MapOption.DASHBOARD_XML !== 'undefined') {
					tempWCDE = gDashboard.structure.MapOption.DASHBOARD_XML.WEB ? WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.GAUGE_DATA_ELEMENT) : [];
				} else {
					tempWCDE = [];
				}
				$.each(tempWCDE,function(_i,_e){
					if(_e.CTRL_NM == self.meta.ComponentName){
						webGaugeDataElement = _e;
						return false;
					}
				});
				// initialize format options from GAUGE_XML
				$.each(WISE.util.Object.toArray(self.Gauge.DataItems.Measure), function(_i, _mea) {
					$.each(WISE.util.Object.toArray(webGaugeDataElement.MEASURES), function(_k, _measure) {
						if (_mea.UniqueName === _measure.UNI_NM) {
							_mea.NumericFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
							_mea.NumericFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
							return false;
						}
					});
				});
				if (webGaugeDataElement.ABSOLUTE_VARIATION) {
					self.Gauge.GaugeElement.AbsoluteVariationNumericFormat = _.clone(webGaugeDataElement.ABSOLUTE_VARIATION);
				}
				if (webGaugeDataElement.PERCENT_VARIATION) {
					self.Gauge.GaugeElement.PercentVariationNumericFormat = _.clone(webGaugeDataElement.PERCENT_VARIATION);
				}
				if (webGaugeDataElement.PERCENT_OF_TARGET) {
					self.Gauge.GaugeElement.PercentOfTargetNumericFormat = _.clone(webGaugeDataElement.PERCENT_OF_TARGET);
				}
				if (webGaugeDataElement.SCALE_LABEL) {
					self.Gauge.GaugeElement.ScaleLabelNumericFormat = _.clone(webGaugeDataElement.SCALE_LABEL);
				}
			} else {
				self.fieldManager.getherFields(self.fieldManager);
				self.Gauge.DataItems = self.fieldManager.DataItems;
				self.Gauge.Values = self.fieldManager.values;
				self.Gauge.SeriesDimensions = self.fieldManager.SeriesDimensions;
				if (typeof self.Gauge.GaugeElement === 'undefined') {
					self.Gauge.GaugeElement = {};
				}
				self.Gauge.GaugeElement.ActualValue = self.fieldManager.ActualValue;
				self.Gauge.GaugeElement.TargetValue = self.fieldManager.TargetValue;
			}
		} else if (type === 'view') {
			self.Gauge = self.meta;
			var webGaugeDataElement = {};
			var tempWCDE;
			if (typeof gDashboard.structure.MapOption.DASHBOARD_XML !== 'undefined') {
				tempWCDE = gDashboard.structure.MapOption.DASHBOARD_XML.WEB ? WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.GAUGE_DATA_ELEMENT) : [];
			} else {
				tempWCDE = [];
			}
			$.each(tempWCDE,function(_i,_e){
				var CtrlNM = _e.CTRL_NM + "_" + WISE.Constants.pid;
				if(CtrlNM == self.meta.ComponentName){
					webGaugeDataElement = _e;
					return false;
				}
			});
			// initialize missing measure numeric formats
			$.each(WISE.util.Object.toArray(self.Gauge.DataItems.Measure),function(_i,_mea){
				var dataNumFormat = _mea.NumericFormat || {};
				if (typeof dataNumFormat.FormatType === 'undefined') {
					dataNumFormat.FormatType = 'Number';
				}
				if (typeof dataNumFormat.Unit === 'undefined') {
					dataNumFormat.Unit = _i === 0 ? 'Ones' : 'Auto';
				}
				if (typeof dataNumFormat.Precision === 'undefined') {
					dataNumFormat.Precision = 0;
				}
				if (typeof dataNumFormat.IncludeGroupSeparator === 'undefined') {
					dataNumFormat.IncludeGroupSeparator = _i === 0 ? true : false;
				}
				if (typeof dataNumFormat.SuffixEnabled === 'undefined') {
					dataNumFormat.SuffixEnabled = false;
				}
				if (typeof dataNumFormat.Suffix === 'undefined') {
					dataNumFormat.Suffix = { 
						O: '', 
						K: '천', 
						M: '백만', 
						B: '십억' 
					};
				}
				$.each(WISE.util.Object.toArray(webGaugeDataElement.MEASURES), function(_k, _measure) {
					if (_mea.UniqueName === _measure.UNI_NM) {
						dataNumFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
						dataNumFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
						return false;
					}
				});
				_mea.NumericFormat = dataNumFormat;
			});
			if (webGaugeDataElement.ABSOLUTE_VARIATION) {
				self.Gauge.GaugeElement.AbsoluteVariationNumericFormat = _.clone(webGaugeDataElement.ABSOLUTE_VARIATION);
			}
			if (webGaugeDataElement.PERCENT_VARIATION) {
				self.Gauge.GaugeElement.PercentVariationNumericFormat = _.clone(webGaugeDataElement.PERCENT_VARIATION);
			}
			if (webGaugeDataElement.PERCENT_OF_TARGET) {
				self.Gauge.GaugeElement.PercentOfTargetNumericFormat = _.clone(webGaugeDataElement.PERCENT_OF_TARGET);
			}
			if (webGaugeDataElement.SCALE_LABEL) {
				self.Gauge.GaugeElement.ScaleLabelNumericFormat = _.clone(webGaugeDataElement.SCALE_LABEL);
			}
		}
		// set general values
		if (typeof self.Gauge.ComponentName === 'undefined') {
			self.Gauge.ComponentName = self.ComponentName;
		}
		if (typeof self.Gauge.DataSource === 'undefined') {
			self.Gauge.DataSource = self.dataSourceId;
		}else if(self.Gauge.DataSource != self.dataSourceId){
			self.Gauge.DataSource = self.dataSourceId;
		}
		if (typeof self.Gauge.Name === 'undefined') {
			self.Gauge.Name = self.Name;
		}
		if (typeof self.Gauge.ShowCaption === 'undefined') {
			self.Gauge.ShowCaption = true;
		}
		// TODO 열/행 정렬 기능
		/* if (typeof self.Gauge.ContentArrangementMode === 'undefined') {
			self.Gauge.ContentArrangementMode = 'Auto';
		}
		if (typeof self.Gauge.ContentLineCount === 'undefined') {
			self.Gauge.ContentLineCount = 3;
		} */
		if (typeof self.Gauge.ViewType === 'undefined') {
			self.Gauge.ViewType = 'CircularFull';
		}
		if (typeof self.Gauge.ShowGaugeCaptions === 'undefined') {
			self.Gauge.ShowGaugeCaptions = true;
		}

		// set gauge element options
		if (typeof self.Gauge.GaugeElement.Minimum === 'undefined') {
			self.Gauge.GaugeElement.MinimumEnabled = false;
			self.Gauge.GaugeElement.Minimum = 0;
		} else {
			self.Gauge.GaugeElement.MinimumEnabled = true;
		}
		if (typeof self.Gauge.GaugeElement.Maximum === 'undefined') {
			self.Gauge.GaugeElement.MaximumEnabled = false;
			// TODO 최대값 자동으로 가져오기
			self.Gauge.GaugeElement.Maximum = 0;
		} else {
			self.Gauge.GaugeElement.MaximumEnabled = true;
		}

		// set gauge delta options
		if (typeof self.Gauge.GaugeElement.DeltaOptions === 'undefined') {
			self.Gauge.GaugeElement.DeltaOptions = {
				ResultIndicationMode: 'GreaterIsGood',
				ResultIndicationThresholdType: 'Percent',
				ResultIndicationThreshold: 0,
				ValueType: 'AbsoluteVariation'
			};
		} else {
			if (typeof self.Gauge.GaugeElement.DeltaOptions.ResultIndicationMode === 'undefined') {
				self.Gauge.GaugeElement.DeltaOptions.ResultIndicationMode = 'GreaterIsGood';
			}
			if (typeof self.Gauge.GaugeElement.DeltaOptions.ResultIndicationThresholdType === 'undefined') {
				self.Gauge.GaugeElement.DeltaOptions.ResultIndicationThresholdType = 'Percent';
			}
			if (typeof self.Gauge.GaugeElement.DeltaOptions.ResultIndicationThreshold === 'undefined') {
				self.Gauge.GaugeElement.DeltaOptions.ResultIndicationThreshold = 0;
			}
			if (typeof self.Gauge.GaugeElement.DeltaOptions.ValueType === 'undefined') {
				self.Gauge.GaugeElement.DeltaOptions.ValueType = 'AbsoluteVariation';
			}
		}
		// set gauge absolute variation numeric format
		if (typeof self.Gauge.GaugeElement.AbsoluteVariationNumericFormat !== 'object') {
			self.Gauge.GaugeElement.AbsoluteVariationNumericFormat = {
				FormatType: 'Number',
				Unit: 'Auto',
				SuffixEnabled: false,
				Suffix: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				IncludeGroupSeparator: false
			};
		} else {
			if (typeof self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.FormatType === 'undefined') {
				self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.FormatType = 'Number';
			}
			if (typeof self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.Unit === 'undefined') {
				self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.Unit = 'Auto';
			}
			if (typeof self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.SuffixEnabled === 'undefined') {
				self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.SuffixEnabled = false;
			}
			if (typeof self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.Suffix === 'undefined') {
				self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.Suffix = {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				};
			}
			if (typeof self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.Precision === 'undefined') {
				self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.Precision = 0;
			}
			if (typeof self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.IncludeGroupSeparator === 'undefined') {
				self.Gauge.GaugeElement.AbsoluteVariationNumericFormat.IncludeGroupSeparator = false;
			}
		}
		// set gauge percent variation numeric format
		if (typeof self.Gauge.GaugeElement.PercentVariationNumericFormat !== 'object') {
			self.Gauge.GaugeElement.PercentVariationNumericFormat = {
				FormatType: 'Percent',
				Unit: 'Auto',
				SuffixEnabled: false,
				Suffix: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 2,
				IncludeGroupSeparator: false
			};
		} else {
			if (typeof self.Gauge.GaugeElement.PercentVariationNumericFormat.FormatType === 'undefined') {
				self.Gauge.GaugeElement.PercentVariationNumericFormat.FormatType = 'Percent';
			}
			if (typeof self.Gauge.GaugeElement.PercentVariationNumericFormat.Unit === 'undefined') {
				self.Gauge.GaugeElement.PercentVariationNumericFormat.Unit = 'Auto';
			}
			if (typeof self.Gauge.GaugeElement.PercentVariationNumericFormat.SuffixEnabled === 'undefined') {
				self.Gauge.GaugeElement.PercentVariationNumericFormat.SuffixEnabled = false;
			}
			if (typeof self.Gauge.GaugeElement.PercentVariationNumericFormat.Suffix === 'undefined') {
				self.Gauge.GaugeElement.PercentVariationNumericFormat.Suffix = {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				};
			}
			if (typeof self.Gauge.GaugeElement.PercentVariationNumericFormat.Precision === 'undefined') {
				self.Gauge.GaugeElement.PercentVariationNumericFormat.Precision = 2;
			}
			if (typeof self.Gauge.GaugeElement.PercentVariationNumericFormat.IncludeGroupSeparator === 'undefined') {
				self.Gauge.GaugeElement.PercentVariationNumericFormat.IncludeGroupSeparator = false;
			}
		}
		// set gauge percent of target numeric format
		if (typeof self.Gauge.GaugeElement.PercentOfTargetNumericFormat !== 'object') {
			self.Gauge.GaugeElement.PercentOfTargetNumericFormat = {
				FormatType: 'Percent',
				Unit: 'Auto',
				SuffixEnabled: false,
				Suffix: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 2,
				IncludeGroupSeparator: false
			};
		} else {
			if (typeof self.Gauge.GaugeElement.PercentOfTargetNumericFormat.FormatType === 'undefined') {
				self.Gauge.GaugeElement.PercentOfTargetNumericFormat.FormatType = 'Percent';
			}
			if (typeof self.Gauge.GaugeElement.PercentOfTargetNumericFormat.Unit === 'undefined') {
				self.Gauge.GaugeElement.PercentOfTargetNumericFormat.Unit = 'Auto';
			}
			if (typeof self.Gauge.GaugeElement.PercentOfTargetNumericFormat.SuffixEnabled === 'undefined') {
				self.Gauge.GaugeElement.PercentOfTargetNumericFormat.SuffixEnabled = false;
			}
			if (typeof self.Gauge.GaugeElement.PercentOfTargetNumericFormat.Suffix === 'undefined') {
				self.Gauge.GaugeElement.PercentOfTargetNumericFormat.Suffix = {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				};
			}
			if (typeof self.Gauge.GaugeElement.PercentOfTargetNumericFormat.Precision === 'undefined') {
				self.Gauge.GaugeElement.PercentOfTargetNumericFormat.Precision = 2;
			}
			if (typeof self.Gauge.GaugeElement.PercentOfTargetNumericFormat.IncludeGroupSeparator === 'undefined') {
				self.Gauge.GaugeElement.PercentOfTargetNumericFormat.IncludeGroupSeparator = false;
			}
		}
		// set gauge scale label numeric format
		if (typeof self.Gauge.GaugeElement.ScaleLabelNumericFormat !== 'object') {
			self.Gauge.GaugeElement.ScaleLabelNumericFormat = {
				FormatType: 'Number',
				Unit: 'Auto',
				SuffixEnabled: false,
				Suffix: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				IncludeGroupSeparator: false
			};
		} else {
			if (typeof self.Gauge.GaugeElement.ScaleLabelNumericFormat.FormatType === 'undefined') {
				self.Gauge.GaugeElement.ScaleLabelNumericFormat.FormatType = 'Auto';
			}
			if (typeof self.Gauge.GaugeElement.ScaleLabelNumericFormat.Unit === 'undefined') {
				self.Gauge.GaugeElement.ScaleLabelNumericFormat.Unit = 'Auto';
			}
			if (typeof self.Gauge.GaugeElement.ScaleLabelNumericFormat.SuffixEnabled === 'undefined') {
				self.Gauge.GaugeElement.ScaleLabelNumericFormat.SuffixEnabled = false;
			}
			if (typeof self.Gauge.GaugeElement.ScaleLabelNumericFormat.Suffix === 'undefined') {
				self.Gauge.GaugeElement.ScaleLabelNumericFormat.Suffix = {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				};
			}
			if (typeof self.Gauge.GaugeElement.ScaleLabelNumericFormat.Precision === 'undefined') {
				self.Gauge.GaugeElement.ScaleLabelNumericFormat.Precision = 0;
			}
			if (typeof self.Gauge.GaugeElement.ScaleLabelNumericFormat.IncludeGroupSeparator === 'undefined') {
				self.Gauge.GaugeElement.ScaleLabelNumericFormat.IncludeGroupSeparator = false;
			}
		}
		self.meta = self.Gauge;
	};

	/**
	 * Return the range scale for the gauge widget.
	 * 
	 * @param _data gauge data values
	 * @param _measures metadata of gauge values
	 */
	this.getSeriesScale = function(_data, _measures) {
		var scale = {};
		if ($.type(_data) === 'array' && _data.length > 0) {
			$.each(_data, function(_i0, _d0) {
				$.each(_measures, function(_i2, _d2) {
					if (_.has(_d0, _d2.nameBySummaryType)) {
						if (!scale[_d2.nameBySummaryType]) {
							var oMin = _.min(_data, function(_stooges){ return _stooges[_d2.nameBySummaryType]; });
							var oMax = _.max(_data, function(_stooges){ return _stooges[_d2.nameBySummaryType]; });
							scale[_d2.nameBySummaryType] = {
								'min': oMin[_d2.nameBySummaryType],
								'max': oMax[_d2.nameBySummaryType]
							};
						}
					}
				});
			});
			
		}
		return scale;
	};
	
	/** @Override */
	this.resize = function() {
		self.panelManager.resize();
	};

	/**
	 * Clear master filter selections and tracking on all items.
	 */
	this.clearTrackingConditions = function() {
		//
	};
	
	/**
	 * Initialize header buttons for download, master filter, etc.
	 * @param _itemid HTML DOM identifier for gauge container
	 */
	this.renderButtons = function(_itemid) {
		var buttonPanerlId = _itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanerlId);
		
		// export data
		if (WISE.Constants.browser !== 'IE9') {
			var exportDataId = _itemid + '_topicon_exp';
			var exportHtml = '<li><a id="' + exportDataId + '" href="#"><img src="' + WISE.Constants.context + '/images/cont_box_icon_export.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_export_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_export.png\'" alt="Export To PNG" title="Export To PNG"></a></li>';
			topIconPanel.append(exportHtml);
			
			$("#" + exportDataId).click(function(_e) {
				
				if (self.filteredData && self.filteredData.length > 0) {
					var __pngBase64s = '';
	
					if (self.panelManager.childPanelIdBastenn.length === 1) {
						var cid = self.panelManager.childPanelIdBastenn[0];
						var svgCode;
						switch (self.gaugeTypeByContainerId[cid]) {
						case 'linear':
							svgCode = $('#' +cid).dxLinearGauge('instance').svg();
						default:
							svgCode = $('#' +cid).dxCircularGauge('instance').svg();
						}
						
						WISE.resources.dx.exports.image(svgCode);
					} 
					else {
						// zip download
						$.each(self.panelManager.childPanelIdBastenn, function(_i, _cid) {
							
							if(self.seriesDimensions.length > 0 && (self.panelManager.activePanelId && _cid.indexOf(self.panelManager.activePanelId) === -1)) {
								return true;
							}
							
							var svgCode, dxo = self.gaugeTypeByContainerId[_cid];
							if ($.type(dxo) === 'string') {
								switch (dxo) {
								case 'linear':
									svgCode = $('#' +_cid).dxLinearGauge('instance').svg();
								default:
									svgCode = $('#' +_cid).dxCircularGauge('instance').svg();
								}
								
								var canvas = document.createElement('canvas');
								document.body.appendChild(canvas);
								
								//2020.11.10 mksong 동적로딩 d3 오류 수정 dogfoot
								WISE.loadedSourceCheck('d3');
								canvg(canvas, svgCode,{ ignoreMouse: true, ignoreAnimation: true });
								
								var png = canvas.toDataURL('image/png');
								png = png.replace(/^data:image\/png;base64,/, '');
								
								__pngBase64s += png + '::space::';
								
								document.body.removeChild(canvas);
							}
						});
							
						__pngBase64s = __pngBase64s.substring(0, __pngBase64s.length - ('::space::'.length))
							
						var iframe = document.createElement('iframe');
						var iframeName = 'iframeDL_' + new Date().valueOf();
	//					iframe.setAttribute('id', iframeName);
						iframe.setAttribute('name', iframeName);
						iframe.setAttribute('style', 'width: 0; height: 0; border: none;');
						document.body.appendChild(iframe);
						
						var form = document.createElement('form');
						form.setAttribute('name', 'frmDL_' + new Date().valueOf());
						form.setAttribute('target', iframeName);
						form.setAttribute('method', 'post');
						form.setAttribute('action', WISE.Constants.context + '/file/down/base64/png/zip.do');
						document.body.appendChild(form);
						
						var input = document.createElement('input');
						input.setAttribute('type', 'hidden');
						input.setAttribute('name', 'base64');
						input.setAttribute('value', __pngBase64s);
	//					input.setAttribute('value', encodeURIComponent(png));
						form.appendChild(input);
						
						form.submit();
						
						var remove = function() {
							form.removeChild(input);
							document.body.removeChild(form);
							document.body.removeChild(iframe);
						};
						
						setTimeout(remove, 10000);
					}
					var param = {
							'pid': WISE.Constants.pid,
							'userId':userJsonObject.userId
						}
						$.ajax({
							type : 'post',
							data : param,
							cache : false,
							url : WISE.Constants.context + '/report/exportLog.do',
							complete: function() {
								gProgressbar.hide();
							}
						});
				}
				else {
					WISE.alert(gMessage.get('WISE.message.page.common.nodata'));
				}
				
				_e.preventDefault();
			});
		} // end of if (WISE.Constants.browser === 'IE9') {
	};

	/** 
	 * Append delta value text to the gauge SVG object.
	 * 
	 * @param {String} _pid Gauge object's identifier
	 * @param {Object} _options Gauge values and delta options {value: int, subvalues: int[], delta: Object}
	 */
	this.applyDeltaValue = function(_pid, _options) {
		var svg = $('#' + _pid).find('svg');
		// gauge SVG exists
		if (svg.length === 1) {
			// apply sytling options according to gauge type
			var align;
			switch (self.Gauge.ViewType) {
				case 'CircularQuarterRight':
				case 'LinearVertical':
					align = 'start';
					break;
				case 'CircularQuarterLeft':
					align = 'end';
					break;
				default: // 'CircularFull', 'CircularHalf', 'CircularThreeFourth', 'LinearHorizontal'
					align = 'middle';
			}
			var x;
			var y;
			var fontSize;
			// text XY coordinates for linear gauge
			if (self.Gauge.ViewType === 'LinearHorizontal') {
				x = parseInt(svg[0].getBoundingClientRect().width) * 0.5;
				y = parseInt(svg[0].getBoundingClientRect().height) * 0.7;
				fontSize = '1.7em';
			} 
			else if (self.Gauge.ViewType === 'LinearVertical') {
				x = 0;
				y = parseInt(svg[0].getBoundingClientRect().height) * 0.9;
				fontSize = '1.7em';
			}
			// text XY coordinates for circular gauge 
			else {
				x = parseInt(svg.find('.dxg-spindle-hole').attr('cx'));
				y = parseInt(svg.find('.dxg-spindle-hole').attr('cy')) - 20;
				fontSize = '1.7em';
			}
			var transform = 'translate(' + x + ', ' + y + ')';
			
			// create formatted delta value text
			var options = self.Gauge.GaugeElement;
			var measures = WISE.util.Object.toArray(self.Gauge.DataItems.Measure);
			var valueTextObject = WISE.libs.Dashboard.item.DataUtility.makeTextValueObjectOfDeltaOptions(_options.value, _options.subvalues, _options.delta);
			// special case for "neutral" color
			if (valueTextObject.fc === 'neutral') {
				valueTextObject.fc = '#646464';
			}
			// generate delta value text
			var deltaText;
			var value;
			var prefix;
			var numericFormat;
			if (measures.length === 1) {
				value = _options.value;
				numericFormat = measures[0].NumericFormat;
			} else {
				switch (_options.delta.ValueType) {
					case 'ActualValue':
						value = _options.value;
						numericFormat = measures[0].NumericFormat;
						break;
					case 'PercentVariation': 
						value = valueTextObject.pvv;
						numericFormat = options.PercentVariationNumericFormat;
						prefix = valueTextObject.ind + (value > 0 ? ' +' : ' ');
						break;
					case 'PercentOfTarget':
						value = valueTextObject.pot;
						numericFormat = options.PercentOfTargetNumericFormat;
						prefix = valueTextObject.ind + (value > 0 ? ' +' : ' ');
						break;
					default: // 'AbsoluteVariation'
						value = valueTextObject.avv;
						numericFormat = options.AbsoluteVariationNumericFormat;
						prefix = valueTextObject.ind + (value > 0 ? ' +' : ' ');
				}
			}
			deltaText = WISE.util.Number.unit(value, numericFormat.FormatType, numericFormat.Unit, numericFormat.Precision, 
				numericFormat.IncludeGroupSeparator, prefix, numericFormat.Suffix, numericFormat.SuffixEnabled);
			// create SVG text object
			var deltaTextSvg = document.createElementNS("http://www.w3.org/2000/svg", "text");
			deltaTextSvg.setAttribute('class', 'custom-delta-value');
			deltaTextSvg.style.whiteSpace = 'pre';
			deltaTextSvg.style.fontFamily = "'Segoe UI Light', 'Helvetica Neue Light', 'Segoe UI', 'Helvetica Neue', 'Trebuchet MS', Verdana, sans-serif";
			deltaTextSvg.style.fontWeight = 800;
			deltaTextSvg.style.fill = valueTextObject.fc === undefined ? '#232323' : valueTextObject.fc;
			deltaTextSvg.style.cursor = 'default';
			deltaTextSvg.style.fontSize = fontSize;
			deltaTextSvg.setAttributeNS(null, 'transform', transform);
			deltaTextSvg.setAttributeNS(null, 'text-anchor', align);

			var textNode = document.createTextNode(deltaText);
			deltaTextSvg.appendChild(textNode);
			svg[0].appendChild(deltaTextSvg);
		}
	};

	/**
	 * Recalculate and replace delta values on all gauge widgets.
	 */
	this.recalculateDeltaValue = function() {
		$.each(self.dxItem, function(i, gauge) {
			var id = gauge.element().attr('id');
			var options = {
				value: gauge.option('value'),
				subvalues: gauge.option('subvalues'),
				delta: self.Gauge.GaugeElement.DeltaOptions
			};
			$('#' + id).find('svg .custom-delta-value').remove();
			self.applyDeltaValue(id, options);
		});
	}

	/**
	 * generate UI for data and design functions
	 */ 
	this.menuItemGenerate = function(){
		if($('#data').length > 0){
			$('#data').remove();
		}
		$('#menulist').addClass('col-2');
		if($('#data').length == 0){
			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
		}
		
		if($('#design').length > 0){
			$('#design').remove();
		}

		if($('#tab5primary').length == 0){
			// 2020.01.16 mksong 영역 크기 조정 dogfoot
			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
		}

		// match gauge viewtype image with corresponding settings
		var viewTypeImg;
		switch(self.Gauge.ViewType) {
			case 'CircularHalf':
				viewTypeImg = WISE.Constants.context + "/resources/main/images/ico_halfClrcular.png";
				break;
			case 'CircularQuarterLeft':
				viewTypeImg = WISE.Constants.context + "/resources/main/images/ico_leftQuarterCircular.png";
				break;	
			case 'CircularQuarterRight':
				viewTypeImg = WISE.Constants.context + "/resources/main/images/ico_rightQuarterCircular.png";
				break;	
			case 'CircularThreeFourth':
				viewTypeImg = WISE.Constants.context + "/resources/main/images/ico_threeQuarterCircular.png";
				break;	
			case 'LinearHorizontal':
				viewTypeImg = WISE.Constants.context + "/resources/main/images/ico_linearH.png";
				break;	
			case 'LinearVertical':
				viewTypeImg = WISE.Constants.context + "/resources/main/images/ico_linearV.png";
				break;							
			default: // CircularFull
				viewTypeImg =  WISE.Constants.context + "/resources/main/images/ico_fullClrcular.png";
		}
		
		$('#tab5primary').empty();
		$('<li class="slide-ui-item"><a href="#" id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
		$('<li class="slide-ui-item"><a href="#" id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
		// $('<li class="slide-ui-item"><a href="#" id="editOrder" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_Vlines.png" alt=""><span>정렬 옵션</span></a></li>').appendTo($('#tab5primary'));
		$('<li class="slide-ui-item"><a href="#" id="editViewType" class="lnb-link more functiondo"><img src="'+viewTypeImg+'" alt=""><span>스타일 편집</span></a></li>').appendTo($('#tab5primary'));
		$('<li class="slide-ui-item"><a href="#" id="showGaugeCaptions" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_showGaugeCaptions.png" alt=""><span>게이지 캡션 보기</span></a></li>').appendTo($('#tab5primary'));
		$('<li class="slide-ui-item"><a href="#" id="editDelta" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_triangle.png" alt=""><span>델타 옵션</span></a></li>').appendTo($('#tab5primary'));
		$('<li class="slide-ui-item"><a href="#" id="editFormat" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_exchangeRate.png" alt=""><span>서식 옵션</span></a></li>').appendTo($('#tab5primary'));
		menuItemSlideUi();
		lnbResponsive();
		
		$('#tab4primary').empty();
		if($('#tab4primary').length == 0){
			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
		}
		
		$(  "<h4 class=\"tit-level3\">필터링</h4>" + 
			"<div class=\"panel-body\">" + 
			"	<div class=\"design-menu rowColumn\">" + 
			"		<ul class=\"desing-menu-list col-2\">" + 
			"			<li>" + 
			"				<a href=\"#\" id=\"editFilter\" class=\"functiondo\">" +
			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_basicFilter.png\" alt=\"\"><span>필터 편집</span>" + 
			"				</a>" + 
			"			</li>" + 
			"			<li>" + 
			"				<a href=\"#\" id=\"clearFilter\" class=\"functiondo\">" + 
			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>초기화</span>" + 
			"				</a>" + 
			"			</li>" + 
			"		</ul>" + 
			"	</div>" + 
			"</div>" +
			/* DOGFOOT hsshim 2020-02-06 범정부 요청: 
			 * Interactivity -> 상호작용
			 * Interactivity Options -> 상호작용 설정
			 */ 
			"<h4 class=\"tit-level3\">상호작용</h4>" + 
			"<div class=\"panel-body\">" + 
			"	<div class=\"design-menu rowColumn\">" + 
			"		<ul class=\"desing-menu-list col-3\">" + 
			"			<li>" + 
			"				<a href=\"#\" id=\"singleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_singleMasterFilter.png\" alt=\"\"><span>단일 마스터<br>필터</span>" + 
			"				</a>" + 
			"			</li>" + 
			"			<li>" + 
			"				<a href=\"#\" id=\"multipleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_multipleMasterFilter.png\" alt=\"\"><span>다중 마스터<br>필터</span>" + 
			"				</a>" + 
			"			</li>" + 
			"			<li>" + 
			"				<a href=\"#\" id=\"drillDown\" class=\"multi-toggle-button functiondo\">" + 
			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_drillDown.png\" alt=\"\"><span>드릴<br>다운</span>" + 
			"				</a>" + 
			"			</li>" + 
			"		</ul>" + 
			"	</div>" + 
			"</div>" + 
			/* DOGFOOT hsshim 2020-02-06 범정부 요청: 
			 * Interactivity -> 상호작용
			 * Interactivity Options -> 상호작용 설정
			 */ 
			"<h4 class=\"tit-level3\">상호작용 설정</h4>" + 
			"<div class=\"panel-body\">" + 
			"	<div class=\"design-menu rowColumn\">" + 
			"		<ul class=\"desing-menu-list col-2\">" + 
			"			<li>" + 
			"				<a href=\"#\" id=\"crossFilter\" class=\"single-toggle-button functiondo\">" + 
			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_crossDataSourceFiltering.png\" alt=\"\"><span>교차 데이터<br>소스 필터링</span>" + 
			"				</a>" + 
			"			</li>" + 
			"			<li>" + 
			"				<a href=\"#\" id=\"ignoreMasterFilter\" class=\"single-toggle-button functiondo\">" + 
			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>마스터 필터<br>무시</span>" + 
			"				</a>" + 
			"			</li>" + 
			"		</ul>" + 
			"	</div>" + 
			"</div>"
		).appendTo($('#tab4primary'));
		
		// initialize UI elements
		tabUi();
		designMenuUi();
		compMoreMenuUi();
        $('.single-toggle-button').on('click', function(e) {
            e.preventDefault();
            $(this).toggleClass('on');
        });
        $('.multi-toggle-button').on('click', function(e) {
            e.preventDefault();
            var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
            if ($(this)[0] !== currentlyOn[0]) {
                currentlyOn.removeClass('on');
            }
            $(this).toggleClass('on');
		});
		if(self.meta && self.meta.FilterString && self.meta.FilterString.length > 0){
			$('#editFilter').addClass('on');
		}
		// toggle 'on' status according to chart options
		if (self.IO) {
			if (self.IO['MasterFilterMode'] === 'Single') {
				$('#singleMasterFilter').addClass('on');
			} else if (self.IO['MasterFilterMode'] === 'Multiple') {
				$('#multipleMasterFilter').addClass('on');
			}
			if (self.IO['IsDrillDownEnabled']) {
				$('#drillDown').addClass('on');
			}
			if (self['IsMasterFilterCrossDataSource']) {
				$('#crossFilter').addClass('on');
			}
			if (self.IO['IgnoreMasterFilters']) {
				$('#ignoreMasterFilter').addClass('on');
			}
		}
		
		$('<div id="editPopup">').dxPopup({
			height: 'auto',
			width: 500,
			visible: false,
			showCloseButton: false
		}).appendTo('#tab5primary');
		// settings popover
		$('<div id="editPopover">').dxPopover({
			height: 'auto',
			width: 'auto',
			position: 'bottom',
			visible: false
		}).appendTo('#tab5primary');
		
		$('.functiondo').on('click',function(e){
			self.functionDo(this.id);	
		});
	};

	/**
	 * data and design functions
	 * 
	 * @param _f: clicked button's id 
	 */
	this.functionDo = function(_f) {		
		switch(_f) {
		/* DATA OPTIONS */
			// edit filter builder
			case 'editFilter': {
				break;
			}
			// clear filters
			case 'clearFilter': {
				break;
			}
			// toggle single master filter mode
			case 'singleMasterFilter': {
				break;
			}
			// toggle multiple master filter mode
			case 'multipleMasterFilter': {
				break;
			}
			// toggle drill down
			case 'drillDown': {
				break;
			}
			// toggle cross data source filtering
			case 'crossFilter': {
				break;
			}
			// toggle ignore master filter
			case 'ignoreMasterFilter': {
				break;
			}
		/* DESIGN OPTIONS */
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.Gauge.ShowCaption = true;
				} else {
					titleBar.css('display', 'none');
					self.Gauge.ShowCaption = false;
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
						var html = 	'<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput"></div>' +
									'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
						contentElement.append(html);
                        
                        $('#' + self.itemid + '_titleInput').dxTextBox({
							text: self.Name
						});
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
							var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
                            if(newName.trim() == '') {
                            	WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                            	$('#' + self.itemid + '_titleInput').dxTextBox('instance').option('value', self.Name);
                            } else {
                            	var ele = $('#' + self.itemid + '_title');
                            	ele.attr( 'title', newName)
                                ele.find( '.lm_title' ).html(newName);
                            	
								self.Gauge.Name = newName;
								self.Name = newName;
                            	p.hide();
                            }
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
			// change gauge layout type
			case 'editViewType': {
				if (!(self.dxItem) || self.dxItem.length === 0) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
                    target: '#editViewType',
					contentTemplate: function(contentElement) {
                        $(	'<div style="height: auto; width: 150px;">' +
								'<ul class="add-item-body icon-radio-list" style="display:block;">'+ 
									'<li >'+ 
										'<a  href="#" class="select-viewtype" viewtype="CircularFull">' +
											'<img src="' + WISE.Constants.context + '/resources/main/images/ico_fullClrcular.png" alt="">' +
										'</a>' + 
									'</li>' + 
									'<li>' + 
										'<a  href="#" class="select-viewtype" viewtype="CircularHalf">' +
											'<img src="' + WISE.Constants.context + '/resources/main/images/ico_halfClrcular.png" alt="">' +
										'</a>' + 
									'</li>' +  
									'<li>' + 
										'<a  href="#" class="select-viewtype" viewtype="CircularQuarterLeft">' +
											'<img src="' + WISE.Constants.context + '/resources/main/images/ico_leftQuarterCircular.png" alt="">' +
										'</a>' + 
									'</li>' + 
									'<li >'+ 
										'<a  href="#" class="select-viewtype" viewtype="CircularQuarterRight">' +
											'<img src="' + WISE.Constants.context + '/resources/main/images/ico_rightQuarterCircular.png" alt="">' +
										'</a>' + 
									'</li>' + 
									'<li>' + 
										'<a  href="#" class="select-viewtype" viewtype="CircularThreeFourth">' +
											'<img src="' + WISE.Constants.context + '/resources/main/images/ico_threeQuarterCircular.png" alt="">' +
										'</a>' + 
									'</li>' +  
									'<li>' + 
										'<a  href="#" class="select-viewtype" viewtype="LinearHorizontal">' +
											'<img src="' + WISE.Constants.context + '/resources/main/images/ico_linearH.png" alt="">' +
										'</a>' + 
									'</li>' + 
									'<li >'+ 
										'<a  href="#" class="select-viewtype" viewtype="LinearVertical">' +
											'<img src="' + WISE.Constants.context + '/resources/main/images/ico_linearV.png" alt="">' +
										'</a>' + 
									'</li>' + 
								'</ul>' + 
                            '</div>'							
						).appendTo(contentElement);

                        // toggle on for current viewtype
                        $('.select-viewtype[viewtype="' + self.Gauge.ViewType + '"]').addClass('on');
						
						// enable viewtype selection buttons
						$('.select-viewtype').off('click').on('click', function(e) {
                            $('.select-viewtype.on').removeClass('on');
							$(this).addClass('on');
							self.Gauge.ViewType = $(this).attr('viewtype');
							var newImg = $(this).find('img').attr('src');
							$('#editViewType img').attr('src', newImg);
							self.renderGauge(self.globalData, true);
						});
					}
				});
				
				p.option('visible', !(p.option('visible')));
				break;
			}
			// show and hide gauge titles and subtitles
			case 'showGaugeCaptions': {
				if (!(self.dxItem) || self.dxItem.length === 0) {
					break;
				}
				self.Gauge.ShowGaugeCaptions = !(self.Gauge.ShowGaugeCaptions);
				$.each(self.dxItem, function(i, gauge) {
					gauge.option('title.text', self.Gauge.ShowGaugeCaptions ? gauge.option('wiseTitle') : '');
					gauge.option('title.subtitle.text', self.Gauge.ShowGaugeCaptions ? gauge.option('wiseSubtitle') : '');
				});
				self.recalculateDeltaValue();
				break;
			}
			// edit delta value options
			case 'editDelta': {
				var deltaOptions = self.Gauge.GaugeElement.DeltaOptions;
				var deltaMapping = {
					'GreaterIsGood': 'Greater is good', 
					'LessIsGood': 'Less is good', 
					'WarningIfGreater': 'Warning if greater', 
					'WarningIfLess': 'Warning if less', 
					'NoIndication': 'No indication',
					'Greater is good': 'GreaterIsGood',
					'Less is good': 'LessIsGood', 
					'Warning if greater': 'WarningIfGreater', 
					'Warning if less': 'WarningIfLess', 
					'No indication': 'NoIndication',
					'ActualValue': 'Actual value', 
					'AbsoluteVariation': 'Absolute variation', 
					'PercentVariation': 'Percent variation', 
					'PercentOfTarget': 'Percent of target',
					'Actual value': 'ActualValue', 
					'Absolute variation': 'AbsoluteVariation', 
					'Percent variation': 'PercentVariation', 
					'Percent of target': 'PercentOfTarget'
				};
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '델타 옵션',
					contentTemplate: function(contentElement) {
						// initialize template
						contentElement.append(	'<div id="' + self.itemid + '_deltaOptions"></div>' +
												'<div style="padding-bottom:20px;"></div>' +
												'<div class="modal-footer" style="padding-bottom:0px;">' +
													'<div class="row center">' +
														'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
														'<a id="close" href="#" class="btn neutral close">취소</a>' +
													'</div>' +
												'</div>');
						
						// initialize components
						var deltaForm = $('#' + self.itemid + '_deltaOptions').dxForm({
							items: [
								{
									dataField: '값 유형',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Actual value', 'Absolute variation', 'Percent variation', 'Percent of target'],
										value: deltaMapping[deltaOptions.ValueType]
									}
								},
								{
									dataField: '결과 표시',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Greater is good', 'Less is good', 'Warning if greater', 'Warning if less', 'No indication'],
										value: deltaMapping[deltaOptions.ResultIndicationMode]
									}
								},
								{
									dataField: '임계값 유형',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Absolute', 'Percent'],
										value: deltaOptions.ResultIndicationThresholdType
									}
								},
								{
									dataField: '임계값 값',
									editorType: 'dxNumberBox',
									editorOptions: {
										value: deltaOptions.ResultIndicationThreshold
									}
								}
							]
						}).dxForm('instance');
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
							var formData = deltaForm.option('formData');
							deltaOptions.ValueType = deltaMapping[formData['값 유형']];
							deltaOptions.ResultIndicationMode = deltaMapping[formData['결과 표시']];
							deltaOptions.ResultIndicationThresholdType = formData['임계값 유형'];
							deltaOptions.ResultIndicationThreshold = formData['임계값 값'] || 0;
							self.bindData(self.globalData);
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
			// edit format options
			case 'editFormat': {
				/**
				 * Helper function for changing value format.
				 * @param form dxForm instance
				 * @param format format selected value's numeric format
				 */
				function changeFormat(form, format) {
					selectedValueFormat = format;
					form.getEditor('포맷 형식').option('value', format.FormatType);
					form.getEditor('단위').option('value', format.Unit);
					form.getEditor('사용자 지정 접미사').option('value', format.SuffixEnabled);
					form.getEditor('O').option('value', format.Suffix.O);
					form.getEditor('K').option('value', format.Suffix.K);
					form.getEditor('M').option('value', format.Suffix.M);
					form.getEditor('B').option('value', format.Suffix.B);
					form.getEditor('정도').option('value', format.Precision);
					form.getEditor('그룹 구분 포함').option('value', format.IncludeGroupSeparator);
				}
				// do nothing if gauge is not initialized
				if (typeof self.Gauge === 'undefined' || typeof self.Gauge.GaugeElement === 'undefined') {
					break;
				}
				// gather field data
				var valueFieldId = '#gaugeValueList' + self.index;
				var actualValueFormat;
				var targetValueFormat;
				var absoluteVariationFormat = _.cloneDeep(self.Gauge.GaugeElement.AbsoluteVariationNumericFormat);
				var percentVariationFormat = _.cloneDeep(self.Gauge.GaugeElement.PercentVariationNumericFormat);
				var percentOfTargetFormat = _.cloneDeep(self.Gauge.GaugeElement.PercentOfTargetNumericFormat);
				var scaleLabelFormat = _.cloneDeep(self.Gauge.GaugeElement.ScaleLabelNumericFormat);
				var selectedValueFormat;
				var formatList;
				$(valueFieldId + ' .analysis-data .wise-column-chooser').each(function(i, value) {
					if (i === 0) {
						actualValueFormat = _.cloneDeep($(value).data('formatOptions'));
					} else if (i === 1) {
						targetValueFormat = _.cloneDeep($(value).data('formatOptions'));
					} else {
						return false;
					}
				});
				if (typeof targetValueFormat !== 'undefined') {
					selectedValueFormat = actualValueFormat;
					formatList = ['Actual value', 'Target value', 'Absolute variation', 'Percent of target', 'Percent variation', '스케일 라벨'];
				} else if (typeof actualValueFormat !== 'undefined') {
					selectedValueFormat = actualValueFormat;
					formatList = ['Actual value', 'Absolute variation', 'Percent of target', 'Percent variation', '스케일 라벨'];
				} else {
					selectedValueFormat = absoluteVariationFormat;
					formatList = ['Absolute variation', 'Percent of target', 'Percent variation', '스케일 라벨'];
				}

				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '서식 옵션',
					contentTemplate: function(contentElement) {
						var example = 1234567890.123;
						var initialized = false;

						// initialize template
						contentElement.append(	'<div class="popup-body">' +
													'<div class="popup-body-left">' +
														'<p>값 유형 선택:</p>' +
														'<div id="' + self.itemid + '_valueFormatList"></div>' +
													'</div>' + 
													'<div class="popup-body-right">' +
														'<div id="' + self.itemid + '_formatOptions"></div>' +
														'<textarea id="' + self.itemid + '_formatExampleText" class="example-text" disabled></textarea>' +
													'</div>' +
												'</div>' +
												'<div style="padding-bottom:20px;"></div>' +
												'<div class="modal-footer" style="padding-bottom:0px;">' +
													'<div class="row center">' +
														'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
														'<a id="close" href="#" class="btn neutral close">취소</a>' +
													'</div>' +
												'</div>');
						
						// initialize components
						$('#' + self.itemid + '_valueFormatList').dxList({
							dataSource: formatList,
							selectionMode: 'single',
							selectedItems: [formatList[0]],
							focusStateEnabled: false,
							onSelectionChanged: function(e) {
								switch (e.addedItems[0]) {
									case 'Actual value':
										changeFormat(formatOptionsForm, actualValueFormat);
										break;
									case 'Target value':
										changeFormat(formatOptionsForm, targetValueFormat);
										break;
									case 'Absolute variation':
										changeFormat(formatOptionsForm, absoluteVariationFormat);
										break;
									case 'Percent of target':
										changeFormat(formatOptionsForm, percentOfTargetFormat);
										break;
									case 'Percent variation':
										changeFormat(formatOptionsForm, percentVariationFormat);
										break;
									case '스케일 라벨':
										changeFormat(formatOptionsForm, scaleLabelFormat);
										break;
									default: break;
								}
							}
						});
						var formatOptionsForm = $('#' + self.itemid + '_formatOptions').dxForm({
							items: [
								{
									dataField: '포맷 형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Auto', 'General', 'Number', 'Currency', 'Scientific', 'Percent'],
										value: selectedValueFormat.FormatType,
										onValueChanged: function(e) {
											selectedValueFormat.FormatType = e.value;
											if (e.value === 'Auto' || e.value === 'General') {
												formatOptionsForm.getEditor('단위').option('disabled', true);
												formatOptionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
												formatOptionsForm.getEditor('O').option('disabled', true);
												formatOptionsForm.getEditor('K').option('disabled', true);
												formatOptionsForm.getEditor('M').option('disabled', true);
												formatOptionsForm.getEditor('B').option('disabled', true);
												formatOptionsForm.getEditor('정도').option('disabled', true);
												formatOptionsForm.getEditor('그룹 구분 포함').option('disabled', true);
											} else if (e.value === 'Scientific' || e.value === 'Percent') {
												formatOptionsForm.getEditor('단위').option('disabled', true);
												formatOptionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
												formatOptionsForm.getEditor('O').option('disabled', true);
												formatOptionsForm.getEditor('K').option('disabled', true);
												formatOptionsForm.getEditor('M').option('disabled', true);
												formatOptionsForm.getEditor('B').option('disabled', true);
												formatOptionsForm.getEditor('정도').option('disabled', false);
												formatOptionsForm.getEditor('그룹 구분 포함').option('disabled', true);
											} else {
												formatOptionsForm.getEditor('단위').option('disabled', false);
												formatOptionsForm.getEditor('사용자 지정 접미사').option('disabled', false);
												if (formatOptionsForm.getEditor('사용자 지정 접미사').option('value')) {
													formatOptionsForm.getEditor('O').option('disabled', false);
													formatOptionsForm.getEditor('K').option('disabled', false);
													formatOptionsForm.getEditor('M').option('disabled', false);
													formatOptionsForm.getEditor('B').option('disabled', false);	
												}
												formatOptionsForm.getEditor('정도').option('disabled', false);
												formatOptionsForm.getEditor('그룹 구분 포함').option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '단위',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
										value: selectedValueFormat.Unit,
										onInitialized: function(e) {
											var formatType = selectedValueFormat.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											selectedValueFormat.Unit = e.value;
										}
									}
								},
								{
									dataField: '사용자 지정 접미사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: selectedValueFormat.SuffixEnabled,
										onInitialized: function(e) {
											var formatType = selectedValueFormat.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											selectedValueFormat.SuffixEnabled = e.value;
											if (e.value) {
												formatOptionsForm.getEditor('O').option('disabled', false);
												formatOptionsForm.getEditor('K').option('disabled', false);
												formatOptionsForm.getEditor('M').option('disabled', false);
												formatOptionsForm.getEditor('B').option('disabled', false);
											} else {
												formatOptionsForm.getEditor('O').option('disabled', true);
												formatOptionsForm.getEditor('K').option('disabled', true);
												formatOptionsForm.getEditor('M').option('disabled', true);
												formatOptionsForm.getEditor('B').option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'O',
									editorType: 'dxTextBox',
									editorOptions: {
										value: selectedValueFormat.Suffix.O,
										onInitialized: function(e) {
											var formatType = selectedValueFormat.FormatType;
											var suffixEnabled = selectedValueFormat.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											selectedValueFormat.Suffix.O = e.value;
										}
									}
								},
								{
									dataField: 'K',
									editorType: 'dxTextBox',
									editorOptions: {
										value: selectedValueFormat.Suffix.K,
										onInitialized: function(e) {
											var formatType = selectedValueFormat.FormatType;
											var suffixEnabled = selectedValueFormat.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											selectedValueFormat.Suffix.K = e.value;
										}
									}
								},
								{
									dataField: 'M',
									editorType: 'dxTextBox',
									editorOptions: {
										value: selectedValueFormat.Suffix.M,
										onInitialized: function(e) {
											var formatType = selectedValueFormat.FormatType;
											var suffixEnabled = selectedValueFormat.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											selectedValueFormat.Suffix.M = e.value;
										}
									}
								},
								{
									dataField: 'B',
									editorType: 'dxTextBox',
									editorOptions: {
										value: selectedValueFormat.Suffix.B,
										onInitialized: function(e) {
											var formatType = selectedValueFormat.FormatType;
											var suffixEnabled = selectedValueFormat.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											selectedValueFormat.Suffix.B = e.value;
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
										value: selectedValueFormat.Precision,
										onInitialized: function(e) {
											var formatType = selectedValueFormat.FormatType;
											if (formatType === 'Auto' || formatType === 'General') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											selectedValueFormat.Precision = e.value;
										}
									}
								},
								{
									dataField: '그룹 구분 포함',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: selectedValueFormat.IncludeGroupSeparator,
										onInitialized: function(e) {
											var formatType = selectedValueFormat.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											selectedValueFormat.IncludeGroupSeparator = e.value;
										}
									}
								}
							],
							onContentReady: function(form) {
								if (!initialized) {
									initialized = true;
									var updateExample = function(e) {
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
										$('#' + self.itemid + '_formatExampleText').val(WISE.util.Number.unit(example, type, unit, precision, separator, prefix, suffix, suffixEnabled));
									}
									updateExample(form);
									form.component.option('onFieldDataChanged', updateExample);
								}
							}
						}).dxForm('instance');
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
							$(valueFieldId + ' .analysis-data .wise-column-chooser').each(function(i, value) {
								if (i === 0) {
									$(value).data('formatOptions', actualValueFormat);
								} else if (i === 1) {
									$(value).data('formatOptions', targetValueFormat);
								} else {
									return false;
								}
							});
							self.Gauge.GaugeElement.AbsoluteVariationNumericFormat = absoluteVariationFormat;
							self.Gauge.GaugeElement.PercentVariationNumericFormat = percentVariationFormat;
							self.Gauge.GaugeElement.PercentOfTargetNumericFormat = percentOfTargetFormat;
							self.Gauge.GaugeElement.ScaleLabelNumericFormat = scaleLabelFormat;
							self.bindData(self.globalData);
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
			default: break;
		}
	};
};

WISE.libs.Dashboard.item.GaugeGenerator.PanelManager = function() {
	var self = this;
	
	this.parentLayerId;
	this.itemid; // gauge chart item id, chartItem
	this.gaugePanel = {};
	
	this.distinctDataBasten;
	this.childPanelIdBastenn = [];
	
	this.itemPanelMinSize = 300;
	
	this.init = function() {
		this.gaugePanel = {};
		this.childPanelIdBastenn = [];
	};
	
	this.resize = function() {
		
		var childCount = self.childPanelIdBastenn.length;
		
		$.each(this.gaugePanel, function(_n, _vp) {
			var ww = _vp.panel.width();
			var hh = _vp.panel.height();
            var itemPanelHeightSize, itemPanelWidthSize;
            
            if (childCount === 1) {
            	itemPanelWidthSize = ww - 4; // padding-height, bottom : 2px
            	itemPanelHeightSize = hh - 4;  // padding-right, left : 2px
            }
            else {
            	if (ww < self.itemPanelMinSize) {
                    itemPanelWidthSize = ww - 4; // padding-height, bottom : 2px
                }
                else {
                    var _i = 0, itemPanelWidthSizeCountTimes;
                    for (_i = 0; _i < childCount; _i++) {
                    	itemPanelWidthSizeCountTimes = self.itemPanelMinSize * (_i+1);
                    	if (ww < itemPanelWidthSizeCountTimes) {
                    		break;
                    	}
                    }
                    
                    var childCountForRow = childCount < (_i+1) ? childCount : (_i+1);
                    
                    itemPanelWidthSize = parseInt(ww / childCountForRow, 10);
                    itemPanelWidthSize = itemPanelWidthSize - 15; // 15: scroll width
                }
                
                if (hh < self.itemPanelMinSize) {
                	itemPanelHeightSize = hh - 4;  // padding-right, left : 2px
                }
                else {
                	itemPanelHeightSize = itemPanelWidthSize;
                }
                
                if (itemPanelHeightSize > self.itemPanelMinSize) {
                	itemPanelHeightSize = hh - 4;  // padding-right, left : 2px
                }
            }
            
            _.each(self.childPanelIdBastenn, function(_childPanelId) {
            	$('#'+_childPanelId)
            		.css('width', itemPanelWidthSize)
            		.css('height', itemPanelHeightSize);
            });
		});
	};

	this.makePanel = function(_gauges, _seriesDimensions, _rawData, _dimensions, _measures) {
		this.makeGaugePanel(_gauges, _seriesDimensions);
		
		if (_seriesDimensions && _seriesDimensions.length > 0) {
			this.makeChildPanelBySeriesDimensions(_seriesDimensions, _rawData, _dimensions, _measures);
		} else {
			this.makeChildPanelWithoutDimensions(_gauges, _rawData, _measures);
		}
	};
	
	/**
	 * Create an uninitialized gauge panel instance.
	 * @param _gauges gauge widget data
	 */
	this.makeGaugePanel = function(_gauges) {
		var PP = $('#' + this.itemid);
		PP.empty();
		
		$.each(_gauges, function(_i, _v) {
			var seriesName = '';
			var subSeriesName = '';
			var caption = '';
			if (_v.name) {
				caption = _v.name;
			} else {
				caption = _v.actual ? _v.actual.captionBySummaryType : '';
				caption += _v.target ? ' vs ' + _v.target.captionBySummaryType : '';
			} 
			if (_v.actual) {
				seriesName = _v.actual.captionBySummaryType;
				if (_v.target) {
					subSeriesName = _v.target.captionBySummaryType;
				}
			}
			else {
				if (_v.target) {
					seriesName = _vo.target.captionBySummaryType;
				}
			}
			var scale;
			if (_.isEmpty(self.scale)) {
				if ($.type(_v.scale.max) === 'number' || $.type(_v.scale.min) === 'number') {
					scale = _v.scale;
				}
			}
			else {
				if ($.type(self.scale[seriesName]) === 'object' || $.type(self.scale[subSeriesName]) === 'object') {
//					scale = self.scale[seriesName];
					var stooges = [self.scale[seriesName],self.scale[subSeriesName]];
					var Min = _.min(stooges,'min');
					var Max = _.max(stooges,'max');
					scale = {};
//					scale.min = Min.min;
					scale.min = 0;
					scale.max = Max.max;
				}
			}
			var id = self.itemid + '_' + _v.wiseId;
			var activeCssClass = 'active'
			var valuePanel = $('<div id="' + id + '" class="dx-item-gauge-panel ' + activeCssClass + '"></div>');
			PP.append(valuePanel);
			self.gaugePanel[id] = {
				panel: valuePanel, 
				sn: seriesName, 
				ssn: subSeriesName, 
				title: caption, 
				actual: _v.actual,
				target: _v.target,
				scale: scale,
			};
		});
	};
	
	var calcChildPanelSize = function(_vp, _childCount, _maxCols, _maxRows) {
		var ww = _vp.panel.width();
		var hh = _vp.panel.height();
		var itemPanelHeightSize;
		var itemPanelWidthSize;
		var maxCols = typeof _maxCols === 'number' ? _maxCols : Math.ceil(Math.sqrt(_childCount));
		var maxRows = Math.ceil(_childCount / maxCols);
        
        if (maxRows === 1 || hh < self.itemPanelMinSize) {
			itemPanelHeightSize = hh - 10;
		} else {
			for (var i = maxRows; i > 0; i--) {
				itemPanelHeightSize = Math.floor(hh / i) - 10;
				if (itemPanelHeightSize >= self.itemPanelMinSize) {
					break;
				}
			}
		}
		if (maxCols === 1 || ww < self.itemPanelMinSize) {
			itemPanelWidthSize = ww - 10;
		}
		else {
			for (var i = maxCols; i > 0; i--) {
				itemPanelWidthSize = Math.floor(ww / i) - 10;
				if (itemPanelWidthSize >= self.itemPanelMinSize) {
					break;
				}
			}
		}
        
        return { 
			w: itemPanelWidthSize, 
			h: itemPanelHeightSize
		};
	};
	
	this.resize = function() {
		var childCount = self.childPanelIdBastenn.length;
		$.each(this.gaugePanel, function(_n, _vp) {
			var size = calcChildPanelSize(_vp, childCount);
			_.each(self.childPanelIdBastenn, function(_childPanelId) {
            	$('#'+_childPanelId)
            		.css('width', size.w)
            		.css('height', size.h);
            });
		});
	};
	
	this.makeChildPanel = function(_childCount) {
		$.each(this.gaugePanel, function(_n, _vp) {
			_vp.panel.empty();
			
			var size = calcChildPanelSize(_vp, _childCount);
			
			var idSeq = 0, tablePanel = '<ul class="ul-panel">';
			for (var row = 0; row < _childCount; row++) {
				var id = _n + '_' + (idSeq++);
				self.childPanelIdBastenn.push(id);
				tablePanel += '<li id="' + id + '" class="child-panel" style="position: relative; width: ' + size.w + 'px; height: ' + size.h + 'px;"></li>';
			}
			tablePanel += '</ul>';
			
			_vp.panel.html(tablePanel);
		});
	};

	this.makeChildPanelWithoutDimensions = function(_gaugeData, _rawData, _measures) {
		self.finalData = [];
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		var tempResult = WISE.libs.Dashboard.Query.likeSql.fromJson([], _measures, _rawData);
		
		$.each(tempResult, function(i, data) {
			var title = '';
			var subtitle = '';
			if(_gaugeData[i].Name && _gaugeData[i].Name != ''){
				title = _gaugeData[i].Name;
			}
			else if (_gaugeData[i].actual) {
				title = _gaugeData[i].actual.captionBySummaryType;
				if (_gaugeData[i].target) {
					title += ' vs ' + _gaugeData[i].target.captionBySummaryType;
				}
			}
			else if (_gaugeData[i].target) {
				title = _gaugeData[i].target.captionBySummaryType;
			}
			self.finalData.push({t: title, st: subtitle, d: data});
		});
		
		self.makeChildPanel(self.finalData.length);
	};
	
	this.makeChildPanelBySeriesDimensions = function(_seriesDimensions, _rawData, _dimensions, _measures) {
		self.finalData = [];
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		var tempResult = WISE.libs.Dashboard.Query.likeSql.fromJson(_dimensions, _measures, _rawData, { orderBy: _dimensions });
		
		$.each(tempResult, function(i, data) {
			var seriesNames = [];
			var title = '';
			var subtitle = '';
			$.each(_seriesDimensions, function(j, series) {
				seriesNames.push(data[series.name]);
			});
			$.each(seriesNames.reverse(), function(k, name) {
				if (k === 0) {
					title = name;
				} else {
					subtitle += name + '-';
				}
			});
			if (subtitle.length > 0) {
				subtitle = subtitle.substring(0, subtitle.length - 1);
			}
			self.finalData.push({t: title, st: subtitle, d: data});
		});
		
		self.makeChildPanel(self.finalData.length);
	};
};

/**
 * Gauge data field manager class.
 */
WISE.libs.Dashboard.GaugeFieldManager = function() {
	var self = this;
	
	this.initialized = false;
	this.alreadyFindOutMeta = false;
	
	//검색 - searchDisable
	this.searchDisable = false;
	//검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	//검색
	
	this.dataItemNo=0;
	
	this.meta;
	this.isChange = false; // 사용자가 필드를 변경했는지 여부 체크
	this.columnMeta = {}; // 쿼리된 모든 컬럼정보 저장
	this.isColumnChooser = false;
	
	this.all = [];
	this.values = [];
	this.series = [];
	// this.hide_column_list_dim = [];
	// this.hide_column_list_mea = [];
	
	this.tables = [];
	
	this.Constants = {
		CUSTOMIZED: '계산된필드',
		DELTA: '변동측정필드',
		UNSELECTED_FIELD: 'UNSELECTED_FIELD'
	}
	
	this.init = function() {
		this.columnMeta = {};
		this.tables = [];
		this.all = [];
		this.values = [];
		this.series = [];
		// this.hide_column_list_dim = [];
		// this.hide_column_list_mea = [];
		this.meta = gDashboard.structure.ReportMasterInfo.dataSource;
		
		this.initialized = true;
	};
	
	this.setMetaTables = function(tables){
		this.meta.tables = tables;
	}
	
	this.setDataItemByField = function(_fieldlist){
		var dataItems = {
			Dimension: [],
			Measure: []
		};
		
		for(var i = 0; i < _fieldlist.length; i++){
			var containerName = $(_fieldlist[i]).attr('prev-container');
			var listType = containerName.substr(0, $(_fieldlist[i]).attr('prev-container').search(/\d/));
			if (listType === 'gaugeValueList') {
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				var dataItem = { 
					DataMember: {},
					UniqueName: ''
				};
				dataItem.DataMember = $(_fieldlist[i]).attr('UNI_NM');
				dataItem.Name = $(_fieldlist[i]).attr('caption');
				dataItem.UniqueName = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem.CubeUniqueName = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem.UNI_NM = $(_fieldlist[i]).attr('uni_nm');
				dataItem.NumericFormat = NumericFormat;
				dataItem.SummaryType = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				dataItems.Measure.push(dataItem);
			}else{
				var dataItem = { 
					DataMember: {},
					UniqueName: ''
				};
				dataItem.DataMember = $(_fieldlist[i]).attr('UNI_NM');
				dataItem.Name = $(_fieldlist[i]).attr('caption');
				dataItem.UniqueName = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem.CubeUniqueName = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem.SortByMeasure = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem.UNI_NM = $(_fieldlist[i]).attr('uni_nm');
				dataItem.SortOrder = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				dataItems.Dimension.push(dataItem);
			}
		}
		return dataItems;
	};
	
	this.setValuesByField = function(_values) {
		var values = { Value : [] };
		_.each(_values, function(_v) {
			var value = { UniqueName: _v.uniqueName };
			values.Value.push(value);
		});
		return values;
	};
	
	this.setSeriesDimensionsByField = function(_series) {
		var seriesDimensions = { SeriesDimension: [] };
		_.each(_series, function(_s) {
			var value = { UniqueName: _s.uniqueName };
			seriesDimensions.SeriesDimension.push(value);
		})
		return seriesDimensions;
	};

	// this.setHiddenMeasuresByField = function(_hiddenMeasure){
	// 	this.HiddenMeasures = {'Measure' : []};
	// 	_.each(_hiddenMeasure,function(_a){
	// 		var Value = {'UniqueName' : _a.uniqueName};
	// 		self.HiddenMeasures['Measure'].push(Value);
	// 	})
	// 	return self.HiddenMeasures;
	// };

	this.setActualAndTargetValues = function(_measures) {
		$.each(_measures, function(i, measure) {
			if (i === 0) {
				self.ActualValue = {
					UniqueName: measure.UniqueName
				};
			} else if (i === 1) {
				self.TargetValue = {
					UniqueName: measure.UniqueName
				};
			} else {
				return false;
			}
		});
	}
	
	this.getherFields = function(_fieldManager) {
		var _panelManager = _fieldManager.panelManager;
		var all = _panelManager['allContentPanel'].children();
		var values = _panelManager['gaugeValueContentPanel' + _fieldManager.index].children('ul.analysis-data');
		var seriesList = _panelManager['gaugeSeriesContentPanel' + _fieldManager.index].children('ul.analysis-data');
		
   		// var hide_column_list_dimList = _panelManager['pie_hide_column_list_dimContentPanel'+_fieldManager.index].children('ul.analysis-data');
    	// var hide_column_list_meaList = _panelManager['pie_hide_column_list_meaContentPanel'+_fieldManager.index].children('ul.analysis-data');
    	
    	this.values = [];
    	this.measures = [];
    	this.dimensions = [];
		this.seriesDimensions = [];
    	// this.hiddenMeasures = [];
    	
    	this.Values = {};
    	
//    	if (values.length ===0) {
//    		throw this.Constants.UNSELECTED_FIELD;
//    	}
    	
    	//2020.04.21 ajkim 항목이 없을 때 조회 안되도록 설정 dogfoot
    	if(values.length === 0){
			WISE.alert('측정값을 1개 이상 올려야 조회가 가능합니다.');
			gProgressbar.hide();
			return;
		}
    	var allSelectedFields = [];
		
    	var measureFieldOption = function(_elem){
    		var summaryType = $(_elem).find('.on >.summaryType').attr('summarytype') || 'sum';
			var caption = $(_elem).attr('caption');
			var uniNm = $(_elem).attr('UNI_NM');
    		var measure  = {
				summaryType: summaryType,
    			caption: caption,
    			captionBySummaryType: caption+'(' + summaryType + ')',
    			currencyCulture: undefined,
    			format: 'fixedPoint',
    			name: uniNm,
    			nameBySummaryType: summaryType + '_' + caption,
    			precision: 0,
    			type: 'measure',
    			uniqueName:  $(_elem).attr('dataitem')
    		};
    		return measure;
    	};
    	
    	var dimensionFieldOption = function(_elem){
			var caption = $(_elem).attr('caption');
			var uniNm = $(_elem).attr('UNI_NM');
    		var dimension  = {
    			caption: caption,
    			name: uniNm,
    			rawCaption: undefined,
    			type: 'dimension',
    			uniqueName:  $(_elem).attr('dataitem')
    		};
    		return dimension;
    	};
    	
    	_.each(values, function(_elem, _i) {
    		var child = $(_elem).children();
    		allSelectedFields.push(child);
    		var measureMeta = measureFieldOption(child);
    		self.values.push(measureMeta);
    	});
    	
    	_.each(seriesList, function(_elem, _i) {
    		var child = $(_elem).children();
    		allSelectedFields.push(child);
    		var dimensionMeta = dimensionFieldOption(child);
    		self.seriesDimensions.push(dimensionMeta);
		});
		
    	// _.each(hide_column_list_meaList, function(_elem, _i) {
    	// 	var child = $(_elem).children();
    	// 	allSelectedFields.push(child);
    	// 	var measureMeta = measureFieldOption(child);
    	// 	measureMeta.ishidden = true;
    	// 	self.hiddenMeasures.push(measureMeta);
    	// });
    	
		// _.each(hide_column_list_dimList, function(_elem) {
		// 	allSelectedFields.push(_elem);	
		// });
		// _.each(hide_column_list_meaList, function(_elem) {
		// 	allSelectedFields.push(_elem);	
		// });
    	
		this.DataItems = self.setDataItemByField(allSelectedFields);
		if (typeof this.DataItems.Measure !== 'undefined') {
			self.setActualAndTargetValues(self.DataItems.Measure);
		}
    	this.Values = self.setValuesByField(self.values);
		this.SeriesDimensions = self.setSeriesDimensionsByField(self.seriesDimensions);
    	// this.HiddenMeasures = self.setHiddenMeasuresByField(self.hiddenMeasures);
	};
	
};