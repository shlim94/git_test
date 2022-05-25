/* DOGFOOT hsshim 2020-01-22 
 * - 카드 만드는 기능 정리 및 개선 
 * - 카드 레이아웃 설정 UI 및 기능 개선
 */
/**
 * Card widget generator class.
 */
WISE.libs.Dashboard.item.CardGenerator = function() {
	var self = this;
	
	this.type = 'CARD_CHART';
	
	this.dashboardid;
	this.itemid;
	
	/* DOGFOOT mksong 2020-07-21 카드 팝업 오류 수정  */
//	this.dxItem = [];
	this.dataSourceId;
	
	this.dimensions = [];
	this.measures = [];
	this.HiddenMeasures = [];
	
	this.Card = {};
	this.cards = [];
	this.seriesDimensions = [];
	this.sparklineElements = [];
	
	/* DOGFOOT mksong 2020-08-10 카드 마스터필터 추가 */
	this.trackingData = [];
	
	this.panelManager;
	
	this.drillDownIndex; // must be number type
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	/**
	 * Get custom card dxItemConfig.
	 * 
	 * @param _card: meta object
	 * @param _osd: series data object {sn:'', d:[]}
	 * @param _vpi: value panel information object {sn:'', panel: ''}
	 * @param _sparklineVisible: if true, enable sparkline
	 * @param _sparklineOptions: sparkline widget settings
	 */
	this.getWiseItemConfig = function(_card, _osd, _ovp, _sparklineData) {
		var title = {
			text: _osd.t,
			subtext: _osd.st
		};
		var value = 0, subValues = [];
		if (typeof _osd.d !== 'undefined') {
			var data = WISE.util.Object.toArray(_osd.d)[0];
			if ( $.type(_ovp.sn) === 'string' || $.type(_ovp.sn)=== 'number') {
				value = data[_ovp.sn];
				if ( $.type(_ovp.ssn) === 'string' || $.type(_ovp.ssn)=== 'number') {
					subValues.push(data[_ovp.ssn]);
				}
			}
			else {
				if ( $.type(_ovp.ssn) === 'string' || $.type(_ovp.ssn)=== 'number') {
					value = data[_ovp.ssn];
				}
			}
		}
		else {
			//2020.01.21 mksong 경고창 타입 지정 dogfoot
			WISE.alert('ERROR: 데이터가 없습니다.','error');
		}
		
		var dxConfigs = {
			actual: _ovp.actual,
			target: _ovp.target,
			name: _card.Card.Name,
			title: title,
			value: value,
			subvalues: subValues,
			widthSize: this.CUSTOMIZED.get('widthSize'),
			fontSize: this.CUSTOMIZED.get('fontSize'),
			absoluteVariation: _card.Card.AbsoluteVariationNumericFormat,
			percentVariation: _card.Card.PercentVariationNumericFormat,
			percentOfTarget: _card.Card.PercentOfTargetNumericFormat,
			layoutTemplate: _card.Card.LayoutTemplate,
			deltaOptions: _card.Card.CardDeltaOptions,
			sparkline: {
				data: _sparklineData,
				//2020.07.22 mksong 카드 스파크라인 옵션 설정 dogfoot
				options: _card.Card.SparklineOptions
//				options: _ovp.sparkline
			}
		};
		return dxConfigs;
	};

	this.setTackingFlag = function(chk) {
		this.tracked = chk;
	};

	/**
	 * @override
	 * Link a dataset to card instance.
	 * @param _data query data in JSON format
	 */
	this.bindData = function(_data) {
	//2020.02.07 mksong sqllike 적용 dogfoot
//		if (!this.tracked) {
//			this.globalData = _.clone(_data);
//			this.filteredData = _.clone(_data);
//		}
//		
//		$("#" + this.itemid).empty();
//		
//		if (!this.filteredData || ($.type(this.filteredData) === 'array' && this.filteredData.length === 0)) {
//			var nodataHtml = '<div class="nodata-layer"></div>';
//			$("#" + this.itemid).empty().append(nodataHtml);
//		}
//		else {
			this.renderCard(_data);
//		}
	};
	
	/**
	 * Render card widget.
	 * @param _data card widget data
	 */
	this.renderCard = function(_data) {
		// generate card widget metadata
		self.dxItem = [];
		if (self.fieldManager !=null && gDashboard.isNewReport) { // 신규 생성
			self.setCard('new');
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Card);
			gDashboard.itemGenerateManager.generateItem(self, self.Card);
		}
		else if (self.fieldManager) { // 레포트 열기
			this.setCard('open');
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Card);
			gDashboard.itemGenerateManager.generateItem(self, self.Card);
		}
		else if (self.meta && $.isEmptyObject(self.Card)) {
			this.setCard('view');
			gDashboard.itemGenerateManager.itemCustomize(self,self.Card);
			gDashboard.itemGenerateManager.generateItem(self, self.Card);
		}
		//2020.02.07 mksong sqllike 적용 dogfoot
		self.panelManager.init(this.dataSourceId);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		
		this.QU = WISE.libs.Dashboard.util.QueryUtility;
		// generate card widget data
		//2020.07.24 mksong 카드 최대폭, 최소폭 기능 dogfoot
		/* DOGFOOT MKSONG 2020-07-29 카드 콘텐츠 배열 기능 추가 */
		/* DOGFOOT mksong 2020-08-06 카드 마스터필터 무시 오류 수정 */
		//20210709 AJKIM 카드 sqlLike 매개변수 panelManager > Card instance로 변경 dogfoot
		this.panelManager.makePanel(this.cards, this.seriesDimensions, self.panelManager.tempData, this.dimensions, this.measures.concat(self.HiddenMeasures), self.Card.Card.LayoutTemplate, self.Card.Card.ContentArrangementMode, self.Card.Card.ContentLineCount, self.IO, self);
		$.each(self.panelManager.gaugePanel, function(_pn, _ovp) {
			var sparklineDataObject;
			if (self.sparklineElements.length > 0) {
				sparklineDataObject = self.QU.querySparklineData(self.sparklineElements[0], _ovp.actual, self.dimensions, self);
			}
			$.each(self.panelManager.finalData, function(_i, _osd) {
				var pid = _pn + '_' + _i;
				var dxConfigs = self.getWiseItemConfig(self.meta, _osd, _ovp, sparklineDataObject);
				var dxItem = $('#' + pid).wiseCard(dxConfigs);
				
				/* DOGFOOT mksong 2020-08-06 카드 마스터필터 기능  추가*/
				dxItem.configs = dxConfigs;
				
				if(self.IO.MasterFilterMode != 'Off' && self.IO.MasterFilterMode != undefined){
					/* DOGFOOT mksong 2020-08-10 카드 마스터필터 수정 */
					dxItem.children().click(function(e){
						dxItem.children().toggleClass('selected');
						if(dxItem.children().hasClass('selected')){
							dxItem.selected = true;
							switch(self.IO['MasterFilterMode']){
					       		case 'Multiple':
					       			$.each(self.dimensions, function(_i, _ao) {
					       				var selectedData = {};
					       				$.each(self.panelManager.finalData,function(_k,_finalData){
					       					if(_finalData.t == dxItem.configs.title.text){
					       					    selectedData[_ao.name] = _finalData.d[_ao.caption];
					       					    self.trackingData.push(selectedData);
					       					}
					       				});					       			
						       		});
					                break;
					       		case 'Single':
			                    	$.each(self.dxItem, function(i, card) {
			                    		if(card.find('.selected').length != 0 && card != dxItem){
			                    			card.clearSelection();
			                    		}
			                    	});
			                    	
					       			self.trackingData = [];
					       			$.each(self.dimensions, function(_i, _ao) {
					       				var selectedData = {};
					       				$.each(self.panelManager.finalData,function(_k,_finalData){
					       					if(_finalData.t == dxItem.configs.title.text){
					       					    selectedData[_ao.name] = _finalData.d[_ao.caption];
					       					    self.trackingData.push(selectedData);
					       					}
					       				});					       			
						       		});
					           		break;
							}
						}else{
							dxItem.clearSelection();
						}
						/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
						if(WISE.Constants.editmode === "viewer"){
							gDashboard.itemGenerateManager.focusedItem = self;
						}
						gDashboard.filterData(self.itemid, self.trackingData);
					});
				}
				
				dxItem.clearSelection = function(){
					/* DOGFOOT mksong 2020-08-06 카드 마스터필터 clearSelection 기능 수정 */
					dxItem.selected = false;
					dxItem.children().removeClass('selected');
					var selectedData = {};
					$.each(self.dimensions, function(_i, _ao) {
						$.each(self.panelManager.finalData,function(_k,_finalData){
	       					if(_finalData.t == dxItem.configs.title.text){
	       					    selectedData[_ao.name] = _finalData.d[_ao.caption];
	       					}
	       				});
					});
					var isDeleted = false;
					$.each(self.trackingData,function(_i,_trackingData){
						if(!isDeleted){
							$.each(_.keys(selectedData), function(_k, _key) {
								if(_trackingData[_key] == selectedData[_key]){
		       					    self.trackingData.splice(_i,1);
		       					    isDeleted = true;
		       					}							
							});	
						}
					});
				};
				
				self.dxItem.push(dxItem);
			});
		});
//		$('.dx-item-card-panel b').attr('style', gDashboard.fontManager.getCustomFontStringForItem(20));
//		$('.dx-item-card-panel .top-value').attr('style', gDashboard.fontManager.getCustomFontStringForItem(10));
		
		//2020.08.05 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
		if(!self.functionBinddata){
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}
			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();
				gDashboard.updateReportLog();
			}	
			
			$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _d) {
				if(_d.type != 'IMAGE'){
					if(_d.dimensions.length == 0 && _d.measures.length == 0){
						gProgressbar.hide();
					}	
				}
			});
		}else{
			gProgressbar.hide();
			self.functionBinddata = false;
		}
	};

	/**
	 * Create card meta.
	 * 
	 * @param {string} type Type of report meta to generate. (ie. "new", "open" or "view")
	 */
	this.setCard = function(type) {
		// set field values
		if (type === 'new') {
			self.fieldManager.init();
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			self.Card.DataItems = self.fieldManager.DataItems;
			self.Card.Values = self.fieldManager.values;
			self.Card.SeriesDimensions = self.fieldManager.SeriesDimensions;
			self.Card.SparklineArgument = self.fieldManager.SparklineArgument;
			self.Card.HiddenMeasures = self.fieldManager.HiddenMeasures;
			if (typeof self.Card.Card === 'undefined') {
				self.Card.Card = {};
			}
			self.Card.Card.ActualValue = self.fieldManager.ActualValue;
			self.Card.Card.TargetValue = self.fieldManager.TargetValue;
			
			/* DOGFOOT mksong 2020-08-05 마스터필터 기능 추가 */
			if (self.Card.InteractivityOptions) {
				if (typeof self.Card.InteractivityOptions.MasterFilterMode === 'undefined') {
					self.Card.InteractivityOptions.MasterFilterMode = 'Off';
				}
				if (typeof self.Card.InteractivityOptions.TargetDimensions === 'undefined') {
					self.Card.InteractivityOptions.TargetDimensions = 'Argument';
				}
				if (typeof self.Card.InteractivityOptions.IsDrillDownEnabled === 'undefined') {
					self.Card.InteractivityOptions.IsDrillDownEnabled = false;
				}
				if (typeof self.Card.InteractivityOptions.IgnoreMasterFilters === 'undefined') {
					self.Card.InteractivityOptions.IgnoreMasterFilters = false;
				}
			} else {
				self.Card.InteractivityOptions = {
					MasterFilterMode: 'Off',
					TargetDimensions: 'Argument',
					IsDrillDownEnabled: false,
					IgnoreMasterFilters: false
				};
			}
			if (typeof self.Card.IsMasterFilterCrossDataSource === 'undefined') {
				self.Card.IsMasterFilterCrossDataSource = false;
			}
		} else if (type === 'open') {
			// load initial meta
			if (typeof self.meta == 'undefined') {
				self.setCard('new');
				return;
			}
			else {
				self.Card = self.meta;
			}
			if (!self.fieldManager.initialized) {
				// load CHART_XML options
				self.fieldManager.init();
				var webCardDataElement = {};
				var tempWCDE;
				if (typeof gDashboard.structure.MapOption.DASHBOARD_XML !== 'undefined') {
					tempWCDE = gDashboard.structure.MapOption.DASHBOARD_XML.WEB ? WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CARD_DATA_ELEMENT) : [];
				} else {
					tempWCDE = [];
				}
				$.each(tempWCDE,function(_i,_e){
					if(_e.CTRL_NM == self.meta.ComponentName){
						webCardDataElement = _e;
						return false;
					}
				});
				// initialize format options from CARD_XML
				$.each(WISE.util.Object.toArray(self.Card.DataItems.Measure), function(_i, _mea) {
					$.each(WISE.util.Object.toArray(webCardDataElement.MEASURES), function(_k, _measure) {
						if (_mea.UniqueName === _measure.UNI_NM) {
							/* DOGFOOT mksong 2020-08-05 cs 보고서 불러온 후 NumericForamt 오류 수정 */
							if(_mea.NumericFormat == undefined){
								_mea.NumericFormat = _measure.NUMERIC_FORMAT;
							}
							_mea.NumericFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
							_mea.NumericFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
							return false;
						}
					});
				});
				if (webCardDataElement.ABSOLUTE_VARIATION) {
					self.Card.Card.AbsoluteVariationNumericFormat = _.clone(webCardDataElement.ABSOLUTE_VARIATION);
				}
				if (webCardDataElement.PERCENT_VARIATION) {
					self.Card.Card.PercentVariationNumericFormat = _.clone(webCardDataElement.PERCENT_VARIATION);
				}
				if (webCardDataElement.PERCENT_OF_TARGET) {
					self.Card.Card.PercentOfTargetNumericFormat = _.clone(webCardDataElement.PERCENT_OF_TARGET);
				}
				/* DOGFOOT mksong 2020-08-05 카드 폭 기능 */
				if (webCardDataElement.CARD_MAXWIDTH) {
					self.Card.Card.LayoutTemplate.CardMaxWidth = _.clone(webCardDataElement.CARD_MAXWIDTH);
				}
				if (webCardDataElement.CARD_MINWIDTH) {
					self.Card.Card.LayoutTemplate.CardMinWidth = _.clone(webCardDataElement.CARD_MINWIDTH);
				}
			} else {
				gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
				self.Card.DataItems = self.fieldManager.DataItems;
				self.Card.Values = self.fieldManager.values;
				self.Card.SeriesDimensions = self.fieldManager.SeriesDimensions;
				self.Card.SparklineArgument = self.fieldManager.SparklineArgument;
				self.Card.HiddenMeasures = self.fieldManager.HiddenMeasures;
				if (typeof self.Card.Card === 'undefined') {
					self.Card.Card = {};
				}
				self.Card.Card.ActualValue = self.fieldManager.ActualValue;
				self.Card.Card.TargetValue = self.fieldManager.TargetValue;
			}
			/* DOGFOOT mksong 2020-08-05 마스터필터 기능 추가 */
			if (self.Card.InteractivityOptions) {
				if (typeof self.Card.InteractivityOptions.MasterFilterMode === 'undefined') {
					self.Card.InteractivityOptions.MasterFilterMode = 'Off';
				}
				if (typeof self.Card.InteractivityOptions.TargetDimensions === 'undefined') {
					self.Card.InteractivityOptions.TargetDimensions = 'Argument';
				}
				if (typeof self.Card.InteractivityOptions.IsDrillDownEnabled === 'undefined') {
					self.Card.InteractivityOptions.IsDrillDownEnabled = false;
				}
				if (typeof self.Card.InteractivityOptions.IgnoreMasterFilters === 'undefined') {
					self.Card.InteractivityOptions.IgnoreMasterFilters = false;
				}
			} else {
				self.Card.InteractivityOptions = {
					MasterFilterMode: 'Off',
					TargetDimensions: 'Argument',
					IsDrillDownEnabled: false,
					IgnoreMasterFilters: false
				};
			}
			if (typeof self.Card.IsMasterFilterCrossDataSource === 'undefined') {
				self.Card.IsMasterFilterCrossDataSource = false;
			}
		} else if (type === 'view') {
			self.Card = self.meta;
			var webCardDataElement = {};
			var tempWCDE;
			if (typeof gDashboard.structure.MapOption.DASHBOARD_XML !== 'undefined') {
				tempWCDE = gDashboard.structure.MapOption.DASHBOARD_XML.WEB ? WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CARD_DATA_ELEMENT) : [];
			} else {
				tempWCDE = [];
			}
			$.each(tempWCDE,function(_i,_e){
				var CtrlNM = _e.CTRL_NM + "_" + WISE.Constants.pid;
				if(CtrlNM == self.meta.ComponentName || _e.CTRL_NM == self.meta.ComponentName){
					webCardDataElement = _e;
					return false;
				}
			});
			// initialize missing measure numeric formats
			$.each(WISE.util.Object.toArray(self.Card.DataItems.Measure),function(_i,_mea){
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
				$.each(WISE.util.Object.toArray(webCardDataElement.MEASURES), function(_k, _measure) {
					if (_mea.UniqueName === _measure.UNI_NM) {
						dataNumFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
						dataNumFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
						return false;
					}
				});
				_mea.NumericFormat = dataNumFormat;
			});
			if (webCardDataElement.ABSOLUTE_VARIATION) {
				self.Card.Card.AbsoluteVariationNumericFormat = _.clone(webCardDataElement.ABSOLUTE_VARIATION);
			}
			if (webCardDataElement.PERCENT_VARIATION) {
				self.Card.Card.PercentVariationNumericFormat = _.clone(webCardDataElement.PERCENT_VARIATION);
			}
			if (webCardDataElement.PERCENT_OF_TARGET) {
				self.Card.Card.PercentOfTargetNumericFormat = _.clone(webCardDataElement.PERCENT_OF_TARGET);
			}
			/* DOGFOOT mksong 2020-08-05 카드 폭 기능 */
			if (webCardDataElement.CARD_MAXWIDTH) {
				self.Card.Card.LayoutTemplate.CardMaxWidth = _.clone(webCardDataElement.CARD_MAXWIDTH);
			}
			if (webCardDataElement.CARD_MINWIDTH) {
				self.Card.Card.LayoutTemplate.CardMinWidth = _.clone(webCardDataElement.CARD_MINWIDTH);
			}
		}
		// set general values
		if (typeof self.Card.ComponentName === 'undefined') {
			self.Card.ComponentName = self.ComponentName;
		}
		if (typeof self.Card.DataSource === 'undefined') {
			self.Card.DataSource = self.dataSourceId;
		}else if(self.Card.DataSource != self.dataSourceId){
			self.Card.DataSource = self.dataSourceId;
		}
		if (typeof self.Card.Name === 'undefined') {
			self.Card.Name = self.Name;
		}
		if (typeof self.Card.ShowCaption === 'undefined') {
			self.Card.ShowCaption = true;
		}
		
		/* DOGFOOT mksong 2020-08-05 마스터필터 기능 추가 */
		if (self.Card.InteractivityOptions) {
			if (typeof self.Card.InteractivityOptions.MasterFilterMode === 'undefined') {
				self.Card.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (typeof self.Card.InteractivityOptions.TargetDimensions === 'undefined') {
				self.Card.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (typeof self.Card.InteractivityOptions.IsDrillDownEnabled === 'undefined') {
				self.Card.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (typeof self.Card.InteractivityOptions.IgnoreMasterFilters === 'undefined') {
				self.Card.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			self.Card.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (typeof self.Card.IsMasterFilterCrossDataSource === 'undefined') {
			self.Card.IsMasterFilterCrossDataSource = false;
		}
		
		/* DOGFOOT MKSONG 2020-07-29 카드 콘텐츠 배열 기능 추가 */
		if (typeof self.Card.Card.ContentArrangementMode === 'undefined') {
			self.Card.Card.ContentArrangementMode = 'Auto';
		}
		if (typeof self.Card.Card.ContentLineCount === 'undefined') {
			self.Card.Card.ContentLineCount = 3;
		}
		
		// set card display name
		if (typeof self.Card.Card.Name === 'undefined' || self.Card.Card.Name.length === 0) {
			self.Card.Card.Name = self.getDefaultName();
		}
		// set card delta options
		if (typeof self.Card.Card.CardDeltaOptions === 'undefined') {
			self.Card.Card.CardDeltaOptions = {
				ResultIndicationMode: 'GreaterIsGood',
				ResultIndicationThresholdType: 'Percent',
				ResultIndicationThreshold: 0
			};
		} else {
			if (typeof self.Card.Card.CardDeltaOptions.ResultIndicationMode === 'undefined') {
				self.Card.Card.CardDeltaOptions.ResultIndicationMode = 'GreaterIsGood';
			}
			if (typeof self.Card.Card.CardDeltaOptions.ResultIndicationThresholdType === 'undefined') {
				self.Card.Card.CardDeltaOptions.ResultIndicationThresholdType = 'Percent';
			}
			if (typeof self.Card.Card.CardDeltaOptions.ResultIndicationThreshold === 'undefined') {
				self.Card.Card.CardDeltaOptions.ResultIndicationThreshold = 0;
			}
		}
		// set card absolute variation numeric format
		if (typeof self.Card.Card.AbsoluteVariationNumericFormat !== 'object') {
			self.Card.Card.AbsoluteVariationNumericFormat = {
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
			if (typeof self.Card.Card.AbsoluteVariationNumericFormat.FormatType === 'undefined') {
				self.Card.Card.AbsoluteVariationNumericFormat.FormatType = 'Number';
			}
			if (typeof self.Card.Card.AbsoluteVariationNumericFormat.Unit === 'undefined') {
				self.Card.Card.AbsoluteVariationNumericFormat.Unit = 'Auto';
			}
			if (typeof self.Card.Card.AbsoluteVariationNumericFormat.SuffixEnabled === 'undefined') {
				self.Card.Card.AbsoluteVariationNumericFormat.SuffixEnabled = false;
			}
			if (typeof self.Card.Card.AbsoluteVariationNumericFormat.Suffix === 'undefined') {
				self.Card.Card.AbsoluteVariationNumericFormat.Suffix = {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				};
			}
			if (typeof self.Card.Card.AbsoluteVariationNumericFormat.Precision === 'undefined') {
				self.Card.Card.AbsoluteVariationNumericFormat.Precision = 0;
			}
			if (typeof self.Card.Card.AbsoluteVariationNumericFormat.IncludeGroupSeparator === 'undefined') {
				self.Card.Card.AbsoluteVariationNumericFormat.IncludeGroupSeparator = false;
			}
		}
		// set card percent variation numeric format
		if (typeof self.Card.Card.PercentVariationNumericFormat !== 'object') {
			self.Card.Card.PercentVariationNumericFormat = {
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
			if (typeof self.Card.Card.PercentVariationNumericFormat.FormatType === 'undefined') {
				self.Card.Card.PercentVariationNumericFormat.FormatType = 'Percent';
			}
			if (typeof self.Card.Card.PercentVariationNumericFormat.Unit === 'undefined') {
				self.Card.Card.PercentVariationNumericFormat.Unit = 'Auto';
			}
			if (typeof self.Card.Card.PercentVariationNumericFormat.SuffixEnabled === 'undefined') {
				self.Card.Card.PercentVariationNumericFormat.SuffixEnabled = false;
			}
			if (typeof self.Card.Card.PercentVariationNumericFormat.Suffix === 'undefined') {
				self.Card.Card.PercentVariationNumericFormat.Suffix = {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				};
			}
			if (typeof self.Card.Card.PercentVariationNumericFormat.Precision === 'undefined') {
				self.Card.Card.PercentVariationNumericFormat.Precision = 2;
			}
			if (typeof self.Card.Card.PercentVariationNumericFormat.IncludeGroupSeparator === 'undefined') {
				self.Card.Card.PercentVariationNumericFormat.IncludeGroupSeparator = false;
			}
		}
		// set card percent of target numeric format
		if (typeof self.Card.Card.PercentOfTargetNumericFormat !== 'object') {
			self.Card.Card.PercentOfTargetNumericFormat = {
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
			if (typeof self.Card.Card.PercentOfTargetNumericFormat.FormatType === 'undefined') {
				self.Card.Card.PercentOfTargetNumericFormat.FormatType = 'Percent';
			}
			if (typeof self.Card.Card.PercentOfTargetNumericFormat.Unit === 'undefined') {
				self.Card.Card.PercentOfTargetNumericFormat.Unit = 'Auto';
			}
			if (typeof self.Card.Card.PercentOfTargetNumericFormat.SuffixEnabled === 'undefined') {
				self.Card.Card.PercentOfTargetNumericFormat.SuffixEnabled = false;
			}
			if (typeof self.Card.Card.PercentOfTargetNumericFormat.Suffix === 'undefined') {
				self.Card.Card.PercentOfTargetNumericFormat.Suffix = {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				};
			}
			if (typeof self.Card.Card.PercentOfTargetNumericFormat.Precision === 'undefined') {
				self.Card.Card.PercentOfTargetNumericFormat.Precision = 2;
			}
			if (typeof self.Card.Card.PercentOfTargetNumericFormat.IncludeGroupSeparator === 'undefined') {
				self.Card.Card.PercentOfTargetNumericFormat.IncludeGroupSeparator = false;
			}
		}
		// set card sparkline options
		if (typeof self.Card.Card.SparklineOptions === 'undefined') {
			self.Card.Card.SparklineOptions = {
				ViewType: 'Line',
				HighlightMinMaxPoints: true,
				HighlightStartEndPoints: true
			};
		} else {
			if (typeof self.Card.Card.SparklineOptions.ViewType === 'undefined') {
				self.Card.Card.SparklineOptions.ViewType = 'Line';
			}
			if (typeof self.Card.Card.SparklineOptions.HighlightMinMaxPoints === 'undefined') {
				self.Card.Card.SparklineOptions.HighlightMinMaxPoints = true;
			}
			if (typeof self.Card.Card.SparklineOptions.HighlightStartEndPoints === 'undefined') {
				self.Card.Card.SparklineOptions.HighlightStartEndPoints = true;
			}
		}
		// set card layout template
		if (typeof self.Card.Card.LayoutTemplate === 'undefined') {
			self.Card.Card.LayoutTemplate = {
				MinWidth: 200,
				MaxWidth: undefined,
				Type: 'Stretched',
				TopValue: {
					Visible: true,
					ValueType: 'ActualValue',
					DimensionIndex: 0,
					Font: {
						Size: 14,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				},
				MainValue: {
					Visible: true,
					ValueType: 'Title',
					DimensionIndex: 0,
					Font: {
						Size: 20,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				},
				SubValue: {
					Visible: true,
					ValueType: 'Subtitle',
					DimensionIndex: 0,
					Font: {
						Size: 14,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				},
				BottomValue1: {
					Visible: true,
					ValueType: 'PercentVariation',
					DimensionIndex: 0,
					Font: {
						Size: 14,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				},
				BottomValue2: {
					Visible: true,
					ValueType: 'AbsoluteVariation',
					DimensionIndex: 0,
					Font: {
						Size: 20,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				},
				DeltaIndicator: {
					Visible: true,
					Font: {
						Size: 14,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				},
				Sparkline: {
					Visible: true
				}
			};
		} else {
			if (typeof self.Card.Card.LayoutTemplate.MinWidth === 'undefined') {
				self.Card.Card.LayoutTemplate.MinWidth = 200;
			}
			if (typeof self.Card.Card.LayoutTemplate.MaxWidth === 'undefined') {
				self.Card.Card.LayoutTemplate.MaxWidth = undefined;
			}
			/* DOGFOOT mksong 2020-08-05 카드 폭 기능 */
			if (typeof self.Card.Card.LayoutTemplate.CardMinWidth === 'undefined') {
				self.Card.Card.LayoutTemplate.CardMinWidth = 200;
			}
			if (typeof self.Card.Card.LayoutTemplate.CardMaxWidth === 'undefined') {
				self.Card.Card.LayoutTemplate.CardMaxWidth = 'auto';
			}
			if (typeof self.Card.Card.LayoutTemplate.Type === 'undefined') {
				self.Card.Card.LayoutTemplate.Type = 'Stretched';
			}
			if (typeof self.Card.Card.LayoutTemplate.TopValue === 'undefined') {
				self.Card.Card.LayoutTemplate.TopValue = {
					Visible: true,
					ValueType: 'ActualValue',
					DimensionIndex: 0,
					Font: {
						Size: 14,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				};
			}
			if (typeof self.Card.Card.LayoutTemplate.MainValue === 'undefined') {
				self.Card.Card.LayoutTemplate.MainValue = {
					Visible: true,
					ValueType: 'Title',
					DimensionIndex: 0,
					Font: {
						Size: 20,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				};
			}
			if (typeof self.Card.Card.LayoutTemplate.SubValue === 'undefined') {
				self.Card.Card.LayoutTemplate.SubValue = {
					Visible: true,
					ValueType: 'Subtitle',
					DimensionIndex: 0,
					Font: {
						Size: 14,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				};
			}
			if (typeof self.Card.Card.LayoutTemplate.BottomValue1 === 'undefined') {
				self.Card.Card.LayoutTemplate.BottomValue1 = {
					Visible: true,
					ValueType: 'PercentVariation',
					DimensionIndex: 0,
					Font: {
						Size: 14,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				};
			}
			if (typeof self.Card.Card.LayoutTemplate.BottomValue2 === 'undefined') {
				self.Card.Card.LayoutTemplate.BottomValue2 = {
					Visible: true,
					ValueType: 'AbsoluteVariation',
					DimensionIndex: 0,
					Font: {
						Size: 20,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				};
			}
			if (typeof self.Card.Card.LayoutTemplate.DeltaIndicator === 'undefined') {
				self.Card.Card.LayoutTemplate.DeltaIndicator = {
					Visible: true,
					Font: {
						Size: 14,
						Color: '#333',
						ColorVisible: false,
						Align: 'None'
					}
				};
			}
			if (typeof self.Card.Card.LayoutTemplate.Sparkline === 'undefined') {
				self.Card.Card.LayoutTemplate.Sparkline = {
					Visible: true
				};
			}
		}
		this.meta = this.Card;
	}

	/**
	 * Return a default name using given measurements.
	 */
	this.getDefaultName = function() {
		var result = '';
		$.each(self.measures, function(i, measure) {
			if (i === 0) {
				result = measure.captionBySummaryType; 
			} else {
				result += ' vs ' + measure.captionBySummaryType;
			}
		});
		return result;
	}
	
	/** 
	 * @Override
	 * Resize card widget.
	 */
	this.resize = function() {
		if (this.panelManager) {
			this.panelManager.resize();
		}
		_.each(this.dxItem, function(_item) {
			_item.resize();
		});
	};

	/**
	 * generate UI for data and design functions
	 */ 
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
//		if($('#data').length > 0){
//			$('#data').remove();
//		}
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
//		}
//		
//		if($('#design').length > 0){
//			$('#design').remove();
//		}
//
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
//		}
//		
//		$('#tab5primary').empty();
//		$('<li class="slide-ui-item"><a href="#" id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		/* DOGFOOT hsshim 2020-02-03 카드 UI 개선 */
//		// $('<li class="slide-ui-item"><a href="#" id="editArrange" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_Vlines.png" alt=""><span>정렬 옵션</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="editLayout" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_alphabet.png" alt=""><span>레이아웃 옵션</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="editDelta" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_triangle.png" alt=""><span>델타 옵션</span></a></li>').appendTo($('#tab5primary'));
//		//$('<li class="slide-ui-item"><a href="#" id="editSparkline" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_graph.png" alt=""><span>스파크 라인 옵션</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="editFormat" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_exchangeRate.png" alt=""><span>서식 옵션</span></a></li>').appendTo($('#tab5primary'));
//		/* DOGFOOT hsshim 2020-02-03 끝 */
//		menuItemSlideUi();
//		lnbResponsive();
//		
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
//		}
//		
//		$(  "<h4 class=\"tit-level3\">필터링</h4>" + 
//			"<div class=\"panel-body\">" + 
//			"	<div class=\"design-menu rowColumn\">" + 
//			"		<ul class=\"desing-menu-list col-2\">" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"editFilter\" class=\"functiondo\">" +
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_basicFilter.png\" alt=\"\"><span>필터 편집</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"clearFilter\" class=\"functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>초기화</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"		</ul>" + 
//			"	</div>" + 
//			"</div>" +
//			/* DOGFOOT hsshim 2020-02-06 범정부 요청: 
//			 * Interactivity -> 상호작용
//			 * Interactivity Options -> 상호작용 설정
//			 */ 
//			"<h4 class=\"tit-level3\">상호작용</h4>" + 
//			"<div class=\"panel-body\">" + 
//			"	<div class=\"design-menu rowColumn\">" + 
//			"		<ul class=\"desing-menu-list col-3\">" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"singleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_singleMasterFilter.png\" alt=\"\"><span>단일 마스터<br>필터</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"multipleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_multipleMasterFilter.png\" alt=\"\"><span>다중 마스터<br>필터</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"drillDown\" class=\"multi-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_drillDown.png\" alt=\"\"><span>드릴<br>다운</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"		</ul>" + 
//			"	</div>" + 
//			"</div>" + 
//			/* DOGFOOT hsshim 2020-02-06 범정부 요청: 
//			 * Interactivity -> 상호작용
//			 * Interactivity Options -> 상호작용 설정
//			 */ 
//			"<h4 class=\"tit-level3\">상호작용 설정</h4>" + 
//			"<div class=\"panel-body\">" + 
//			"	<div class=\"design-menu rowColumn\">" + 
//			"		<ul class=\"desing-menu-list col-2\">" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"crossFilter\" class=\"single-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_crossDataSourceFiltering.png\" alt=\"\"><span>교차 데이터<br>소스 필터링</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"ignoreMasterFilter\" class=\"single-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>마스터 필터<br>무시</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"		</ul>" + 
//			"	</div>" + 
//			"</div>"
//		).appendTo($('#tab4primary'));
//		
//		// initialize UI elements
//		tabUi();
//		designMenuUi();
//		compMoreMenuUi();
//        $('.single-toggle-button').on('click', function(e) {
//            e.preventDefault();
//            $(this).toggleClass('on');
//        });
//        $('.multi-toggle-button').on('click', function(e) {
//            e.preventDefault();
//            var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
//            if ($(this)[0] !== currentlyOn[0]) {
//                currentlyOn.removeClass('on');
//            }
//            $(this).toggleClass('on');
//		});
//		if(self.meta && self.meta.FilterString && self.meta.FilterString.length > 0){
//			$('#editFilter').addClass('on');
//		}
//		// toggle 'on' status according to chart options
//		if (self.IO) {
//			if (self.IO['MasterFilterMode'] === 'Single') {
//				$('#singleMasterFilter').addClass('on');
//			} else if (self.IO['MasterFilterMode'] === 'Multiple') {
//				$('#multipleMasterFilter').addClass('on');
//			}
//			if (self.IO['IsDrillDownEnabled']) {
//				$('#drillDown').addClass('on');
//			}
//			if (self['IsMasterFilterCrossDataSource']) {
//				$('#crossFilter').addClass('on');
//			}
//			if (self.IO['IgnoreMasterFilters']) {
//				$('#ignoreMasterFilter').addClass('on');
//			}
//        }
//		$('<div id="editPopup">').dxPopup({
//			height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('#tab5primary');
//		// settings popover
//		$('<div id="editPopover">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//		}).appendTo('#tab5primary');
//		
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);	
//		});
	}

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
				/* DOGFOOT mksong 2020-08-05 마스터필터 기능 추가 */
				if (!(self.dxItem)) {
					break;
				}
				// Both master filter and drill-down cannot be active at the same time. Turn drill-down off.
//				if (self.IO.IsDrillDownEnabled) {
//					self.Card.InteractivityOptions.IsDrillDownEnabled = false;
//					self.IO.IsDrillDownEnabled = false;
//					drillDownIndex = 0;
//					ddParentStack = [];
//					ddCurrentID = '';
//					self.bindData(self.globalData, true);	
//				}
				
				gProgressbar.show();
				setTimeout(function () {
					// toggle off
					if (self.IO.MasterFilterMode === 'Single') {
						$('#' + self.trackingClearId).addClass('invisible');
						self.Card.InteractivityOptions.MasterFilterMode = 'Off';
						self.IO.MasterFilterMode = 'Off';
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
						if(reTrackItem){
							gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
						}else{
							gDashboard.filterData(self.itemid, self.trackingData);	
						}
					// toggle on
					} else {
						$('#' + self.trackingClearId).removeClass('invisible');
						self.Card.InteractivityOptions.MasterFilterMode = 'Single';
						self.IO.MasterFilterMode = 'Single';
						
						gDashboard.itemGenerateManager.viewedItemList=[];
						gDashboard.itemGenerateManager.viewedItemList[0] = self.ComponentName ;		
						
						// Only one master filter can be on. Turn off master filters on other items.
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
							/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
							if(gDashboard.getLayoutType() == "Container"){
								var ContainerList = gDashboard.setContainerList(self);            	

								$.each(ContainerList,function(_l,_con){
									if (_con.DashboardItem == item.ComponentName) {
										if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
											$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
											item.IO.MasterFilterMode = 'Off';
											item.meta.InteractivityOptions.MasterFilterMode = 'Off';
											/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
											gDashboard.filterData(item.itemid, []);
										}
									}
								})

							}else{
								if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
									$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
									item.IO.MasterFilterMode = 'Off';
									item.meta.InteractivityOptions.MasterFilterMode = 'Off';
									/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
									gDashboard.filterData(item.itemid, []);
								}
							}
						});
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, self.trackingData);
						
						/* DOGFOOT mksong 2020-08-06 카드 마스터필터 초기 선택 */
						self.functionBinddata = true;
						self.bindData(self.globalData, true);
						self.dxItem[0].click();
					}
				},10);
				break;
			}
			// toggle multiple master filter mode
			case 'multipleMasterFilter': {
				/* DOGFOOT mksong 2020-08-05 마스터필터 기능 추가 */
				if (!(self.dxItem)) {
					break;
				}
				// Both master filter and drill-down cannot be active at the same time. Turn drill-down off.
//				if (self.IO.IsDrillDownEnabled) {
//					self.Card.InteractivityOptions.IsDrillDownEnabled = false;
//					self.IO.IsDrillDownEnabled = false;
//					drillDownIndex = 0;
//					ddParentStack = [];
//					ddCurrentID = '';
//					self.bindData(self.globalData, true);	
//				}	
				
				gProgressbar.show();
				setTimeout(function () {
					if (self.IO.MasterFilterMode === 'Multiple') {
						$('#' + self.trackingClearId).addClass('invisible');
						self.Card.InteractivityOptions.MasterFilterMode = 'Off';
						self.IO.MasterFilterMode = 'Off';
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
						if(reTrackItem){
							gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
						}else{
							gDashboard.filterData(self.itemid, self.trackingData);	
						}
					} else {
						$('#' + self.trackingClearId).removeClass('invisible');
						self.Card.InteractivityOptions.MasterFilterMode = 'Multiple';
						self.IO.MasterFilterMode = 'Multiple';
						// Only one master filter can be on. Turn off master filters on other items.
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
							/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
							if(gDashboard.getLayoutType() == "Container"){
								var ContainerList = gDashboard.setContainerList(self);            	

								$.each(ContainerList,function(_l,_con){
									if (_con.DashboardItem == item.ComponentName) {
										if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
											$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
											item.IO.MasterFilterMode = 'Off';
											item.meta.InteractivityOptions.MasterFilterMode = 'Off';
											/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
											gDashboard.filterData(item.itemid, []);
										}
									}
								})

							}else{
								if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
									$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
									item.IO.MasterFilterMode = 'Off';
									item.meta.InteractivityOptions.MasterFilterMode = 'Off';
									/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
									gDashboard.filterData(item.itemid, []);
								}
							}
						});
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, self.trackingData);
						/* DOGFOOT mksong 2020-08-06 카드 마스터필터 초기 선택 */
						self.functionBinddata = true;
						self.bindData(self.globalData, true);
						self.dxItem[0].click();
					}
				},10);
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
				/* DOGFOOT mksong 2020-08-05 마스터필터 무시 기능 추가 */
				if (!(self.dxItem)) {
					break;
				}	
				self.IO.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
				self.Card.InteractivityOptions.IgnoreMasterFilters = self.IO.IgnoreMasterFilters;
				self.tracked = !self.IO.IgnoreMasterFilters;

				gProgressbar.show();
				
				setTimeout(function () {	
					if (self.IO.IgnoreMasterFilters) {
						self.functionBinddata = true;
					}				
					self.bindData(self.globalData, true);
				},10);
				
				
				break;
			}
		/* DESIGN OPTIONS */
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.Card.ShowCaption = true;
				} else {
					titleBar.css('display', 'none');
					self.Card.ShowCaption = false;
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
									'<p>카드 이름 </p><div id="' + self.itemid + '_nameInput"></div>' +
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
						
						$('#' + self.itemid + '_nameInput').dxTextBox({
							text: self.Card.Card.Name
						});
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
							var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
							var newCardName = $('#' + self.itemid + '_nameInput').dxTextBox('instance').option('text');
                            if(newName.trim() == '') {
                            	WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                            	$('#' + self.itemid + '_titleInput').dxTextBox('instance').option('value', self.Name);
                            } else {
                            	/* DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류 수정  20191223 */
                            	
//                            	var goldenLayout = gDashboard.goldenLayoutManager;
//                            	goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);
                            	
                            	var ele = $('#' + self.itemid + '_title');
                            	ele.attr( 'title', newName)
                                ele.find( '.lm_title' ).html(newName);
                            	
								self.Card.Card.Name = newCardName;
								self.Card.Name = newName;
								self.Name = newName;
								//2020.08.05 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData);
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
			/* DOGFOOT MKSONG 2020-07-29 카드 콘텐츠 배열 기능 추가 */
			case 'editArrange': {
				if (!(self.dxItem)) {
					break;
				}
				var contentLineCount = self.meta.Card.ContentLineCount;
				var contentArrangementMode = self.meta.Card.ContentArrangementMode;
				var arrangementModeMapping = {
					'Auto': '자동정렬', 
					'FixedColumnCount': '열 정렬', 
					'FixedRowCount': '행 정렬'
				};
				var arrangementModeMapping2 = {
						'자동정렬': 'Auto', 
						'열 정렬': 'FixedColumnCount', 
						'행 정렬': 'FixedRowCount'
					};
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
									dataField: '정렬 유형',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['자동정렬', '열 정렬', '행 정렬'],
										value: arrangementModeMapping[contentArrangementMode] == undefined ? '자동정렬' : arrangementModeMapping[contentArrangementMode],
										onValueChanged : function(e){
											arrangeForm.option('items')[0].editorOptions['value'] = e.value;
											if(arrangementModeMapping2[e.value] != 'Auto'){
												arrangeForm.option('items')[1].editorOptions['disabled'] = false;
											}else{
												arrangeForm.option('items')[1].editorOptions['disabled'] = true;
											}
											arrangeForm.repaint();
										}
									}
								},
								{
									dataField: '카운트',
									editorType: 'dxNumberBox',
									editorOptions: {
										disabled : contentArrangementMode == 'Auto' || contentArrangementMode == undefined ? true : false,
										value: contentLineCount == undefined ? 3 : contentLineCount,
										min : 0
									}
								}
							]
						}).dxForm('instance');
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
							var formData = arrangeForm.option('formData');
							self.meta.Card.ContentArrangementMode = arrangementModeMapping2[formData['정렬 유형']];
							self.meta.Card.ContentLineCount = formData['카운트'];
							//2020.08.05 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
							self.functionBinddata = true;
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
			case 'editLayout': {
				/* DOGFOOT mksong 2020-07-21 카드 팝업 오류 수정  */
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					/* DOGFOOT mksong 2020-07-21 카드 팝업 타이틀 동기화  */
					title: '레이아웃 옵션',
					width: 750,
					/* DOGFOOT syjin 2021-06-07 카드 레이아웃 옵션 팝업창 짤림현상 수정  */
					height: 927,
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						// map of value types and value type strings
						var valueMap = {
							'Title': 'Title',
							'Subtitle': 'Subtitle', 
							'Absolute Variation': 'AbsoluteVariation', 
							'Actual Value': 'ActualValue', 
							'Card Name': 'CardName', 
							'Percent of Target': 'PercentOfTarget', 
							'Percent of Variation': 'PercentVariation', 
							'Target Value': 'TargetValue',
							'AbsoluteVariation': 'Absolute Variation',
							'ActualValue': 'Actual Value',
							'CardName': 'Card Name',
							'PercentOfTarget': 'Percent of Target',
							'PercentVariation': 'Percent of Variation',
							'TargetValue': 'Target Value',
						};
						
						var tempFontSetting = {
							Size: 14,
							Color: '#333',
							ColorVisible: false,
							Align: 'None'
						}
						
						var tempFontSettingTitle = {
							Size: 20,
							Color: '#333',
							ColorVisible: false,
							Align: 'None'
						}
						// example card configurations
						var exampleCardConfig = {
							actual: { 
								formatType: 'Number', 
								unit: 'Ones', 
								precision: 0, 
								includeGroupSeparator: true, 
								suffix: {B: '십억', K: '천', M: '백만', O: ''}, 
								suffixEnabled: false,
							},
							target: { 
								formatType: 'Number', 
								unit: 'Ones', 
								precision: 0, 
								includeGroupSeparator: true, 
								suffix: {B: '십억', K: '천', M: '백만', O: ''}, 
								suffixEnabled: false,
							},
							name: '카드 이름',
							title: {text: '제목', subtext: '부제목'},
							value: 54321,
							subvalues: [12345],
							absoluteVariation: { 
								FormatType: 'Number', 
								Unit: 'Auto', 
								Precision: 0, 
								IncludeGroupSeparator: false, 
								Suffix: {B: '십억', K: '천', M: '백만', O: ''}, 
								SuffixEnabled: false,
							},
							percentVariation: { 
								FormatType: 'Percent', 
								Unit: 'Auto', 
								Precision: 2, 
								IncludeGroupSeparator: false, 
								Suffix: {B: '십억', K: '천', M: '백만', O: ''}, 
								SuffixEnabled: false,
							},
							percentOfTarget: { 
								FormatType: 'Percent', 
								Unit: 'Auto', 
								Precision: 2, 
								IncludeGroupSeparator: false, 
								Suffix: {B: '십억', K: '천', M: '백만', O: ''},  
								SuffixEnabled: false,
							},
							layoutTemplate: {
								Type: self.Card.Card.LayoutTemplate.Type, 
								TopValue: {
									DimensionIndex: self.Card.Card.LayoutTemplate.TopValue.DimensionIndex, 
									ValueType: self.Card.Card.LayoutTemplate.TopValue.ValueType, 
									Visible: self.Card.Card.LayoutTemplate.TopValue.Visible,
									Font: _.cloneDeep(self.Card.Card.LayoutTemplate.TopValue.Font? self.Card.Card.LayoutTemplate.TopValue.Font : tempFontSetting)
								}, 
								MainValue: {
									DimensionIndex: self.Card.Card.LayoutTemplate.MainValue.DimensionIndex,
									ValueType: self.Card.Card.LayoutTemplate.MainValue.ValueType, 
									Visible: self.Card.Card.LayoutTemplate.MainValue.Visible,
									Font: _.cloneDeep(self.Card.Card.LayoutTemplate.MainValue.Font? self.Card.Card.LayoutTemplate.MainValue.Font : tempFontSettingTitle)
								}, 
								SubValue: {
									DimensionIndex: self.Card.Card.LayoutTemplate.SubValue.DimensionIndex, 
									ValueType: self.Card.Card.LayoutTemplate.SubValue.ValueType, 
									Visible: self.Card.Card.LayoutTemplate.SubValue.Visible,
									Font: _.cloneDeep(self.Card.Card.LayoutTemplate.SubValue.Font? self.Card.Card.LayoutTemplate.SubValue.Font : tempFontSetting)
								}, 
								BottomValue1: {
									DimensionIndex: self.Card.Card.LayoutTemplate.BottomValue1.DimensionIndex, 
									ValueType: self.Card.Card.LayoutTemplate.BottomValue1.ValueType, 
									Visible: self.Card.Card.LayoutTemplate.BottomValue1.Visible,
									Font: _.cloneDeep(self.Card.Card.LayoutTemplate.BottomValue1.Font? self.Card.Card.LayoutTemplate.BottomValue1.Font : tempFontSetting)
								}, 
								BottomValue2: {
									DimensionIndex: self.Card.Card.LayoutTemplate.BottomValue2.DimensionIndex, 
									ValueType: self.Card.Card.LayoutTemplate.BottomValue2.ValueType, 
									Visible: self.Card.Card.LayoutTemplate.BottomValue2.Visible,
									Font: _.cloneDeep(self.Card.Card.LayoutTemplate.BottomValue2.Font? self.Card.Card.LayoutTemplate.BottomValue2.Font : tempFontSettingTitle)
								}, 
								DeltaIndicator: {
									Visible: self.Card.Card.LayoutTemplate.DeltaIndicator.Visible,
									Font: _.cloneDeep(self.Card.Card.LayoutTemplate.DeltaIndicator.Font? self.Card.Card.LayoutTemplate.DeltaIndicator.Font : tempFontSetting)
								}, 
								Sparkline: {Visible: self.Card.Card.LayoutTemplate.Sparkline.Visible}, 
								//2020.07.24 mksong 카드 최대폭, 최소폭 기능 dogfoot
								MinWidth : self.Card.Card.LayoutTemplate.MinWidth,
								MaxWidth : self.Card.Card.LayoutTemplate.MaxWidth,
								/* DOGFOOT mksong 2020-08-05 카드 폭 기능 */
								CardMinWidth : self.Card.Card.LayoutTemplate.CardMinWidth,
								CardMaxWidth : self.Card.Card.LayoutTemplate.CardMaxWidth
							},
							deltaOptions: {
								ResultIndicationThresholdType: "Percent", 
								ResultIndicationMode: "GreaterIsGood", 
								ResultIndicationThreshold: 0
							},
							sparkline: {
								data: {
									argumentField: "seq",
									valueField: "third",
									dataSource: [
										{third: 4, seq: 0},
										{third: 0, seq: 1},
										{third: 6, seq: 2},
										{third: 7, seq: 3},
										{third: 3, seq: 4},
										{third: 9, seq: 5},
										{third: 5, seq: 6},
										{third: 2, seq: 7},
										{third: 1, seq: 8},
										{third: 8, seq: 9},
									]
								},
								options: undefined
							}
						};
						// initialize template
						contentElement.append(	'<div class="popup-body">' +
													'<div class="popup-body-left" style="width: 50%">' +
														//2020.07.24 mksong 카드 내용 최대폭, 최소폭 기능 dogfoot
														'<p>최소폭: </p>' +
														'<div id="' + self.itemid + '_layoutMinWidth"></div>' +
														'<p>최대폭: </p>' +
														'<div id="' + self.itemid + '_layoutMaxWidth"></div>' +
														'<p>자동</p>' +
														'<div id="' + self.itemid + '_layoutAutoWidth"></div>' +
													'</div>' + 
													'<div class="popup-body-right" style="width: 50%">' +
														//2020.08.05 mksong 카드 최대폭, 최소폭 기능 dogfoot
														'<p>카드 최소폭: </p>' +
														'<div id="' + self.itemid + '_layoutCardMinWidth"></div>' +
														'<p>카드 최대폭: </p>' +
														'<div id="' + self.itemid + '_layoutCardMaxWidth"></div>' +
														'<p>자동</p>' +
														'<div id="' + self.itemid + '_layoutCardAutoWidth"></div>' +
													'</div>' +
												'</div>' +
												'<div class="popup-body">' +
													'<div class="popup-body-left" style="width: 30%">' +
														'<p>서식 스타일 선택:</p>' +
														'<div id="' + self.itemid + '_layoutList"></div>' +
													'</div>' + 
													'<div class="popup-body-right" style="width: 70%">' +
														'<div id="' + self.itemid + '_customLayoutGrid"></div>' +
													'</div>' +
												'</div>' +
												'<div class="popup-body">' +
													'<div class="dx-item-card-panel">' +
														'<ul class="ul-panel">' +
															'<li id="exampleCard" class="child-panel" style="width: 100%; height: 300px;"></div>' + 
														'</ul>' +
													'</div>' +
												'</div>' +
												'<div style="padding-bottom:20px;"></div>' +
												'<div class="modal-footer" style="padding-bottom:0px;">' +
													'<div class="row center">' +
														'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
														'<a id="close" href="#" class="btn neutral close ">취소</a>' +
													'</div>' +
												'</div>');
						//2020.07.24 mksong 카드 최대폭, 최소폭 기능 dogfoot
						var minWidth =  $('#' + self.itemid + '_layoutMinWidth').dxNumberBox({
							showSpinButtons: true,
							min: 0,
							/* DOGFOOT mksong 2020-08-10 카드 폭 예시카드 반영 */
							value: self.Card.Card.LayoutTemplate.MinWidth,
							onValueChanged : function(_e){
								exampleCardConfig.layoutTemplate.MinWidth = _e.value;
								maxWidth.option('min', _e.value);
								$('#exampleCard').empty().wiseCard(exampleCardConfig);
							}
						}).dxNumberBox('instance');
						
						var maxWidth =  $('#' + self.itemid + '_layoutMaxWidth').dxNumberBox({
							showSpinButtons: true,
							min: minWidth.option('value'),
							disabled : self.Card.Card.LayoutTemplate.MaxWidth == undefined || self.Card.Card.LayoutTemplate.MaxWidth == 'auto',
							/* DOGFOOT mksong 2020-08-10 카드 폭 예시카드 반영 */
							value : self.Card.Card.LayoutTemplate.MaxWidth != undefined && self.Card.Card.LayoutTemplate.MaxWidth != 'auto' ? self.Card.Card.LayoutTemplate.MaxWidth : (self.Card.Card.LayoutTemplate.MaxWidth == undefined || self.Card.Card.LayoutTemplate.MaxWidth == 'auto' ? minWidth.option('value') : self.Card.Card.LayoutTemplate.MaxWidth),
							onValueChanged : function(_e){
								exampleCardConfig.layoutTemplate.MaxWidth = _e.value;
								$('#exampleCard').empty().wiseCard(exampleCardConfig);
							}
						}).dxNumberBox('instance');
						
						var autoWidth = $('#'+ self.itemid + '_layoutAutoWidth').dxCheckBox({
							value : self.Card.Card.LayoutTemplate.MaxWidth == undefined || self.Card.Card.LayoutTemplate.MaxWidth == 'auto' ? true : false,
							onValueChanged : function(_e){
								maxWidth.option('disabled', _e.value);
								/* DOGFOOT mksong 2020-08-10 카드 폭 예시카드 반영 */
								if(_e.value == true){
								    exampleCardConfig.layoutTemplate.MaxWidth = 'auto';
								    $('#exampleCard').empty().wiseCard(exampleCardConfig);
								}else{
									exampleCardConfig.layoutTemplate.MaxWidth = maxWidth.option('value');
									$('#exampleCard').empty().wiseCard(exampleCardConfig);
								}
							}
						}).dxCheckBox('instance');
						//2020.07.24 mksong 카드 최대폭, 최소폭 기능 끝 dogfoot
						
						//2020.08.05 mksong 카드 최대폭, 최소폭 기능 dogfoot
						var cardMinWidth =  $('#' + self.itemid + '_layoutCardMinWidth').dxNumberBox({
							showSpinButtons: true,
							min: 0,
							/* DOGFOOT mksong 2020-08-10 카드 폭 예시카드 반영 */
							value: self.Card.Card.LayoutTemplate.CardMinWidth,
							onValueChanged : function(_e){
								exampleCardConfig.layoutTemplate.CardMinWidth = _e.value;
								cardMaxWidth.option('min', _e.value);
								$('#exampleCard').css('min-width',_e.value + 'px');
								$('#exampleCard').empty().wiseCard(exampleCardConfig);
							}
						}).dxNumberBox('instance');
						
						var cardMaxWidth =  $('#' + self.itemid + '_layoutCardMaxWidth').dxNumberBox({
							showSpinButtons: true,
							min: cardMinWidth.option('value'),
							disabled : self.Card.Card.LayoutTemplate.CardMaxWidth == undefined || self.Card.Card.LayoutTemplate.CardMaxWidth == 'auto',
							/* DOGFOOT mksong 2020-08-10 카드 폭 예시카드 반영 */
							value : self.Card.Card.LayoutTemplate.CardMaxWidth != undefined && self.Card.Card.LayoutTemplate.CardMaxWidth != 'auto' ? self.Card.Card.LayoutTemplate.CardMaxWidth : (self.Card.Card.LayoutTemplate.CardMaxWidth == undefined || self.Card.Card.LayoutTemplate.CardMaxWidth == 'auto' ? cardMinWidth.option('value') : self.Card.Card.LayoutTemplate.CardMaxWidth),
							onValueChanged : function(_e){
								exampleCardConfig.layoutTemplate.CardMaxWidth = _e.value;
								$('#exampleCard').css('max-width',_e.value + 'px');
								$('#exampleCard').empty().wiseCard(exampleCardConfig);
							}
						}).dxNumberBox('instance');
						
						var cardAutoWidth = $('#'+ self.itemid + '_layoutCardAutoWidth').dxCheckBox({
							value : self.Card.Card.LayoutTemplate.CardMaxWidth == undefined || self.Card.Card.LayoutTemplate.CardMaxWidth == 'auto' ? true : false,
							onValueChanged : function(_e){
								cardMaxWidth.option('disabled', _e.value);
								/* DOGFOOT mksong 2020-08-10 카드 폭 예시카드 반영 */
								if(_e.value == true){
								    exampleCardConfig.layoutTemplate.CardMaxWidth = 'auto';
								    $('#exampleCard').css('max-width','100%');
								    $('#exampleCard').css('width','100%');
								    $('#exampleCard').empty().wiseCard(exampleCardConfig);
								}else{
									exampleCardConfig.layoutTemplate.CardMaxWidth = cardMaxWidth.option('value');
									$('#exampleCard').css('max-width',cardMaxWidth.option('value') + 'px');
									$('#exampleCard').empty().wiseCard(exampleCardConfig);
								}
							}
						}).dxCheckBox('instance');
						//2020.07.24 mksong 카드 최대폭, 최소폭 기능 끝 dogfoot
						
						// initialize components
						var layoutList = $('#' + self.itemid + '_layoutList').dxList({
							dataSource: ['Stretched', 'Centered', 'Compact', 'Lightweight'],
							selectionMode: 'single',
							selectedItems: [self.Card.Card.LayoutTemplate.Type],
							focusStateEnabled: false,
							onSelectionChanged: function(e) {
								exampleCardConfig.layoutTemplate.Type = e.addedItems[0];
								$('#exampleCard').empty().wiseCard(exampleCardConfig);
							}
						}).dxList('instance');
						var customLayoutGrid = $('#' + self.itemid + '_customLayoutGrid').dxDataGrid({
							columns: [{
								dataField: 'visible',
								caption: '표시',
								dataType: 'boolean',
								allowEditing: true,
								width: '50px'
							}, {
								dataField: 'cardDataType',
								caption: '값/요소',
								allowEditing: true,
								width: '145px',
								editCellTemplate: function(cellElement, cellInfo) {
									return $("<div>").dxSelectBox({
										dataSource: ['Title', 'Subtitle', 'Absolute Variation', 'Actual Value', 'Card Name', 'Percent of Target', 'Percent of Variation', 'Target Value'],
										value: cellInfo.value,
										disabled: (cellInfo.data.valueType === 'DeltaIndicator' || cellInfo.data.valueType === 'Sparkline'),
										onValueChanged: function(e) {
											cellInfo.setValue(e.value);
										}
									});
								}
							},
							//20200727 ajkim 카드 폰트 설정 추가 dogfoot
							{
								dataField: 'fontSize',
								caption: '글꼴크기',
								dataType: "number",
								allowEditing: true,
								calculateCellValue : function(rowData) {
									if(rowData["cardDataType"] == 'Sparkline')
										return '-'
									else
										return rowData.fontSize
								}
							}, {
								dataField: 'fontColor',
								caption: '글꼴색상',
								allowEditing: true,
								cellTemplate: function (cellElement, cellInfo) {
				                    if (cellInfo.rowType !== "data") {
				                        return;
				                    }
				                    var color = cellInfo.value? cellInfo.value : '#333';
				                    if(cellInfo.data.cardDataType !== 'Sparkline')
				                    	cellElement.css("background-color", color);
				                },
								 editCellTemplate: function (cellElement, cellInfo) {
				                    if (cellInfo.rowType !== "data") {
				                        return;
				                    }
				                    var color = cellInfo.value? cellInfo.value : '#333';
				                    $("<div>").dxColorBox({
				                        value: color,
				                        onValueChanged: function(args) {
				                            cellInfo.setValue(args.value);
				                        },
				                        disabled: (cellInfo.data.valueType === 'Sparkline')
				                    }).appendTo(cellElement);
				                }
							}, 
							{
								dataField: 'fontColorVisible',
								caption: '색상적용',
								dataType: 'boolean',
								allowEditing: true,
								calculateCellValue : function(rowData) {
									if(rowData["cardDataType"] == 'Sparkline')
										return false;
									else
										return rowData.fontColorVisible;
								}
//								width: '50px'
							},
							{
								dataField: 'fontAlign',
								caption: '정렬',
//								dataType: "number",
								allowEditing: true,
//								calculateCellValue : function(rowData) {
//									if(rowData["cardDataType"] == 'Sparkline')
//										return '-'
//									else
//										return rowData.fontSize
//								},
								editCellTemplate: function(cellElement, cellInfo) {
									return $("<div>").dxSelectBox({
										dataSource: ['Left', 'Center', 'Right', 'None'],
										value: cellInfo.value,
										disabled: (cellInfo.data.valueType === 'Sparkline') ||
										((layoutList.option('selectedItems')[0] === 'Centered' || layoutList.option('selectedItems')[0] === 'Compact')
												&& (cellInfo.data.valueType === 'BottomValue2' || cellInfo.data.valueType === 'DeltaIndicator')),
										onValueChanged: function(e) {
											cellInfo.setValue(e.value);
										}
									});
								}
							}],
							dataSource: [{
								valueType: 'TopValue',
								visible: self.Card.Card.LayoutTemplate.TopValue.Visible,
								cardDataType: valueMap[self.Card.Card.LayoutTemplate.TopValue.ValueType],
								fontSize : self.Card.Card.LayoutTemplate.TopValue.Font? self.Card.Card.LayoutTemplate.TopValue.Font.Size : 14,
								fontColor : self.Card.Card.LayoutTemplate.TopValue.Font? self.Card.Card.LayoutTemplate.TopValue.Font.Color : '#333',
								fontColorVisible : self.Card.Card.LayoutTemplate.TopValue.Font? self.Card.Card.LayoutTemplate.TopValue.Font.ColorVisible : false,
								fontAlign : self.Card.Card.LayoutTemplate.TopValue.Font? self.Card.Card.LayoutTemplate.TopValue.Font.Align : 'None',
							}, {
								valueType: 'MainValue',
								visible: self.Card.Card.LayoutTemplate.MainValue.Visible,
								cardDataType: valueMap[self.Card.Card.LayoutTemplate.MainValue.ValueType],
								fontSize : self.Card.Card.LayoutTemplate.MainValue.Font? self.Card.Card.LayoutTemplate.MainValue.Font.Size : 20,
								fontColor : self.Card.Card.LayoutTemplate.MainValue.Font? self.Card.Card.LayoutTemplate.MainValue.Font.Color : '#333',
								fontColorVisible : self.Card.Card.LayoutTemplate.MainValue.Font? self.Card.Card.LayoutTemplate.MainValue.Font.ColorVisible : false,
								fontAlign : self.Card.Card.LayoutTemplate.MainValue.Font? self.Card.Card.LayoutTemplate.MainValue.Font.Align : 'None'
							}, {
								valueType: 'SubValue',
								visible: self.Card.Card.LayoutTemplate.SubValue.Visible,
								cardDataType: valueMap[self.Card.Card.LayoutTemplate.SubValue.ValueType],
								fontSize : self.Card.Card.LayoutTemplate.SubValue.Font? self.Card.Card.LayoutTemplate.SubValue.Font.Size : 14,
								fontColor : self.Card.Card.LayoutTemplate.SubValue.Font? self.Card.Card.LayoutTemplate.SubValue.Font.Color : '#333',
								fontColorVisible : self.Card.Card.LayoutTemplate.SubValue.Font? self.Card.Card.LayoutTemplate.SubValue.Font.ColorVisible : false,
								fontAlign : self.Card.Card.LayoutTemplate.SubValue.Font? self.Card.Card.LayoutTemplate.SubValue.Font.Align : 'None'
							}, {
								valueType: 'BottomValue1',
								visible: self.Card.Card.LayoutTemplate.BottomValue1.Visible,
								cardDataType: valueMap[self.Card.Card.LayoutTemplate.BottomValue1.ValueType],
								fontSize : self.Card.Card.LayoutTemplate.BottomValue1.Font? self.Card.Card.LayoutTemplate.BottomValue1.Font.Size : 14,
								fontColor : self.Card.Card.LayoutTemplate.BottomValue1.Font? self.Card.Card.LayoutTemplate.BottomValue1.Font.Color : '#333',
								fontColorVisible : self.Card.Card.LayoutTemplate.BottomValue1.Font? self.Card.Card.LayoutTemplate.BottomValue1.Font.ColorVisible : false,
								fontAlign : self.Card.Card.LayoutTemplate.BottomValue1.Font? self.Card.Card.LayoutTemplate.BottomValue1.Font.Align : 'None'
							}, {
								valueType: 'BottomValue2',
								visible: self.Card.Card.LayoutTemplate.BottomValue2.Visible,
								cardDataType: valueMap[self.Card.Card.LayoutTemplate.BottomValue2.ValueType],
								fontSize : self.Card.Card.LayoutTemplate.BottomValue2.Font? self.Card.Card.LayoutTemplate.BottomValue2.Font.Size : 20,
								fontColor : self.Card.Card.LayoutTemplate.BottomValue2.Font? self.Card.Card.LayoutTemplate.BottomValue2.Font.Color : '#333',
								fontColorVisible : self.Card.Card.LayoutTemplate.BottomValue2.Font? self.Card.Card.LayoutTemplate.BottomValue2.Font.ColorVisible : false,
								fontAlign : self.Card.Card.LayoutTemplate.BottomValue2.Font? self.Card.Card.LayoutTemplate.BottomValue2.Font.Align : 'None'	
							}, {
								valueType: 'DeltaIndicator',
								visible: self.Card.Card.LayoutTemplate.DeltaIndicator.Visible,
								cardDataType: 'Delta Indicator',
								fontSize : self.Card.Card.LayoutTemplate.DeltaIndicator.Font? self.Card.Card.LayoutTemplate.DeltaIndicator.Font.Size : 14,
								fontColor : self.Card.Card.LayoutTemplate.DeltaIndicator.Font? self.Card.Card.LayoutTemplate.DeltaIndicator.Font.Color : '#333',
								fontColorVisible : self.Card.Card.LayoutTemplate.DeltaIndicator.Font? self.Card.Card.LayoutTemplate.DeltaIndicator.Font.ColorVisible : false,
								fontAlign : self.Card.Card.LayoutTemplate.DeltaIndicator.Font? self.Card.Card.LayoutTemplate.DeltaIndicator.Font.Align : 'None'
							}, {
								valueType: 'Sparkline',
								visible: self.Card.Card.LayoutTemplate.Sparkline.Visible,
								cardDataType: 'Sparkline',
							}],
							editing: {
								mode: "cell",
								allowUpdating: true
							},
							onRowUpdated: function(e) {
								exampleCardConfig.layoutTemplate[e.key.valueType].Visible = e.key.visible;
								exampleCardConfig.layoutTemplate[e.key.valueType].ValueType = valueMap[e.key.cardDataType];
								if(!exampleCardConfig.layoutTemplate[e.key.valueType].Font){
									exampleCardConfig.layoutTemplate[e.key.valueType].Font = {Color: '#333', Size: 14, ColorVisible: false};
								}
								exampleCardConfig.layoutTemplate[e.key.valueType].Font.Color = e.key.fontColor;
								exampleCardConfig.layoutTemplate[e.key.valueType].Font.Size = e.key.fontSize;
								exampleCardConfig.layoutTemplate[e.key.valueType].Font.ColorVisible = e.key.fontColorVisible;
								exampleCardConfig.layoutTemplate[e.key.valueType].Font.Align = e.key.fontAlign;
								$('#exampleCard').empty().wiseCard(exampleCardConfig);
							},
							onEditorPreparing: function(e) {
							    if (e.row.data["cardDataType"] == 'Sparkline' && e.caption !== '표시') {
							    	e.editorOptions.readOnly = true;
							    }     
							}
						}).dxDataGrid('instance');
						// example card
						$('#exampleCard').wiseCard(exampleCardConfig);
						// confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
							self.Card.Card.LayoutTemplate.Type = layoutList.option('selectedItems')[0];
							//2020.07.24 mksong 카드 최대폭, 최소폭 기능 dogfoot
							//20200727 ajkim 카드 폰트 설정 추가 dogfoot
							self.Card.Card.LayoutTemplate.MinWidth = minWidth.option('value');
							self.Card.Card.LayoutTemplate.MaxWidth = autoWidth.option('value') ? 'auto' : maxWidth.option('value');
							//2020.08.05 mksong 카드 최대폭, 최소폭 기능 dogfoot
							self.Card.Card.LayoutTemplate.CardMinWidth = cardMinWidth.option('value');
							self.Card.Card.LayoutTemplate.CardMaxWidth = cardAutoWidth.option('value') ? 'auto' : cardMaxWidth.option('value');
							self.Card.Card.LayoutTemplate.TopValue.Visible = customLayoutGrid.cellValue(0, 'visible');
							self.Card.Card.LayoutTemplate.TopValue.ValueType = valueMap[customLayoutGrid.cellValue(0, 'cardDataType')];
							if(!self.Card.Card.LayoutTemplate.TopValue.Font){
								self.Card.Card.LayoutTemplate.TopValue.Font = {ColorVisible : false, Color: '#333', Size: 14, Align: 'None'};
							}
							self.Card.Card.LayoutTemplate.TopValue.Font.ColorVisible = customLayoutGrid.cellValue(0, 'fontColorVisible');
							self.Card.Card.LayoutTemplate.TopValue.Font.Color = customLayoutGrid.cellValue(0, 'fontColor');
							self.Card.Card.LayoutTemplate.TopValue.Font.Size = customLayoutGrid.cellValue(0, 'fontSize');
							self.Card.Card.LayoutTemplate.TopValue.Font.Align = customLayoutGrid.cellValue(0, 'fontAlign');
							self.Card.Card.LayoutTemplate.MainValue.Visible = customLayoutGrid.cellValue(1, 'visible');
							self.Card.Card.LayoutTemplate.MainValue.ValueType = valueMap[customLayoutGrid.cellValue(1, 'cardDataType')];
							if(!self.Card.Card.LayoutTemplate.MainValue.Font){
								self.Card.Card.LayoutTemplate.MainValue.Font = {ColorVisible : false, Color: '#333', Size: 14, Align: 'None'};
							}
							self.Card.Card.LayoutTemplate.MainValue.Font.ColorVisible = customLayoutGrid.cellValue(1, 'fontColorVisible');
							self.Card.Card.LayoutTemplate.MainValue.Font.Color = customLayoutGrid.cellValue(1, 'fontColor');
							self.Card.Card.LayoutTemplate.MainValue.Font.Size = customLayoutGrid.cellValue(1, 'fontSize');
							self.Card.Card.LayoutTemplate.MainValue.Font.Align = customLayoutGrid.cellValue(1, 'fontAlign');
							self.Card.Card.LayoutTemplate.SubValue.Visible = customLayoutGrid.cellValue(2, 'visible');
							self.Card.Card.LayoutTemplate.SubValue.ValueType = valueMap[customLayoutGrid.cellValue(2, 'cardDataType')];
							if(!self.Card.Card.LayoutTemplate.SubValue.Font){
								self.Card.Card.LayoutTemplate.SubValue.Font = {ColorVisible : false, Color: '#333', Size: 14, Align: 'None'};
							}
							self.Card.Card.LayoutTemplate.SubValue.Font.ColorVisible = customLayoutGrid.cellValue(2, 'fontColorVisible');
							self.Card.Card.LayoutTemplate.SubValue.Font.Color = customLayoutGrid.cellValue(2, 'fontColor');
							self.Card.Card.LayoutTemplate.SubValue.Font.Size = customLayoutGrid.cellValue(2, 'fontSize');
							self.Card.Card.LayoutTemplate.SubValue.Font.Align = customLayoutGrid.cellValue(2, 'fontAlign');
							self.Card.Card.LayoutTemplate.BottomValue1.Visible = customLayoutGrid.cellValue(3, 'visible');
							self.Card.Card.LayoutTemplate.BottomValue1.ValueType = valueMap[customLayoutGrid.cellValue(3, 'cardDataType')];
							if(!self.Card.Card.LayoutTemplate.BottomValue1.Font){
								self.Card.Card.LayoutTemplate.BottomValue1.Font = {ColorVisible : false, Color: '#333', Size: 14, Align: 'None'};
							}
							self.Card.Card.LayoutTemplate.BottomValue1.Font.ColorVisible = customLayoutGrid.cellValue(3, 'fontColorVisible');
							self.Card.Card.LayoutTemplate.BottomValue1.Font.Color = customLayoutGrid.cellValue(3, 'fontColor');
							self.Card.Card.LayoutTemplate.BottomValue1.Font.Size = customLayoutGrid.cellValue(3, 'fontSize');
							self.Card.Card.LayoutTemplate.BottomValue1.Font.Align = customLayoutGrid.cellValue(3, 'fontAlign');
							self.Card.Card.LayoutTemplate.BottomValue2.Visible = customLayoutGrid.cellValue(4, 'visible');
							self.Card.Card.LayoutTemplate.BottomValue2.ValueType = valueMap[customLayoutGrid.cellValue(4, 'cardDataType')];
							if(!self.Card.Card.LayoutTemplate.BottomValue2.Font){
								self.Card.Card.LayoutTemplate.BottomValue2.Font = {ColorVisible : false, Color: '#333', Size: 14, Align: 'None'};
							}
							self.Card.Card.LayoutTemplate.BottomValue2.Font.ColorVisible = customLayoutGrid.cellValue(4, 'fontColorVisible');
							self.Card.Card.LayoutTemplate.BottomValue2.Font.Color = customLayoutGrid.cellValue(4, 'fontColor');
							self.Card.Card.LayoutTemplate.BottomValue2.Font.Size = customLayoutGrid.cellValue(4, 'fontSize');
							self.Card.Card.LayoutTemplate.BottomValue2.Font.Align = customLayoutGrid.cellValue(4, 'fontAlign');
							self.Card.Card.LayoutTemplate.DeltaIndicator.Visible = customLayoutGrid.cellValue(5, 'visible');
							if(!self.Card.Card.LayoutTemplate.DeltaIndicator.Font){
								self.Card.Card.LayoutTemplate.DeltaIndicator.Font = {ColorVisible : false, Color: '#333', Size: 14, Align: 'None'};
							}
							self.Card.Card.LayoutTemplate.DeltaIndicator.Font.ColorVisible = customLayoutGrid.cellValue(5, 'fontColorVisible');
							self.Card.Card.LayoutTemplate.DeltaIndicator.Font.Color = customLayoutGrid.cellValue(5, 'fontColor');
							self.Card.Card.LayoutTemplate.DeltaIndicator.Font.Size = customLayoutGrid.cellValue(5, 'fontSize');
							self.Card.Card.LayoutTemplate.DeltaIndicator.Font.Align = customLayoutGrid.cellValue(5, 'fontAlign');
							self.Card.Card.LayoutTemplate.Sparkline.Visible = customLayoutGrid.cellValue(6, 'visible');
							//2020.08.05 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
							self.functionBinddata = true;
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
				if($('#editPopup').dxPopup('instance').option('height') !== 'auto'){
					setTimeout(function(){
						$('#editPopup').dxPopup('instance').option('height', 'auto');
					}, 1000)
				}
				
				break;
			}
			case 'editDelta': {
				/* DOGFOOT mksong 2020-07-21 카드 팝업 오류 수정  */
				if (!(self.dxItem)) {
					break;
				}
				var deltaOptions = self.meta.Card.CardDeltaOptions;
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
					'No indication': 'NoIndication'
				};
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '델타 옵션',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
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
							deltaOptions.ResultIndicationMode = deltaMapping[formData['결과 표시']];
							deltaOptions.ResultIndicationThresholdType = formData['임계값 유형'];
							deltaOptions.ResultIndicationThreshold = formData['임계값 값'] || 0;
							//2020.08.05 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
							self.functionBinddata = true;
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
			case 'editSparkline': {
				/* DOGFOOT mksong 2020-07-21 카드 팝업 오류 수정  */
				if (!(self.dxItem)) {
					break;
				}
				var sparklineOptions = self.meta.Card.SparklineOptions;
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '스파크 라인 옵션',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize template
						contentElement.append(	'<div id="' + self.itemid + '_sparklineOptions"></div>' +
												'<div style="padding-bottom:20px;"></div>' +
												'<div class="modal-footer" style="padding-bottom:0px;">' +
													'<div class="row center">' +
														'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
														'<a id="close" href="#" class="btn neutral close">취소</a>' +
													'</div>' +
												'</div>');
						
						// initialize components
						var sparklineForm = $('#' + self.itemid + '_sparklineOptions').dxForm({
							items: [
								{
									dataField: '스파크 라인 보기 형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Line', 'Area', 'Bar', 'Win/Loss'],
										value: sparklineOptions.ViewType
									}
								},
								{
									dataField: '최소/최대 포인트를 강조',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: sparklineOptions.HighlightMinMaxPoints
									}
								},
								{
									dataField: '시작/끝 포인트를 강조',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: sparklineOptions.HighlightStartEndPoints
									}
								}
							]
						}).dxForm('instance');
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
							var formData = sparklineForm.option('formData');
							sparklineOptions.ViewType = formData['스파크 라인 보기 형식'];
							sparklineOptions.HighlightMinMaxPoints = formData['최소/최대 포인트를 강조'];
							sparklineOptions.HighlightStartEndPoints = formData['시작/끝 포인트를 강조'];
							//2020.08.05 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
							self.functionBinddata = true;
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
				// do nothing if card is not initialized
				if (typeof self.meta === 'undefined' || typeof self.meta.Card === 'undefined') {
					break;
				}
				// gather field data
				var valueFieldId = '#cardValueList' + self.index;
				var actualValueFormat;
				var targetValueFormat;
				var absoluteVariationFormat = _.cloneDeep(self.meta.Card.AbsoluteVariationNumericFormat);
				var percentVariationFormat = _.cloneDeep(self.meta.Card.PercentVariationNumericFormat);
				var percentOfTargetFormat = _.cloneDeep(self.meta.Card.PercentOfTargetNumericFormat);
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
					formatList = ['Actual value', 'Target value', 'Absolute variation', 'Percent of target', 'Percent variation'];
				} else if (typeof actualValueFormat !== 'undefined') {
					selectedValueFormat = actualValueFormat;
					formatList = ['Actual value', 'Absolute variation', 'Percent of target', 'Percent variation'];
				} else {
					selectedValueFormat = absoluteVariationFormat;
					formatList = ['Absolute variation', 'Percent of target', 'Percent variation'];
				}

				/* DOGFOOT mksong 2020-07-21 카드 팝업 오류 수정  */
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '서식 옵션',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
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
										//20210712 AJKIM 소수점 방지 dogfoot
										format: "#",
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
							self.meta.Card.AbsoluteVariationNumericFormat = absoluteVariationFormat;
							self.meta.Card.PercentVariationNumericFormat = percentVariationFormat;
							self.meta.Card.PercentOfTargetNumericFormat = percentOfTargetFormat;
							//2020.08.05 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
							self.functionBinddata = true;
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
	}

	/**
	 * Clear master filter selections and tracking on all items.
	 */
	this.clearTrackingConditions = function() {
		/* DOGFOOT mksong 2020-08-05 마스터필터 클리어 추가 */
		if (self.IO && self.IO.MasterFilterMode) {
			if (self.dxItem) {
				self.dxItem.forEach(function(card) {
					card.clearSelection();
				});
			}
			self.trackingData = [];
			self.selectedPoint = undefined;
		}
	};
	
	/**
	 * Initialize header buttons for download, master filter, etc.
	 * @param _itemid HTML DOM identifier for card container
	 */
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
//		var buttonPanelId = _itemid + '_topicon';
//		var topIconPanel = $('#' + buttonPanelId);
//		
//		// export data
//		if (WISE.Constants.browser !== 'IE9') {
//			var page = window.location.pathname.split('/');
//			if (page[page.length - 1] === 'viewer.do') {
//				var exportDataId = _itemid + '_topicon_exp';
//				var exportHtml = '<li><a id="' + exportDataId + '" href="#"><img src="' + WISE.Constants.context + '/images/cont_box_icon_export.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_export_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_export.png\'" alt="Export To PNG" title="Export To PNG"></a></li>';
//				topIconPanel.append(exportHtml);
//
//				if ($.type(this.seriesDimensions) === 'array' && this.seriesDimensions.length > 0 && $.type(this.cards) === 'array' && this.cards.length > 1) {
//					// value-panel selection
//					var valueListId = _itemid + '_topicon_vl';
//					var popoverid = _itemid + '_topicon_vl_popover';
//					var valueListHtml = '<li><a id="' + valueListId + '" href="#"><img src="' + WISE.Constants.context + 
//						'/images/cont_box_icon_layer.png" onMouseOver="this.src=\'' + WISE.Constants.context + 
//						'/images/cont_box_icon_layer_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + 
//						'/images/cont_box_icon_layer.png\'" alt="Select Panel" title="Select Panel"></a></li>';
//					topIconPanel.append(valueListHtml);
//					var popoverHtml = '<div id="' + popoverid + '"><ul style="width: 300px">';
//					$.each(this.cards, function(_i, _vo) {
//						var caption = $.type(_vo.actual) === 'object' ? _vo.actual.caption : '';
//						caption += $.type(_vo.target) === 'object' ? ' vs ' + _vo.target.caption : '';
//						popoverHtml += '<li style="clear: both; cursor: pointer;" data-panel-key="' + (self.itemid + '_' + _vo.wiseId) + '">' + caption + '</li>';
//					});
//					popoverHtml += '</ul></div>';
//					$('body').append(popoverHtml);
//					var popover = $("#" + popoverid).dxPopover({
//						target: "#" + valueListId,
//						position: "bottom",	
//						shading: false,
//						shadingColor: "rgba(0, 0, 0, 0.5)"
//					}).dxPopover("instance");
//					$("#" + valueListId).click(function() {popover.show();});
//					$('#' + popoverid).on('click', function(_e) {
//						popover.hide();
//						var targetPanelId = _e.target.getAttribute('data-panel-key');
//					});
//				}
//			} else {
//				$('#export_popover').dxPopover({
//					height: 'auto',
//					width: 195,
//					position: 'bottom',
//					visible: false,
//				});
//				var exportDataId = this.itemid + '_topicon_exp';
//				//2020.02.20 MKSONG 다운로드 아이콘 통일 DOGFOOT
//				var exportHtml = '<li id="' + exportDataId + '" title="내보내기" class="img"><img src="' + WISE.Constants.context + '/resources/main/images/ico-download_new.png" alt="이미지 다운로드"></li>';
//
//	            topIconPanel.find('.lm_maximise').before(exportHtml);
//				
//				$('#'+exportDataId).off('click').click(function(){
//					var p = $('#export_popover').dxPopover('instance');
//					p.option({
//						target: topIconPanel,
//						contentTemplate: function() {
//							var html = '';
//							html += '<div class="add-item noitem" style="padding:0px;">';
//							html += '	<span class="add-item-head on">다운로드</span>';
//							html += '	<ul class="add-item-body">';
//							html += '		<li id="typeImg" class="exportFunction" title="이미지 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_exportImages.png" alt="이미지 다운로드"><span>이미지 다운로드</span></a></li>';
//							html += '		<li id="typeCsv" class="exportFunction" title="CSV 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcexcell.png" alt="CSV 다운로드"><span>CSV 다운로드</span></a></li>';
//							html += '		<li id="typeTxt" class="exportFunction" title="TXT 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_txt.png" alt=""><span>TXT 다운로드</span></a></li>';
//							html += '	</ul>';
//							html += '</div>';
//	                        return html;
//						}
//					});
//					p.show();
//				});
//
//				// tracking conditions clear
//				if (self.IO && self.IO['MasterFilterMode']) {
//					self.trackingClearId = self.itemid + '_topicon_tracking_clear';
//					
//					//20200506 ajkim 마스터필터가 적용된 경우에만 마스터 필터 초기화 활성화 dogfoot
//					var trackingClearHtml;
//					if(self.IO['MasterFilterMode'] === 'Off')
//						trackingClearHtml = '<li id="' + self.trackingClearId + '" title="마스터 필터 초기화" class="nofilter invisible"></li>';
//					else
//						trackingClearHtml = '<li id="' + self.trackingClearId + '" title="마스터 필터 초기화" class="nofilter"></li>';
//					
//					topIconPanel.find('.lm_maximise').before(trackingClearHtml);
//				}
//				if(self.IO && self.IO['IsDrillDownEnabled'] !== null) {
//					self.DrilldownClearId = self.itemid + '_topicon_drilldown_clear';
//					var DrillDownClearHtml = '<li id="' + self.DrilldownClearId + '" title="드릴업" class="back"></li>';
//					topIconPanel.find('.lm_maximise').before(DrillDownClearHtml);
//				}
//			}
//		}
	};
};

/**
 * Card panel container manager class.
 */
WISE.libs.Dashboard.item.CardGenerator.PanelManager = function() {
	var self = this;
	
	this.parentLayerId;
	this.itemid; // pie chart item id, chartItem
	this.gaugePanel = {};
	
	//2020.02.07 mksong sqllike 적용 dogfoot
	this.dataSourceId;
	
	this.childPanelIdBastenn = [];
	
	var G = 0.50;
	//2020.07.30 MKSONG DOGFOOT 카드 사이즈 오류 수정
//	this.itemPanelMinWidth = 250;
	this.itemPanelMinHeight = 200;
	
	//2020.02.07 mksong sqllike 적용 dogfoot
	this.init = function(_dataSource) {
		this.gaugePanel = {};
		this.childPanelIdBastenn = [];
		this.dataSourceId = _dataSource;
	}
	
	//2020.07.24 mksong 카드 최대폭, 최소폭 기능 dogfoot
	/* DOGFOOT MKSONG 2020-07-29 카드 콘텐츠 배열 기능 추가 */
	/* DOGFOOT mksong 2020-08-06 카드 마스터필터 무시 오류 수정 */
	this.makePanel = function(_cards, _seriesDimensions, _rawData, _dimensions, _measures, _CardLayout, _CardArragneMode, _arragneMaxCount, _IO, _instance) {
		self.CardLayout = _CardLayout;
		self.IO = _IO;
		/* DOGFOOT MKSONG 2020-07-29 카드 콘텐츠 배열 기능 추가 */
		self.ContentArrangementMode = _CardArragneMode;
		self.ContentLineCount = _arragneMaxCount;
		this.makeCardPanel(_cards, _seriesDimensions, _instance);
		
		if (_seriesDimensions && _seriesDimensions.length > 0) {
			this.makeChildPanelBySeriesDimensions(_seriesDimensions, _rawData, _dimensions, _measures, _instance);
		} else {
			this.makeChildPanelWithoutDimensions(_cards, _rawData, _measures, _instance);
		}
		
		//2020.05.04 AJKIM 데이터 항목 없을 때 이미지 추가 DOGFOOT
		if (!self.finalData || ($.type(self.finalData) === 'array' && self.finalData.length === 0)) {
			$('#'+self.itemid + ' .nodata-layer').remove();
			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
			$("#" + self.itemid).children().css('display','none');
			$("#" + self.itemid).prepend(nodataHtml);
			$("#" + self.itemid).css('display', 'block');
			gProgressbar.hide();
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}

			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();	
				gDashboard.updateReportLog();
			}
		}else{
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
	};
	
	/**
	 * Create an uninitialized card panel instance.
	 * @param _cards card widget data
	 */
	this.makeCardPanel = function(_cards, _seriesDimensions, _instance) {
		var PP = $('#' + this.itemid);
		PP.empty();
		
		$.each(_cards, function(_i, _v) {
			var seriesName = '';
			var subSeriesName = '';
			var caption = '';
			//20210713 AJKIM 카드 사용자정의 데이터 추가 dogfoot
			var fieldList = gDashboard.customFieldManager.fieldInfo[_instance.dataSourceId];
			$.each(fieldList, function(i, field){
				if(_v.actual && field.Name == _v.actual.name){
					_v.actual.captionBySummaryType = field.Name;
				}else if(_v.target && field.Name == _v.target.name){
					_v.target.captionBySummaryType = field.Name;
				}
			});
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
			var id = self.itemid + '_' + _v.wiseId;
			var activeCssClass = 'active'
			var valuePanel = $('<div id="' + id + '" class="dx-item-card-panel ' + activeCssClass + '"></div>');
			PP.append(valuePanel);
			self.gaugePanel[id] = {
				panel: valuePanel, 
				sn: seriesName, 
				ssn: subSeriesName, 
				title: caption, 
				actual: _v.actual,
				target: _v.target,
				sparkline: _v.sparkline
			};
		});
	};
	
	var calcChildPanelSize = function(_vp, _childCount, _maxCols, _maxRows) {
		var ww = _vp.panel.width();
		var hh = _vp.panel.height();
		var itemPanelHeightSize;
		var itemPanelWidthSize;
		
		/* DOGFOOT mksong 2020-08-05 콘텐츠 배열 & 폭 최적화 */
//		var maxCols = typeof _maxCols === 'number' ? _maxCols : Math.ceil(Math.sqrt(_childCount));
		var maxCols;
		if(_maxRows == undefined){
			maxCols = typeof _maxCols === 'number' ? _maxCols : Math.ceil(Math.sqrt(_childCount));
		}else{
			/* DOGFOOT mksong 2020-08-10 카드 열 최대값 오류 수정 */
			maxCols = typeof _maxCols === 'number' ? _maxCols : Math.ceil(_childCount / _maxRows);
		}
		
		var maxRows = _maxRows == undefined ? Math.ceil(_childCount / maxCols) : _maxRows;

		var maxWidth = self.CardLayout.CardMaxWidth;
		var minWidth = self.CardLayout.CardMinWidth;
		
        if (maxRows === 1 || hh < self.itemPanelMinHeight) {
			itemPanelHeightSize = hh - 10;
		} else {
			for (var i = maxRows; i > 0; i--) {
				itemPanelHeightSize = Math.floor(hh / i) - 10;
				if (itemPanelHeightSize >= self.itemPanelMinHeight) {
					break;
				}
			}
		}
		//2020.07.30 MKSONG DOGFOOT 카드 사이즈 오류 수정
		if (maxCols === 1 || ww < self.CardLayout.MinWidth) {
			itemPanelWidthSize = ww - 10;
		/* DOGFOOT mksong 2020-08-05 콘텐츠 배열 & 폭 최적화 */
		} else if(minWidth * maxCols > ww){
			itemPanelWidthSize = minWidth;
		} else if(maxWidth * maxCols < ww){
			itemPanelWidthSize = maxWidth;
		} else {
			for (var i = maxCols; i > 0; i--) {
				itemPanelWidthSize = Math.floor(ww / i) - 10;
				//2020.07.30 MKSONG DOGFOOT 카드 사이즈 오류 수정
				if (itemPanelWidthSize >= self.CardLayout.MinWidth) {
					break;
				}
			}
		}
        
        /* DOGFOOT mksong 2020-08-05 콘텐츠 배열 & 폭 최적화 */
        return {
			w: itemPanelWidthSize, 
			h: itemPanelHeightSize,
			maxw: maxWidth,
			minw: minWidth,
			/* DOGFOOT mksong 2020-08-10 카드 사이즈 오류 수정 */
//			marginCount: ww > (maxCols + 2) * itemPanelWidthSize ? (maxCols * maxRows - _childCount) : 0,
			marginCount: (maxCols * maxRows - _childCount),
			marginw : (ww - (maxCols * itemPanelWidthSize)) / 2 -10,
			maxCols: maxCols,
			maxRows: maxRows
		};
	};
	
	this.resize = function() {
		var childCount = self.childPanelIdBastenn.length;
		$.each(this.gaugePanel, function(_n, _vp) {
			/* DOGFOOT MKSONG 2020-07-29 카드 콘텐츠 배열 기능 추가 */
			var size;
			if(self.ContentArrangementMode == 'Auto'){
				size = calcChildPanelSize(_vp, childCount);	
			}else{
				if(self.ContentArrangementMode == 'FixedRowCount'){
					size = calcChildPanelSize(_vp, childCount, undefined, self.ContentLineCount);
				}else{
					size = calcChildPanelSize(_vp, childCount, self.ContentLineCount);
				}
			}
			
			/* DOGFOOT mksong 2020-08-10 카드 사이즈 오류 수정 */
			if(size.w * size.maxCols > _vp.panel.width()){
				$('#'+self.itemid).find('.ul-panel').css('min-width',(size.w * size.maxCols + 20) +'px');
			}else{
				$('#'+self.itemid).find('.ul-panel').css('min-width','auto');
			}
			
//			$('#'+self.itemid).find('.ul-panel').css('overflow','hidden');
			
			$.each(self.childPanelIdBastenn, function(_i, _childPanelId) {
				//2020.07.24 mksong 카드 최대폭, 최소폭 기능 dogfoot
				var width = size.w;
				if(size.w < size.minw){
					width = size.minw;
				}
				
				if(size.maxw !='auto' && (size.w > size.maxw)){
					width = size.maxw;
				}
				$('#'+_childPanelId)
        		.css('width', width)
        		.css('height', size.h);
				
				/* DOGFOOT mksong 2020-08-10 카드 사이즈 오류 수정 */
//				if(size.marginCount > 0 && (_i+1) <= ((size.maxRows-1) * size.maxCols)){
//					if((_i+1) % size.maxCols == 1){
//						$('#'+_childPanelId)
//		        		.css('margin-left', size.marginw);
//					}else if((_i+1) % size.maxCols == 0){
//						$('#'+_childPanelId)
//		        		.css('margin-right', size.marginw);
//					}
//				}
//				else{
//					$('#'+_childPanelId)
//	        		.css('margin-left', 0)
//	        		.css('margin-right', 0);
//				}
            });
		});
		gProgressbar.hide();
	};
	
	this.makeChildPanel = function(_childCount) {
		$.each(this.gaugePanel, function(_n, _vp) {
			_vp.panel.empty();
			
			/* DOGFOOT MKSONG 2020-07-29 카드 콘텐츠 배열 기능 추가 */
			var size;
			if(self.ContentArrangementMode == 'Auto'){
				size = calcChildPanelSize(_vp, _childCount);	
			}else{
				if(self.ContentArrangementMode == 'FixedRowCount'){
					size = calcChildPanelSize(_vp, _childCount, undefined, self.ContentLineCount);
				}else{
					size = calcChildPanelSize(_vp, _childCount, self.ContentLineCount);
				}
			}
			
			/* DOGFOOT mksong 2020-08-10 카드 사이즈 오류 수정 */
			var idSeq = 0, tablePanel;
			if(size.w * size.maxCols > _vp.panel.width()){
				tablePanel = '<ul class="ul-panel" style="min-width:' + size.w * size.maxCols +'px; height: auto; overflow:hidden;">';	
			}else{
				tablePanel = '<ul class="ul-panel">';
			}
			 
			for (var row = 0; row < _childCount; row++) {
				var id = _n + '_' + (idSeq++);
				self.childPanelIdBastenn.push(id);
				
				/* DOGFOOT mksong 2020-08-10 콘텐츠 배열 & 폭 최적화 */
				if(size.marginCount > 0 && (row+1) <= ((size.maxRows-1) * size.maxCols)){
					if((row + 1) % size.maxCols == 1){
						tablePanel += '<li id="' + id + '" class="child-panel" style="width: ' + size.w + 'px; height: ' + size.h + 'px;';	
					}else if((row + 1) % size.maxCols == 0){
						tablePanel += '<li id="' + id + '" class="child-panel" style="width: ' + size.w + 'px; height: ' + size.h + 'px;';
					}else{
						tablePanel += '<li id="' + id + '" class="child-panel" style="width: ' + size.w + 'px; height: ' + size.h + 'px;';
					}
				}else {
					//2020.07.24 mksong 카드 최대폭, 최소폭 기능 dogfoot
					tablePanel += '<li id="' + id + '" class="child-panel" style="width: ' + size.w + 'px; height: ' + size.h + 'px;';
				}
				if(size.maxw){
					if(size.maxw != 'auto'){
						tablePanel += 'max-width:' + size.maxw + 'px;';	
					}
				}
				if(size.minw){
					tablePanel += 'min-width:'+size.minw + 'px;';
				}
				tablePanel += '"></li>';
			}
			tablePanel += '</ul>';
			
			_vp.panel.html(tablePanel);
			
			/* DOGFOOT mksong 2020-08-10 카드 사이즈 오류 수정 */
			if(size.w * size.maxCols > _vp.panel.width()){
				_vp.panel.css('overflow','auto');
			}
		});
	};

	this.makeChildPanelWithoutDimensions = function(_cardData, _rawData, _measures, _instance) {
		self.finalData = [];
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;

		//20210713 AJKIM 카드 사용자정의 데이터 추가 dogfoot
		this.calculatedFields = [];
		this.tempMeasureFields = [];
		/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
		this.tempDimensionFields = [];
		this.calculateCaption;
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[this.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(_measures,function(_i,_measure){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_measure != undefined){
							if(field.Name == _measure.name){
								self.calculatedFields.push(_measure);
								self.calculateCaption = _measure.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.measures,function(_k, _measure){
											if(_tempDataField == _measure.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								_measures.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
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
										_measures.push(dataMember);
										self.tempMeasureFields.push(_measures.length-1);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
				});
			}
		}
		
		//2020.07.31 MKSGON fromJsonForCaptionBySummaryType로 변경 DOGFOOT
		var tempResultConfig = WISE.libs.Dashboard.Query.likeSql.fromJsonForCaptionBySummaryType([], _measures, _rawData);
		
		/* DOGFOOT mksong 2020-08-10 카드 마스터필터 오류 수정 */
		if(self.IO.IgnoreMasterFilters || (self.IO.MasterFilterMode != undefined && self.IO.MasterFilterMode != 'Off')){
			tempResultConfig.Where = [];
		}
		var tempResult = WISE.libs.Dashboard.Query.likeSql.doSqlLike(self.dataSourceId, tempResultConfig, _instance);
		self.tempData = tempResult;
		_instance.filteredData = tempResult;

		//2020.02.04 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 수정 끝 dogfoot
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && self.calculatedFields.length > 0) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[self.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(self.calculatedFields,function(_i,_calculatedField){
						if(field.Name == _calculatedField.name){
							/* DOGFOOT shlim 사용자 정의 데이터 정렬기준항목으로 생성 가능하도록 수정  20210121 */
							gDashboard.customFieldManager.addCustomFieldsToDataSourceForSummaryValue(field, tempResult, _calculatedField, _measures, [],self.HiddenMeasures);		
							gDashboard.customFieldManager.addCustomFieldsToDataSource(field, self.globalData, true);
						}
					});
				});
			}
		}

		gDashboard.customFieldManager.addSummaryFieldData(self, tempResult);
		
		$.each(tempResult, function(i, data) {
			var title = '';
			var subtitle = '';
			//20210722 AJKIM 카드 타이틀 오류 수정
			/*if(_cardData[i].Name && _cardData[i].Name != ''){
				title = _instance.getDefaultName();
			}
			else */if (_cardData[i].actual) {
				title = _cardData[i].actual.captionBySummaryType;
				if (_cardData[i].target) {
					title += ' vs ' + _cardData[i].target.captionBySummaryType;
				}
			}
			else if (_cardData[i].target) {
				title = _cardData[i].target.captionBySummaryType;
			}
			self.finalData.push({t: title, st: subtitle, d: data});
		});
		
		self.makeChildPanel(self.finalData.length);
	};
	
	this.makeChildPanelBySeriesDimensions = function(_seriesDimensions, _rawData, _dimensions, _measures, _instance) {
		self.finalData = [];
		//2020.02.07 mksong sqllike 적용 dogfoot
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		//2020.07.31 MKSGON fromJsonForCaptionBySummaryType로 변경 DOGFOOT
		//20210713 AJKIM 카드 사용자정의 데이터 추가 dogfoot
		this.calculatedFields = [];
		this.tempMeasureFields = [];
		/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
		this.tempDimensionFields = [];
		this.calculateCaption;
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[this.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(_measures,function(_i,_measure){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_measure != undefined){
							if(field.Name == _measure.name){
								self.calculatedFields.push(_measure);
								self.calculateCaption = _measure.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.measures,function(_k, _measure){
											if(_tempDataField == _measure.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								_measures.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
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
										_measures.push(dataMember);
										self.tempMeasureFields.push(_measures.length-1);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
					/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
					$.each(self.dimensions,function(_i,_dimension){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_dimension != undefined){
							if(field.Name == _dimension.name){
								self.calculatedFields.push(_dimension);
								self.calculateCaption = _dimension.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.dimensions,function(_k, _dimension2){
											if(_tempDataField == _dimension2.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								_dimension.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
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
										_dimension.push(dataMember);
										self.tempDimensionFields.push(_dimension.length-1);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
				});
			}
		}
		/* DOGFOOT mksong 2020-08-06 카드 오타 및 마스터필터 무시 오류 수정 */
		var tempResultConfig = SQLikeUtil.fromJsonForCaptionBySummaryType(_dimensions, _measures, _rawData, { orderBy: _dimensions });
		/* DOGFOOT mksong 2020-08-10 카드 마스터필터 오류 수정 */
		if(self.IO.IgnoreMasterFilters || (self.IO.MasterFilterMode != undefined && self.IO.MasterFilterMode != 'Off')){
			tempResultConfig.Where = [];
		}
		
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		/* DOGFOOT mksong 2020-08-06 카드 오타 및 마스터필터 무시 오류 수정 */
		var tempResult = SQLikeUtil.doSqlLike(self.dataSourceId, tempResultConfig, _instance);
		//20210713 AJKIM 카드 사용자정의 데이터 추가 dogfoot
		_instance.tempData = tempResult;
		_instance.filteredData = tempResult;

		//2020.02.04 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 수정 끝 dogfoot
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && self.calculatedFields.length > 0) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[self.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(self.calculatedFields,function(_i,_calculatedField){
						if(field.Name == _calculatedField.name){
							/* DOGFOOT shlim 사용자 정의 데이터 정렬기준항목으로 생성 가능하도록 수정  20210121 */
							gDashboard.customFieldManager.addCustomFieldsToDataSourceForSummaryValue(field, tempResult, _calculatedField, _measures, _dimensions,self.HiddenMeasures);		
							gDashboard.customFieldManager.addCustomFieldsToDataSource(field, self.globalData, true);
						}
					});
				});
			}
		}

		gDashboard.customFieldManager.addSummaryFieldData(self, tempResult);
		
		$.each(tempResult, function(i, data) {
			var seriesNames = [];
			var title = '';
			var subtitle = '';
			$.each(_seriesDimensions, function(j, series) {
				seriesNames.push(data[series.caption]);
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
 * Card data field manager class.
 */
WISE.libs.Dashboard.CardFieldManager = function() {
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
	this.sparkline = [];
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
		this.sparkline = [];
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
			// var listType = $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'cardValueList' || 
			// $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'card_hide_measure_list' ? true : false;
			// 20200728 ajkim 카드 정렬 기준 항목 추가 dogfoot
			if (listType === 'cardValueList' || listType === 'card_hide_measure_list') {
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
					dataItem.CubeUniqueName = $(_fieldlist[i]).attr('cubeUniNm');
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
					dataItem.CubeUniqueName = $(_fieldlist[i]).attr('cubeUniNm');
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

	this.setSparklineArgumentByField = function(_sparkline) {
		if (typeof _sparkline[0] === 'object') {
			return { UniqueName: _sparkline[0].uniqueName };
		} else {
			return undefined;
		}
	}
	
	 this.setHiddenMeasuresByField = function(_hiddenMeasure){
	 	this.HiddenMeasures = {'Measure' : []};
	 	_.each(_hiddenMeasure,function(_a){
	 		var Value = {'UniqueName' : _a.uniqueName};
	 		self.HiddenMeasures['Measure'].push(Value);
	 	})
	 	return self.HiddenMeasures;
	 };

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
	
};
