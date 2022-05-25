/**
 *
 */
WISE.libs.Dashboard.item.AdhocReportUtility={
	Save: function(_FieldChooser){
		var self = this;
		var gridData;
		var chartData;

		// 2021-03-15 yyb 아이템이 하나일때 Loop에서 차트를 먼저 체크하는 에러 수정(차트가 null)
		var _dxItemBasten;
		var sLayout = gDashboard.structure.Layout;
//	    var sKind = sLayout == 'G' ? 'pivotGrid' : '';	// 그리드만 체크한다.
		/*dogfoot 그리드만 보기 구조 변경
		* 그리드만 보기 저장후 불러와서 다시 저장 하면 오류 & 차트 보기 변경시 오류
		* 차트 meta 정보는 저장되어있어야함
		shlim 20210324*/
	    var sKind = '';	// 그리드만 체크한다.
		if (sKind != '') {
        	_dxItemBasten = gDashboard.itemGenerateManager.dxItemBasten.filter(function(el) {
        		return el.kind == sKind;
        	});
        }
        else {
        	_dxItemBasten = gDashboard.itemGenerateManager.dxItemBasten;
        }

		$.each(_dxItemBasten, function(_i,_o) {
			if (_o.type == 'PIVOT_GRID') {
				self.PIVOT = _o;
				self.GR = _o.dxItem;
//				gridData = self.GR.getDataSource();
				var fields = [];
				$.each(self.PIVOT.dataSourceConfig.fields, function(_ii, _dd){
					if(_dd.area == 'column' || _dd.area == 'row' || _dd.area == 'hidden') {
						fields.push(_dd);
					} else {
						$.each(self.PIVOT.DI.Measure, function(_iii, _ddd){
							if(_ddd.UNI_NM == _dd.UNI_NM){
								fields.push(_dd);
							}
						});
					}
				});
				gridData = fields;
			}
			else {
				self.CHART = _o;
				if(_o.dxItem){
					self.CH = _o.dxItem;
					chartData = self.CH.getDataSource();
				}
			}
		});
// this.CH = gDashboard.itemGenerateManager.dxItemBasten[0].dxItem;
// this.GR = gDashboard.itemGenerateManager.dxItemBasten[1].dxItem;
		this.fieldfilter = new WISE.libs.Dashboard.FieldFilter();
		this.CU = WISE.libs.Dashboard.item.ChartUtility;
		this.getCaptionName = function(_fldNm){
			var dimensions = gDashboard.itemGenerateManager.dxItemBasten[1].dimensions;
			var measures = gDashboard.itemGenerateManager.dxItemBasten[0].measures;
			var caption = ''
			$.each(dimensions, function(_i, _d){
				if(_d.name == _fldNm){
					caption = _d.rawCaption;
				}
			});

			$.each(measures, function(_i, _d){
				if(_d.name == _fldNm){
					caption = _d.rawCaption;
				}
			});
			return caption;

		};


		var report_mstr = {};
		var report_json = {};


		var rowArray = [];
		var colArray = [];
		var dataArray = [];
		var dataSortArray = [];
		var gridArray = [];
		var paramArray = [];

		var chart_option = {};
		var param_option = {};

		//2020.04.09 mksong 비정형 아이템 이름 변경 저장 및 불러오기 dogfoot
		var titleElement = {'PIVOT_TITLE': self.PIVOT ? self.PIVOT.meta.Name : '', 'CHART_TITLE': self.CHART ? self.CHART.meta.Name : ''};
		var memoElement = {'PIVOT_MEMO': self.PIVOT ? self.PIVOT.meta.MemoText : '', 'CHART_MEMO': self.CHART ? self.CHART.meta.MemoText : ''};
		var gridElement = {};
		var rowElement = {};
		var colElement = {};
		var dataElement = {};
		var dataSortElement = {};

		if(self.PIVOT){
			$.each(gridData,function(_i,_e){
				var report_option = {};
				var grid_option = {};
				var sort_option = {};
				switch(_e.area){
				case 'column':
					if(WISE.Context.isCubeReport) {
						report_option['UNI_NM'] = _e.cubeUNI_NM;
						grid_option['UNI_NM'] = _e.cubeUNI_NM;
						grid_option['TYPE'] = 'DIM';
					} else {
						report_option['UNI_NM'] = _e.UNI_NM;
						grid_option['UNI_NM'] = _e.UNI_NM;
						grid_option['TYPE'] = 10;
					}
					report_option['FLD_NM'] = _e.UNI_NM;
					report_option['AREA_INDEX'] = _e.areaIndex;

					colArray.push(report_option);

					grid_option['FLD_NM'] = _e.UNI_NM;
					grid_option['CAPTION'] = _e.caption;
					grid_option['FORMAT_STRING'] = '';
// report_option['VISIBLE'] = 'Y';
					grid_option['VISIBLE'] = _e.visible == true ? 'Y':'N';
					grid_option['DRAW_CHART'] =  _e.DRAW_CHART == true ? 'Y':'N';
// switch(_e.visible){
// case true:
// // report_option['VISIBLE'] = 'Y';
// grid_option['DRAW_CHART'] = 'Y';
// grid_option['VISIBLE'] = 'Y';
// break;
// case false:
// // report_option['VISIBLE'] = 'N';
// grid_option['DRAW_CHART'] = 'N';
// grid_option['VISIBLE'] = 'N';
// break;
// default:
// // report_option['VISIBLE'] = 'Y';
// grid_option['DRAW_CHART'] = 'Y';
// grid_option['VISIBLE'] = 'Y';
// break;
// }
					grid_option['SUMMARY_TYPE'] = '';
					gridArray.push(grid_option);

					if(_e.sortByField != undefined){
						sort_option['SORT_FLD_NM'] = _e.UNI_NM;
						sort_option['BASE_FLD_NM'] = _e.sortByField;
						sort_option['SORT_MODE'] = _e.sortOrder == 'asc' ? 'ASC' : 'DESC';
						dataSortArray.push(sort_option);
					//2020.03.10 mksong 비정형 정렬 오류 수정 dogfoot
					}else{
						sort_option['SORT_FLD_NM'] = _e.UNI_NM;
						sort_option['BASE_FLD_NM'] = _e.UNI_NM;
						sort_option['SORT_MODE'] = _e.sortOrder == 'asc' ? 'ASC' : 'DESC';
						dataSortArray.push(sort_option);
					}
					break;

				case 'row':
					if(WISE.Context.isCubeReport) {
						report_option['UNI_NM'] = _e.cubeUNI_NM;
						grid_option['UNI_NM'] = _e.cubeUNI_NM;
						grid_option['TYPE'] = 'DIM';
					} else {
						report_option['UNI_NM'] = _e.UNI_NM;
						grid_option['UNI_NM'] = _e.UNI_NM;
						grid_option['TYPE'] = 10;
					}
					report_option['FLD_NM'] = _e.UNI_NM;
					report_option['AREA_INDEX'] = _e.areaIndex;
					rowArray.push(report_option);
					grid_option['FLD_NM'] = _e.UNI_NM;
					grid_option['CAPTION'] = _e.caption;
					grid_option['FORMAT_STRING'] = '';
// report_option['VISIBLE'] = 'Y';
					grid_option['VISIBLE'] = _e.visible == true ? 'Y':'N';
					grid_option['DRAW_CHART'] =  _e.DRAW_CHART == true ? 'Y':'N';
// switch(_e.visible){
// case true:
// // report_option['VISIBLE'] = 'Y';
// grid_option['VISIBLE'] = 'Y';
// grid_option['DRAW_CHART'] = 'Y';
// break;
// case false:
// // report_option['VISIBLE'] = 'N';
// grid_option['VISIBLE'] = 'N';
// grid_option['DRAW_CHART'] = 'N';
// break;
// default:
// // report_option['VISIBLE'] = 'Y';
// grid_option['VISIBLE'] = 'Y';
// grid_option['DRAW_CHART'] = 'Y';
// break;
// }
					grid_option['SUMMARY_TYPE'] = '';
					gridArray.push(grid_option);

					if(_e.sortByField != undefined){
						sort_option['SORT_FLD_NM'] = _e.UNI_NM;
						sort_option['BASE_FLD_NM'] = _e.sortByField;
						sort_option['SORT_MODE'] = _e.sortOrder == 'asc' ? 'ASC' : 'DESC';
						dataSortArray.push(sort_option);
					//2020.03.10 mksong 비정형 정렬 오류 수정 dogfoot
					}else{
						sort_option['SORT_FLD_NM'] = _e.UNI_NM;
						sort_option['BASE_FLD_NM'] = _e.UNI_NM;
						sort_option['SORT_MODE'] = _e.sortOrder == 'asc' ? 'ASC' : 'DESC';
						dataSortArray.push(sort_option);
					}
					break;
				case 'data':
					if(_e.UNI_NM.indexOf('DELTA_FIELD') != -1){
						if(WISE.Context.isCubeReport) {
							report_option['UNI_NM'] = _e.cubeUNI_NM;
							grid_option['UNI_NM'] = _e.cubeUNI_NM;
						} else {
							report_option['UNI_NM'] = _e.UNI_NM;
							grid_option['UNI_NM'] = _e.UNI_NM;
						}
						report_option['FLD_NM'] = _e.UNI_NM;
						report_option['FORMAT_TYPE'] = 'Numeric';
						report_option['FORMAT_STRING'] = _e.format.key;
						report_option['VISIBLE'] = 'Y';
						grid_option['VISIBLE'] = _e.visible == true ? 'Y':'N';
						grid_option['DRAW_CHART'] =  _e.DRAW_CHART == true ? 'Y':'N';
// switch(_e.visible){
// case true:
// report_option['VISIBLE'] = 'Y';
// grid_option['VISIBLE'] = _e.visible;
// grid_option['DRAW_CHART'] = 'Y';
// break;
// case false:
// report_option['VISIBLE'] = 'N';
// grid_option['VISIBLE'] = 'N';
// grid_option['DRAW_CHART'] = 'N';
// break;
// default:
// report_option['VISIBLE'] = 'Y';
// grid_option['VISIBLE'] = 'Y';
// grid_option['DRAW_CHART'] = 'Y';
// break;
// }
						report_option['AREA_INDEX'] = _e.areaIndex;
						switch(_e.summaryType){
						case 'count':
							report_option['SUMMARY_TYPE'] = '0';
							break;
						case 'sum':
							report_option['SUMMARY_TYPE'] = '1';
							break;
						case 'min':
							report_option['SUMMARY_TYPE'] = '2';
							break;
						case 'max':
							report_option['SUMMARY_TYPE'] = '3';
							break;
						case 'avg':
							report_option['SUMMARY_TYPE'] = '4';
							break;
						/*dogfoot shlim  본사적용 필요 20210701*/
						case 'countdistinct':
							report_option['SUMMARY_TYPE'] = '5';
							break;
						}
// report_option['SUMMARY_TYPE'] = '1';
						grid_option['TYPE'] = 'DELTA';
						grid_option['FLD_NM'] = _e.UNI_NM;
						grid_option['CAPTION'] = _e.caption;
						grid_option['FORMAT_STRING'] =  _e.format.key;

						grid_option['SUMMARY_TYPE'] = '';
					}
					else{
						if(WISE.Context.isCubeReport) {
							report_option['UNI_NM'] = _e.cubeUNI_NM;
							grid_option['UNI_NM'] = _e.cubeUNI_NM;
							grid_option['TYPE'] = 'MEA';
						} else {
							report_option['UNI_NM'] = _e.UNI_NM;
							grid_option['UNI_NM'] = _e.UNI_NM;
							grid_option['TYPE'] = 11;
						}
						report_option['FLD_NM'] = _e.UNI_NM;
						report_option['FORMAT_TYPE'] = 'Numeric';
						report_option['FORMAT_STRING'] =  _e.format.key;
						report_option['VISIBLE'] = 'Y';
						grid_option['VISIBLE'] = _e.visible == true ? 'Y':'N';
						grid_option['DRAW_CHART'] =  _e.DRAW_CHART == true ? 'Y':'N';
						/*dogfoot 피벗그리드 포멧 저장 추가 shlim 20210329 */
						if(typeof self.PIVOT != "undefined"){
                        	$.each(self.PIVOT.DI.Measure,function(_im,_mea){
                        		if(_mea.UNI_NM == _e.UNI_NM){
                        			report_option['NUMERIC_FORMAT'] = _mea.NumericFormat;
                        		}
                        	})
                        }
// switch(_e.visible){
// case true:
// report_option['VISIBLE'] = 'Y';
// grid_option['VISIBLE'] = 'Y';
// grid_option['DRAW_CHART'] = 'Y';
// break;
// case false:
// report_option['VISIBLE'] = 'N';
// grid_option['VISIBLE'] = 'N';
// grid_option['DRAW_CHART'] = 'N';
// break;
// default:
// report_option['VISIBLE'] = 'Y';
// grid_option['VISIBLE'] = 'Y';
// grid_option['DRAW_CHART'] = 'Y';
// break;
// }
						report_option['AREA_INDEX'] = _e.areaIndex;
						switch(_e.summaryType){
						case 'count':
							report_option['SUMMARY_TYPE'] = '0';
							break;
						case 'sum':
							report_option['SUMMARY_TYPE'] = '1';
							break;
						case 'min':
							report_option['SUMMARY_TYPE'] = '2';
							break;
						case 'max':
							report_option['SUMMARY_TYPE'] = '3';
							break;
						case 'avg':
							report_option['SUMMARY_TYPE'] = '4';
							break;
						/*dogfoot shlim  본사적용 필요 20210701*/
						case 'countdistinct':
							report_option['SUMMARY_TYPE'] = '5';
							break;
						}
// report_option['SUMMARY_TYPE'] = '1';
						grid_option['FLD_NM'] = _e.UNI_NM;
						grid_option['CAPTION'] = _e.caption;
						grid_option['FORMAT_STRING'] = _e.format.key;

						switch(_e.summaryType){
						case 'count':
							grid_option['SUMMARY_TYPE'] = '0';
							break;
						case 'sum':
							grid_option['SUMMARY_TYPE'] = '1';
							break;
						case 'min':
							grid_option['SUMMARY_TYPE'] = '2';
							break;
						case 'max':
							grid_option['SUMMARY_TYPE'] = '3';
							break;
						case 'avg':
							grid_option['SUMMARY_TYPE'] = '4';
							break;
						/*dogfoot shlim  본사적용 필요 20210701*/
						case 'countdistinct':
							report_option['SUMMARY_TYPE'] = '5';
							break;
						}
					}
					dataArray.push(report_option);
					gridArray.push(grid_option);
					break;
				case 'hidden':
					if(WISE.Context.isCubeReport) {
						report_option['UNI_NM'] = _e.cubeUNI_NM;
						grid_option['UNI_NM'] = _e.cubeUNI_NM;
					} else {
						report_option['UNI_NM'] = _e.UNI_NM;
						grid_option['UNI_NM'] = _e.UNI_NM;
					}
					report_option['FLD_NM'] = _e.dataField;

					report_option['VISIBLE'] = 'N';
					grid_option['VISIBLE'] = 'N';
					grid_option['DRAW_CHART'] =  'N';
					report_option['HIDDEN'] =  true;
					report_option['AREA_INDEX'] = _e.areaIndex;
					if(_e.summaryType != undefined){
						report_option['FORMAT_TYPE'] = 'Numeric';
						/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */
						report_option['FORMAT_STRING'] =  '';
						if(WISE.Context.isCubeReport) {
							grid_option['TYPE'] = 'MEA';
						}else{
							grid_option['TYPE'] = 11;
						}
						switch(_e.summaryType){
						case 'count':
							report_option['SUMMARY_TYPE'] = '0';
							grid_option['SUMMARY_TYPE'] = '0';
							break;
						case 'sum':
							report_option['SUMMARY_TYPE'] = '1';
							grid_option['SUMMARY_TYPE'] = '1';
							break;
						case 'min':
							report_option['SUMMARY_TYPE'] = '2';
							grid_option['SUMMARY_TYPE'] = '2';
							break;
						case 'max':
							report_option['SUMMARY_TYPE'] = '3';
							grid_option['SUMMARY_TYPE'] = '3';
							break;
						case 'avg':
							report_option['SUMMARY_TYPE'] = '4';
							grid_option['SUMMARY_TYPE'] = '4';
							break;
						/*dogfoot shlim  본사적용 필요 20210701*/
						case 'countdistinct':
							report_option['SUMMARY_TYPE'] = '5';
							grid_option['SUMMARY_TYPE'] = '5';
							break;
						}
						dataArray.push(report_option);
					}else{
						if(WISE.Context.isCubeReport) {
							grid_option['TYPE'] = 'DIM';
						} else {
							grid_option['TYPE'] = 10;
						}
						rowArray.push(report_option);
					}

//report_option['SUMMARY_TYPE'] = '1';
					grid_option['FLD_NM'] = _e.dataField;
					grid_option['CAPTION'] = _e.caption;;
					/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */

					gridArray.push(grid_option);
					break;
				}
			});

			if(colArray.length == 0)
				report_json['COL_ELEMENT'] = "";
			else{
				colElement['COL'] = colArray;
				report_json['COL_ELEMENT'] = colElement;
			}
			if(rowArray.length ==0)
				report_json['ROW_ELEMENT'] = "";
			else{
				rowElement['ROW'] = rowArray;
				report_json['ROW_ELEMENT'] = rowElement;
			}
			dataElement['DATA'] = dataArray;
			dataSortElement['DATA_SORT'] = dataSortArray;
			report_json['DATA_ELEMENT'] = dataElement;
			report_json['DATASORT_ELEMENT'] = dataSortElement;
			/* DOGFOOT hsshim 200109 비정형 사용자 정의 데이터 저장 */
			report_json['CALCDATA_ELEMENT'] = gDashboard.customFieldManager.getAdhocCalcDataElement();

			report_json['DELTAVALUE_ELEMENT'] = [];



			var deltaArray = [];
			var deltaElement = {};

			$.each(self.PIVOT.deltaItems,function(_i,_delta){
				var eachItem = {
					'FLD_NM' : _delta.FLD_NM,
					'CAPTION' : _delta.CAPTION,
					'BASE_UNI_NM' : _delta.BASE_UNI_NM,
					'BASE_FLD_NM' : _delta.BASE_FLD_NM,
					'DELTA_VALUE_TYPE' : _delta.DELTA_VALUE_TYPE
				};
				deltaArray.push(eachItem);
			});


			if(deltaArray.length == 0)
				report_json['DELTAVALUE_ELEMENT'] = "";
			else{
				deltaElement['DELTA_VALUE'] = deltaArray;
				report_json['DELTAVALUE_ELEMENT'] = deltaElement;
			}
			
			// 비정형 변동측정값 옵션 저장
			report_json['DELTA_OPT'] = self.PIVOT.meta.deltaOpt;

			report_json['HIGHLIGHT_ELEMENT'] = [];

			var highlightArray = [];
			var highlightElement = {};

			$.each(self.PIVOT.highlightItems,function(_i,_highlight){
				var back_color = gDashboard.itemColorManager.hexToRgb(_highlight.BACK_COLOR);
				var fore_color = gDashboard.itemColorManager.hexToRgb(_highlight.FORE_COLOR);
				var eachItem = {
					'SEQ':_highlight.ID+1000,
					'UNI_NM':_highlight.FLD_NM,
					'FLD_NM':_highlight.FLD_NM,
					'COND':_highlight.COND,
					'VALUE1':_highlight.VALUE1,
					'VALUE2':_highlight.VALUE2 == null ? '' : _highlight.VALUE2,
					'BACK_COLOR':back_color.r+","+back_color.g+","+back_color.b,
					'FORE_COLOR':fore_color.r+","+fore_color.g+","+fore_color.b,
					'APPLY_CELL': _highlight.APPLY_CELL == true ? 'Y':'N',
					'APPLY_TOTAL': _highlight.APPLY_TOTAL == true ? 'Y':'N',
					'APPLY_GRANDTOTAL' : _highlight.APPLY_GRANDTOTAL == true ? 'Y':'N',
					'IMAGE_INDEX':_highlight.IMAGE_INDEX == ""? "": (Number(_highlight.IMAGE_INDEX) -1)+""
				}
				highlightArray.push(eachItem);
			});

			if(highlightArray.length == 0)
				report_json['HIGHLIGHT_ELEMENT'] = "";
			else{
				highlightElement['HIGHLIGHT'] = highlightArray;
				report_json['HIGHLIGHT_ELEMENT'] = highlightElement;
			}

			report_json['MULTISUMMARY_ELEMENT'] = '';

			report_json['TOPBOTTOM_ELEMENT'] = [];

			var topBottomArray = [];
			var topBottomElement = {};
			if(self.PIVOT.topBottomInfo.DATA_FLD_NM != ''){
				var topBottomInfo = self.PIVOT.topBottomInfo;
				var eachItem = {
					'DATA_UNI_NM': topBottomInfo.DATA_FLD_NM,
					'DATA_FLD_NM' : topBottomInfo.DATA_FLD_NM,
					'APPLY_UNI_NM' : topBottomInfo.APPLY_FLD_NM,
					'APPLY_FLD_NM' : topBottomInfo.APPLY_FLD_NM,
					'TOPBOTTOM_TYPE': topBottomInfo.TOPBOTTOM_TYPE,
					'TOPBOTTOM_CNT': topBottomInfo.TOPBOTTOM_CNT,
					'PERCENT' : topBottomInfo.PERCENT == true ? 'Y':'N',
					'SHOW_OTHERS' : topBottomInfo.SHOW_OTHERS == true ? 'Y':'N'
				};
				topBottomArray.push(eachItem);
			}
			if(topBottomArray.length == 0)
				report_json['TOPBOTTOM_ELEMENT'] = "";
			else{
				topBottomElement['TOPBOTTOM_VALUE'] = topBottomArray;
				report_json['TOPBOTTOM_ELEMENT'] = topBottomElement;
			}

			if(gDashboard.structure.ReportMasterInfo.subquery != undefined){
				report_json['SUBQUERY_ELEMENT'] = gDashboard.structure.ReportMasterInfo.subquery;
			}
			/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
			var nullRemoveType = 'noRemove';
			if(typeof self.PIVOT.meta.NullRemoveType != 'undefined') {
				nullRemoveType = self.PIVOT.meta.NullRemoveType;
			}
			/*dogfoot 피벗그리드 필터표시 설정 추가 shlim 20201130*/
			var dimFilterMode = 'OFF';
			if(typeof self.PIVOT.meta.DimFilterMode != 'undefined') {
				dimFilterMode = self.PIVOT.meta.DimFilterMode;
			}
			// 20200619 ajkim 비정형 메모 저장 dogfoot
			report_json['WEB'] = { 'MEMO_ELEMENT': memoElement, 'NULL_REMOVE_TYPE': nullRemoveType};
			gridElement['GRID'] = gridArray;
			gridElement['LAYOUT_TYPE'] = self.PIVOT.meta.LayoutType;
			report_json['TITLE_ELEMENT'] = titleElement;
			report_json['GRID_ELEMENT'] = gridElement;
			report_json['MEALOC_ELEMENT'] = 'Col';
			report_json['MEALOC_AREAINDEX'] = '0';
			/*dogfoot 비정형 보고서 저장 오류 수정 shlim 20210329 */
			if(self.PIVOT.dxItem){
			    if(self.PIVOT.dxItem.option('showTotalsPrior') == "both"){
					report_json['TOTALLOC_ELEMENT'] = 'Top';
				}else{
					report_json['TOTALLOC_ELEMENT'] = 'Bottom';
				}	
			}else{
			    report_json['TOTALLOC_ELEMENT'] = 'Bottom';	
			}

			//2020.11.13 mksong 비정형 보고서 showCaption 기능 추가 dogfoot
			report_json['DISP_PIVOT_CAPTION_ELEMENT'] = self.PIVOT.meta.ShowCaption == true ? 'True':'False';
			report_json['DISP_COL_TOTAL_ELEMENT'] = self.PIVOT.meta.ShowColumnTotals == true ? 'True':'False';
			report_json['DISP_COL_GRANDTOTAL_ELEMENT'] = self.PIVOT.meta.ShowColumnGrandTotals == true ? 'True':'False';
			report_json['DISP_ROW_TOTAL_ELEMENT'] =  self.PIVOT.meta.ShowRowTotals == true ? 'True':'False';
			report_json['DISP_ROW_GRANDTOTAL_ELEMENT'] =  self.PIVOT.meta.ShowRowGrandTotals == true ? 'True':'False';
			/*dogfoot 피벗그리드 필터표시 설정 추가 shlim 20201130*/
			report_json['DIM_FILTER_MODE'] =  typeof self.PIVOT.meta.DimFilterMode != 'undefined' ? self.PIVOT.meta.DimFilterMode : 'OFF';
			/*dogfoot 비정형 초기상태 저장 추가 shlim 20200717*/
			report_json['AUTOEXPAND_COLUMNGROUPS_ELEMENT'] =  self.PIVOT.meta.AutoExpandColumnGroups == true ? 'True':'False';
			report_json['AUTOEXPAND_ROWGROUPS_ELEMENT'] =  self.PIVOT.meta.AutoExpandRowGroups == true ? 'True':'False';
			report_json['DATA_OPTION_UNBOUND_MODE'] = 'UseSummaryValues';
			/*dogfoot 피벗 그리드 측정값 행열 위치 설정 저장 dev20 이상에서만 작동 shlim 20210324*/
			report_json["DATA_FIELD_POSITION"] = self.PIVOT.meta.DataFieldPosition ? self.PIVOT.meta.DataFieldPosition : "column";
			/*dogfoot shlim 20210414*/
			report_json["AUTO_SIZE_ENABLED"] = self.PIVOT.meta.AutoSizeEnabled === true ? 'True':'False';
			
			// 비정형 피벗그리드 페이징옵션 저장
			report_json["PAGING_OPTIONS"] = self.PIVOT.meta.pagingOptions;
			// 20210826 행열 전환 저장
			report_json["COLROWSWITCH"] = self.PIVOT.meta.ColRowSwitch ? true : false;
		}
		/*dogfoot 비정형 그리드 저장 오류 수정 shlim 20210329 */
		if(self.CHART){
			var measureElements = [];
			chart_option['WEB'] = [];

			$.each(WISE.util.Object.toArray(self.CHART.meta.DataItems.Measure), function(index, measure) {
				measureElements.push({
					UNI_NM: measure.UniqueName,
					NAME: measure.Name,
					NUMERIC_FORMAT: {
						FORMAT_TYPE: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.FormatType : 'Number',
						UNIT: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.Unit : 'Ones',
						SUFFIX_ENABLED: (typeof measure.NumericFormat !== 'undefined' && measure.NumericFormat.SuffixEnabled) ? 'Y' : 'N',
						SUFFIX: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.Suffix : { O: '', K: '천', M: '백만', B: '십억' },
						PRECISION: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.Precision : 0,
						PRECISION_OPTION: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.PrecisionOption : '반올림',
						INCLUDE_GROUP_SEPARATOR: (typeof measure.NumericFormat !== 'undefined' && measure.NumericFormat.IncludeGroupSeparator) ? 'Y' : 'N',
					}
				})
			});

			chart_option['WEB'] = {CHART_DATA_ELEMENT : {
				MEASURES: measureElements,
				PANE_ELEMENT: [],
				/* DOGFOOT ktkang 비정형 저장 추가  20200810 */
				LEGEND_POSITION: {},
				AXISY_OPTION: {},
				ROTATED: false
			}};
			/* DOGFOOT ktkang 비정형 저장 추가  20200810 */
			if(typeof self.CHART.meta.ChartLegend != 'undefined') {
				var chartLegend = {
					VISIBLE: typeof self.CHART.meta.ChartLegend.Visible !== 'undefined' ? self.CHART.meta.ChartLegend.Visible : true,
					ISINSIDEPOSITION: typeof self.CHART.meta.ChartLegend.IsInsidePosition !== 'undefined' ? self.CHART.meta.ChartLegend.IsInsidePosition : false,
					INSIDEPOSITION: typeof self.CHART.meta.ChartLegend.InsidePosition !== 'undefined' ? self.CHART.meta.ChartLegend.InsidePosition : 'TopRightHorizontal',
					OUTSIDEPOSITION: typeof self.CHART.meta.ChartLegend.OutsidePosition !== 'undefined' ? self.CHART.meta.ChartLegend.OutsidePosition : 'TopRightHorizontal'
				};

				chart_option['WEB']['CHART_DATA_ELEMENT']['LEGEND_POSITION'] = chartLegend;
			}

			if(typeof self.CHART.meta.Rotated != 'undefined') {
				chart_option['WEB']['CHART_DATA_ELEMENT']['ROTATED'] = self.CHART.meta.Rotated;
			}

			if(typeof self.CHART.meta.AxisY !== 'undefined') {
				var axisY = {
					TITLE: (typeof self.CHART.meta.AxisY.Title !== 'undefined') ? self.CHART.meta.AxisY.Title : '',
					FORMAT_TYPE: (typeof self.CHART.meta.AxisY.FormatType !== 'undefined') ? self.CHART.meta.AxisY.FormatType : 'Number',
					UNIT: (typeof self.CHART.meta.AxisY.Unit !== 'undefined') ? self.CHART.meta.AxisY.Unit : 'Ones',
					SUFFIX_ENABLED: (typeof self.CHART.meta.AxisY.SuffixEnabled !== 'undefined' && self.CHART.meta.AxisY.SuffixEnabled) ? 'Y' : 'N',
					SUFFIX: (typeof self.CHART.meta.AxisY.Suffix !== 'undefined') ? self.CHART.meta.AxisY.Suffix : { O: '', K: '천', M: '백만', B: '십억' },
					PRECISION: (typeof self.CHART.meta.AxisY.Precision !== 'undefined') ? self.CHART.meta.AxisY.Precision : 0,
					PRECISION_OPTION: (typeof self.CHART.meta.AxisY.Precision !== 'undefined') ? self.CHART.meta.AxisY.PrecisionOption : '반올림',
					INCLUDE_GROUP_SEPARATOR: (typeof self.CHART.meta.AxisY.IncludeGroupSeparator !== 'undefined' && self.CHART.meta.AxisY.IncludeGroupSeparator) ? 'Y' : 'N',
					SHOW_FOR_ZERO_VALUES: (typeof self.CHART.meta.AxisY.ShowZero !== 'undefined') ? self.CHART.meta.AxisY.ShowZero : true,
					VISIBLE: (typeof self.CHART.meta.AxisY.Visible !== 'undefined') ? self.CHART.meta.AxisY.Visible : true
				};

				chart_option['WEB']['CHART_DATA_ELEMENT']['AXISY_OPTION'] = axisY;
			}

			if (typeof self.CHART.meta.AxisY != 'undefined' || typeof self.CHART.meta.Panes.Pane.Series.Simple != 'undefined' ||
				typeof self.CHART.meta.Panes.Pane.Series.Weighted != 'undefined' || self.CHART.meta.Panes.Pane.Series.Ranged != 'undefined') {
				// series options
				var seriesElement = [];
				$.each(WISE.util.Object.toArray(self.CHART.meta.DataItems.Measure), function(i, measure) {
					var uniqueName = measure.UniqueName;
					var name = measure.Name;
					var found = false;
					$.each(WISE.util.Object.toArray(self.CHART.meta.Panes.Pane.Series.Simple), function(j, series) {
						if (uniqueName === series.Value.UniqueName) {
							seriesElement.push({
								SERIES_KEY: 'Series_' + i,
								UNI_NM: uniqueName,
								SERIES_INDEX: i,
								SERIES_NAME: name,
								SERIES_PANE_NAME: self.CHART.meta.Panes.Pane.Name,
								SERIES_CODE: 'SimpleSeries',
								SERIES_TYPE: series.SeriesType,
								LINE_STYLE_TYPE: 0,
								SERIES_WIDTH: 0.5,
								SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
								SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
								SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
								SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor),
								IGNORE_EMPTY_POINTS: series.IgnoreEmptyPoints,
								PLOT_ON_SECONDARY_AXIS: series.PlotOnSecondaryAxis,
                                SHOW_POINT_MARKER: series.ShowPointMarkers,
                                CONTENT_TYPE: series.PointLabelOptions.ContentType,
                                ORIENTATION: series.PointLabelOptions.Orientation,
                                OVERLAPPING_MODE: series.PointLabelOptions.OverlappingMode,
                                POSITION: series.PointLabelOptions.Position,
                                SHOW_FOR_ZERO_VALUES: series.PointLabelOptions.ShowForZeroValues
							});
							found = true;
							return false;
						}
					});
					if (found) {
						return true;
					}
					$.each(WISE.util.Object.toArray(self.CHART.meta.Panes.Pane.Series.Weighted), function(j, series) {
						if (uniqueName === series.Value.UniqueName) {
							seriesElement.push({
								SERIES_KEY: 'Series_' + i,
								UNI_NM: uniqueName,
								SERIES_INDEX: i,
								SERIES_NAME: name,
								SERIES_PANE_NAME: self.CHART.meta.Panes.Pane.Name,
								SERIES_CODE: 'WeightedSeries',
								SERIES_TYPE: series.SeriesType,
								LINE_STYLE_TYPE: 0,
								SERIES_WIDTH: 0.5,
								SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
								SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
								SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
								SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
							});
							found = true;
							return false;
						}
					});
					if (found) {
						return true;
					}
					$.each(WISE.util.Object.toArray(self.CHART.meta.Panes.Pane.Series.Ranged), function(j, series) {
						if (uniqueName === series.Value.UniqueName) {
							seriesElement.push({
								SERIES_KEY: 'Series_' + i,
								UNI_NM: uniqueName,
								SERIES_INDEX: i,
								SERIES_NAME: name,
								SERIES_PANE_NAME: self.CHART.meta.Panes.Pane.Name,
								SERIES_CODE: 'RangedSeries',
								SERIES_TYPE: series.SeriesType,
								LINE_STYLE_TYPE: 0,
								SERIES_WIDTH: 0.5,
								SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
								SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
								SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
								SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
							});
						}
					});
				});
				chart_option['WEB']['CHART_DATA_ELEMENT']['PANE_ELEMENT'] = {};
				chart_option['WEB']['CHART_DATA_ELEMENT']['PANE_ELEMENT'] = {SERIESE_ELEMENT : seriesElement};
			}
			/*dogfoot 비정형 그리드 저장 오류 수정 shlim 20210329 */
			chart_option['CHART_TYPE']=self.CU.Series.Simple.getChartNumber(self.CH?self.CH.option('commonSeriesSettings.type'):"");
			chart_option['PALETTE'] = self.CHART.meta.Palette;
			chart_option['DRAW_DATA_BASIS'] = 'Measure';
			chart_option['LEGEND_ENABLE'] = self.CHART.meta.ChartLegend.Visible ? 'True' : 'False',
			chart_option['LEGEND_STYLE'] = 'Table';
			/* DOGFOOT hsshim 2020-02-06 비정형 범례 저장 오류 수정 */
			chart_option['LEGEND_DOCK'] = self.CU.Legend.setAdhoc(self.CHART.meta.ChartLegend.OutsidePosition);
			chart_option['LEGEND_POSITION'] = self.CHART.meta.ChartLegend.IsInsidePosition ? 'True' : 'False';
			chart_option['USE_PERCENT'] = 'False';
			chart_option['VALUE_SHOWN_AS_LABEL'] = 'True';
			chart_option['EMPTY_POINT_STYLE'] = 'Empty';
			chart_option['SERIES_MARK_SIZE'] = 8;
			chart_option['SERIES_BORDER_WIDTH'] = 3;
			chart_option['ENABLE_3D'] = 'False';
			chart_option['CLUSTERED'] = 'False';
			chart_option['POINT_DEPTH'] = 100;
			chart_option['POINT_GAP_DEPTH'] = 100;
			chart_option['PERSPEXTIVE'] = 0;
			chart_option['RIGHT_ANGLE_AXES'] = 'False';
			chart_option['X_ANGLE'] = self.CHART.meta.AxisX.Rotation;
			chart_option['Y_ANGLE'] = 0;
			chart_option['AXISX_MAJOR_GRID_ENABLED'] = self.CHART.meta.AxisX.Visible;
//			chart_option['AXISX_MAJOR_GRID_ENABLED'] = self.CH.option('argumentAxis.grid.visible');
			/*dogfoot 비정형 그리드 저장 오류 수정 shlim 20210329 */
			chart_option['AXISX_MINOR_GRID_ENABLED'] = self.CH?self.CH.option('commonAxisSettings.minorGrid.visible'):"";
			chart_option['AXISX_INTERLACED'] = 'False';
			/*dogfoot 비정형 그리드 저장 오류 수정 shlim 20210329 */
			chart_option['AXISX_REVERSE'] = self.CH? self.CH.option('argumentAxis.inverted'):"";
			chart_option['AXISX_MARGIN'] = 'True';
			chart_option['AXISX_INTERVAL'] = 0;
			chart_option['AXISX_INTERVAL_OFFSET'] = 0;
			chart_option['AXISX_INTERVAL_TYPE'] = 0;
			chart_option['AXISX_TITLE'] = self.CHART.meta.AxisX.Title;
			chart_option['AXISY_MAJOR_GRID_ENABLED'] = self.CHART.meta.AxisY.Visible;
//			chart_option['AXISY_MAJOR_GRID_ENABLED'] = self.CH.option('valueAxis.gird.visible');
			chart_option['AXISY_MINOR_GRID_ENABLED'] = 'False';
			chart_option['AXISY_INTERLACED'] = 'False';
			/*dogfoot 비정형 그리드 저장 오류 수정 shlim 20210329 */
			chart_option['AXISY_REVERSE'] = self.CH?self.CH.option('valueAxis.inverted'):"";
			chart_option['AXISY_MARGIN'] = 'True';
			chart_option['AXISY_INTERVAL'] = 0;
			chart_option['AXISY_INTERVAL_OFFSET'] = 0;
			chart_option['AXISY_INTERVAL_TYPE'] = 0;
			chart_option['ANIMATION'] = self.CHART.meta.Animation;
			chart_option['AXISY_MAX'] = 0;
			chart_option['AXISY_MIN'] = 0;
			/*dogfoot 비정형 그리드 저장 오류 수정 shlim 20210329 */
			chart_option['AXISY_SCALE_BREAK'] = self.CH?self.CH.option('valueAxis.type'):"";
			chart_option['AXISY_TITLE'] = self.CHART.meta.AxisY.Title
			/*dogfoot 비정형 그리드 저장 오류 수정 shlim 20210329 */
			chart_option['AXISY2_MAJOR_GRID_ENABLED'] = self.CH?self.CH.option('valueAxis.gird.visible'):"";
			chart_option['AXISY2_MINOR_GRID_ENABLED'] = 'False';
			chart_option['AXISY2_INTERLACED'] = 'False';
			chart_option['AXISY2_REVERSE'] = 'False';
			chart_option['AXISY2_MARGIN'] = 'True';
			chart_option['AXISY2_INTERVAL'] = 0;
			chart_option['AXISY2_INTERVAL_OFFSET'] = 0;
			chart_option['AXISY2_INTERVAL_TYPE'] = 0;
			chart_option['AXISY2_MAX'] = 0;
			chart_option['AXISY2_MIN'] = 0;
			chart_option['AXISY2_SCALE_BREAK'] = '';
			chart_option['AXISY2_TITLE'] = '';
			var property = 1;
// $.each(self.CH.getAllSeries(),function(_i,_e){
// chart_option['SERIES'+(_i+1)+"_UNI_NM"] = _e.name;
// chart_option['SERIES'+(_i+1)+"_CHART_TYPE"] =
// self.CU.Series.Simple.getChartNumber(_e.type);
// if(_e.axis.indexOf('SECONDARY')!=-1)
// chart_option['SERIES'+(_i+1)+"_AXISY2"] = 'True';
// else
// chart_option['SERIES'+(_i+1)+"_AXISY2"] = 'False';
// property++;
// });
			var originDSID = "";

			for(property;property<=self.CHART.measures.length;property++)
			{
				var name = '',
					chartType = '',
					y2 = 'False',
					measure = self.CHART.measures[property - 1];
				if (typeof measure !== 'undefined') {
					var uniqueName = measure.uniqueName;
					name = measure.UNI_NM;

					var dataItemOptions = $('#dataAdHocList' + self.PIVOT.fieldManager.index).find('li[dataitem="' + uniqueName + '"] .seriesoption').data('dataItemOptions');
					/* DOGFOOT ktkang 비정형 불러오기 후 저장 오류 수정  20200707 */
					/*dogfoot 비정형 그리드 저장 오류 수정 shlim 20210329 */
					if(dataItemOptions != undefined && !$.isEmptyObject(dataItemOptions) && dataItemOptions.seriesType != undefined) {
						chartType = self.CU.Series.Simple.getChartNumber(dataItemOptions.seriesType.toLowerCase());
						y2 = dataItemOptions.plotOnSecondaryAxis ? 'True' : 'False';
					}
				}
				chart_option['SERIES'+(property)+"_UNI_NM"] = name;
				chart_option['SERIES'+(property)+"_CHART_TYPE"] = chartType;
				chart_option['SERIES'+(property)+"_AXISY2"] = y2;
			}

			//2020.11.13 mksong 비정형 보고서 showCaption 기능 추가 dogfoot
			report_json['DISP_CHART_CAPTION_ELEMENT'] = self.CHART.meta.ShowCaption == true ? 'True':'False';
		}

		report_mstr['REPORT_XML'] = report_json;
		report_mstr['CHART_XML'] = chart_option;

		if(_FieldChooser.DATASRC_TYPE == "CUBE"){
// var condition = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

// $.each(condition,function(_i,_paramItems){
// _paramItems.value = _paramItems.paramName;
// });
			WISE.Context.isCubeReport = true;

			var param = {
				'pid': WISE.Constants.pid,
				'dsid': _FieldChooser.DATASRC_ID,
				'dstype' : _FieldChooser.DATASRC_TYPE,
				'params': {}
			};

			var selected = {dim:[],mea:[]};

			var G,R,C,D,DU;
			DU = WISE.libs.Dashboard.item.DataUtility;
			G = report_mstr['REPORT_XML']['GRID_ELEMENT'] ? WISE.util.Object.toArray(report_mstr['REPORT_XML']['GRID_ELEMENT']['GRID']) : [];
			R = report_mstr['REPORT_XML']['ROW_ELEMENT'] ? WISE.util.Object.toArray(report_mstr['REPORT_XML']['ROW_ELEMENT']['ROW']) : [];
			C = report_mstr['REPORT_XML']['COL_ELEMENT'] ? WISE.util.Object.toArray(report_mstr['REPORT_XML']['COL_ELEMENT']['COL']) : [];
			D = report_mstr['REPORT_XML']['DATA_ELEMENT'] ? WISE.util.Object.toArray(report_mstr['REPORT_XML']['DATA_ELEMENT']['DATA']) : [];

			// rows
			if(R.length >= 1){
				_.each(R, function(_R) {
					var member = DU.getRowMember(_R, G);

					if (member['VISIBLE'] === 'Y') {
						selected.dim.push({uid: WISE.Context.isCubeReport ? (member.isCCF ? member['CAPTION'] : member['UNI_NM']) : member['CAPTION']});
					}
				});
			}
			// columns
			if(C.length >= 1){
				_.each(C, function(_C) {
					var member = DU.getColumnMember(_C, G);
					if (member['VISIBLE'] === 'Y') {
						selected.dim.push({uid: WISE.Context.isCubeReport ? (member.isCCF ? member['CAPTION'] : member['UNI_NM']) : member['CAPTION']});
					}
				});
			}
			if(D.length >= 1){
				// datas
				_.each(D, function(_D) {
					var member = DU.getMeasureMember(_D, G);
					if (member['VISIBLE'] === 'Y') {
						selected.mea.push({uid: WISE.Context.isCubeReport ? (member.isCCF ? member['CAPTION'] : member['UNI_NM']) : member['CAPTION']});
					}
				});
			}
			param.cols = $.toJSON(selected);
// var paramObject = WISE.libs.Dashboard.item.ReportUtility.getCubeSql(param);
// report_mstr['originSql'] = paramObject.CubeSql;
// originDSID = paramObject.DS_ID;
			report_mstr['originSql'] = _FieldChooser.SQL_QUERY;
		}
		report_mstr['PARAM_XML'] = gDashboard.parameterFilterBar.parameterInformation.length == 0? '': gDashboard.parameterFilterBar.parameterInformation;
		report_mstr['DATASET'] = _FieldChooser;

		if (gDashboard.customParameterHandler.getArrayCalcParamInfomation().length > 0){
			$.extend(report_mstr['PARAM_XML'], gDashboard.customParameterHandler.calcParameterInformation);
		}
		var tempobj = {};
		tempobj['REPORT_META'] = report_mstr;
		return tempobj;
	},
	generateDefault:function(){
		var newReport =
		{
			"REPORT_XML": {
				"COL_ELEMENT": {
					"COL": {
					}
				},
				"ROW_ELEMENT": {
					"ROW": {
					}
				},
				"DATA_ELEMENT": {
					"DATA": {
					}
				},
				"DATASORT_ELEMENT": {
					"DATA_SORT": {
					}
				},
				"GRID_ELEMENT": {
				},
				"SUBQUERY_ELEMENT": {
				},
				"MEALOC_ELEMENT": "Col",
				"MEALOC_AREAINDEX": "0",
				"TOTALLOC_ELEMENT": "Bottom",
				"DISP_COL_TOTAL_ELEMENT": "True",
				"DISP_COL_GRANDTOTAL_ELEMENT": "True",
				"DISP_ROW_TOTAL_ELEMENT": "True",
				"DISP_ROW_GRANDTOTAL_ELEMENT": "True",
				"FIXED_ROW_HEADERS_ELEMENT": "0",
				"DATA_OPTION_UNBOUND_MODE": "UseSummaryValues"
			},
			"CHART_XML": {
			    "CHART_TYPE": "10",
			    "PALETTE": "Default",
			    "DRAW_DATA_BASIS": "Measure",
			    "LEGEND_ENABLE": "True",
			    "LEGEND_STYLE": "Table",
			    "LEGEND_DOCK": "Right",
			    "VALUE_SHOWN_AS_LABEL": "True",
			    "EMPTY_POINT_STYLE": "Empty",
			    "SERIES_MARK_SIZE": "8",
			    "SERIES_BORDER_WIDTH": "3",
			    "ENABLE_3D": "False",
			    "CLUSTERED": "False",
			    "POINT_DEPTH": "100",
			    "POINT_GAP_DEPTH": "100",
			    "PERSPEXTIVE": "0",
			    "RIGHT_ANGLE_AXES": "True",
			    "X_ANGLE": "30",
			    "Y_ANGLE": "30",
			    "AXISX_MAJOR_GRID_ENABLED": "True",
			    "AXISX_MINOR_GRID_ENABLED": "False",
			    "AXISX_INTERLACED": "False",
			    "AXISX_REVERSE": "False",
			    "AXISX_MARGIN": "True",
			    "AXISX_INTERVAL": "0",
			    "AXISX_INTERVAL_OFFSET": "0",
			    "AXISX_INTERVAL_TYPE": "0",
			    "AXISY_MAJOR_GRID_ENABLED": "True",
			    "AXISY_MINOR_GRID_ENABLED": "False",
			    "AXISY_INTERLACED": "False",
			    "AXISY_REVERSE": "False",
			    "AXISY_MARGIN": "True",
			    "AXISY_INTERVAL": "0",
			    "AXISY_INTERVAL_OFFSET": "0",
			    "AXISY_INTERVAL_TYPE": "0",
			    "AXISY_MAX": "0",
			    "AXISY_MIN": "0",
			    "AXISY_SCALE_BREAK": "False",
			    "AXISY2_MAJOR_GRID_ENABLED": "True",
			    "AXISY2_MINOR_GRID_ENABLED": "False",
			    "AXISY2_INTERLACED": "False",
			    "AXISY2_REVERSE": "False",
			    "AXISY2_MARGIN": "True",
			    "AXISY2_INTERVAL": "0",
			    "AXISY2_INTERVAL_OFFSET": "0",
			    "AXISY2_INTERVAL_TYPE": "0",
			    "AXISY2_MAX": "0",
			    "AXISY2_MIN": "0",
			    "AXISY2_SCALE_BREAK": "False",
			    "SERIES1_AXISY2": "False",
			    "SERIES2_AXISY2": "False",
			    "SERIES3_AXISY2": "False",
			    "SERIES4_AXISY2": "False",
			    "SERIES5_AXISY2": "False"
			},
			"ReportMasterInfo":{
				"layout":"CTGB",
				"type":"AdHoc",
				"dataSource":{
					"dataset":{"type":""},
					"id":0,
					"parameters":[]
				}
			}// ReportMasterInfo end
		}// var newReport end
		return newReport;
	},// generate function end
	getCubeSql:function(param){
		var returnSql=""
		$.ajax({
			type : 'post',
			data : param,
			async : false,
			url : WISE.Constants.context + '/report/cube/generateQueries.do',
			success : function(_dataSet) {
				_dataSet = JSON.parse(_dataSet);

				returnSql = _dataSet;
			}
		});
		return returnSql;
	}
}
