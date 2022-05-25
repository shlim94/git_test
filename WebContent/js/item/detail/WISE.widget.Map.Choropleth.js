WISE.libs.Dashboard.item.ChoroplethMapGenerator = function() {
	var self = this;

	this.type = 'CHOROPLETH_MAP';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
    this.palette;
    //2021.06.21 syjin 팔레트 사용자 지정 추가
    this.paletteStartColor = "";
	this.paletteLastColor = "";	
	this.paletteCustomCheck = false;
	
	this.fieldManager;

	this.dimensions = [];
	this.measures = [];
	this.valueMaps = [];  // Maps-ValueMap node

	this.attributeDimension = {};
	this.tooltipMeasures = [];
	
	//현재 속한 지역
	this.currentLocation = {
			State : "",
			City : ""
	};
	
	this.attributeName = [];
	this.shapeTitleAttributeName;
	// 2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가 dogfoot
	this.toolTipAttributeName;  // this.attributeName을 따른다
	this.tracked;
	this.legend;
	this.isMasterFilterCrossDataSource;
	this.CustomScale;
	this.GradientPalette;
	this.selectedValues =[];
	this.selectedText="";
	this.panelManager;
	this.backColor = "255,255,255";
	this.layerColor = '210,210,210';
	this.Map = [];
	this.fileMeta = [{},{},{}];
	this.shpIndex;
	this.shpFilemeta;
	this.dbfFilemeta;
	this.parseSources = [];
	this.shpF = [];
	this.dbfF = [];
	// 2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가 dogfoot
	var mapTooltipFormat = [];

	this.valueRange = {};
	
	// dogfoot 지도 범위, 지도 파일 변수 배열 처리 20210519 syjin dogfoot
	// this.CustomUrl = "";
	this.CustomUrl = [];
	this.searchOk = false;
// this.CustomUrl = true;

	// jhkim - custom chart palette
	this.isCustomPalette = false;

	this.attrName = [];
	this.fileProperties = [];
	
	this.ShapefileArea = "";
	// dogfoot 지도 범위, 지도 파일 변수 배열 처리 20210519 syjin dogfoot
	// this.ViewArea = [];
	this.ViewArea = {
			area:[]
	};
	this.targetIndex;
	this.searchCheck = false;
	this.LocationName = "";
	this.activePanel = "";
	this.shpReady = false;
	this.dbfReady = false;
	this.LockNavigation = true;

	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	this.colorOptions = {};
	
	//레이블 옵션
	this.labelOption = {
			Visible : true,
			FontSize : 16,
			FormatType : 'Argument',
			Unit : 'Ones',
			//dogfoot 지역 사용자 색상 지정 추가 20210707 syjin
			ColorEnabled : true,
			Color : '#A2FF99',
			PrefixEnabled : false,
			PrefixFormat : '',
			SuffixEnabled : false,
			Suffix : {
				O : '',
				K : "Thousands",
				M : "Millions",
				B : "Billions"
			},
			Precision : 0
	}
	
	this.getLabelFormat = function(_pointInfo, labelFormat){
		if (_pointInfo.layer.type === 'area') {
			var type = self.labelOption.FormatType,
				labelFormat = 'Number',
				labelUnit = self.labelOption.Unit,
				labelPrefixEnabled = self.labelOption.PrefixEnabled,
				labelSuffixEnabled = self.labelOption.SuffixEnabled,
				labelPrecision =self.labelOption.Precision,
				labelSeparator = true,
				labelPrefix = '',
				labelSuffix = self.labelOption.Suffix;
			if (labelPrefixEnabled) {
				labelPrefix = self.labelOption.PrefixFormat;
			}
			
			var text;
			var argumentText = _pointInfo.layer.getElements()[_pointInfo.index].attribute(self.toolTipAttributeName[self.shpIndex]);
			var value = _pointInfo.layer.getElements()[_pointInfo.index].attribute(self.measures[0].nameBySummaryType);
			value = value == undefined ? 0 : value;
			var percentValue = _pointInfo.layer.getElements()[_pointInfo.index].attribute('percentValue');
			percentValue = percentValue == undefined ? 0 : percentValue;


			// range series

			switch(type) {
				case 'None':
					return '';
				case 'Argument':
					return { text : argumentText};
				case 'Value':
					return WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
				case 'Percent':
					return (percentValue*100).toFixed(labelPrecision) + '%';
				case 'ArgumentAndValue':
					text = '<b>' + argumentText + '</b>: '
						+ WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
					break;
				case 'ValueAndPercent':
					return WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, labelPrefix, labelSuffix, labelSuffixEnabled)
						+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
				case 'ArgumentAndPercent':
					return  '<b>' + argumentText + '</b>: ('
						+ (percentValue*100).toFixed(labelPrecision) + '%)';
				case 'ArgumentValueAndPercent':
					text  = '<b>' + argumentText + '</b>: '
					+ WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
					+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
					break;
				default:
					text  = '<b>' + argumentText + '</b>: '
					+ WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
					+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
					break;
				}
				return {html: text};
			}
			return '';
	};
	
	//색상편집 객체
	this.editPaletteOption = {
			paletteBasic : "Material",
			customCheck : false,
			paletteStartColor : "#ffffff",
			paletteLastColor : "#000000",
			valueType : "percent",
			labelCount : 10,	//기본값 6개 (기본 팔레트로 설정할 경우 6개의 색상으로 로테이션 돌림)
			paletteRangeArray : [],
			paletteArray : []
	};
	
	//현재 지도의 색상 팔레트 배열 가져오기
	this.getPaletteArray = function(paletteName, colorGroupingField, colorGroups){	//팔레트 네임, 그룹필드, 그룹 배열, 반환값
		var beforePalette = self.dxItem.option('layers[0].palette');
		var beforeColorGroupingField = self.dxItem.option('layers[0].colorGroupingField');
		var beforeColorGroups = self.dxItem.option('layers[0].colorGroups'); 
		var arrayColor = [];
		self.paletteArrayCheck = true;
		if(colorGroupingField=="%") colorGroupingField = "percent";
		
		//적용된 팔레트로 설정하기
		self.dxItem.option('layers[0].palette', paletteName);
		self.dxItem.option('layers[0].colorGroupingField', colorGroupingField)
		self.dxItem.option('layers[0].colorGroups', colorGroups)
						
		var legend = {
			source : {
				grouping : "color",
				layer : "areaLayer"
			},
			customizeText : function(_arg){
				if(self.paletteArrayCheck){
					arrayColor.push(_arg.color);
				}
				return;
			}
		}
		self.dxItem.option('legends', [legend]);		
		
		self.paletteArrayCheck = false;
		//이전 팔레트로 돌아가기
		self.dxItem.option('layers[0].palette', beforePalette);
		self.dxItem.option('layers[0].colorGroupingField', beforeColorGroupingField);
		self.dxItem.option('layers[0].colorGroups', beforeColorGroups); 
		
		return arrayColor;
	}
	
	this.getPaletteRange = function(valueType, labelCount){
		var range = 0;
		var paletteRange = [];
		
		if(valueType == "percent"){
			range = parseInt(100/(labelCount));	//정수처리					
		}else{			
			var maxVal = 0;
			var summrayType = "";
			
			$.each(this.panelManager.valuePanel, function(_pn, _ovp) {
				summrayType = _ovp.value.nameBySummaryType;
			})
			
			$.each(self.datasetColor, function(s_i, s_v){
				maxVal += s_v[summrayType];
			})
			
			range = parseInt(maxVal/(labelCount));
		}
		
		for(var i=0; i<labelCount+1; i++){
			if(i == 0){
				paletteRange[i] = 0;
			}else{
				paletteRange[i] = range * i;
			}
		}
		
		return paletteRange;
	}
	
	this.paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet',
		'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office'];
	
	// 2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 DOGFOOT
	this.paletteCollection2 = ['밝음', '발광체', '바다', '파스텔', '부드러움', '연한 파스텔', '나무', '포도',
		'단색', '우주', '진보라', '안개숲', '연파랑', '기본값', '사무실 테마'];
	
	this.paletteObject = {
			'Bright':'밝음',
			'Harmony Light':'발광체',
			'Ocean':'바다',
			'Pastel':'파스텔',
			'Soft':'부드러움',
			'Soft Pastel':'연한 파스텔',
			'Vintage':'나무',
			'Violet':'포도',
			'Carmine':'단색',
			'Dark Moon':'우주',
			'Dark Violet':'진보라',
			'Green Mist':'안개숲',
			'Soft Blue':'연파랑',
			'Material':'기본값',
			'Office':'사무실 테마',
			'Custom':'사용자 정의 테마',
		};
	this.paletteObject2 = {
		'밝음':'Bright',
		'발광체':'Harmony Light',
		'바다':'Ocean',
		'파스텔':'Pastel',
		'부드러움':'Soft',
		'연한 파스텔':'Soft Pastel',
		'나무':'Vintage',
		'포도':'Violet',
		'단색':'Carmine',
		'우주':'Dark Moon',
		'진보라':'Dark Violet',
		'안개숲':'Green Mist',
		'연파랑':'Soft Blue',
		'기본값':'Material',
		'사무실 테마':'Office',
		'사용자 정의 테마':'Custom',
	}
	this.paletteConfirm = function(p){
		$("#" + self.itemid + "btn_tabpanel_ok").click(function(){
			var dataSource = $("#" + self.itemid + "_colorPreView").dxDataGrid('instance').option('dataSource');
			
			var paletteBasic = $("#" + self.itemid + "paletteBasic").dxSelectBox('instance').option('value');
			var customCheck = $("#" + self.itemid + "customCheck").dxCheckBox('instance').option('value');
			var startColor = $("#" + self.itemid + "startColor").dxColorBox('instance').option('value');
			var lastColor = $("#" + self.itemid + "lastColor").dxColorBox('instance').option('value');
			var valueType = $("#" + self.itemid + "valueType").dxRadioGroup('instance').option('value');
			if(valueType == "%") valueType = "percent";
			else valueType = self.nameBySummaryType;
			
			var labelCount = $("#" + self.itemid + "labelCount").dxNumberBox('instance').option('value');
			
			var paletteRangeArray = self.getPaletteRange(valueType, labelCount);

			var paletteArray = [];
			
			$.each(dataSource, function(_i, _v){
				paletteRangeArray[_i] = _v['범위'];
				paletteArray[_i] = _v['색상'];
			})
			
			//save edit info 
			//초기화
			self.editPaletteOption['paletteBasic'] = self.paletteObject2[paletteBasic];
			self.editPaletteOption['customCheck'] = customCheck;
			self.editPaletteOption['paletteStartColor'] = startColor;
			self.editPaletteOption['paletteLastColor'] = lastColor;
			self.editPaletteOption['valueType'] = valueType;
			self.editPaletteOption['labelCount'] = labelCount;	
			
			self.editPaletteOption['paletteRangeArray'] = paletteRangeArray;
			self.editPaletteOption['paletteArray'] = paletteArray;
			
			//set vectorMap palette
			self.dxItem.option('layers[0].palette', self.editPaletteOption['paletteArray']);
			self.dxItem.option('layers[0].colorGroupingField', self.editPaletteOption['valueType']);
			self.dxItem.option('layers[0].colorGroups', self.editPaletteOption['paletteRangeArray']);
			//범례 안보이게
			//self.dxItem.option('legends[0].visible', false);
			var legend = [
				{
					horizontalAlignment: "left",
					orientation: "vertical",
					source:
					{
						grouping: "color",
						layer: "areaLayer"
					},
					verticalAlignment: "top",
					font: gDashboard.fontManager.getDxItemLabelFont(),
					customizeText:function(_arg){
						/* dogfoot 지도 범례 표기 형식 변경 shlim 20200617 */
						return _arg.start + ' ~ ';
					}
				}
			];
			self.dxItem.option('legends', legend);
			self.dxItem.option('legends[0].visible', self.Map.MapLegend.Visible);
			
			p.hide();
		})
	}
	
	this.paletteCancel = function(p){
		$("#" + self.itemid + "btn_tabpanel_close").click(function(){
			//범례 안보이게
			//self.dxItem.option('legends[0].visible', false);
			var legend = [
				{
					horizontalAlignment: "left",
					orientation: "vertical",
					source:
					{
						grouping: "color",
						layer: "areaLayer"
					},
					verticalAlignment: "top",
					font: gDashboard.fontManager.getDxItemLabelFont(),
					customizeText:function(_arg){
						/* dogfoot 지도 범례 표기 형식 변경 shlim 20200617 */
						return _arg.start + ' ~ ';
					}
				}
			];
			self.dxItem.option('legends', legend);
			self.dxItem.option('legends[0].visible', self.Map.MapLegend.Visible);
			p.hide();
		})
	}
	
	this.setColorForm = function(id){		
		//var originalPalette = paletteCollection.indexOf(self.Map.Palette) != -1
		//? self.Map.Palette
		//: 'Custom';
		var originalPalette = self.paletteCollection.indexOf(self.editPaletteOption.paletteBasic) != -1
		? self.editPaletteOption.paletteBasic
		: 'Custom';
		
		$("#" + id).dxForm({
			items: [
				{
					dataField : "기본",
					editorType : "dxSelectBox",
					editorOptions : {
						items: self.paletteCollection2,
						value : self.paletteObject[originalPalette],
						disabled : self.editPaletteOption['customCheck'] ? true : false,
						itemTemplate : function(data){
							var html = $('<div />');
                            $('<p />').text(data).css({
                                display: 'inline-block',
                                float: 'left'
                            }).appendTo(html);
                            
                            var itemPalette = DevExpress.viz.getPalette(self.paletteObject2[data]).simpleSet;
                          
                            for (var i = 5; i >= 0; i--) {
                                $('<div />').css({
                                    backgroundColor: itemPalette[i],
                                    height: 30,
                                    width: 30,
                                    display: 'inline-block',
                                    float: 'right'
                                }).appendTo(html);
                            }
                            return html;
						},
						elementAttr : {
							id : self.itemid + "paletteBasic",
							style : "margin-bottom : 15px;"
						}
					}
				},
				{
					dataField : "사용자 지정",
					editorType : "dxCheckBox",
					editorOptions : {
						value : self.editPaletteOption['customCheck'],
						onValueChanged : function(_e){
							if(_e.value){
								$("#" + self.itemid + "paletteBasic").dxSelectBox('instance').option('value', "사용자 지정 테마");
								$("#" + self.itemid + "paletteBasic").dxSelectBox('instance').option('disabled', true);
								
								$("#" + self.itemid + "startColor").dxColorBox('instance').option('disabled', false);
								$("#" + self.itemid + "lastColor").dxColorBox('instance').option('disabled', false);
							}else{
								$("#" + self.itemid + "paletteBasic").dxSelectBox('instance').option('disabled', false);
								
								$("#" + self.itemid + "startColor").dxColorBox('instance').option('disabled', true);
								$("#" + self.itemid + "lastColor").dxColorBox('instance').option('disabled', true);
							}
						},
						elementAttr : {
							id : self.itemid + "customCheck"
						}
					}
				},
				{
					dataField : "시작 색",
					editorType : "dxColorBox",
					editorOptions : {
						value : self.editPaletteOption['paletteStartColor'],
						disabled : self.editPaletteOption['customCheck'] ? false : true,
						elementAttr : {
							id : self.itemid + "startColor"
						}
					}
				},
				{
					dataField : "마지막 색",
					editorType : "dxColorBox",
					editorOptions : {
						value : self.editPaletteOption['paletteLastColor'],
						disabled : self.editPaletteOption['customCheck'] ? false : true,
						elementAttr : {
							id : self.itemid + "lastColor",
							style : "margin-bottom : 15px;"
						}
					}
				},
				{
					dataField : "기준",
					editorType : "dxRadioGroup",
					editorOptions : {
						items : ["%", "값"],
						value : self.editPaletteOption.valueType=="percent"?"%":self.editPaletteOption.valueType==self.nameBySummaryType?"값":self.editPaletteOption.valueType,
						//value : self.editPaletteOption.valueType=="percent"?"%":"값",
						layout: "horizontal",
						elementAttr : {
							id : self.itemid + "valueType",
							style : "margin-bottom : 15px;"
						}
					}
				},
				{
					dataField : "라벨의 수",
					editorType : "dxNumberBox",
					editorOptions : {
						value : self.editPaletteOption.labelCount,
						min : 1,
						max : 50,
						showSpinButtons : true,
						elementAttr : {
							id : self.itemid + "labelCount",
							style : "margin-bottom : 15px;"
						}
					}
				}
			]
		})
	}
	
	this.setColorPreView = function(id, colorDataSource){
		$("#" + id).dxDataGrid({
			dataSource : colorDataSource,
			height : 350,
			showBorders : true,
			columns:[{
				dataField : "범위",
				//dogfoot 색상 편집 미리보기 데이터 그리드 헤더 가운데 정렬 및 정렬 기능 비활성화 syjin 20210628
				alignment : "center",
				allowSorting : false,	
				cellTemplate : function(container, options){
					console.log(options);
					var index = options.rowIndex;
					var rangeValue = options.value;
					var html = "";
					
					html += "<div id='range" + index + "'/>"
					
					container.append(html);		
					
					$("#range" + index).dxNumberBox({
						value : rangeValue,
						onValueChanged : function(_e){
							$("#" + id).dxDataGrid('instance').option('dataSource['+index+'].범위', _e.value);
						}
					})
				}
			},{
				dataField : "색상",
				//dogfoot 색상 편집 미리보기 데이터 그리드 헤더 가운데 정렬 및 정렬 기능 비활성화 syjin 20210628
				alignment : "center",
				allowSorting : false,
				cellTemplate : function(container, options){
					var index = options.rowIndex;
					var colorValue = options.value;
					var html = "";
					
					html += "<div id='color" + index + "'/>"
					
					container.append(html);	
					
					$("#color" + index).dxColorBox({
						value : colorValue,
						onValueChanged : function(_e){
							$("#" + id).dxDataGrid('instance').option('dataSource['+index+'].색상', _e.value);
						}
					})
				}
			}
			]
		})
	}
		
	this.setColorApply = function(id){
		$("#" + id).dxButton({
			text : "적용",
			type : "default",
			onClick : function(){
				var paletteBasic = $("#" + self.itemid + "paletteBasic").dxSelectBox('instance').option('value');
				var customCheck = $("#" + self.itemid + "customCheck").dxCheckBox('instance').option('value');
				var startColor = $("#" + self.itemid + "startColor").dxColorBox('instance').option('value');
				var lastColor = $("#" + self.itemid + "lastColor").dxColorBox('instance').option('value');
				var valueType = $("#" + self.itemid + "valueType").dxRadioGroup('instance').option('value');
				if(valueType == "%") valueType = "percent";
				var labelCount = $("#" + self.itemid + "labelCount").dxNumberBox('instance').option('value');
				var paletteRangeArray = [];
				var paletteArray = [];
				
				var paletteName = "";
				var colorDataSource = [];
				
				if(customCheck){
					self.setCustomPalette(startColor, lastColor);
					paletteName = "myCustomPalette";
				}else{
					paletteName = self.paletteObject2[paletteBasic];
				}
										
				//palette 미리 보기 배열
				paletteRangeArray = self.getPaletteRange(valueType, labelCount);
				paletteArray = self.getPaletteArray(paletteName, valueType, paletteRangeArray);	//팔레트 네임, 그룹필드, 그룹 배열, 반환값
								
				for(var i=0; i<paletteArray.length; i++){
					var colorDataSourceObject = {
							"범위" : paletteRangeArray[i],
							"색상" : paletteArray[i]
					};
					
					colorDataSource.push(colorDataSourceObject);
				}
				
				//초기화
				//self.editPaletteOption['paletteBasic'] = self.paletteObject2[paletteBasic];
				//self.editPaletteOption['customCheck'] = customCheck;
				//self.editPaletteOption['paletteStartColor'] = startColor;
				//self.editPaletteOption['paletteLastColor'] = lastColor;
				//self.editPaletteOption['valueType'] = valueType;
				//self.editPaletteOption['labelCount'] = labelCount;
				//self.editPaletteOption['paletteRangeArray'] = paletteRangeArray;
				//self.editPaletteOption['paletteArray'] = paletteArray;
				
				$("#" + self.itemid + "_colorPreView").dxDataGrid('instance').option('dataSource', colorDataSource);
			}
		})
	}
	// this.fileInfo = [];
	/**
	 * @param _map:
	 *            meta object
	 */
	this.setCurrentLocation = function(_e, shpIndex){
		var attrName;
		if(self.attributeName.Name == undefined){
            attrName = self.attributeName[self.shpIndex];
		}else{
            //attrName = Object.values(self.attributeName.Name[self.shpIndex])[0];
			attrName = self.attributeName.Name[Object.keys(self.attributeName.Name[self.shpIndex])[0]];
		}
		var currentLocation = _e.target.attribute(attrName);
		
		if(shpIndex == 0){
			self.currentLocation['State'] = currentLocation;
		}else if(shpIndex == 1){
			self.currentLocation['City'] = currentLocation;
		}
	}
	// 2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가 dogfoot
	this.getTooltipFormat =  function(_pointInfo, mapTooltipFormat) {
		if (_pointInfo.layer.type === 'area') {
			var type = mapTooltipFormat.type,
				labelFormat = 'Number',
				labelUnit = mapTooltipFormat.format,
				labelPrefixEnabled = mapTooltipFormat.prefixEnabled,
				labelSuffixEnabled = mapTooltipFormat.suffixEnabled,
				labelPrecision = mapTooltipFormat.precision,
				labelSeparator = mapTooltipFormat.prefixEnabled,
				labelPrefix = mapTooltipFormat.prefixFormat,
				labelSuffix = mapTooltipFormat.suffix;
			if (labelPrefixEnabled) {
				labelPrefix = mapTooltipFormat.prefixFormat;
			}

			var text;
			var argumentText = _pointInfo.layer.getElements()[_pointInfo.index].attribute(self.toolTipAttributeName[self.shpIndex]);
			var value = _pointInfo.layer.getElements()[_pointInfo.index].attribute(self.measures[0].nameBySummaryType);
			value = value == undefined ? 0 : value;
			var percentValue = _pointInfo.layer.getElements()[_pointInfo.index].attribute('percentValue');
			percentValue = percentValue == undefined ? 0 : percentValue;


			// range series

			switch(type) {
				case 'None':
					return '';
				case 'Argument':
					return argumentText;
				case 'Value':
					return WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, labelPrefixEnabled?labelPrefix:undefined, labelSuffix, labelSuffixEnabled);
				case 'Percent':
					return (percentValue*100).toFixed(labelPrecision) + '%';
				case 'ArgumentAndValue':
					text = '<b>' + argumentText + '</b>: '
						+ WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, labelPrefixEnabled?labelPrefix:undefined, labelSuffix, labelSuffixEnabled);
					break;
				case 'ValueAndPercent':
					return WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, labelPrefixEnabled?labelPrefix:undefined, labelSuffix, labelSuffixEnabled)
						+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
				case 'ArgumentAndPercent':
					return  '<b>' + argumentText + '</b>: ('
						+ (percentValue*100).toFixed(labelPrecision) + '%)';
				case 'ArgumentValueAndPercent':
					text  = '<b>' + argumentText + '</b>: '
					+ WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, labelPrefixEnabled?labelPrefix:undefined, labelSuffix, labelSuffixEnabled)
					+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
					break;
				default:
					text  = '<b>' + argumentText + '</b>: '
					+ WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
					+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
					break;
				}
				return {html: text};
			}
			return '';
	};

	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	};
	
	this.undisabledCheckCount = function(){
		var cnt = 0;
		
		for(var i=0; i<3; i++){
			if(!self.disabledCheck(i)){
				cnt++;
			}
		}
		
		self.undisabledCheckCnt = cnt;
	}
	
	this.getGeojsonFile = function(shpIndex){
		var data = "";
		var url = "";
		if(self.CustomUrl[shpIndex].Url == undefined)
			url = self.CustomUrl[shpIndex];
		else
			url = self.CustomUrl[shpIndex].Url
		$.ajax({
        	url: url,
        	dataType: "json",
        	async: false,
        	success: function(json){
        		data = json;                            		                         		
        	}
        })	
        return data; 
	}
	
	this.getFirstIndex = function(){
		var index= [
			"mapStateContentPanel" + self.index,
			"mapCityContentPanel" + self.index,
			"mapDongContentPanel" + self.index
		];
        
        var firstIndex = 0;
        if(WISE.Constants.editmode == "viewer"){
        	for(var i=0; i<3; i++){
        		if(self.customShapefile.url[i] != ""){
        			firstIndex = i;
        			break;
        		}
        	}
        }else{
        	for(var i=0; i<3; i++){
    		    if($(self.fieldManager.panelManager[index[i]][0]).find('.fieldName').length > 0){
                    firstIndex = i;
    		    	break;
    		    }
    		}
        }
            
        return firstIndex;
	}
	
	this.getLastIndex = function(){
		var lastIndex = 0;
		
		var index= [
			"mapStateContentPanel" + self.index,
			"mapCityContentPanel" + self.index,
			"mapDongContentPanel" + self.index
		];
		
		if(WISE.Constants.editmode == "viewer"){
			for(var i=2; i>=0; i--){
        		if(self.customShapefile.url[i] != ""){
        			lastIndex = i;
        			break;
        		}
        	}
		}else{
			for(var i=2; i>=0; i--){
			    if($(self.fieldManager.panelManager[index[i]][0]).find('.fieldName').length > 0){
	                lastIndex = i;
			    	break;
			    }
			}
		}
		
		return lastIndex;
	}
	
	this.disabledCheck = function(index){
		var type= [
			"mapStateContentPanel" + self.index,
			"mapCityContentPanel" + self.index,
			"mapDongContentPanel" + self.index
		];

		if(WISE.Constants.editmode == "viewer"){
            if(self.customShapefile.url[index] == ""){
            	return true;
            }
            else{
            	return false;
            }
        }else{
			if($(self.fieldManager.panelManager[type[index]][0]).find('.fieldName').length == 0){
				return true;
			}else{
				return false;
			}
        }
	}
	
	this.getDxItemConfig = function(_map) {
		// dogfoot 지도 범위, 지도 파일 변수 배열 처리 20210519 syjin dogfoot

		// var viewArea = _map['ViewArea'];
		if(_map['ShpIndex'] == undefined)	{
			self.shpIndex = 0;
			self.meta['shpIndex'] = self.shpIndex;
		}
// self.shpIndex = _map['ShpIndex'];
// self.meta['shpIndex'] = self.shpIndex;
// }
		var viewArea;
		// if(self.dimensions.length>1){
			viewArea = _map['ViewArea']['area'][self.shpIndex];
		// }else{
		// viewArea = _map['ViewArea']['area'];
		// }
		self.isMasterFilterCrossDataSource = _map.IsMasterFilterCrossDataSource ? true : false;
		/* legend definition */
		this.mapLegend = {
			source: { layer: "areaLayer", grouping: "color" },
			orientation: ((this.legend.Orientation || '').toLowerCase() || 'vertical'),
			markerType: "circle"
		};

		if(typeof window[self.dashboardid] != 'undefined'){
			var mapOption = typeof window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.DATA_ELEMENT);
		}
		else{
			var mapOption = '';
		}

		var confMeasure = WISE.util.Object.toArray(_map['DataItems']['Measure']);

		this.mapLegend = WISE.libs.Dashboard.item.MapGenerator.setLegendPostion(this.mapLegend, this.legend.Position);
// var mapOption = typeof
// window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ?
// '' :
// WISE.util.Object.toArray(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.DATA_ELEMENT);
		if(mapOption != ''){
			$.each(mapOption,function(_i,_e){
				if(_e.CTRL_NM == _map.ComponentName){
					self.backColor = _e.BACK_COLOR;
					self.layerColor = _e.NULL_DATA_BACK_COLOR;
					return false;
				}
			})
		}

		// 2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가 dogfoot
		var tooltip = {
			enabled: _map['TooltipContentType'] === 'None' ? false : true,
			font:gDashboard.fontManager.getDxItemLabelFont(),
		};
		
		if(_map['TooltipContentType'] != undefined){
			mapTooltipFormat = {
				type: _map['TooltipContentType'],
				format: _map['TooltipMeasureFormat'],
				prefixEnabled: _map['TooltipPrefixEnabled'],
				prefixFormat: _map['TooltipPrefixFormat'],
				suffixEnabled: _map['TooltipSuffixEnabled'],
				suffix: _map['TooltipSuffix'],
				precision: _map['TooltipPrecision'],
			}
		}else{
			var savedTooltip;
			var choroIndex;
			
			$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _v){
				if(_v.type == 'CHOROPLETH_MAP'){
					choroIndex = _i;
					return false;
				}
			})
						
			if(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML)[0].CHOROPLETH_MAP_DATA_ELEMENT.length > 1){
				/* DOGFOOT syjin 뷰어에서 코로플레스 무한로딩 현상 수정  20211126 */
				var index = 0;
								
				$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML)[0].CHOROPLETH_MAP_DATA_ELEMENT, function(_i, _v){
					if(_v.CTRL_NM == self.ComponentName.slice(0, self.ComponentName.indexOf('_'))){
						index = _i;
						return false;
					}
				})
				
				savedTooltip = WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML)[0].CHOROPLETH_MAP_DATA_ELEMENT[index].TOOLTIP_OPTIONS;
			}else{
				savedTooltip = WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML)[0].CHOROPLETH_MAP_DATA_ELEMENT.TOOLTIP_OPTIONS;
			}
						
			//dogfoot 지도 툴팁 조회 후 초기화 현상 수정 syjin 20210830
			mapTooltipFormat = {
				type: savedTooltip['CONTENT_TYPE'],
				format: savedTooltip['MEASURE'],
				prefixEnabled: savedTooltip['PREFIX_ENABLED_YN']=='Y'?true:false,
				prefixFormat: savedTooltip['PREFIX_FORMAT'],
				suffixEnabled: savedTooltip['SUFFIX_ENABLED_YN'],
				suffix: {
					'B' : savedTooltip['SUFFIX_B'],
					'K' : savedTooltip['SUFFIX_K'],
					'M' : savedTooltip['SUFFIX_M'],
					'O' : savedTooltip['SUFFIX_O'],
				},
				precision: savedTooltip['PRECISION'],
			}
		}
		
		
		tooltip.customizeTooltip = function(_pointInfo) {
			if (_pointInfo.layer.type === 'area') {
				var type = mapTooltipFormat.type;

				var Number = WISE.util.Number,
					labelFormat = 'Number',
					labelUnit = 'O',
					labelPrecision = 0,
					labelSeparator = true,
					labelSuffixEnabled = false,
					labelPrefixEnabled = mapTooltipFormat.prefixEnabled,
					labelPrefix = '',
					labelSuffix = {
						O: '',
						K: '천',
						M: '백만',
						B: '십억'
					};
// if (_map.DataItems.Measure.length == 1) {
					//dogfoot 지도 툴팁 조회 후 초기화 현상 수정 syjin 20210830
					labelFormat = typeof mapTooltipFormat.type == 'undefined' ? labelFormat : mapTooltipFormat.type;
					labelUnit = typeof mapTooltipFormat.format == 'undefined'? labelUnit : mapTooltipFormat.format;
					labelPrecision = typeof mapTooltipFormat.precision == 'undefined' ? labelPrecision : mapTooltipFormat.precision;
					labelSeparator = typeof mapTooltipFormat.prefixEnabled == 'undefined' ? labelSeparator : mapTooltipFormat.prefixEnabled;
					labelSuffixEnabled = typeof mapTooltipFormat.suffixEnabled == 'undefined' ? labelSuffixEnabled : mapTooltipFormat.suffixEnabled;
					labelSuffix = typeof mapTooltipFormat.suffix == 'undefined' ? labelSuffix : mapTooltipFormat.suffix;
// }
				if (labelPrefixEnabled) {
					labelPrefix = mapTooltipFormat.prefixFormat;
				}
				var text;
				if(self.toolTipAttributeName['Name'] != undefined){
					var arr = [];
					if(Array.isArray(self.toolTipAttributeName['Name'])){
                        $.each(self.toolTipAttributeName['Name'], function(_i, _v){
							$.each(_v, function(_i2, _v2){
								arr.push(_v2);
							})
						})
					}else{
						$.each(self.toolTipAttributeName['Name'], function(_i, _v){							
							arr.push(_v);							
						})
					}

                    self.toolTipAttributeName = arr;
				}
				
				var argumentText = _pointInfo.layer.getElements()[_pointInfo.index].attribute(self.toolTipAttributeName[self.shpIndex]) + labelPrefix;
				
				// dogfoot 코로플레스 측정값 2개이상일 때 tracking_data 옵션 추가 syjin 20210414
				var nameBySummaryType = "";
				if(!self.currentMeasureName){
                    self.currentMeasureName = self.measures[0].caption;
				}
                $.each(self.measures, function(_i, _v){
                	if(_v['caption'] == self.currentMeasureName){
                        nameBySummaryType = _v.nameBySummaryType;
                	}
                })
				var value = _pointInfo.layer.getElements()[_pointInfo.index].attribute(nameBySummaryType);
				value = value == undefined ? 0 : value;
				var percentValue = _pointInfo.layer.getElements()[_pointInfo.index].attribute('percentValue');
				percentValue = percentValue == undefined ? 0 : percentValue;


				// range series

				switch(type) {
					case 'None':
						return '';
					case 'Argument':
						//return argumentText;
						return { text : argumentText};
					case 'Value':
		// return WISE.util.Number.unit(value, format, unit, precision,
		// separator, prefix, suffix, suffixEnabled);
						return Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
					case 'Percent':
		// return (percentValue*100).toFixed(precision) + '%';
						return (percentValue*100).toFixed(labelPrecision) + '%';
					case 'ArgumentAndValue':
						text = '<b>' + argumentText + '</b>: '
							+ Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
						break;
					case 'ValueAndPercent':
						return WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, labelPrefix, labelSuffix, labelSuffixEnabled)
							+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
					case 'ArgumentAndPercent':
						return  '<b>' + argumentText + '</b>: ('
							+ (percentValue*100).toFixed(labelPrecision) + '%)';
					case 'ArgumentValueAndPercent':
						text  = '<b>' + argumentText + '</b>: '
						+ Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
						+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
						break;
		// return '<b>' + argumentText + '</b>: '
		// + WISE.util.Number.unit(value, format, unit, precision, separator,
		// prefix, suffix, suffixEnabled)
		// + ' (' + (percentValue*100).toFixed(precision) + '%)';
					default:
		// return '<b>' + argumentText + '</b>: '
		// + WISE.util.Number.unit(value, format, unit, precision, separator,
		// prefix, suffix, suffixEnabled)
		// + ' (' + (percentValue*100).toFixed(precision) + '%)';
						text  = '<b>' + argumentText + '</b>: '
						+ Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
						+ ' (' + (percentValue*100).toFixed(labelPrecision) + '%)';
						break;
					}
					return {html: text};
			}
			return '';
		};
		
		//지도 팔레트 초기화
		var paletteColor = "";
		var paletteRange = [];
		
		if(self.editPaletteOption.paletteArray.length == 0){
			paletteColor = self.editPaletteOption.paletteBasic;
		}else{
			paletteColor = self.editPaletteOption.paletteArray;
		}
		
		if(self.editPaletteOption.paletteRangeArray.length == 0){
			//dogfoot 코로플레스 필터 적용 후 조회시 색상 미표시 오류 수정syjin 20210820
			paletteRange = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
		}else{
			paletteRange = self.editPaletteOption.paletteRangeArray;
		}
		
		/* dogfoot 코로플레스 지도 MapLabel 개발 이전 보고서 열기 오류 수정 shlim 20201201 */
		if(this.meta.MapLabel == undefined){
			this.meta.MapLabel=[];
			this.meta.MapLabel['Visible'] = false;
		}
		
		// variable for dbClick
		var clicks = 0;
		var firstIndex = self.getFirstIndex();
		
		var labelDataFiled = "";
		if(Array.isArray(this.toolTipAttributeName)){
			labelDataFiled = this.toolTipAttributeName[firstIndex];
		}else{
			labelDataFiled = this.toolTipAttributeName
		}
		
		if(WISE.Constants.editmode == "viewer"){
			if(this.toolTipAttributeName.Name == undefined){
				labelDataFiled =  this.toolTipAttributeName[firstIndex];
			}else{
				if(Array.isArray(this.toolTipAttributeName.Name)){
                    //labelDataFiled = Object.values(this.toolTipAttributeName.Name[firstIndex])[0];
					labelDataFiled = this.toolTipAttributeName.Name[Object.keys(this.toolTipAttributeName.Name[firstIndex])[0]];
				}else{
					//labelDataFiled = Object.values(this.toolTipAttributeName.Name)[0];
					labelDataFiled = this.toolTipAttributeName.Name[Object.keys(this.toolTipAttributeName.Name)[0]];					
				}
			}
		}
		
		if(self.labelOption.Visible)
			labelDataFiled = "labelHtml";
		else
			labelDataFiled = "";
		
		var selectionMode = "";
		if(self.IO != undefined){
			if(self.IO.MasterFilterMode == "Multiple"){
				selectionMode = "multiple";
			}else{
				selectionMode = "single";
			}
			
		}
		
		var dxConfigs = {
			background: {
				borderColor: 'white',
				color:"rgb("+self.backColor+")"
			},
// colorGroups: [],
// colorGroupingField: '',
			layers: [{
				type: 'area',
				name: 'areaLayer',
				hoverEnabled: true,
				color:"rgb("+self.layerColor+")",
				// palette: this.CUSTOMIZED.get('palette'),
				palette: paletteColor,
				colorGroupingField: self.editPaletteOption.valueType,
				colorGroups: paletteRange,
// data: WISE.Constants.context+'/resources/mapdata/state.geojson',
				data:'',
				label: {
					// 2020.11.27 mksong 코로플레스지도 레이블 표기 dogfoot
					enabled: this.meta.MapLabel.Visible ? true : false,
					dataField: labelDataFiled,
					font : {
						size : self.labelOption.FontSize
					}
					// dataField: 'name_value'
				},
				// dogfoot 코로플레스 다중 마스터 필터 적용 시 선택 영역 다중으로 선택되도록 수정 syjin
				// 20210411
				selectionMode: selectionMode
			}],
			onDrawn: function(e){
				if(!self.searchCheck && !gDashboard.isNewReport &&!self.drillCheck){
					$.each(e.component.getLayers()[0].getElements(), function(_i, _v){
						if(_v.index == self.targetIndex){
							_v.applySettings({selectedColor : self.labelOption.Color});
							_v.selected(true);
						}
					})
				}
			},
			center: [Number(viewArea['CenterPointLongitude']), Number(viewArea['CenterPointLatitude'])],
			bounds: [Number(viewArea['LeftLongitude']), Number(viewArea['TopLatitude']), Number(viewArea['RightLongitude']), Number(viewArea['BottomLatitude'])],
			controlBar: {
			    enabled: false
		    },
		    wheelEnabled: _map['LockNavigation'],
		    panningEnabled: _map['LockNavigation'],
		    loadingIndicator: {
		    	show: true,
		    	backgroundColor: '#ededed',
		    	text: gMessage.get('WISE.message.page.common.loding')
			},
			// 2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가 dogfoot
			tooltip: tooltip,
			/*
			 * onDrawn:function(_e){
			 * $.each($(".dxm-layer-labels").find("text"),function(_i,_v){
			 * $(_v).attr("visibility","none"); }) },
			 * onZoomFactorChanged:function(_e){
			 * $.each($(".dxm-layer-labels").find("text"),function(_i,_v){
			 * $(_v).attr("visibility","none"); }) },
			 */
			onClick: function(_e) {
				var item = $('#'+self.activePanel).dxVectorMap('instance');
				if(self.IO != undefined){
					if(self.IO.MasterFilterMode == 'off'){
						if(item){
							item.clearSelection();
						}
					}
				}
				clicks++;
				
			    if (clicks == 1) {
			    	timer = setTimeout(function () {
			        	/* dogfoot 코로플레스 맵 마스터필터 추가 shlim 20201126 */
			    		if(self.IO != undefined){
							if (self.IO.MasterFilterMode !== 'Off') {
								if(_e.target){
									var imgSrc, overImgSrc, clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
						        	imgSrc = 'cont_box_icon_filter';
						        	overImgSrc = 'cont_box_icon_filter_';
	
						           	$(clearTrackingImg)
						           		.attr('src', WISE.Constants.context + '/images/' + imgSrc + '.png')
						           		.on('mouseover', function() {
						           			$(this).attr('src', WISE.Constants.context + '/images/' + overImgSrc + '.png');
						           		})
						           		.on('mouseout', function() {
						           			$(this).attr('src', WISE.Constants.context + '/images/' + imgSrc + '.png');
						           		});
						           
						           	var attributeName = [];
									if(self.attributeName.Name == undefined){
										attributeName = self.attributeName;
									}else{
										var array = self.attributeName['Name'];
	
										$.each(array, function(_i, _v){
											$.each(_v, function(_i2, _v2){
												attributeName.push(_v2);
											})
										})
									} 
									
						           switch(self.IO.MasterFilterMode){
						           	    case 'Single':
			                                var trackedDataName = _e.target.attribute(attributeName[self.shpIndex]);
			                                var selected = {};
			                                var selected = {};
											if(self.selectedText.indexOf(trackedDataName) == -1){
												//dogfoot 마스터필터 같은 이름의 지역이 선택되어 같은 값으로 나오는 문제가 있음 상위 지역까지 포함하여 처리 20210622
												self.selectedValues = [];
												if(self.shpIndex == 1){
													if(self.attributeDimension[self.shpIndex-1] != undefined){
														selected[self.attributeDimension[self.shpIndex-1].name] = self.currentLocation['State'];
                                                    	self.selectedValues.push(selected);
													}
												}else if(self.shpIndex == 2){
													if(self.attributeDimension[self.shpIndex-1] != undefined){
														selected[self.attributeDimension[self.shpIndex-1].name] = self.currentLocation['City'];
														self.selectedValues.push(selected);
													}
												}									
												selected = {};
												selected[self.attributeDimension[self.shpIndex].name] = trackedDataName;
												self.selectedValues.push(selected);
												_e.target.selected(true);
											}
											else{
												$.each(self.selectedValues,function(_i,_f){
													if(_f[self.attributeDimension[self.shpIndex].name] == trackedDataName){
														self.selectedValues.splice(_i,1);
														return false;
													}
												});
												_e.target.selected(false);
											}
											self.selectedText = "";
											$.each(self.selectedValues,function(_i,_e){
												self.selectedText += _e[self.attributeDimension[self.shpIndex].name]+' ';
											})
											if(self.selectedText==""){
												var clearImg = $("#" + self.trackingClearId).find('img')[0];
												$(clearImg).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
											}
											// $('#' + self.itemid +
											// '_tracking_data_container').empty();
											// $('#' + self.itemid +
											// '_tracking_data_container').html('[ '
											// + self.selectedText + ']');
						           	    break;
						           	    case 'Multiple':
						           	        var trackedDataName = _e.target.attribute(attributeName[self.shpIndex]);
						           	        
											var selected = {};
																	
											if(self.selectedText.indexOf(trackedDataName) == -1){
												if(self.shpIndex == 1){
                                                    selected[self.attributeDimension[self.shpIndex-1].name] = self.currentLocation['State'];
                                                    self.selectedValues.push(selected);
												}else if(self.shpIndex == 2){
													selected[self.attributeDimension[self.shpIndex-1].name] = self.currentLocation['City'];
													self.selectedValues.push(selected);
												}	
												selected = {};
												selected[self.attributeDimension[self.shpIndex].name] = trackedDataName; 
												self.selectedValues.push(selected);
												_e.target.selected(true);
											}
											else{
												$.each(self.selectedValues,function(_i,_f){
													if(_f[self.attributeDimension[self.shpIndex].name] == trackedDataName){
														self.selectedValues.splice(_i,1);
														return false;
													}
												});
												_e.target.selected(false);
											}
											
					// selected[self.attributeDimension.name] = trackedDataName;
					// self.selectedValues.push(selected);
	
											self.selectedText = "";
											$.each(self.selectedValues,function(_i,_e){
												self.selectedText += _e[self.attributeDimension[self.shpIndex].name]+' ';
											})
											if(self.selectedText==""){
												var clearImg = $("#" + self.trackingClearId).find('img')[0];
												$(clearImg).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
											}
											// $('#' + self.itemid +
											// '_tracking_data_container').empty();
											// $('#' + self.itemid +
											// '_tracking_data_container').html('[ '
											// + self.selectedText + ']');
						           	    break;
						           }
	
	
	
	
					           		window[self.dashboardid].filterData(self.itemid, self.selectedValues,self.isMasterFilterCrossDataSource);
					           	}
							}
							else{
								if(_e.target != undefined && _e.target.selected != undefined){
									if(_e.target.index == self.targetIndex){
	                                  _e.target.selected(false);
	                                   self.targetIndex = undefined;
									}else{
										//dogfoot 지역 사용자 색상 지정 표시여부 추가 20210709 syjin
										if(!self.labelOption.ColorEnabled)
											_e.target.applySettings({selectedColor : ""});
										_e.target.selected(true);
										self.targetIndex = _e.target.index;	
									}			
								}
							}
			    		}
			        	clicks = 0;
			        }, 300);
			    }else{
			    	if(_e.target != undefined){
			    		//현재 지역 저장
			    		self.setCurrentLocation(_e, self.shpIndex);
			    		
			    		self.clearTrackingConditions();
			    		
			    		//드릴 업 시 마스터 필터 데이터 초기화
			    		//gProgressbar.show();
			    		//gDashboard.filterData(self.itemid, []);
			    		//gProgressbar.hide();
			    		
	                    var lastIndex = self.getLastIndex();
	                   	                    
				    	if(self.shpIndex < lastIndex){
				    		self.drillCheck = true;
					    	self.shpIndex += 1;
					    	self.targetIndex = undefined;
					    	var index = self.shpIndex;
					    	self.meta.shpIndex = self.shpIndex;
					    	
					    	var arrayDimension = [];
					    	var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
	                        var dimensions = [];
	                        var cnt = 0;
	                        
	                        for(var i=0; i<3; i++){                        	
								if(!self.disabledCheck(i)){
	                                dimensions.push(self.dimensions[cnt]);
	                                cnt++;
								}else{
									dimensions.push({});
								}
	                        }
				            arrayDimension.push(dimensions[self.shpIndex]);
				            // where절 삭제
				            gDashboard.itemGenerateManager.sqlConfigWhere = [];
				            
				            //값 기준 변경(지역별)
				            var currentLocation = "";
				            if(self.shpIndex-1 == 0){
                                currentLocation = "State";
				            }else if(self.shpIndex-1 == 1){
                                currentLocation = "City";
				            }
				            var whereObject = {
				            	data : [self.currentLocation[currentLocation]],
				            	key : dimensions[self.shpIndex-1].caption
				            }
				            				            
				            var datasetConfig = self.SQLike.fromJson(arrayDimension, self.measures, []);
				            datasetConfig.Where.push(whereObject);
				            var dataset = SQLikeUtil.doSqlLike(self.dataSourceId, datasetConfig, self);
	
				            self.filteredData = dataset;
				            self.csvData = self.filteredData;
				            
				            self.generateMapChart(dataset, self.measures, true);
				            self.shpIndex = index;
				            	    		
					    	if(_e.target != undefined){
					    		
					    	}
					    	var dimensionLength = self.dimensions.length;
					    				    	
					    	//
					    	// if(self.shpIndex <= dimensionLength-1){
					    		var beforeData;
						    	if(gDashboard.isNewReport){
						    		if(self.fileMeta[self.shpIndex-1].data != undefined)
						    			beforeData = self.fileMeta[self.shpIndex-1].data;
						    		else
						    			beforeData = self.getGeojsonFile(self.shpIndex-1);
						    	}else{
						    		// beforeData =
									// self.featuresData[self.shpIndex-1];
						    		beforeData = self.getGeojsonFile(self.shpIndex-1);
						    	}
						    	
						    	var title;
						    	switch(self.shpIndex-1){
						    		case 0:
						    			title = "시도";
						    			break;
						    		case 1:
						    			title = "시군구";
						    			break;
						    		case 2: 
						    			title = "읍면동";
						    			break;
						    	}
						    	// var title =
								// self.fileMeta[self.shpIndex-1].title;
						    	var data;
						    	if(gDashboard.isNewReport){
						    		data = _.cloneDeep(self.fileMeta[self.shpIndex].data);
						    	}else{
						    		// data =
									// _.cloneDeep(self.featuresData[self.shpIndex]);
						    		data = self.getGeojsonFile(self.shpIndex);
						    	}
								// var data =
								// _.cloneDeep(self.fileMeta[self.shpIndex].data);
								//var selectLocationName = _e.target.attribute().name;	
								var attributeName = "";
								
								if(self.attributeName.Name == undefined){
									attributeName = self.attributeName[self.shpIndex-1];
								}else{
									//attributeName = Object.values(self.attributeName.Name[self.shpIndex-1])[0];
									attributeName = self.attributeName.Name[Object.keys(self.attributeName.Name[self.shpIndex-1])[0]];
								}
								
								//dogfoot 코로플레스 code 속성으로 접근하도록 고정 syjin 20210826
						    	//var selectLocationName = _e.target.attribute()[attributeName];
								var selectLocationName = _e.target.attribute()['code'];
								var locationCode = 0;
								var dataSource = {};
								
								//dogfoot 코로플레스 code 속성으로 접근하도록 고정 syjin 20210826
								//locationCode = self.getLocationCode(beforeData.features, selectLocationName, attributeName);
								locationCode = self.getLocationCode(beforeData.features, selectLocationName, 'code');
								self.locationCode = locationCode.substring(0,2);
								
								dataSource = self.initDataSource(data, title, locationCode, true);
								self.initBounds(dataSource);
								
								self.dxItem.option('layers[0].dataSource', dataSource);
								self.dxItem.option('bounds', dataSource.bbox);
								//self.dxItem.option('layers[0].label.dataField', self.toolTipAttributeName[self.shpIndex]);
								// dogfoot 2021.06.07 코로플레스 드릴다운 적용 시 색상편집 적용
								// syjin
								if(Object.keys(self.colorOptions).length > 0){
									self.setColorOptions();
								}
								
								var viewArea = {
			    					'BottomLatitude': dataSource.bbox[1],
			    					'TopLatitude':  dataSource.bbox[3],
			    					'LeftLongitude':  dataSource.bbox[0],
			    					'RightLongitude':  dataSource.bbox[2],
			    					'CenterPointLatitude': (dataSource.bbox[1] + data.bbox[3])/2,
									'CenterPointLongitude': (dataSource.bbox[0] + data.bbox[2])/2,
			    				};
										
								self.ViewArea['area'][self.shpIndex] = viewArea;
								
								//syjin 20210806 드릴 업 시 마스터 필터 적용되도록 개선 dogfoot
					    		gProgressbar.show();
					    		
								var selected = {};
								self.selectedValues = [];
								if(self.shpIndex == 1){
									if(self.attributeDimension[self.shpIndex-1] != undefined){
										selected[self.attributeDimension[self.shpIndex-1].name] = self.currentLocation['State'];
										self.selectedValues.push(selected);
									}
								}else if(self.shpIndex == 2){
									if(self.attributeDimension[self.shpIndex-1] != undefined){
										selected[self.attributeDimension[self.shpIndex-1].name] = self.currentLocation['City'];
										self.selectedValues.push(selected);
									}
								}	
								
								//dogfoot 코로플레스 드릴 다운시 마스터필터(단일 일때만) 적용 syjin 20210823
								if(self.IO != undefined){
									if(self.IO.MasterFilterMode=="Single"){
										gDashboard.filterData(self.itemid, self.selectedValues,self.isMasterFilterCrossDataSource);
									}
								}
								gProgressbar.hide();
								
								clicks=0;
					    	// }
				    	}
			    	}
			    }
			}
		};
		return dxConfigs;
	};
	
	this.removeFileData = function(data){
		var index = 0;
		$.each(data.features, function(_i, _v){
			if(_v.properties == undefined){
				index = _i;
				return false;
			}
		})
		if(index != 0){
			data.features.splice(index, data.features.length-index+1);
		}
		return index;
	}
	
	this.getLocationCode = function(dataFeatures, locationName, attributeName){
		var locationCode = 0;
		self.LocationName = locationName;
		
		$.each(dataFeatures, function(_i, _v){
			if(_v.properties!=undefined){
				if(_v.properties[attributeName] == locationName){
					locationCode = _v.properties.code;
				}
			}
		})
		
		return locationCode;
	}
	
	// init dataSource
	this.initDataSource = function(data, title, locationCode, drillUp){
		var dataFeatures = data.features;
		var selectFeatures = [];
		var dataSource = data;
		var subIndex = 0;
		
		switch(title){
		case "시도" :
			subIndex = 2;
			break;
		case "시군구" :
			if(drillUp) subIndex = 5;
			else subIndex = 2;
			break;
		case "읍면동" :
			if(!drillUp) subIndex = 5; 
			break;
		}
		//dogfoot 지도 드릴다운 예외처리 syjin 20210830
		if(locationCode.length > subIndex)
			locationCode = locationCode.substring(0, subIndex);
		
		$.each(dataFeatures, function(_i, _v){
			if(_v.properties != undefined){
				if(_v.properties.code.substring(0,subIndex)== locationCode){
					selectFeatures.push(_v)
				}
			}
		})
		
		dataSource.features = [];
		// dataFeatures = selectFeatures;
		dataSource.features = selectFeatures;
		
		return dataSource;
	}
	
	// 20210413 AJKIM 코로플레스 마스터 필터 무시 추가 dogfoot
	this.ignoreMasterFilter = function(datasetConfig, item){
		// 20210413 AJKIM 코로플레스 마스터 필터 무시 추가 dogfoot
		if(typeof item.dataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
			if(item.dataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
				datasetConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
			}else{
				datasetConfig.Where = [];
			}
		}else{
			datasetConfig.Where = [];
		}
	}
	
	// init mapBounds
	this.initBounds = function(data){
		var lat = [];
		var longi = [];

		$.each(data.features, function(_i, _v){
			var coordinates = _v['geometry']['coordinates'];

			$.each(coordinates, function(c_i, c_v){

				var coord = c_v;

				$.each(coord, function(cr_i, cr_v){
					// 위도
					longi.push(cr_v[0]);
					// 경도
					lat.push(cr_v[1]);
				})
			})
		})

		var maxLongi = Math.max.apply(null, longi);
		var minLongi = Math.min.apply(null, longi);

		var maxLat = Math.max.apply(null, lat);
		var minLat = Math.min.apply(null, lat);

		var bounds = [minLongi, maxLat, maxLongi, minLat];

		data.bbox = bounds;
	}
	
	// dogfoot 2021.06.07 코로플레스 드릴다운 적용 시 색상편집 적용 syjin
	this.setColorOptions = function(){
		self.dxItem.option('layers[0].colorGroups', self.editPaletteOption.paletteRangeArray)
		self.dxItem.option('layers[0].colorGroupingField', self.editPaletteOption.valueType)
		self.dxItem.option('layers[0].palette', self.editPaletteOption.paletteArray);
	}
	
	this.setChoroplethMap = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		
		//fileMeta 추가
		this.Map['FileMeta'] = this.fileMeta;
		//레이블 추가
		this.Map['LabelOption'] = this.labelOption;
		
		//색상편집 추가
		this.Map['EditPaletteOption'] = this.editPaletteOption;
		
		//현재 지역 추가
		this.Map['CurrentLocation'] = this.currentLocation;		
		this.Map['palette'] = this.palette;
		//2021.06.21 syjin 팔레트 사용자 지정 추가
		this.Map['PaletteStartColor'] = this.paletteStartColor;
		this.Map['PaletteLastColor'] = this.paletteLastColor;	
		this.Map['PaletteCustomCheck'] = this.paletteCustomCheck;
		this.Map['ComponentName'] = this.ComponentName;
		this.Map['DataItems'] = this.fieldManager.DataItems;
		this.Map['DataSource'] = this.dataSourceId;
		this.Map['Name'] = this.Name;
		this.Map['AttributeDimension'] = this.fieldManager.attributeDimension;
		/* dogfoot 코로플레스 맵 안그려지는 오류 수정 shlim 20200612 */
		// this.Map['Maps'] = typeof this.Map['Maps'] != 'undefined' &&
		// this.Map['Maps'] != "" ? this.Map['Maps'] : this.fieldManager.Values;
		/* dogfoot 코로플레스 측정값 바뀌면 조회 안되는 오류 수정 syjin 20210615 */
		this.Map['Maps'] = this.fieldManager.Values;
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.Map['IsMasterFilterCrossDataSource'] = false;
		this.Map['CustomShapefile'] = this.CustomUrl;
		//this.Map['CustomShapefile'] = this.meta['CustomShapefile'];
		/* 디버그용 */
// this.Map['CustomShapefile'] = {'Url':
// "http://localhost:11080/ds/UploadFiles/geojson/KOR_adm1_edit_kor.geojson"};
		this.Map['AttributeName'] = self.attrName;
		this.Map['ShapefileArea'] = self.ShapefileArea;
		this.Map['ViewArea'] = self.ViewArea;
		this.Map['LocationName'] = self.LocationName;
// this.Map['ShowCaption'] = true;
		this.Map['LockNavigation'] = self.LockNavigation;
		/* view.do 와 맞추기 위한 더미 Element 또는 모르는것 */
// this.Map['MapLegend'] = "";
		/* dogfoot 지도 팔레트 첫 생성시 범례 못그리는 오류 수정 shlim 20200617 */
		this.Map['MapLegend'] = this.Map['MapLegend'] != undefined && this.Map['MapLegend'] !="" ? this.Map['MapLegend'] : {'Visible': false};
		// 2020.11.27 mksong 코로플레스지도 레이블 표기 dogfoot
		this.Map['MapLabel'] = this.Map['MapLabel'] != undefined && this.Map['MapLabel'] !="" ? this.Map['MapLabel'] : {'Visible': true};
		this.Map['WeightedLegend'] = "";
		// shpIndex 추가
		this.Map['ShpIndex'] = this.shpIndex;
		this.Map['TargetIndex'] = this.targetIndex;
		/* dogfoot 코로플레스 맵 마스터필터 추가 shlim 20201126 */
		if (this.Map.InteractivityOptions) {
			if (!(this.Map.InteractivityOptions.MasterFilterMode)) {
				this.Map.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Map.InteractivityOptions.IsDrillDownEnabled)) {
				this.Map.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.Map.InteractivityOptions.IgnoreMasterFilters)) {
				this.Map.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Map.InteractivityOptions = {
				MasterFilterMode: 'Off',
// TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
// this.Map['InteractivityOptions'] = {
// MasterFilterMode: 'none',
// // TargetDimensions: 'Argument',
// IsDrillDownEnabled: false,
// IgnoreMasterFilters: false
// };		
		// 2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가 dogfoot
		//this.Map.TooltipContentType = 'ArgumentValueAndPercent';
		//dogfoot 지도 툴팁 조회 후 초기화 현상 수정 syjin 20210830
		if(mapTooltipFormat.length == 0){
			this.Map.TooltipContentType = mapTooltipFormat.type==undefined?"ArgumentValueAndPercent":mapTooltipFormat.type;
			this.Map.TooltipMeasureFormat = 'O';
			this.Map.TooltipPrefixEnabled = true;
			this.Map.TooltipPrefixFormat = '';
			this.Map.TooltipSuffixEnabled = false;
			this.Map.TooltipSuffix = {
				O: '',
				K: 'K',
				M: 'M',
				B: 'B'
			};
			this.Map.TooltipPrecision = 0;
		}else{
			this.Map.TooltipContentType = mapTooltipFormat.type;
			this.Map.TooltipMeasureFormat = mapTooltipFormat.format;
			this.Map.TooltipPrefixEnabled = mapTooltipFormat.prefixEnabled;
			this.Map.TooltipPrefixFormat = mapTooltipFormat.prefixFormat;
			this.Map.TooltipSuffixEnabled = mapTooltipFormat.suffixEnabled;
			this.Map.TooltipSuffix = {
				O: mapTooltipFormat.suffix.O,
				K: mapTooltipFormat.suffix.K,
				M: mapTooltipFormat.suffix.M,
				B: mapTooltipFormat.suffix.B
			};
			this.Map.TooltipPrecision = mapTooltipFormat.precision;
		}
		
				
		if (!(this.Map.Palette)) {
			this.Map.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		this.meta = this.Map;

	}

	this.setChoroplethMapForOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setChoroplethMap();
		}
		else{
			this.Map = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		
		var attributeName = [];
		if(self.attributeName.Name == undefined){
			attributeName = self.attributeName;
		}else{
			var array = [];
			
			if(!Array.isArray(self.attributeName['Name'])) {
				array = WISE.util.Object.toArray(self.attributeName['Name']);
			}else{
				array = self.attributeName['Name'];
			}
						
			for(var i=0; i<3; i++){
				if(self.attributeName['Name'][i] == ""){
					self.attributeName['Name'][i] = {};
				}
			}
			
			$.each(array, function(_i, _v){
				$.each(_v, function(_i2, _v2){
					attributeName[_i] = _v2;
				})
			})
		}
		
		//fileMeta 추가
		this.Map['FileMeta'] = this.fileMeta;
		
		//레이블 추가
		this.Map['LabelOption'] = this.labelOption;
		
		//색상편집 객체
		this.Map['EditPaletteOption'] = this.editPaletteOption;
		
		this.Map['CurrentLocation'] = this.currentLocation;
		this.Map['AttributeName'] = attributeName;
		this.Map['ComponentName'] = this.ComponentName;
		this.Map['DataItems'] = this.fieldManager.DataItems;
		this.Map['DataSource'] = this.dataSourceId;
		this.Map['Name'] = this.Name;
		this.Map['AttributeDimension'] = this.fieldManager.attributeDimension;
		/* dogfoot 코로플레스 맵 안그려지는 오류 수정 shlim 20200612 */
		this.Map['Maps'] = this.fieldManager.Values;
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.Map['CustomShapefile'] = this.meta['CustomShapefile'];
		this.Map['LocationName'] = this.meta['LocationName'];
		if(this.meta['LockNavigation'] != undefined){
			this.Map['LockNavigation'] = self.LockNavigation = !this.meta['LockNavigation'];
			this.meta['LockNavigation'] = undefined;
		}
		if(this.meta['MapLegend'] != undefined){
			this.Map['MapLegend'] = this.meta['MapLegend'] == "" ? {'Visible': false} : this.meta['MapLegend'];
		}
		// 2020.11.27 mksong 코로플레스지도 레이블 표기 dogfoot
		if(this.meta['MapLabel'] != undefined){
			this.Map['MapLabel'] = this.meta['MapLabel'] == "" ? {'Visible': true} : this.meta['MapLabel'];
		}else{
			this.Map['MapLabel'] = this.meta['MapLabel'] = {'Visible': true};
		}
					
// /*view.do 와 맞추기 위한 더미 Element 또는 모르는것*/
		//if (!(this.Map.PaletteCustomCheck)) {
		//	this.Map['PaletteStartColor'] = this.paletteStartColor;
		//	this.Map['PaletteLastColor'] = this.paletteLastColor;	
		//	this.Map['PaletteCustomCheck'] = this.paletteCustomCheck;
		//}
		if (!(this.Map.Palette)) {
			this.Map.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		/* dogfoot 코로플레스 맵 마스터필터 추가 shlim 20201126 */
		if (this.Map.InteractivityOptions) {
			if (!(this.Map.InteractivityOptions.MasterFilterMode)) {
				this.Map.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Map.InteractivityOptions.IsDrillDownEnabled)) {
				this.Map.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.Map.InteractivityOptions.IgnoreMasterFilters)) {
				this.Map.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Map.InteractivityOptions = {
				MasterFilterMode: 'Off',
// TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}

		// 2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가 dogfoot
		var page = window.location.pathname.split('/');
		var dashboardXml = gDashboard.structure.MapOption.DASHBOARD_XML || {};
		var mapDataElements = WISE.util.Object.toArray(dashboardXml);
		/* DOGFOOT hsshim 2020-02-06 끝 */
		var mapDataElement = {
			TOOLTIP_OPTIONS: {
				CONTENT_TYPE: 'ArgumentValueAndPercent',
				MEASURE: 'O',
				PREFIX_ENABLED_YN: 'N',
				PREFIX_FORMAT: '',
				SUFFIX_ENABLED_YN: 'N',
				SUFFIX_O: '',
				SUFFIX_K: 'K',
				SUFFIX_M: 'M',
				SUFFIX_B: 'B',
				PRECISION: 0
			}
		};
		$.each(mapDataElements,function(_i,_e) {
			var CtrlNM;
			var cnt = 0;
			// 2020.10.07 mksong CHOROPLETH_MAP_DATA_ELEMENT undefined 오류 수정
			// dogfoot
			if(_e.CHOROPLETH_MAP_DATA_ELEMENT != undefined){
				if (page[page.length - 1] === 'viewer.do'){
					if(_e.CHOROPLETH_MAP_DATA_ELEMENT.length == undefined){
						CtrlNM = _e.CHOROPLETH_MAP_DATA_ELEMENT.CTRL_NM + "_" + WISE.Constants.pid;
					}else{
						for(var i=0; i<_e.CHOROPLETH_MAP_DATA_ELEMENT.length; i++){
							if(_e.CHOROPLETH_MAP_DATA_ELEMENT[i].CTRL_NM == self.ComponentName){
								CtrlNM = _e.CHOROPLETH_MAP_DATA_ELEMENT[i].CTRL_NM + "_" + WISE.Constants.pid;
								cnt = i;
							}
						}
					}
				}else{
					if(_e.CHOROPLETH_MAP_DATA_ELEMENT.length == undefined){
						CtrlNM = _e.CHOROPLETH_MAP_DATA_ELEMENT.CTRL_NM;
					}else{//아이템 여러개 있을 경우
						//20211026 syjin 지도 툴팁 아이템 여러 개 있을 경우 불러오기 수정
						for(var i=0; i<_e.CHOROPLETH_MAP_DATA_ELEMENT.length; i++){
							if(_e.CHOROPLETH_MAP_DATA_ELEMENT[i].CTRL_NM == self.ComponentName){
								CtrlNM = _e.CHOROPLETH_MAP_DATA_ELEMENT[i].CTRL_NM;
								cnt = i;
							}
						}
						//CtrlNM = _e.CHOROPLETH_MAP_DATA_ELEMENT[_i].CTRL_NM;
					}
					
				}
				/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */								
				if(_e.CHOROPLETH_MAP_DATA_ELEMENT.length == undefined){
					mapDataElement = _e.CHOROPLETH_MAP_DATA_ELEMENT;
				}else{
					//20211026 syjin 지도 툴팁 아이템 여러 개 있을 경우 불러오기 수정
					mapDataElement = _e.CHOROPLETH_MAP_DATA_ELEMENT[cnt];
				}														
			}			
		});
		/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
		// 2020.02.12 mksong self.CU가 undefined로 오류 나서 주석 dogfoot
		var dataElement = {};
		if(self.CU!=undefined && self.CU.Data!=undefined) {
			dataElement = self.CU.Data.getDataElement(dashboardXml, mapDataElement.CTRL_NM || self.ComponentName);
		}

		if (typeof this.Map.TooltipContentType === 'undefined') {
			this.Map.TooltipContentType = mapDataElement.TOOLTIP_OPTIONS
				? mapDataElement.TOOLTIP_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.Map.TooltipMeasureFormat === 'undefined') {
			this.Map.TooltipMeasureFormat = mapDataElement.TOOLTIP_OPTIONS
				? mapDataElement.TOOLTIP_OPTIONS.MEASURE
				: 'O';
		}
		if (typeof this.Map.TooltipPrefixEnabled === 'undefined') {
			this.Map.TooltipPrefixEnabled = mapDataElement.TOOLTIP_OPTIONS
				&& mapDataElement.TOOLTIP_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Map.TooltipPrefixFormat === 'undefined') {
			this.Map.TooltipPrefixFormat = mapDataElement.TOOLTIP_OPTIONS
				? mapDataElement.TOOLTIP_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.Map.TooltipSuffixEnabled === 'undefined') {
			this.Map.TooltipSuffixEnabled = mapDataElement.TOOLTIP_OPTIONS
				&& mapDataElement.TOOLTIP_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Map.TooltipSuffix === 'undefined') {
			this.Map.TooltipSuffix = mapDataElement.TOOLTIP_OPTIONS
				? {
					O: mapDataElement.TOOLTIP_OPTIONS.SUFFIX_O,
					K: mapDataElement.TOOLTIP_OPTIONS.SUFFIX_K,
					M: mapDataElement.TOOLTIP_OPTIONS.SUFFIX_M,
					B: mapDataElement.TOOLTIP_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.Map.TooltipPrecision === 'undefined') {
			this.Map.TooltipPrecision = mapDataElement.TOOLTIP_OPTIONS
				? mapDataElement.TOOLTIP_OPTIONS.PRECISION
				: 0;
		}


		this.meta = this.Map;

	};
	
	this.setCustomPalette = function(startColor, lastColor){
		var myPalette = {
		    simpleSet: ['#60a69f', '#78b6d9', '#6682bb', '#a37182', '#eeba69'], // for "Chart", "PieChart", "BarGauge", "Funnel",
		                                                                        // and "TreeMap" with a gradient or range colorizer 
		    indicatingSet: ['#90ba58', '#eeba69', '#a37182'], // for "CircularGauge" and "LinearGauge"
		    gradientSet: [startColor, lastColor] // for "VectorMap" and "TreeMap" with a gradient or range colorizer 
		};
		
		DevExpress.viz.registerPalette('myCustomPalette', myPalette);
	}
	
	/** @Override */
	this.bindData = function(_data, _ativePanelId) {
		// 2020.02.07 mksong sqllike 적용 dogfoot
// if (!this.tracked) {
// this.globalData = _.clone(_data);
// this.filteredData = _.clone(_data);
// }
		$("#" + this.itemid).empty();
		
		// 2020.02.07 mksong sqllike 적용 dogfoot
// if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
// var nodataHtml = '<div class="nodata-layer"></div>';
// $("#" + this.itemid).empty().append(nodataHtml);
// }
// else {
		
		if(self.shpFilemeta == null || self.dbfFilemeta == null){
			setTimeout(this.renderMap(_data, _ativePanelId),3000);
		}else{
			this.renderMap(_data, _ativePanelId);
		}
		
// }
	};
	
	this.generateMapChart = function(dataset, measures, drill, where){
		$.each(this.panelManager.valuePanel, function(_pn, _ovp) {
			var dxConfigs = self.getDxItemConfig(self.meta);
			var areaLayer = dxConfigs.layers[0];
			var currentTarget = {};

			$.each(WISE.util.Object.toArray(self.meta.Maps.ValueMap),function(_i,_Maparr){
				if(_ovp.value.uniqueName == _Maparr.Value.UniqueName){
					currentTarget = _Maparr;
				}
			});
			/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
			/*var colorGroupArray = self.gradientValue(self.datasetColor, currentTarget.CustomScale, currentTarget.GradientPalette, _ovp.value.nameBySummaryType,currentTarget.CustomColorSet);
			if(typeof currentTarget.CustomScale == 'undefined'){
				// if(drill){
				// self.dxItem.option('layers[0].colorGroups', colorGroupArray);
				// }else{
					areaLayer.colorGroups = colorGroupArray;
				// }
			}
			else if(typeof currentTarget.CustomScale.PercentScale == 'undefined'){					
					areaLayer.colorGroups = colorGroupArray;					
			}
			else{				
					areaLayer.colorGroups = colorGroupArray;					
			}

			areaLayer.colorGroupingField = _ovp.value.nameBySummaryType;

			if(typeof currentTarget.GradientPalette != 'undefined'){
				var startColor = self.getHexColor(currentTarget.GradientPalette.StartColor).toUpperCase(), endColor = self.getHexColor(currentTarget.GradientPalette.EndColor).toUpperCase();
				areaLayer.palette = [startColor,endColor];
			}
			else if(typeof currentTarget.CustomPalette != 'undefined'){
				if(self.meta.Palette == 'Custom'){
					if(currentTarget.CustomPalette.Color != ""){
					    var colorArray = new Array();
						$.each(currentTarget.CustomPalette.Color,function(_i,_colorItems){
							if(typeof _colorItems == 'string' && _colorItems.indexOf('#') > -1){
								colorArray.push(_colorItems.toUpperCase());
							}else{
								colorArray.push(self.getHexColor(_colorItems).toUpperCase());
							}
						});
						areaLayer.palette = colorArray;
					}else{
						areaLayer.palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
					}

				}else{

						if(typeof self.meta.Palette == 'string'){
							areaLayer.palette = self.meta.Palette;
						}

				}
			}
			else{
				if(typeof self.meta.Palette == 'string'){
					areaLayer.palette = self.meta.Palette;
				}else{
					if(self.colorOptions.customType=='custom'){
						areaLayer.palette = self.meta.Palette;
					}else{
				        areaLayer.palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
					}
				}
				
				//dogfoot 지도 팔레트 기본값이 뷰어랑 다른 오류 수정 shlim 20200616 
			}
			*/
						
            //self.setCustomPalette(self.editPaletteOption.paletteStartColor, self.editPaletteOption.paletteLastColor, areaLayer);
            			
			var selectedMeasures;
			$.each(measures, function(_i,_measures){
				if(_ovp.value.uniqueName == _measures.uniqueName){
					selectedMeasures = _measures;
					return;
				}
			});
			
			//값 기준 변경(지역별)
			self.totalValue = 0;
			$.each(dataset,function(_i,_data){
				self.totalValue += _data[_ovp.value.nameBySummaryType];
			});
			
			//값 기준(전체)
			//var totalValue = 0;
			//$.each(dataset,function(_i,_data){
			//	totalValue += _data[_ovp.value.nameBySummaryType];
			//});
			
			areaLayer.customize = function (_elements) {
				var shpIndex = self.shpIndex;
				var attributeName = [];
				if(self.attributeName.Name == undefined){
					attributeName = self.attributeName;
				}else{
					var array = self.attributeName['Name'];

					if(Array.isArray(array)){
                    	$.each(array, function(_i, _v){
							$.each(_v, function(_i2, _v2){
								attributeName.push(_v2);
							})
					    })
                    }else{
                    	$.each(array, function(_i, _v){
                    	  attributeName.push(_v);  
                    	})
                    }
				}
				// dogfoot 코로플레스 측정값 2개이상일 때 tracking_data 옵션 추가 syjin 20210414
				$.each(self.panelManager.valuePanel, function(_pn, _ovp) {
					$.each(_elements, function (_i0, _element) {
						var name = _element.attribute(attributeName[self.shpIndex]);
						// $.each(dataset, function(_i1, _d1) {
						$.each(self.filteredData, function(_i1, _d1) {
							if ($.type(self.attributeDimension[shpIndex]) === 'object' && (name == _d1[self.attributeDimension[shpIndex].name])) {
								var d = _d1[_ovp.value.nameBySummaryType];
								
								self.nameBySummaryType = _ovp.value.nameBySummaryType;
								
								if (d !== undefined) {
									//dogfoot 지역 사용자 색상 지정 추가 20210707 syjin
									_element.attribute(_ovp.value.nameBySummaryType, d);
									// dogfoot 코로플레스 % 기준 색상 편집 오류 수정 20210414
									// syjin
									if(self.labelOption.ColorEnabled){
										_element.applySettings({selectedColor : self.labelOption.Color});
									}
									_element.attribute('percentValue', d / self.totalValue);
									_element.attribute('percent', d / self.totalValue * 100);
									var formatVal = "";
									if(selectedMeasures.format.type == undefined){
										formatVal = selectedMeasures.format.substring(0,1) == 'd'? undefined:selectedMeasures.format.substring(0,1);
									}else{
										formatVal = selectedMeasures.format.type.substring(0,1) == 'd'? undefined:selectedMeasures.format.type.substring(0,1);
									}
									//var tooltipHtml = '<b style = "' + gDashboard.fontManager.getCustomFontStringForItem(12) + '">'+name+'</b><br/>';
									//tooltipHtml += '<b style = "' + gDashboard.fontManager.getCustomFontStringForItem(12) + '">' + (_ovp.value.vmValueName || _ovp.value.caption) + ':</b> ' + WISE.util.Number.unit(d,'Number',undefined,selectedMeasures.precision,undefined,undefined,undefined,undefined);
									var tooltipHtml = "";
									if(typeof self.getTooltipFormat(_element, mapTooltipFormat) === "object"){
									    tooltipHtml = self.getTooltipFormat(_element, mapTooltipFormat).html;
									}else{
									    tooltipHtml = self.getTooltipFormat(_element, mapTooltipFormat);
									}
									
									var labelHtml = "";
									if(typeof self.getLabelFormat(_element, self.labelOption) === 'object'){
										if(self.getLabelFormat(_element, self.labelOption).text != undefined)
											labelHtml = self.getLabelFormat(_element, self.labelOption).text;
										else
											labelHtml = self.getLabelFormat(_element, self.labelOption).html;
									}else{
										labelHtml = self.getLabelFormat(_element, self.labelOption);
									}
									_element.attribute('tooltipHtml', tooltipHtml);
									_element.attribute('labelHtml', labelHtml);
									// _element.attribute('name_value', name + "
									// : "+ d);
								}
								return false;
							}

						});
					});
				});
			};
			/* legend */
			if (self.legend && self.legend.Visible) {
				var legend = {customizeText: function (_arg) {
// return
// WISE.util.Number.unit(_arg.start,selectedMeasures.format.substring(0,1),selectedMeasures.precision);
// if(_arg.index == (areaLayer.palette.length-1)){
// return _arg.start + ' ~ ';
// }else{
// return _arg.start + ' ~ ' + (_arg.end - 1);
// }
					/* dogfoot 범례 표기 변경 shlim 20200617 */
					return _arg.start + ' ~ ';

				}};
				// extend parent object
				WISE.util.Object.overrideExtend(legend, self.mapLegend);

				dxConfigs.legends = [legend];
			}
			switch(self.shapefileArea) {
			case 'Europe':
				areaLayer.dataSource = DevExpress.viz.map.sources.europe;
				break;
			case 'Asia':
				dxConfigs.zoomFactor = 1.41;
				dxConfigs.center = [117.993, 57.500];
				dxConfigs.bounds = [-180, 85, 180, -60];
				areaLayer.dataSource = DevExpress.viz.map.sources.world;
				break;
			case 'NorthAmerica':
				dxConfigs.zoomFactor = 1.45;
				dxConfigs.center = [-109.971, 64.990];
				dxConfigs.bounds = [-180, 85, 180, -60];
				areaLayer.dataSource = DevExpress.viz.map.sources.world;
				break;
			case 'SouthAmerica':
				dxConfigs.zoomFactor = 3.00;
				dxConfigs.center = [-69.995, -26.998];
				dxConfigs.bounds = [-180, 85, 180, -60];
				areaLayer.dataSource = DevExpress.viz.map.sources.world;
				break;
			case 'Africa':
				areaLayer.dataSource = DevExpress.viz.map.sources.africa;
				break;
			case 'USA':
				dxConfigs.zoomFactor = 0.5;
				areaLayer.dataSource = DevExpress.viz.map.sources.usa;
				break;
			case 'Canada':
				areaLayer.dataSource = DevExpress.viz.map.sources.canada;
				break;
			default:				
				
				if (self.customShapefile) {					
					/* load shp 일 경우 */				
					if(self.shpFilemeta != undefined && self.dbfFilemeta != undefined){// shp
																						// 파일																						// 업로드
						if(!gDashboard.isNewReport){
							$.ajax({
								type:'post',
								url:self.CustomUrl[self.shpIndex].Url,								
								async:false,
								success:function(json){ 
									if(!self.searchCheck){
										var data = json.features;
										var locationCode = self.getLocationCode(data, self.LocationName, self.attributeName[self.shpIndex]);
										var dataSource = self.initDataSource(json, "시도", locationCode, true);
									}else{
										dataSource = json;
									}
									
									if(typeof dataSource == 'string')
										areaLayer.dataSource = JSON.parse(dataSource);
								}
							})
							
							
						}else{
							areaLayer.dataSource = self.CustomUrl[self.shpIndex].Url;
						}
				
						dxConfigs.bounds[0] = dxConfigs.bounds[0] - 5;
						dxConfigs.bounds[1] = dxConfigs.bounds[1] + 0.5;
					}else{// geojson 불러오기
						if(!gDashboard.isNewReport && !self.searchCheck){// 불러오기
							//if(self.CustomUrl.length == 0){
								self.CustomUrl = ["","",""];
								if(self.dimensions.length > 1){
									if(self.meta.CustomShapefile.url == undefined){
                                        self.CustomUrl = self.meta.CustomShapefile;
									}else{
										var customShapeFileLength = self.meta.CustomShapefile.url.length;								
										for(var i=0; i<customShapeFileLength; i++){
											if(!self.disabledCheck(i)){
												var url = {'Url':self.meta.CustomShapefile.url[i].Url.replace(/shp/gi,"geojson")};
												self.CustomUrl[i] = url;
											}else{
												self.CustomUrl[i] = {};
											}
										}
									}
								}else{
									var url = "";
									if(self.meta.CustomShapefile.url == undefined){
                                        url = {'Url':self.meta.CustomShapefile[self.shpIndex].Url.replace(/shp/gi,"geojson")}; 
									}else{
                                        url = {'Url':self.meta.CustomShapefile.url[self.shpIndex].Url.replace(/shp/gi,"geojson")};
									}
									self.CustomUrl[self.shpIndex] = url;
								}
							//}
							
							var data = self.getGeojsonFile(self.shpIndex);
							
							if(self.shpIndex == 0){
								areaLayer.dataSource = data;
							}else{
								var title = self.shpIndex==1?"시도":"시군구";
								//if(self.customShapefile.url[self.shpIndex-1]!=""){
								if(self.CustomUrl[self.shpIndex-1]!="" && Object.keys(self.CustomUrl[self.shpIndex-1]).length != 0){
									var beforeData = self.getGeojsonFile(self.shpIndex-1);																
									var locationCode = self.getLocationCode(beforeData.features, self.LocationName, self.attributeName[self.shpIndex-1]);
									var dataSource = self.initDataSource(data, title, locationCode, true);	
									
									areaLayer.dataSource = dataSource;
								}else{
									areaLayer.dataSource = data
								}																								
							}						
						}else{// 새로만들기
							if(self.CustomUrl[self.shpIndex] == undefined){
								var customShapeFileLength = self.meta.CustomShapefile.url.length;								
								for(var i=0; i<customShapeFileLength; i++){
									if(!self.disabledCheck(i)){
										var url = {};
										if(self.meta.CustomShapefile.url[i].Url != undefined){
											url = {'Url':self.meta.CustomShapefile.url[i].Url.replace(/shp/gi,"geojson")};
											self.CustomUrl[i] = url;
										}
									}else{
										self.CustomUrl[i] = {};
									}
								}
							}
							
							if(typeof self.CustomUrl[self.shpIndex] == "string"){
							    areaLayer.dataSource = self.CustomUrl[self.shpIndex];	
							}else{
							    areaLayer.dataSource = self.CustomUrl[self.shpIndex].Url;							
							}						
						}
					}
										
					if (self.CUSTOMIZED.get('useShapeFile')) {
						_ovp.useShapeFile = true;
						_ovp.shapelocation = self.shapelocation;
					} else {
						 var mapdata = WISE.widget.getCustom(WISE.Constants.pid, this.type);
						 var itemdata = WISE.widget.getCustom(WISE.Constants.pid, this.type);
						 var commondata = WISE.widget.getCustom('common','CHOROPLETH_MAP');
						 if(typeof mapdata != 'undefined')
							 mapdata= mapdata['CHOROPLETH_MAP']['data'];
						 else if(typeof itemdata != 'undefined')
							 mapdata= itemdata['CHOROPLETH_MAP']['data'];
						 else{
							 mapdata = self.CUSTOMIZED.get('data');
						 }
					}
					
					//firstIndex가 0 보다 큰 경우 bounds 초기화
					var index= [
						"mapStateContentPanel" + self.index,
						"mapCityContentPanel" + self.index,
						"mapDongContentPanel" + self.index
					];
					
					var firstIndex = self.getFirstIndex();
                    
                    if(firstIndex >= 1){
                    	var bounds = self.getGeojsonFile(self.shpIndex);
                    	dxConfigs.bounds = bounds.bbox;
                    	dxConfigs.center = [(bounds.bbox[0] + bounds.bbox[2])/2, (bounds.bbox[1] + bounds.bbox[3])/2];                  	
                    }
					
                  //단일 마스터 필터 일때만
                    if(where != undefined){
                    	var focusedItem = gDashboard.itemGenerateManager.focusedItem;
                    	if(WISE.Constants.editmode == 'viewer'){
                    		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(d_i, d_v){
                    			if(d_v.type == 'CHOROPLETH_MAP' && d_v.selectedText != ""){
                    				focusedItem = d_v;
                    				return false;
                    			}
                    		})
                    	}
                    	
	                    if(where.length == 1 && focusedItem.IO.MasterFilterMode == "Single"){
	                    	console.log(where);
	                    	//focusedItem index
	                    	var focusedIndex = focusedItem.shpIndex;
	                        var selectedData = where[0].data[0];
	                        var data = self.getGeojsonFile(self.shpIndex);
	                        var title = self.shpIndex==1?"시도":"시군구";
	
	                        if(focusedIndex + 1 == self.shpIndex){
	                            var beforeData = focusedItem.getGeojsonFile(focusedIndex);
	                            var locationCode = self.getLocationCode(beforeData.features, selectedData, self.attributeName[self.shpIndex]);
	                            var dataSource = self.initDataSource(data, title, locationCode, true);
	                            
	                            areaLayer.dataSource = dataSource;
	                            self.initBounds(dataSource);
	                            dxConfigs.bounds = dataSource.bbox;
	                            dxConfigs.center = [(dataSource.bbox[0] + dataSource.bbox[2])/2, (dataSource.bbox[1] + dataSource.bbox[3])/2];
	                        }
	                    }
                    	
                    	
                    	
                    }
				} else {
					/* 월드 맵 */
					dxConfigs.zoomFactor = 1.00;
					dxConfigs.center = [0.000, 46.036];
					dxConfigs.bounds = [-180, 85, 180, -60];
					areaLayer.dataSource = DevExpress.viz.map.sources.world;
				}
			}

			_ovp.dxConfigs = dxConfigs;

		});
	};
	
	this.renderMap = function(_data, _ativePanelId) {
		// 2020.02.07 mksong sqllike 적용 dogfoot
		if(self.searchOk || !gDashboard.isNewReport){
			var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
			var dataSourceId = this.dataSourceId;
			
			
			// self.shpIndex = 0;
			for(var i=0; i<3; i++){
				if(!self.disabledCheck(i)){
					self.shpIndex = i;
					break;
				}
			}
					
	// self.attrName = 'NAME_1';//HASC_1
			var tempdata = _data;
			var tempativePanelId = _ativePanelId;
			var newItem = false;
			if(self.meta == undefined){
				newItem = true;
			}else{
				if(self.meta.Maps == undefined)
					newItem = true;
			}
			/*
			 * if(_functionDo){ this.generate(self.meta); }else
			 */if((this.fieldManager !=null && gDashboard.isNewReport == true) || newItem){ // 신규
																					// 생성
				self.setChoroplethMap();
				gDashboard.itemGenerateManager.addParentItems(self);
				gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
				gDashboard.itemGenerateManager.generateItem(self, self.meta);
				/* dogfoot 코로플레스 맵 안그려지는 오류 수정 shlim 20200617 */
				if(WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale != undefined){
					this.fieldManager.CustomScale = {'RangeStop': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale.RangeStop};
					/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
					this.fieldManager.CustomPalette = {'Color': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomPalette.Color};
					/* dogfoot 지도 생성,불러오기 오류 수정 shlim 20200617 */
					if(typeof WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] != 'undefined'){
					    this.fieldManager.CustomColorSet = {'CustomColorSetCheck' : WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet']['CustomColorSetCheck']};
					}else{
						WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] = {'CustomColorSetCheck':'N'};
						this.fieldManager.CustomColorSet = {'CustomColorSetCheck':'N'};
					}
				}else if(WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale == undefined){

				}
			}
			else if(this.fieldManager != null && gDashboard.isNewReport == false){ // 레포트
																					// 열기
				if(WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale != undefined){
					this.fieldManager.CustomScale = {'RangeStop': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale.RangeStop};
					/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
					this.fieldManager.CustomPalette = {'Color': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomPalette.Color};
					/* dogfoot 지도 생성,불러오기 오류 수정 shlim 20200617 */
					if(typeof WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] != 'undefined'){
					    this.fieldManager.CustomColorSet = {'CustomColorSetCheck' : WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet']['CustomColorSetCheck']};
					}else{
						WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] = {'CustomColorSetCheck':'N'};
						this.fieldManager.CustomColorSet = {'CustomColorSetCheck':'N'};
					}
				}
				
				gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
				this.setChoroplethMapForOpen();
				gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
				gDashboard.itemGenerateManager.generateItem(self, self.meta);
			}
			/*
			 * if(this.fieldManager !=null && gDashboard.isNewReport == true){
			 * self.setChoroplethMap();
			 * gDashboard.itemGenerateManager.addParentItems(self);
			 * gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			 * this.generate(self.meta); }else{
			 * gDashboard.itemGenerateManager.addParentItems(self);
			 * gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			 * this.generate(self.meta); }
			 */
			this.panelManager.empty();
			/* dogfoot 코로플레스 맵 안그려지는 오류 수정 shlim 20200616 */
	// this.VM = WISE.util.Object.toArray((self.meta['Maps'] &&
	// self.meta['Maps']['ValueMap']) || []);
	//
	// this.valueMaps = [];
	// $.each(this.VM, function(_i0, _a0) {
	// var uniqueName = _a0['Value']['UniqueName'];
	// var dataMember = self.DU.getDataMember(uniqueName, self.DI,
	// self.dimensions,
	// self.measures);
	// dataMember.vmName = _a0['Name'];
	// dataMember.vmValueName = _a0['ValueName'];
	//
	// var rangeStop = (_a0['CustomScale'] && _a0['CustomScale']['RangeStop'])
	// ||
	// undefined;
	// if (rangeStop) {
	// rangeStop.push(self.CUSTOMIZED.get('rangeStopMaxValue'));
	// }
	//
	// dataMember.colorGroups = (_a0['CustomScale'] &&
	// _a0['CustomScale']['RangeStop']) ||
	// self.CUSTOMIZED.get('CustomScale_RangeStop');
	// self.valueMaps.push(dataMember);
	// });
			
			// 2021.04.28 syjin 코로플레스 attributeDimension 수정 dogfoot
			// this.attributeDimension =
			// this.DU.getDataMember(self.meta['AttributeDimension']['UniqueName'],
			// this.DI, this.dimensions);
			self.attributeDimension = [];

			var attrDimension;
           
            var startNum = self.getFirstIndex();
            
			$.each(self.meta['AttributeDimension'], function(_i, _v){
	            var location = ['시도', '시군구', '읍면동'];

	            
	            if(Array.isArray(_v)){
                    $.each(_v, function(_i2, _v2){
                    	data = self.DU.getDataMember(_v2['UniqueName'], self.DI, self.dimensions)
                        if(location[startNum] == '시도'){
							self.attributeDimension[0] = data;
						}else if(location[startNum] == '시군구'){
							self.attributeDimension[1] = data;
						}else{
							self.attributeDimension[2] = data;
						}
                    	startNum++;
                    })
	            }else{
					data = self.DU.getDataMember(_v['UniqueName'], self.DI, self.dimensions);	

					if(location[startNum] == '시도'){
						self.attributeDimension[0] = data;
					}else if(location[startNum] == '시군구'){
						self.attributeDimension[1] = data;
					}else{
						self.attributeDimension[2] = data;
					}	
					startNum++;
	            }	            
			})
			
			this.panelManager.makePanel(this.valueMaps, ['dummy_value']);

			var dataset, dimensions = self.dimensions, measures = self.measures;
			
			var dimensions = [];
            var cnt = 0;
            var firstCheck = false;
            var firstIndex = 0;
            for(var i=0; i<3; i++){                        	
				if(!self.disabledCheck(i)){
                    dimensions.push(self.dimensions[cnt]);
                    cnt++;
                    if(!firstCheck) {
                    	firstCheck = true;
                    	firstIndex = i;
                    }
				}else{
					dimensions.push({});
				}
            }
            
			if ($.type(self.tooltipMeasures) === 'array' && self.tooltipMeasures.length > 0) {
				measures = measures.concat(self.tooltipMeasures);
			}

			// 2020.02.07 mksong sqllike 적용 dogfoot
			/* dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619 */
			gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
			
			var arrayDimension = [];
			var arrayDimensionColor = [];
			var index = self.shpIndex==undefined?0:self.shpIndex;
			arrayDimension.push(dimensions[index]);
			arrayDimensionColor.push(dimensions[firstIndex]);
			var datasetConfig = self.SQLike.fromJson(arrayDimension, measures, self.filteredData);
			var datasetConfigColor = self.SQLike.fromJson(arrayDimensionColor, measures, self.filteredData);
			// var datasetConfig = self.SQLike.fromJson(dimensions, measures,
			// self.filteredData);
			
			// 20210413 AJKIM 코로플레스 마스터 필터 무시 추가 dogfoot
			self.ignoreMasterFilter(datasetConfig, self);
			
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
			var dataset = SQLikeUtil.doSqlLike(dataSourceId, datasetConfig, self);
            self.datasetColor = SQLikeUtil.doSqlLike(dataSourceId, datasetConfigColor, self);
            
			if (!dataset || ($.type(dataset) === 'array' && dataset.length === 0)) {
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
				return;
			}else{
				$('#'+self.itemid + ' .nodata-layer').remove();
				$("#" + self.itemid).children().css('display','block');
			}

			self.filteredData = dataset;
			self.csvData = self.filteredData;
			// ValueArray.push(self.filteredData);

	// this.panelManager.mapData = dataset;

			var tooltipFirstyColumnStyle = 'font-weight:bold; padding-right:5px; text-align:right;';
			
			var where = datasetConfig.Where;;
			
			// generate map chart
			self.generateMapChart(dataset, measures, '', where);
			
			if (!_ativePanelId) {
				// 맨 처음 value-panel만 active 시킨다.
				$.each(this.panelManager.valuePanel, function(_pn, _ovp) {
					_ativePanelId = _pn;
					return false;
				});
			}

			// 2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
			$('#'+self.itemid).css('display','block');
			self.activePanel = _ativePanelId;
			self.panelManager.activeValuePanel(self.itemid,_ativePanelId);


			// self.dxItem = $("#" +
			// self.itemid).dxVectorMap(dxConfigs).dxVectorMap('instance');

			self.dxItem = $('#'+self.activePanel).dxVectorMap('instance');
			if(userJsonObject.menuconfig.Menu.CHORO_DEFAULT_VALUE){
				var data = _.cloneDeep(self.fileMeta[0].data);
				var dataFeatures = data.features;
				
				var locationCode = self.getLocationCode(dataFeatures, userJsonObject.menuconfig.Menu.CHORO_STATE,dataFeatures, self.attributeName[self.shpIndex]);
				var dataSource = self.initDataSource(data, "시도", locationCode, true);
				self.initBounds(dataSource);
				
				self.dxItem.option('layers[0].dataSource', dataSource);
				self.dxItem.option('bounds', dataSource.bbox);
			}
			
			
			// 2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}
			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();
				gDashboard.updateReportLog();
			}
			// $.each($(".dxm-layer-labels").find("text"),function(_i,_v){
			// $(_v).attr("visibility","none");
			// })
			// dogfoot 코로플레스 측정값 2개이상일 때 tracking_data 옵션 추가 syjin 20210414
			gDashboard.itemGenerateManager.renderButtons(self);
		}else{
			gProgressbar.hide();
			WISE.alert('지도 불러오기를 해주세요.');
		}
	};
	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO['MasterFilterMode'] && self.activePanel != "") {

			// dogfoot 코로플레스 tracking 초기화 오류 수정 syjin 20210413
			var item = $('#'+self.activePanel).dxVectorMap('instance');
			if(item){
				item.clearSelection();
				self.trackingData = [];
				self.selectedText = "";
			}

			// $('#' + self.itemid + '_tracking_data_container').html('');
			self.selectedValues = [];
			self.trackingData = [];
			var clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
       		$(clearTrackingImg)
       			.attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png')
       			.on('mouseover', function() {
       				$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
       			})
       			.on('mouseout', function() {
       				$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
       			});
		}
	};

	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
		// tracking data text area
// $('#'+_itemid + '_tracking_data_container').empty();
// if (this.valueMaps && this.valueMaps.length > 1) {
// // value-panel selection
// var valueListId = _itemid + '_topicon_vl';
// var popoverid = _itemid + '_topicon_vl_popover';
//
// var listHtml = '<li><a id="' + valueListId + '" href="#"><img src="' +
// WISE.Constants.context + '/images/cont_box_icon_layer.png"
// onMouseOver="this.src=\'' + WISE.Constants.context +
// '/images/cont_box_icon_layer_.png\'" onMouseOut="this.src=\'' +
// WISE.Constants.context + '/images/cont_box_icon_layer.png\'" alt="Select
// Panel" title="Select Panel"></a></li>';
// $('#' + _itemid + '_tracking_data_container').append(listHtml);
//
// var p = $('#editPopover').dxPopover('instance');
//
// var temphtml = "<div style='width:150px;'>";
// temphtml += '<div class="add-item noitem">';
// $.each(this.valueMaps, function(_i, _vo) {
// temphtml += '<div class="select-style" data-key="' + (self.itemid + '_' +
// _vo.uniqueName) + '"><span data-key="' + (self.itemid + '_' + _vo.uniqueName)
// + '">' + _vo.caption + '</span></a>';
// });
// temphtml += '</div>';
// temphtml += '</div>';
//
// p.option({
// target: '#'+valueListId,
// contentTemplate: function(contentElement) {
// $(temphtml).appendTo(contentElement);
// $('.select-style').on('click',function(_e){
// p.hide();
// var targetPanelId = _e.target.getAttribute('data-key');
// self.panelManager.activeValuePanel(self.itemid,targetPanelId);
// });
// },
// // visible:false
// })
// $('#' + _itemid + '_topicon').off('click').on('click',function(){
// p.option('visible', !(p.option('visible')));
// });
// }
//
// // tracking conditions clear
// if (self.IO && self.IO['MasterFilterMode']) {
// if(self.IO['MasterFilterMode'] != "Off"){
// self.trackingClearId = self.itemid + '_topicon_tracking_clear';
//
// var trackingClearHtml = '';
// trackingClearHtml += '<li><a id="' + self.trackingClearId + '" href="#">';
// trackingClearHtml += '<img src="' + WISE.Constants.context +
// '/images/cont_box_icon_filter_disable.png" ';
// trackingClearHtml += 'onMouseOver="this.src=\'' + WISE.Constants.context +
// '/images/cont_box_icon_filter_disable.png\'" ';
// trackingClearHtml += 'onMouseOut="this.src=\'' + WISE.Constants.context +
// '/images/cont_box_icon_filter_disable.png\'" ';
// trackingClearHtml += 'alt="Clear Filters" title="Clear Filters"></a></li>';
// topIconPanel.append(trackingClearHtml);
//
// $("#" + self.trackingClearId).click(function(_e) {
// var clearTrackingImg = $(this).find('img')[0];
// if(clearTrackingImg.src.indexOf('cont_box_icon_filter_.png') > -1 ) {
// $('#' + self.itemid + '_tracking_data_container').html('');
// window[self.dashboardid].filterData(self.itemid, []);
// self.clearTrackingConditions();
// }
// });
// }
//
// }
	};

	this.getHexColor = function(number){
	    return "#"+((number)>>>0).toString(16).slice(-6);
	};
	/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
	this.gradientValue = function(_data,range,colorList,summaryCol,customChck){
		self.valueRange = {};
// self.valueRange['rangeStop'] = typeof range == 'undefined' ?
// [0,10,20,30,40,50,60,70,80,90]
// :range.RangeStop.slice(0,range.RangeStop.length-1);
		self.valueRange['rangeStop'] = [0,10,20,30,40,50,60,70,80,90];
		/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
		var ColorSetCheck =  typeof customChck != 'undefined' ? customChck.CustomColorSetCheck : 'N';
        if(ColorSetCheck == 'Y'){
            self.valueRange['customRangeStop'] = range['RangeStop'];
        }
		self.valueRange['PercentScale'] = typeof range == 'undefined' ? true : range.PercentScale;
		var returnGroup = new Array();
		if(self.valueRange.PercentScale == false){
			returnGroup = self.valueRange['rangeStop'];
// 더미코드. 만약을 위해 삭제 안함.

// var startR = self.hextoDec(startColor.substring(1,3)), startG =
// self.hextoDec(startColor.substring(3,5)), startB=
// self.hextoDec(startColor.substring(5,7));
// var endR = self.hextoDec(endColor.substring(1,3)), endG =
// self.hextoDec(endColor.substring(3,5)), endB =
// self.hextoDec(endColor.substring(5,7));



// var RedDiffer = startR > endR ? startR-endR : endR-startR;
// var GreenDiffer = startG > endG ? startG-endG : endG-startG;
// var BlueDiffer = startB > endB ? startB-endB : endB-startB;

// var returnColor = new Array();
// var RedReturn = startR > endR ? endR : startR;
// var GreenReturn = startG > endG ? endG : startG;
// var BlueReturn = startB > endB ? endB : startB;
// returnColor.push(startColor);
// for(var i=0;i<valueRange.length;i++){
// RedReturn = RedReturn + Math.round(RedDiffer/valueRange.length);
// GreenReturn = GreenReturn + Math.round(GreenDiffer/valueRange.length);
// BlueReturn = BlueReturn + Math.round(BlueDiffer/valueRange.length);

// var str = "";
// str +=
// "#"+self.decimalToHex(RedReturn)+""+self.decimalToHex(GreenReturn)+""+self.decimalToHex(BlueReturn)+"";
// returnColor.push(str);
// }

		}
		else{
			/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
			if(ColorSetCheck == 'Y'){
				/* dogfoot 지도 팔레트 설정 후 조회시 최대 범위값 추가 shlim 20200617 */
                self.valueRange['customRangeStop'].forEach(function(range, index) {
					returnGroup.push(range);
				});

                returnGroup.push(self.CUSTOMIZED.get('rangeStopMaxValue'));
			}else{
				// var maxJson =
				// (self.getJSONArrayMax(_data,summaryCol)),minJson =
				// (self.getJSONArrayMin(_data,summaryCol));
				// var minVal = minJson[summaryCol], gap = maxJson[summaryCol] -
				// minJson[summaryCol];
				var minVal = 0;
				var maxVal = 0;
				
				$.each(_data, function(s_i, s_v){
					maxVal += s_v[summaryCol];
				})
				
				returnGroup.push(minVal);
				for(var i=1;i<self.valueRange['rangeStop'].length;i++){
					// returnGroup.push(Math.round(minVal+gap*(self.valueRange['rangeStop'][i]/100)));
					returnGroup.push(Math.round(maxVal * self.valueRange['rangeStop'][i]/100));
				}
				returnGroup.push(maxVal);
			}
		}
		return returnGroup;
	};

	this.hextoDec = function(val) {
	    var hex = val.split('').reverse().join('');
	    var dec = 0;
	    for (var i = 0; i < hex.length; i++) {
	        var conv = '0123456789ABCDEF'.indexOf(hex[i]);
	        dec += conv * Math.pow(16, i);
	    }
	    return dec;
	};

	this.decimalToHex = function(d, padding) {
	    var hex = Number(d).toString(16);
	    padding = typeof (padding) === "undefined" || padding === null ? padding = 2 : padding;

	    while (hex.length < padding) {
	        hex = "0" + hex;
	    }

	    return hex;
	};

	this.getJSONArrayMax = function(arr, prop) {
	    var max;
	    for (var i=0 ; i<arr.length ; i++) {
	        if (!max || parseInt(arr[i][prop]) > parseInt(max[prop]))
	            max = arr[i];
	    }
	    return max;
	};

	this.getJSONArrayMin = function(arr, prop) {
	    var min;
	    for (var i=arr.length ; i>0 ; i--) {
	        if (!min || parseInt(arr[i][prop]) < parseInt(min[prop]))
	            min = arr[i];
	        /* dogfoot 코로플레스 맵 데이터 1개일때 오류 수정 shlim 20201126 */
	        if(arr.length == 1){
	        	min = arr[0];
	        }
	    }
	    return min;
	};

	this._base64ToArrayBuffer = function(base64) {
		var binary_string;
		if(WISE.Constants.browser =='IE7' || WISE.Constants.browser =='IE8' || WISE.Constants.browser =='IE9'){
			binary_string = atob(base64);
		}
		else{
			binary_string = window.atob(base64);
		}
		var len = binary_string.length;
		var bytes = new Uint8Array( len );
		for (var i = 0; i < len; i++)        {
		    bytes[i] = binary_string.charCodeAt(i);
		}
		return bytes.buffer;
	};

	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
// if($('#data').length > 0){
// $('#data').remove();
// }
// $('#menulist').addClass('col-2');
// if($('#data').length == 0){
// $('#menulist').append($('<li id="data" rel="panelDataA-2"><a
// href="#tab4primary" data-toggle="tab">'+
// gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));
// }
//
// if($('#design').length > 0){
// $('#design').remove();
// }
//
// if($('#tab5primary').length == 0){
// // 2020.01.16 mksong 영역 크기 조정 dogfoot
// $('.menu-comp.custom-menu').append('<div class="slide-ui responsive
// itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a
// href="#" class="slide-ui-next">next</a><ul id="tab5primary"
// class="slide-ui-list lnb-lst-tab"></ul></div>');
// }
//
// $('#tab5primary').empty();
// $('#tab5primary').append('<span class="drag-line"></span>');
//
// $('<li class="slide-ui-item"><a href="#" id="captionVisible" class="lnb-link
// slide-ui-item more functiondo"><img
// src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png"
// alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
// $('<li class="slide-ui-item"><a href="#" id="editName" class="lnb-link
// slide-ui-item more functiondo"><img
// src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png"
// alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
// $('<li class="slide-ui-item"><a href="#" id="loadMap" class="lnb-link
// slide-ui-item more functiondo"><img
// src="'+WISE.Constants.context+'/resources/main/images/ico_importMap.png"
// alt=""><span>지도 불러오기</span></a></li>').appendTo($('#tab5primary'));
// $('<li class="slide-ui-item"><a href="#" id="lockNavigation" class="lnb-link
// slide-ui-item more functiondo"><img
// src="'+WISE.Constants.context+'/resources/main/images/ico_lockNavigation.png"
// alt=""><span>탐색 잠금</span></a></li>').appendTo($('#tab5primary'));
// $('<li class="slide-ui-item"><a href="#" id="Showlegend" class="lnb-link
// slide-ui-item more functiondo"><img
// src="'+WISE.Constants.context+'/resources/main/images/ico_showColorLegend.png"
// alt=""><span>범레</span></a></li>').appendTo($('#tab5primary'));
// $('<li class="slide-ui-item" title="팔레트"><a href="#" id="editPalette"
// class="lnb-link more functiondo"><img
// src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png"
// alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
// $('<li class="slide-ui-item" title="색상 편집"><a href="#" id="customPalette"
// class="lnb-link more functiondo"><img
// src="'+WISE.Constants.context+'/resources/main/images/ico_editColor.png"
// alt=""><span>색상 편집</span></a></li>').appendTo($('#tab5primary'));
//
//
//
// // $('<a id="setBackColor" class="lnb-link slide-ui-item more functiondo"
// style="padding-right: 15px;"><img
// src="'+WISE.Constants.context+'/resources/main/images/ico_color.png"
// alt=""><span>지도 배경색</span></a>').appendTo($('#tab5primary'));
//
// $('#tab4primary').empty();
// if($('#tab4primary').length == 0){
// $('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2
// tab-content"><div id ="data-menu" class="panel-body"></div></div>'));
// }
//
// // $('<a id="editFilter" class="btn
// point">필터편집</a>').appendTo($('#tab4primary'));
// // $('<a id="clearFilter" class="btn
// point">초기화</a>').appendTo($('#tab4primary'));
// // $('<a id="masterFilter" class="btn point">마스터
// 필터</a>').appendTo($('#tab4primary'));
// // $('<a id="drillDown" class="btn point">드릴
// 다운</a>').appendTo($('#tab4primary'));
// // $('<a id="crossDataSourceFiltering" class="btn point">교차 데이터 소스
// 필터링</a>').appendTo($('#tab4primary'));
// // $('<a id="ignoreMasterFilter" class="btn point">마스터 필터
// 무시</a>').appendTo($('#tab4primary'));
//
// $( "<h4 class=\"tit-level3\">필터링</h4>" +
// "<div class=\"panel-body\">" +
// " <div class=\"design-menu rowColumn\">" +
// " <ul class=\"desing-menu-list col-2\">" +
// " <li>" +
// " <a href=\"#\" id=\"editFilter\" class=\"functiondo\">" +
// " <img src=\"" + WISE.Constants.context +
// "/resources/main/images/ico_basicFilter.png\" alt=\"\"><span>필터 편집</span>" +
// " </a>" +
// " </li>" +
// " <li>" +
// " <a href=\"#\" id=\"clearFilter\" class=\"functiondo\">" +
// " <img src=\"" + WISE.Constants.context +
// "/resources/main/images/ico_ignoreMasterFilters.png\"
// alt=\"\"><span>초기화</span>" +
// " </a>" +
// " </li>" +
// " </ul>" +
// " </div>" +
// "</div>" +
// "<h4 class=\"tit-level3\">상호 작용</h4>" +
// "<div class=\"panel-body\">" +
// " <div class=\"design-menu rowColumn\">" +
// " <ul class=\"desing-menu-list col-3\">" +
// " <li>" +
// " <a href=\"#\" id=\"singleMasterFilter\" class=\"multi-toggle-button
// functiondo\">" +
// " <img src=\"" + WISE.Constants.context +
// "/resources/main/images/ico_singleMasterFilter.png\" alt=\"\"><span>단일
// 마스터<br>필터</span>" +
// " </a>" +
// " </li>" +
// " <li>" +
// " <a href=\"#\" id=\"multipleMasterFilter\" class=\"multi-toggle-button
// functiondo\">" +
// " <img src=\"" + WISE.Constants.context +
// "/resources/main/images/ico_multipleMasterFilter.png\" alt=\"\"><span>다중
// 마스터<br>필터</span>" +
// " </a>" +
// " </li>" +
// " <li>" +
// " <a href=\"#\" id=\"drillDown\" class=\"multi-toggle-button functiondo\">" +
// " <img src=\"" + WISE.Constants.context +
// "/resources/main/images/ico_drillDown.png\" alt=\"\"><span>드릴<br>다운</span>" +
// " </a>" +
// " </li>" +
// " </ul>" +
// " </div>" +
// "</div>" +
// "<h4 class=\"tit-level3\">상호 작용 설정</h4>" +
// "<div class=\"panel-body\">" +
// " <div class=\"design-menu rowColumn\">" +
// " <ul class=\"desing-menu-list col-2\">" +
// " <li>" +
// " <a href=\"#\" id=\"crossFilter\" class=\"single-toggle-button
// functiondo\">" +
// " <img src=\"" + WISE.Constants.context +
// "/resources/main/images/ico_crossDataSourceFiltering.png\" alt=\"\"><span>교차
// 데이터<br>소스 필터링</span>" +
// " </a>" +
// " </li>" +
// " <li>" +
// " <a href=\"#\" id=\"ignoreMasterFilter\" class=\"single-toggle-button
// functiondo\">" +
// " <img src=\"" + WISE.Constants.context +
// "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>마스터
// 필터<br>무시</span>" +
// " </a>" +
// " </li>" +
// " </ul>" +
// " </div>" +
// "</div>"
// ).appendTo($('#tab4primary'));
// tabUi();
// designMenuUi();
// compMoreMenuUi();
//
// $('.single-toggle-button').on('click', function(e) {
// e.preventDefault();
// $(this).toggleClass('on');
// });
// $('.multi-toggle-button').on('click', function(e) {
// e.preventDefault();
// var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
// if ($(this)[0] !== currentlyOn[0]) {
// currentlyOn.removeClass('on');
// }
// $(this).toggleClass('on');
// });
//
// // toggle 'on' status according to chart options
// if (self.IO) {
// if (self.IO['MasterFilterMode'] === 'Single') {
// $('#singleMasterFilter').addClass('on');
// } else if (self.IO['MasterFilterMode'] === 'Multiple') {
// $('#multipleMasterFilter').addClass('on');
// }
// if (self.IO['IsDrillDownEnabled']) {
// $('#drillDown').addClass('on');
// }
// if (self['isMasterFilterCrossDataSource']) {
// $('#crossFilter').addClass('on');
// }
// if (self.IO['IgnoreMasterFilters']) {
// $('#ignoreMasterFilter').addClass('on');
// }
// if (self.IO['TargetDimensions'] === 'Argument') {
// $('#targetArgument').addClass('on');
// } else if (self.IO['TargetDimensions'] === 'Series') {
// $('#targetSeries').addClass('on');
// }
// }
//
//
// $('<div id="editPopup">').dxPopup({
// height: 'auto',
// width: 500,
// visible: false,
// showCloseButton: false
// }).appendTo('#tab5primary');
// // settings popover
// $('<div id="editPopover">').dxPopover({
// height: 'auto',
// width: 'auto',
// position: 'bottom',
// visible: false
// }).appendTo('#tab5primary');
//
// $('.functiondo').on('click',function(e){
// self.functionDo(this.id);
// });

	};

	this.functionDo = function(_f) {
		switch(_f) {
		/* DATA OPTIONS */
// case 'editFilter': {
// // if (!(self.dxItem)) {
// // break;
// // }
// var p = $('#editPopup').dxPopup('instance');
// p.option({
// title: '필터 편집',
// contentTemplate: function(contentElement) {
// var field = [];
// $.each(self.seriesDimensions, function(_i, series) {
// field.push({ dataField: series['name'], dataType: 'string' });
// });
// $.each(self.dimensions, function(_i, dimension) {
// field.push({ dataField: dimension['name'], dataType: 'string' });
// });

// contentElement.append('<div id="' + self.itemid + '_editFilter">');
// $('#' + self.itemid + '_editFilter').dxFilterBuilder({
// fields: field,
// value: self.filter
// });
// }
// });
// // apply filter to current item
// p.option('toolbarItems[0].options.onClick', function() {
// var filter = $('#' + self.itemid +
// '_editFilter').dxFilterBuilder('instance').getFilterExpression();
// var newDataSource = new DevExpress.data.DataSource({
// store: self.globalData,
// paginate: false
// });
// newDataSource.filter(filter);
// newDataSource.load();
//
// self.filter = filter;
// self.bindData(newDataSource.items());
//
// p.hide();
// });
// p.show();
// break;
// }
			// clear filters
// case 'clearFilter': {
// // if (!(self.dxItem)) {
// // break;
// // }
// if (self.filter) {
// self.filter = null;
// self.bindData(self.globalData);
// }
// break;
// }
// toggle master filter mode
			/* dogfoot 코로플레스 맵 마스터필터 추가 shlim 20201126 */
			case 'singleMasterFilter': {
				if (!(self.dxItem)) {
					break;
				}
				gProgressbar.show();
				setTimeout(function () {
					self.functionBinddata = true;
					self.trackingClearId = self.itemid + '_topicon_tracking_clear';
					
					// dogfoot 코로플레스 단일 마스터 필터 적용 시 선택 영역만 선택되도록 수정 syjin
					// 20210411
					self.dxItem.getLayers()[0].clearSelection();					
					$("#"+self.activePanel).dxVectorMap('instance').option('layers[0].selectionMode','single');
					self.selectedText = "";
					self.targetIndex = undefined;
					
					// toggle off
					if (self.IO.MasterFilterMode === 'Single') {
						$('#' + self.trackingClearId).addClass('invisible');
						self.Map.InteractivityOptions.MasterFilterMode = 'Off';
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
						self.Map.InteractivityOptions.MasterFilterMode = 'Single';
						self.IO.MasterFilterMode = 'Single';

						// Only one master filter can be on. Turn off master
						// filters on other items.
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
							/* dogfoot 컨테이너별 마스터필터 적용 shlim 20201013 */
							if(gDashboard.getLayoutType() == "Container"){
								var ContainerList = gDashboard.setContainerList(self);

								$.each(ContainerList,function(_l,_con){
									if (_con.DashboardItem == item.ComponentName) {
										if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
											$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
											item.IO.MasterFilterMode = 'Off';
											item.meta.InteractivityOptions.MasterFilterMode = 'Off';
											/*
											 * DOGFOOT hsshim 2020-02-06 마스터 필터
											 * 기능 리팩토링 적용 (코드 정리)
											 */
											gDashboard.filterData(item.itemid, []);
										}

									}
								})

							}else{
								if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
									$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
									item.IO.MasterFilterMode = 'Off';
									item.meta.InteractivityOptions.MasterFilterMode = 'Off';
									/*
									 * DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링
									 * 적용 (코드 정리)
									 */
									gDashboard.filterData(item.itemid, []);
								}
							}
						});
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, self.trackingData);
					}
				},10);
				break;
			}
			case 'multipleMasterFilter': {
				if (!(self.dxItem)) {
					break;
				}
				gProgressbar.show();
				setTimeout(function () {
					self.functionBinddata = true;
					self.trackingClearId = self.itemid + '_topicon_tracking_clear';
					
					// dogfoot 코로플레스 다중 마스터 필터 적용 시 선택 영역 다중으로 선택되도록 수정 syjin
					// 20210411
					self.dxItem.getLayers()[0].clearSelection();					
					$("#"+self.activePanel).dxVectorMap('instance').option('layers[0].selectionMode','multiple');
					self.selectedText = "";
					self.targetIndex = undefined;
					
					// toggle off
					if (self.IO.MasterFilterMode === 'Multiple') {
						$('#' + self.trackingClearId).addClass('invisible');
						self.Map.InteractivityOptions.MasterFilterMode = 'Off';
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
						self.Map.InteractivityOptions.MasterFilterMode = 'Multiple';
						self.IO.MasterFilterMode = 'Multiple';

						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
							if(gDashboard.getLayoutType() == "Container"){
								var ContainerList = gDashboard.setContainerList(self);

								$.each(ContainerList,function(_l,_con){
									if (_con.DashboardItem == item.ComponentName) {
										if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
											$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
											item.IO.MasterFilterMode = 'Off';
											item.meta.InteractivityOptions.MasterFilterMode = 'Off';
											gDashboard.filterData(item.itemid, []);
										}

									}
								})

							}else{
								if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
									$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
									item.IO.MasterFilterMode = 'Off';
									item.meta.InteractivityOptions.MasterFilterMode = 'Off';
									/*
									 * DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링
									 * 적용 (코드 정리)
									 */
									gDashboard.filterData(item.itemid, []);
								}
							}
						});
						self.clearTrackingConditions();
						gDashboard.filterData(self.itemid, self.trackingData);
					}
				},10);
				break;
			}
// toggle multiple master filter mode
// enable drill down
// case 'drillDown': {
// if (!(self.dxItem)) {
// break;
// }
// var p = $('#editPopover').dxPopover('instance');
// p.option({
// target: '#drillDown',
// contentTemplate: function(contentElement) {
// contentElement.append('<div id="' + self.itemid + '_drillDown">');
// $('#' + self.itemid + '_drillDown').dxRadioGroup({
// dataSource: ['On', 'Off'],
// value: self.IO['IsDrillDownEnabled'] ? 'On' : 'Off',
// onValueChanged: function(e) {
// self.IO['IsDrillDownEnabled'] = e.value ==='On' ? true : false;
// var newData = self.__getChartData();
// self.dxItem.option({dataSource: newData});

// }
// });
// }
// });
// p.option('visible', !(p.option('visible')));
// break;
// }
			// enable cross data source filtering
// case 'crossFilter': {
// // if (!(self.dxItem)) {
// // break;
// // }
// var p = $('#editPopover').dxPopover('instance');
// p.option({
// target: '#crossFilter',
// contentTemplate: function(contentElement) {
// contentElement.append('<div id="' + self.itemid + '_crossFiltering">');
// $('#' + self.itemid + '_crossFiltering').dxRadioGroup({
// dataSource: ['On', 'Off'],
// value: self.isMasterFilterCrossDataSource ? 'On' : 'Off',
// onValueChanged: function(e) {
// self.isMasterFilterCrossDataSource = e.value === 'On' ? true : false;
// self.meta['IsMasterFilterCrossDataSource'] =
// self.isMasterFilterCrossDataSource;
// }
// });
// }
// });
// p.option('visible', !(p.option('visible')));
// break;
// }
			// ignore master filter
			// 20210413 AJKIM 코로플레스 마스터 필터 무시 추가 dogfoot
			case 'ignoreMasterFilter': {								
// if (!(_d3Item.dxItem)) {
// break;
// }
				self.meta.InteractivityOptions.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
				self.tracked = !self.meta.InteractivityOptions.IgnoreMasterFilters;
				gProgressbar.show();
				/* DOGFOOT 20201021 ajkim setTimeout 제거 */
				if (self.meta.InteractivityOptions.IgnoreMasterFilters) {
					// 2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
					self.functionBinddata = true;
					// 2021.04.16 syjin 상호작용-마스터필터무시 버튼 눌렀을 때 지도 사라지는 오류 수정
					// dogfoot
					// self.bindData(self.globalData, true);
					self.bindData(self.globalData);
				} else {
					self.bindData(self.globalData);
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
						if (item.ComponentName !== self.ComponentName && item.IO && self.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
							self.doTrackingCondition(item.itemid, item);
							return false;
						}
					});
				}
				gProgressbar.hide();
				break;
			}
// case 'ignoreMasterFilter': {
// // if (!(self.dxItem)) {
// // break;
// // }
// var p = $('#editPopover').dxPopover('instance');
// p.option({
// target: '#ignoreMasterFilter',
// contentTemplate: function(contentElement) {
// contentElement.append('<div id="' + self.itemid + '_ignoreMasterFilters">');
// $('#' + self.itemid + '_ignoreMasterFilters').dxRadioGroup({
// dataSource: ['On', 'Off'],
// value: self.IO['IgnoreMasterFilters'] ? 'On' : 'Off',
// onValueChanged: function(e) {
// self.IO['IgnoreMasterFilters'] = e.value === 'On' ? true : false;
// self.tracked = !self.IO['IgnoreMasterFilters'];
// self.bindData(self.globalData);
// }
// });
// }
// });
// p.option('visible', !(p.option('visible')));
// break;
// }
			// edit target dimensions
// case 'targetDimension': {
// // if (!(self.dxItem)) {
// // break;
// // }
// var p = $('#editPopover').dxPopover('instance');
// p.option({
// target: '#targetDimension',
// contentTemplate: function(contentElement) {
// contentElement.append('<div id="' + self.itemid + '_targetDimensions">');
// $('#' + self.itemid + '_targetDimensions').dxRadioGroup({
// dataSource: ['Argument', 'Series'],
// value: self.IO['TargetDimensions'],
// onValueChanged: function(e) {
// self.IO['TargetDimensions'] = e.value;
// window[self.dashboardid].filterData(self.itemid, [], self.dataSourceId,
// self.isMasterFilterCrossDataSource);
// filterArray = new Array();
// self.clearTrackingConditions();
// selectedPoint = null;
// }
// });
// }
// });
// p.option('visible', !(p.option('visible')));
// break;
// }

			// edit filter builder
			case 'captionVisible': {
// if (!(self.activePanel)) {
// break;
// }
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.Map['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.Map['ShowCaption'] = false;
				}
				break;
			}
			// edit chart title
			// 2020.10.06 MKSONG 이름편집 오류 수정 DOGFOOT
			case 'editName': {
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '이름 편집',
					width:500,
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize title input box
						contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput">');
                        var html = '<div class="modal-footer" style="padding-bottom:0px;">';
						html += '<div class="row center">';
						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
						html += '</div>';
						html += '</div>';
						html += '</div>';
						contentElement.append(html);

                        $('#' + self.itemid + '_titleInput').dxTextBox({
							text: $('#' + self.itemid + '_title').text()
                        });

                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
                            if(newName.trim() == '') {
                            	WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                            	$('#' + self.itemid + '_titleInput').dxTextBox('instance').option('value', self.Name);
                            } else {
                            	/*
								 * DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류
								 * 수정 20191223
								 */
// var goldenLayout = gDashboard.goldenLayoutManager;
// goldenLayout.changeTitle(self.itemid, newName,
// goldenLayout.canvasLayout.root.contentItems);
                            	var ele = $('#' + self.itemid + '_title');
                            	ele.attr( 'title', newName)
                                ele.find( '.lm_title' ).html(newName);

                                if (self.meta) {
                                    self.meta['Name'] = newName;
                                }
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
			case 'loadMap': {
				var empty = false;
				var index= [
					"mapStateContentPanel" + self.index,
					"mapCityContentPanel" + self.index,
					"mapDongContentPanel" + self.index
				];
				
				var emptyCheck = function(index){
					if($(self.fieldManager.panelManager[index][0]).find('.fieldName').length == 0){
						return true;
					}else{
						return false;
					}
				}
				
				for(var i=0; i<3; i++){
					if(!emptyCheck(index[i])){
						empty = true;
						break;
					}
				}
				
				if(empty){			
					var cancelBtn = function(){
						$('#cancelButton').dxButton({
		            		text: "취소",
		            		type: "danger",
		            		onClick:function(){
		            			$('#loadMapPopup').hide();
		            			$('#loadMapPopup').remove();
		            		}
		            	});
					}
					
					var confirmBtn = function(){
						$('#okButton').dxButton({
							type: "success",
							onClick:function(){
								var emptyValueCheck = function(){
									var empty = false;
									var tabIndex = $("#map_tabpanel").dxTabPanel('instance').option().selectedIndex;
									var id = "";
									if(tabIndex == 0){
										id = 'selectProperties';
									}else{
										id = 'selectPropertiesShp';
									}
                                    for(var i=0; i<3; i++){
                                    	if(!disabledCheck(i)){
											var value = $("#"+id+i).dxSelectBox('instance').option('value');
											if(value == ""){
												empty = true;
												break;	
											}
                                    	}
                                    }
                                    return empty;
								}

								if(!emptyValueCheck()){	            				
		            				self.ShapefileArea = "Custom";
		            				
		            				// dogfoot 지도 범위, 지도 파일
									// 변수 배열 처리 20210519
									// syjin dogfoot
		            				self.ViewArea['area'] = [];
		            				// self.CustomUrl = [];
		            				
		            				for(var i=0; i<self.fileMeta.length; i++){
		            					var tabIndex = $("#map_tabpanel").dxTabPanel('instance').option().selectedIndex;
                                        var fileName = "";
                                        var fileProperties = "";
                                        var filePropertiesItems = "";
                                        
		            					if(!disabledCheck(i)){
		            						self.ViewArea['area'][i] = self.fileMeta[i]['viewArea'];
		            						self.CustomUrl[i] = self.fileMeta[i]['customUrl'];
		            						
		            						if(tabIndex == 0){
	                                            fileName = $("#selectFileName"+i).dxSelectBox('instance').option('value');
	                                            
	                                            fileProperties = $("#selectProperties"+i).dxSelectBox('instance').option('value');
	                                            filePropertiesItems = $("#selectProperties"+i).dxSelectBox('instance').option('items');
	                                        }else{
	                                            fileName = $("#shpCaption"+i).html().slice(0,-4);
	                                            
	                                            fileProperties = $("#selectPropertiesShp"+i).dxSelectBox('instance').option('value');
	                                            filePropertiesItems = $("#selectPropertiesShp"+i).dxSelectBox('instance').option('items');
	                                        }
			            					
			            					self.fileMeta[i].fileInfo = {
			            						"fileName" : fileName,
			            						"fileProperties" : fileProperties,
			            						"filePropertiesItems" : filePropertiesItems
			            					}			            					
		            					}else{
		            						self.ViewArea['area'][i] = {};
		            						self.CustomUrl[i] = {};
		            								            						            					
			            					self.fileMeta[i].fileInfo = {
			            						"fileName" : "",
			            						"fileProperties" : "",
			            						"filePropertiesItems" : ""
			            					}
		            					}
		            					
		            					
                                        
                                        
		            				}            										   
		            					
		            				$('#loadMapPopup').dxPopup('hide');
		            				$('#loadMapPopup').remove();
		            				
		            				self.searchOk = true;
		            			}else{
		            				WISE.alert("빈 항목이 있습니다.",'error');
		            			}
							}
						})
					}
					
					var fileEvent = function(){
						$('.file-ui').each(function(){
		                    var realFileBtn = $(this).find(".real-file");
		                    var customBtn = $(this).find(".custom-button");
		                    var customTxt = $(this).find(".custom-text");
		                    customBtn.on("click", function() {
		                        realFileBtn.click();
		                    });
//
		                    realFileBtn.on("change", function() {
		                        if (realFileBtn.val()) {
		                            customTxt.html(realFileBtn.val().match(
		                              /[\/\\]([\w\d\s\.\-\(\)]+)$/
		                            )[1])
		                        } else {
		                            customTxt.html("No file chosen, yet.");
		                        }
		                    });
		                });
					}
					
									
					var disabledCheck = function(index){
						var type= [
							"mapStateContentPanel" + self.index,
							"mapCityContentPanel" + self.index,
							"mapDongContentPanel" + self.index
						];
						
						if($(self.fieldManager.panelManager[type[index]][0]).find('.fieldName').length == 0){
							return true;
						}else{
							return false;
						}
					}
					
					self.disabledCheck = disabledCheck;
					
					var disabledShpFile = function(index){
						if(disabledCheck(index)){
							$("#dbfButton"+index+" .custom-button").attr("disabled", true);
							$("#shpButton"+index+" .custom-button").attr("disabled", true);
						}
					}
					
					var getDirName = function(name){
						if(name == '시도' || name == 0){
						    dirName = "state";
					    }else if(name == '시군구' || name == 1){
                            dirName = "city";
					    }else{
                            dirName = "dong";
					    }

					    return dirName;
					}

					var getIndex = function(name){
						if(name == '시도'){
						    index = 0;
					    }else if(name == '시군구'){
                            index = 1;
					    }else{
                            index = 2;
					    }

					    return index;
					}
					
					var setOptionForm = function(id, area, index, disabledCheck, fileList, num){	
						var fileValue = "";
                        var propertiesItems = "";
						var propertiesValue = "";
						
						if(self.CustomUrl!=undefined && self.CustomUrl.length > 0 && self.fileMeta[num].fileInfo != undefined){
							if(!self.disabledCheck(num) && self.CustomUrl[num] != undefined && Object.keys(self.CustomUrl[num]).length>0 && index==0){
								fileValue = self.fileMeta[num].fileInfo.fileName;
								propertiesItems = self.fileMeta[num].fileInfo.filePropertiesItems;
								propertiesValue = self.fileMeta[num].fileInfo.fileProperties;
							}
						}
						
						if(!gDashboard.isNewReport){
							if(self.fileMeta[num].fileInfo != undefined){ 
								fileValue = self.fileMeta[num].fileInfo.fileName;
								propertiesItems = self.fileMeta[num].fileInfo.filePropertiesItems;
								propertiesValue = self.fileMeta[num].fileInfo.fileProperties;
							}
						}
						
						var items = [
							{
								   dataField : area,
								   editorType : index==0?"dxSelectBox":"",
								   editorOptions : {
									   items: fileList,
									   disabled: disabledCheck?true:false,
									   onValueChanged:function(_e){ 
										   var name = (_e.component.option('name') || _e.component._options._optionManager._options.name);
									   	   var dirName = getDirName(name);										   
										   var data = getGeoJson(_e.value, dirName, getIndex(name));
									   },
									   value : fileValue,
									   elementAttr : {
										   id : index==0?"selectFileName"+num:"selectFileNameShp"+num
									   }	
								   },						  							
							},
							{
							   dataField : area + " 속성 선택",
							   editorType : "dxSelectBox",
							   editorOptions : {
								   items: propertiesItems,
								   disabled: disabledCheck?true:false,
								   onValueChanged:function(_e){
									   var num;
									   var name = (_e.component.option('name') || _e.component._options._optionManager._options.name)
									   if(name == '시도 속성 선택'){
										   num = 0;
									   }else if(name == '시군구 속성 선택'){
										   num = 1;
									   }else{
										   num = 2;
									   }
		 	                		   self.attrName[num] = _e.value;
		 	                		   self.attributeName[num] = self.attrName[num];
		 	                	   },
		 	                	   value : propertiesValue,
		 	                	   elementAttr:{
		 	                	       id : index==0?"selectProperties"+num:"selectPropertiesShp"+num
		 	                	   }                	   
							   }
							}
						];
						
						var optionsForm = $('#'+id).dxForm({
							items: items
						})
					}
										
					var getFileList = function(dirName){						
						var fileList = [];
						var param = {
								"name" : dirName
						}
						$.ajax({
	                    	   cache: false,
	          	               url: WISE.Constants.context + '/download/getListSHP.do',
	          	               async:false,
	          	               data: JSON.stringify(param),
	          	               contentType: "application/json",	          	              
	          	               type: 'POST',
	          	               success: function(result){
	          	                   var length = Object.keys(result).length;

	          	                   for(var i=length; i>=1; i--){
	          	                       var file = {}
	          	                       fileList.push(result['file'+i].slice(0, -8));                	          	                       
	          	                   }
	          	               }
	          	          })
	          	          
	          	          return fileList;
					}
					
					var initFileMeta = function(fileName, data, index){				
						//if(index == 0)
							//self.fileMeta = [{}, {}, {}];
						if(!disabledCheck(index)){
							var dirName = getDirName(index);
							var object = {
								data : data,
								customUrl : {'Url': WISE.Constants.context+'/UploadFiles/geojson/'+dirName+'/'+(fileName+".geojson")},
								viewArea : {
									'BottomLatitude': data.bbox[1],
									'TopLatitude':  data.bbox[3],
									'LeftLongitude':  data.bbox[0],
									'RightLongitude':  data.bbox[2],
									'CenterPointLatitude': (data.bbox[1] + data.bbox[3])/2,
									'CenterPointLongitude': (data.bbox[0] + data.bbox[2])/2,
        	                    }
							}
							self.fileMeta[index] = object;
						}				
					}
					
					var getGeoJson = function(fileName, dirName, index){
						var data = "";
						
						gProgressbar.show();
						$.ajax({
							type:'post',
							url:WISE.Constants.context + '/report/getGeoJSon.do',
							data:{
								geojsonUrl:fileName+".geojson",
								name:dirName
							},
							async:false,
							success:function(_data){
								data = _data.geoJsonMeta;
								var properties = getProperties(data);
								setProperties(properties, index);
								initFileMeta(fileName, data, index);
								gProgressbar.hide();
							}
						})
					}
                    
                    var getProperties = function(data){
                    	var properties = [];

                    	$.each(data.features["0"].properties,function(_i,_field){
	            	        properties.push(_i);
					    });

					    return properties;
                    }
                    
                    var setProperties = function(properties, index){
                    	$("#selectProperties"+index).dxSelectBox('instance').option('items', properties);
                    }
                    
					$('#wrapper').append('<div id="loadMapPopup"></div>');
					
					var html = "";
					html += '<div class="modal-inner">';
					html += '	<div class="modal-body">';				
					html += ' 		<div id="map_tabpanel">';                  
		            html += '       </div>';	    		
		            html += '	</div>';
		            html += '	<div class="modal-footer">';
					html += '		<div id="ActionArea" class="row center">';
					html += '			<a id="okButton" href="#" class="btn positive ok-hide">확인</a>';
					html += '			<a id="cancelButton" href="#" class="btn neutral close">취소</a>';
					html += '		</div>';
					html += '		<div id="ApplyArea" class="row center" style="display:none">';
					html += '		</div>';
					html += '	</div>';
					html += '</div>';

					$('#loadMapPopup').dxPopup({
						width:600,
						height:680,
						visible:true,
						title: "지도 불러오기",
						contentTemplate: function(contentElement) {
							contentElement.append(html);
							var item = [
								{
									title : '불러오기'
								}, 
								{
									title : 'shp 사용'
								}
							];
							var tabPanel = $("#map_tabpanel").dxTabPanel({
								// height: 'calc(100% - 45px)',
						        selectedIndex: 0,
								dataSource: item,
								loop: false,
								animationEnabled: false,
						        swipeEnabled: true,
						        onSelectionChanged: function(e){

						        },
						        itemTemplate: function(data, index, element){
						        	console.log(data);
						        	var html = "";
						        	if(index == 0){
                                        html += "<div id='geojsonStateForm' style='margin:20px; margin-bottom:60px;'>";
                                        html += "</div>";
                                        html += "<div id='geojsonCityForm' style='margin:20px; margin-bottom:60px;'>";
                                        html += "</div>";
                                        html += "<div id='geojsonDongForm' style='margin:20px; margin-bottom:60px;'>";
                                        html += "</div>";
                                        
                                        element.append(html);
			            				          					            					            						            				
                                        setOptionForm('geojsonStateForm', "시도", index, disabledCheck(0), getFileList('state'), 0);
                                        setOptionForm('geojsonCityForm', "시군구", index, disabledCheck(1), getFileList('city'), 1);
                                        setOptionForm('geojsonDongForm', "읍면동", index, disabledCheck(2), getFileList('dong'), 2);
						        	}else{
						        		html += "<div id='shpStateForm' style='margin:20px; margin-bottom:60px;'>";
                                        html += "</div>";
                                        
                                        html += "</div>";
                                        html += "<div id='shpCityForm' style='margin:20px; margin-bottom:60px;'>";
                                        html += "</div>";
                                     
                                        html += "<div id='shpDongForm' style='margin:20px; margin-bottom:60px;'>";
                                        html += "</div>";
                                    
                                        for(var i=0; i<3; i++){                	
	                                        html += '					<form id="frm'+i+'" name="frm" enctype="multipart/form-data" accept-charset="UTF-8">';
	                        				html += '						<div class="layout-col">'
	                        	            html += '           			     <div class="modal-article">';
	                        	            html += '           			         <div id="shpButton'+i+'" class="file-ui" style="position:absolute;">'
	                        	            html += '									<input id="shpInput'+i+'" type="file" name=".shp" class="real-file" accept=".shp" hidden="hidden"/>';
	                        	            html += '									<input type="button" class="btn positive crud custom-button" value="SHP파일 선택" style="float:left;display:inline-block;overflow:hidden;text-align:center;border-radius:5px;vertical-align:top;"/>';
	                        	            html += '           	  		          	<span id="shpCaption'+i+'" class="custom-text" style="width:150px">파일을 선택 해주세요.</span>';
	                        	            html += '	        		            </div>';
	                        	            html += '							</div>';
	                        	            html += '  		   		     	</div>';
	                        	            html += '     			     	<div class="layout-col">';
	                        	            html += '							<div class="modal-article">';
	                        	            html += '								<div id="dbfButton'+i+'" class="file-ui" style="position:absolute;">';
	                        	            html += '									<input id="dbfInput'+i+'" type="file" name=".dbf" class="real-file" accept=".dbf"  hidden="hidden"/>';
	                        	            html += '									<input type="button" class="btn positive crud custom-button" value="DBF파일 선택" style="float:left;display:inline-block;overflow:hidden;text-align:center;border-radius:5px;vertical-align:top;"/>';
	                        	            html += '									<span id="dbfCaption'+i+'" class="custom-text"  style="width:150px">파일을 선택 해주세요.</span>';
	                        	            html += '								</div>';
	                        	            html += '							</div>';
	                        	            html += '						</div>';
	                        	            html += '					</form>';
                                        }
                                        
                                        html += "<div id='shpConfirmBtn'>";
                                        html += "</div>";
                                        // $(element).css("position",
										// "relative");
                                        element.append(html);
                                        $(element).parent().attr('style', 'margin-top:15px')
                                        
                                        // 파일선택 클릭
                                        fileEvent();
            			            	
                                        // 버튼 disable 처리
                                        var changeCheck = 0 ;
                                        for(var i=0; i<3; i++){
                                        	disabledShpFile(i);
                                        	if(!disabledCheck(i)){
                                        		$("#shpInput"+i).addClass('file-upload');
                                        		$("#dbfInput"+i).addClass('file-upload');
                                        		changeCheck += 2;
                                        	}
                                        }

                                        $(".file-upload").change(function(e){
                                        	
                                        	var check = true;
                                        	for(var i=0; i<changeCheck; i++){                                        		                                       		
                                    			if($(".file-upload")[i].value == ""){
                                                    check = false;
                                    			}                                       			                                        		
                                        	}

                                        	if(check)  $("#shpConfirmBtn").dxButton('instance').option('onClick')();
                                        })


                                        // 적용 클릭
                                        $("#shpConfirmBtn").dxButton({

        									text: "적용",
        									type: "normal",
        									elementAttr: {
        										id : "shpConfirmBtn"
        									},
        									visible: false,
        									onClick: function(e){     										
        										self.undisabledCheckCount();
        										
        										var noFileCheck = false;
        										self.fileMeta = [{},{},{}];
        										var items = [
        											{
        												title : "시도"
        											},
        											{
        												title : "시군구"
        											},
        											{
        												title : "읍면동"
        											}
        										];
        										
        										var fileIdx = -1;
        										for(var i=0; i<3; i++){
        											
        											if(!disabledCheck(i)){
        												var shpFile = document.getElementById('shpInput'+i).files[0];
            					            			var dbfFile = document.getElementById('dbfInput'+i).files[0];
            					            			var fileMeta = {
        					            						title : items[i]['title'],
        			            								shpFile : shpFile,
        			            								dbfFile : dbfFile
        					            				};
        					            				
        					            				self.fileMeta[i]=fileMeta
        					            				fileIdx++;
        					            				
            					            			if (!(shpFile && dbfFile)) {		            				
            					            				noFileCheck = true;
            					                        }
            					            			
            					            			if(!noFileCheck){
            					            				// setTimeout(self.convertGeoJson(shpFile,dbfFile),4000);
            					            				if(!shpFile || !dbfFile){
            					            					WISE.alert('파일을 선택하세요.','error');
            					            				}else{
            					            					setTimeout(self.convertGeoJson(fileMeta.shpFile, fileMeta.dbfFile, fileIdx, i),4000);
            					            				}
            					            			}
        											} 
        				            			}           										
        									}        								
                                        })	
            							           			                                                                     
                                        $("#shpButton0").css('top', '14px');
                                        $("#shpButton0").css('left', '106px');
                                        
                                        $("#dbfButton0").css('top', '14px');
                                        $("#dbfButton0").css('left', '340px');
                                        
                                        $("#shpButton1").css('top', '142px');
                                        $("#shpButton1").css('left', '106px');
                                        
                                        $("#dbfButton1").css('top', '142px');
                                        $("#dbfButton1").css('left', '340px');
                                        
                                        $("#shpButton2").css('top', '266px');
                                        $("#shpButton2").css('left', '106px');
                                        
                                        $("#dbfButton2").css('top', '266px');
                                        $("#dbfButton2").css('left', '340px');
                                        
                                        setOptionForm('shpStateForm', "시도", index, disabledCheck(0),'',0);
                                        setOptionForm('shpCityForm', "시군구", index, disabledCheck(1),'',1);
                                        setOptionForm('shpDongForm', "읍면동", index, disabledCheck(2),'',2);
						        	}
                                    
						        	confirmBtn();
						        	cancelBtn();
						        	
						        }
							})															
			            },
			            onContentReady: function() {
			            				            				            	
			            }
					})
				}else{
					WISE.alert('데이터 항목에 값을 넣어주세요.');	
				}
				
				break;
			}
			case 'lockNavigation':{
				if (!(self.dxItem)) {
					break;
				}

				var wheelCheck = self.dxItem.option('panningEnabled');
				if(wheelCheck == true || typeof wheelCheck == 'undefined'){
					self.dxItem.option('panningEnabled',false);
					self.dxItem.option('zoomingEnabled',false);
					self.LockNavigation=false
				}else{
					self.dxItem.option('panningEnabled',true);
					self.dxItem.option('zoomingEnabled',true);
					self.LockNavigation=true
				}

				break;
			}
			// edit tooltip value measure, precision and suffix
			case 'editTooltip': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				var mapping = {
					'없음': 'None',
					'인수': 'Argument',
					'값': 'Value',
					'%': 'Percent',
					'인수 및 값': 'ArgumentAndValue',
					'값 및 %': 'ValueAndPercent',
					'인수 및 %': 'ArgumentAndPercent',
					'인수, 값 및 %': 'ArgumentValueAndPercent',
					None: '없음',
					Argument: '인수',
					Value: '값',
					Percent: '%',
					ArgumentAndValue: '인수 및 값',
					ValueAndPercent: '값 및 %',
					ArgumentAndPercent: '인수 및 %',
					ArgumentValueAndPercent: '인수, 값 및 %',
					Auto: 'A',
					Ones: 'O',
					Thousands: 'K',
					Millions: 'M',
					Billions: 'B',
					A: 'Auto',
					O: 'Ones',
					K: 'Thousands',
					M: 'Millions',
					B: 'Billions'
				};
				p.option({
					title: '툴팁 편집',
					height: 706,
					width: 500,
					contentTemplate: function(contentElement) {
                        contentElement.append('<div id="' + self.itemid + '_tooltipForm">');
                        var html = 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);

						$('#' + self.itemid + '_tooltipForm').dxForm({
							dataSource: {
								'표기 형식': mapping[mapTooltipFormat.type],
								'단위': mapTooltipFormat.format,
								'사용자 지정 접두사': mapTooltipFormat.prefixEnabled,
								'접두사': mapTooltipFormat.prefixFormat,
								'사용자 지정 접미사': mapTooltipFormat.suffixEnabled,
								O: mapTooltipFormat.suffix.O,
								K: mapTooltipFormat.suffix.K,
								M: mapTooltipFormat.suffix.M,
								B: mapTooltipFormat.suffix.B,
								'정도': mapTooltipFormat.precision,
							},
							items: [
								{
									dataField: '표기 형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										dataSource: ['없음', '인수', '값', '%', '인수 및 값',
											 '값 및 %', '인수 및 %', '인수, 값 및 %'],
										value: mapping[mapTooltipFormat.type],
										onValueChanged: function(e) {
											if (e.value === '값' || e.value === '인수 및 값' || e.value === '값 및 %' || e.value === '인수, 값 및 %') {
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('단위').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접두사').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접미사').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도').option('disabled', false);
											} else {
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('단위').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접두사').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접미사').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도').option('disabled', true);
											}
										}
									}
								},
								{
										dataField: '단위',
										editorType: 'dxSelectBox',
										editorOptions: {
											dataSource: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
											layout: 'horizontal',
											value: mapping[mapTooltipFormat.format],
											onInitialized: function(e) {
												var formatType = mapping[mapTooltipFormat.type];
												if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
													e.component.option('disabled', false);
												} else {
													e.component.option('disabled', true);
												}
											}
										}
								},
								{
									dataField: '사용자 지정 접두사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: mapTooltipFormat.prefixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[mapTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										},
										onValueChanged: function(e) {
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: '접두사',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapTooltipFormat.prefixFormat,
										onInitialized: function(e) {
											var formatType = mapping[mapTooltipFormat.type];
											var prefixEnabled = mapTooltipFormat.prefixEnabled;
											
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
											//if (prefixEnabled) {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
											
											if(prefixEnabled){
												e.component.option('disabled', false);
											}else{
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '사용자 지정 접미사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: mapTooltipFormat.suffixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[mapTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										},
										onValueChanged: function(e) {
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('disabled', !e.value);
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('disabled', !e.value);
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('disabled', !e.value);
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: 'O',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapTooltipFormat.suffix.O,
										onInitialized: function(e) {
											var formatType = mapping[mapTooltipFormat.type];
											var suffixEnabled = mapTooltipFormat.suffixEnabled;
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %' || suffixEnabled) {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'K',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapTooltipFormat.suffix.K,
										onInitialized: function(e) {
											var formatType = mapping[mapTooltipFormat.type];
											var suffixEnabled = mapTooltipFormat.suffixEnabled;
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %' || suffixEnabled) {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'M',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapTooltipFormat.suffix.M,
										onInitialized: function(e) {
											var formatType = mapping[mapTooltipFormat.type];
											var suffixEnabled = mapTooltipFormat.suffixEnabled;
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %' || suffixEnabled) {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'B',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapTooltipFormat.suffix.B,
										onInitialized: function(e) {
											var formatType = mapping[mapTooltipFormat.type];
											var suffixEnabled = mapTooltipFormat.suffixEnabled;
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %' || suffixEnabled) {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
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
										value: mapTooltipFormat.precision,
										onInitialized: function(e) {
											var formatType = mapping[mapTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
							]
                        });

                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            // save tooltip settings
                            mapTooltipFormat.type = mapping[$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('표기 형식').option('value')];
							self.Map.TooltipContentType = mapTooltipFormat.type;
                            mapTooltipFormat.format = mapping[$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('단위').option('value')];
							self.Map.TooltipMeasureFormat = mapTooltipFormat.format;
							mapTooltipFormat.prefixEnabled = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접두사').option('value');
							self.Map.TooltipPrefixEnabled = mapTooltipFormat.prefixEnabled;
							mapTooltipFormat.prefixFormat = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('value');
							self.Map.TooltipPrefixFormat = mapTooltipFormat.prefixFormat;
							mapTooltipFormat.suffixEnabled = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접미사').option('value');
                            self.Map.TooltipSuffixEnabled = mapTooltipFormat.suffixEnabled;
							mapTooltipFormat.suffix.O = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('value');
							mapTooltipFormat.suffix.K = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('value');
							mapTooltipFormat.suffix.M = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('value');
							mapTooltipFormat.suffix.B = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('value');
							self.Map.TooltipSuffix = mapTooltipFormat.suffix;
							mapTooltipFormat.precision = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도').option('value');
                            self.Map.TooltipPrecision = mapTooltipFormat.precision;
                            // create new custom label format
							self.dxItem.option('tooltip.customizeTooltip', function(_pointInfo) {
								if(typeof self.getTooltipFormat(_pointInfo, mapTooltipFormat) == 'string'){
									return { text: self.getTooltipFormat(_pointInfo, mapTooltipFormat)};
								}else{
									return self.getTooltipFormat(_pointInfo, mapTooltipFormat);
								}


							});
                            p.hide();
						});
						contentElement.find('#close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			// 2020.11.27 mksong 코로플레스지도 레이블 표기 dogfoot
			case 'showLabel':{
//				if (!(self.dxItem)) {
//					break;
//				}
//				if(self.meta.MapLabel.Visible == true){
//					self.meta.MapLabel.Visible = false;
//					self.dxItem.option('layers[0].label.enabled',false);
//				}
//				else{
//					self.meta.MapLabel.Visible = true;
//					self.dxItem.option('layers[0].label.enabled',true);
//				}

				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				var mapping = {
					'없음': 'None',
					'인수': 'Argument',
					'값': 'Value',
					'%': 'Percent',
					'인수 및 값': 'ArgumentAndValue',
					'값 및 %': 'ValueAndPercent',
					'인수 및 %': 'ArgumentAndPercent',
					'인수, 값 및 %': 'ArgumentValueAndPercent',
					None: '없음',
					Argument: '인수',
					Value: '값',
					Percent: '%',
					ArgumentAndValue: '인수 및 값',
					ValueAndPercent: '값 및 %',
					ArgumentAndPercent: '인수 및 %',
					ArgumentValueAndPercent: '인수, 값 및 %',
					Auto: 'A',
					Ones: 'O',
					Thousands: 'K',
					Millions: 'M',
					Billions: 'B',
					A: 'Auto',
					O: 'Ones',
					K: 'Thousands',
					M: 'Millions',
					B: 'Billions'
				};
				p.option({
					title: '레이블 편집',
					height: 785,
					width: 500,
					contentTemplate: function(contentElement) {
                        contentElement.append('<div id="' + self.itemid + '_labelForm">');
                        var html = 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);

						$('#' + self.itemid + '_labelForm').dxForm({
							dataSource: {
								'표시 여부': self.labelOption.Visible,
								'표기 형식': mapping[self.labelOption.FormatType],
								'크기': self.labelOption.FontSize,
								'단위': self.labelOption.Unit,
								//dogfoot 지역 사용자 색상 지정 추가 20210707 syjin
								'색상 표시여부' : self.labelOption.ColorEnabled,
								'색상' : self.labelOption.Color,
								'사용자 지정 접두사': self.labelOption.PrefixEnabled,
								'접두사': self.labelOption.PrefixFormat,
								'사용자 지정 접미사': self.labelOption.SuffixEnabled,
								O: self.labelOption.Suffix.O,
								K: self.labelOption.Suffix.K,
								M: self.labelOption.Suffix.M,
								B: self.labelOption.Suffix.B,
								'정도': self.labelOption.Precision,
							},
							items: [
								{
									dataField: '표시 여부',
									editorType: 'dxCheckBox',
									editorOptions: {
										value : self.labelOption.Visible										
									}
								},
								{
									dataField: '표기 형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										dataSource: ['인수', '값', '%', '인수 및 값',
											 '값 및 %', '인수 및 %', '인수, 값 및 %'],
										value: mapping[self.labelOption.FormatType],
										onValueChanged: function(e) {
											if (e.value === '값' || e.value === '인수 및 값' || e.value === '값 및 %' || e.value === '인수, 값 및 %') {
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('단위').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접두사').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접미사').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도').option('disabled', false);
											} else {
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('단위').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접두사').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접미사').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도').option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '크기',
									editorType: 'dxNumberBox',
									editorOptions: {
										value : self.labelOption.FontSize
									}
								},
								{
										dataField: '단위',
										editorType: 'dxSelectBox',
										editorOptions: {
											dataSource: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
											layout: 'horizontal',
											value: mapping[self.labelOption.Unit],
											onInitialized: function(e) {
												var formatType = mapping[self.labelOption.FormatType];
												if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
													e.component.option('disabled', false);
												} else {
													e.component.option('disabled', true);
												}
											}
										}
								},
								//dogfoot 지역 사용자 색상 지정 추가 20210707 syjin
								{
									dataField: '색상 표시여부',
									editorType: 'dxCheckBox',
									editorOptions: {							
										value: self.labelOption.ColorEnabled,
										onValueChanged: function(e){
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('색상').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: '색상',
									editorType: 'dxColorBox',
									editorOptions: {							
										value: self.labelOption.Color,
										disabled: self.labelOption.ColorEnabled?false:true
									}
								},
								{
									dataField: '사용자 지정 접두사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: self.labelOption.PrefixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[self.labelOption.FormatType];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										},
										onValueChanged: function(e) {
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: '접두사',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.labelOption.PrefixFormat,
										onInitialized: function(e) {
											var formatType = mapping[self.labelOption.FormatType];
											var prefixEnabled = self.labelOption.PrefixEnabled;
											
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
											
											if(prefixEnabled){
												e.component.option('disabled', false);
											}else{
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '사용자 지정 접미사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: self.labelOption.SuffixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[self.labelOption.FormatType];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										},
										onValueChanged: function(e) {
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('disabled', !e.value);
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('disabled', !e.value);
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('disabled', !e.value);
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: 'O',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapping[self.labelOption.Suffix.O],
										onInitialized: function(e) {
											var formatType = mapping[self.labelOption.FormatType];
											var suffixEnabled = self.labelOption.SuffixEnabled;
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
											
											if(suffixEnabled){
												e.component.option('disabled', false);
											}else{
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'K',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapping[self.labelOption.Suffix.K],
										onInitialized: function(e) {
											var formatType = mapping[self.labelOption.FormatType];
											var suffixEnabled = self.labelOption.SuffixEnabled;
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
											
											if(suffixEnabled){
												e.component.option('disabled', false);
											}else{
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'M',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapping[self.labelOption.Suffix.M],
										onInitialized: function(e) {
											var formatType = mapping[self.labelOption.FormatType];
											var suffixEnabled = self.labelOption.SuffixEnabled;
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
											
											if(suffixEnabled){
												e.component.option('disabled', false);
											}else{
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'B',
									editorType: 'dxTextBox',
									editorOptions: {
										value: mapping[self.labelOption.Suffix.B],
										onInitialized: function(e) {
											var formatType = mapping[self.labelOption.FormatType];
											var suffixEnabled = self.labelOption.SuffixEnabled;
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
											
											if(suffixEnabled){
												e.component.option('disabled', false);
											}else{
												e.component.option('disabled', true);
											}
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
										value: mapping[self.labelOption.Precision],
										onInitialized: function(e) {
											var formatType = mapping[self.labelOption.FormatType];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
							]
                        });

                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            // save tooltip settings
							self.labelOption.Visible = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('표시 여부').option('value');
							self.labelOption.FontSize = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('크기').option('value');
                            self.labelOption.FormatType = mapping[$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('표기 형식').option('value')];
							//self.Map.TooltipContentType = mapTooltipFormat.type;
                            self.labelOption.Unit = mapping[$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('단위').option('value')];
							//self.Map.TooltipMeasureFormat = mapTooltipFormat.format;
                            //dogfoot 지역 사용자 색상 지정 추가 20210707 syjin
                            self.labelOption.ColorEnabled = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('색상 표시여부').option('value');
                            self.labelOption.Color = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('색상').option('value');
                            self.labelOption.PrefixEnabled = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접두사').option('value');
							//self.Map.TooltipPrefixEnabled = mapTooltipFormat.prefixEnabled;
                            self.labelOption.PrefixFormat = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('value');
							//self.Map.TooltipPrefixFormat = mapTooltipFormat.prefixFormat;
                            self.labelOption.SuffixEnabled = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접미사').option('value');
                            //self.Map.TooltipSuffixEnabled = mapTooltipFormat.suffixEnabled;
                            self.labelOption.Suffix.O = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('value');
                            self.labelOption.Suffix.K = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('value');
                            self.labelOption.Suffix.M = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('value');
                            self.labelOption.Suffix.B = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('value');
							//self.Map.TooltipSuffix = mapTooltipFormat.suffix;
							self.labelOption.Precision = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도').option('value');
                            //self.Map.TooltipPrecision = mapTooltipFormat.precision;
                            // create new custom label format
							
							self.dxItem.option('layers[0].customize')(self.dxItem.getLayers()[0].getElements());
							self.dxItem.option('layers[0].label.dataField', "");
							self.dxItem.option('layers[0].label.dataField', "labelHtml");
							self.dxItem.option('layers[0].label.font.size', self.labelOption.FontSize);
							self.dxItem.option('layers[0].label.enabled', self.labelOption.Visible);
							
//							self.dxItem.option('tooltip.customizeTooltip', function(_pointInfo) {
//								if(typeof self.getLabelFormat(_pointInfo, mapTooltipFormat) == 'string'){
//									return { text: self.getLabelFormat(_pointInfo, self.labelOption)};
//								}else{
//									return self.getLabelFormat(_pointInfo, self.labelOption);
//								}
//							});
							
                            p.hide();
						});
						contentElement.find('#close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
			
				break;
			}
			case 'Showlegend':{
				if (!(self.dxItem)) {
					break;
				}
				if(self.meta.MapLegend.Visible == true){
					self.meta.MapLegend.Visible = false;
					self.dxItem.option('legends',[]);
				}
				else{
					self.meta.MapLegend.Visible = true;
					self.dxItem.option('legends',
							[
								{
									horizontalAlignment: "left",
									orientation: "vertical",
									source:
									{
										grouping: "color",
										layer: "areaLayer"
									},
									verticalAlignment: "top",
									font: gDashboard.fontManager.getDxItemLabelFont(),
									customizeText:function(_arg){
										/* dogfoot 지도 범례 표기 형식 변경 shlim 20200617 */
										return _arg.start + ' ~ ';
// if(_arg.index == (areaLayer.palette.length-1)){
// return _arg.start + ' ~ ';
// }else{
// return _arg.start + ' ~ ' + (_arg.end - 1);
// }
									}
								}
							]
					);
				}
				break;
			}
			case 'setBackColor':{
				if (!(self.dxItem)) {
					break;
				}
				self.dxItem.option('background',{'borderColor': "white", 'color': "rgb(25,25,25)"});
				break;
			}
			case 'editPalette': {
				if (!(self.dxItem)) {
					break;
				}
				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet',
					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office'];
				// 2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 DOGFOOT
				var paletteCollection2 = ['밝음', '발광체', '바다', '파스텔', '부드러움', '연한 파스텔', '나무', '포도',
					'단색', '우주', '진보라', '안개숲', '연파랑', '기본값', '사무실 테마'];
				var paletteObject = {
						'Bright':'밝음',
						'Harmony Light':'발광체',
						'Ocean':'바다',
						'Pastel':'파스텔',
						'Soft':'부드러움',
						'Soft Pastel':'연한 파스텔',
						'Vintage':'나무',
						'Violet':'포도',
						'Carmine':'단색',
						'Dark Moon':'우주',
						'Dark Violet':'진보라',
						'Green Mist':'안개숲',
						'Soft Blue':'연파랑',
						'Material':'기본값',
						'Office':'사무실 테마',
						'Custom':'사용자 정의 테마',
					};
				var paletteObject2 = {
					'밝음':'Bright',
					'발광체':'Harmony Light',
					'바다':'Ocean',
					'파스텔':'Pastel',
					'부드러움':'Soft',
					'연한 파스텔':'Soft Pastel',
					'나무':'Vintage',
					'포도':'Violet',
					'단색':'Carmine',
					'우주':'Dark Moon',
					'진보라':'Dark Violet',
					'안개숲':'Green Mist',
					'연파랑':'Soft Blue',
					'기본값':'Material',
					'사무실 테마':'Office',
					'사용자 정의 테마':'Custom',
				};

				if (self.meta.Maps.ValueMap[0].CustomPalette != undefined){
					if(self.meta.Maps.ValueMap[0].CustomPalette.Color.length > 0) {
						paletteCollection.push('Custom');
						paletteCollection2.push('사용자 정의 테마');
					}
				}
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chagePalette = self.Map.Palette;
				p.option({
                    target: '#editPalette',
                    onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // create html layout
                        var html = 	'<div id="' + self.itemid + '_paletteBox"></div>' +                       			
								 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="save-ok" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="save-cancel" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        var select = $('#' + self.itemid + '_paletteBox');
                        // palette select
                        var originalPalette = paletteCollection.indexOf(self.Map.Palette) != -1
										? self.Map.Palette
										: 'Custom';
						select.dxSelectBox({
                            width: 400,
                            items: paletteCollection2,
                            itemTemplate: function(data) {
                                var html = $('<div />');
                                $('<p />').text(data).css({
                                    display: 'inline-block',
                                    float: 'left'
                                }).appendTo(html);

                                var colorArray = [];
                                if(data === '사용자 정의 테마'){
                                	$.each(self.meta.Maps.ValueMap[0].CustomPalette.Color,function(_i,_color){
     									if(typeof _color == 'string' && _color.indexOf('#') > -1){
     										colorArray.push(_color.toUpperCase());
     									}else{
     										colorArray.push(self.getHexColor(_color).toUpperCase());
     									}
     								});
                                }

                                var itemPalette = data === '사용자 정의 테마'
										? colorArray
										: DevExpress.viz.getPalette(paletteObject2[data]).simpleSet;
                                for (var i = 5; i >= 0; i--) {
                                    $('<div />').css({
                                        backgroundColor: itemPalette[i],
                                        height: 30,
                                        width: 30,
                                        display: 'inline-block',
                                        float: 'right'
                                    }).appendTo(html);
                                }
                                return html;
                            },
							value: paletteObject[originalPalette],							
							onValueChanged: function(e) {
								if (e.value == '사용자 정의 테마') {
                                    self.isCustomPalette = true;
                                    var colorArray = [];
                                	$.each(self.meta.Maps.ValueMap[0].CustomPalette.Color,function(_i,_color){
     									if(typeof _color == 'string' && _color.indexOf('#') > -1){
     										colorArray.push(_color.toUpperCase());
     									}else{
     										colorArray.push(self.getHexColor(_color).toUpperCase());
     									}
     								});
                                    self.dxItem.option('layers[0].palette', colorArray);
								} else {
                                    self.isCustomPalette = false;
                                    self.dxItem.option('layers[0].palette',paletteObject2[e.value]);
                                    // self.dxItem.option('palette',
									// paletteObject2[e.value]);
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.meta.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            // 2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝
							// DOGFOOT
                            self.meta.Maps.ValueMap[0].CustomType = "palette"
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	if(self.meta.Palette == 'Custom'){
                        		var colorArray = [];
                            	$.each(self.meta.Maps.ValueMap[0].CustomPalette.Color,function(_i,_color){
 									if(typeof _color == 'string' && _color.indexOf('#') > -1){
 										colorArray.push(_color.toUpperCase());
 									}else{
 										colorArray.push(self.getHexColor(_color).toUpperCase());
 									}
 								});
                        		self.dxItem.option('layers[0].palette', colorArray);
                        	}else{
                        		// self.dxItem.option('layers[0].palette',
								// self.meta.Palette);
                        		var value = $('#' + self.itemid + '_paletteBox').dxSelectBox('instance').option('value');
                        		if(value != "사용자 정의 테마"){
                        			if(typeof self.meta.Palette == "string"){
                        				self.dxItem.option('layers[0].palette', self.meta.Palette);
                        			}else{
                        				self.dxItem.option('layers[0].palette', self.beforePalette);
                        			}
                        		}else{
                        			if(typeof self.meta.Palette == "string"){
                        				self.dxItem.option('layers[0].palette', self.meta.Palette);	
                        			}
                        		}
                        	}
                            chagePalette = self.meta.Palette;
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.meta.Palette = chagePalette;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
			// set custom colors
			case 'customPalette': {
				if (!(self.dxItem)) {
					break;
				}
					/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
				var html = ""; 
				html += "<div class='modal-inner' style='max-height:none; min-height: auto;'>";
				html += 	"<div class='modal-body' style='height:100%;'>";
				html += 		"<div class='row' style='height:100%; align-items:center'>";
				html += 			"<div class='column' style='width:50%; height:50%;'>";
				html +=					"<div class='modal-article' style='height:100%;'>";
				html +=						"<div id='" + self.itemid + "_colorForm'/>";
				html +=						"<div style='text-align:center'>";
				html +=							"<div id='" + self.itemid + "_colorApply' style='margin-top:23px;'/>";
				html +=						"</div>";
				html +=					"</div>";
				html +=				"</div>";
				html += 			"<div class='column' style='width:50%; height:50%;'>";
				html +=					"<div class='modal-article' style='height:100%;'>";
				html +=						"<div id='" + self.itemid + "_colorPreView'/>";
				html +=					"</div>";
				html +=				"</div>";
				html +=			"</div>";
				html +=		"</div>";
				html += 	"<div class='modal-footer' style='padding-top:15px;'>";
				html += 		"<div class='row center'>";
				html +=				"<a id='" + self.itemid + "btn_tabpanel_ok' class='btn positive ok-hide'>확인</a>";
				html +=				"<a id='" + self.itemid + "btn_tabpanel_close' class='btn neutral close'>취소</a>";
				html +=			"</div>";
				html += 	"</div>";				
				html +=	"</div>";
				
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '색상 편집',
					width: '900px',
					height: '580px',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						contentElement.append(html);
						
						//paletteArray 비어 있을 때 초기화(기본값일 때)
						if(self.editPaletteOption.paletteRangeArray.length == 0){
							self.editPaletteOption.paletteRangeArray = self.getPaletteRange(self.editPaletteOption.valueType, self.editPaletteOption.labelCount);
							self.editPaletteOption.paletteArray = self.getPaletteArray(self.editPaletteOption.paletteName, self.editPaletteOption.valueType, self.editPaletteOption.paletteRangeArray);	//팔레트 네임, 그룹필드, 그룹 배열, 반환값
						}
							
						var colorDataSource = [];
						
						for(var i=0; i<self.editPaletteOption.paletteRangeArray.length-1; i++){
							var colorDataSourceObject = {
									"범위" : self.editPaletteOption.paletteRangeArray[i],
									"색상" : self.editPaletteOption.paletteArray[i]
							}
							colorDataSource.push(colorDataSourceObject);
						}
						
						//색상편집
						self.setColorForm(self.itemid + "_colorForm");	//id
						//미리보기
						self.setColorPreView(self.itemid + "_colorPreView", colorDataSource);	//id, dataSource
						//적용버튼
						self.setColorApply(self.itemid + "_colorApply");
						//확인버튼
						self.paletteConfirm(p);
						//취소버튼
						self.paletteCancel(p);
						
						self.dxItem.option('legends[0].visible', true);
					}
				});
				p.show();
				break;
			}
		}
	};

	// 객체에서 null 등의 빈값 제거 yyb 2021-03-09
	this.removeEmpty = function(obj) {
	  Object.keys(obj).forEach(function(key) {
	    if (obj[key] && typeof obj[key] === 'object') {
			self.removeEmpty(obj[key]);
		}
	    else if (obj[key] == null || obj[key] == 'undefined' || obj[key] == '') {
			delete obj[key];
		}
	  });
	};

	this.convertGeoJson = function(shpFile,dbfFile,index,fileIdx){
		gProgressbar.show();
		var shpreader = new FileReader();
		shpreader.onload = (function(that, callback){
            return function(e){
            	gProgressbar.show();
            	self.shpFilemeta = e.target.result;
            	self.shpF[fileIdx] = e.target.result;
            	var dbfreader = new FileReader();
	        	dbfreader.onload = (function(that){
		            return function(e){
		            	self.dbfFilemeta = e.target.result;
		            	self.dbfF[fileIdx] = e.target.result;
		            	// var parseSources = { shp: self.shpFilemeta, dbf:
						// self.dbfFilemeta};
		            	var parseSources = { shp: self.shpF[fileIdx], dbf: self.dbfF[fileIdx]};
		            	self.parseSources.push(parseSources);
					    parseOptions = { precision: 2 };
					    data = DevExpress.viz.vectormaputils.parse(parseSources, parseOptions);

						/*
						 * yyb 2021-03-09 저장된 json 파일에 null등의 빈값이 있으면 제대로 불러오지
						 * 못하는 버그가 있어 만들때 처리함
						 */
						self.removeEmpty(data);
						
						var dataFeatures = data.features;
                        var selectFeatures = [];
                        
						var param = {'fileName':shpFile.name,'geojson':data, 'index':fileIdx};

						$.ajax({
                    	   cache: false,
          	               url: WISE.Constants.context + '/report/uploadGeoJSON.do',
          	               async:false,
          	               data: JSON.stringify(param),
          	               contentType: "application/json",
          	               type: 'POST',
          	               success: function(result){
// alert("geojson 업로드 성공!!");
        	                   var form = $('#frm'+index)[0];
		            	       var formData = new FormData(form);
        	                   $.ajax({
	            	               cache: false,
	            	               url: WISE.Constants.context + '/report/uploadSHP.do',
	            	               async:false,
	            	               processData: false,
	            	               contentType: false,
	            	               data: formData,
	            	               type: 'POST',
	            	               success: function(result){
	            	                   gProgressbar.hide();
	            	                   var coulmnHead = new Array();

	            	                   $.each(data.features["0"].properties,function(_i,_field){
	            	                	   coulmnHead.push(_i);
	            	                   });
	            	                   
	            	                   var dirName = '';
	            	                   if(fileIdx == 0){
	            	                	   $("#shpStateForm").dxForm('instance').option('items[1].editorOptions.items', coulmnHead);
	            	                	   dirName = 'state';
	            	                   }else if(fileIdx == 1){
	            	                	   $("#shpCityForm").dxForm('instance').option('items[1].editorOptions.items', coulmnHead);
	            	                	   dirName = 'city';
	            	                   }else{
	            	                	   $("#shpDongForm").dxForm('instance').option('items[1].editorOptions.items', coulmnHead);
	            	                	   dirName = 'dong';
	            	                   }
	            	                   // $('#ActionArea').css('display','none');
	            	                   // $('#popUpRedraw'+index).dxLookup('instance').option('dataSource',coulmnHead);
	            	                   var featuresArray = [];
	            	                   $.each(data.features,function(_i,_features){
	            	                	   var obj = _features.properties;
	            	                	   featuresArray.push(obj);
	            	                   });
	            	                   // $('#shpAttrPreview'+index).dxDataGrid('instance').option('dataSource',featuresArray);
	            	                  // $('#shpAttrPreview'+index).dxDataGrid('instance').option('paging.pageSize',5);
	            	                   
// if(index == 0){
// $('#ApplyArea').css('display','block')
// $('#ApplyArea').append("<a id='applyOK' class='btn positive ok-hide'
// href='#'>적용</a>");
// $('#applyOK').dxButton({
// text: "확인",
// type: "default",
// onClick:function(){
// if(self.attrName != ""){
// $('#loadMapPopup').dxPopup('hide');
// $('#loadMapPopup').remove();
// self.ShapefileArea = "Custom";
//							            				
// // dogfoot 지도 범위, 지도 파일
// // 변수 배열 처리 20210519
// // syjin dogfoot
// self.ViewArea['area'] = [];
// self.CustomUrl = [];
//							            				
// for(var i=0; i<self.fileMeta.length; i++){
// self.ViewArea['area'].push(self.fileMeta[i]['viewArea']);
// self.CustomUrl.push(self.fileMeta[i]['customUrl']);
// }
// }
// }
// });
// }
	            	                   
	            	                   self.fileMeta[fileIdx].data = data;
	            	                   self.fileMeta[fileIdx].customUrl = {'Url': WISE.Constants.context+'/UploadFiles/geojson/'+dirName+'/'+(shpFile.name).replace('.shp','.geojson')};
            	                	   self.fileMeta[fileIdx].viewArea = {
		            	                		'BottomLatitude': data.bbox[1],
					            				'TopLatitude':  data.bbox[3],
					            				'LeftLongitude':  data.bbox[0],
					            				'RightLongitude':  data.bbox[2],
					            				'CenterPointLatitude': (data.bbox[1] + data.bbox[3])/2,
				            					'CenterPointLongitude': (data.bbox[0] + data.bbox[2])/2,
		            	               }
            	                	   
            	                	   gProgressbar.hide();
	            	               },
	            	               error:function(error){
	            	            	   console.log(error);
	            	            	   WISE.alert('error'+ajax_error_message(error),'error');
	            	               }
	            	           });
        	               },
        	               error:function(error){
        	            	   console.log(error);
        	            	   WISE.alert('error'+ajax_error_message(error),'error');
        	               }
                       });
						
						// if(index+1 <
						// self.fieldManager.panelManager.mapParameterContentPanel1.children().length)
						// if(fileIdx+1 < self.undisabledCheckCount)
						// callback(self.fileMeta[fileIdx+1].shpFile,
						// self.fileMeta[fileIdx+1].dbfFile, index+1);
		            }
			    })(this);
	        	dbfreader.readAsArrayBuffer(dbfFile);
            }
	    })(this, self.convertGeoJson);
    	shpreader.readAsArrayBuffer(shpFile);
    	
    	
	}
};
WISE.libs.Dashboard.ChoroplethMapFieldManager = function() {
	var self = this;

	this.initialized = false;
	this.alreadyFindOutMeta = false;

	// 검색 - searchDisable
	this.searchDisable = false;
	// 검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	// 검색

	this.dataItemNo=0;

	this.meta;
	this.isChange = false; // 사용자가 필드를 변경했는지 여부 체크
	this.columnMeta = {}; // 쿼리된 모든 컬럼정보 저장
	this.isColumnChooser = false;

	this.all = [];
	this.values = [];
	this.arguments = [];
	this.series = [];
// this.hide_column_list_dim = [];
// this.hide_column_list_mea = [];

	this.tables = [];

	this.palette;
	this.CustomScale = {};
	this.CustomPalette =  {};
	/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
	this.CustomColorSet;

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
		this.arguments = [];
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
		this.DataItems = {};
		self.DataItems['Dimension'] = [];
		self.DataItems['Measure'] = [];
		var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};

		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
// dataItem['DataMember'] = $(_fieldlist[i]).children().get(0).innerText;
// dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				if (self.seriesType === 'Bubble') {
					dataItem['ColoringMode'] = 'Hue';
				}
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
// dataItem['DataMember'] = $(_fieldlist[i]).children().get(0).innerText;
// dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
// dataItem['NumericFormat'] = NumericFormat;
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = NumericFormat;
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};

	this.setValuesByField = function(_values){
		this.Values = {'ValueMap' : []};
		_.each(_values,function(_v){
			var Value = {'UniqueName' : _v.uniqueName};
			if(self.CustomScale.RangeStop != undefined){
				/* dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616 */
				self.Values['ValueMap'].push({'Value':Value,'UniformScale': "",'CustomScale':self.CustomScale,'CustomPalette':self.CustomPalette,'CustomColorSet':self.CustomColorSet});
			}else{
				self.Values['ValueMap'].push({'Value':Value,'UniformScale': ""});
			}
		});
		return self.Values;
	};

// this.setSeriesDimensionsByField = function(_series){
// this.SeriesDimensions = {'SeriesDimension' : []};
// _.each(_series,function(_s){
// var Value = {'UniqueName' : _s.uniqueName};
// self.SeriesDimensions['SeriesDimension'].push(Value);
// })
// return self.SeriesDimensions;
// };
	
// 2021.04.28 syjin 코로플레스 attributeDimension 수정 dogfoot
// this.setArgumentsByField = function(_argument){
// this.attributeDimension = {};
// // _.each(_argument,function(_a){
// /*dogfoot 코로플레스 맵 안그려지는 오류 수정 shlim 20200612*/
// var Value = {'UniqueName' : _argument[0].uniqueName};
// // self.Arguments['Argument'].push(Value);
// self.attributeDimension = Value;
// // })
// return self.attributeDimension;
// };
	
	this.setArgumentsByField = function(_argument){
		this.attributeDimension = [];
		_.each(_argument,function(_a){
			/* dogfoot 코로플레스 맵 안그려지는 오류 수정 shlim 20200612 */
			var Value = {'UniqueName' : _a.uniqueName};
			// self.Arguments['Argument'].push(Value);
			self.attributeDimension.push(Value);
		})
		return self.attributeDimension;
	};
};
