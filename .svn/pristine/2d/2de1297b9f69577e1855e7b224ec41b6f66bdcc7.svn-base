/**
 * Manage and calcuate custom field inputs.
 */
WISE.libs.Dashboard.CustomParameterHandler = function() {
	var self = this;
	this.calcParameterInformation = {};
	this.tempCalcParam = {};
	this.selectedCalcItem = {};
	this.preParamCaptionList = [];
	
	this.utility = WISE.libs.Dashboard.item.DatasetUtility;
	
	/**
	 * 1. 사용자 정의 데이터 매개변수 초기화
	 */
	this.init = function(){
		self.selectedCalcItem = {};
		self.preParamCaptionList = [];
		self.tempCalcParam = this.cloneObject(self.calcParameterInformation);
		this.editCalcFilter();
		this.initCalcParamInformation("calcParamItemDescArea");
	}
	
	/**
	 * 1. 매개변수 초기 화면 설정
	 */
	this.initCalcParamInformation = function(_targetId,_paramItem){
		
		$('#'+_targetId).empty();
		var html = "";
		html +="<div id='calcParamInfoSetting' style='height:auto;'></div>";
		html +="<div id='calcParamShowing'></div>";
		html +="<div id='calcParamTypeSetting' style='height:auto;width:95%;float:left;display:none'></div>";
		$('#'+_targetId).append(html);
		html = '';
		html += '<div id="calcNameArea" style="width:100%;height:20%;float:left;margin-bottom:10px"></div>';
		html += '<div id="calcCaptionArea" style="width:100%;height:20%;float:left;margin-bottom:10px"></div>';
//		html += '<div id="calcDataTypeArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
//		html += '<div id="calcEtcArea" style="width:100%;height:20%;float:left;padding:5px"></div>'
		$('#calcParamInfoSetting').append(html);
		html ='';
		html += '<div id="calcParamNameArea" style="width:70%;float:left;"></div>';
//		html += '<div id="warning" style="width:50%;float:left;padding-left:10px;">* 매개변수 명은 영문으로 설정하세요</div>';
		html += '<div id="calcWarning" style="width:30%;float:left;padding-left:10px;"></div>';
		$('#calcNameArea').append(html);
		
		html = '';
		html += '<div id="calcParamCaptionArea" style="width:70%;float:left;"></div>';
		$('#calcCaptionArea').append(html);
		
//		html = '';
//		html += '<div id="dataTypeListArea" style="width:70%;float:left;"></div>';
//		html += '<div id="dataBindingArea" style="width:30%;float:left;padding-left:10px;"><div id="dataBind"  style="padding: 8px 15px 9px 0;"></div></div>';

//		html += '<div id="dataEditArea" style="width:50%;float:left;padding-left:10px;"><div id="dataEdit"  style="padding: 8px 15px 9px 0;"></div></div>';
		
//		$('#dataTypeArea').append(html);
		
//		html = '';
//		html += '<div id="paramTypeListArea" style="width:50%;float:left;"></div>';
////		html += '<div id="paramDelArea" style="width:50%;float:left;padding-left:10px;"><div id="paramDelYN"  style="padding: 8px 15px 9px 0;"></div></div>';
//		$('#paramTypeArea').append(html);
		
//		html = '';
//		html += '<div id="calcParamETCAreaA" style="width:60%;float:left;">';
//		html += '<div id="calcOrderArea" style="width:45%;float:left;"></div><div id="calcWidthArea" style="width:45%;float:right;"></div>';
//		html += '</div>';
//		html += '<div id="calcParamETCAreaB" style="width:30%;float:left;margin-left:30px;">';
//		html += '<div id="calcVisibleArea" style="width:45%;float:left;"><div id="calcVisibleYN" style="padding: 8px 15px 9px 0;"/></div>';
//		html += '<div id="conditionArea" style="width:45%;float:left;"></div>';
//		html += '</div>';
//		$('#calcEtcArea').append(html);
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 명</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcParamName"></div>';
		html += '</div>';
		html += '</div>';
		$('#calcParamNameArea').append(html);
		$('#calcParamName').dxTextBox({
			/*dogfoot 매개변수명 변경  오류 수정 shlim 20200625*/
			//readOnly:true
		});
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 Caption *</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcParamCaption"></div>';
		html += '</div>';
		html += '</div>';
		$('#calcParamCaptionArea').append(html);
		$('#calcParamCaption').dxTextBox();
		
		
//		html = '';
//		html += '<div class="dx-field">';
//		html += '<div class="dx-field-label">순서</div>';
//		html += '<div class="dx-field-value">';
//		html += '<div id="calcOrderInput"></div>';
//		html += '</div>';
//		html += '</div>';
//		$('#calcOrderArea').append(html);
//		$('#calcOrderInput').dxNumberBox({
//			showSpinButtons: true
//		});
		
//		html = '';
//		html += '<div class="dx-field">';
//		html += '<div class="dx-field-label">넓이</div>';
//		html += '<div class="dx-field-value">';
//		html += '<div id="calcWidthInput"></div>';
//		html += '</div>';
//		html += '</div>';
//		$('#calcWidthArea').append(html);
//		$('#calcWidthInput').dxNumberBox({
//			showSpinButtons: true
//		});
//		
//		html = '';
//		
//		$('#calcVisibleYN').dxCheckBox({text:'Visible'});
		
		html = '';	
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 기본값</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcDefaultValue"></div>';
		html += '</div>';
		html += '</div>';
		
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">슬라이드 정도</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcSlideValue"></div>';
		html += '</div>';
		html += '</div>';
		
		html += '<div style="width:100%">';
		html += '<div style="width:45%;float:left;">';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">최소값</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcSlideMinValue"></div>';
		html += '</div>';
		html += '</div>';
		html += '</div>';
		
		html += '<div style="width:45%;float:right;">';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">최대값</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcSlideMaxValue"></div>';
		html += '</div>';
		html += '</div>';
		html += '</div>';
		html += '</div>';
		
		$('#calcParamTypeSetting').append(html);
		
		/* DOGFOOT ktkang 필터 선택 변경시 기본 값 부분이 초기화 되는 현상 수정  20200205*/
		var defaultVal = '';
		if(_paramItem){
			defaultVal = _paramItem.DEFAULT_VALUE;
		}else{
			defaultVal = '';
		}
		$('#calcDefaultValue').dxTextArea({
			value: defaultVal
		});
		
		$('#calcSlideValue').dxNumberBox({
			showSpinButtons: true
		});
		
		$('#calcSlideMinValue').dxNumberBox({
			showSpinButtons: true
		});
		
		$('#calcSlideMaxValue').dxNumberBox({
			showSpinButtons: true
		});
		
		$('#calcParamTypeSetting').css('display','block');
	
	};
	
	/**
	 * 1. 사용자 정의 데이터 매개변수 리스트 생성 및 설정
	 */
	this.editCalcFilter = function(){
		
		var calcParamArray = self.getArrayCalcParamInfomation();
		var selectedCalcItem;
		
		$('#paramCalcListArea').dxDataGrid({
    		dataSource: calcParamArray,
    		columns:[
    			{
		            dataField: "PARAM_NM",
		            caption:"매개변수 명",
		            alignment:"center",
    			},
    			{
		            dataField: "PARAM_CAPTION",
		            caption:"매개변수 캡션",
		            alignment:"center",
    			},
//    			{
//		            dataField: "ORDER",
//		            caption:"순서",
//		            alignment:"center",
//    			},
    		],
            selection: {
                mode: "single"
            },
            onSelectionChanged:function(_e){
            	
            	if(typeof selectedCalcItem != 'undefined'){
            		if(selectedCalcItem.PARAM_CAPTION != $('#calcParamCaption').dxTextBox('instance').option('value')){
						self.preParamCaptionList.push({'newParamCaption':$('#calcParamCaption').dxTextBox('instance').option('value'),'preParamCaption' : selectedCalcItem.PARAM_CAPTION})
					}
					if(self.checkParamNm(selectedCalcItem.PARAM_NM,$('#calcParamName').dxTextBox('instance').option('value'))){
						selectedCalcItem.PARAM_NM = $('#calcParamName').dxTextBox('instance').option('value');
					}else{
						$('#calcParamName').dxTextBox('instance').option('value',selectedCalcItem.PARAM_NM);
						$('#paramCalcListArea').dxDataGrid('selectRowsByIndexes',0)
						WISE.alert('매개변수 명은 중복 될수 없습니다.')
						return false;
					}
            		
            		selectedCalcItem.UNI_NM = $('#calcParamName').dxTextBox('instance').option('value');
            		selectedCalcItem.PARAM_CAPTION = $('#calcParamCaption').dxTextBox('instance').option('value');
//            		selectedCalcItem.ORDER = $('#calcOrderInput').dxNumberBox('instance').option('value');
//            		selectedCalcItem.WIDTH = $('#calcWidthInput').dxNumberBox('instance').option('value');
//            		selectedCalcItem.VISIBLE = $('#calcVisibleYN').dxCheckBox('instance').option('value') ? 'Y':'N';
            		selectedCalcItem.DEFAULT_VALUE = $('#calcDefaultValue').dxTextArea('instance').option('value') ? $('#calcDefaultValue').dxTextArea('instance').option('value'):"";
            		selectedCalcItem.SET_VALUE = $('#calcDefaultValue').dxTextArea('instance').option('value') ? $('#calcDefaultValue').dxTextArea('instance').option('value'):"";
            		selectedCalcItem.SLIDER_POINT = $('#calcSlideValue').dxNumberBox('instance').option('value');
            		selectedCalcItem.SLIDER_MIN = $('#calcSlideMinValue').dxNumberBox('instance').option('value');
            		selectedCalcItem.SLIDER_MAX = $('#calcSlideMaxValue').dxNumberBox('instance').option('value');
            		
            	//alert(_e);	
	            	
            	}
            	
            	if(_e.selectedRowsData[0]){
            	    self.selectedCalcItem = selectedCalcItem = _e.selectedRowsData[0];
            	    self.setCalcParamInfo(_e.selectedRowsData[0]);
            	}else{
            		self.initCalcParamInformation("calcParamItemDescArea");
            	}
            	
                $('#paramCalcListArea').dxDataGrid("instance").option('dataSource', self.getArrayCalcParamInfomation());

            	$('#removeCalcParam').dxButton({
    				icon: "close",
        			onClick:function(){
        				delete self.tempCalcParam[selectedCalcItem.PARAM_NM];
        				self.initCalcParamInformation("calcParamItemDescArea");
        				$('#paramCalcListArea').dxDataGrid("instance").option('dataSource', self.getArrayCalcParamInfomation());
//        				$('#paramCalcListArea').dxDataGrid('selectRowsByIndexes',self.getArrayCalcParamInfomation().length-1)
        			}
        		});
    		},
    		onContentReady:function(_e){
    			
    			
    			$('#addCalcParam').dxButton({
    				icon: "plus",
        			onClick:function(){
        				var newParamItem = gDashboard.customParameterHandler.addCalcParamItem();
        				
        				if(self.getArrayCalcParamInfomation().length <= 1){
        					self.setCalcParamInfo(newParamItem);
        				}
        				$('#paramCalcListArea').dxDataGrid("instance").option('dataSource', self.getArrayCalcParamInfomation());
        			}
        		});
    			//

    		}
    	}).dxDataGrid("instance");
		///$('#paramCalcListArea').dxDataGrid('selectRowsByIndexes',0)
		$('#paramCalcListArea').dxDataGrid("instance").clearSelection()
	}
	
	/**
	 * 1. 사용자 정의 데이터 매개변수 리스트 선택시 우측 매개변수 설정 부분 변경
	 */
	this.setCalcParamInfo = function(_paramItem){
		$('#calcParamName').dxTextBox('instance').option('value',_paramItem['PARAM_NM'] && _paramItem['PARAM_NM'] != "" ? _paramItem['PARAM_NM'] : "");
		$('#calcParamCaption').dxTextBox('instance').option('value',_paramItem['PARAM_CAPTION'] && _paramItem['PARAM_CAPTION'] != "" ? _paramItem['PARAM_CAPTION']:"");
		
//		$('#calcOrderInput').dxNumberBox('instance').option('value',_paramItem['ORDER'] && _paramItem['ORDER'] !="" ? _paramItem['ORDER']:0);
//		$('#calcWidthInput').dxNumberBox('instance').option('value',_paramItem['WIDTH'] && _paramItem['WIDTH'] !=""? _paramItem['WIDTH']:0);
//		$('#calcVisibleYN').dxCheckBox('instance').option('value',_paramItem['VISIBLE'] == 'Y'? true:false);
		
		$('#calcDefaultValue').dxTextArea('instance').option('value',_paramItem['DEFAULT_VALUE'] != undefined && _paramItem['DEFAULT_VALUE'] != "" ? _paramItem['DEFAULT_VALUE']:"1");
		
		$('#calcSlideValue').dxNumberBox('instance').option('value',_paramItem['SLIDER_POINT'] && _paramItem['SLIDER_POINT'] !=""? _paramItem['SLIDER_POINT']:0);
		$('#calcSlideMinValue').dxNumberBox('instance').option('value',_paramItem['SLIDER_MIN'] && _paramItem['SLIDER_MIN'] !=""? _paramItem['SLIDER_MIN']:0);
		$('#calcSlideMaxValue').dxNumberBox('instance').option('value',_paramItem['SLIDER_MAX'] && _paramItem['SLIDER_MAX'] !=""? _paramItem['SLIDER_MAX']:0);
	};
	
	/**
	 * 1. 사용자 정의 데이터 매개변수 리스트 가져오기
	 */
	this.getArrayCalcParamInfomation = function(_getList){
		var calcParamArray = [];
		if(Object.keys(self.tempCalcParam).length > 0){
			$.each(self.tempCalcParam,function(_i,_items){
				calcParamArray.push(_items);
			});
		}else if(Object.keys(self.calcParameterInformation).length > 0){
			$.each(self.calcParameterInformation,function(_i,_items){
				calcParamArray.push(_items);
			});
		}
		return calcParamArray;
	}

	this.getArrayUseCalcParam = function(_getList){
		var calcParamArray = [];
		if(Object.keys(self.calcParameterInformation).length > 0){
			$.each(gDashboard.customFieldManager.fieldInfo,function(_keys,_filed){
				$.each(_filed,function(_i,_fieldIdx){
					$.each(self.calcParameterInformation,function(_i,_items){
						if(_fieldIdx.Expression.indexOf('['+ _items.PARAM_CAPTION+']') > -1){
							calcParamArray.push(_items);
						}
					});
				})
			})
		}
		return calcParamArray;
	}
	
	/**
	 * 1. 사용자 정의 데이터 매개변수 리스트 값 선언
	 */
	this.setArrayCalcParamInfomation = function(){
		self.calcParameterInformation = {};
		$.each(self.getArrayCalcParamInfomation(),function(_i,_paramItem){
            self.calcParameterInformation[_paramItem.PARAM_NM] = _paramItem
		})
	}
	
	/**
	 * 1. 사용자 정의 데이터 매개변수 화면 필터 리스트 설정
	 */
	this.setCalcFilterList = function(_targetId){
		$("#"+_targetId).empty();
		
		var html = "";
		
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcParamList" style="height:auto;"></div>';
		html += '</div>';
		html += '</div>';
		
		html += '<div class="dx-field" style="margin-top:10px">';
		html += '<div class="dx-field-label">입력 값</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcValInput"></div>';
		html += '</div>';
		html += '</div>';

		html += '<div class="dx-field">';
		html += '<div>';
		html += '<div id="calcValSlider"></div>';
		html += '</div>';
		html += '</div>';
		
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">창 유지</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="calcViewOption"></div>';
		html += '</div>';
		html += '</div>';

		html += '<div class="modal-footer" style="padding-top:15px;">' + 
					'<div class="row center">' + 
						'<a class="btn positive calcList-ok-hide">조회</a>' + 
						'<a class="btn neutral calcList-close">닫기</a>' +
					'</div>' + 
				'</div>';
		$('#'+_targetId).append(html);
		
		var preSelectedItem,preSetValue,preVislble;
	

		$("#calcParamList").dxSelectBox({
	        dataSource: new DevExpress.data.ArrayStore({
	            data: self.getArrayUseCalcParam(),
	            key: "PARAM_NM"
	        }),
	        displayExpr: "PARAM_CAPTION",
	        valueExpr: "PARAM_NM",
	        value: self.getArrayCalcParamInfomation()[0].PARAM_NM,
	        onSelectionChanged: function (_e) {
	        	
                if(preSelectedItem != undefined){
                	self.calcParameterInformation[preSelectedItem.PARAM_NM].SET_VALUE = $("#calcValInput").dxNumberBox("instance").option("value");
                	preSetValue = $("#calcValInput").dxNumberBox("instance").option("value");
                }

				var handlerSlider = $("#calcValSlider").dxSlider({
					min: _e.selectedItem.SLIDER_MIN,
					max: _e.selectedItem.SLIDER_MAX,
					value: _e.selectedItem.SET_VALUE,
					step: self.getNumberUnit(_e.selectedItem.SLIDER_POINT),
					onValueChanged: function(data) {
						sliderValue.option("value", data.value);
					},
					tooltip: {
						enabled: true
					}
				}).dxSlider("instance");

				var sliderValue = $("#calcValInput").dxNumberBox({
					value: _e.selectedItem.SET_VALUE,
					min: _e.selectedItem.SLIDER_MIN,
					max: _e.selectedItem.SLIDER_MAX,
					step: self.getNumberUnit(_e.selectedItem.SLIDER_POINT),
					showSpinButtons: true,
					onValueChanged: function(data) {
						handlerSlider.option("value", data.value);
						preSetValue = data.value;
					}
				}).dxNumberBox("instance");

				var visibleVal = $('#calcViewOption').dxCheckBox({
			        value: _e.selectedItem.VISIBLE == 'Y' ? true:false,
			        onValueChanged: function(data) {
						preVislble = data.value ? 'Y':'N';
					}
			    });

                preSelectedItem = _e.selectedItem
                preSetValue = _e.selectedItem.SET_VALUE;
                preVislble = _e.selectedItem.VISIBLE;
                
//	        	sliderValue.option("value",_e.selectedItem.SET_VALUE)
//	        	sliderValue.option("min",_e.selectedItem.SLIDER_MIN)
//	        	sliderValue.option("max",_e.selectedItem.SLIDER_MAX)
//	        	sliderValue.option("step",self.getNumberUnit(_e.selectedItem.SLIDER_POINT))
//                
//              handlerSlider.option("value",_e.selectedItem.SET_VALUE)
//	        	handlerSlider.option("min",_e.selectedItem.SLIDER_MIN)
//	        	handlerSlider.option("max",_e.selectedItem.SLIDER_MAX)
//	        	handlerSlider.option("step",self.getNumberUnit(_e.selectedItem.SLIDER_POINT))
	        },
	        
	    });

        $('#editPopover').dxPopover('instance').option("onHiding",function(_e){
        	self.calcParameterInformation[preSelectedItem.PARAM_NM].SET_VALUE = preSetValue;
        	self.calcParameterInformation[preSelectedItem.PARAM_NM].VISIBLE = preVislble;
        })
		//onHiding    
		$('a.calcList-ok-hide').on('click', function() {

			self.calcParameterInformation[preSelectedItem.PARAM_NM].SET_VALUE = $("#calcValInput").dxNumberBox("instance").option("value");        
			self.calcParameterInformation[preSelectedItem.PARAM_NM].VISIBLE = $("#calcViewOption").dxCheckBox("instance").option("value") ? "Y":"N";
			gDashboard.query();	
			
			if(!$("#calcViewOption").dxCheckBox("instance").option("value")){
			    $('#editPopover').dxPopover('instance').hide();
			}
			
			//
		});
        
        $('a.calcList-close').on('click', function() {
			$('#editPopover').dxPopover('instance').hide();
		});
        
        
	}
	
	/**
	 * 1. 화면 필터 버튼 생성자
	 */
	this.setCalcFilterButton = function(_fields,setfilter){
		var useCalcParamYn = false;
		self.tempCalcParam = {};
		$.each(gDashboard.customFieldManager.fieldInfo,function(_keys,_filed){
			$.each(_filed,function(_i,_fieldIdx){
				$.each(self.getArrayCalcParamInfomation(),function(_j,_info){
					if(_fieldIdx.Expression.indexOf('['+ _info.PARAM_CAPTION+']') > -1){
						useCalcParamYn = true;
					}
				})
			})
		})
		
		
		if(useCalcParamYn){
			$('#calcParamButton').dxButton({
				text:"사용자 정의 매개변수",
				onClick:function(){
					self.openCalcFilterPopup();
					self.setCalcFilterList("calcFilterList");
				},
			});
			$('#calcParamButton').css("display","block");
		}else{
			$('#calcParamButton').css("display","none");
		}
	}
	
	/**
	 * 1. 필터버튼 선택시 리스트 팝업창 생성자
	 */
	this.openCalcFilterPopup = function(){
		$('#editPopover').dxPopover({
			target: '#calcParamButton',
			width: 300,
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForEditText('editPopover');
			},
			contentTemplate: function(contentElement) {
                contentElement.empty();
				contentElement.append('<div id="calcFilterList">');
			},
			closeOnOutsideClick: false,
		});
		var p = $('#editPopover').dxPopover('instance');
		
		p.option('visible', !(p.option('visible')));
	}
	
	/**
	 * 사용자 정의 데이터 매개변수 추가 동작
	 */
	this.addCalcParamItem = function(){
//		self.tempCalcParam = {
//				/* DOGFOOT ktkang 주제영역 필터 올릴 때 데이터 타입 설정  20200309 */
//					DS_ID: ds_id,
//					DS_TYPE: 'DS',
//					PARAM_TYPE: paramType,
//					DATASRC_TYPE: "TBL",
//					DATASRC: tableNm,
//					/* DOGFOOT ktkang KERIS 년도, 년월일 때 기본값 오늘기준으로 자동 입력   20200228 */
//					DEFAULT_VALUE: defaultValue,
//					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
//					ORDER: Object.keys(gDashboard.parameterFilterBar.parameterInformation).length + 1,
//					PARAM_CAPTION:,
//					PARAM_NM: "@",
//					VISIBLE: "Y",
//					WHERE_CLAUSE: tableNm + '.' + cubeParamInfo.physicalColumnKey,
//					WIDTH: 250,
//					WISE_CUBE_UNI_NM :
//				};
		
		var newWhereClause = {
			PARAM_CAPTION: self.utility.getCalcParamId(self.tempCalcParam),
			PARAM_NM: "@" + self.utility.getCalcParamId(self.tempCalcParam),
			UNI_NM: "@" + self.utility.getCalcParamId(self.tempCalcParam),
            VISIBLE: "Y",
            ORDER:0,
            WIDTH: 250,
            SLIDER_POINT:0,
			SLIDER_MIN:0,
			SLIDER_MAX:100,
            DEFAULT_VALUE: "1",
            SET_VALUE:"1",
            CALC_PARAM_YN:"Y",
        };
		self.tempCalcParam[newWhereClause.PARAM_NM] = newWhereClause;
		return newWhereClause;
	}
	
	/**
	 * 1. 사용자 정의 데이터 매개변수 설정 후 확인 시 마지막 셋팅값 저장
	 * 2. 계산식의 매개변수 캡션명이 변경된 사용자 정의 매개변수 명칭 수정
	 */
	this.setCalcParaminfomation = function(){
        
       
    	if(typeof self.selectedCalcItem != 'undefined'){
			if(self.selectedCalcItem.PARAM_CAPTION != $('#calcParamCaption').dxTextBox('instance').option('value')){
				self.preParamCaptionList.push({'newParamCaption':$('#calcParamCaption').dxTextBox('instance').option('value'),'preParamCaption' : self.selectedCalcItem.PARAM_CAPTION})
			}
            if(self.checkParamNm(self.selectedCalcItem.PARAM_NM,$('#calcParamName').dxTextBox('instance').option('value'))){
                self.selectedCalcItem.PARAM_NM = $('#calcParamName').dxTextBox('instance').option('value');	
            }else{
            	$('#calcParamName').dxTextBox('instance').option('value',self.selectedCalcItem.PARAM_NM);
				WISE.alert('매개변수 명은 중복 될수 없습니다.')
				return false;
			}
			self.selectedCalcItem.UNI_NM = $('#calcParamName').dxTextBox('instance').option('value');
			self.selectedCalcItem.PARAM_CAPTION = $('#calcParamCaption').dxTextBox('instance').option('value');
//			self.selectedCalcItem.ORDER = $('#calcOrderInput').dxNumberBox('instance').option('value');
//			self.selectedCalcItem.WIDTH = $('#calcWidthInput').dxNumberBox('instance').option('value');
//			self.selectedCalcItem.VISIBLE = $('#calcVisibleYN').dxCheckBox('instance').option('value') ? 'Y':'N';
			self.selectedCalcItem.DEFAULT_VALUE = $('#calcDefaultValue').dxTextArea('instance').option('value') ? $('#calcDefaultValue').dxTextArea('instance').option('value'):"";
			self.selectedCalcItem.SET_VALUE = $('#calcDefaultValue').dxTextArea('instance').option('value') ? $('#calcDefaultValue').dxTextArea('instance').option('value'):"";
			self.selectedCalcItem.SLIDER_POINT = $('#calcSlideValue').dxNumberBox('instance').option('value');
			self.selectedCalcItem.SLIDER_MIN = $('#calcSlideMinValue').dxNumberBox('instance').option('value');
			self.selectedCalcItem.SLIDER_MAX = $('#calcSlideMaxValue').dxNumberBox('instance').option('value');
		    //alert(_e);	
		}
    	
        var duplicateParmaNm = self.checkParamNm();
         
        if(duplicateParmaNm){
			if(self.preParamCaptionList.length > 0){

				var textArea = $('#calcTextArea').val()
				$.each(self.preParamCaptionList,function(_i,_changeFiled){
					if(textArea.indexOf('['+_changeFiled.preParamCaption+']') > -1){
						textArea = textArea.replace('['+_changeFiled.preParamCaption+']','['+_changeFiled.newParamCaption+']')
					}
				})
				$('#calcTextArea').val(textArea);
			}
			$('.select-type')[0].click();

			self.setArrayCalcParamInfomation();

			return true;
        }else{
        	return false;
        }
		
	}
	
	/**
	 * 1. 사용자 정의 데이터 매개변수명 설정 시 기존 필터와 중복되지 않도록 체크
	 */
	this.checkParamNm = function(_preParam,_newParam){
		var returnVal = true;
		if(Object.keys(self.tempCalcParam).length > 0){
			$.each(self.tempCalcParam,function(_i,_calcItem){
				$.each(gDashboard.datasetMaster.state.params,function(_i,_paramItem){
					if(_calcItem.PARAM_NM === _paramItem.PARAM_NM){
						returnVal = false;
					}
				});
			});
            
            if(_preParam != undefined && _newParam != ""){
				if(self.tempCalcParam[_newParam].PARAM_NM != _preParam){
					returnVal = false;
				}	
            }    
		}
		return returnVal;
	};
	
	/**
	 * 1. object 복사
	 */
	this.cloneObject = function(obj) {
		return JSON.parse(JSON.stringify(obj));
	}
	
	/**
	 * 1. 슬라이드 정도 값 가져오기
	 */
	this.getNumberUnit = function(_value){
		var returnNum = "0."
		if(_value > 0){
		    for(var i = 0; i < _value-1; i++){
                returnNum += "0"
		    }
		    returnNum += "1"	
		}else{
			returnNum = 1
		}
		
		return parseFloat(returnNum);
	}
	
	/**
	 * 1. 뷰어 용 사용자 정의 매개변수 선언자
	 */
	this.setState = function(state) {
        self.calcParameterInformation = {};
        $.each(state.params,function(_i,_paramItem){
            self.calcParameterInformation[_paramItem.PARAM_NM] = _paramItem
		})   
    };
}