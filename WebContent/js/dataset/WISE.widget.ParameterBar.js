/**
 * 매개변수 필터바 컴포넌트 클래스
 * Parameter bar component class.
 */
WISE.libs.Dashboard.ParameterBar = function() {
    var self = this;
    
    this.parameterInformation = {};
    this.parameterQueryHandler;
    this.totalConditionWidth = 0;
    
    this.utility = WISE.libs.Dashboard.item.DatasetUtility;
    
    /* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
    this.state = {
        element: null,
        params: [],
        fields: {},
        paramValues: {},
        listValues: {},
        onQuery: function() {},
        isDownloadExpand: false
    };
	
	/* 2020.12.18 mksong 주택금융공사 연결필터 오류 수정 dogfoot */
	this.linkedFilterObject = {};
	//2020.12.30 MKSONG 매개변수 중복 데이터 조회 오류 수정 DOGFOOT
	this.initParamList = [];
	
    /**
     * Update component state.
     * @param {object} state
     * @param {string} action
     */
    this.setState = function(state, action) {
        switch (action) {
            case 'LIST_VALUES':
                $.extend(self.state.listValues, state);
                break;
            case 'PARAM_VALUES':
                $.extend(self.state.paramValues, state);
                break;
            default:
                $.extend(self.state, state);
        }
    };

    /**
     * Renders dataset designer component.
     * @param props { element: HTMLElement, params: object[], fields: object, paramValues: object, onQuery: function }
     */
     /*dogfoot shlim 20210420*/
    this.render = function(props,_addFilterCheck) {
        self.setState(props);
        /*dogfoot shlim 20210420*/
       if(!_addFilterCheck){
		    self.setState({ paramValues: self.utility.generateNewParamValues(self.state.params)});
       }
        
		/* 2020.12.18 mksong 주택금융공사 연결필터 오류 수정 dogfoot */
		$.each(self.state.params,function(_i,_param){
			$.each(_param.wiseVariables,function(_k,_variable){
				if(_variable.indexOf('@') != -1){
					if(self.linkedFilterObject[_variable] == undefined){
						self.linkedFilterObject[_variable] = [];
					}
					
					//2020.12.30 MKSONG 매개변수 중복 데이터 조회 오류 수정 DOGFOOT
					if(self.linkedFilterObject[_variable].indexOf(_param.PARAM_NM) < 0){
						self.linkedFilterObject[_variable].push(_param.PARAM_NM);	
					}
				}	
			})
		});
		/*dogfoot shlim 20210420*/
		if(_addFilterCheck){
			generateFieldsToAdd(_.sortBy(self.state.params, 'ORDER'));
			self.resize2();
        }else{
        	self.state.element.empty();
			generateFields(_.sortBy(self.state.params, 'ORDER'));
			self.resize2();
        }
//        self.state.element.empty();
//        generateFields(_.sortBy(self.state.params, 'ORDER'));
//        self.resize2();
    };

    /**
     * Return a modified version of state's param values with key values instead of caption values.
     */
    this.getKeyParamValues = function() {
    	var paramValues = _.cloneDeep(self.state.paramValues);
    	$.each(paramValues, function(nm, value) {
    		/* goyong ktkang 비트윈 리스트 오류 수정  20210527 */
    		var betweenString = nm.slice(-3);
    		if(betweenString == '_fr' || betweenString == '_to') {
    			nm = nm.substring(0, nm.length-3);
    		}
    		var keyValuePair = self.state.listValues[nm];
    		if (keyValuePair) {
    			for (var i = 0; i < value.value.length; i++) {
    				for (var j = 0; j < keyValuePair.length; j++) {
    					/*dogfoot 리스트 필터 쿼리일때 key caption 명 다르면 못찾는 오류 수정 shlim 20200728*/
    					if( typeof keyValuePair[j].CAPTION_VALUE === 'undefined'){
    						if (value.value[i] === keyValuePair[j][value.captionName]) {
    							value.value[i] = keyValuePair[j][value.keyName];
    							break;
    						}
    					}else {
    						if (value.value[i] === keyValuePair[j].CAPTION_VALUE) {
    							value.value[i] = keyValuePair[j].KEY_VALUE;
    							break;
    						}
    					}
    				}
    			}
    		}
    	});
    	return paramValues;
    }

    /**
     * Add responsive styling to parameter bar.
     */
    this.resize2 = function() {
        $('.filter-bar').css('height', 'auto');
        $('.filter.filter-more').css('display','block');
        containerBoxUi();
        /*dogfoot shlim 20210420*/
        if(WISE.Constants.editmode != "viewer"){
        	if(Object.keys(gDashboard.goldenLayoutManager).length != 0){
        		gDashboard.goldenLayoutManager.render_config_layout();	
            }
        }else{
        	if(gDashboard.goldenLayoutManager[WISE.Constants.pid]){
        	    if(Object.keys(gDashboard.goldenLayoutManager[WISE.Constants.pid]).length != 0){
					gDashboard.goldenLayoutManager[WISE.Constants.pid].render_config_layout();	
				}	
        	}
        }
    }
    
    this.resize = function() {
		$('#contentContainer').removeClass('double').removeClass('triple');
		$('.filter-item').removeClass('double').removeClass('triple');
		$('#btn_query').removeClass('double').removeClass('triple');
		var page = window.location.pathname.split('/');
//		if (page[page.length - 1] != 'viewer.do') {
//			$('#contentContainer').css('top',$('#wrap').height());
//		}
//		var tcw = (this.totalConditionWidth + 15 + 40)/2;
		
//		if(self.totalConditionWidth === 0){
		self.totalConditionWidth = 0;
			$.each($('.filter-item .condition-item-container'), function(i, el){
			/*dogfoot shlim 20210415*/
				if($(el).parent().find('.line-break').length>0){
				    self.totalConditionWidth += $('.line-break').width(); 	
				}
				self.totalConditionWidth += $(el).width(); 
			});
//		}
		/*dogfoot shlim 20210702*/
		var tcw = (this.totalConditionWidth + 15 + 90);
		

		// DOGFOOT 20200206 cshan - 필터 접기 & 펼치기 기능에 대상 영역의 사이즈를 잘못 지정하는 오류 수정
//		if (tcw > $(document).width() - $('#btn_query').width()-250) {
//			var divide = parseInt(tcw / ($(document).width() - $('#btn_query').width()-250),10);
//		if (tcw > $(document).width() - $('#btn_query').width()-$('#btn_query').outerWidth()) {
//			var divide = parseInt(tcw / ($(document).width() - $('#btn_query').width()-$('#btn_query').outerWidth()),10);
		if (tcw > $('.filter-item').width() /*- $('#btn_query').width()-$('#btn_query').outerWidth()*/) {
		var divide = parseInt(tcw / ($('.filter-item').width()/* - $('#btn_query').width()-$('#btn_query').outerWidth()*/),10);
			
			if (page[page.length - 1] != 'viewer.do') {
				$('.filter-bar').css('height', 'auto');
				$('.filter-more').css('opacity','1');/*dogfoot shlim 20210415*/
			}else{
				$('.filter-more').css('display','block');
				// 2019.12.10 수정자 : mksong 뷰어 필터 아이콘 view DOGFOOT
				$('.filter-gui').css('display','block');
				$('.filter-more').css('opacity','1');/*dogfoot shlim 20210415*/
			}
			//20211123 [산림청] syjin 필터 기본적으로 펼치게 수정 dogfoot
			$('.filter-bar').addClass('on');
			$('.filter.filter-more').css('display','block');
//			$('div#someDiv').css('height', null);
			switch(divide) {
			case 1: // double
				$('#contentContainer').addClass('double');
				$('.filter-item').addClass('double');
				$('#btn_query').addClass('double');
				break;
			case 2:
				$('#contentContainer').addClass('triple');
				$('.filter-item').addClass('triple');
				$('#btn_query').addClass('triple');
				break;
			default:
				$('#contentContainer').addClass('triple');
				$('.filter-item').addClass('triple');
				$('#btn_query').addClass('triple');
				break;
			}
		}
		else {
			$('article').removeClass('double').removeClass('triple');
			$('.filter-item').removeClass('double').removeClass('triple');
//			$('.filter.filter-more').css('display','none');
			$('.filter.filter-more').css('opacity','0');/*dogfoot shlim 20210415*/
//			if (page[page.length - 1] == 'viewer.do') {
//				$('.filter-more').css('display','none');
//				/* DOGFOOT mksong 필터 css 수정 20200210 */
//				$('.filter-bar').css('height','40px');
//			}else{
			if(!gDashboard.reportUtility.lc){
//				$('.filter-bar').css('height','40px');
				$('.filter-bar').css('height', userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+'px');
				/*dogfoot 뷰어 폴더리스트 css 오류 수정 shlim 20210507*/
				$('.panel-tab .tree-area').css("margin-top", userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+'px')
			}else{
				if(gDashboard.reportUtility.lc.FILTER_HEIGHT_SETTING!=""){
					$("#filter-bar").css({
						"max-height" : "1000px",
						"height" : gDashboard.reportUtility.lc.FILTER_HEIGHT_SETTING+"px"
					});
					$("#report-filter-item").css({
						"display" : "flex",
						"align-items" : "center"
					})
				}
			}
//			}
			
		}
		
		$.each($('.condition-item .dx-texteditor-input'), function(_i, _o) {
			var paramid = $(_o).parent().parent().attr('id');
			var popoverid = paramid + '_popover';
			var containerHeight = 29;
			/* DOGFOOT ktkang 뷰어에서 보고서 목록 열 때 리스트 필터 깨지는 오류 수정  20200110 */
			var leftOffset = $(_o).offset().left;
			var windowWidth = window.innerWidth || document.body.clientWidth;
			windowWidth = windowWidth - 300;
			var leftVal;
			
			if(leftOffset > windowWidth) {
				leftVal = windowWidth - 200;
			} else {
				leftVal = leftOffset;
			}
			$('#' + popoverid+'_space')
				.css('top',($(_o).offset().top + containerHeight) + 'px')
				.css('left', (leftVal + 'px'));
		});
		// 20200730 ajkim 디자이너 모드에서 필터 펼칠 때 아이템 밀리는 오류 수정 dogfoot
		// 202000805 shlim 스프레드시트 팝업창 오류 수정 goldenLayoutManager 없음 dogfoot
		if(WISE.Constants.editmode == "designer"){
            if(gDashboard.goldenLayoutManager.canvasLayout){
	            /*dogfoot 필터 영역 리사이즈시 차트 부분 레이아웃 오류 수정 shlim 20200824*/
            	gDashboard.goldenLayoutManager.render_config_layout();
                $('.panel.cont').css('height', 'calc(100vh - ' + (84 + ($('.filter-bar').height() < 40? 40 : $('.filter-bar').height())) + 'px)')
                gDashboard.goldenLayoutManager.canvasLayout.updateSize($('.panel.cont').width());
            
                /* DOGFOOT 20201021 ajkim setTimeout 시간 변경 300 > 10*/
                setTimeout(function(){
                    $.each($('.lm_item'), function(i, ele){
                        var h = WISE.Constants.editmode !== 'viewer'? $(ele).height() - $(ele).find('.lm_header').height() : $(ele).height() - $(ele).find('.lm_header').height() - 10;

                    	$(ele).find('.lm_items').height(h);
        		         $(ele).find('.lm_item_container').height(h);
        		         $(ele).find('.lm_content').height(h);
                    })
                    gDashboard.goldenLayoutManager.resize();
                }, 10)
            }
            gDashboard.goldenLayoutManager.render_config_layout();
            gDashboard.goldenLayoutManager.resize();
		}
	};
    
    this.setParameterInformation = function(_information) {
		try {
			var parameterList = _information;
			if (parameterList) {
//				if(this.parameterInformation.length == 0 || $.isEmptyObject(this.parameterInformation) == true){
				/* DOGFOOT ktkang 뷰어에서 디자이너 이동 후 필터 추가하면 기존 필터 사라지는 오류 수정  20200818 */
				if(Array.isArray(this.parameterInformation) && this.parameterInformation.length != 0){
					this.parameterInformation = {};
				}
				if($.isEmptyObject(this.parameterInformation) == true){
					
					$.each(parameterList, function(_i, _param) {
						if(_param == undefined)return;
						var paramId = _param.UNI_NM == undefined ? _param.PARAM_NM : _param.UNI_NM;
						self.parameterInformation[paramId] = _param;
					});
				}else{
					$.each(parameterList, function(_i, _param) {
						if(_param == undefined)return;
						var paramId = _param.UNI_NM == undefined ? _param.PARAM_NM : _param.UNI_NM;
						self.parameterInformation[paramId] = _param;
					});
				}
				
			}
		} catch (e) {
			this.parameterInformation = {};
			WISE.libs.Dashboard.MessageHandler.error({status: 500, msg: 'error occured while set parameter-set information - ' + e.toString()});
		}
	};
	
	/* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 오류 수정  20200731 */
	this.drawParameterDeleteButton = function(_paramId, _o, _$paramContainer) {		
		if(_o.EDIT_YN == 'N') return;		
		//cube 타입일때만 삭제가능
		/* DOGFOOT ktkang 뷰어에서는 필터 삭제 불가하도록 수정   20210112 */
		var page = window.location.pathname.split('/');
		/* DOGFOOT syjin 단일 테이블 일 때, 필터 삭제 버튼 추가  20210309 */
		/*dogfoot shlim 20210415*/
		/*dogfoot shlim 20210420*/
		/* DOGFOOT syjin 뷰어에서 매개변수편집 삭제 유무 활성화  20211126 */
		//if((WISE.Context.isCubeReport || gDashboard.dataSourceManager.datasetInformation.dataSource1.DATASRC_TYPE === "DS")&& (page[page.length - 1] === 'edit.do' || _o.ADD_FILTER)) {
		if((WISE.Context.isCubeReport || gDashboard.dataSourceManager.datasetInformation.dataSource1.DATASRC_TYPE === "DS")&& (page[page.length - 1] === 'edit.do' || _o.ADD_FILTER || _o.EDIT_YN == 'Y')) {
			var filterRemoveText = gMessage.get('WISE.message.page.widget.filter.remove');
			_$paramContainer.find('.wise-area-icon-filter-remove').remove();
			
			$('<div class="wise-area-icon-filter-remove" title="' + filterRemoveText + '"></div>')
				.on('click', function() {
					var index = -1;
					$.each(self.state.params,function(_i,_param){
						if (_param.PARAM_NM == _paramId) {
							index = _i;
							return false;
						}
    				});
							 	                
					if (index != -1) {
						/*dogfoot shlim 20210420*/
                        var removeParamNm=""
						$.each(self.state.fields,function(_paramnm,_param){
							if (_paramnm == _paramId) {
								removeParamNm = _paramnm;
								return false;
							}
						});
						if(removeParamNm !=""){
						    delete self.state.fields[removeParamNm];	
						}

						removeParamNm="";
						$.each(self.state.paramValues,function(_paramnm,_param){
							if (_paramnm == _paramId) {
								removeParamNm = _paramnm;
								return false;
								/* DOGFOOT ktkang 고용정보원09  비트윈필터 삭제 오류 수정  */
							} else if(_paramnm == _paramId + '_fr') {
								removeParamNm = _paramnm;
								return false;
							}
						});
						if(removeParamNm !=""){
							/* DOGFOOT ktkang 고용정보원09  비트윈필터 삭제 오류 수정  */
							if(removeParamNm.indexOf('_fr') > -1) {
								delete self.state.paramValues[removeParamNm];
								removeParamNm = removeParamNm.replace('_fr', '_to');
								delete self.state.paramValues[removeParamNm];
							} else {
								delete self.state.paramValues[removeParamNm];
							}
						}
        				delete gDashboard.parameterFilterBar.parameterInformation[_o.UNI_NM];
        				var paramList = [];
        				gDashboard.structure.ReportMasterInfo.paramJson = [];
        				/* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 오류 수정  20200819 */
        				Object.keys(gDashboard.parameterFilterBar.parameterInformation).map(function(_items, _i) {
        					paramList.push(gDashboard.parameterFilterBar.parameterInformation[_items]);
        					gDashboard.structure.ReportMasterInfo.paramJson.push(gDashboard.parameterFilterBar.parameterInformation[_items]);
        				});
						/*dogfoot shlim 20210415*/
        				var reportInfo = gDashboard.structure.ReportMasterInfo;
                        /*dogfoot shlim 20210420*/
                        
        				/* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 오류 수정  20200709 */
        				var paramTest = gDashboard.datasetMaster.utility.getParamArray(gDashboard.structure.ReportMasterInfo.paramJson);
        				gDashboard.datasetMaster.setState({ params: paramTest });
        				var filterBarElement;
        				switch (WISE.Constants.editmode) {
        				case 'designer':
    						filterBarElement = $('#report-filter-item');
        					break;
        				/*dogfoot shlim 20210415*/
        				case 'viewer':
    						filterBarElement = gDashboard.viewerParameterBars[reportInfo.id].state.element;
        					break;
        				default:
        					filterBarElement = $('.filter-item');
        				}
        				/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
        				
    					if(self.state.isDownloadExpand)
    						filterBarElement = $('#report-filter-item-de');
    					
    					//필터 삭제시 잔상 남는 오류 수정
//        				gDashboard.parameterFilterBar.render({
//        					element: filterBarElement,
//        					params: gDashboard.datasetMaster.state.params
//        				},true);/*dogfoot shlim 20210420*/
						
						$(this).parent().remove();
						$('#'+ $(this).parent()[0].children[1].id +'_popover_space').hide(); 
						self.resize();		
										
						if(gDashboard.dataSourceManager.datasetInformation.dataSource1.DATASRC_TYPE == "DS"){
							/* DOGFOOT syjin 필터 예외처리 20210311 */
							if((gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY.indexOf("WHERE") > -1) &&(gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY.indexOf("WHERE")>-1)){
								gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY = gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY.substr(0,gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY.indexOf("WHERE"));
								gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY = gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY.substr(0,gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY.indexOf("WHERE"));
							}
							/* DOGFOOT syjin 단일 테이블 일 때, 필터 삭제 시 sql문 오류 수정  20210311 */
							if(paramList.length > 1){	
							    $.each(paramList, function(_i, _v){
							    	if(_i == 0){
							    		gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY =  gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY + " WHERE A.\"" + _v.PARAM_CAPTION + "\" IN ("+_v.PARAM_NM + ")";
								        gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY =  gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY + " WHERE A." + _v.PARAM_CAPTION + " IN (" +_v.PARAM_NM + ")";
							    	}else{
							    		gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY =  gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY + " AND A.\"" + _v.PARAM_CAPTION + "\" IN (" +_v.PARAM_NM + ")";
							    		gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY =  gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY + " AND A." + _v.PARAM_CAPTION + " IN (" +_v.PARAM_NM + ")";
							    	}
							    })
		                    }else if(paramList.length == 1){
		                    	$.each(paramList, function(_i, _v){
		                    		gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY =  gDashboard.datasetMaster.state.datasets.dataSource1.DATASET_QUERY + " WHERE A.\"" + _v.PARAM_CAPTION + "\" IN ("+_v.PARAM_NM + ")";
							        gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY =  gDashboard.datasetMaster.state.datasets.dataSource1.SQL_QUERY + " WHERE A." + _v.PARAM_CAPTION + " IN (" +_v.PARAM_NM + ")";
		                    	})                 	
		                    } 
						}			
					}			
				})
				.on('mouseenter', function() {
					$(this).prev().addClass('dx-state-focused');
				})
				.on('mouseleave', function() {
					$(this).prev().removeClass('dx-state-focused');
				})
				.appendTo(_$paramContainer);/*dogfoot 주제영역 필터 올릴시 제거 버튼 뒤에 붙도록 수정 shlim 20200824*/
		}
	};
	
	this.toggleParameter = function(_reportId){
		var filterContainer = $('.filter-row').children('.filter-item');
		$.each(filterContainer,function(_i,_e){
			if($(_e).attr('report_id') == _reportId){
				$(_e).css('display','inline-block');
			}else{
				$(_e).css('display','none');
			}
		});
		/* DOGFOOT ktkang 뷰어에서 보고서 여러개 열었을 때 오류 수정  20200805 */
		var parameterArray = [];
		$.each(gDashboard.totalConditionBuffer,function(_i,_e){
			if(_e.reportId == _reportId){
				self.totalConditionWidth = _e.totalConditionWidth;
				self.parameterQueryHandler = _e.parameterQueryHandler;
				parameterArray.push(_e.param);
			} 
		});
		self.resize();
		
//		$.each(this.parameterInformation, function(_k, _o) {parameterArray.push(_o);});
		parameterArray.sort(function(_a, _b) {return _a['ORDER'] - _b['ORDER'];});
		if(self.parameterQueryHandler)
			self.parameterQueryHandler.setDataSourceInformations(parameterArray);
//		self.parameterQueryHandler.queryAll(); // 조회 조건을 갖고 있지 않은 조건만 조회	
		
	};
    /**
     * Event handler for field components. Update state with changed values.
     * @param {string} fieldId 
     * @param {string[]} value 
     */
    function onValueChange(fieldId, value) {
        if (typeof value === 'string') {
            // convert string value into array
            value = value.split(',');
        }
        // remove trailing white spaces
        /* DOGFOOT ktkang 필터 값이 number로 넘어 올 때 에러 수정  20200701 */
        if (typeof value === 'array') {
        	value = _.map(value, function(v) { 
        		if(typeof v === 'number') {
        			return v; 
        		} else {
//        			return v.trim(); 
        			return v; 
        		}
        	});
        }
        
        if (typeof value === 'object') {
        	value = _.map(value, function(v, i) { 
        	/* DOGFOOT ajkim Between 전체 오류 수정 20210222*/
        		if(v === '전체')
        			return '_ALL_VALUE_';
        		if(typeof v === 'number') {
        			return v; 
        		} else {
//        			return v.trim(); 
        			return v; 
        		}
        	});
        }
        /* DOGFOOT ktkang 기본값이 숫자로 들어올 때 오류 수정  20200702 */
        if ((typeof value != 'number') && (value.length === 0 || value[0].length === 0)) {
            value = ['_EMPTY_VALUE_'];
        }
        var paramValueObj = _.clone(self.state.paramValues[fieldId]);
        var newState = {};
        paramValueObj.value = value;

        paramValueObj.betweenCalendarValue = value[0];
        newState[fieldId] = paramValueObj;

      	self.setState(newState, 'PARAM_VALUES');
        self.state.onQuery(newState);
        /*dogfoot shlim 20210414*/
        if(paramValueObj.operation == "Between"){
        	/*dogfoot between 연계 필터 to 필터 만들고 실행하도록 수정 shlim 20210427*/
        	/*dogfoot shlim 20210430*/
//        	if(fieldId.indexOf("_to") > -1){
        		    fieldId = paramValueObj.orgParamName
//			}
        }
		/* 2020.12.18 mksong 주택금융공사 연결필터 오류 수정 dogfoot */
		//2020.12.30 MKSONG 매개변수 중복 데이터 조회 오류 수정 DOGFOOT
		if(self.initParamList.length == 0){
			$.each(self.linkedFilterObject[fieldId], function(_i, _linkedParam){
				$.each(self.state.params, function(i, param) {
					if(_linkedParam == param.PARAM_NM){
						if(param.PARAM_TYPE.indexOf('LIST') !== -1 && param.DATASRC_TYPE === 'QUERY') {
			                var listParams = param.DATASRC.match(/@\S*/g);
			                var listParamsArray = [];
							$.each(listParams, function(_i, _e) {
								listParamsArray.push(_e.toString().replace(/\)/g, ''))
							});
							listParamsArray = _.uniq(listParamsArray);
			                /* DOGFOOT ktkang 매개변수 명이 한글 일 때 처리  20200706 */
			                if (listParamsArray && listParamsArray.indexOf(fieldId) !== -1) {
			                	/* DOGFOOT ktkang 전체 일 때 전체로 나오지 않던 오류 수정  20200702 */
			                	var totalSeletion;
			                	if(param.ALL_YN==='Y' && param.MULTI_SEL === 'N') {
			                		totalSeletion = true;
			                	}
			                	
			                    if (param.PARAM_TYPE === 'LIST') {
			                   		/*dogfoot USE_SCRIPT Y 일때 기본값 돌리는 과정 추가 shlim 20200708*/
			                    	var defaultValue;
			                    	if(!(param.DEFAULT_VALUE_USE_SQL_SCRIPT ==='Y')){
			                    		if(!Array.isArray(param.DEFAULT_VALUE)) {
					                    	if(param.DEFAULT_VALUE.toString().toUpperCase()=='[ALL]') {
					                    		defaultValue = "_ALL_";
					                    	}else if(param.DEFAULT_VALUE == ''){
					                    		defaultValue = "_ALL_";
				                            }
										}else{
											if(param.DEFAULT_VALUE.toString().toUpperCase()=='[ALL]') {
												defaultValue = "_ALL_";
											}else if(param.DEFAULT_VALUE == ''){
												defaultValue = "_ALL_";
											}else{
												defaultValue = param.DEFAULT_VALUE
											}
										}
			                    	}
									/*dogfoot shlim 20210419*/
			                    	if(self.state.fields[param.PARAM_NM]){
									    getListItems(param, self.state.fields[param.PARAM_NM].list, defaultValue, totalSeletion);		
									}
			                        /*dogfoot 연계필터 3개이상일때 하위 한개씩 변경되도록 반복문 강제 종료 shlim 20200709*/
			                        return false;
			                    } else if (param.PARAM_TYPE === 'BETWEEN_LIST') {
									getListItems(param, self.state.fields[param.PARAM_NM].fromField.list, '_ALL_', totalSeletion);
		                        	getListItems(param, self.state.fields[param.PARAM_NM].toField.list, '_ALL_', totalSeletion);
			                    } 
			                }
			            }
					}
		        });
			});
		}
		
		
        // recalculate any list filters generated via query
    }

    /**
     * Generate a parameter field for each unique param.
     * @param {object[]} params 
     */
    function generateFields(params) {
        var fields = {};
        params.forEach(function(param) {
        	//2020.12.30 MKSONG 매개변수 중복 데이터 조회 오류 수정 DOGFOOT
			//2021.01.14 MKSONG 연계필터 initParamList 입력창 필터 포함된 경우 오류 수정 DOGFOOT
			if(self.initParamList.indexOf(param.PARAM_NM) < 0 && param.PARAM_TYPE != 'INPUT' && param.PARAM_TYPE != 'BETWEEN_INPUT'){
				self.initParamList.push(param.PARAM_NM);	
			}
			
        	/*dogfoot 필터 key값이 중복인 경우 무시 처리 shlim 20200619*/
        	if(typeof fields[param.PARAM_NM] != 'undefined'){
        		//WISE.alert('중복 필터 오류. <br>같은 KEY항목의 필터가 있습니다. ');
        	}else{
				switch (param.PARAM_TYPE) {
					case 'LIST':
						fields[param.PARAM_NM] = ListFilter(param);
						break;
					case 'BETWEEN_LIST':
						fields[param.PARAM_NM] = BetweenFilter(param, 'LIST');
						break;
					case 'INPUT':
						fields[param.PARAM_NM] = InputFilter(param);
						break;
					case 'BETWEEN_INPUT':
						fields[param.PARAM_NM] = BetweenFilter(param, 'INPUT');
						break;
					case 'CAND':
						fields[param.PARAM_NM] = DateFilter(param);
						break;
					case 'BETWEEN_CAND':
						fields[param.PARAM_NM] = BetweenFilter(param, 'CAND');
						break;
					default:
				}
            }
            /* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 오류 수정  20200709 */
        	var paramId = param.PARAM_NM;
    		var condid = 'param_' + paramId.replace(/@/, '');
    		if(WISE.Constants.editmode == 'viewer') {
    			condid = condid + '_' + WISE.Constants.pid;
    		}
    		
    		/* DOGFOOT ktkang 필터 오류 수정  20200804 */
    		self.parameterQueryHandler = new WISE.libs.Dashboard.ParameterQueryHandler();	
    		gDashboard.totalConditionBuffer.push(
    			{
    				reportId: WISE.Constants.pid, 
    				totalConditionWidth : self.totalConditionWidth,
    				parameterQueryHandler : self.parameterQueryHandler,
    				/* DOGFOOT ktkang 뷰어에서 보고서 여러개 열었을 때 오류 수정  20200805 */
    				param : param
    			}
    		);

    		var $paramContainer = $('#' + condid).parents('.condition-item-container');
    		/* DOGFOOT ktkang 비트윈필터 삭제 버튼 추가  20200812 */
    		if(param.PARAM_TYPE.indexOf('BETWEEN') != -1) {
    			$paramContainer = $('#' + condid + '_to').parents('.condition-item-container');
    		}
    		/* DOGFOOT syjin 단일 테이블 일 때, 필터 삭제 버튼 추가  20210309 */
    		if(WISE.Context.isCubeReport || gDashboard.dataSourceManager.datasetInformation.dataSource1.DATASRC_TYPE === "DS") {
    			self.drawParameterDeleteButton(paramId, param, $paramContainer);
    		}
        });
        /* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
        if(WISE.Constants.editmode == 'viewer' && gDashboard.reportType == 'DashAny' && gDashboard.structure.Items.TabContainer != undefined){
        	gDashboard.itemGenerateManager.isParamReady = true;
        	if(gDashboard.hasTab == true){
        		gDashboard.tabQuery = true;	
        	}
        }
        self.setState({ fields: fields });
    }
    /*dogfoot shlim 20210420*/
    /**
     * Generate a parameter field for each unique param.
     * @param {object[]} params 
     */
    function generateFieldsToAdd(params) {
        var fields = self.state.fields;
        params.forEach(function(param) {
        	//2020.12.30 MKSONG 매개변수 중복 데이터 조회 오류 수정 DOGFOOT
			//2021.01.14 MKSONG 연계필터 initParamList 입력창 필터 포함된 경우 오류 수정 DOGFOOT
			if(param.ADD_FILTER && self.initParamList.indexOf(param.PARAM_NM) < 0 && param.PARAM_TYPE != 'INPUT' && param.PARAM_TYPE != 'BETWEEN_INPUT'){
				self.initParamList.push(param.PARAM_NM);	
			}
			
        	/*dogfoot 필터 key값이 중복인 경우 무시 처리 shlim 20200619*/
        	if(typeof fields[param.PARAM_NM] != 'undefined'){
        		//WISE.alert('중복 필터 오류. <br>같은 KEY항목의 필터가 있습니다. ');
        	}else{
        		if(param.ADD_FILTER){
        			self.setState(self.utility.generateNewParamValues(WISE.util.Object.toArray(param)),'PARAM_VALUES');
        			switch (param.PARAM_TYPE) {
						case 'LIST':
							fields[param.PARAM_NM] = ListFilter(param);
							break;
						case 'BETWEEN_LIST':
							fields[param.PARAM_NM] = BetweenFilter(param, 'LIST');
							break;
						case 'INPUT':
							fields[param.PARAM_NM] = InputFilter(param);
							break;
						case 'BETWEEN_INPUT':
							fields[param.PARAM_NM] = BetweenFilter(param, 'INPUT');
							break;
						case 'CAND':
							fields[param.PARAM_NM] = DateFilter(param);
							break;
						case 'BETWEEN_CAND':
							fields[param.PARAM_NM] = BetweenFilter(param, 'CAND');
							break;
						default:
					}
        		}
				
            }
            /* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 오류 수정  20200709 */
        	var paramId = param.PARAM_NM;
    		var condid = 'param_' + paramId.replace(/@/, '');
    		if(WISE.Constants.editmode == 'viewer') {
    			condid = condid + '_' + WISE.Constants.pid;
    		}
    		
    		/* DOGFOOT ktkang 필터 오류 수정  20200804 */
    		self.parameterQueryHandler = new WISE.libs.Dashboard.ParameterQueryHandler();	
    		gDashboard.totalConditionBuffer.push(
    			{
    				reportId: WISE.Constants.pid, 
    				totalConditionWidth : self.totalConditionWidth,
    				parameterQueryHandler : self.parameterQueryHandler,
    				/* DOGFOOT ktkang 뷰어에서 보고서 여러개 열었을 때 오류 수정  20200805 */
    				param : param
    			}
    		);

    		var $paramContainer = $('#' + condid).parents('.condition-item-container');
    		/* DOGFOOT ktkang 비트윈필터 삭제 버튼 추가  20200812 */
    		if(param.PARAM_TYPE.indexOf('BETWEEN') != -1) {
    			$paramContainer = $('#' + condid + '_to').parents('.condition-item-container');
    		}
    		/* DOGFOOT syjin 단일 테이블 일 때, 필터 삭제 버튼 추가  20210309 */
    		if(WISE.Context.isCubeReport || gDashboard.dataSourceManager.datasetInformation.dataSource1.DATASRC_TYPE === "DS") {
    			self.drawParameterDeleteButton(paramId, param, $paramContainer);
    		}
        });
        self.setState({ fields: fields });
    }

    this.setParameterArray = function(parameterArray, queryView ,_editDataSet){
		self.totalConditionWidth = 0;
		$.each(parameterArray, function(_k, _o) {
			if (_o['VISIBLE'] === 'N') {
				if (_o['PARAM_TYPE'] === 'LIST') {
					self.parameterQueryHandler.queryParameter(_o);
				}
				var dummyItem = new WISE.libs.Dashboard.DummyDxItem();
				dummyItem.options.wiseUniqueName =  _o['UNI_NM'];
				dummyItem.options.wiseParameterType = _o['PARAM_TYPE'];
				dummyItem.options.wiseParamCaption = _o['PARAM_CAPTION'];
				dummyItem.options.wiseParamName = _o['PARAM_NM'];
				dummyItem.options.wiseVisible = _o['VISIBLE'];
				dummyItem.options.wiseDefaultValue = _o['DEFAULT_VALUE']+"";
				dummyItem.options.wiseDataType = _o['DATA_TYPE'];
				dummyItem.options.wiseWhereClause = _o['WHERE_CLAUSE'];
				/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
				if(typeof _o['WISE_CUBE_UNI_NM'] == 'undefined') {
					var tbl = _o['WHERE_CLAUSE'].split('.')[0];
					var col = _o['WHERE_CLAUSE'].split('.')[1];
					dummyItem.options.wiseCubeUniqueName = '[' + tbl + '].[' + col + ']';
				} else {
					dummyItem.options.wiseCubeUniqueName = _o['WISE_CUBE_UNI_NM'];
				}
				
				
				self.parameterQueryHandler.elementBasket.push(dummyItem);
				return true;
			}
			var paramId = _o.PARAM_NM.replace(/@/, '');
		
			var condid = self.paramPrefix + paramId;
			
			var page = window.location.pathname.split('/');
			if (page[page.length - 1] === 'viewer.do') {
				condid  = condid + "_"+self.reportId;
			}
			if(queryView && !WISE.Context.isCubeReport){
				condid = condid+"_query_view"
			}
			var requiredBullet = '';
			var $paramContainer = $('<div class="condition-item-container" />');
			if(page[page.length - 1] === 'config.do'){
				/*dogfoot shlim 20210419*/
				$('<div id="' + condid + '_caption' + '" class="condition-item condition-caption" style="line-height:29px;vertical-align:middle;padding: 0 5px 0 5px;">' + requiredBullet + _o['PARAM_CAPTION'] + '</div>').appendTo($paramContainer);
				$('<div id="' + condid + '" class="condition-item"></div>').appendTo($paramContainer);
			}else{
				/*dogfoot shlim 20210419*/
				$('<div id="' + condid + '_caption' + '" class="condition-item condition-caption" style="line-height:29px;vertical-align:middle;padding: 0 5px 0 5px;font-size: 1.25em;">' + requiredBullet + _o['PARAM_CAPTION'] + '</div>').appendTo($paramContainer);
				$('<div id="' + condid + '" class="condition-item"></div>').appendTo($paramContainer);
			}
			if(queryView && !WISE.Context.isCubeReport) {
				$('#filter-item2').append($paramContainer);
				if($('#filter-item2').children().length > 2){
					var i = Math.round(($('#filter-item2').children().length) / 2)
					$('#edit_sqlFiltersArea').css('height', (45 * i) +'px')
				}
			} else {
				if (page[page.length - 1] === 'viewer.do') {
					$('#'+self.reportId+'_paramContainer').append($paramContainer);
				}else{
					$('.filter-item').append($paramContainer);
				}
			}
			
			self.drawParameterDeleteButton(condid, _o, $paramContainer);
			
			/* calc condition width(px) */
			var captionLength = (_o['PARAM_CAPTION'] || '').length; 
			var captionWidth = captionLength * 9;
			var conditionWidth = (_o['WIDTH'] || 0);
			conditionWidth = (conditionWidth < 10 ? 10 : conditionWidth); 
			if((captionWidth + conditionWidth) >= $(window).width()){
				conditionWidth = ($(window).width()/2)-50;
			}
			self.totalConditionWidth += (captionWidth + conditionWidth);
			
			switch (_o['PARAM_TYPE']) {
			case 'INPUT':
				$('#' + condid).css('border-radius', '6px');
				var inputBox = $('#' + condid).dxTextBox({
				    value: (_o['DEFAULT_VALUE'] || ''),
				    width: (conditionWidth + 'px'),
				    /* goyong ktkang 고용정보원 디자인 수정  20210525 */
				    height : 30,
				}).dxTextBox("instance");
				
				$.each(WISE.Constants.conditions, function(_i, _v) {
					if (_v.key === _o.PARAM_NM) {
						inputBox.option('value', _v.value);
						return false;
					}
				});
				
				inputBox.option('wiseUniqueName', _o['UNI_NM']);
				inputBox.option('wiseParameterType', _o['PARAM_TYPE']);
				inputBox.option('wiseParamCaption', _o['PARAM_CAPTION']);
				inputBox.option('wiseParamName', _o['PARAM_NM']);
				inputBox.option('wiseVisible', _o['VISIBLE']);
				inputBox.option('wiseDefaultValue', _o['DEFAULT_VALUE']);
				inputBox.option('wiseDataType', _o['DATA_TYPE']);
				inputBox.option('wiseWhereClause', _o['WHERE_CLAUSE']);
				if(typeof _o['WISE_CUBE_UNI_NM'] == 'undefined') {
					var tbl = _o['WHERE_CLAUSE'].split('.')[0];
					var col = _o['WHERE_CLAUSE'].split('.')[1];
					inputBox.option('wiseCubeUniqueName', '[' + tbl + '].[' + col + ']');
				} else {
					inputBox.option('wiseCubeUniqueName', _o['WISE_CUBE_UNI_NM']);
				}
				
				self.parameterQueryHandler.elementBasket.push(condid + ':dxTextBox');
				break;
			case 'BETWEEN_INPUT':
				var condidFr = condid + '_fr';
				var condidTo = condid + '_to';
				$('<div id="' + condidFr + '" class="condition-item"></div>').appendTo($('#'+condid));
				/*dogfoot shlim 20210419*/
				$('<div id="' + condid + '_spacer" class="condition-item between-item" style="margin: 7px 3px 0 3px; font-weight:bold;"> ~ </div>').appendTo($('#'+condid));
				$('<div id="' + condidTo + '" class="condition-item"></div>').appendTo($('#'+condid));
				var defaultVal = _o['DEFAULT_VALUE'];
				var generateBETInputBox = function(_id,_idx){
					var inputBox = $('#' + _id).dxTextBox({
					    value: (defaultVal[_idx] || ''),
					    width: (conditionWidth + 'px')
					}).dxTextBox("instance");
					$('#' + _id).css('width','135px');
					$.each(WISE.Constants.conditions, function(_i, _v) {
						
						if (_v.key === _o.PARAM_NM) {
							inputBox.option('value', _v.value);
							return false;
						}
					});
					var thisItemId= _id.substring(_id.indexOf(_o['PARAM_NM'].replace(/\@/,'')));
					
					inputBox.option('wiseUniqueName', _o['UNI_NM']);
					inputBox.option('wiseParameterType', _o['PARAM_TYPE']);
					inputBox.option('wiseParamCaption', _o['PARAM_CAPTION']);
					inputBox.option('wiseParamName', '@'+thisItemId);
					inputBox.option('wiseVisible', _o['VISIBLE']);
					inputBox.option('wiseDefaultValue', _o['DEFAULT_VALUE']);
					inputBox.option('wiseDataType', _o['DATA_TYPE']);
					inputBox.option('wiseWhereClause', _o['WHERE_CLAUSE']);
					inputBox.option('wiseOrgParamName', _o['PARAM_NM']);
					if(typeof _o['WISE_CUBE_UNI_NM'] == 'undefined') {
						var tbl = _o['WHERE_CLAUSE'].split('.')[0];
						var col = _o['WHERE_CLAUSE'].split('.')[1];
						inputBox.option('wiseCubeUniqueName', '[' + tbl + '].[' + col + ']');
					} else {
						inputBox.option('wiseCubeUniqueName', _o['WISE_CUBE_UNI_NM']);
					}
					self.parameterQueryHandler.elementBasket.push(_id + ':dxTextBox');
				}
				var queriedData = self.parameterQueryHandler.parameterDataSet[_o['PARAM_NM']];
				generateBETInputBox(condidFr,0);
				generateBETInputBox(condidTo,1);
				break;
			case 'CAND':
				var formatString;
				switch(_o['CAPTION_FORMAT']) {
					case 'yyyy년MM월dd일': formatString = 'yyyy년 MM월 dd일'; break;
					default: formatString = _o['CAPTION_FORMAT'];
				}
				var zoomLevel;
				switch(_o['CAPTION_FORMAT']) {
				case 'yyyy':
				case 'yyyy년':
					zoomLevel = 'decade'; break;
				case 'yyyyMM':
				case 'yyyy-MM':
				case 'yyyy년MM월':	
					zoomLevel = 'year'; break;
				default:
					zoomLevel = 'month';
				}
				
				var varDate;
				var dt = new Date();
				
				if(_o['DEFAULT_VALUE'] && _o['CAND_DEFAULT_TYPE']=="QUERY"){
					var parseDate = _o['DEFAULT_VALUE'].toString();
					var y =parseDate.substr(0,4),m = parseDate.substr(4,2),d = parseDate.substr(6,2);
					if (m < 0) m = '01';
					if(d.length == 0) d = '01';
					var dateStr = m + '/'+ d + '/' + y;
					dt = new Date(dateStr);
					if((_o['CAPTION_FORMAT'] == 'yyyy-MM-dd' || _o['CAPTION_FORMAT'] == 'yyyy년MM월dd일') && parseDate.length == 10){
						var y =parseDate.substr(0,4),m = parseDate.substr(5,2),d = parseDate.substr(8,2);
						if (m < 0) m = '1';
						var dateStr = m + '/'+ d + '/' + y;
						dt = new Date(dateStr);
					}
					else if((_o['CAPTION_FORMAT'] == 'yyyy-MM' || _o['CAPTION_FORMAT'] == 'yyyy년MM월') && parseDate.length == 7){
						var y =parseDate.substr(0,4),m = parseDate.substr(5,2),d = parseDate.substr(8,2);
						if(m < 0) m='1';
						if(d.length ==0 || d < 0) d = '1';

						var dateStr = m + '/'+ d + '/' + y;
						dt = new Date(dateStr);
					}
					
				}
				switch(_o['CAND_PERIOD_BASE']) {
				case 'YEAR':
					var yyyy = dt.getFullYear() + Number(_o['CAND_PERIOD_VALUE']);
					var mm = dt.getMonth();
					var dd = dt.getDate();
					varDate = new Date(yyyy, mm, dd);
					break;
				case 'MONTH':
					var yyyy = dt.getFullYear();
					var mm = dt.getMonth();

					mm = mm + Number(_o['CAND_PERIOD_VALUE']);
					if (mm > 12) {
						yyyy = yyyy + parseInt(mm / 12, 10);
						mm = mm - 12;
					}

					var dd = dt.getDate();
					varDate = new Date(yyyy, mm,dd);
					break;
				default:
					var yyyy = dt.getFullYear();
					var mm = dt.getMonth();
					var dd = dt.getDate() + Number(_o['CAND_PERIOD_VALUE']);
					varDate = new Date(yyyy, mm, dd);
				}
				
				var DefaultDate = varDate;
				var calendarBox = $('#' + condid).dxDateBox({
				    min: new Date(2000,1,1),
				    max: new Date(2999,12,31),
				    firstDayOfWeek: 0,
				    acceptCustomValue: true,
				    showClearButton: false,
				    width: (conditionWidth + 'px'),
				    /* goyong ktkang 고용정보원 디자인 수정  20210525 */
				    height : 30,
				    displayFormat: formatString,
				    value : DefaultDate,
				    maxZoomLevel: zoomLevel,
				    onFocusOut: function(_e) {
				    	if (_e.component.option('value') === null) {
				    		WISE.alert(gMessage.get('WISE.message.page.condition.date.invalid',[_o['PARAM_CAPTION']])); // 이(가) 날짜형식이 아닙니다.
				    	}
				    },
				    onValueChanged: function(_e){
				    	self.parameterQueryHandler.setParameterValue(_o, _e.value.format(formatString));
			    		self.parameterQueryHandler.queryAll(_o['PARAM_NM']);
					},
				    wiseKeyFormatString: _o['KEY_FORMAT']
				}).dxDateBox("instance");
				$('#' + condid).dxDateBox({
				    calendarOptions: {
				      firstDayOfWeek: 7
				    }
				});
				calendarBox.option('wiseUniqueName', _o['UNI_NM']);
				calendarBox.option('wiseParameterType', _o['PARAM_TYPE']);
				calendarBox.option('wiseParamCaption', _o['PARAM_CAPTION']);
				calendarBox.option('wiseParamName', _o['PARAM_NM']);
				calendarBox.option('wiseVisible', _o['VISIBLE']);
				calendarBox.option('wiseDefaultValue', _o['DEFAULT_VALUE']);
				calendarBox.option('wiseDataType', _o['DATA_TYPE']);
				calendarBox.option('wiseWhereClause', _o['WHERE_CLAUSE']);
				if(typeof _o['WISE_CUBE_UNI_NM'] == 'undefined') {
					var tbl = _o['WHERE_CLAUSE'].split('.')[0];
					var col = _o['WHERE_CLAUSE'].split('.')[1];
					calendarBox.option('wiseCubeUniqueName', '[' + tbl + '].[' + col + ']');
				} else {
					calendarBox.option('wiseCubeUniqueName', _o['WISE_CUBE_UNI_NM']);
				}
				
				self.parameterQueryHandler.elementBasket.push(condid + ":dxDateBox");
				break;
			case 'BETWEEN_CAND':
				var eventFocusOut = function(_e) {
					var ret = self.parameterHandler.getBetweenCalnedarValues(_e.component);
					var widget = self.parameterHandler.arrangeConditionValue(_e.component);
					widget.value = ret.valbasten;
					widget.betweenCalendarValue = ret.betweenCalendarValue;
					
				};	
				
				/* from */
				var fromMeta = _.clone(_o);
				var fromParameterName = fromMeta['PARAM_NM'] + '_fr';
				var periodBase = fromMeta['CAND_PERIOD_BASE'] ? fromMeta['CAND_PERIOD_BASE'].split(',') : ['DAY','DAY'];
				var periodValue = fromMeta['CAND_PERIOD_VALUE'] ? fromMeta['CAND_PERIOD_VALUE'].split(',') : [0,0];
				var condidFr = condid + '_fr';
				var condidTo = condid + '_to';
				
				$('<div id="' + condidFr + '" class="condition-item"></div>').appendTo($('#'+condid));
				/*dogfoot shlim 20210419*/
				$('<div id="' + condid + '_spacer" class="condition-item between-item" style="margin: 7px 3px 0 3px; font-weight:bold;"> ~ </div>').appendTo($('#'+condid));
				$('<div id="' + condidTo + '" class="condition-item"></div>').appendTo($('#'+condid));
				
				fromMeta['PARAM_NM'] = fromParameterName;
				fromMeta['ORG_PARAM_NM'] = _o['PARAM_NM'];
				fromMeta['CAND_PERIOD_BASE'] = periodBase[0] || 'DAY';
				fromMeta['CAND_PERIOD_VALUE'] = Number(periodValue[0]) + Number(periodValue[1]) || 0;
				
				var formatString;
				switch(fromMeta['CAPTION_FORMAT']) {
				case 'yyyy년MM월dd일': formatString = 'yyyy년 MM월 dd일'; break;
				default: formatString = fromMeta['CAPTION_FORMAT'];
				}
				var zoomLevel;
				switch(fromMeta['CAPTION_FORMAT']) {
				case 'yyyy':
				case 'yyyy년':
					zoomLevel = 'decade'; break;
				case 'yyyyMM':
				case 'yyyy-MM':
				case 'yyyy년MM월':	
					zoomLevel = 'year'; break;
				default:
					zoomLevel = 'month';
				}
				
				var varDate;
				
				var dt = new Date();
				
				var DefaultDate = "";
				
				if(fromMeta['DEFAULT_VALUE']!=""&&fromMeta['CAND_DEFAULT_TYPE']=="QUERY"){
					var parseDate = fromMeta['DEFAULT_VALUE'][0].toString();
					var y =parseDate.substr(0,4),m = parseDate.substr(4,2),d = parseDate.substr(6,2);
					if(d.length <= 0 || d < 0) d = '1';
					if( !(d > 0)) m = m + 1;
					dt = new Date(y,m,d);
					if(dt == 'Invalid Date' && parseDate.length == 10){
						var y =parseDate.substr(0,4),m = parseDate.substr(5,2),d = parseDate.substr(8,2);
						if(m < 0) m='1';
						if( !(d > 0)) m = m + 1;
						dt = new Date(y,m,d);
					}
					else if(Number(m) <= 0 && parseDate.length == 7){
						var y =parseDate.substr(0,4),m = parseDate.substr(5,2),d = parseDate.substr(8,2);
						if(m.length <=0 || m < 0) m='1';
						if(d.length <= 0 || d < 0) d = '1';
						dt = new Date(y,m,d);
					}
				}
				
				switch(fromMeta['CAND_PERIOD_BASE']) {
				case 'YEAR':
					var yyyy;
					if(fromMeta.getDefault){
						yyyy = fromMeta.DEFAULT_VALUE[0];	
					}else{
						yyyy = dt.getFullYear() + Number(fromMeta['CAND_PERIOD_VALUE']);	
					}
					var mm = dt.getMonth();
					var dd = dt.getDate();
					varDate = new Date(yyyy, mm, dd);
					break;
				case 'MONTH':
					var yyyy = dt.getFullYear();
					var mm;
					if(fromMeta.getDefault){
						mm = fromMeta.DEFAULT_VALUE[0];	
					}else{
						mm = dt.getMonth();
						
						mm = mm + Number(fromMeta['CAND_PERIOD_VALUE']);
						if (mm > 12) {
							yyyy = yyyy + parseInt(mm / 12, 10);
							mm = mm - 12;
						}
					}
					var dd = dt.getDate();
					varDate = new Date(yyyy, mm,dd);
					break;
				default:
					var yyyy = dt.getFullYear();
					var mm = dt.getMonth()-1;
					var dd;
					if(fromMeta.getDefault){
						dd = fromMeta.DEFAULT_VALUE[0];	
					}else{
						dd = dt.getDate() + Number(fromMeta['CAND_PERIOD_VALUE']);							
					}
					
					if(mm < 0 ) mm = 0;
					varDate = new Date(yyyy, mm, dd);
				}
				
				// DOGFOOT 20200206 cshan - between 일때는 각 입력창의 사이즈를 필터의 사이즈 /2 로 표기
				var calendarBoxFr = $('#' + condidFr).dxDateBox({
				    min: new Date(2000,1,1),
				    max: new Date(2999,12,31),
				    firstDayOfWeek: 0,
				    acceptCustomValue: true,
				    showClearButton: false,
				    width: ((conditionWidth/2) + 'px'),
				    /* goyong ktkang 고용정보원 디자인 수정  20210525 */
				    height : 30,
				    value: varDate,
				    displayFormat: formatString,
				    maxZoomLevel: zoomLevel,
				    onFocusOut: function(_e) {
				    	if (_e.component.option('value') === null) {
				    		WISE.alert(gMessage.get('WISE.message.page.condition.date.invalid',[fromMeta['PARAM_CAPTION']])); // 이(가) 날짜형식이 아닙니다.
				    	}
				    },
				    wiseKeyFormatString: fromMeta['KEY_FORMAT']
				}).dxDateBox("instance");
				
				$('#' + condidFr).dxDateBox({
				    calendarOptions: {
				      firstDayOfWeek: 7
				  }
				});
				
				calendarBoxFr.option('wiseUniqueName', _o['UNI_NM']);
				calendarBoxFr.option('wiseParameterType', fromMeta['PARAM_TYPE']);
				calendarBoxFr.option('wiseParamCaption', fromMeta['PARAM_CAPTION']);
				calendarBoxFr.option('wiseParamName', fromMeta['PARAM_NM']);
				calendarBoxFr.option('wiseVisible', fromMeta['VISIBLE']);
				calendarBoxFr.option('wiseDefaultValue', fromMeta['DEFAULT_VALUE']);
				calendarBoxFr.option('wiseDataType', fromMeta['DATA_TYPE']);
				calendarBoxFr.option('wiseWhereClause', fromMeta['WHERE_CLAUSE']);
				calendarBoxFr.option('wiseOrgParamName', fromMeta['ORG_PARAM_NM']); // between calendar 일경우에만 사용됨
				if(typeof fromMeta['WISE_CUBE_UNI_NM'] == 'undefined') {
					var tbl = fromMeta['WHERE_CLAUSE'].split('.')[0];
					var col = fromMeta['WHERE_CLAUSE'].split('.')[1];
					calendarBoxFr.option('wiseCubeUniqueName', '[' + tbl + '].[' + col + ']');
				} else {
					calendarBoxFr.option('wiseCubeUniqueName', fromMeta['WISE_CUBE_UNI_NM']);
				}
				
				self.parameterQueryHandler.elementBasket.push(condidFr + ":dxDateBox");
				
				/* to */
				var toMeta = _.clone(_o);
				var toParameterName = toMeta['PARAM_NM'] + '_to';
				formatString = '';
				
				toMeta['PARAM_NM'] = toParameterName;
				toMeta['ORG_PARAM_NM'] = _o['PARAM_NM'];
				toMeta['CAND_PERIOD_BASE'] = periodBase[1] || 'DAY';
				toMeta['CAND_PERIOD_VALUE'] = periodValue[1] || 0;
				
				switch(toMeta['CAPTION_FORMAT']) {
				case 'yyyy년MM월dd일': formatString = 'yyyy년 MM월 dd일'; break;
				default: formatString = toMeta['CAPTION_FORMAT'];
				}
				var zoomLevel;
				switch(toMeta['CAPTION_FORMAT']) {
				case 'yyyy':
				case 'yyyy년':
					zoomLevel = 'decade'; break;
				case 'yyyyMM':
				case 'yyyy-MM':
				case 'yyyy년MM월':	
					zoomLevel = 'year'; break;
				default:
					zoomLevel = 'month';
				}
				
				dt = new Date();
				var DefaultDate = "";
				
				if(toMeta['DEFAULT_VALUE']!=""&&toMeta['CAND_DEFAULT_TYPE']=="QUERY"){
					var parseDate = toMeta['DEFAULT_VALUE'][1].toString();
					var y =parseDate.substr(0,4),m = parseDate.substr(4,2),d = parseDate.substr(6,2);
					if(d.length <= 0 || d < 0) d = '1';
					if( !(d > 0)) m = m + 1;
					dt = new Date(y,m,d);
					if(dt == 'Invalid Date' && parseDate.length == 10){
						var y =parseDate.substr(0,4),m = parseDate.substr(5,2),d = parseDate.substr(8,2);
						if(m < 0) m='1';
						if( !(d > 0)) m = m + 1;
						dt = new Date(y,m,d);
					}
					else if(Number(m) <= 0 && parseDate.length == 7){
						var y =parseDate.substr(0,4),m = parseDate.substr(5,2),d = parseDate.substr(8,2);
						if(m.length <=0 || m < 0) m='1';
						if(d.length <= 0 || d < 0) d = '1';
						dt = new Date(y,m,d);
					}
				}
				
				switch(toMeta['CAND_PERIOD_BASE']) {
				case 'YEAR':
					var yyyy = dt.getFullYear() + Number(toMeta['CAND_PERIOD_VALUE']);
					var mm = dt.getMonth();
					var dd = dt.getDate();
					varDate = new Date(yyyy, mm, dd);
					break;
				case 'MONTH':
					var yyyy = dt.getFullYear();
					var mm = dt.getMonth();
					
					mm = mm + Number(toMeta['CAND_PERIOD_VALUE']);
					if (mm > 12) {
						yyyy = yyyy + parseInt(mm / 12, 10);
						mm = mm - 12;
					}
					
					var dd = dt.getDate();
					varDate = new Date(yyyy, mm,dd);
					break;
				default:
					var yyyy = dt.getFullYear();
					var mm = dt.getMonth()-1;
					var dd = dt.getDate() + Number(toMeta['CAND_PERIOD_VALUE']);
					varDate = new Date(yyyy, mm, dd);
				}
				
				var calendarBoxTo = $('#' + condidTo).dxDateBox({
				    min: new Date(2000,1,1),
				    max: new Date(2999,12,31),
				    firstDayOfWeek: 0,
				    acceptCustomValue: true,
				    showClearButton: false,
				    width: ((conditionWidth/2) + 'px'),
				    /* goyong ktkang 고용정보원 디자인 수정  20210525 */
				    height : 30,
				    value: varDate,
				    displayFormat: formatString,
				    maxZoomLevel: zoomLevel,
				    onFocusOut: function(_e) {
				    	if (_e.component.option('value') === null) {
				    		WISE.alert(gMessage.get('WISE.message.page.condition.date.invalid',[toMeta['PARAM_CAPTION']])); // 이(가) 날짜형식이 아닙니다.
				    	}
				    },
				    wiseKeyFormatString: toMeta['KEY_FORMAT']
				}).dxDateBox("instance");
				$('#' + condidTo).dxDateBox({
				    calendarOptions: {
				      firstDayOfWeek: 7
				  }
				});
				
				calendarBoxTo.option('wiseUniqueName', _o['UNI_NM']);
				calendarBoxTo.option('wiseParameterType', toMeta['PARAM_TYPE']);
				calendarBoxTo.option('wiseParamCaption', toMeta['PARAM_CAPTION']);
				calendarBoxTo.option('wiseParamName', toMeta['PARAM_NM']);
				calendarBoxTo.option('wiseVisible', toMeta['VISIBLE']);
				calendarBoxTo.option('wiseDefaultValue', toMeta['DEFAULT_VALUE']);
				calendarBoxTo.option('wiseDataType', toMeta['DATA_TYPE']);
				calendarBoxTo.option('wiseWhereClause', toMeta['WHERE_CLAUSE']);
				calendarBoxTo.option('wiseOrgParamName', toMeta['ORG_PARAM_NM']); // between calendar 일경우에만 사용됨
				if(typeof toMeta['WISE_CUBE_UNI_NM'] == 'undefined') {
					var tbl = toMeta['WHERE_CLAUSE'].split('.')[0];
					var col = toMeta['WHERE_CLAUSE'].split('.')[1];
					calendarBoxTo.option('wiseCubeUniqueName', '[' + tbl + '].[' + col + ']');
				} else {
					calendarBoxTo.option('wiseCubeUniqueName', toMeta['WISE_CUBE_UNI_NM']);
				}
				
				self.parameterQueryHandler.elementBasket.push(condidTo + ":dxDateBox");
				
				break;
			case 'LIST':
				var KEY_COLUMN = _o['KEY_VALUE_ITEM'];
				var CAPTION_COLUMN = _o['CAPTION_VALUE_ITEM'];
				
				if(_o.DATASRC_TYPE == "TBL"){
					KEY_COLUMN = "KEY_VALUE";
					CAPTION_COLUMN = "CAPTION_VALUE";
				}
				
				var swit = true; //필터 검색때문
				var initialized = false;
				var generateComboList = function(_data) {
					var getListValueIndex = function(_data, _value) {
						var valueIndex;
						$.each(_data, function(_i, _n) {
							if (WISE.util.String.trim((_n[KEY_COLUMN] + '')) == (WISE.util.String.trim(_value))) {
								valueIndex = _i;
								return false;
							}
						});
						return valueIndex;
					};
					var getListValue = function(_data, _value) {
						var value;
						
						$.each(_data, function(_i, _n) {
							if ((WISE.util.String.trim(_n[CAPTION_COLUMN] + '')) == (WISE.util.String.trim(_value))) {
								value = (_n[KEY_COLUMN] + '');
								return false;
							}
						});
						return value;
					};
					
					var comboData = $.map(_data, function(_n, _i) {
						return _n[CAPTION_COLUMN]+'';
					});
					
					var clearComboData = function() {
						if (valueListPanel) {
							valueListPanel.option('canNotQuery',true);
							
							var selectedItems = valueListPanel.option('selectedItems');
				    		$.each(selectedItems, function(_i, _v) {
				    			valueListPanel.unselectItem(_v);
				    			if (_i === (selectedItems.length - 1)) {
				    				valueListPanel.option('canNotQuery',false);
				    			}
				    		});

				    		WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] = [];
				    		self.parameterQueryHandler.setParameterValue(_o, []);
				    		self.parameterQueryHandler.queryAll(_o['PARAM_NM']);
						}
					};
				
					$('#' + condid).attr('style', 'cursor: pointer !important;');
					var showClearButton = _o['MULTI_SEL'] == 'Y' ? true : false;
					
					var valueListPanel, defaultValueIndex;
					$('#' + condid).css('border-radius', '6px');
					var selectListBox = $('#' + condid).dxTextBox({
						width: (conditionWidth + 'px'),
						/* goyong ktkang 고용정보원 디자인 수정  20210525 */
						height : 30,
//						placeholder: gMessage.get('WISE.message.page.widget.selectbox.common.placeholder'),
						showClearButton: showClearButton,
						readOnly: true,
						/* DOGFOOT ktkang [All] 일 경우 텍스트 전체로 나오도록 수정  20200705 */
						onValueChanged: function(_e) {
							if(_e.value == '[All]' || (valueListPanel.option('dataSource')._items.toString() == _e.value)) {
								this.option('value','전체');
							}
						},
						onItemClick: function(_e) {
							//2020.02.20 JHKIM KERIS 필터 조건 선택시 아이콘 추가 DOGFOOT
							//필터 아이콘 제거	
							
							var eVlaueSplit = _e.value;
							if(typeof _e.value == 'string'){
								eVlaueSplit = _e.value.split(",");
							}
							
							if(eVlaueSplit.length == self.parameterQueryHandler.parameterDataSet[_o['PARAM_NM']].length){
								this.option('value',gMessage.get('WISE.message.page.widget.selectbox.common.all'));
							}else if(typeof eVlaueSplit == 'string' &&  _e.value != gMessage.get('WISE.message.page.widget.selectbox.common.all')){
								this.option('value',' ');
							}
							
							
							var checkBox = $('#'+_e.element[0].id+'_popover .dx-list-select-all-checkbox').dxCheckBox("instance");									
							
							if(checkBox) {								
								if(checkBox.value){
									var CreateTagId = "Tag"+_e.element[0].id;
									var SelectTorCreateTag =  document.querySelector("#"+CreateTagId);
									if(SelectTorCreateTag!=null){
										var id = _e.element[0].id+"_caption";
										var SelectTorTag = document.querySelector("#"+id);
										var removeTag = document.getElementById(CreateTagId);
										if(SelectTorTag!=null){
											SelectTorTag.removeChild(removeTag);
										}
									}
								}
							}
							

							if (initialized) {
								self.parameterQueryHandler.setParameterValue(_o, valueListPanel.option('selectedItems'));
								self.parameterQueryHandler.queryAll(_o['PARAM_NM']);
							}
						}
					}).dxTextBox("instance");
					
					
					/* clear button event - onClick */
					$('#' + condid)
						.find('.dx-clear-button-area')
						.on('click', function(_e) {
							if (valueListPanel) {
								if (valueListPanel.option('selectionMode') === 'multiple') {
								}
								var dataSource = new DevExpress.data.DataSource({
								    store: selectListBox.option('wiseQueriedData'),
								    pageSize: self.CUSTOMIZED.get('datasource.list.pageSize')
								});
								valueListPanel.option('dataSource', dataSource);
								valueListPanel.option('selectedItemKeys', []);
								
								clearComboData();
							}
						});
					
					var popoverid = condid + '_popover';
					var popoverHtml = '<div id="' + popoverid + '_space" style="z-index:1510;position:absolute; height:455px;"><div id="' + popoverid + '" class="dx-list-multi-select-panel dx-list-hack" style="z-index: 1510"></div><div class="popover_btn_space" style="border: 1px solid;height: 60px;border-color: #ccc;">';					
					    popoverHtml +='<button id="'+popoverid+'_btn_ok" type="button" class="ui-button-ok" role="button"><span class="ui-button-text">확인</span></button>'
					    popoverHtml +='<button id="'+popoverid+'_btn_cancel" type="button" class="ui-button-cancel" role="button"><span class="ui-button-text">취소</span></button></div></div>'
					
					
					if($('#'+popoverid+'_space').length == 0)
						$('body').append(popoverHtml);					    
					    
				    $('#'+popoverid+'_btn_ok').click(function() {				    	
				    	if( valueListPanel.option('selectedItems').length > 0 ){
				    		self.parameterQueryHandler.setParameterValue(_o, valueListPanel.option('selectedItems'));
							self.parameterQueryHandler.queryAll(_o['PARAM_NM']);				    		
				    	}
				    	self.tempItems[_o['PARAM_NM']] = valueListPanel.option('selectedItems');
				    	$('#'+popoverid+'_space').hide();  
				    });
				    
				    $('#'+popoverid+'_btn_cancel').click(function() {
				    	if( self.tempItems[_o['PARAM_NM']]){
				    		if(valueListPanel.option('selectionMode') == 'single'){
				    			valueListPanel.selectItem(self.tempItems[_o['PARAM_NM']][0]);
				    		}else{
				    			valueListPanel.option('selectedItems',self.tempItems[_o['PARAM_NM']]);
				    		}				    		
				    		selectListBox.option('value', self.tempItems[_o['PARAM_NM']].join(','));	
				    		self.parameterQueryHandler.setParameterValue(_o, self.tempItems[_o['PARAM_NM']]);				    		
				    	}else{
				    		selectListBox.option('value','');	
				    		valueListPanel.unselectAll();
				    	}				    				    	
				    	$('#'+popoverid+'_space').hide();  
				    });
				    
					/* render total */
					var listTopGap = 0;
					
					if (_o['MULTI_SEL'] === 'Y') {
						listTopGap = 49;//테두리를 겹치게 하기 위해 1px 						
					}
					/* render total */
					
					// container css					
//					var top = $('article').hasClass('remove-title') ? 42 : 98;
					var top = $('#'+condid).offset().top + $('#'+condid).height();
					$('#' + popoverid+'_space')
						.css('top',(top + listTopGap)+'px')
						.css('left', '637px');					
					
					var containerPosition = $('#' + condid).position();
					var top = $('article').hasClass('remove-title') ? 0 : 56;
					top = containerPosition.top + 35 + top;
					var searchID = condid+'_search';
					/* condition list width */
					var textMaxLength;
					$.each(_data, function(_i, _vo) {
						var text = (_vo[CAPTION_COLUMN] || '') + '';
						if (!textMaxLength || textMaxLength < text.length) {
							textMaxLength = text.length;
						}
					});
					textMaxLength = (textMaxLength * 10) + 120;
					if(isNaN(textMaxLength)) {
						textMaxLength = _o.WIDTH;
					}
					
					if (textMaxLength < parseInt(conditionWidth)) {
						textMaxLength = parseInt(conditionWidth);
					} else if(parseInt(conditionWidth) < 500 && textMaxLength > 500) {
						textMaxLength = 500;
					}
					
					$('#' + popoverid+'_space').css('width', (textMaxLength + 'px'));
					
					var initilizing = true;
					var selectionMode, fnOnSelectionChanged;
					
					if (_o['MULTI_SEL'] === 'N') {
						selectionMode = 'single';
						
						if(_o['ALL_YN'] === 'Y'){
							comboData = [gMessage.get('WISE.message.page.widget.selectbox.common.all')].concat(comboData);
						}
						
						fnOnSelectionChanged = function(_e) {
							swit = true;
							
							_data = self.parameterQueryHandler.parameterDataSet[_o['PARAM_NM']];
							
							
					    	selectListBox.option('value', _e.addedItems);
					    	var paramData = selectListBox.option('wiseParamData');
					    };
					}
					else { // multi selection
						selectionMode = 'multiple';						
						/* 
						 * WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']]를 변수로 받으면 동작을 않함 ㅡ.,ㅡ;
						 *  ex) var sss = WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']]; <- 이렇게 하면 안됨
						 */
						WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] = [];
						
						fnOnSelectionChanged = function(_e) {
							swit = true;
					    	var that = this;
					    	
//					    	일정 갯수 선택하면 이 이후 선택 불가능하게 하는 코드 (조달청-2018.08.22)
//					    	if(_e.component.option('selectedItems').length > 5){
//					    		alert('123');
//					    		var newArray = _e.component.option('selectedItems').slice(0, 5);
//					    		_e.component.option('selectedItems',newArray);
//					    	}
					    	
					    	var canNotQueryEvent = false;
					    	_data = self.parameterQueryHandler.parameterDataSet[_o['PARAM_NM']];
					    	
					    	var addedItems = that.option('selectedItems');
					    	
					    	var isAdded = addedItems.length > 0;
					    	
					    	if (isAdded) {
					    		if(WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] == false){
					    			WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] = [];
						    	}
					    	}
					    	
					    	WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] = addedItems;
					    	if(_e.component.option('dataSource')._items.length == addedItems.length){
					    		selectListBox.option('value', '전체');
					    	}else{
					    		selectListBox.option('value', WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']].join(','));
					    	}
					    } // end of fnOnSelectionChanged
					} // end of if else multi-list
					
					
					
					var panelHeight = comboData.length > 10 ? undefined : 'auto';
					if(panelHeight == 'auto'){
						$("#" + popoverid+'_space').css('height','auto');
					}
					
					valueListPanel = $("#" + popoverid).dxList({
						dataSource: new DevExpress.data.DataSource({
						    store: comboData,
						    pageSize: self.CUSTOMIZED.get('datasource.list.pageSize')
						}),
						height: 400,
					    editEnabled: false,
					    readOnly: true,
					    showSelectionControls: true,
					    selectionMode: selectionMode == 'multiple' ? 'all' : selectionMode,
					    disabled: false,
					    searchEnabled: _o['SEARCH_YN'] == 'Y' ? true : false,
					    useNativeScrolling: self.CUSTOMIZED.get('useNativeScrolling','Config'),
					    noDataText: gMessage.get('WISE.message.page.common.nodata'),
					    onSelectionChanged: fnOnSelectionChanged
					}).dxList("instance");
					
					// set default value
					var selectListItem = function(_data, _selectedValue, _o) {
						valueListPanel.option('selectedItems',[]);
						var selectedValue = _selectedValue + '';
						var itemArr = [];
						if (selectedValue) {
							if (selectedValue.indexOf(',') > -1) {
								var array = valueListPanel.option('selectedItemKeys');
								$.each(_data,function(_dataIdx,_dataItems){
									$.each(selectedValue.split(','), function(_i0, _v0) {
										if ((_dataItems[KEY_COLUMN] + '') == (WISE.util.String.trim(_v0))) {
											array.push(_dataItems[CAPTION_COLUMN]+'');
											itemArr.push(_dataItems[CAPTION_COLUMN]+'');
										}
									});
								});
								valueListPanel.option('selectedItemKeys',array);
							}
							else {
								var valueIndex = getListValueIndex(_data, selectedValue);
								if (valueIndex !== undefined) {
									$.each(_data,function(_dataIdx,_dataItems){
										if ((_dataItems[KEY_COLUMN] + '') == (WISE.util.String.trim(selectedValue))) {
											valueListPanel.option('selectedItemKeys',_dataItems[CAPTION_COLUMN]+'');
											itemArr.push(_dataItems[CAPTION_COLUMN]+'');
											return false;
										}
									});
								}
								if(selectedValue === '[All]' || selectedValue ==='_ALL_VALUE_')
								{
									
								}
								
							}
						}
						if(selectedValue === '[All]' || selectedValue ==='_ALL_VALUE_'){
							selectListBox.option('value', gMessage.get('WISE.message.page.widget.selectbox.common.all'));
							self.tempItems[_o['PARAM_NM']] = ['전체'];
						}else{
//							selectListBox.option('value', selectedValue);
							selectListBox.option('value', itemArr.join(','));
						}
						
					}; // end of selectListItem
					
					var setDefaultValue = false;
					if (WISE.Constants.conditions.length > 0) {
						$.each(WISE.Constants.conditions, function(_i, _c) {
							if (_c.key === _o.PARAM_NM) {
								selectListItem(_data, _c.value, _o);
								setDefaultValue = true;
							}
						});
					}
					if (!setDefaultValue) {
						selectListItem(_data, _o['DEFAULT_VALUE'], _o);
					}
					// end of setting default value
					
					$('#' + condid)
						.on('mouseleave', function(_e) {
							valueListPanel.option('readyToOpen',false);
						})
						.on('click', function(_e) {
							var target = (_e.target.getAttribute('class') || '');
							if (target.indexOf('dx-texteditor-input') > -1 || target.indexOf('dx-placeholder') > -1) {
								if (!$('#' + popoverid+'_space').is(':visible')) {
									$('#' + popoverid+'_space').show();
									
									if(this.innerText ==  gMessage.get('WISE.message.page.widget.selectbox.common.all') || this.childNodes[0].childNodes[0].value == gMessage.get('WISE.message.page.widget.selectbox.common.all')){
										if(_o.MULTI_SEL == 'N'){
											valueListPanel.selectItem('전체');
										}else{
											$('#' + popoverid).dxList('instance').selectAll();
										}
										
									}
									
									if(_o['SEARCH_YN'] == 'Y')
										$('#'+searchID+'Panel').show();
									
									
								} else {
									$('#' + popoverid+'_space').hide();
									if(_o['SEARCH_YN'] == 'Y')
										$('#'+searchID+'Panel').hide();
								}
								valueListPanel.option('readyToOpen',true);
							}
						});
					
					$("#" + popoverid+'_space')
						.on('mouseover', function(_e) {
							valueListPanel.option('readyToOpen',true);
						})
						.on('mouseleave', function(_e) {
							valueListPanel.option('readyToOpen',false);
						});

					
					$('body').on('click', function(_e) {
						if(_o['SEARCH_YN'] == 'Y'){
							if($('#'+searchID+'Input').length != 0){
								$('#'+searchID+'Input').dxTextBox('instance').on('focusIn',function(){
									swit=false;
									return;
								}).on('focusOut',function(){
									swit=true;
									return;
								});	
							}
							
							if($('#'+searchID+'Type').length != 0){
								$('#'+searchID+'Type').dxSelectBox('instance').on('focusIn',function(){
									swit=false;
									return;
								}).on('focusOut',function(){
									swit=true;
									return;
								});	
							}
							
							if($('#'+searchID+'Option').length != 0){
								$('#'+searchID+'Option').dxSelectBox('instance').on('focusIn',function(){
									swit=false;
									return;
								}).on('focusOut',function(){
									swit=true;
									return;
								});
							}
						}
					});
					if(_o['SEARCH_YN'] == 'Y'){
						selectListBox.option('wiseSearchYN', _o['SEARCH_YN']);
					}
					
					selectListBox.option('wiseUniqueName', _o['UNI_NM']);
					selectListBox.option('wiseParameterType', _o['PARAM_TYPE']);
					selectListBox.option('wiseSelectionMode', selectionMode); // multi, single
					selectListBox.option('wiseParamCaption', WISE.util.String.trim(_o['PARAM_CAPTION']||''));
					selectListBox.option('wiseParamName', _o['PARAM_NM']);
					selectListBox.option('wiseVisible', _o['VISIBLE']);
					selectListBox.option('wiseDefaultValue', _o['DEFAULT_VALUE']+'');
					selectListBox.option('wiseDataType', _o['DATA_TYPE']);
					selectListBox.option('wiseSortType', _o['SORT_TYPE']);
					selectListBox.option('wiseWhereClause', _o['WHERE_CLAUSE']);
					selectListBox.option('wiseOperation', _o['OPER']);
					selectListBox.option('wiseKeyColumn', _o['DATASRC_TYPE'] == 'TBL'? 'KEY_VALUE':_o['KEY_VALUE_ITEM']);
					selectListBox.option('wiseCaptionColumn', _o['DATASRC_TYPE'] == 'TBL'? 'CAPTION_VALUE':_o['CAPTION_VALUE_ITEM']);
					selectListBox.option('wiseOriginKeyColumn', _o['KEY_VALUE_ITEM']);
					selectListBox.option('wiseOriginCaptionColumn', _o['CAPTION_VALUE_ITEM']);
					selectListBox.option('wiseDataSrcType', _o['DATASRC_TYPE']);
					if(typeof _o['WISE_CUBE_UNI_NM'] == 'undefined') {
						var tbl = _o['WHERE_CLAUSE'].split('.')[0];
						var col = _o['WHERE_CLAUSE'].split('.')[1];
						selectListBox.option('wiseCubeUniqueName',  _o['UNI_NM']);
					} else {
						selectListBox.option('wiseCubeUniqueName', _o['WISE_CUBE_UNI_NM']);
					}
					
					selectListBox.option('wiseQueriedData', comboData);
					//여기 작업해야함
//					var hidingOption = self.CUSTOMIZED.get('hiding');
//					if(hidingOption.validate){
//						_.each(hidingOption.paramCode,function(_paramList){
//							if(_paramList.paramKey == _o['PARAM_NM']){
//								if(_paramList.hidingWhenAll){
//									if(_o['DEFAULT_VALUE'] == '[All]'){
//										selectListBox.option('visible',false);
//										$('#'+condid+"_caption").css('display','none');
//										return false;
//									}
//								}
//								else{
//									_.each(_paramList.paramValue,function(_paramVal){
//										_.each(_o['DEFAULT_VALUE'].split(','),function(_inputVal){
//											if(_paramVal == '@All' && _o['DEFAULT_VALUE'] != '[All]'){
//												selectListBox.option('visible',false);
//												$('#'+condid+"_caption").css('display','none');
//												return false;
//											}
//											else{
//												if(_inputVal+'' == _paramVal){
//													selectListBox.option('visible',false);
//													$('#'+condid+"_caption").css('display','none');
//													return false;
//												}
//											}
//											
//										});
//										return false;
//									});
//									return false;
//								}
//							}
//						})
//					}
					
//					if(_o['PARAM_NM'] == '@DPTCD' && _o['DEFAULT_VALUE'] != '[All]'){
//						selectListBox.option('visible',false);
//						$('#'+condid+"_caption").css('display','none');
//					}
					self.parameterQueryHandler.elementBasket.push(condid + ':dxTextBox');
					
					initilizing = false;
					$('#' + popoverid+'_space').hide();
					if(_o['SEARCH_YN'] == 'Y')
						$('#'+searchID+'Panel').hide();
				}; // end of generateComboList
				
				if (_o['DATASRC_TYPE'] === 'QUERY') {
					var queriedData = self.parameterQueryHandler.parameterDataSet[_o['PARAM_NM']];
					generateComboList(queriedData);
				}
				else {
					var callback = function(_data) {
						generateComboList(_data);
					};
					var page = window.location.pathname.split('/');
					var __CONFIG = WISE.widget.getCustom('common', 'Config');
					
					if(__CONFIG == undefined && (page[page.length - 1] == 'config.do')){
						self.parameterQueryHandler.queryParameter(_o, callback);
					}else if (__CONFIG.debug) {
						self.parameterQueryHandler.queryParameter(_o, callback);
					}else {
						try {
							self.parameterQueryHandler.queryParameter(_o, callback);
						}
						catch (e) {
							var msg = 'error occurred while rendering UI Conditions - ' + e.toString();
							throw {status: 500, msg: msg};
						}
					}
				}
				initialized = true;
				
				break;
			case 'BETWEEN_LIST':
				var KEY_COLUMN = _o['KEY_VALUE_ITEM'];
				var CAPTION_COLUMN = _o['CAPTION_VALUE_ITEM'];
				var condidFr = condid + '_fr';
				var condidTo = condid + '_to';
				
				if(_o.DATASRC_TYPE == "TBL"){
					KEY_COLUMN = "KEY_VALUE";
					CAPTION_COLUMN = "CAPTION_VALUE";
				}
				
				$('<div id="' + condidFr + '" class="condition-item"></div>').appendTo($('#'+condid));
				/*dogfoot shlim 20210419*/
				$('<div id="' + condid + '_spacer" class="condition-item between-item" style="margin: 7px 3px 0 3px; font-weight:bold;"> ~ </div>').appendTo($('#'+condid));
				$('<div id="' + condidTo + '" class="condition-item"></div>').appendTo($('#'+condid));
				
				var generateBETComboList = function(_id,_data,_idx) {
					var getListValueIndex = function(_data, _value) {
						var valueIndex;
						$.each(_data, function(_i, _n) {
							if (WISE.util.String.trim((_n[KEY_COLUMN] + '')) == (WISE.util.String.trim(_value))) {
								valueIndex = _i;
								return false;
							}
						});
						return valueIndex;
					};
					var getListValue = function(_data, _value) {
						var value;
						$.each(_data, function(_i, _n) {
							if ((_n[CAPTION_COLUMN] + '') == (WISE.util.String.trim(_value))) {
								value = (_n[KEY_COLUMN] + '');
								return false;
							}
						});
						return value;
					};
					
					var comboData = $.map(_data, function(_n, _i) {
						return _n[CAPTION_COLUMN]+'';
					});
					var clearComboData = function() {
						if (valueListPanel) {
							valueListPanel.option('canNotQuery',true);
							
							var selectedItems = valueListPanel.option('selectedItems');
				    		$.each(selectedItems, function(_i, _v) {
				    			valueListPanel.unselectItem(_v);
				    			if (_i === (selectedItems.length - 1)) {
				    				valueListPanel.option('canNotQuery',false);
				    			}
				    		});

				    		WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] = [];
				    		self.parameterQueryHandler.setParameterValue(_o, []);
				    		self.parameterQueryHandler.queryAll(_o['PARAM_NM']);
						}
					};
				
					$('#' + _id).attr('style', 'cursor: pointer !important;');
					var valueListPanel, defaultValueIndex;
					var selectListBox = $('#' + _id).dxTextBox({
						width: (conditionWidth + 'px'),
//						placeholder: gMessage.get('WISE.message.page.widget.selectbox.common.all'),
						showClearButton: true,
						readOnly: false,
						onKeyUp: function(_e) {
							if (valueListPanel) {
								var filtered = [], inputValue = _e.jQueryEvent.target.value;
								
								var autoCompleteData = _e.component.option('wiseQueriedData');
								_.each(autoCompleteData, function(_d) {
									if (_d.indexOf(inputValue) > -1) {
										filtered.push(_d);
									}
								});
								
								var dataSource = new DevExpress.data.DataSource({
								    store: filtered,
								    pageSize: self.CUSTOMIZED.get('datasource.list.pageSize')
								});
								
								valueListPanel.option('dataSource', dataSource);
							}
						},
						onValueChanged: function(_e) {
							if(_e.value === gMessage.get('WISE.message.page.widget.selectbox.common.all')) {
								clearComboData();
							}
						}
					}).dxTextBox("instance");
					 $('#' + _id).css('width','135px');
					/* clear button event - onClick */
					$('#' + _id)
						.find('.dx-clear-button-area')
						.on('click', function(_e) {
							if (valueListPanel) {
								if (valueListPanel.option('selectionMode') === 'multi') {
								}
								var dataSource = new DevExpress.data.DataSource({
								    store: selectListBox.option('wiseQueriedData'),
								    pageSize: self.CUSTOMIZED.get('datasource.list.pageSize')
								});
								valueListPanel.option('dataSource', dataSource);
								
								clearComboData();
							}
						});
					
					var popoverid = _id + '_popover';
					var popoverHtml = '<div id="' + popoverid + '" class="dx-list-multi-select-panel dx-list-hack"></div>';
					$('body').append(popoverHtml);
					
					var listTopGap = 0;
					listTopGap = 41;		
					var containerPosition = $('#' + _id).position();					
					var top = $('#'+condid).offset().top + $('#'+condid).height();
					$('#' + popoverid+'_space')
						.css('top',(top + listTopGap)+'px')
						.css('left', '637px');
	
					/* condition list width */
					var textMaxLength;
					$.each(_data, function(_i, _vo) {
						var text = (_vo[CAPTION_COLUMN] || '') + '';
						if (!textMaxLength || textMaxLength < text.length) {
							textMaxLength = text.length;
						}
					});
					textMaxLength = (textMaxLength * 10) + 120;
					
					if (textMaxLength < parseInt(conditionWidth)) {
						textMaxLength = parseInt(conditionWidth);
					}
					$('#' + popoverid).css('width', (textMaxLength + 'px'));
					
					var initilizing = true;
					var selectionMode, fnOnSelectionChanged;
					
					if (_o['MULTI_SEL'] === 'N') {
						selectionMode = 'single';
						
						fnOnSelectionChanged = function(_e) {
					    	selectListBox.option('value', _e.addedItems);
					    	var paramData = selectListBox.option('wiseParamData');
					    	if (!initilizing) {	
					    		var addedValue = [];
					    		_.each(_e.addedItems, function(_d) {
					    			if(paramData === undefined)
					    				addedValue.push(getListValue(_data,_d));
					    			else
					    				addedValue.push(getListValue(paramData,_d));
					    		});
					    	}
					    };
					}
					
					var panelHeight = comboData.length > 10 ? undefined : 'auto';
					if(panelHeight == 'auto'){
						$("#" + popoverid+'_space').css('height','auto');
					}
					
					valueListPanel = $("#" + popoverid).dxList({
						dataSource: new DevExpress.data.DataSource({
						    store: comboData,
						    pageSize: self.CUSTOMIZED.get('datasource.list.pageSize')
						}),
						//height: panelHeight,
					    editEnabled: false,
					    readOnly: true,
					    showSelectionControls: true,
					    selectionMode: 'single',
					    disabled: false,
					    useNativeScrolling: self.CUSTOMIZED.get('useNativeScrolling','Config'),
					    noDataText: gMessage.get('WISE.message.page.common.nodata'),
					    onSelectionChanged: fnOnSelectionChanged
					}).dxList("instance");
	
					
					var selectListItem = function(_data, _selectedValue, _o) {
						valueListPanel.option('selectedItems',[]);
						var selectedValue = _selectedValue[_idx] + '';
						var itemArr = [];
						if (selectedValue) {
							if (selectedValue.indexOf(',') > -1) {
								var array = valueListPanel.option('selectedItemKeys');
								$.each(_data,function(_dataIdx,_dataItems){
									$.each(selectedValue.split(','), function(_i0, _v0) {
										if ((_dataItems[KEY_COLUMN] + '') == (WISE.util.String.trim(_v0))) {
											array.push(_dataItems[CAPTION_COLUMN]+'');
											itemArr.push(_dataItems[CAPTION_COLUMN]+'');
										}
									});
								});
								valueListPanel.option('selectedItemKeys',array);
							}
							else {
								var valueIndex = getListValueIndex(_data, selectedValue);
								if (valueIndex !== undefined) {
									$.each(_data,function(_dataIdx,_dataItems){
										if ((_dataItems[KEY_COLUMN] + '') == (WISE.util.String.trim(selectedValue))) {
											valueListPanel.option('selectedItemKeys',_dataItems[CAPTION_COLUMN]+'');
											itemArr.push(_dataItems[CAPTION_COLUMN]+'');
											return false;
										}
									});
								}
								if(selectedValue === '[All]' || selectedValue ==='_ALL_VALUE_')
								{
									
								}
								
							}
						}
						if(selectedValue === '[All]' || selectedValue ==='_ALL_VALUE_'){
							selectListBox.option('value', gMessage.get('WISE.message.page.widget.selectbox.common.all'));
							self.tempItems[_o['PARAM_NM']] = ['전체'];
						}else{
							selectListBox.option('value', itemArr.join(','));
						}
						
					}; // end of selectListItem
					
					var setDefaultValue = false;
					if (WISE.Constants.conditions.length > 0) {
						$.each(WISE.Constants.conditions, function(_i, _c) {
							if (_c.key === _o.PARAM_NM) {
								selectListItem(_data, _c.value, _o,_i);
								setDefaultValue = true;
							}
						});
					}
					if (!setDefaultValue) {
						selectListItem(_data, _o['DEFAULT_VALUE'], _o);
					}
					// end of setting default value
					
					$('#' + _id)
						.on('mouseleave', function(_e) {
							valueListPanel.option('readyToOpen',false);
						})
						.on('click', function(_e) {
							var target = (_e.target.getAttribute('class') || '');
							if (target.indexOf('dx-texteditor-input') > -1 || target.indexOf('dx-placeholder') > -1) {
								if (!$('#' + popoverid+'_space').is(':visible')) {
									$('#' + popoverid+'_space').show();
								} else {
									$('#' + popoverid+'_space').hide();
								}
								valueListPanel.option('readyToOpen',true);
							}
						});
					
					$("#" + popoverid)
						.on('mouseover', function(_e) {
							valueListPanel.option('readyToOpen',true);
						})
						.on('mouseleave', function(_e) {
							valueListPanel.option('readyToOpen',false);
						});
					
					$('body').on('click', function(_e) {
						if (!valueListPanel.option('readyToOpen') && $('#' + popoverid+'_space').is(':visible')) {
							$('#' + popoverid+'_space').hide();
						}
					
					});
					var thisItemId= _id.substring(_id.indexOf(_o['PARAM_NM'].replace(/\@/,'')));
					selectListBox.option('wiseUniqueName', _o['UNI_NM']);
					selectListBox.option('wiseParameterType', _o['PARAM_TYPE']);
					selectListBox.option('wiseSelectionMode', selectionMode); // multi, single
					selectListBox.option('wiseParamCaption', WISE.util.String.trim(_o['PARAM_CAPTION']||''));
					selectListBox.option('wiseParamName', '@'+thisItemId);
					selectListBox.option('wiseVisible', _o['VISIBLE']);
					selectListBox.option('wiseDefaultValue', _o['DEFAULT_VALUE']+'');
					selectListBox.option('wiseDataType', _o['DATA_TYPE']);
					selectListBox.option('wiseSortType', _o['SORT_TYPE']);
					selectListBox.option('wiseWhereClause', _o['WHERE_CLAUSE']);
					selectListBox.option('wiseOperation', _o['OPER']);
					selectListBox.option('wiseKeyColumn', _o['KEY_VALUE_ITEM']);
					selectListBox.option('wiseCaptionColumn', _o['CAPTION_VALUE_ITEM']);
					selectListBox.option('wiseQueriedData', comboData);
					selectListBox.option('wiseOrgParamName', _o['PARAM_NM']);
					
					if(typeof _o['WISE_CUBE_UNI_NM'] == 'undefined') {
						var tbl = _o['WHERE_CLAUSE'].split('.')[0];
						var col = _o['WHERE_CLAUSE'].split('.')[1];
						selectListBox.option('wiseCubeUniqueName', '[' + tbl + '].[' + col + ']');
					} else {
						selectListBox.option('wiseCubeUniqueName', _o['WISE_CUBE_UNI_NM']);
					}
					
					self.parameterQueryHandler.elementBasket.push(_id + ':dxTextBox');
					initilizing = false;
					$('#' + popoverid+'_space').hide();
				}; // end of generateComboList
				
				if (_o['DATASRC_TYPE'] === 'QUERY') {
					var queriedData = self.parameterQueryHandler.parameterDataSet[_o['PARAM_NM']];
					generateBETComboList(condidFr,_data,0);
					generateBETComboList(condidTo,_data,1);
				}
				else {
					var callback = function(_data) {
						generateBETComboList(condidFr,_data,0);
						generateBETComboList(condidTo,_data,1);
					};
					
					var __CONFIG = WISE.widget.getCustom('common', 'Config');
					if(__CONFIG == undefined && (page[page.length - 1] == 'config.do')){
						self.parameterQueryHandler.queryParameter(_o, callback);
					}else if (__CONFIG.debug) {
						self.parameterQueryHandler.queryParameter(_o, callback);
					}
					else {
						try {
							self.parameterQueryHandler.queryParameter(_o, callback);
						}
						catch (e) {
							var msg = 'error occurred while rendering UI Conditions - ' + e.toString();
							throw {status: 500, msg: msg};
						}
					}
				}
				
				break;
			} // end of switch
			
			if (_k === parameterArray.length - 1) {
				self.totalConditionWidth = self.totalConditionWidth + (parameterArray.length * 15) + 80;
				self.resize();
			}
			
		}); // end of $.each(parameterArray
		gDashboard.totalConditionBuffer.push(
			{
				reportId:self.reportId, 
				totalConditionWidth : self.totalConditionWidth,
				parameterQueryHandler : self.parameterQueryHandler
			}
		);
		
		if(WISE.Constants.editmode == 'designer'){
		/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
			if(!_editDataSet){
				gDashboard.reportUtility.setDataSetInfo();	
			}else{
				gProgressbar.hide();
			}
		}else{
			gDashboard.query();
		}
	};
	
	this.getValue = function() {
		var valObj = {};
		$.each(self.parameterQueryHandler.elementBasket, function(_k, _o) {
			if ($.type(_o) === 'string') {
				var pid = _o.split(':')[0];
				var dxItem = _o.split(':')[1];
				_o = $('#' + pid)[dxItem]('instance');
			}
			var betweenCalendarValue = undefined; // BETWEEN_COND타입에서만 FROM 또는 TO의 값을 저장
			var valbasten = [];
			var paramName = _o.option('wiseParamName');
			var checkBox = $('#'+pid+'_popover .dx-list-select-all-checkbox').dxCheckBox("instance");									
			if(checkBox == undefined) {
				checkBox = {value : false};
			}
			if (_o.option('wiseVisible') === 'N') {
				if(_o.option('wiseDefaultValue') != '[All]')
					valbasten = _o.option('wiseDefaultValue').split(',');
				else if(_o.option('wiseDefaultValue') == '[All]')
					valbasten.push('_ALL_VALUE_');
				else
					valbasten.push('_EMPTY_VALUE_');
			}
			else {
				var val = _o.option('value');
				switch(_o.option('wiseParameterType')) {
				case 'CAND':
					if ($.type(val) === 'date') {
						var keyFormatString = _o.option('wiseKeyFormatString') || 'yyyyMMdd';
						val = val.format(keyFormatString);
					}
					else
					{
						var keyFormatString = _o.option('wiseKeyFormatString') || 'yyyyMMdd';
						var varDate = new Date(val);
						val = varDate.format(keyFormatString);
					}
					
					valbasten.push(val + '');
					break;
					
				case 'BETWEEN_CAND':
					var ret = self.getBetweenCalnedarValues(_o);
					valbasten = ret.valbasten;
					betweenCalendarValue = ret.betweenCalendarValue;
					break;
				case 'BETWEEN_INPUT':
				case 'BETWEEN_LIST':
					var ret = self.getBetweenListValues(_o);
					valbasten = ret.valbasten;
					betweenCalendarValue = ret.betweenListValue;
					break;
				case 'INPUT':
					var val = _o.option('value');
					if(val == '[All]')
						valbasten.push('_ALL_VALUE_');
					else{
						var valArr = new Array();
						$.each((val+"").split(','),function(_i,_val){
							valArr.push(_val.trim());
						})
						valbasten = valArr;
					}
					break;
				case 'LIST':
					var KEY_COLUMN = _o.option('wiseKeyColumn');
					var CAPTION_COLUMN = _o.option('wiseCaptionColumn');
					
					val = $('#'+pid+'_popover').dxList('instance').option('selectedItems');
					if(val.length == 0){
						val = [];
					}
					else{
						val = $('#'+pid+'_popover').dxList('instance').option('selectedItems').join(",");
					}

					if (!val || ($.type(val) === 'array' && val.length === 0)) {
						if (self.parameterQueryHandler.parameterDataSet[paramName]) {
							valbasten.push('_EMPTY_VALUE_');
						}
					}
					else if (checkBox.value) {
						if (self.parameterQueryHandler.parameterDataSet[paramName]) {
							if(_o.option('wiseSearchYN')){
								if(_o.option('wiseSelectionMode') === 'multiple'){
									$.each(_o.option('wiseQueriedData'), function(_i0, _si) {
										$.each(self.parameterQueryHandler.parameterDataSet[paramName], function(_i1, _so) {
											if (_so[CAPTION_COLUMN] == _si) {
							    				valbasten.push(_so[KEY_COLUMN] + '');
							    			}
										});
									});
								}
							}
							else{
								valbasten.push('_ALL_VALUE_');
							}
						}
					}
					else {
						// multi selection
						if (_o.option('wiseSelectionMode') === 'multiple') {
					    	$.each(val.split(','), function(_i0, _si) {
					    		$.each(self.parameterQueryHandler.parameterDataSet[paramName], function(_i1, _so) {
					    			if (_so[CAPTION_COLUMN] == _si) {
					    				valbasten.push(_so[KEY_COLUMN] + '');
					    			}
					    		});
					    	});
						}
						else {
							// single list
							$.each(self.parameterQueryHandler.parameterDataSet[paramName], function(_i1, _so) {
				    			if ((_so[CAPTION_COLUMN]+'') === (val+'')) {
				    				valbasten.push(_so[KEY_COLUMN] + '');
				    			}
				    		});
						}
						
						if (valbasten.length === 0) {
							valbasten.push('_EMPTY_VALUE_');
						}
					}
					break;
				default:
					if (!val || val == '[All]'|| checkBox.value) {
						if (self.parameterQueryHandler.parameterDataSet[paramName]) {
							valbasten.push('_EMPTY_VALUE_');
						}
					}
					else {
						valbasten.push(val + '');
					}
				}
			}

			valObj[paramName] = self.arrangeConditionValue(_o, valbasten, betweenCalendarValue);

			// check empty value 
			if(!gDashboard.isNewReport){
				_.each(self.CUSTOMIZED.get('mandatory'), function(_el) {
					if (_el === paramName) {
						if (valbasten.length === 0 || valbasten[0] === '_EMPTY_VALUE_') {
							valObj[paramName]['mandatory'] = true;
							valObj[paramName]['name'] = _o.option('wiseParamCaption');
						}
					}
				});	
			}
		});

		return valObj;
	}
	
this.getBetweenCalnedarValues = function(_widget) {
		var betweenCalendarValue, valbasten = [];
		var fr, to, orgParamName = _widget.option('wiseOrgParamName').replace(/\@/,'');
		var page = window.location.pathname.split('/');
		
		_.each(self.parameterQueryHandler.elementBasket, function(_el) {
			if (page[page.length - 1] === 'viewer.do') {
				if (_el.indexOf(orgParamName +'_'+self.reportId+ '_fr') > -1) {
					fr = _el;
					return false;
				}
			}else{
				if (_el.indexOf(orgParamName + '_fr') > -1) {
					fr = _el;
					return false;
				}
				/* DOGFOOT 20200206 cshan - 뷰어에서 between 캘린더 오류 수정*/
				if(_el.indexOf(orgParamName+'_query_view_fr') >-1){
					fr = _el;
					return false;
				}
			}
		});
		_.each(self.parameterQueryHandler.elementBasket, function(_el) {
			if (page[page.length - 1] === 'viewer.do') {
				if (_el.indexOf(orgParamName +'_'+self.reportId+ '_to') > -1) {
					to = _el;
					return false;
				}
			}else{
				if (_el.indexOf(orgParamName + '_to') > -1) {
					to = _el;
					return false;
				}
				/* DOGFOOT 20200206 cshan - 뷰어에서 between 캘린더 오류 수정*/
				if(_el.indexOf(orgParamName+'_query_view_to') >-1){
					to = _el;
					return false;
				}
			}
		});
		var frO = self.getConditionWidget(fr);
		var toO = self.getConditionWidget(to);
		
		var frVal = self.getCalendarValue(frO.widget);
		var toVal = self.getCalendarValue(toO.widget);
		
		valbasten.push(frVal);
		valbasten.push(toVal);
		var pnm = '';
		if (page[page.length - 1] === 'viewer.do') {
			if( _widget.option('wiseParamName').replace(/\@/,'').indexOf('_fr') > -1)
				pnm = orgParamName +'_'+self.reportId+ '_fr';
			else
				pnm = orgParamName +'_'+self.reportId+ '_to';
		}else{
			/* DOGFOOT 20200206 cshan - 뷰어에서 between 캘린더 오류 수정*/
			if(_widget.option('wiseParamName').replace(/\@/,'').indexOf('to') > -1 && to.indexOf('query_view') > -1){
				pnm = _widget.option('wiseParamName').replace(/\@/,'');
				pnm = pnm.substring(0,pnm.indexOf('_fr'))+'_query_view_to';
			}else if(_widget.option('wiseParamName').replace(/\@/,'').indexOf('fr') > -1 && fr.indexOf('query_view') > -1){
				pnm = _widget.option('wiseParamName').replace(/\@/,'');
				pnm = pnm.substring(0,pnm.indexOf('_fr'))+'_query_view_fr';
			}else{
				pnm = _widget.option('wiseParamName').replace(/\@/,'');
			}
			
		}
//		var pnm = _widget.option('wiseParamName').replace(/\@/,'');
		if (fr.indexOf(pnm) > -1) betweenCalendarValue = frVal;
		if (to.indexOf(pnm) > -1) betweenCalendarValue = toVal;
		return {valbasten:valbasten, betweenCalendarValue:betweenCalendarValue};
	};
	
	this.arrangeConditionValue = function(_widget, _valueArray, _betweenCalendarValue) {
		var widget_name = "";
		if(typeof _widget.option('wiseDataSrcType') != 'undefined'){
			if( _widget.option('wiseDataSrcType') == "TBL"){
				widget_name = _widget.option('wiseOriginKeyColumn');
			}
			else{
				widget_name =  _widget.option('wiseKeyColumn');
			}
		}else{
			widget_name =  _widget.option('wiseKeyColumn');
		}
		var conditionValue = {
			"uniqueName": _widget.option('wiseUniqueName'),
			"name": widget_name,
			"paramName": _widget.option('wiseParamName'),
			"value": _valueArray, 
			"type": _widget.option('wiseDataType'), 
			"tableName": _widget.option('wiseTableName'),
			"defaultValue": _widget.option('wiseDefaultValue'), 
			"whereClause": _widget.option('wiseWhereClause'),
			"parameterType": _widget.option('wiseParameterType'),
			/* DOGFOOT ktkang 주제영역 연결되어 있는 필터 추가 부분 수정  20200207 */
			"cubeUniqueName": _widget.option('wiseCubeUniqueName'),
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			"operation": _widget.option('wiseOperation')
		};
		
		if ('BETWEEN_CAND' === _widget.option('wiseParameterType') || 'BETWEEN_LIST' === _widget.option('wiseParameterType')|| 'BETWEEN_INPUT' === _widget.option('wiseParameterType')) {
			conditionValue['orgParamName'] = _widget.option('wiseOrgParamName'); // between calendar 일경우에만 사용됨
			if (!_.isEmpty(_betweenCalendarValue)) conditionValue["betweenCalendarValue"] = _betweenCalendarValue;
		}
		
		return conditionValue;
	};
	
    /**
     * Generate list items for a list component.
     * @param {object} param 
     * @param {dxList} component 
     * @param {string} defaultValue 
     */
    function getListItems(param, component, defaultValue,totalSeletion) { /*dogfoot 단일리스트 필터 전체 추가 20200701*/
    	/* DOGFOOT ktkang SQL 암호화 추가  20200721 */
    	if(param.HIDDEN_VALUE.toLowerCase().indexOf('select') > -1) {
    		param.HIDDEN_VALUE = Base64.encode(param.HIDDEN_VALUE);
    	}
    	/* DOGFOOT ktkang 주제영역 필터 데이터 권한 추가  20200806 */
    	param.cubeId = 0;
		if(WISE.Context.isCubeReport) {
			$.each(gDashboard.datasetMaster.state.datasets, function(_i, _e) {
				param.cubeId = _e.DATASRC_ID;
			});
		}
		
		//20210927 AJKIM [자산관리공사]연계필터 값이 비어있을 경우 쿼리에 빈값 넣기 dogfoot
		var tempParams = self.getKeyParamValues();
		
		if(userJsonObject.siteNm == 'KAMKO'){
			$.each(tempParams, function(i, param){
				for(var j = 0; j< param.value.length; j++){
					if(param.value[j] == '_EMPTY_VALUE_' || param.value[j] == '_ALL_VALUE_'){
						param.value[j] = '';
					}
				}
			})
		}
		
        var request = $.extend(param, { 
            DS_TYPE: 'DS',
            parameterValues: $.toJSON(tempParams),
			'closYm': userJsonObject.closYm,
			'userId' : userJsonObject.userId
        });
        $.ajax({
            method: 'POST',
            data: request,
            async: true,
            url: WISE.Constants.context + '/report/condition/queries.do',
            beforeSend: function() {
                gProgressbar.show();
            },
            complete: function() {
            	//2020.12.30 MKSONG 매개변수 중복 데이터 조회 오류 수정 DOGFOOT
				self.initParamList.splice([self.initParamList.indexOf(param.PARAM_NM)],1);
				/* DOGFOOT syjin [산림청] 뷰어에서 연계필터 변경 시 무한로딩 현상 수정 20211008 */
				gProgressbar.setStopngoProgress(true);
                gProgressbar.hide();
				gDashboard.contentReadyParamList = [];
                /*dogfoot 비트윈필터 쿼리직접입력 오류 수정 shlim 20210507*/
                if(param.PARAM_TYPE.toLowerCase().indexOf('between') == -1 && param.HIDDEN_VALUE.toLowerCase().indexOf('select') == -1) {
                	param.HIDDEN_VALUE = Base64.decode(param.HIDDEN_VALUE);
                }
            },
            success: function(data) {
            	/* DOGFOOT ktkang SQL 암호화 추가  20200721 */
                var listItems = {};
                listItems[param.PARAM_NM] = data.data;
                self.setState(listItems, 'LIST_VALUES');

                var valueList = [];
                if(Array.isArray(defaultValue)){
                	valueList = defaultValue;
            	}else if (defaultValue) {
                    valueList.push(defaultValue);
                    /* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
                } else if(typeof data.defaultValue != 'undefined' && data.defaultValue != '') {
                	valueList = _.map(
                			data.defaultValue, 
                			function(v) { 
                				if(typeof v === 'number') {
                        			return v; 
                        		} else {
//                        			return v.trim(); 
                        			return v; 
                        		}
                			}
                	);
                } else {
                    valueList = _.map(
                        param.DEFAULT_VALUE.toString().replace(/[\[\]]/g,'').split(','), 
                        function(v) { 
                        	if(typeof v === 'number') {
                    			return v; 
                    		} else {
//                    			return v.trim(); 
                    			return v; 
                    		}
                        }
                    );
                    if (valueList.length === 1 && valueList[0] === 'All') {
                        valueList = [];
                    }
                }
                
                if(param.DATASRC_TYPE==='TBL') {
	                /*dogfoot 단일리스트 필터 전체 추가 20200701*/
                	if(totalSeletion){
                		if(param.MULTI_SEL == 'N' && param.PARAM_TYPE == 'LIST' && data.data.length == 1
                				&& (param.PARAM_NM == '@AU_INST_LCD' || param.PARAM_NM == '@AU_INST_MCD' || param.PARAM_NM == '@AU_INST_SCD')) {
                		} else {
                			var allVal = {};
                    	    allVal['CAPTION_VALUE'] = '전체'
                    	    allVal['KEY_VALUE'] = '전체'
                    	    data.data.unshift(allVal);
                		}
                    }
                    component.option({
                        dataSource: _.map(data.data, 'CAPTION_VALUE'),
                    });
                } else {
	                /*dogfoot 단일리스트 필터 전체 추가 20200701*/
                	if(totalSeletion){
                		if(param.MULTI_SEL == 'N' && param.PARAM_TYPE == 'LIST' && data.data.length == 1
                				&& (param.PARAM_NM == '@AU_INST_LCD' || param.PARAM_NM == '@AU_INST_MCD' || param.PARAM_NM == '@AU_INST_SCD')) {
                		} else {
                			var allVal = {};
                    	    allVal[param.CAPTION_VALUE_ITEM] = '전체'
                    	    allVal[param.KEY_VALUE_ITEM] = '전체'
                    	    
                    	    data.data.unshift(allVal);
                    	    var singleList = new Array;
                    	    singleList.push(valueList[0]);
                    	    valueList = singleList;
                		}
                    }
                    component.option({
                        dataSource: _.map(data.data, param.CAPTION_VALUE_ITEM),
                    });
                }
                // used when you want to select everything in the list
                if (defaultValue === '_ALL_') {
                	//component.selectItem(0);
                	var selectedList = new Array();
                    $.each(data.data, function(_i,_data){
						if(typeof _data.KEY_VALUE === 'undefined'){
								selectedList.push(_data[param.CAPTION_VALUE_ITEM]);
						}else{
								selectedList.push(_data.CAPTION_VALUE);
						}
					});
                    if(param.MULTI_SEL == 'N' && param.PARAM_TYPE == 'LIST' && data.data.length == 1
                    		&& (param.PARAM_NM == '@AU_INST_LCD' || param.PARAM_NM == '@AU_INST_MCD' || param.PARAM_NM == '@AU_INST_SCD')) {
                    	setTimeout(function(){
                    		selectedList.push(data.data[0][param.CAPTION_VALUE_ITEM]);
                    		component.option('selectedItemKeys',selectedList);
                        },500);
                    } else {
                    	component.option('selectedItemKeys',selectedList);
                    }
                } 
                // select certain values only
                else {
	                /*dogfoot USE_SCRIPT Y 일때 기본값 돌리는 과정 추가 shlim 20200708*/
                	var selectedList = new Array();
                	for (var i = 0; i < valueList.length; i++) {
                    	$.each(data.data, function(_i,_data){
                    		if(typeof _data.KEY_VALUE === 'undefined'){
//                    			if(_data[param.KEY_VALUE_ITEM].trim() == valueList[i]){
								/* 2020.12.18 mksong 주택금융공사 필터 전체값 오류 수정 dogfoot */
								var valueData =  valueList[i] == "_ALL_VALUE_" ? '전체' : valueList[i]; 
                                if(_data[param.KEY_VALUE_ITEM] == valueData){
									selectedList.push(_data[param.CAPTION_VALUE_ITEM]);
								}
                    		}else{
//                    			if(_data.KEY_VALUE.trim() == valueList[i]){
								/* 2020.12.18 mksong 주택금융공사 필터 전체값 오류 수정 dogfoot */
								var valueData =  valueList[i] == "_ALL_VALUE_" ? '전체' : valueList[i];
                    		    if(_data.KEY_VALUE == valueData){
									selectedList.push(_data.CAPTION_VALUE);
								}	
                    		}
                    	});
                    }
                    component.option('selectedItemKeys',selectedList);
                }
                gProgressbar.hide();
            },
            error:function(error){
            	if(error.responseJSON != undefined) {
            		WISE.alert("code:" + error.status + "<br>message:" + error.responseJSON.message);
            	}
            }
        });
    }
    /* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
    function getDefaultValue(param, component, defaultValue) { /*dogfoot 단일리스트 필터 전체 추가 20200701*/
    	if(param.DEFAULT_VALUE_USE_SQL_SCRIPT == 'Y') {
    		if(typeof defaultValue == 'undefined' || defaultValue == null) {
    			defaultValue = param.DEFAULT_VALUE;
    		}
    		var request = {
    				dsid : param.DS_ID,
    				/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
    				defaultSql : Base64.encode(defaultValue),
    				'closYm': userJsonObject.closYm,
    				'userId' : userJsonObject.userId
    		}
    		$.ajax({
    			method: 'POST',
    			data: request,
    			url: WISE.Constants.context + '/report/condition/defaultQueries.do',
    			beforeSend: function() {
    				gProgressbar.show();
    			},
    			complete: function() {
    				//2020.12.30 MKSONG 매개변수 중복 데이터 조회 오류 수정 DOGFOOT
					self.initParamList.splice([self.initParamList.indexOf(param.PARAM_NM)],1);
					gDashboard.contentReadyParamList = [];
    				gProgressbar.hide();
    			},
    			success: function(data) {
    				var valueList = [];
    				if(typeof data.data != 'undefined' && data.data != '') {
    					valueList = _.map(
    							data.data, 
    							function(v) { 
    								if(typeof v === 'number') {
    				        			return v; 
    				        		} else {
//    				        			return v.trim(); 
    				        			return v; 
    				        		}
    							}
    					);
						//DEFAULT_VALUE, HIDDEN_VALUE 저장하기
    					$.each(gDashboard.datasetMaster.state.params,function(i,item){
							if(param.PARAM_NM===item.PARAM_NM) {
								/*dogfoot 캘린더 필터 기본값 쿼리오류 수정 , BETWEEN 캘린더 기본값 쿼리 오류 수정 shlim 20200728*/
								if(param.PARAM_TYPE == 'CAND'){
									if(typeof gDashboard.datasetMaster.state.params[i].DEFAULT_VALUE == 'string') {
										var encodeSqlArr = gDashboard.datasetMaster.state.params[i].DEFAULT_VALUE
										gDashboard.datasetMaster.state.params[i].DEFAULT_VALUE = new Array();
										gDashboard.datasetMaster.state.params[i].HIDDEN_VALUE = encodeSqlArr
									}
								}else if(param.PARAM_TYPE == 'BETWEEN_CAND'){
									if(typeof gDashboard.datasetMaster.state.params[i].DEFAULT_VALUE == 'string') {
										var encodeSqlArr = gDashboard.datasetMaster.state.params[i].DEFAULT_VALUE.split(',');
										gDashboard.datasetMaster.state.params[i].DEFAULT_VALUE = new Array();
										//gDashboard.datasetMaster.state.params[i].HIDDEN_VALUE = Base64.encode(encodeSqlArr[0])+','+Base64.encode(encodeSqlArr[1]);
										gDashboard.datasetMaster.state.params[i].DEFAULT_VALUE.push(valueList[0]);
									}
								}
							}
						});
    				} else {
    					valueList = _.map(
    							param.DEFAULT_VALUE.toString().replace(/[\[\]]/g,'').split(','), 
    							function(v) { 
    								if(typeof v === 'number') {
    				        			return v; 
    				        		} else {
//    				        			return v.trim(); 
    				        			return v; 
    				        		}
    							}
    					);
    					if (valueList.length === 1 && valueList[0] === 'All') {
    						valueList = [];
    					}
    				}

    				// used when you want to select everything in the list
    				if (defaultValue === '_ALL_') {
    					component.option('value', '전체');
    				} 
    				// select certain values only
    				else {
    					var valueCon = '';
    					for (var i = 0; i < valueList.length; i++) {
    						if(i == valueList.length -1 ){
    							valueCon = valueList[i]; 
    						} else {
    							valueCon = valueList[i] + ','; 
    						}
    					}
    					/* DOGFOOT ktkang 비트윈 달력 필터 오류 수정  20200702 */
    					if(param.PARAM_TYPE.indexOf('CAND') > -1) {
    						var scope;
    				        var format = param['CAPTION_FORMAT'];
    				        switch(format) {
    				            case 'yyyy':
    				            case 'yyyy년':
    				                scope = 'decade'; 
    				                break;
    				            case 'yyyyMM':
    				            case 'yyyy-MM':
    				            case 'yyyy년MM월':	
    				                scope = 'year'; 
    				                break;
    				            case 'yyyy년MM월dd일': 
    				                scope = 'month';
    				                format = 'yyyy년 MM월 dd일'; 
    				                break;
    				            default:
    				                scope = 'month';
    				        }
    				    
    				        var dt;
    				        dt = moment(valueCon, format.toLocaleUpperCase());
    				        
    				        component.option('value', dt);
    					} else {
    						component.option('value', valueCon);
    					}
    				}
    			},
    			error:function(error){
    				if(error.responseJSON != undefined) {
    					WISE.alert("code:" + error.status + "<br>message:" + error.responseJSON.message);
    				}
    			}
    		});
    	} else {
    		component.option('value', defaultValue);
    		//2020.12.30 MKSONG 매개변수 중복 데이터 조회 오류 수정 DOGFOOT
			self.initParamList.splice([self.initParamList.indexOf(param.PARAM_NM)],1);
			gDashboard.contentReadyParamList.splice([self.initParamList.indexOf(param.PARAM_NM)],1);
    	}
    }

    /**
     * Return an object that contains info for a list component.
     * @param {object} param 
     */
    function ListFilter(param) {
        var fieldId = getFieldId(param, gDashboard.structure.ReportMasterInfo);
        var visibleParam = param.VISIBLE==='Y'?'block':'none'; 
        var visibleTF = param.VISIBLE==='Y'?true:false; 
        /*dogfoot 필터 visible 오류 수정 shlim 20200904*/
        /*dogfoot 리스트필터 KEY 정렬 추가  shlim 20210329 */
        if(typeof param.ORDERBY_KEY === "undefined"){
        	param.ORDERBY_KEY = '';
        }
        /*dogfoot shlim 20210415*/
        if(typeof param.LINE_BREAK != 'undefined' && param.LINE_BREAK == 'Y'){
        	/*dogfoot shlim 20210420*/
        	self.state.element.append('<div class="line-break" style="width:100%;"></div>');
        }
        
      //dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
        var captionWidth = "";
        if(param.CAPTION_WIDTH_VISIBLE == 'Y'){
            //captionWidth = param.CAPTION_WIDTH + "px";
        	captionWidth = "25%";
        }
        
        
        self.state.element.append(
            '<div class="condition-item-container" paramVisible="'+visibleParam+'" style="display:' + visibleParam + ';">' +
                '<div id="' + fieldId + '_caption" class="condition-caption" style="display:' + visibleParam + '; width: '+captionWidth+';">' +
                    param.PARAM_CAPTION + 
                '</div>' +
                '<div id="' + fieldId + '" class="condition-item"></div>' +
                '<div id="' + fieldId + '_list_cont"></div>' +
//                '<div id="' +param.PARAM_CAPTION + '_tooltip"></div>' +
                /*dogfoot 뷰어 보고서 여러개 열람시  필터 매개변수 중복 된 툴팁 표시 안되는 오류 수정 shlim 20210324*/
                '<div id="' +param.PARAM_NM.toString().replace("@","")+"_" + WISE.Constants.pid + '_tooltip"></div>' +
            '</div>'
        );
        // text box
        var textBox = self.state.element.find('#' + fieldId).dxTextBox({
            width: param.WIDTH,
            /* goyong ktkang 고용정보원 디자인 수정  20210525 */
            height : 30,
            // showClearButton: true,
            readOnly: true,
            visible: visibleTF
            /*dogfoot shlim 20210415*/
            /*buttons:[{
            	name:"dropDown",
            	location:"after",
            	options:{
            		icon: WISE.Constants.context + "/resources/main/images/select_custom_arrow.png"
            	}
            }]*/
        }).dxTextBox("instance");
        /*dogfoot 리스트 필터 드롭다운 버튼 추가 shlim 20210421*/
//        $("#"+fieldId).css({
//			"background": "url("+WISE.Constants.domain+"/editds/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
//		})

        var list = $('<div id="' + fieldId + '_list" style="height:210px;">');        
        
        var popoverHtml = '<div class="popover_btn_space">';
        
        /* DOGFOOT syjin 자산관리공사 필터 팝오버 창 확인, 취소 버튼 색상변경 20211007 */
        if(userJsonObject.siteNm == 'KAMKO'){
        	 popoverHtml +='<button id="'+fieldId+'_btn_ok" type="button" class="" role="button" style="background-color:#1b8466; color:white;"><span class="ui-button-text">확인</span></button>';
     	    popoverHtml +='<button id="'+fieldId+'_btn_cancel" type="button" class="" role="button" style="background-color:#a4a4a4; color:white;"><span class="ui-button-text">취소</span></button></div>';
        }else {
        	popoverHtml +='<button id="'+fieldId+'_btn_ok" type="button" class="ui-button-ok" role="button"><span class="ui-button-text">확인</span></button>';
    	    popoverHtml +='<button id="'+fieldId+'_btn_cancel" type="button" class="ui-button-cancel" role="button"><span class="ui-button-text">취소</span></button></div>';
        }
		// all check
    	var selMode = '';
    	if(param.ALL_YN==='Y') {
        	selMode = param.MULTI_SEL === 'Y' ? 'all' : 'single';
        	/*dogfoot 단일리스트 필터 전체 추가 20200701*/
        	if(param.MULTI_SEL === 'N'){
        		var totalSeletion = true
        	}
    	} else {
    		selMode = param.MULTI_SEL === 'Y' ? 'multiple' : 'single';
    	}

        // popover
        var popover = self.state.element.find('#' + fieldId + '_list_cont').dxPopover({
            target: self.state.element.find('#' + fieldId),
            width: param.WIDTH >= 270? param.WIDTH: 270,
            height: '300px',
            deferRendering: false,            
            contentTemplate: function(element) {
                element.append(list);
                // list                
                list = list.dxList({
                    showSelectionControls: true,
                    selectionMode: selMode,
                    selectAllMode: "allPages",
                    searchEnabled: param.SEARCH_YN === 'Y',
                    noDataText: gMessage.get('WISE.message.page.common.nodata'),
                    onSelectionChanged: function(e) {
                    	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
                    	if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
							gDashboard.itemGenerateManager.selectedTabList = [];
							gDashboard.tabQuery = true;
						}
                    	
                        var valueText = '전체';
                        var selected = e.component.option('selectedItems');
                        /* DOGFOOT ktkang 전체 일 때 전체로 나오지 않던 오류 수정  20200702 */
                        /*dogfoot 리스트 값 1개일때 전체가 아닌 1개의 값 으로 표시 shlim 20210402*/
                        if (selected.length != e.component.option('dataSource').length || e.component.option('dataSource').length == 1) {
                            valueText = selected.toString();
                        }
                        /*dogfoot 데이터 미선택시 경고창 shlim 20200625*/
//                        if(selected.length == 0){
//                        	WISE.alert('필터를 선택해 주십시오');
//                        }
                        /* DOGFOOT ktkang 단일 연계 필터 전체 일 때 자식필터 오류 수정  20200703 */
                        /* DOGFOOT ajkim 주제영역 필터 오류 수정 20210222*/
                        /*dogfoot 리스트 값 1개일때 전체가 아닌 1개의 값 으로 표시 shlim 20210402*/
                        if((selMode == 'single' && valueText == '전체') || (e.component.option('selectedItems').length == e.component.option('dataSource').length && e.component.option('dataSource').length != 1)) {
                        	/*dogfoot ktkang 단일필터 전체 선택시 전체값 못가져오는 오류 수정 20200729*/
//                        	selected = JSON.parse(JSON.stringify(e.component.option('dataSource')));
//                        	selected.shift();
                        	selected = "_ALL_VALUE_";
                            valueText = '전체';
                        	 /* DOGFOOT ktkang 아무것도 선택안하면 전체로 표기하도록 수정  20200709 */
                        } else if(valueText == "") {
                        	valueText = '전체';
                        }

                        if(selMode == "single" && e.component.option('selectedItems') == ''){
                            textBox.option('value', valueText);	
                        }else{
                        	textBox.option('value', valueText);	
                            onValueChange(param.PARAM_NM, selected);
                        }
                        
//                        if(param.WIDTH == 201) {
//                        	$.each(self.state.params,function(_i,_param){
//                        		if(_param.WIDTH == 202) {
//                        			var fieldIdGoyong = getFieldId(_param, gDashboard.structure.ReportMasterInfo);
//                        			var selModeGoyong = param.MULTI_SEL === 'Y' ? 'multiple' : 'single';
//                        			var instanceGoyong = self.state.element.find('#' + fieldIdGoyong + '_list').dxList('instance');
//                        			if(selModeGoyong == "single" && typeof instanceGoyong != 'undefined' && instanceGoyong.option('selectedItem') != '전체') {
//                        				self.state.element.find('#' + fieldIdGoyong).dxTextBox('instance').option('value', '전체');
//                        				instanceGoyong.option('selectedItemKeys', ['전체']);
//                        			} else {
//                        				self.state.element.find('#' + fieldIdGoyong).dxTextBox('instance').option('value', '전체');
//                        				onValueChange(param.PARAM_NM, '_ALL_VALUE_');
//                        			}
//                        		}
//                        	});
//                        } else if(param.WIDTH == 202) {
//                        	$.each(self.state.params,function(_i,_param){
//                        		if(_param.WIDTH == 201) {
//                        			var fieldIdGoyong = getFieldId(_param, gDashboard.structure.ReportMasterInfo);
//                        			var selModeGoyong = param.MULTI_SEL === 'Y' ? 'multiple' : 'single';
//                        			var instanceGoyong = self.state.element.find('#' + fieldIdGoyong + '_list').dxList('instance');
//                        			if(selModeGoyong == "single" && typeof instanceGoyong != 'undefined' && instanceGoyong.option('selectedItem') != '전체') {
//                        				self.state.element.find('#' + fieldIdGoyong).dxTextBox('instance').option('value', '전체');
//                        				instanceGoyong.option('selectedItemKeys', ['전체']);
//                        			} else {
//                        				self.state.element.find('#' + fieldIdGoyong).dxTextBox('instance').option('value', '전체');
//                        				onValueChange(param.PARAM_NM, '_ALL_VALUE_');
//                        			}
//                        		}
//                        	});
//                        }
                    },
                    onInitialized: function(e) {
                    	if(gDashboard.contentReadyParamList.indexOf(param.UNI_NM) == -1) {
                    		gDashboard.contentReadyParamList.push(param.UNI_NM);
                    		gDashboard.finishParams++;
                    	}
                    	var defaultValue;
                    	if(!Array.isArray(param.DEFAULT_VALUE)) {
	                    	if(param.DEFAULT_VALUE.toString().toUpperCase()=='[ALL]') {
	                    		defaultValue = "_ALL_";
	                    	}
                    	}else{
                    		defaultValue = param.DEFAULT_VALUE
                		}
                    	/*dogfoot 단일리스트 필터 전체 추가 20200701*/
                    	if(totalSeletion){
                    		getListItems(param, e.component, defaultValue,totalSeletion);
                    	}else{
                    		getListItems(param, e.component, defaultValue);
                    	}
                        /* DOGFOOT ktkang 전체 일 때 전체로 나오지 않던 오류 수정  20200702 */
//                        setTimeout(function(){
//                        	if(defaultValue=="_ALL_") textBox.option('value', '전체');
//                        },500);
                    },onContentReady: function( e ) {  
                    	$("#"+fieldId).find('.dx-texteditor-input').css({
                    		/*dogfoot shlim 20210504*/
							"background": "url("+WISE.Constants.context+"/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
						})
	                    var listitems = e.element.find('.dx-item');
	                    if(listitems.length != 0){
	                    	/*dogfoot 뷰어 보고서 여러개 열람시  필터 매개변수 중복 된 툴팁 표시 안되는 오류 수정 shlim 20210324*/
							var tooltip = $('#'+param.PARAM_NM.toString().replace("@","")+"_" + WISE.Constants.pid + '_tooltip').dxTooltip().dxTooltip('instance');
							listitems.on('dxhoverstart', function (args) {
								tooltip.show(args.target);
								tooltip.content().text($(this).data().dxListItemData);
							});

							listitems.on('dxhoverend', function () {
								tooltip.hide();
							});
						}
					}  
                }).dxList("instance");
                
                return popoverHtml;
                
            }
        }).dxPopover('instance');

        // click event to show list
        self.state.element.find('#' + fieldId).on('click', function() {
            popover.option('visible', !popover.option('visible'));
        });
               
		self.state.element.find('#' + fieldId + '_btn_ok').on('mousedown', function() {
			popover.option('visible', !popover.option('visible'));
		});
		 
		self.state.element.find('#' + fieldId + '_btn_cancel').on('mousedown', function() {
			popover.option('visible', !popover.option('visible'));
		});
         
        return {
            textBox: textBox,
            list: list,
            popover: popover
        };
    }

    /**
     * Return an input filter component.
     * @param {object} param 
     */
    function InputFilter(param) {
        var fieldId = getFieldId(param, gDashboard.structure.ReportMasterInfo);
        var visibleParam = param.VISIBLE==='Y'?'block':'none';
        var visibleTF = param.VISIBLE==='Y'?true:false;
        /*dogfoot shlim 20210415*/
        if(typeof param.LINE_BREAK != 'undefined' && param.LINE_BREAK == 'Y'){
	        /*dogfoot shlim 20210420*/
        	self.state.element.append('<div class="line-break" style="width:100%;"></div>');
        }
        self.state.element.append(
        /*dogfoot 필터 visible 오류 수정 shlim 20200904*/
            '<div class="condition-item-container" paramVisible="'+visibleParam+'" style="display:' + visibleParam + ';">' +
                '<div id="' + fieldId + '_caption" class="condition-caption" style="display:' + visibleParam + ';">' +
                    param.PARAM_CAPTION + 
                '</div>' +
                '<div id="' + fieldId + '" class="condition-item"></div>' +
            '</div>'
        );
		var field = self.state.element.find('#' + fieldId).dxTextBox({
            width: param.WIDTH,
            visible: visibleTF,
            /* goyong ktkang 고용정보원 디자인 수정  20210525 */
            height: 30,
            readOnly: typeof param.INPUT_EDIT_YN == 'undefined' ? false : param.INPUT_EDIT_YN == 'Y'? false : true,
            onValueChanged: function(e) {
            	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
            	if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
					gDashboard.itemGenerateManager.selectedTabList = [];
					gDashboard.tabQuery = true;
				}
            	
            	if(e.value === '[All]' || e.value === '전체'){
            		e.value='_ALL_VALUE_';
            	}
                onValueChange(param.PARAM_NM, e.value);
            },
            /* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
            onInitialized: function(e) {
            	var defaultValue;
            	if(!Array.isArray(param.DEFAULT_VALUE)) {
                	if(param.DEFAULT_VALUE.toString().toUpperCase()=='[ALL]') {
                		defaultValue = "_ALL_";
                	}
            	}else{
            		if(param.DEFAULT_VALUE_USE_SQL_SCRIPT == 'Y'){
                        defaultValue = param.HIDDEN_VALUE;
            		}else{
            			defaultValue = param.DEFAULT_VALUE;
            		}
        		}
            		
            	getDefaultValue(param, e.component, defaultValue);
            	/*dogfoot 입력창 필터 - 연계필터 설정시  오류 수정 shlim 202103*/
            	if(gDashboard.contentReadyParamList.indexOf(param.UNI_NM) == -1) {
            		gDashboard.contentReadyParamList.push(param.UNI_NM);
            		gDashboard.finishParams++;
            	}
            	self.initParamList.push(param.PARAM_NM);
                setTimeout(function(){
                	if(defaultValue=="_ALL_") e.component.option('value', '전체');
                },500);
            }
        }).dxTextBox('instance');

        // value must be assigned after initialization for "onValueChange" event to trigger
//        field.option('value', param.DEFAULT_VALUE || '');
		/*dogfoot shlim 20210414*/
		field.option('value', param.DEFAULT_VALUE.toString());
        /*dogfoot 입력창 필터 - 연계필터 설정시  오류 수정 shlim 202103*/
        self.initParamList.splice([self.initParamList.indexOf(param.PARAM_NM)],1);
        gDashboard.contentReadyParamList.splice([self.initParamList.indexOf(param.PARAM_NM)],1);
        
        return field;
    }
    
    /**
     * Return a date filter component.
     * @param {object} param 
     */
    function DateFilter(param) {
        var fieldId = getFieldId(param, gDashboard.structure.ReportMasterInfo);
        var visibleParam = param.VISIBLE==='Y'?'block':'none';
        var visibleTF = param.VISIBLE==='Y'?true:false;
        /*dogfoot shlim 20210415*/
        if(typeof param.LINE_BREAK != 'undefined' && param.LINE_BREAK == 'Y'){
        	/*dogfoot shlim 20210420*/
        	self.state.element.append('<div class="line-break" style="width:100%;"></div>');
        }
        self.state.element.append(
        /*dogfoot 필터 visible 오류 수정 shlim 20200904*/
            '<div class="condition-item-container" paramVisible="'+visibleParam+'" style="display:' + visibleParam + ';">' +
                '<div id="' + fieldId + '_caption" class="condition-caption" style="display:' + visibleParam + ';">' +
                    param.PARAM_CAPTION + 
                '</div>' +
                '<div id="' + fieldId + '" class="condition-item"></div>' +
            '</div>'
        );
        var scope;
        var format = param['CAPTION_FORMAT'];
        switch(format) {
            case 'yyyy':
            case 'yyyy년':
                scope = 'decade'; 
                break;
            case 'yyyyMM':
            case 'yyyy-MM':
            case 'yyyy년MM월':	
                scope = 'year'; 
                break;
            case 'yyyy년MM월dd일': 
                scope = 'month';
                format = 'yyyy년 MM월 dd일'; 
                break;
            default:
                scope = 'month';
        }
    
        var dt;
        // special case for linked reports
        if (param['OVERRIDE_DEFAULT']) {
            dt = moment(param['DEFAULT_VALUE'], format.toLocaleUpperCase());
        } 
        // date calculated relative to current date
        else if (param['CAND_DEFAULT_TYPE'] === 'NOW') {
            switch(param['CAND_PERIOD_BASE']) {
                case 'YEAR':
                    dt = moment().add(param['CAND_PERIOD_VALUE'], 'years');
                    break;
                case 'MONTH':
                    dt = moment().add(param['CAND_PERIOD_VALUE'], 'months');
                    break;
                default:
                    dt = moment().add(param['CAND_PERIOD_VALUE'], 'days');
            }
        } 
        // default date given as a string
        else if (param['DEFAULT_VALUE']) {
            dt = moment(param['DEFAULT_VALUE'], format.toLocaleUpperCase());
        }
        if (dt && dt.isValid()) {
            dt = dt.toDate();
        } else {
            dt = new Date();
        }

        var field = self.state.element.find('#' + fieldId).dxDateBox({
            min: new Date(1900,1,1),
            max: new Date(2999,12,31),
            visible: visibleTF,
            firstDayOfWeek: 0,
            acceptCustomValue: true,
            showClearButton: false,
            width: param.WIDTH,
            /* goyong ktkang 고용정보원 디자인 수정  20210525 */
            height: 30,
            displayFormat: format,
            maxZoomLevel: scope,
            useMaskBehavior:false,/*dogfoot shlim 20210415*/
            // 고용정보원 본사처리 - 9 begin
            isValid:false,
            onEnterKey:function(e){
            	var changeVal,dtx;
            	if(self.state.element.find('#' + fieldId).find(".dx-texteditor-input").val() == ""){
        			field.option('value', e.component.option('value'));
                }else{
                	changeVal = self.state.element.find('#' + fieldId).find(".dx-texteditor-input").val()
					dtx = moment(changeVal, format.toLocaleUpperCase());
                    if(dtx._isValid){
                    	field.option('value', dtx);
                    }
                    else{
                    	field.option('value', e.component.option('value'));
                    }
                }
            },
            // 고용정보원 본사처리 - 9 end
            /*dogfoot shlim 20210430*/
            onChange:function(e){
            	var changeVal,dtx;
            	if(e.event.type == "change"){
            		/*dogfoot 달력필터 입력 오류 수정 shlim 20210507*/
            		if(self.state.element.find('#' + fieldId).find(".dx-texteditor-input").val() == ""){
            			field.option('value', e.component.option('value'));
                    }else{
                    	changeVal = self.state.element.find('#' + fieldId).find(".dx-texteditor-input").val()
						dtx = moment(changeVal, format.toLocaleUpperCase());
                        if(dtx._isValid){
                        	field.option('value', dtx);
                        }
                        else{
                        	field.option('value', e.component.option('value'));
                        }
                    }
            		
            	}
            },
            onValueChanged: function(e) {
            	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
            	if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
					gDashboard.itemGenerateManager.selectedTabList = [];
					gDashboard.tabQuery = true;
				}
            	
				var val = e.component.option('text');
				/*dogfoot 달력 필터 포멧 같을때 파라메타값 오류 수정 shlim 20200724*/
				if(param['KEY_FORMAT'] != param['CAPTION_FORMAT']){
					switch(param['KEY_FORMAT']) {
						case 'yyyy':
							val = val.substring(0,4);
							break;
						case 'yyyyMM':
							val = val.substring(0,4)+val.substring(5,7);
							break;
						case 'yyyy-MM':
							val = val.substring(0,4)+'-'+val.substring(4,6)
							break;
						case 'yyyyMMdd': 
							val = val.substring(0,4)+val.substring(5,7)+val.substring(8,10);
							break;
						case 'yyyy-MM-dd': 
							val = val.substring(0,4)+'-'+val.substring(4,6)+'-'+val.substring(6,8);
							break;
						default:
							val = val;
					}
	            }				
                onValueChange(param.PARAM_NM, val);
            },
            calendarOptions: {
                firstDayOfWeek: 7
            },
            /* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
            onInitialized: function(e) {
            	if(gDashboard.contentReadyParamList.indexOf(param.UNI_NM) == -1) {
            		gDashboard.contentReadyParamList.push(param.UNI_NM);
            		gDashboard.finishParams++;
            	}
            	var defaultValue;
            	if(!Array.isArray(param.DEFAULT_VALUE)) {
                	if(param.DEFAULT_VALUE.toString().toUpperCase()=='[ALL]') {
                		defaultValue = "_ALL_";
                	}
            	}else{
					/*dogfoot 캘린더 필터 기본값 쿼리 오류 수정 shlim 20200728*/
            		defaultValue = param.HIDDEN_VALUE
        		}
            		
            	getDefaultValue(param, e.component, defaultValue);
            }
        }).dxDateBox("instance");

        // value must be assigned after initialization for "onValueChange" event to trigger
        field.option('value', dt);

        return field;
    }

    /**
     * Return an object that contains info for a "BETWEEN" filter.
     * @param {object} param 
     * @param {string} type 
     */
    function BetweenFilter(param, type) {
        // INPUT GENERATOR
        function generateInputFilter(id, value, info, betweenName) {
            var field = self.state.element.find('#' + id).dxTextBox({
                width: info.WIDTH,
                /* goyong ktkang 고용정보원 디자인 수정  20210525 */
                height: 30,
                onValueChanged: function(e) {
                    onValueChange(betweenName, e.value);
                },
            }).dxTextBox("instance");

            // value must be assigned after initialization for "onValueChange" event to trigger
            field.option('value', value || '');
            
            return field;
        }
        // LIST GENERATOR
        function generateListFilter(id, value, info, betweenName) {
            // text box
            var textBox = self.state.element.find('#' + id).dxTextBox({
                width: info.WIDTH,
                /* goyong ktkang 고용정보원 디자인 수정  20210525 */
                height : 30,
                // showClearButton: true,
                readOnly: true,
            }).dxTextBox("instance");

            var list = $('<div id="' + id + '_list"></div>');

            // popover
            var popover = self.state.element.find('#' + id + '_list_cont').dxPopover({
                target: self.state.element.find('#' + id),
                width: info.WIDTH,
                deferRendering: false,
                contentTemplate: function(element) {
                    element.append(list);
                    // list
                    list = list.dxList({
                        showSelectionControls: true,
                        selectionMode: info.MULTI_SEL === 'Y' ? 'all' : 'single',
                        searchEnabled: info.SEARCH_YN === 'Y',
                        noDataText: gMessage.get('WISE.message.page.common.nodata'),
                        onSelectionChanged: function(e) {
                        	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
                        	if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
								gDashboard.itemGenerateManager.selectedTabList = [];
								gDashboard.tabQuery = true;
							}
                        	
                            var valueText = '전체';
                            var selected = e.component.option('selectedItems');
                            if (selected.length > 0 && selected.length !== e.component.option('items').length) {
                                valueText = selected.toString();
                            }
                            textBox.option('value', valueText);
                            onValueChange(betweenName, selected);
                        },
                        onInitialized: function(e) {
                        	if(gDashboard.contentReadyParamList.indexOf(param.UNI_NM) == -1) {
                        		gDashboard.contentReadyParamList.push(param.UNI_NM);
                        		gDashboard.finishParams++;
                        	}
                        	/* DOGFOOT ktkang 전체 일 때 전체로 나오지 않던 오류 수정  20200702 */
                        	var totalSeletion;
                        	if(info.ALL_YN==='Y' && info.MULTI_SEL === 'N') {
                        		totalSeletion = true;
                        	}
                        	
                        	if(totalSeletion){
                        		getListItems(info, e.component, value,totalSeletion);
                        	}else{
                        		getListItems(info, e.component, value);
                        	}
                        },
                        onContentReady: function(e) {
                        	$("#"+id).find('.dx-texteditor-input').css({
                        		/*dogfoot shlim 20210504*/
    							"background": "url("+WISE.Constants.context+"/resources/main/images/select_custom_arrow.png) no-repeat 93% 50%/10px auto #fff",
    						});
                        }
                    }).dxList("instance");
                }
            }).dxPopover('instance');

            // click event to show list
            self.state.element.find('#' + id).on('click', function() {
                popover.option('visible', !popover.option('visible'));
            });

            return {
                textBox: textBox,
                popover: popover,
                list: list
            };
        }
        // CALENDAR GENERATOR
        function generateDateFilter(id, value, info, betweenName, index) {
            var scope;
            var format = info['CAPTION_FORMAT'];
            switch(format) {
                case 'yyyy':
                case 'yyyy년':
                    scope = 'decade'; 
                    break;
                case 'yyyyMM':
                case 'yyyy-MM':
                case 'yyyy년MM월':	
                    scope = 'year'; 
                    break;
                case 'yyyy년MM월dd일': 
                    scope = 'month';
                    format = 'yyyy년 MM월 dd일'; 
                    break;
                default:
                    scope = 'month';
            }
        
            var dt;
            /*dogfoot 캘린더 기간 설정 shlim 20210427*/
            var gapName;
             // special case for linked reports
            if (param['OVERRIDE_DEFAULT']) {
                dt = moment(value, format.toLocaleUpperCase());
            } 
            // date calculated relative to current date
            else if (info['CAND_DEFAULT_TYPE'] === 'NOW') {
            	/* DOGFOOT ktkang 주제영역 필터 유형 추가  20200806 */
            	var periodValue = 0;
            	if(info['CAND_PERIOD_BASE'] != "") {
            		var periodValues = _.map(info['CAND_PERIOD_VALUE'].split(','), function(val) { return Number(val.trim()) });
            		if (index === 0) {
            			/*dogfoot between 달력 현재~미래일때 from값 오류 수정 shlim 20200728*/
            			periodValue = periodValues[0] + periodValues[1];
//          			periodValue = periodValues[0];
            		} else {
            			periodValue = periodValues[1];
            		}

            		switch(info['CAND_PERIOD_BASE'].split(',')[index].trim()) {
            		case 'YEAR':
            			/*dogfoot 캘린더 기간 설정 shlim 20210427*/
            		    gapName = '년'
            			dt = moment().add(periodValue, 'years');
            			break;
            		case 'MONTH':
	            		/*dogfoot 캘린더 기간 설정 shlim 20210427*/
            		    gapName = '개월'
            			dt = moment().add(periodValue, 'months');
            			break;
            		default:
            			/*dogfoot 캘린더 기간 설정 shlim 20210427*/
            		    gapName = '일'
            			dt = moment().add(periodValue, 'days');
            		}
            	}
            } 
            // default date given as a string
            else {
                dt = moment(value, format.toLocaleUpperCase());
            }
            if (dt && dt.isValid()) {
                dt = dt.toDate();
            } else {
                dt = new Date();
            }
    
            var field = self.state.element.find('#' + id).dxDateBox({
                min: new Date(1900,1,1),
                max: new Date(2999,12,31),
                firstDayOfWeek: 0,
                acceptCustomValue: true,
                showClearButton: false,
                width: info.WIDTH,
                /* goyong ktkang 고용정보원 디자인 수정  20210525 */
                height: 30,
                displayFormat: format,
                maxZoomLevel: scope,
                useMaskBehavior:false,/*dogfoot shlim 20210415*/
                isValid:false,
                // 고용정보원 본사처리 - 9 begin
                onEnterKey:function(e){
                	var changeVal,dtx;
                	if(self.state.element.find('#' + id).find(".dx-texteditor-input").val() == ""){
						field.option('value', e.component.option('value'));
					}else{
						changeVal = self.state.element.find('#' + id).find(".dx-texteditor-input").val()
						dtx = moment(changeVal, format.toLocaleUpperCase());
						if(dtx._isValid){
							field.option('value', dtx);
						}
						else{
							field.option('value', e.component.option('value'));
						}
					}
                },
                // 고용정보원 본사처리 - 9 end
                onChange:function(e){
//                	var changeVal,dtx;
//                	if(e.event.type == "change"){
//                		changeVal = self.state.element.find('#' + id).find(".dx-texteditor-input").val()
//                		dtx = moment(changeVal, format.toLocaleUpperCase());
//                		field.option('value', dtx);
//                	}
//                	
					/*dogfoot 달력필터 입력 오류 수정 shlim 20210507*/
                	var changeVal,dtx;
                	if(e.event.type == "change"){
                		if(self.state.element.find('#' + id).find(".dx-texteditor-input").val() == ""){
                			field.option('value', e.component.option('value'));
                        }else{
                        	changeVal = self.state.element.find('#' + id).find(".dx-texteditor-input").val()
    						dtx = moment(changeVal, format.toLocaleUpperCase());
                            if(dtx._isValid){
                            	field.option('value', dtx);
                            }
                            else{
                            	field.option('value', e.component.option('value'));
                            }
                        }
                		
                	}
                },
                onValueChanged: function(e) {
                	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
                	if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
						gDashboard.itemGenerateManager.selectedTabList = [];
						gDashboard.tabQuery = true;
					}
                	
                	var val = e.component.option('text');
                	/*dogfoot 달력 필터 To날짜가 From 보다 작을때 알림창 표시  shlim 20200811*/
                	/*dogfoot 캘린더 기간 설정 shlim 20210427*/
                	var calendarCheck = true,calendarGapCheck = {'checkVal' : true,'date':val};
                	var alertGapName;
					/*dogfoot 달력 필터 포멧 같을때 파라메타값 오류 수정 shlim 20200724*/
					if(info['KEY_FORMAT'] != info['CAPTION_FORMAT']){
						switch(info['KEY_FORMAT']) {
							case 'yyyy':
								val = val.substring(0,4);
								break;
							case 'yyyyMM':
								val = val.substring(0,4)+val.substring(5,7);
								break;
							case 'yyyy-MM':
								val = val.substring(0,4)+'-'+val.substring(4,6)
								break;
							case 'yyyyMMdd': 
								val = val.substring(0,4)+val.substring(5,7)+val.substring(8,10);
								break;
							case 'yyyy-MM-dd': 
								val = val.substring(0,4)+'-'+val.substring(4,6)+'-'+val.substring(6,8);
								break;
							default:
								val = val;
						}
		            }
					/*dogfoot 달력 필터 To날짜가 From 보다 작을때 알림창 표시  shlim 20200811*/
					if(e.element[0].id.indexOf('_to') > -1 || e.element[0].id.indexOf('_fr') > -1){
						calendarCheck = checkBetweenVal(e.element[0].id,val);
						if(calendarCheck != true){
							if(e.previousValue != null){
								e.component.option('value', e.previousValue);
							}else{
								e.component.option('value', calendarCheck);
							}
							calendarCheck = false;
						}
						/*dogfoot 캘린더 기간 설정 shlim 20210427*/
//						if(info['CAND_MAX_GAP'] && info['CAND_MAX_GAP'] != '0'){
//							calendarGapCheck = checkBetweenGapVal(e.element[0].id,info,index);
//							alertGapName = info.CAND_MAX_GAP+gapName
//						}else{
//							if(WISE.Constants.companyname =="고용정보원"){
//								var _tempCandObject = {};
//								
//								_tempCandObject['CAND_MAX_GAP'] = '5'
//								_tempCandObject['CAND_PERIOD_BASE'] = 'YEAR,YEAR'
//								alertGapName = "5년"
//								calendarGapCheck = checkBetweenGapVal(e.element[0].id,_tempCandObject,index);
//							}
//						}
		            }
		            
					if(calendarCheck){
						onValueChange(betweenName, val);	
//						/*dogfoot 캘린더 기간 설정 shlim 20210427*/
//						if(calendarGapCheck.checkVal){
//						    onValueChange(betweenName, val);		
//						}else{
//							if(e.previousValue != null){
//								e.component.option('value', e.previousValue);
//							}else{
//								e.component.option('value', calendarGapCheck.date);
//							}
//							WISE.alert('조회기간은 '+alertGapName+'을 넘길 수 없습니다. <br> 날짜를 다시 선택해 주세요.');	
//						}
					}else{
                        WISE.alert('To 값이 From 보다 이전 값 입니다. <br> 날짜를 다시 선택해 주세요.');
					}
                },
                calendarOptions: {
                    firstDayOfWeek: 7
                },
                /* DOGFOOT ktkang 데이터 집합 기본값 USE_SQL 로 되어있을 때 오류 수정  20200701 */
                onInitialized: function(e) {
                	if(gDashboard.contentReadyParamList.indexOf(param.UNI_NM) == -1) {
                		gDashboard.contentReadyParamList.push(param.UNI_NM);
                		gDashboard.finishParams++;
                	}
                	var defaultValue;
                	if(!Array.isArray(info.DEFAULT_VALUE)) {
                    	if(info.DEFAULT_VALUE.toString().toUpperCase()=='[ALL]') {
                    		defaultValue = "_ALL_";
                    	}
                	}
                	
                	if(betweenName.indexOf('_fr') > -1) {
                    	/* DOGFOOT ktkang 비트윈 달력 필터 오류 수정  20200702 */
                    		if(typeof info.DEFAULT_VALUE == 'object') {
                    			self.initParamList.splice([self.initParamList.indexOf(info.PARAM_NM)],1);
                    			defaultValue = info.DEFAULT_VALUE[0];
                    		} else {
                    			if(info.DEFAULT_VALUE_USE_SQL_SCRIPT === 'Y'){
                    			    defaultValue = Base64.decode(info.HIDDEN_VALUE.split(",")[0]);	
                    			}else{
                    				defaultValue = info.DEFAULT_VALUE.split(',')[0]
                    			}
                    			
                    			/*dogfoot between 캘린더 오류 수정 shlim 20200716*/
                        		//defaultValue = Base64.decode(defaultValue);
                        		
                        		getDefaultValue(info, e.component, defaultValue);
                    		}
                    	} else if(betweenName.indexOf('_to') > -1) {
                    		if(typeof info.DEFAULT_VALUE == 'object') {
                    			self.initParamList.splice([self.initParamList.indexOf(info.PARAM_NM)],1);
                    			defaultValue = info.DEFAULT_VALUE[1];
                    		} else {
                    			if(info.DEFAULT_VALUE_USE_SQL_SCRIPT === 'Y'){
                    			    defaultValue = Base64.decode(info.HIDDEN_VALUE.split(",")[1]);
                    			}else{
                    				defaultValue = info.DEFAULT_VALUE.split(',')[1]
                    			}
                    			
                    			/*dogfoot between 캘린더 오류 수정 shlim 20200716*/
                        		//defaultValue = Base64.decode(defaultValue);
                        		
                        		getDefaultValue(info, e.component, defaultValue);
                    		}
                    	}
                }
            }).dxDateBox("instance");
    
            // value must be assigned after initialization for "onValueChange" event to trigger
            field.option('value', dt);
    
            return field;
        }

        var fieldId = getFieldId(param, gDashboard.structure.ReportMasterInfo);
        var visibleParam = param.VISIBLE==='Y'?'block':'none';
        var fromFieldId = fieldId + '_fr';
		var toFieldId = fieldId + '_to';
		/*dogfoot shlim 20210415*/
		if(typeof param.LINE_BREAK != 'undefined' && param.LINE_BREAK == 'Y'){
			/*dogfoot shlim 20210420*/
        	self.state.element.append('<div class="line-break" style="width:100%;"></div>');
        }
        self.state.element.append(
        /*dogfoot 필터 visible 오류 수정 shlim 20200904*/
            '<div id="' + fieldId + '" class="condition-item-container" paramType="calendarBox" paramVisible="'+visibleParam+'" style="display:' + visibleParam + ';">' +
                '<div id="' + fieldId + '_caption" class="condition-caption betweencalendarBox">' +
                    param.PARAM_CAPTION + 
                '</div>' +
                '<div id="' + fromFieldId + '" class="condition-item betweencalendarBox"></div>' +
                /*dogfoot shlim 20210419*/
                '<div class="condition-item between-item betweencalendarBox" style="margin: 3px 3px 3px 3px; font-weight:bold;"> ~ </div>' +
                '<div id="' + toFieldId + '" class="condition-item betweencalendarBox"></div>' +
                '<div id="' + fromFieldId + '_list_cont"></div>' +
                '<div id="' + toFieldId + '_list_cont"></div>' +
            '</div>'
        );

        var defaultValOne = '';
		var defaultValTwo = '';
		if (typeof param.DEFAULT_VALUE === 'string') {
			var defaultVals = param.DEFAULT_VALUE.split(',');
			/* DOGFOOT ktkang 비트윈 달력 필터 오류 수정  20200702 */
			if(typeof param.DEFAULT_VALUE[0] == 'string') {
				defaultValOne = defaultVals[0].replace(/[\[\]"\s]/g, '') || '';
	            defaultValTwo = defaultVals[1] ? (defaultVals[1].replace(/[\[\]"\s]/g, '') || '') : defaultValOne;
			} else {
				defaultValOne = defaultVals[0] || '';
				defaultValTwo = defaultVals[1] ? (defaultVals[1] || '') : defaultValOne;
			}
			
		} else {
			if(typeof param.DEFAULT_VALUE[0] == 'string') {
			defaultValOne = param.DEFAULT_VALUE[0].replace(/[\[\]"\s]/g, '') || '';
			defaultValTwo = param.DEFAULT_VALUE[1] ? (param.DEFAULT_VALUE[1].replace(/[\[\]"\s]/g, '') || '') : defaultValOne;
			} else {
				defaultValOne = param.DEFAULT_VALUE[0] || '';
				defaultValTwo = param.DEFAULT_VALUE[1] ? (param.DEFAULT_VALUE[1] || '') : defaultValOne;
			}
		}

        switch (type) {
            case 'INPUT':
                return {
                    fromField: generateInputFilter(fromFieldId, defaultValOne, param, param.PARAM_NM + '_fr'),
                    toField: generateInputFilter(toFieldId, defaultValTwo, param, param.PARAM_NM + '_to'),
                };
            case 'LIST':
                return {
                    fromField: generateListFilter(fromFieldId, defaultValOne, param, param.PARAM_NM + '_fr'),
                    toField: generateListFilter(toFieldId, defaultValTwo, param, param.PARAM_NM + '_to'),
                };
            case 'CAND':
                return {
                    fromField: generateDateFilter(fromFieldId, defaultValOne, param, param.PARAM_NM + '_fr', 0),
                    toField: generateDateFilter(toFieldId, defaultValTwo, param, param.PARAM_NM + '_to', 1),
                };
            default: return {};
        }
    }
    /*dogfoot 달력 필터 To날짜가 From 보다 작을때 알림창 표시  shlim 20200811*/
    function checkBetweenVal(_id, _val) {
    	var frId,toId,frval,toval;

    	frId = _id.replace('to','fr');
    	toId = _id.replace('fr','to');
    	
    	if($('#'+frId).find('input').length ==0 || $('#'+toId).find('input').length == 0) return true;

    	frval = $('#'+frId).dxDateBox("instance").option('value')
    	toval = $('#'+toId).dxDateBox("instance").option('value')

   		return frval>toval ? frval:true;
    }
    
	/*dogfoot 캘린더 기간 설정 shlim 20210427*/
    function checkBetweenGapVal(_id, _info,index) {
    	var frId,toId,frval,toval,returnval=true;

    	frId = _id.replace('to','fr');
    	toId = _id.replace('fr','to');
    	
    	if($('#'+frId).find('input').length ==0 || $('#'+toId).find('input').length == 0) return {'checkVal' : true,'date':toval};

    	frval = $('#'+frId).dxDateBox("instance").option('value')
    	toval = $('#'+toId).dxDateBox("instance").option('value')
    	
    	
    	var periodValue = 0;
    	if(_info['CAND_PERIOD_BASE'] != "") {
    		var periodValues = Number("-"+_info['CAND_MAX_GAP']);
    		

    		switch(_info['CAND_PERIOD_BASE'].split(',')[index].trim()) {
    		case 'YEAR':
    			dt = moment(toval).add(periodValues, 'years');
    			break;
    		case 'MONTH':
    			dt = moment(toval).add(periodValues, 'months');
    			break;
    		default:
    			dt = moment(toval).add(periodValues, 'days');
    		}
    	}
        if(frval < dt){
        	returnval= false;
        }
    	
   		return {'checkVal' : returnval,'date':toval};
    }

    function getFieldId(param, reportInfo) {
        if (WISE.Constants.editmode === 'viewer') {
            return 'param_' + param.PARAM_NM.replace('@', '') + '_' + reportInfo.id;
        } else {
            return 'param_' + param.PARAM_NM.replace('@', '');
        }
    }
}