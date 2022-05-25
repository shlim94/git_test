WISE.libs.Dashboard.ParameterHandler = function() {
	var self = this;
	this.parameterQueryHandler;
//	var parameterInformation = {}; //PARAMETER_SET
	
	this.parameterInformation = {};
	this.type = 'CONDITION';
	
	this.dashboardid;
	this.reportId;
	this.paramPrefix = 'param_';
	this.tempItems = [];	
	this.totalConditionWidth = 0;
	
	this.init = function() {
//		if(!gDashboard.isNewReport){
			this.setParameterInformation(gDashboard.structure.ReportMasterInfo.paramJson);
//			this.setParameterInformation(window[this.dashboardid].structure.ReportMasterInfo.paramJson);
//			this.setParameterInformation(gDashboard.structure.ReportMasterInfo.dataSource.parameters);
//			this.parameterQueryHandler = new WISE.libs.Dashboard.ParameterQueryHandler();
			this.tempItems = [];
			this.parameterQueryHandler = new WISE.libs.Dashboard.ParameterQueryHandler();	

//		}else{
			
//		}
	};
	
	this.initForDataSet = function(Info){
		this.setParameterInformation(Info);

		
		this.parameterQueryHandler = new WISE.libs.Dashboard.ParameterQueryHandler();

	};
	
	this.drawParameterCaption = function(_condid, _o, _$paramContainer) {
		var requiredBullet = '';
		$.each(this.CUSTOMIZED.get('mandatory'), function(_i, _vo) {
			if (_vo === _o['PARAM_NM']) {
				requiredBullet = '<font color="red">*</font>';
				return false;
			}
		});
		
		$('<div id="' + _condid + '_caption' + '" class="condition-item condition-caption">' + requiredBullet + _o['PARAM_CAPTION'] + '</div>').appendTo(_$paramContainer);
		$('<div id="' + _condid + '" class="condition-item"></div>').appendTo(_$paramContainer);
	};
	
	/* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 오류 수정  20200709 */
	this.drawParameterDeleteButton = function(_paramId, _o, _$paramContainer) {		
		if(_o.EDIT_YN == 'N') return;		
		//cube 타입일때만 삭제가능
		/* DOGFOOT ktkang 뷰어에서는 필터 삭제 불가하도록 수정   20210112 */
		var page = window.location.pathname.split('/');
		if(WISE.Context.isCubeReport && page[page.length - 1] === 'edit.do') {
			var filterRemoveText = gMessage.get('WISE.message.page.widget.filter.remove');
			$('<div class="wise-area-icon-filter-remove" title="' + filterRemoveText + '"></div>')
				.on('click', function() {
					var index = -1;
					$.each(gDashboard.parameterFilterBar.parameterInformation,function(_i,_param){
						if (_param.PARAM_NM == _paramId) {
							index = _i;
							return false;
						}
    				});
					
					if (index != -1) {
						/* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 추가  20200221 */
						delete self.parameterInformation[_o.UNI_NM];
        				delete gDashboard.parameterFilterBar.parameterInformation[_o.UNI_NM];
        				var paramList = [];
        				gDashboard.structure.ReportMasterInfo.paramJson = [];
        				$.each(gDashboard.parameterFilterBar.parameterInformation,function(_i,_items){
        					paramList.push(_items);
        					gDashboard.structure.ReportMasterInfo.paramJson.push(_items);
        				});

        				$('.filter-item').empty();
        				/* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 오류 수정  20200709 */
        				var paramTest = gDashboard.datasetMaster.utility.getParamArray(gDashboard.structure.ReportMasterInfo.paramJson);
        				gDashboard.datasetMaster.setState({ params: paramTest });
        				var filterBarElement;
        				switch (WISE.Constants.editmode) {
        				case 'designer':
        					filterBarElement = $('#report-filter-item');
        					break;
        				default:
        					filterBarElement = $('.filter-item');
        				}
        				gDashboard.parameterFilterBar.render({
        					element: filterBarElement,
        					params: gDashboard.datasetMaster.state.params
        				});
						
						$(this).parent().remove();
						$('#'+ $(this).parent()[0].children[1].id +'_popover_space').hide(); 
						self.resize();
					}
				})
				.on('mouseenter', function() {
					$(this).prev().addClass('dx-state-focused');
				})
				.on('mouseleave', function() {
					$(this).prev().removeClass('dx-state-focused');
				})
				.prependTo(_$paramContainer);
		}
	};
	
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
				self.totalConditionWidth += $(el).width(); 
			});
//		}
		
		var tcw = (this.totalConditionWidth + 15 + 40);
		

		// DOGFOOT 20200206 cshan - 필터 접기 & 펼치기 기능에 대상 영역의 사이즈를 잘못 지정하는 오류 수정
//		if (tcw > $(document).width() - $('#btn_query').width()-250) {
//			var divide = parseInt(tcw / ($(document).width() - $('#btn_query').width()-250),10);
//		if (tcw > $(document).width() - $('#btn_query').width()-$('#btn_query').outerWidth()) {
//			var divide = parseInt(tcw / ($(document).width() - $('#btn_query').width()-$('#btn_query').outerWidth()),10);
		if (tcw > $('.filter-item').width() /*- $('#btn_query').width()-$('#btn_query').outerWidth()*/) {
		var divide = parseInt(tcw / ($('.filter-item').width()/* - $('#btn_query').width()-$('#btn_query').outerWidth()*/),10);
			
			if (page[page.length - 1] != 'viewer.do') {
				$('.filter-bar').css('height', 'auto');
			}else{
				$('.filter-more').css('display','block');
				// 2019.12.10 수정자 : mksong 뷰어 필터 아이콘 view DOGFOOT
				$('.filter-gui').css('display','block');
			}
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
			$('.filter.filter-more').css('display','none');
//			if (page[page.length - 1] == 'viewer.do') {
//				$('.filter-more').css('display','none');
//				/* DOGFOOT mksong 필터 css 수정 20200210 */
//				$('.filter-bar').css('height','40px');
//			}else{
			if(!gDashboard.reportUtility.lc){
				$('.filter-bar').css('height','40px');
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
		if(gDashboard.goldenLayoutManager.canvasLayout && WISE.Constants.editmode == "designer"){
			$('.panel.cont').css('height', 'calc(100vh - ' + (84 + ($('.filter-bar').height() < 40? 40 : $('.filter-bar').height())) + 'px)')
	        gDashboard.goldenLayoutManager.canvasLayout.updateSize($('.panel.cont').width());
			/* DOGFOOT 20201022 ajkim setTimeout 시간 변경 300 > 200*/
			setTimeout(function(){
                $.each($('.lm_item'), function(i, ele){
                    var h = WISE.Constants.editmode !== 'viewer'? $(ele).height() - $(ele).find('.lm_header').height() : $(ele).height() - $(ele).find('.lm_header').height() - 10;

                	$(ele).find('.lm_items').height(h);
    		         $(ele).find('.lm_item_container').height(h);
    		         $(ele).find('.lm_content').height(h);
                })
                gDashboard.goldenLayoutManager.resize();
            }, 200)
		}
	};
	
	this.setParameterInformation = function(_information) {
		try {
			var parameterList = _information;
			if (parameterList) {
//				if(this.parameterInformation.length == 0 || $.isEmptyObject(this.parameterInformation) == true){
				if(Array.isArray(this.parameterInformation)){
					this.parameterInformation = {};
				}
				if($.isEmptyObject(this.parameterInformation) == true){
					
					$.each(parameterList, function(_i, _param) {
						if(_param == undefined)return;
//						var paramId = _param.PARAM_NM;
						var paramId = _param.UNI_NM == undefined ? _param.PARAM_NM : _param.UNI_NM;
						self.parameterInformation[paramId] = _param;
					});
				}else{
					$.each(parameterList, function(_i, _param) {
						if(_param == undefined)return;
//						var paramId = _param.PARAM_NM;
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
	this.reloadParamData = function(){
		return self.parameterQueryHandler.parameterDataSet;
	};
	this.setParamData = function(_param_data){
		 self.parameterQueryHandler.parameterDataSet = _param_data;
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
		$.each(gDashboard.totalConditionBuffer,function(_i,_e){
			if(_e.reportId == _reportId){
				self.totalConditionWidth = _e.totalConditionWidth;
//				self.parameterQueryHandler.elementBasket = _e.elementBasket;
//				self.parameterQueryHandler.parameterDataSet = _e.parameterDataSet;
//				self.parameterQueryHandler.parameterValues = _e.parameterValues;
				self.parameterQueryHandler = _e.parameterQueryHandler;
			} 
		});
		self.resize();
		var parameterArray = [];
		$.each(this.parameterInformation, function(_k, _o) {parameterArray.push(_o);});
		parameterArray.sort(function(_a, _b) {return _a['ORDER'] - _b['ORDER'];});
		self.parameterQueryHandler.setDataSourceInformations(parameterArray);
//		self.parameterQueryHandler.queryAll(); // 조회 조건을 갖고 있지 않은 조건만 조회	
		
	};
	
	//2020.03.07 MKSONG 비동기 구현 위해 부분 함수 옵션으로 호출하도록 수정 DOGFOOT
	//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
	this.render = function(queryView, _option, _editDataSet) {
		if(gDashboard.isNewReport){
			this.__CUSTOMIZED = {
				'common': WISE.widget.getCustom('common', this.type),
//					'page': WISE.widget.getCustom(WISE.Constants.pid, this.type)
				'page':''
			};	
		} else{
			this.__CUSTOMIZED = {
				'common': WISE.widget.getCustom('common', this.type),
				'page': WISE.widget.getCustom(WISE.Constants.pid, this.type)
			};
		}
//		if(!gDashboard.isNewReport){
			self.parameterQueryHandler.CUSTOMIZED = this.CUSTOMIZED = {
				get: function(_path, _scope) {
					if (_scope === undefined) {
						var __instance = self;
						
						var val1, val2;
						try {
							val1 = eval('__instance.__CUSTOMIZED.page.' + _path)
						} catch (_e) {
						}
						try {
							val2 = eval('__instance.__CUSTOMIZED.common.' + _path);
						} catch (_e) {
						}
						
						return val1 || val2;
					} else {
						var val;
						try {
							val =  eval('__instance.__CUSTOMIZED.' + _scope + '.' + _path)
						} catch (_e) {
						}
						
						return val;
					}
				}	
			};
//		}
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'viewer.do') {
			$('.filter-row').append('<div id="'+self.reportId+'_paramContainer" class="filter-item" report_id = "'+self.reportId+'"></div>');
//			$('.filter-item').attr('id',self.reportId+'_paramContainer');
//			$('.filter-item').attr('id',self.reportId+'_paramContainer');
		}else{
			if($('.filter-item').children().length == 0 )
				$('.filter-item').empty();
		}
		

		if (this.parameterInformation) {
			// sorting parameter
			var parameterArray = [];
			$.each(this.parameterInformation, function(_k, _o) {
				parameterArray.push(_o);
			});
			parameterArray.sort(function(_a, _b) {return _a['ORDER'] - _b['ORDER'];});
			
//			if(!gDashboard.isNewReport){
				// query 타입 콤보를 위해 데이터를 조회하며, 연관되지 않은 sql 만 실행 한다.
				//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
				self.parameterQueryHandler.setDataSourceInformations(parameterArray);	
				//2020.03.09 MKSONG 데이터 집합 수정 및 생성 오류 수정 DOGFOOT
				if(parameterArray.length != 0){
					self.parameterQueryHandler.queryAll(undefined,parameterArray,queryView ,_option, _editDataSet); // 조회 조건을 갖고 있지 않은 조건만 조회	
				}else{
					if(_option != undefined){
						_option();	
					}else{
						self.parameterQueryHandler.queryAll(undefined,parameterArray,queryView ,_option, _editDataSet); // 조회 조건을 갖고 있지 않은 조건만 조회	
					}
				}
//			}
		} // end of if (this.parameterInformation) {
		self.resize();
	};
	
	//2020.03.06 mksong parameterArray setting 함수화 dogfoot
	//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
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
			/* DOGFOOT ktkang 주제영역 필터삭제 오류 수정  20200310 */
			if(queryView && !WISE.Context.isCubeReport){
				condid = condid+"_query_view"
			}
			var requiredBullet = '';
//			$.each(self.CUSTOMIZED.get('mandatory'), function(_i, _vo) {
//				if (_vo === _o['PARAM_NM']) {
//					requiredBullet = '<font color="red">*</font>';
//					return false;
//				}
//			});
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
//			var $paramContainer = $('<div class="condition-item-container" />');
//			$('<div id="' + condid + '_caption' + '" class="condition-item condition-caption" style="line-height:29px;vertical-align:middle;padding: 0 10px 0 10px;font-size: 1.25em;">' + requiredBullet + _o['PARAM_CAPTION'] + '</div>').appendTo($paramContainer);
//			$('<div id="' + condid + '" class="condition-item"></div>').appendTo($paramContainer);
			/* DOGFOOT ktkang 주제영역 필터삭제 오류 수정  20200310 */
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
			
			/* DOGFOOT ktkang 주제영역에서 필터 삭제 기능 추가  20200221 */
			self.drawParameterDeleteButton(condid, _o, $paramContainer);
			
			/* calc condition width(px) */
			var captionLength = (_o['PARAM_CAPTION'] || '').length; 
			var captionWidth = captionLength * 9;
			/* DOGFOOT ktkang KERIS 필터 길이를 Caption 포함하지 않은 아이템 길이로 정하기  20200110 */
			var conditionWidth = (_o['WIDTH'] || 0);
//			var conditionWidth = (_o['WIDTH'] || 0) - captionWidth;
			conditionWidth = (conditionWidth < 10 ? 10 : conditionWidth); 
			if((captionWidth + conditionWidth) >= $(window).width()){
				conditionWidth = ($(window).width()/2)-50;
			}
			self.totalConditionWidth += (captionWidth + conditionWidth);
			
			// DOGFOOT shlim 마지막 필터 리스트 UI 위치 변경 20200308
//			if (_k === parameterArray.length - 1) {
////				self.totalConditionWidth = self.totalConditionWidth + (parameterArray.length * self.CUSTOMIZED.get('gap')) + 80;
//				self.totalConditionWidth = self.totalConditionWidth + (parameterArray.length * 15) + 80;
//				self.resize();
//			}
			
			switch (_o['PARAM_TYPE']) {
			case 'INPUT':
				$('#' + condid).css('border-radius', '6px');
				var inputBox = $('#' + condid).dxTextBox({
				    value: (_o['DEFAULT_VALUE'] || ''),
				    width: (conditionWidth + 'px'),
				    /* DOGFOOT mksong 필터 css 수정 20200210 */
				    height : 28,
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
				/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
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
				$('<div id="' + condid + '_spacer" class="condition-item" style="margin: 7px 3px 0 3px; font-weight:bold;"> ~ </div>').appendTo($('#'+condid));
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
					/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
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
				
//				if(_o['DEFAULT_VALUE']!=""&&_o['CAND_DEFAULT_TYPE']=="QUERY"){
//					switch(_o['CAPTION_FORMAT']) {
//					case 'yyyy':
//					case 'yyyy년':
//						var parseDate = _o['DEFAULT_VALUE'].toString();
//						var y =parseDate.substr(0,4);
//						DefaultDate = new Date(y);
////						DefaultDate = new Date(_o['DEFAULT_VALUE'].toString());
//						break;
//					case 'yyyyMM':
//						var parseDate = _o['DEFAULT_VALUE'].toString();
//						var y =parseDate.substr(0,4),m = parseDate.substr(4,2)-1;
//						DefaultDate = new Date(y,m);
////						DefaultDate = new Date(_o['DEFAULT_VALUE'].toString());
//						break;
//					case 'yyyy-MM':
//					case 'yyyy년MM월':
//						var parseDate = _o['DEFAULT_VALUE'].toString();
//						var y =parseDate.substr(0,4),m = parseDate.substr(5,2)-1;
//						DefaultDate = new Date(y,m);
////						DefaultDate = new Date(_o['DEFAULT_VALUE'].toString());
//						break;
//					case 'yyyy-MM-dd':
//					case 'yyyy년MM월dd일':
//						var parseDate = _o['DEFAULT_VALUE'].toString();
//						var y =parseDate.substr(0,4),m = parseDate.substr(5,2)-1,d = parseDate.substr(8,2);
//						DefaultDate = new Date(y,m,d);
//						break;
//					default:
//						var parseDate = _o['DEFAULT_VALUE'].toString();
//						var y =parseDate.substr(0,4),m = parseDate.substr(4,2)-1,d = parseDate.substr(6,2);
//						DefaultDate = new Date(y,m,d);
//						break;
//					}
//				}
				
				var varDate;
				
				var dt = new Date();
				
//				if(_o['DEFAULT_VALUE'] && _o['CAND_DEFAULT_TYPE']=="QUERY"){
//					var parseDate = _o['DEFAULT_VALUE'].toString();
//					var y =parseDate.substr(0,4),m = parseDate.substr(4,2),d = parseDate.substr(6,2);
//					
//					if(m.length <=0 || m < 0) m='1';
//					if( !(d > 0)) m = m + 1;//d = '1';
////					if( !(d > 0)) d = '1';
//					dt = new Date(y,m,d);

//					if(dt == 'Invalid Date' && parseDate.length == 10){
//						var y =parseDate.substr(0,4),m = parseDate.substr(5,2),d = parseDate.substr(8,2);
//						if(m < 0) m='1';
//						dt = new Date(y,m-1,d);
//					}
//					else if(Number(m) <= 0 && parseDate.length == 7){
//						var y =parseDate.substr(0,4),m = parseDate.substr(5,2),d = parseDate.substr(8,2);
//						if(m.length <=0 || m < 0) m='1';
//						if(d.length <= 0 || d < 0) d = '1';
//						dt = new Date(y,m-1,d);
//					}
//				}
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
//					mm = mm -1;

					var dd = dt.getDate();
					varDate = new Date(yyyy, mm,dd);
					break;
				default:
					var yyyy = dt.getFullYear();
					var mm = dt.getMonth();
					var dd = dt.getDate() + Number(_o['CAND_PERIOD_VALUE']);
					varDate = new Date(yyyy, mm, dd);
				}
				
				
//				if(_o['CAND_PERIOD_TYPE'] != 'QUERY')
//				{
//					
//					switch(_o['CAND_PERIOD_BASE']) {
//					case 'YEAR':
//						var yyyy = dt.getFullYear() + Number(_o['CAND_PERIOD_VALUE']);
//						var mm = dt.getMonth();
//						var dd = dt.getDate();
//						varDate = new Date(yyyy, mm, dd);
//						break;
//					case 'MONTH':
//						var yyyy = dt.getFullYear();
//						var mm = dt.getMonth();
//						
//						mm = mm + Number(_o['CAND_PERIOD_VALUE']);
//						if (mm > 12) {
//							yyyy = yyyy + parseInt(mm / 12, 10);
//							mm = mm - 12;
//						}
////						mm = mm -1;
//
//						var dd = dt.getDate();
//						varDate = new Date(yyyy, mm);
//						break;
//					default:
//						var yyyy = dt.getFullYear();
//						var mm = dt.getMonth()-1;
//						var dd = dt.getDate() + Number(_o['CAND_PERIOD_VALUE']);
//						if(mm < 0 ) mm = 0;
//						varDate = new Date(yyyy, mm, dd);
//					}
////					switch(_o['CAND_PERIOD_BASE']) {
////					case 'YEAR':
////						var yyyy = dt.getFullYear() + Number(_o['CAND_PERIOD_VALUE']);
////						var mm = dt.getMonth();
////						var dd = dt.getDate();
////						varDate = new Date(yyyy,mm,dd)/*.format(formatString)*/;
////						break;
////					case 'MONTH':
////						var yyyy = dt.getFullYear();
////						var mm = dt.getMonth() + 1;
////						
////						mm = mm + Number(_o['CAND_PERIOD_VALUE']);
////						if (mm > 12) {
////							yyyy = yyyy + parseInt(mm / 12, 10);
////							mm = mm - 12;
////						}
////						mm = mm -1;
////
////						var dd = dt.getDate();
////						varDate = new Date(yyyy, mm)/*.format(formatString);*/;
////						
////						break;
//////					case 'DAY':
//////						var yyyy = dt.getFullYear();
//////						var mm = dt.getMonth();
//////						var dd = dt.getDate() + Number(_o['CAND_PERIOD_VALUE']);
//////						varDate = new Date(yyyy, mm, dd)/*.format(formatString)*/
//////						break;
////					default:
////						var yyyy = dt.getFullYear();
////						var mm = dt.getMonth();
////						var dd = dt.getDate() + Number(_o['CAND_PERIOD_VALUE']);
////						varDate = new Date(yyyy, mm, dd);
////						break;
////					}
//				}
				
//				var defaultval = _o['DEFAULT_VALUE'].toString().replace("/-/g","");
//				DefaultDate = typeof DefaultDate == "undefined" ? varDate : DefaultDate;
				var DefaultDate = varDate;
				var calendarBox = $('#' + condid).dxDateBox({
				    min: new Date(2000,1,1),
				    max: new Date(2999,12,31),
				    firstDayOfWeek: 0,
				    acceptCustomValue: false,
				    showClearButton: false,
				    width: (conditionWidth + 'px'),
				    height : 29,
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
				/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
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
				$('<div id="' + condid + '_spacer" class="condition-item" style="margin: 7px 3px 0 3px; font-weight:bold;"> ~ </div>').appendTo($('#'+condid));
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
//				if(fromMeta['DEFAULT_VALUE']!="" && fromMeta['CAND_DEFAULT_TYPE']=="QUERY"){
//					switch(fromMeta['CAPTION_FORMAT']) {
//					case 'yyyy':
//					case 'yyyy년':
//						DefaultDate = new Date(fromMeta['DEFAULT_VALUE'][0].toString());
//						
//						break;
//					case 'yyyyMM':
//					case 'yyyy-MM':
//					case 'yyyy년MM월':	
//						DefaultDate = new Date(fromMeta['DEFAULT_VALUE'][0].toString());
//						break;
//					default:
//						var parseDate = fromMeta['DEFAULT_VALUE'][0].toString();
//						var y =parseDate.substr(0,4),m = parseDate.substr(4,2)-1,d = parseDate.substr(6,2);
//						DefaultDate = new Date(y,m,d);
//						break;
//					}
//				}
				
				if(fromMeta['DEFAULT_VALUE']!=""&&fromMeta['CAND_DEFAULT_TYPE']=="QUERY"){
					var parseDate = fromMeta['DEFAULT_VALUE'][0].toString();
					var y =parseDate.substr(0,4),m = parseDate.substr(4,2),d = parseDate.substr(6,2);
//					if(m.length <=0 || m < 0) m='1';
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
				
//				switch(fromMeta['CAND_PERIOD_BASE']) {
//				
//				case 'YEAR':
//					var yyyy = dt.getFullYear() + Number(fromMeta['CAND_PERIOD_VALUE']);
//					var mm = dt.getMonth();
//					var dd = dt.getDate();
//					varDate = new Date(yyyy, mm, dd)/*.format(formatString)*/;
//					break;
//					
//				case 'MONTH':
//					var yyyy = dt.getFullYear();
//					var mm = dt.getMonth();
//					
//					mm = mm + Number(fromMeta['CAND_PERIOD_VALUE']);
//					if (mm > 12) {
//						yyyy = yyyy + parseInt(mm / 12, 10);
//						mm = mm - 12;
//					}
//					mm = mm -1;
//
//					var dd = dt.getDate();
//					varDate = new Date(yyyy, mm, dd)/*.format(formatString)*/;
//					break;
////				case 'DAY':
////					var yyyy = dt.getFullYear();
////					var mm = dt.getMonth();
////					var dd = dt.getDate() + Number(fromMeta['CAND_PERIOD_VALUE']);
////					varDate = new Date(yyyy, mm, dd)/*.format(formatString)*/
////					break;
//				default:
//					var yyyy = dt.getFullYear();
//					var mm = dt.getMonth()-1;
//					var dd = dt.getDate() + Number(fromMeta['CAND_PERIOD_VALUE']);
//					varDate = new Date(yyyy, mm, dd)
//				}
				switch(fromMeta['CAND_PERIOD_BASE']) {
				case 'YEAR':
					//2020.02.12 mksong 비트윈 달력 파라미터 전달 오류 수정 dogfoot
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
					//2020.02.12 mksong 비트윈 달력 파라미터 전달 오류 수정 dogfoot
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
						
//						mm = mm -1;
					}
					var dd = dt.getDate();
					/*DOGFOOT cshan 20200113 - between 캘린더 CS와 일자 값이 다른 오류 수정*/
					varDate = new Date(yyyy, mm,dd);
					break;
				default:
					var yyyy = dt.getFullYear();
					var mm = dt.getMonth()-1;
					//2020.02.12 mksong 비트윈 달력 파라미터 전달 오류 수정 dogfoot
					var dd;
					if(fromMeta.getDefault){
						dd = fromMeta.DEFAULT_VALUE[0];	
					}else{
						dd = dt.getDate() + Number(fromMeta['CAND_PERIOD_VALUE']);							
					}
					
					if(mm < 0 ) mm = 0;
					varDate = new Date(yyyy, mm, dd);
				}
				
//				DefaultDate = DefaultDate == "" ? varDate : DefaultDate;
				// DOGFOOT 20200206 cshan - between 일때는 각 입력창의 사이즈를 필터의 사이즈 /2 로 표기
				var calendarBoxFr = $('#' + condidFr).dxDateBox({
				    min: new Date(2000,1,1),
				    max: new Date(2999,12,31),
				    firstDayOfWeek: 0,
				    acceptCustomValue: false,
				    showClearButton: false,
				    width: ((conditionWidth/2) + 'px'),
				    height : 29,
				    value: varDate,
				    displayFormat: formatString,
				    maxZoomLevel: zoomLevel,
				    onFocusOut: function(_e) {
				    	if (_e.component.option('value') === null) {
				    		WISE.alert(gMessage.get('WISE.message.page.condition.date.invalid',[fromMeta['PARAM_CAPTION']])); // 이(가) 날짜형식이 아닙니다.
				    	}
				    },
//				    onValueChanged: function(_e){

//						var values = _e.value;
//						var varDate = new Date(values);
//						if(new Date(varDate) != 'Invalid Date'){
//							values = varDate.format(fromMeta['CAPTION_FORMAT']);
//							_e.component.option('value',values);
//						}
//					},
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
				/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
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
//				if(toMeta['DEFAULT_VALUE']!="" && toMeta['CAND_DEFAULT_TYPE']=="QUERY"){
//					switch(toMeta['CAPTION_FORMAT']) {
//					case 'yyyy':
//					case 'yyyy년':
//						DefaultDate = new Date(toMeta['DEFAULT_VALUE'][1].toString());
//						break;
//					case 'yyyyMM':
//					case 'yyyy-MM':
//					case 'yyyy년MM월':	
//						DefaultDate = new Date(toMeta['DEFAULT_VALUE'][1].toString());
//						break;
//						default:
//							var parseDate = toMeta['DEFAULT_VALUE'][1].toString();
//							var y =parseDate.substr(0,4),m = parseDate.substr(4,2)-1,d = parseDate.substr(6,2);
//							DefaultDate = new Date(y,m,d);
//							break;
//					}
//				}
				
				if(toMeta['DEFAULT_VALUE']!=""&&toMeta['CAND_DEFAULT_TYPE']=="QUERY"){
					var parseDate = toMeta['DEFAULT_VALUE'][1].toString();
					var y =parseDate.substr(0,4),m = parseDate.substr(4,2),d = parseDate.substr(6,2);
//					if(m.length <= 0 || m < 0) m='1';
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
				
//				switch(toMeta['CAND_PERIOD_BASE']) {
//				case 'YEAR':
//					var yyyy = dt.getFullYear() + Number(toMeta['CAND_PERIOD_VALUE']);
//					var mm = dt.getMonth();
//					var dd = dt.getDate();
//					varDate = new Date(yyyy, mm, dd)/*.format(formatString)*/;
//					break;
//				case 'MONTH':
//					var yyyy = dt.getFullYear();
//					var mm = dt.getMonth() + 1;
//					
//					mm = mm + Number(toMeta['CAND_PERIOD_VALUE']);
//					if (mm > 12) {
//						yyyy = yyyy + parseInt(mm / 12, 10);
//						mm = mm - 12;
//					}
//					mm = mm -1;
//
//					var dd = dt.getDate();
//					varDate = new Date(yyyy, mm, dd)/*.format(formatString)*/;
//					break;
////				case 'DAY':
////					var yyyy = dt.getFullYear();
////					var mm = dt.getMonth();
////					var dd = dt.getDate() + Number(toMeta['CAND_PERIOD_VALUE']);
////					varDate = new Date(yyyy, mm, dd)/*.format(formatString)*/
////					break;
//				default:
//					var yyyy = dt.getFullYear();
//					var mm = dt.getMonth()-1;
//					var dd = dt.getDate() + Number(toMeta['CAND_PERIOD_VALUE']);
//					varDate = new Date(yyyy, mm, dd)
//				}
				
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
					/*DOGFOOT cshan 20200113 - between 캘린더 CS와 일자 값이 다른 오류 수정*/
					varDate = new Date(yyyy, mm,dd);
					break;
				default:
					var yyyy = dt.getFullYear();
					var mm = dt.getMonth()-1;
					var dd = dt.getDate() + Number(toMeta['CAND_PERIOD_VALUE']);
					varDate = new Date(yyyy, mm, dd);
				}
				
//				DefaultDate = DefaultDate == "" ? varDate : DefaultDate;
				// DOGFOOT 20200206 cshan - between 일때는 각 입력창의 사이즈를 필터의 사이즈 /2 로 표기
				var calendarBoxTo = $('#' + condidTo).dxDateBox({
				    min: new Date(2000,1,1),
				    max: new Date(2999,12,31),
				    firstDayOfWeek: 0,
				    acceptCustomValue: false,
				    showClearButton: false,
				    width: ((conditionWidth/2) + 'px'),
				    height : 29,
				    value: varDate,
				    displayFormat: formatString,
				    maxZoomLevel: zoomLevel,
				    onFocusOut: function(_e) {
				    	if (_e.component.option('value') === null) {
				    		WISE.alert(gMessage.get('WISE.message.page.condition.date.invalid',[toMeta['PARAM_CAPTION']])); // 이(가) 날짜형식이 아닙니다.
				    	}
				    },
				    onValueChanged: function(_e){
//						var values = _e.value;
//						var varDate = new Date(values);
//						if(new Date(varDate) != 'Invalid Date'){
//							values = varDate.format(fromMeta['CAPTION_FORMAT']);
////							_e.value = values;
//							_e.component.option('value',values);
//						}
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
				/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
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
						/* DOGFOOT mksong 필터 css 수정 20200210 */
						height : 28,
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
						/* DOGFOOT ktkang 리스트 필터 데이터 길이가 엄청 길면 그만큼 사이즈가 늘어남..max값을 정해줌  20200110 */
					} else if(parseInt(conditionWidth) < 500 && textMaxLength > 500) {
						textMaxLength = 500;
					}
					
					$('#' + popoverid+'_space').css('width', (textMaxLength + 'px'));
					
					var initilizing = true;
					var selectionMode, fnOnSelectionChanged;
					
					if (_o['MULTI_SEL'] === 'N') {
						selectionMode = 'single';
						
						// 2020.01.07 mksong 단일선택 필터 전체항목 추가 dogfoot
						if(_o['ALL_YN'] === 'Y'){
							comboData = [gMessage.get('WISE.message.page.widget.selectbox.common.all')].concat(comboData);
						}
						
						fnOnSelectionChanged = function(_e) {
							swit = true;
							
							_data = self.parameterQueryHandler.parameterDataSet[_o['PARAM_NM']];
							
							
					    	selectListBox.option('value', _e.addedItems);
					    	var paramData = selectListBox.option('wiseParamData');
					    	
					    	//self.parameterQueryHandler.setParameterValue(_o, valueListPanel.option('selectedItems'));
							//self.parameterQueryHandler.queryAll(_o['PARAM_NM']);
							
						
//					    	var onQuery = this.option('wiseOnQuery');
//					    	if (!initilizing && onQuery !== 'Y' && _o['DATASRC_TYPE'] === 'QUERY') {
//					    	if (!initilizing) {
//					    		var addedValue = [];
//					    		_.each(_e.addedItems, function(_d) {
//					    			//addedValue.push(getListValue(_data,_d));
//					    			if(paramData === undefined)
//					    				addedValue.push(getListValue(_data,_d));
//					    			else
//					    				addedValue.push(getListValue(paramData,_d));
//					    		});
//					    		
//					    		self.parameterQueryHandler.setParameterValue(_o, addedValue);
//					    		self.parameterQueryHandler.queryAll(_o['PARAM_NM']);
//					    	}
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
					    	//var isRemoved = _e.removedItems.length > 0;
					    	
					    
					    	
					    	if (isAdded) {
					    		if(WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] == false){
					    			WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] = [];
						    	}
					    		
					    		//WISE.util.Array.concatDistinct(WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']], addedItems);
					    	}
					    	
					    	WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] = addedItems;
					    	/* DOGFOOT ktkang 주제영역보고서 저장하고 바로 불러올 때 오류 수정  20200704 */
					    	if(_e.component.option('dataSource')._items.length == addedItems.length){
					    		selectListBox.option('value', '전체');
					    	}else{
					    		selectListBox.option('value', WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']].join(','));
					    	}
					    	
					    	//if (isRemoved) {
					    		//canNotQueryEvent = this.option('canNotQuery');
						    	
					    	//	WISE.libs.Dashboard.ConditionItem.selectedItems[_o['PARAM_NM']] = isAdded
					    	//}
				
					    	
					    	
					    	//var onQuery = this.option('wiseOnQuery');
					    	
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
					   // onItemClick: fnOnSelectionChanged,
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
							//2020.01.21 mksong 보고서 열기 오류 수정 dogfoot
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
							//2020.01.21 mksong 보고서 열기 오류 수정 끝 dogfoot
						}
						/*
						if(swit){
							if (!valueListPanel.option('readyToOpen') && $('#' + popoverid+'_space').is(':visible')) {
								$('#' + popoverid+'_space').hide();
								if(_o['SEARCH_YN'] == 'Y'){
									$('#'+searchID+'Panel').hide();
								}
							}
						
						}*/
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
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
					selectListBox.option('wiseOperation', _o['OPER']);
//					selectListBox.option('wiseKeyColumn', _o['KEY_VALUE_ITEM']);
//					selectListBox.option('wiseCaptionColumn', _o['CAPTION_VALUE_ITEM']);
					selectListBox.option('wiseKeyColumn', _o['DATASRC_TYPE'] == 'TBL'? 'KEY_VALUE':_o['KEY_VALUE_ITEM']);
					selectListBox.option('wiseCaptionColumn', _o['DATASRC_TYPE'] == 'TBL'? 'CAPTION_VALUE':_o['CAPTION_VALUE_ITEM']);
					selectListBox.option('wiseOriginKeyColumn', _o['KEY_VALUE_ITEM']);
					selectListBox.option('wiseOriginCaptionColumn', _o['CAPTION_VALUE_ITEM']);
					selectListBox.option('wiseDataSrcType', _o['DATASRC_TYPE']);
					/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
					if(typeof _o['WISE_CUBE_UNI_NM'] == 'undefined') {
						var tbl = _o['WHERE_CLAUSE'].split('.')[0];
						var col = _o['WHERE_CLAUSE'].split('.')[1];
						//selectListBox.option('wiseCubeUniqueName', '[' + tbl + '].[' + col + ']');
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
			case 'LVL':
				var checkedItems = [];
				var products = [{
				    id: "Video Players",
				    text: "Video Players",
				    items: [{
				        id: "HD Video Player",
				        text: "HD Video Player",
				        items: [{
					        id: "Player",
					        text: "Player"
					    }, {
					        id: "SuperHD Player1",
					        text: "SuperHD Player"
					        
					    }]
				    }, {
				        id: "SuperHD Video Player",
				        text: "SuperHD Video Player",
				        items: [{
					        id: "HD Video",
					        text: "HD Video Player"
					    }, {
					        id: " Video Player",
					        text: "SuperHD Video Player"
					        
					    }]
				        
				    }]
				}, {
				    id: "1_1_2",
				    text: "Televisions",
				    expanded: true,
				    items: [{
				        id: "1_1_2_1",
				        text: "SuperLCD 42",
				        price: 1200
				    }, {
				        id: "1_1_2_2",
				        text: "SuperLED 42",
				        price: 1450
				    }, {
				        id: "1_1_2_3",
				        text: "SuperLED 50",
				        price: 1600
				    }, {
				        id: "1_1_2_4",
				        text: "SuperLCD 55",
				        price: 1350
				    }, {
				        id: "1_1_2_5",
				        text: "SuperLCD 70",
				        price: 4000
				    }]
				}, {
				    id: "1_1_4",
				    text: "Projectors",
				    items: [{
				        id: "1_1_4_1",
				        text: "Projector Plus",
				        price: 550
				    }, {
				        id: "1_1_4_2",
				        text: "Projector PlusHD",
				        price: 750
				    }, {
				        id: "1_1_4_3",
				        text: "Projector PlusHD",
				        price: 750
				    }, {
				        id: "1_1_4_4",
				        text: "Projector PlusHD",
				        price: 750
				    }, {
				        id: "1_1_4_5",
				        text: "Projector PlusHD",
				        price: 750
				    }, {
				        id: "1_1_4_6",
				        text: "Projector PlusHD",
				        price: 750
				    }]
				}];
				
				self.parameterQueryHandler.queryParameter(_o);
				var paramData = self.parameterQueryHandler.parameterDataSet[_o['PARAM_NM']];
				var dataKey = [];
				
				for (var key in paramData[0]) {
					dataKey.push(key);
				}
				dataKey.sort();
				var sqlConfig = []; 
				sqlConfig.SelectDistinct = [];
				sqlConfig.SelectDistinct.push(dataKey[0]);
				sqlConfig.From = paramData;
				
				var lvlData = new Array();
				
				var lvlRootData = SQLike.q(sqlConfig);
		
				for (var item in lvlRootData)
				{
					 
					 var tmpData = new Object();
					 for (var rootItem in lvlRootData[item])
					 {
						tmpData.id = rootItem;
						tmpData.text = lvlRootData[item][rootItem];
					 }
					
					 var whereClause = [];
						sqlConfig = []; 
						sqlConfig.SelectDistinct = [];
						sqlConfig.SelectDistinct.push(dataKey[2]);
						sqlConfig.From = paramData;
						whereClause.push('this.'+dataKey[0]+' == "'+ tmpData.text+'"');
						sqlConfig.Where =  function(_a) {
							
							return this.SPANISHPRODUCTCATEGORYNAME == tmpData.text; 
						};
							
					var nextData = SQLike.q(sqlConfig);
					lvlData.push(tmpData);
					if (nextData.length > 0)
					{
						var chLvlData = new Array();
						for (var chItem in nextData)
						{
							var chTmpData = new Object();
							 for (var chItem1 in nextData[chItem])
							 {
								 chTmpData.id = chItem1;
								 chTmpData.text = nextData[chItem][chItem1];
							 }
							 chLvlData.push(chTmpData);
						}
						
						//tmpData.items.push(nextData);
					}
					tmpData.items = chLvlData;
				}
				var selectListBox = $('#' + condid).dxTextBox({
					width: (conditionWidth + 'px'),
					height : 29,
//					placeholder: gMessage.get('WISE.message.page.widget.selectbox.common.placeholder'),
					value : gMessage.get('WISE.message.page.widget.selectbox.common.all'),
					showClearButton: true,
					readOnly: false,
//					onFocusIn: function(_e) {
//						_e.component.blur();
//					},
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
						
						clearComboData();
					}
				});
				
				$('#' + condid).attr('style', 'cursor: pointer !important;');
				
				var valueListPanel, defaultValueIndex;
				
				var popoverid = condid + '_popover';
				var popoverHtml = '<div id="' + popoverid + '" class="dx-list-multi-select-panel dx-list-hack"></div>';
				$('body').append(popoverHtml);
				
				var listTopGap = 0;
				if (_o['MULTI_SEL'] === 'Y' && _o['ALL_YN'] == 'Y') {
					
				}
				var valueListPanel = $('#' + popoverid).dxTreeView({ 
			        items: lvlData,
			        width: 320,
			        height : 29,
			        showCheckBoxesMode: "normal",
			       /* onItemSelectionChanged: function(e) {
			            var item = e.node;
			    
			            if(isProduct(item)) {
			                processProduct($.extend({
			                    category: item.parent.text
			                }, item));
			            } else {
			                $.each(item.items, function(index, product) {
			                    processProduct($.extend({
			                        category: item.text
			                    }, product));
			                });
			            }
			            checkedItemsList.option("items", checkedItems);
			        },
			        itemTemplate: function(data) {
			            return "<div>" + data.text + 
			                ((data.price) ? (" ($" + data.price + ")") : "") + 
			                "</div>";
			        }*/
			    }).dxTreeView("instance");
			    
			    var checkedItemsList = $("#checked-items").dxList({
			        width: 400,
			        height : 29,
			        items: checkedItems,
			        itemTemplate: function(data) {
			            return "<div>" + data.text + " (" +
			                data.category + ") </div>";
			        }
			    }).dxList("instance");
			    
//			    function isProduct(data) {
//			        return !data.items.length;
//			    }
//			    
//			    function processProduct(product) {
//			        var itemIndex = -1;
//			    
//			        $.each(checkedItems, function (index, item) {
//			            if (item.key === product.key) {
//			                itemIndex = index;
//			                return false;
//			            }
//			        });
//			    
//			        if(product.selected && itemIndex === -1) {
//			            checkedItems.push(product);
//			        } else if (!product.selected){
//			            checkedItems.splice(itemIndex, 1);
//			        }    
//			    }
			    
				$('#' + condid)
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
			
				$("#" + popoverid+'_space')
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

				selectListBox.option('wiseUniqueName', _o['UNI_NM']);
				selectListBox.option('wiseParameterType', _o['PARAM_TYPE']);
				//selectListBox.option('wiseSelectionMode', selectionMode); // multi, single
				selectListBox.option('wiseParamCaption', WISE.util.String.trim(_o['PARAM_CAPTION']||''));
				selectListBox.option('wiseParamName', _o['PARAM_NM']);
				selectListBox.option('wiseVisible', _o['VISIBLE']);
				selectListBox.option('wiseDefaultValue', _o['DEFAULT_VALUE']+'');
				selectListBox.option('wiseDataType', _o['DATA_TYPE']);
				selectListBox.option('wiseSortType', _o['SORT_TYPE']);
				selectListBox.option('wiseWhereClause', _o['WHERE_CLAUSE']);
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				selectListBox.option('wiseOperation', _o['OPER']);
				selectListBox.option('wiseKeyColumn', _o['KEY_VALUE_ITEM']);
				selectListBox.option('wiseCaptionColumn', _o['CAPTION_VALUE_ITEM']);
				selectListBox.option('wiseQueriedData', lvlData);
				/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
				if(typeof _o['WISE_CUBE_UNI_NM'] == 'undefined') {
					var tbl = _o['WHERE_CLAUSE'].split('.')[0];
					var col = _o['WHERE_CLAUSE'].split('.')[1];
					selectListBox.option('wiseCubeUniqueName', '[' + tbl + '].[' + col + ']');
				} else {
					selectListBox.option('wiseCubeUniqueName', _o['WISE_CUBE_UNI_NM']);
				}
				
			    self.parameterQueryHandler.elementBasket.push(condid + ':dxTextBox');

			    
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
				$('<div id="' + condid + '_spacer" class="condition-item" style="margin: 7px 3px 0 3px; font-weight:bold;"> ~ </div>').appendTo($('#'+condid));
				$('<div id="' + condidTo + '" class="condition-item"></div>').appendTo($('#'+condid));
				
				var generateBETComboList = function(_id,_data,_idx) {
//					condid = _id;
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
					    			//addedValue.push(getListValue(_data,_d));
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
//							selectListBox.option('value', selectedValue);
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
//					fromMeta['ORG_PARAM_NM'] = self.meta['PARAM_NM'];
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
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
					selectListBox.option('wiseOperation', _o['OPER']);
					selectListBox.option('wiseKeyColumn', _o['KEY_VALUE_ITEM']);
					selectListBox.option('wiseCaptionColumn', _o['CAPTION_VALUE_ITEM']);
					selectListBox.option('wiseQueriedData', comboData);
					selectListBox.option('wiseOrgParamName', _o['PARAM_NM']);
					/* DOGFOOT ktkang 주제영역으로 만든 보고서 불러오기 후 필터 에러 수정  20200310 */
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
			
			// DOGFOOT shlim 마지막 필터 리스트 UI 위치 변경 20200308
			if (_k === parameterArray.length - 1) {
//				self.totalConditionWidth = self.totalConditionWidth + (parameterArray.length * self.CUSTOMIZED.get('gap')) + 80;
				self.totalConditionWidth = self.totalConditionWidth + (parameterArray.length * 15) + 80;
				self.resize();
			}
			
		}); // end of $.each(parameterArray
		gDashboard.totalConditionBuffer.push(
			{
				reportId:self.reportId, 
				totalConditionWidth : self.totalConditionWidth,
				parameterQueryHandler : self.parameterQueryHandler,
//				elementBasket:parameterQueryHandler.elementBasket, 
//				parameterDataSet:parameterQueryHandler.parameterDataSet,
//				parameterValues : parameterQueryHandler.parameterValues
			}
		);
		
		//2020.03.06 mksong setDataSetInfo 호출 dogfoot
		if(WISE.Constants.editmode == 'designer'){
			//2020.03.08 MKSONG 데이터 집합 수정시 원래대로 돌아가는 오류 수정 DOGFOOT
			if(!_editDataSet){
				gDashboard.reportUtility.setDataSetInfo();	
			}
		}
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
	this.getConditionWidget = function(_o) {
		var pid, dxItem, widget;
		if ($.type(_o) === 'string') {
			pid = _o.split(':')[0];
			dxItem = _o.split(':')[1];
			widget = $('#' + pid)[dxItem]('instance');
		}
		return {pid: pid, dxItem: dxItem, widget: widget};
	};
	this.getCalendarValue = function(_widget) {
		var val = _widget.option('value');
		
		if ($.type(val) === 'date') {
			var keyFormatString = _widget.option('wiseKeyFormatString') || 'yyyyMMdd';
			val = val.format(keyFormatString);
		}

		if (!val || val == null || val === '' || val.toLowerCase() === 'NULL') {
			val = '_EMPTY_VALUE_';
		}
		else {
			val = val + '';
		}
		return val;
	};
	
	this.getListValue = function(_widget){
		var val = _widget.option('value');
		if (!val || val == null || val === '') {
			val = '_EMPTY_VALUE_';
		}
		else if (val == gMessage.get('WISE.message.page.widget.selectbox.common.all')){
//			val = _widget.option('wiseWhereClause');
			val = '_ALL_VALUE_'
		}
		else {
			val = val + '';
		}
		return val;
	};
	
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
	
	this.getBetweenListValues = function(_widget) {
		var betweenListValue, valbasten = [];
		var fr, to, orgParamName = _widget.option('wiseOrgParamName').replace(/\@/,'');
		/* DOGFOOT 20200206 cshan - 뷰어에서 between 캘린더 오류 수정*/
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
				if(_el.indexOf(orgParamName+'_query_view_to') >-1){
					to = _el;
					return false;
				}
			}
		});
		
		var frO = self.getConditionWidget(fr);
		var toO = self.getConditionWidget(to);

		var frVal = self.getListValue(frO.widget);
		var toVal = self.getListValue(toO.widget);
		
		valbasten.push(frVal);
		valbasten.push(toVal);
		var pnm = '';
		if (page[page.length - 1] === 'viewer.do') {
			if( _widget.option('wiseParamName').replace(/\@/,'').indexOf('_fr') > -1)
				pnm = orgParamName +'_'+self.reportId+ '_fr';
			else
				pnm = orgParamName +'_'+self.reportId+ '_to';
		}else{
			pnm = _widget.option('wiseParamName').replace(/\@/,'');
		}
//		var pnm = _widget.option('wiseParamName').replace(/\@/,'');
		if (fr.indexOf(pnm) > -1) betweenListValue = frVal;
		if (to.indexOf(pnm) > -1) betweenListValue = toVal;
		return {valbasten:valbasten, betweenListValue:betweenListValue};
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
//					valbasten.push(_o.option('wiseDefaultValue'));
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
			/*
			valObj[paramName] = {
				"name": _o.option('wiseParamCaption'),
				"value": valbasten, 
				"type": _o.option('wiseDataType'), 
				"defaultValue": _o.option('wiseDefaultValue'), 
				"whereClause": _o.option('wiseWhereClause'),
				"parameterType": _o.option('wiseParameterType')
			};*/
			
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
	
	//2020.03.16 MKSONG 보고서 필터 기본값 변경 DOGFOOT
	this.setDefaultValueByValue = function() {
		var paramObj = self.getValue();
		$.each(self.parameterInformation,function(_key,_parameterInfo){
			$.each(paramObj,function(_key2,_paramObj){
				if(_key == _key2){
					var value = '';
					if(_paramObj.value.length > 1){
						$.each(_paramObj.value,function(_k,_value){
							if(_k != _paramObj.value.length-1){
								value += _value+',';	
							}else{
								value += _value;
							}
						});
					}else{
						value = _paramObj.value[0];
					}
					_parameterInfo.DEFAULT_VALUE = value == '_EMPTY_VALUE_' ? '' : value ;
					_parameterInfo.DEFAULT_VALUE_USE_SQL_SCRIPT = 'N';
				}
			});	
		});
	}
};
