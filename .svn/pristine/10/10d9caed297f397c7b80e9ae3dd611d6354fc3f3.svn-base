/* DOGFOOT ktkang 필터 필수 항목 체크 20191219 */
WISE.libs.Dashboard.FieldFilter = function() {
	var self = this;
	this.queryHandler;
	this.parameterFilterBar;
	this.parameterQueryHandler;
	this.parameterInformation = {};
	/*DOGFOOT cshan 20200113 - 필터 링크된 필터 변경시 오류 수정*/
	this.dataSourceparameterInformation = {};
	this.tempParam;
	this.type = 'CONDITION';
	this.paramPrefix = 'param_';
	this.filterIndex = 1;
	
	this.addFilter = function(_o) {
		self.parameterFilterBar = gDashboard.parameterFilterBar;
		self.parameterQueryHandler = self.parameterFilterBar.parameterQueryHandler;
		
		/* DOGFOOT ktkang 주제영역 연결되어있는 차원 필터로 올리는 기능 오류 수정   20200219 */
		var uname = _o.attr('cubeuninm');
		
		var cube_uname = uname.split('.')[0];
		var cubeParamInfo;
		/* DOGFOOT ktkang 주제영역 필터 올릴 때 데이터 타입 설정  20200309 */
		var ds_id;
		var fromparam ={
			'cube_id':gDashboard.dataSourceManager.datasetInformation[_o.attr('data-source-id')].DATASRC_ID,
			'uni_nm':uname
		};
		$.ajax({
			type : 'post',
			data:fromparam,
			async:false,
			url : WISE.Constants.context + '/report/condition/cubeUniName.do',
			success: function(_data) {
				if(Object.keys(_data).length != 0) {
				/* DOGFOOT ktkang 주제영역 연결되어있는 차원 필터로 올리는 기능 오류 수정   20200212 */
					if(typeof _data.uni_nm != 'undefined' && _data.uni_nm != null) {
						uname = _data.uni_nm;
					}
					
					if(Object.keys(_data.cubeTableColList).length != 0) {
						cubeParamInfo = _data.cubeTableColList[0];
					}
					/* DOGFOOT ktkang 주제영역 필터 올릴 때 데이터 타입 설정  20200309 */
					ds_id = _data.ds_id;
				}
			}
		});
		/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
		var caption = _o.attr('UNI_NM').trim();
		var regExp = /[\[\]]/gi;
		var tableNm = uname.split('.')[0].replace(regExp, "");
		/* DOGFOOT ktkang 주제영역 필터 기본값 추가 기능  20200207 */
		var columnNm = uname.split('.')[1].replace(regExp, "");
		var paramNm = cubeParamInfo.logicalTableName.replace(regExp, "")+columnNm;
		/* DOGFOOT ktkang 주제영역 데이터 드래그로 필터 올리기 기능 수정  20191212 */
		/*dogfoot shlim 20210419*/
		if(self.isDuplicatedFilter(paramNm)) return false;
		
		/* DOGFOOT ktkang KERIS 년도, 년월일 때 기본값 오늘기준으로 자동 입력   20200228 */
		var defaultValue = "[All]";
		var defaultVauleUseSqlScript = "N";
		/* DOGFOOT ktkang 주제영역 필터 유형 추가  20200806 */
		var paramType = 'LIST';
		var formatString = "";
		var candDefaultType = "";
		var oper = "In";
		if(cubeParamInfo.noLoading == 2) {
			paramType = 'INPUT';
		} else if(cubeParamInfo.dateKey != 0) {
			paramType = 'BETWEEN_CAND';
			if(cubeParamInfo.dateKey == 1) {
				formatString = 'yyyyMMdd';
			} else if(cubeParamInfo.dateKey == 2) {
				formatString = 'yyyy-MM-dd';
			} else if(cubeParamInfo.dateKey == 3) {
				formatString = 'yyyyMM';
			} else if(cubeParamInfo.dateKey == 4) {
				formatString = 'yyyy-MM';
			} else if(cubeParamInfo.dateKey == 5) {
				formatString = 'yyyy';
			}
			defaultValue = [];
			var dateNow = new Date();
			dateNow = dateNow.format(formatString);
			defaultValue.push(dateNow);
			defaultValue.push(dateNow);
			candDefaultType = "NOW";
			oper = "Between";
		}
//		if(caption.indexOf('년도') > -1) {
//			defaultValue = "select to_char(sysdate, 'yyyy') from dual";
//			defaultVauleUseSqlScript = "Y";
//		} else if(caption.indexOf('년월') > -1) {
//			defaultValue = "select to_char(sysdate, 'yyyyMM') from dual";
//			defaultVauleUseSqlScript = "Y";
//		}
		
		/* DOGFOOT ktkang 주제영역 필터 올리는 기능 오류 수정  20200120 */
		self.tempParam = {
		/* DOGFOOT ktkang 주제영역 필터 올릴 때 데이터 타입 설정  20200309 */
			DS_ID: ds_id,
			DS_TYPE: 'DS',
			PARAM_TYPE: paramType,
			DATASRC_TYPE: "TBL",
			DATASRC: tableNm,
			/* DOGFOOT ktkang 주제영역 필터 기본값 추가 기능  20200207 */
			KEY_VALUE_ITEM: cubeParamInfo.physicalColumnKey,
			/*dogfoot 주제영역 measure 필터 오류 수정 shlim 20201208*/
//			CAPTION_VALUE_ITEM: cubeParamInfo.physicalColumnName,
			CAPTION_VALUE_ITEM: cubeParamInfo.physicalColumnName != "" ? cubeParamInfo.physicalColumnName : cubeParamInfo.physicalColumnKey,
			ALL_YN :  'Y',
			CAND_DEFAULT_TYPE: candDefaultType,
			/*dogfoot 캘린더 기간 설정 shlim 20210427*/
			CAND_MAX_GAP: '0',
			CAND_PERIOD_BASE: "",
			CAND_PERIOD_VALUE: "",
			CAPTION_FORMAT: formatString,
			DATA_TYPE: "STRING",
			/* DOGFOOT ktkang KERIS 년도, 년월일 때 기본값 오늘기준으로 자동 입력   20200228 */
			DEFAULT_VALUE: defaultValue,
			DEFAULT_VALUE_USE_SQL_SCRIPT: defaultVauleUseSqlScript,
			HIDDEN_VALUE: "",
			KEY_FORMAT: formatString,
			MULTI_SEL: "Y",
			OPER: oper,
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			ORDER: Object.keys(gDashboard.parameterFilterBar.parameterInformation).length + 1,
			PARAM_CAPTION: caption,
//			PARAM_NM: "@"+tableNm+columnNm,
			PARAM_NM: "@"+paramNm,
			SORT_TYPE: "ASC",
			UNI_NM: cube_uname + '.[' + cubeParamInfo.physicalColumnKey + ']',
			VISIBLE: "Y",
			/* goyong ktkang 2개이상 연결된 차원 필터 기본값 오류 수정  20210603 */
			WHERE_CLAUSE: cubeParamInfo.logicalTableName.replace(regExp, "") + '.' + cubeParamInfo.physicalColumnKey,
			WIDTH: 250,
			//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
			CAPTION_WIDTH_VISIBLE: 'N',
            CAPTION_WIDTH: 86.5,
			BIND_YN:'Y',
			/*dogfoot shlim 20210419*/
			SEARCH_YN:'Y',
			EDIT_YN:'Y',
			INPUT_EDIT_YN:'Y',
			LINE_BREAK:'N',/*dogfoot shlim 20210415*/
			RANGE_YN:'',
			RANGE_VALUE:'',
			DEFAULT_VALUE_MAINTAIN:'Y',
			TYPE_CHANGE_YN:'',
			/* DOGFOOT ktkang 주제영역 필터 기본값 추가 기능  20200207 */
			/*dogfoot 주제영역 차원 정렬 측정값 차원으로 변경시 오류 수정 shlim 20210408*/
			SORT_VALUE_ITEM : cubeParamInfo.orderBy != 'Null'? cubeParamInfo.orderBy :'Key Column' ,
			/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
			/*dogfoot 주제영역 차원 정렬 공백 제거  shlim 20210408*/
			ORDERBY_KEY: cubeParamInfo.orderBy.trim() === "Key Column" ? '' : cubeParamInfo.orderBy.trim() === "Name Column" ? '' : cubeParamInfo.orderBy.trim() == "Null" ? '': cubeParamInfo.orderBy.trim() ,
			WISE_CUBE_UNI_NM : uname
		};
		/*dogfoot shlim 20210415*/
		var reportInfo = gDashboard.structure.ReportMasterInfo;
		if(WISE.Constants.editmode != "viewer"){
			/*dogfoot shlim 20210420*/
			//$('.filter-item').empty();
			self.tempParam["ADD_FILTER"] = true;
		}else{
			self.tempParam["ADD_FILTER"] = true;
			//$(gDashboard.viewerParameterBars[reportInfo.id].state.element).empty();
		}
		/* DOGFOOT ktkang KERIS 년도, 년월일 때 기본값 오늘기준으로 자동 입력   20200228 */
		if(defaultVauleUseSqlScript == 'Y'){
		/* DOGFOOT ktkang 주제영역 필터 올릴 때 데이터 타입 설정  20200309 */
		var toparam ={
				'dsid': ds_id,
				'dstype': 'DS',
				/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
				'defaultSql': Base64.encode(defaultValue),
				'closYm': userJsonObject.closYm,
				'userId' : userJsonObject.userId
			};
			$.ajax({
				type : 'post',
				data:toparam,
				async:false,
				url : WISE.Constants.context + '/report/condition/defaultQueries.do',
				success: function(_data) {
					self.tempParam.HIDDEN_VALUE = defaultValue;
					self.tempParam.DEFAULT_VALUE = _data.data;
				}
			});
		}
		/* DOGFOOT ktkang 주제영역 연결되어있는 차원 필터로 올리는 기능 오류 수정  끝  20200212 */
		self.filterIndex++;
		self.parameterInformation[self.tempParam.PARAM_NM] = self.tempParam;
		
		gDashboard.parameterFilterBar.setParameterInformation(self.parameterInformation);
		
		/* DOGFOOT ktkang 주제영역 데이터 드래그로 필터 올리기 기능 수정  20191212 */
		gDashboard.structure.ReportMasterInfo.paramJson = [];
		/* DOGFOOT ktkang 뷰어에서 디자이너 이동 후 필터 추가하면 기존 필터 사라지는 오류 수정  20200818 */
		Object.keys(gDashboard.parameterFilterBar.parameterInformation).map(function(_i, _e) {
			gDashboard.structure.ReportMasterInfo.paramJson.push(gDashboard.parameterFilterBar.parameterInformation[_i]);
		});
		

		/*dogfoot shlim 20210415*/
		/* DOGFOOT ktkang 주제영역 필터 중복 오류 수정  20200705 */
		var paramTest = gDashboard.datasetMaster.utility.getParamArray(reportInfo.paramJson);
		gDashboard.datasetMaster.setState({ params: paramTest });

        switch (WISE.Constants.editmode) {
            case 'designer':
                gDashboard.parameterFilterBar.render({
                    element: $('#report-filter-item'),
                    params: gDashboard.datasetMaster.state.params,
                },true);/*dogfoot shlim 20210420*/
                break;
            case 'viewer':
          		  /*dogfoot shlim 20210415*/
            	filterBarElement = gDashboard.viewerParameterBars[reportInfo.id].state.element;
                //gDashboard.viewerParameterBars[reportInfo.id] = new WISE.libs.Dashboard.ParameterBar();
                gDashboard.viewerParameterBars[reportInfo.id].render({
                    element: filterBarElement,
                    params: gDashboard.datasetMaster.state.params,
                },true);
                break;
            default:
                gDashboard.parameterFilterBar.render({
                    element: $('.filter-item'),
                    params: gDashboard.datasetMaster.state.params,
                });
        }
		
		gProgressbar.hide();
	};
	/* DOGFOOT ktkang 단일 테이블 필터 올리는 부분 구현  20200717 */
	this.addFilterSingle = function(_o, singleTableDs) {
		self.parameterFilterBar = gDashboard.parameterFilterBar;
		self.parameterQueryHandler = self.parameterFilterBar.parameterQueryHandler;
		
		var caption = _o.attr('UNI_NM').trim();
		var filterItem;
		var uniNm;
		if(gDashboard.isNewReport) {
			$.each(singleTableDs.DATA_META, function(_i,_e){
				if(_e.COL_NM == caption) {
					filterItem = _e;
				/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201111 */
				} else if(_e.COL_CAPTION == caption) {
					filterItem = _e;
				}
			});
			uniNm = filterItem.UNI_NM;
		} else {
			$.each(singleTableDs.DATASET_JSON.DATA_SET.COL_ELEMENT.COLUMN, function(_i,_e){
				//20210122 AJKIM 단일테이블 캡션이랑 이름 다를 경우 필터로 사용할 수 없는 오0류 수정 DOGFOOT
				if(_e.COL_CAPTION == caption) {
					filterItem = _e;
				}
			});
			uniNm = "[" + filterItem.TBL_NM + "].[" +  caption + "]";
		}
		
		if(filterItem.DATA_TYPE === "cal" && filterItem.DATA_TYPE === "grp"){
			WISE.alert("계산된 컬럼은 매개변수로 사용할 수 없습니다.");
			gProgressbar.hide();
			return;
		}
		
		
		
		/*dogfoot shlim 20210419*/
		if(self.isDuplicatedFilter(paramNm)) return false;
		
		self.tempParam = {
			DS_ID: singleTableDs.DATASRC_ID,
			DS_TYPE: singleTableDs.DATASRC_TYPE,
			PARAM_TYPE: "LIST",
			DATASRC_TYPE: "TBL",
			DATASRC: filterItem.TBL_NM,
			/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201111 */
			KEY_VALUE_ITEM: filterItem.COL_NM,
			CAPTION_VALUE_ITEM: filterItem.COL_NM,
			ALL_YN :  'Y',
			CAND_DEFAULT_TYPE: "",
			/*dogfoot 캘린더 기간 설정 shlim 20210427*/
			CAND_MAX_GAP: "0",
			CAND_PERIOD_BASE: "",
			CAND_PERIOD_VALUE: "",
			//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
			CAPTION_WIDTH_VISIBLE: 'N',
            CAPTION_WIDTH: 86.5,
			CAPTION_FORMAT: "",
			DATA_TYPE: "STRING",
			DEFAULT_VALUE: "[All]",
			DEFAULT_VALUE_USE_SQL_SCRIPT: "N",
			HIDDEN_VALUE: "",
			KEY_FORMAT: "",
			MULTI_SEL: "Y",
			OPER: "In",
			ORDER: Object.keys(gDashboard.parameterFilterBar.parameterInformation).length + 1,
			PARAM_CAPTION: caption,
			PARAM_NM: "@"+filterItem.TBL_NM+filterItem.COL_NM,
			SORT_TYPE: "ASC",
			UNI_NM: uniNm,
			VISIBLE: "Y",
			WHERE_CLAUSE: 'A."' + filterItem.COL_NM + '"',
			WIDTH: 250,
			BIND_YN:'Y',
			SEARCH_YN:'N',
			EDIT_YN:'Y',
			INPUT_EDIT_YN:'Y',
			LINE_BREAK:'N',/*dogfoot shlim 20210415*/
			RANGE_YN:'',
			RANGE_VALUE:'',
			DEFAULT_VALUE_MAINTAIN:'Y',
			TYPE_CHANGE_YN:'',
			SORT_VALUE_ITEM : 'ASC',
			/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
			ORDERBY_KEY:'',
			WISE_CUBE_UNI_NM : filterItem.UNI_NM
		};
		
		/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
		if(gDashboard.datasetMaster.state.params.length > 0) {
			singleTableDs.DATASET_QUERY = singleTableDs.DATASET_QUERY + " AND A.\"" + filterItem.COL_CAPTION + "\" IN (@" +filterItem.TBL_NM+filterItem.COL_NM + ")";
			singleTableDs.SQL_QUERY = singleTableDs.SQL_QUERY + " AND A." + filterItem.COL_CAPTION + " IN (@" +filterItem.TBL_NM+filterItem.COL_NM + ")";
		} else {
			singleTableDs.DATASET_QUERY = singleTableDs.DATASET_QUERY + " WHERE A.\"" + filterItem.COL_CAPTION + "\" IN (@" +filterItem.TBL_NM+filterItem.COL_NM + ")";
			singleTableDs.SQL_QUERY = singleTableDs.SQL_QUERY + " WHERE A." + filterItem.COL_CAPTION + " IN (@" +filterItem.TBL_NM+filterItem.COL_NM + ")";
		}
 		
		self.filterIndex++;
		self.parameterInformation[self.tempParam.PARAM_NM] = self.tempParam;
		
		gDashboard.parameterFilterBar.setParameterInformation(self.parameterInformation);
		
		gDashboard.structure.ReportMasterInfo.paramJson = [];
		$.each(gDashboard.parameterFilterBar.parameterInformation, function(_i, _o) {
			gDashboard.structure.ReportMasterInfo.paramJson.push(_o);
		});
		

		$('.filter-item').empty();
		var reportInfo = gDashboard.structure.ReportMasterInfo;
		var paramTest = gDashboard.datasetMaster.utility.getParamArray(reportInfo.paramJson);
		gDashboard.datasetMaster.setState({ params: paramTest });

        switch (WISE.Constants.editmode) {
            case 'designer':
                gDashboard.parameterFilterBar.render({
                    element: $('#report-filter-item'),
                    params: gDashboard.datasetMaster.state.params,
                });
                break;
            case 'viewer':
            /*dogfoot shlim 20210415*/
            	filterBarElement = gDashboard.viewerParameterBars[reportInfo.id].state.element;
                gDashboard.viewerParameterBars[reportInfo.id] = new WISE.libs.Dashboard.ParameterBar();
                gDashboard.viewerParameterBars[reportInfo.id].render({
                    element: filterBarElement,
                    params: gDashboard.datasetMaster.state.params,
                });
                break;
            default:
                gDashboard.parameterFilterBar.render({
                    element: $('.filter-item'),
                    params: gDashboard.datasetMaster.state.params,
                });
        }
		
		gProgressbar.hide();
	};

	/* DOGFOOT ktkang 주제영역 데이터 드래그로 필터 올리기 기능 수정  20191212 */
	/*dogfoot shlim 20210419*/
	this.isDuplicatedFilter = function(paramNm) {
		var checker = false;
		var param = gDashboard.parameterFilterBar.parameterInformation;
		$.each(param, function(_i, _o) {
			/*dogfoot shlim 20210419*/
			if (_o['PARAM_NM'] === "@"+paramNm) {
				checker = true;
				/* DOGFOOT ktkang 주제영역에서 동일한 필터 두번 올렸을 때 경고창  20200205 */
				WISE.alert('이미 동일한 필터가 설정되어 있습니다.')
				gProgressbar.hide();
				return false;
			}
		});
		return checker;
	};
	
	this.resize = function() {
		var totalConditionWidth = 0;
		
		$.each($('.condition-item-container'), function(_i, _o) {
			totalConditionWidth += $(_o).width() + 10;
		});
		
		gDashboard.parameterFilterBar.totalConditionWidth = totalConditionWidth + 40;
		gDashboard.parameterFilterBar.resize();
	};
	
	var commonParamType = [
		{key:'LIST', caption:'리스트'},{key:'INPUT', caption:'입력창'},{key:'CAND', caption:'달력'}
	];
	/* DOGFOOT ktkang 필터 Between 삭제  20200727  */
	var commonOperationList = [{key:'In', caption:'In'},{key:'NotIn', caption:'NotIn'},{key:'Equals', caption:'Equals'}];
	var betweenParamType = [
		{key:'BETWEEN_LIST', caption:'between 리스트'},{key:'BETWEEN_INPUT', caption:'between 입력창'},{key:'BETWEEN_CAND', caption:'between 달력'}
	]
	/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
	this.editFilter = function(editDisignerParam, datasourceTarget, paramData, callback, directEdit) {
		if(!WISE.Context.isCubeReport){
			commonOperationList = [{key:'In', caption:'In'},{key:'NotIn', caption:'NotIn'},{key:'Equals', caption:'Equals'}];
		}else{
			commonOperationList = [{key:'In', caption:'In'},{key:'NotIn', caption:'NotIn'},{key:'Equals', caption:'Equals'}, {key: 'Between', caption:'Between'}];
		}
		
		$('.filter-bar').append('<div id="editFilterPopup"></div>');

		if (paramData) {
			self.parameterInformation = {};
			paramData.forEach(function(param) {
				self.parameterInformation[param.PARAM_NM] = _.clone(param);
			});
		} else {
			if ($.isEmptyObject(self.parameterInformation) && gDashboard.parameterFilterBar && gDashboard.parameterFilterBar.parameterInformation) {
				self.parameterInformation = gDashboard.parameterFilterBar.parameterInformation;
			}
		}
			
		if(!Object.keys(self.parameterInformation).length) {
			WISE.alert('수정 할 필터가 없습니다.');
			return false;
		}
		var paramArray = [];
		if(!paramData && datasourceTarget != null){
			$.each(self.dataSourceparameterInformation,function(_i,_datas){
				if(_i == datasourceTarget)
				    paramArray = _datas;
			});
		}else{
			$.each(self.parameterInformation,function(_i,_items){
				paramArray.push(_items);
//				var Obj = new Object();
//				Obj['매개변수 명'] =  _items.PARAM_NM;
//				Obj['매개변수 CAPTION'] = _items.PARAM_CAPTION;
//				Obj['순서'] = _items.ORDER;
//				paramArray.push(Obj);
			});
		}
		
		var html = "<div class=\"modal-body\" style='height:93%'>\r\n" + 
		"                        <div class=\"row\" style='height:100%'>\r\n" + 
		"                            <div class=\"column\" style='width:30%'>\r\n" + 
		"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
		"                                   <div class=\"modal-tit\">\r\n" + 
		"                                   <span>매개변수 목록</span>\r\n";
		/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
		if(WISE.Context.isCubeReport || (typeof directEdit != 'undefined'  && directEdit == true)) {
			html += "									<div id=\"removeParam\" style=\"float: right\"></div>\r\n";
		}
		html += "                                   </div>\r\n" +
		"									<div id=\"paramItemListArea\" />\r\n" + 
		"                                </div>\r\n" +
//		"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
		"                            </div>\r\n" + 
		"                            <div class=\"column\" style=\"width:70%\">\r\n" +
		"                            	<div class=\"row horizen\">\r\n" + 
		" 		                            <div class=\"column\" style=\"padding-bottom:0px; height:100%\">\r\n" +
		'										<div class="modal-article" style="height:100%;">' +
		"											<div id=\"param_area\" class=\"param_area modal-tit\">\r\n" + 
		"   		                                     <span>매개변수 정보</span>" + 
		"       	                	            </div>\r\n" +
		"											<div id=\"paramItemDescArea\" style='height: calc(100% - 30px);padding-bottom:30px;overflow:auto;'></div>\r\n" +
		"       	                	        </div>\r\n" +
		" 									</div>" + //column 끝
	    " 								 </div>" + //row horizon 끝
		"                            </div>\r\n" +  //column 끝 
		"                        </div>\r\n" + //row 끝
		"                    </div>\r\n" + //modal-body 끝
		"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
		"                        <div class=\"row center\">\r\n" + 
		"                            <a id=\"paramBtnOK\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
		"                            <a id=\"paramBtnCancel\" class=\"btn neutral close\" href=\"#\">취소</a>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                </div>";
		$('#editFilterPopup').dxPopup({
			visible:true,
			title: "매개변수 편집",
			width: '90vw',
            height: '90vh',
            maxWidth: 1250,
            maxHeight: 900,            
			contentTemplate:function() {
//				var html = "";
//				html += "<div style='height:100%'>"
//				html += "<div style='width:100%;height:90%'>";
//				html += "<div id='paramItemListArea' style='width:40%; float:left;height:100%; margin:8px 15px 9px 0'></div>";
//				html += "<div style='width:55%;height:95%;float:right; margin:8px 15px 9px 0'><div id='paramItemDescArea' style='height:100%'></div></div>";
//				html += "</div>";
//				html += "<div style='width:100%;height:10%'>";
//				html += "<div id='buttonCenter'></div>";
//				html += "</div>";
//				html += "</div>";
                return html;
            },
            onShown:function(){
            	var selectedItem;
            	/*dogfoot 매개변수명 변경  오류 수정 shlim 20200625*/
            	var paramNmChangeList =[];
            	/**
            	 * 매개변수 정보 초기화
            	 **/
//            	$('#saveParam').dxButton({
//            		text:'저장',
//            		onClick:function(){
//            			
////            			WISE.alert('저장 되었습니다.');
//            		}
//            	})
            	self.initParamInformation("paramItemDescArea");
            	$('#paramItemListArea').dxDataGrid({
            		dataSource:paramArray,
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
            			{
    			            dataField: "ORDER",
    			            caption:"순서",
    			            alignment:"center",
            			},
            		],
                    selection: {
                        mode: "single"
                    },
                    onSelectionChanged:function(_e){
            			if(typeof selectedItem != 'undefined'){
            				/*dogfoot 매개변수명 변경  오류 수정 shlim 20200625*/
            				if(selectedItem.PARAM_NM != $('#paramName').dxTextBox('instance').option('value')){
            					var preParamNm = selectedItem.PARAM_NM ;
            					var newParamNm = $('#paramName').dxTextBox('instance').option('value')

            					paramNmChangeList.push({preParamNm:selectedItem.PARAM_NM,newParamNm:newParamNm});
            				}
            				selectedItem.PARAM_NM = $('#paramName').dxTextBox('instance').option('value');
            				if(selectedItem.UNI_NM == "" || selectedItem.UNI_NM == undefined)
            					selectedItem.UNI_NM = $('#paramName').dxTextBox('instance').option('value');
//            				selectedItem.UNI_NM = $('#paramName').dxTextBox('instance').option('value');
            				/*dogfoot 매개변수 캡션명 공백 일떄 제거  shlim 20210319*/
            				selectedItem.PARAM_CAPTION = $('#paramCaption').dxTextBox('instance').option('value').trim() === " " ? "": $('#paramCaption').dxTextBox('instance').option('value');
//                			selectedItem.PARAM_CAPTION = $('#paramCaption').dxTextBox('instance').option('value');
                			if(typeof directEdit != 'undefined'  && directEdit == true) {
                				selectedItem.PARAM_CAPTION = $('#paramCaption').dxTextBox('instance').option('disabled', false);
                			}
                			selectedItem.DATA_TYPE = $('#dataType').dxSelectBox('instance').option('value');
                			selectedItem.PARAM_TYPE = $('#paramType').dxSelectBox('instance').option('value');
                			
                			selectedItem.ORDER = $('#orderInput').dxNumberBox('instance').option('value');
                			selectedItem.WIDTH = $('#widthInput').dxNumberBox('instance').option('value');
                			selectedItem.VISIBLE = $('#visibleYN').dxCheckBox('instance').option('value') ? 'Y':'N';
                			//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
                			selectedItem.CAPTION_WIDTH_VISIBLE = $('#captionWidthVisible').dxCheckBox('instance').option('value') ? 'Y':'N';
                			selectedItem.CAPTION_WIDTH = $('#captionWidth').dxNumberBox('instance').option('value');
                			if(selectedItem.CAPTION_WIDTH == null){
                				selectedItem.CAPTION_WIDTH = 86.5;
                			}
                			/* DOGFOOT ktkang 필터 NotIn 추가  20200716  */
                			selectedItem.OPER = $('#conditionInput').dxSelectBox('instance').option('value');
                			
                			var paramType = $('#paramType').dxSelectBox('instance').option('value')
                			if(paramType == 'LIST'){
                				selectedItem.DATASRC_TYPE = $('#dataOriginType').dxSelectBox('instance').option('value');
                				selectedItem.SEARCH_YN = $('#dataSearch').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.BIND_YN = $('#dataBind').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				/*dogfoot shlim 20210415*/
                				selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = $('#orderByButton').dxSelectBox('instance').option('value');
                				/*dogfoot USE_SCRIPT Y 일때 기본값 돌리는 과정 추가 shlim 20200708*/
                				selectedItem.HIDDEN_VALUE = $('#UseSqlScriptYN').dxCheckBox('instance').option('value') ? $('#DefaultValue').dxTextArea('instance').option('value') : "";
                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = $('#MultiSelectYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
                				selectedItem.ORDERBY_KEY = $('#orderByKey').dxTextBox('instance').option('value');
                				if(selectedItem.DATASRC_TYPE == 'QUERY'){
                					$.each(self.parameterInformation,function(_i,_e){
                						var paramName = _e.PARAM_NM;
                						if((selectedItem.DATASRC).indexOf(paramName) > -1){
                							selectedItem.wiseVariables.push(paramName);
                							selectedItem.wiseVariables.push(_e.WHERE_CLAUSE);
                						}
                					});
                				}

                			}else if(paramType == 'INPUT'){
                				selectedItem.DATASRC_TYPE = '';
                				selectedItem.SEARCH_YN = 'N';
                				selectedItem.BIND_YN = 'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = 'ASC';
                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = $('#MultiSelectYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
								/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				/*dogfoot shlim 20210415*/
                				
                				selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.INPUT_EDIT_YN = $('#dataInputEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                			}else if (paramType == 'CAND'){
                				if($('#candDefaultType').dxSelectBox('instance').option('value')== 'QUERY'){
                					selectedItem.CAND_DEFAULT_TYPE = 'QUERY';
                					selectedItem.CAND_PERIOD_BASE = "";
                					selectedItem.CAND_PERIOD_VALUE = "";
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					selectedItem.DEFAULT_VALUE = $('#DefaultValueQuery').dxTextArea('instance').option('value');
                					/*dogfoot 캘린더 기본값 쿼리 저장 오류 수정 shlim 20200728*/
                					selectedItem.HIDDEN_VALUE = $('#DefaultValueQuery').dxTextArea('instance').option('value');
                					/* DOGFOOT ktkang 필터 선택 변경시 기본 값 부분이 초기화 되는 현상 수정  20200116*/
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT=$('#defaultQuery').dxCheckBox('instance').option('value')? 'Y':'N';
                					/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                					selectedItem.SORT_VALUE_ITEM = '';
                					/*dogfoot 달력 매개변수 삭제 유무 추가 shlim 20210317*/
                					selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                					/*dogfoot shlim 20210415*/
                					selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				}else{
                					/* goyong ktkang 달력 필터 현재 기본값 오류 수정  20210517 */
                					var candDate = new Date();
                					var candPeriod = $("#DefaultValueNow").dxSelectBox('instance').option('value');
                					var candPeriodValue = $("#candMoveValue").dxNumberBox('instance').option('value');
                					if(candPeriod == 'YEAR'){
                						candDate.setYear(candDate.getFullYear()+candPeriodValue);
                					}else if(candPeriod == 'MONTH'){
                						candDate.setMonth(candDate.getMonth()+candPeriodValue);
                					}else{
                						candDate.setDate(candDate.getDate()+candPeriodValue);
                					}
                					
                					selectedItem.CAND_DEFAULT_TYPE = 'NOW';
                					selectedItem.CAND_PERIOD_BASE = candPeriod;
                					selectedItem.CAND_PERIOD_VALUE = candPeriodValue;
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					/*dogfoot 달력 필터 numeric일때 기본값 없는 오류 수정 shlim 20210318*/
                					selectedItem.DEFAULT_VALUE = self.getFormatDate(candDate, candPeriod);
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                					selectedItem.SORT_VALUE_ITEM = '';
                					/*dogfoot 달력 매개변수 삭제 유무 추가 shlim 20210317*/
                					selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                					/*dogfoot shlim 20210415*/
                					selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				}
                				selectedItem.wiseVariables = [];
                			}else if(paramType == 'BETWEEN_CAND'){
                				if($('#candDefaultType').dxSelectBox('instance').option('value')== 'QUERY'){
	                				/*dogfoot 캘린더 기본값 쿼리 저장 오류 수정 shlim 20200728*/
//                					var fromValue = Number($("#DefaultValueQueryFrom").dxTextArea('instance').option('value'));
//                					var toValue = Number($("#DefaultValueQueryTo").dxTextArea('instance').option('value'));
                					var fromValue = $("#DefaultValueQueryFrom").dxTextArea('instance').option('value');
                					var toValue = $("#DefaultValueQueryTo").dxTextArea('instance').option('value');
                					selectedItem.CAND_DEFAULT_TYPE = 'QUERY';
                					/*dogfoot 캘린더 기간 설정 shlim 20210427*/
                					selectedItem.CAND_MAX_GAP = $('#candFromToGap').dxNumberBox('instance').option('value');
                					selectedItem.CAND_PERIOD_BASE = "";
                					selectedItem.CAND_PERIOD_VALUE = "";
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					selectedItem.DEFAULT_VALUE = fromValue + ','+toValue;//('#DefaultValue').dxTextArea('instance').option('value');
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT=$('#defaultQuery').dxCheckBox('instance').option('value')? 'Y':'N';
                					/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                					selectedItem.SORT_VALUE_ITEM = '';
                					/*dogfoot shlim 20210414*/
                					selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                					/*dogfoot shlim 20210415*/
                					selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                					
                				}else{
                					var fromPeriod = $("#DefaultValueNowFrom").dxSelectBox('instance').option('value');
                					var toPeriod = $("#DefaultValueNowTo").dxSelectBox('instance').option('value');
                					var fromValue = Number($("#candMoveValueFrom").dxNumberBox('instance').option('value'));
                					var toValue = Number($("#candMoveValueTo").dxNumberBox('instance').option('value'));
                					selectedItem.CAND_DEFAULT_TYPE = 'NOW';
                					/*dogfoot 캘린더 기간 설정 shlim 20210427*/
                					selectedItem.CAND_MAX_GAP = $('#candFromToGap').dxNumberBox('instance').option('value');
                					selectedItem.CAND_PERIOD_BASE = fromPeriod + ',' + toPeriod;
                					selectedItem.CAND_PERIOD_VALUE = fromValue + ',' + toValue;
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					
                					var ToDate = new Date();
                					
                					if(toPeriod == 'YEAR'){
                						ToDate.setYear(ToDate.getFullYear()+toValue);
                					}else if(toPeriod == 'MONTH'){
                						ToDate.setMonth(ToDate.getMonth()+toValue);
                					}else{
                						ToDate.setDate(ToDate.getDate()+toValue);
                					}
                					
                					var FromDate = new Date(ToDate);
                					if(fromPeriod == 'YEAR'){
                						FromDate.setYear(FromDate.getFullYear()+fromValue);
                					}else if(fromPeriod == 'MONTH'){
                						FromDate.setMonth(FromDate.getMonth()+fromValue)
                					}else{
                						FromDate.setDate(FromDate.getDate()+fromValue);
                					}
                					/* goyong ktkang 달력 필터 현재 기본값 오류 수정  20210517 */
                					selectedItem.DEFAULT_VALUE = self.getFormatDate(FromDate, fromPeriod)+","+ self.getFormatDate(ToDate, toPeriod);
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                					selectedItem.SORT_VALUE_ITEM = '';
                					selectedItem.wiseVariables = [];
                					/*dogfoot shlim 20210414*/
                					selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                					/*dogfoot shlim 20210415*/
                					selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				}
                			}
                			else if(paramType == 'BETWEEN_LIST'){
                				var fromValue = $("#DefaultValueFrom").dxTextArea('instance').option('value');
            					var toValue = $("#DefaultValueTo").dxTextArea('instance').option('value');
            					
                				selectedItem.DATASRC_TYPE = $('#dataOriginType').dxSelectBox('instance').option('value');
                				selectedItem.SEARCH_YN = $('#dataSearch').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.BIND_YN = $('#dataBind').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = $('#orderByButton').dxSelectBox('instance').option('value');
//                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value') == '[All]' ? '[All]' : $('#DefaultValue').dxTextArea('instance').option('value');
                				
                				selectedItem.DEFAULT_VALUE = [fromValue,toValue];
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = 'N'
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				/*dogfoot shlim 20210415*/
                				selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                			}else if(paramType == 'BETWEEN_INPUT'){
                				var fromValue = $("#DefaultValueFrom").dxTextArea('instance').option('value');
            					var toValue = $("#DefaultValueTo").dxTextArea('instance').option('value');
            					
                				selectedItem.DATASRC_TYPE = '';
                				selectedItem.SEARCH_YN = 'N';
                				selectedItem.BIND_YN = 'N';
                				selectedItem.DATASRC = '';
                				selectedItem.KEY_VALUE_ITEM = "";
                				selectedItem.CAPTION_VALUE_ITEM = "";
                				selectedItem.SORT_TYPE = '';
                				selectedItem.DEFAULT_VALUE = [fromValue, toValue];
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = '';
                				selectedItem.ALL_YN = 'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				/*dogfoot shlim 20210415*/
                				selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                			}
            			}
            			
            			/*dogfoot shlim use sql script Y일때 쿼리입력 안할시 경고창 실행  2020714*/
            			if(selectedItem){
            			    if(selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT == 'Y' && selectedItem.HIDDEN_VALUE.replace(/\s/gi,"") == ""){
								WISE.alert('매개변수 기본값 쿼리를 입력해주세요');
								return false;
							}	
            			}
            			
            			$('#paramType').dxSelectBox('instance').option('value','');
                    	selectedItem = _e.selectedRowsData[0];
                    	if(selectedItem.OPER === 'Between'){
            				$('#paramType').dxSelectBox('instance').option('dataSource',betweenParamType);
            			}else{
            				$('#paramType').dxSelectBox('instance').option('dataSource',commonParamType);
            			}
                    	self.setParamInfo(_e.selectedRowsData[0]);
                    	
                    	/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
                    	if(WISE.Context.isCubeReport || (typeof directEdit != 'undefined'  && directEdit == true)) {
                    		$('#removeParam').dxButton({
                    			text:"삭제",
                    			onClick:function(){
                    				delete self.parameterInformation[selectedItem.UNI_NM];
                    				/*dogfoot 캘린더 기간 설정 shlim 20210427*/
                    				delete self.parameterInformation[selectedItem.PARAM_NM];
                    				delete gDashboard.parameterFilterBar.parameterInformation[selectedItem.UNI_NM];
                    				var paramList = [];
                    				gDashboard.structure.ReportMasterInfo.paramJson = [];
                    				$.each(gDashboard.parameterFilterBar.parameterInformation,function(_i,_items){
                    					paramList.push(_items);
                    					gDashboard.structure.ReportMasterInfo.paramJson.push(_items);
                    				});

                    				$('#paramItemListArea').dxDataGrid('instance').option('dataSource', paramList);

                    				$('#paramName').dxTextBox('instance').option('value', '');
                    				$('#paramName').dxTextBox('instance').option('value', '');
                    				$('#paramCaption').dxTextBox('instance').option('value', '');
                    				$('#dataType').dxSelectBox('instance').option('value', '');
                    				$('#paramType').dxSelectBox('instance').option('value', '');

                    				$('#orderInput').dxNumberBox('instance').option('value', '1');
                    				$('#widthInput').dxNumberBox('instance').option('value', '250');
                    				$('#visibleYN').dxCheckBox('instance').option('value', 'Y');
                    				/* DOGFOOT ktkang 필터 NotIn 추가  20200716  */
                    				$('#conditionInput').dxSelectBox('instance').option('text', 'In');

                    				$('.filter-item').empty();
                    				/* DOGFOOT ktkang 주제영역 필터 중복 오류 수정  20200705 */
                    				var reportInfo = gDashboard.structure.ReportMasterInfo;
                    				gDashboard.datasetMaster.setState({ params: gDashboard.datasetMaster.utility.getParamArray(reportInfo.paramJson) });
									/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
                    				if(!WISE.Context.isCubeReport) {
                    					var lookUpIns = $("#dataSetLookUp").dxLookup('instance');
                    					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
            								lookUpIns = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").dxLookup('instance');
            							}
                    					var focusDs = lookUpIns.option('value');
                    					var singleTable = "";
                    					$.each(gDashboard.datasetMaster.state.datasets, function(_i,_o){
                    						if(_o.DATASET_TYPE == "DataSetSingleDs" || _o.DATASET_TYPE == "DataSetSingleDsView") {
                    							if(_o.DATASET_NM == focusDs) {
                    								singleTable = _o;
                    							}
                    						}
                    					});

                    					singleTable.DATASET_QUERY = singleTable.DATASET_QUERY.substring(0, singleTable.DATASET_QUERY.indexOf('WHERE'));;
                    					singleTable.SQL_QUERY = singleTable.DATASET_QUERY;

                    					if(gDashboard.datasetMaster.state.params.length > 0) {
                    						$.each(gDashboard.datasetMaster.state.params,function(_i,_e){
                    							if(_i == 0) {
                    								singleTable.DATASET_QUERY = singleTable.DATASET_QUERY + " WHERE A.\"" + _e.PARAM_CAPTION + "\" IN (" + _e.PARAM_NM + ")";
                    								singleTable.SQL_QUERY = singleTable.SQL_QUERY + " WHERE A." + _e.PARAM_CAPTION + " IN (" + PARAM_NM + ")";
                    							} else {
                    								singleTable.DATASET_QUERY = singleTable.DATASET_QUERY + " AND A.\"" + _e.PARAM_CAPTION + "\" IN (" + _e.PARAM_NM + ")";
                    								singleTable.SQL_QUERY = singleTable.SQL_QUERY + " AND A." + _e.PARAM_CAPTION + " IN (" + _e.PARAM_NM + ")";
                    							}
                    						});
                    					} 
                    				}
                    				
                    		        switch (WISE.Constants.editmode) {
                    		            case 'designer':
                    		                gDashboard.parameterFilterBar.render({
                    		                    element: $('#report-filter-item'),
                    		                    params: gDashboard.datasetMaster.state.params,
                    		                });
                    		                break;
                    		            case 'viewer':
                    		                filterBarElement = $('<div id="' + reportInfo.id + '_paramContainer" class="filter-item" report_id = "' + reportInfo.id + '"></div>');
                    		                $('.filter-row').append(filterBarElement);
                    		                gDashboard.viewerParameterBars[reportInfo.id] = new WISE.libs.Dashboard.ParameterBar();
                    		                gDashboard.viewerParameterBars[reportInfo.id].render({
                    		                    element: filterBarElement,
                    		                    params: gDashboard.datasetMaster.state.params,
                    		                });
                    		                break;
                    		            default:
                    		                gDashboard.parameterFilterBar.render({
                    		                    element: $('.filter-item'),
                    		                    params: gDashboard.datasetMaster.state.params,
                    		                });
                    		        }
                    			}
                    		});
                    	}
            		},
            		onContentReady:function(_e){
            			$(_e.element).dxDataGrid('selectRowsByIndexes',0)
            		}
            	});
            	
//            	$('#buttonCenter').append("<div id='paramBtnOK'></div><div id='paramBtnCancel'></div>");
            	
            	$('#paramBtnOK').dxButton({
            		text:"확인",
            		type:"success",
            		onClick:function(){
            			if(typeof selectedItem != 'undefined'){
            				/*dogfoot 매개변수명 변경  오류 수정 shlim 20200625*/
            				if(selectedItem.PARAM_NM != $('#paramName').dxTextBox('instance').option('value')){
            					var preParamNm = selectedItem.PARAM_NM ;
            					var newParamNm = $('#paramName').dxTextBox('instance').option('value')

            					paramNmChangeList.push({preParamNm:selectedItem.PARAM_NM,newParamNm:newParamNm});
            				}
            				selectedItem.PARAM_NM = $('#paramName').dxTextBox('instance').option('value');
            				if(selectedItem.UNI_NM == "" || selectedItem.UNI_NM == undefined)
            					selectedItem.UNI_NM = $('#paramName').dxTextBox('instance').option('value');
//            				selectedItem.UNI_NM = $('#paramName').dxTextBox('instance').option('value');
            				/*dogfoot 매개변수 캡션명 공백 일떄 제거  shlim 20210319*/
            				selectedItem.PARAM_CAPTION = $('#paramCaption').dxTextBox('instance').option('value').trim() === "" ? " ": $('#paramCaption').dxTextBox('instance').option('value');
//                			selectedItem.PARAM_CAPTION = $('#paramCaption').dxTextBox('instance').option('value');
                			selectedItem.DATA_TYPE = $('#dataType').dxSelectBox('instance').option('value');
                			selectedItem.PARAM_TYPE = $('#paramType').dxSelectBox('instance').option('value');
                			
                			selectedItem.ORDER = $('#orderInput').dxNumberBox('instance').option('value');
                			selectedItem.WIDTH = $('#widthInput').dxNumberBox('instance').option('value');
                			selectedItem.VISIBLE = $('#visibleYN').dxCheckBox('instance').option('value') ? 'Y':'N';
                			//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
                			selectedItem.CAPTION_WIDTH_VISIBLE = $('#captionWidthVisible').dxCheckBox('instance').option('value') ? 'Y':'N';
                			selectedItem.CAPTION_WIDTH = $('#captionWidth').dxNumberBox('instance').option('value');
                			if(selectedItem.CAPTION_WIDTH == null){
                				selectedItem.CAPTION_WIDTH = 86.5;
                			}
                			selectedItem.OPER = $('#conditionInput').dxSelectBox('instance').option('value');
                			
                			if(selectedItem.PARAM_CAPTION == '' || selectedItem.DATA_TYPE == '' || selectedItem.PARAM_TYPE == '') {
                				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                				return false;
                			}
                			var paramType = $('#paramType').dxSelectBox('instance').option('value');
                			
                			if(paramType == 'LIST'){
                				selectedItem.DATASRC_TYPE = $('#dataOriginType').dxSelectBox('instance').option('value');
                				selectedItem.SEARCH_YN = $('#dataSearch').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.BIND_YN = $('#dataBind').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				/*dogfoot shlim 20210415*/
                				selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = $('#orderByButton').dxSelectBox('instance').option('value');
                				/*dogfoot USE_SCRIPT Y 일때 기본값 돌리는 과정 추가 shlim 20200708*/
                				selectedItem.HIDDEN_VALUE = $('#UseSqlScriptYN').dxCheckBox('instance').option('value') ? $('#DefaultValue').dxTextArea('instance').option('value') : "";
                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value') == '[All]' ? '[All]' : $('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = $('#MultiSelectYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
                				selectedItem.ORDERBY_KEY = $('#orderByKey').dxTextBox('instance').option('value');
                				if(selectedItem.DATASRC_TYPE == 'QUERY'){
                					$.each(self.parameterInformation,function(_i,_e){
                						var paramName = _e.PARAM_NM;
                						if((selectedItem.DATASRC).indexOf(paramName) > -1){
                							selectedItem.wiseVariables.push(paramName);
                							selectedItem.wiseVariables.push(_e.WHERE_CLAUSE);
                						}
                					});
                				}
                				
                				if(selectedItem.DATASRC == '' || selectedItem.DATA_TYPE == '' || selectedItem.KEY_VALUE_ITEM == '' 
                					|| selectedItem.CAPTION_VALUE_ITEM == '' || selectedItem.WHERE_CLAUSE == '') {
                    				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                    				return false;
                    			}
                			}else if(paramType == 'INPUT'){
                				selectedItem.DATASRC_TYPE = '';
                				selectedItem.SEARCH_YN = 'N';
                				selectedItem.BIND_YN = 'N';
                				selectedItem.DATASRC = "";
                				selectedItem.KEY_VALUE_ITEM = "";
                				selectedItem.CAPTION_VALUE_ITEM = "";
                				selectedItem.SORT_TYPE = 'ASC';
                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = 'N';
                				selectedItem.ALL_YN = 'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				/*dogfoot shlim 20210415*/
                				selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.INPUT_EDIT_YN = $('#dataInputEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				
                				/* DOGFOOT ktkang 입력창 필수정보 부분 오류 수정  20200114 */
                				if(selectedItem.WHERE_CLAUSE == '') {
                    				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                    				return false;
                    			}
                			}else if (paramType == 'CAND'){
                				if($('#candDefaultType').dxSelectBox('instance').option('value')== 'QUERY'){
                					selectedItem.CAND_DEFAULT_TYPE = 'QUERY';
                					selectedItem.CAND_PERIOD_BASE = "";
                					selectedItem.CAND_PERIOD_VALUE = "";
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					selectedItem.DEFAULT_VALUE = $('#DefaultValueQuery').dxTextArea('instance').option('value');
                					/*dogfoot 캘린더 기본값 쿼리 저장 오류 수정 shlim 20200728*/
                					selectedItem.HIDDEN_VALUE = $('#DefaultValueQuery').dxTextArea('instance').option('value');
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT=$('#defaultQuery').dxCheckBox('instance').option('value')? 'Y':'N';
                					/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                					selectedItem.SORT_VALUE_ITEM = '';
                					/*dogfoot 달력 매개변수 삭제 유무 추가 shlim 20210317*/
                					selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                					/*dogfoot shlim 20210415*/
                					selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				}else{
                					/* goyong ktkang 달력 필터 현재 기본값 오류 수정  20210517 */
                					var candDate = new Date();
                					var candPeriod = $("#DefaultValueNow").dxSelectBox('instance').option('value');
                					var candPeriodValue = $("#candMoveValue").dxNumberBox('instance').option('value');
                					if(candPeriod == 'YEAR'){
                						candDate.setYear(candDate.getFullYear()+candPeriodValue);
                					}else if(candPeriod == 'MONTH'){
                						candDate.setMonth(candDate.getMonth()+candPeriodValue);
                					}else{
                						candDate.setDate(candDate.getDate()+candPeriodValue);
                					}
                					
                					selectedItem.CAND_DEFAULT_TYPE = 'NOW';
                					selectedItem.CAND_PERIOD_BASE = candPeriod;
                					selectedItem.CAND_PERIOD_VALUE = candPeriodValue;
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					/*dogfoot 달력 필터 numeric일때 기본값 없는 오류 수정 shlim 20210318*/
                					selectedItem.DEFAULT_VALUE = self.getFormatDate(candDate, candPeriod);
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                					selectedItem.SORT_VALUE_ITEM = '';
                					/*dogfoot 달력 매개변수 삭제 유무 추가 shlim 20210317*/
                					selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                					/*dogfoot shlim 20210415*/
                					selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                					
                				}
                				selectedItem.wiseVariables = [];
                				
                				if(selectedItem.CAND_DEFAULT_TYPE == 'QUERY') {
                					if(selectedItem.CAPTION_FORMAT == '' || selectedItem.KEY_FORMAT == '') {
                        				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                        				return false;
                        			}
                				} else {
                					if(selectedItem.CAPTION_FORMAT == '' || selectedItem.KEY_FORMAT == '' || selectedItem.CAND_PERIOD_BASE == '') {
                        				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                        				return false;
                        			}
                				}
                			}
                			else if(paramType == 'BETWEEN_CAND'){
                				if($('#candDefaultType').dxSelectBox('instance').option('value')== 'QUERY'){
                					var fromValue = $("#DefaultValueQueryFrom").dxTextArea('instance').option('value');
                					var toValue = $("#DefaultValueQueryTo").dxTextArea('instance').option('value');
                					selectedItem.CAND_DEFAULT_TYPE = 'QUERY';
                					/*dogfoot 캘린더 기간 설정 shlim 20210427*/
                					selectedItem.CAND_MAX_GAP = $('#candFromToGap').dxNumberBox('instance').option('value');
                					selectedItem.CAND_PERIOD_BASE = "";
                					selectedItem.CAND_PERIOD_VALUE = "";
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					var defaultVal = new Array();
                					defaultVal.push(fromValue);
                					defaultVal.push(toValue);
                					selectedItem.DEFAULT_VALUE  = defaultVal;
                					
                					/* DOGFOOT shlim between 캘린더 기본값 오류 수정  20200724 */
                					selectedItem.FROM_VALUE = $("#DefaultValueQueryFrom").dxTextArea('instance').option('value');
                					selectedItem.TO_VALUE = $("#DefaultValueQueryTo").dxTextArea('instance').option('value');
//                					selectedItem.DEFAULT_VALUE = fromValue + ','+toValue;//('#DefaultValue').dxTextArea('instance').option('value');
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT=$('#defaultQuery').dxCheckBox('instance').option('value')? 'Y':'N';
                					/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                					selectedItem.SORT_VALUE_ITEM = '';
                					/*dogfoot shlim 20210414*/
                					selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                					/*dogfoot shlim 20210415*/
                					selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                					
                				}else{
                					var fromPeriod = $("#DefaultValueNowFrom").dxSelectBox('instance').option('value');
                					var toPeriod = $("#DefaultValueNowTo").dxSelectBox('instance').option('value');
                					var fromValue = Number($("#candMoveValueFrom").dxNumberBox('instance').option('value'));
                					var toValue = Number($("#candMoveValueTo").dxNumberBox('instance').option('value'));
                					selectedItem.CAND_DEFAULT_TYPE = 'NOW';
                					/*dogfoot 캘린더 기간 설정 shlim 20210427*/
                					selectedItem.CAND_MAX_GAP = $('#candFromToGap').dxNumberBox('instance').option('value');
                					selectedItem.CAND_PERIOD_BASE = fromPeriod + ',' + toPeriod;
                					selectedItem.CAND_PERIOD_VALUE = fromValue + ',' + toValue;
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					
                					var ToDate = new Date();
                					
                					if(toPeriod == 'YEAR'){
                						ToDate.setYear(ToDate.getFullYear()+toValue);
                					}else if(toPeriod == 'MONTH'){
                						ToDate.setMonth(ToDate.getMonth()+toValue);
                					}else{
                						ToDate.setDate(ToDate.getDate()+toValue);
                					}
                					var FromDate = new Date(ToDate);
                					if(fromPeriod == 'YEAR'){
                						FromDate.setYear(FromDate.getFullYear()+fromValue);
                					}else if(fromPeriod == 'MONTH'){
                						FromDate.setMonth(FromDate.getMonth()+fromValue)
                					}else{
                						FromDate.setDate(FromDate.getDate()+fromValue);
                					}
                					/* goyong ktkang 달력 필터 현재 기본값 오류 수정  20210517 */
                					selectedItem.DEFAULT_VALUE = self.getFormatDate(FromDate, fromPeriod)+","+ self.getFormatDate(ToDate, toPeriod);
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                					selectedItem.SORT_VALUE_ITEM = '';
                					selectedItem.wiseVariables = [];
                					/*dogfoot shlim 20210414*/
                					selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                					/*dogfoot shlim 20210415*/
                					selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				}
                				
                				if(selectedItem.CAND_DEFAULT_TYPE == 'QUERY') {
                					if(selectedItem.CAPTION_FORMAT == '' || selectedItem.KEY_FORMAT == '') {
                        				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                        				return false;
                        			}
                				} else {
                					if(selectedItem.CAPTION_FORMAT == '' || selectedItem.KEY_FORMAT == '' || selectedItem.CAND_PERIOD_BASE == '') {
                        				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                        				return false;
                        			}
                				}
                			}else if(paramType == 'BETWEEN_LIST'){
                				var fromValue = $("#DefaultValueFrom").dxTextArea('instance').option('value');
            					var toValue = $("#DefaultValueTo").dxTextArea('instance').option('value');
            					
                				selectedItem.DATASRC_TYPE = $('#dataOriginType').dxSelectBox('instance').option('value');
                				selectedItem.SEARCH_YN = $('#dataSearch').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.BIND_YN = $('#dataBind').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = $('#orderByButton').dxSelectBox('instance').option('value');
//                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value') == '[All]' ? '[All]' : $('#DefaultValue').dxTextArea('instance').option('value');
                				
                				selectedItem.DEFAULT_VALUE = [fromValue,toValue];
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = 'N';
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				/*dogfoot shlim 20210415*/
                				selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				if(selectedItem.DATASRC == '' || selectedItem.DATA_TYPE == '' || selectedItem.KEY_VALUE_ITEM == '' 
                					|| selectedItem.CAPTION_VALUE_ITEM == '' || selectedItem.WHERE_CLAUSE == '') {
                    				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                    				return false;
                    			}
                			} else if(paramType == 'BETWEEN_INPUT'){
                				var fromValue = $("#DefaultValueFrom").dxTextArea('instance').option('value');
            					var toValue = $("#DefaultValueTo").dxTextArea('instance').option('value');
            					
                				selectedItem.DATASRC_TYPE = '';
                				selectedItem.SEARCH_YN = 'N';
                				selectedItem.BIND_YN = 'N';
                				selectedItem.DATASRC = '';
                				selectedItem.KEY_VALUE_ITEM = "";
                				selectedItem.CAPTION_VALUE_ITEM = "";
                				selectedItem.SORT_TYPE = '';
                				selectedItem.DEFAULT_VALUE = [fromValue, toValue];
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = '';
                				selectedItem.ALL_YN = 'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				/* DOGFOOT ktkang 필터 정렬 기준 오류 수정  20200212 */
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				/*dogfoot shlim 20210415*/
                				selectedItem.EDIT_YN = $('#dataEdit').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.LINE_BREAK = $('#lineBreak').dxCheckBox('instance').option('value')? 'Y':'N';
                				if(selectedItem.WHERE_CLAUSE == '') {
                    				WISE.alert('필수 정보를 입력하지 않으셨습니다. 다시 한번 확인하세요.');
                    				return false;
                    			}
                			}
                			/* goyong ktkang 필터 여러개일 때 선택되어 있는 필터만 기본값 계산하는 오류 수정  20210514 */
                			var successValue = 0;
                			$.each(self.parameterInformation,function(_i,_e){
                				if(_e.DEFAULT_VALUE_USE_SQL_SCRIPT == 'Y'){
                					if(_e.PARAM_TYPE == 'BETWEEN_CAND'){
                						if(selectedItem.PARAM_NM == _e.PARAM_NM) {
                							if(selectedItem.FROM_VALUE.replace(/\s/gi,"").trim() == "" || selectedItem.TO_VALUE.replace(/\s/gi,"").trim() == "" ){
                								WISE.alert('매개변수 기본값 쿼리를 입력해주세요');
                								return false;
                							}
                						}
                						var hiddenValue;
                						if(selectedItem.PARAM_NM == _e.PARAM_NM) {
                							hiddenValue = new Array();
                							hiddenValue[0] = Base64.encode($('#DefaultValueQueryFrom').dxTextArea('instance').option('value'));
                							hiddenValue[1] = Base64.encode($('#DefaultValueQueryTo').dxTextArea('instance').option('value'));
                						} else {
                							hiddenValue = _e.HIDDEN_VALUE.split(',');
                						}
                						var fromDataValue = '', toDataValue = '';
                						var fromparam ={
                								'dsid':_e.DS_ID,
                								'dstype':'DS',
                								/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
                								'defaultSql': hiddenValue[0],
                								'closYm': userJsonObject.closYm,
                								'userId' : userJsonObject.userId
                						};
                						$.ajax({
                							type : 'post',
                							data:fromparam,
                							async:false,
                							url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                							success: function(_data) {
//              								selectedItem.HIDDEN_VALUE
                								fromDataValue = _data.data;
                								var toparam ={
                										'dsid':_e.DS_ID,
                										'dstype':'DS',
                										/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
                										'defaultSql': hiddenValue[1],
                										'closYm': userJsonObject.closYm,
                										'userId' : userJsonObject.userId
                								};
                								$.ajax({
                									type : 'post',
                									data:toparam,
                									async:false,
                									url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                									success: function(_data) {
//              										selectedItem.HIDDEN_VALUE
                										toDataValue = _data.data;
//              										selectedItem.HIDDEN_VALUE = $('#DefaultValueQueryFrom').dxTextArea('instance').option('value')+','+$('#DefaultValueQueryTo').dxTextArea('instance').option('value');
                										_e.HIDDEN_VALUE = hiddenValue[0] +','+hiddenValue[1];
//              										selectedItem.DEFAULT_VALUE = [fromDataValue,toDataValue];
                										_e.DEFAULT_VALUE = fromDataValue.concat(toDataValue)
                										gDashboard.parameterFilterBar.totalConditionWidth = 0;
                										gDashboard.structure.ReportMasterInfo.paramJson = self.parameterInformation;
                										gDashboard.parameterFilterBar.setParameterInformation(self.parameterInformation);
                										
                										successValue++;
                										if(successValue == Object.keys(self.parameterInformation).length) {
                        									$('#editFilterPopup').dxPopup('hide');
                        		            				$('#editFilterPopup').remove();
                        								}
                									}
                								});
                							}
                						});
                					}else if(_e.PARAM_TYPE == 'BETWEEN_LIST' || _e.PARAM_TYPE == 'BETWEEN_INPUT'){
                						if(selectedItem.PARAM_NM == _e.PARAM_NM) {
                							if($('#DefaultValueFrom').dxTextArea('instance').option('value') == "" || $('#DefaultValueTo').dxTextArea('instance').option('value') == "" ){
                								WISE.alert('매개변수 기본값 쿼리를 입력해주세요');
                								return false;
                							}
                						}
                						var hiddenValue;
                						if(selectedItem.PARAM_NM == _e.PARAM_NM) {
                							hiddenValue = new Array();
                							hiddenValue[0] = Base64.encode($('#DefaultValueFrom').dxTextArea('instance').option('value'));
                							hiddenValue[1] = Base64.encode($('#DefaultValueTo').dxTextArea('instance').option('value'));
                						} else {
                							hiddenValue = _e.HIDDEN_VALUE.split(',');
                						}
                						var fromDataValue = '', toDataValue = '';
                						var fromparam ={
                								'dsid':_e.DS_ID,
                								'dstype':'DS',
                								/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
                								'defaultSql': hiddenValue[0],
                								'closYm': userJsonObject.closYm,
                								'userId' : userJsonObject.userId
                						};
                						$.ajax({
                							type : 'post',
                							data:fromparam,
                							async:false,
                							url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                							success: function(_data) {
//              								selectedItem.HIDDEN_VALUE
                								fromDataValue = _data.data;
                								var toparam ={
                										'dsid':_e.DS_ID,
                										'dstype':'DS',
                										/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
                										'defaultSql': hiddenValue[1],
                										'closYm': userJsonObject.closYm,
                										'userId' : userJsonObject.userId
                								};
                								$.ajax({
                									type : 'post',
                									data:toparam,
                									async:false,
                									url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                									success: function(_data) {
//              										selectedItem.HIDDEN_VALUE
                										toDataValue = _data.data;
//              										selectedItem.HIDDEN_VALUE = $('#DefaultValueFrom').dxTextArea('instance').option('value')+','+$('#DefaultValueTo').dxTextArea('instance').option('value');
                										_e.HIDDEN_VALUE = hiddenValue[0]+','+hiddenValue[1];
//              										selectedItem.DEFAULT_VALUE = [fromDataValue,toDataValue];
                										_e.DEFAULT_VALUE = fromDataValue.concat(toDataValue)
                										gDashboard.parameterFilterBar.totalConditionWidth = 0;
                										gDashboard.structure.ReportMasterInfo.paramJson = self.parameterInformation;
                										gDashboard.parameterFilterBar.setParameterInformation(self.parameterInformation);
                										
                										successValue++;
                										if(successValue == Object.keys(self.parameterInformation).length) {
                        									$('#editFilterPopup').dxPopup('hide');
                        		            				$('#editFilterPopup').remove();
                        								}
                									}
                								});
                							}
                						});
                					}else{
                						/* goyong ktkang 본사적용 달력뿐만 아니라 다 오류남  20210611 */
                						if(_e.DEFAULT_VALUE_USE_SQL_SCRIPT == 'Y' && Array.isArray(_e.DEFAULT_VALUE)) {
                							_e.DEFAULT_VALUE = _e.HIDDEN_VALUE;
                						}
                						/*dogfoot 캘린더 기본값 쿼리 저장 오류 수정 shlim 20200728*/
                						if(_e.DEFAULT_VALUE.replace(/\s/gi,"").trim() == ""){
                							WISE.alert('매개변수 기본값 쿼리를 입력해주세요');
                							return false;
                						}
                						var sql = "";
                						if(selectedItem.PARAM_NM == _e.PARAM_NM) {
                							if(_e.PARAM_TYPE == 'CAND'){
                								sql = $('#DefaultValueQuery').dxTextArea('instance').option('value')
                							}else{
                								sql = $('#DefaultValue').dxTextArea('instance').option('value');
                							}
                						} else {
                							sql = _e.DEFAULT_VALUE;
                						}
                						var param ={
                								'dsid':_e.DS_ID,
                								'dstype':'DS',
                								/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
                								'defaultSql': Base64.encode(sql),
                								'closYm': userJsonObject.closYm,
                								'userId' : userJsonObject.userId
                						};
                						$.ajax({
                							type : 'post',
                							data:param,
                							async:false,
                							url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                							success: function(_data) {
                								if(paramType == 'CAND') {
                									if(selectedItem.PARAM_NM == _e.PARAM_NM){
                    									_e.HIDDEN_VALUE = $('#DefaultValueQuery').dxTextArea('instance').option('value');
                    								}else{
                    									_e.HIDDEN_VALUE = sql;
                    								}
                									_e.VALUE = _data.data;
                								} else {
                									if(selectedItem.PARAM_NM == _e.PARAM_NM) {
                										_e.HIDDEN_VALUE = $('#DefaultValue').dxTextArea('instance').option('value');
                									} else {
                										_e.HIDDEN_VALUE = sql;
                									}
                								}

                								_e.DEFAULT_VALUE = _data.data;
                								gDashboard.parameterFilterBar.totalConditionWidth = 0;
                								gDashboard.structure.ReportMasterInfo.paramJson = self.parameterInformation;
                								gDashboard.parameterFilterBar.setParameterInformation(self.parameterInformation);
//              								gDashboard.parameterHandler.init();
//              								gDashboard.parameterHandler.render();
//              								$('.cont_query').append('<button id="btn_query" type="button" class="cont_query_bt search-button">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button> ');
//              								$('#btn_query').on('click', function() {
//              								gDashboard.itemGenerateManager.clearTrackingConditionAll();
//              								gDashboard.query();
//              								this.blur();
//              								});
                								
                								successValue++;
                								if(successValue == Object.keys(self.parameterInformation).length) {
                									$('#editFilterPopup').dxPopup('hide');
                		            				$('#editFilterPopup').remove();
                								}
                							},
                							error:function(error){
                								gProgressbar.hide();
                								WISE.alert('error'+ajax_error_message(error),'error');
                							}
                						});
                					}
                				}else{
                					if(selectedItem.PARAM_NM == _e.PARAM_NM) {
                						_e.DEFAULT_VALUE = selectedItem.DEFAULT_VALUE;
                					}
                					successValue++;
                					if(successValue == Object.keys(self.parameterInformation).length) {
    									$('#editFilterPopup').dxPopup('hide');
    		            				$('#editFilterPopup').remove();
    								}
                					
                					gDashboard.parameterFilterBar.totalConditionWidth = 0;
                					gDashboard.structure.ReportMasterInfo.paramJson = self.parameterInformation;
                					gDashboard.parameterFilterBar.setParameterInformation(self.parameterInformation);
                				}
                			});
                			/*dogfoot 매개변수명 변경  오류 수정 shlim 20200629*/
                			if(paramNmChangeList!=undefined && paramNmChangeList.length > 0){
                				if(gDashboard.datasetDesigner.state.dataset.DATASET_TYPE == 'DataSetDs'){
                					
                					var dsQueryTextAreaEdit = gDashboard.datasetDesigner.state.dataset.DATASET_QUERY;
                                    var sqlQueryTextAreaEdit = gDashboard.datasetDesigner.state.dataset.SQL_QUERY;
									$.each(paramNmChangeList,function(_index,_newNm){
										var regEx = new RegExp(_newNm.preParamNm, "gmi");
										dsQueryTextAreaEdit = dsQueryTextAreaEdit.replace(regEx,_newNm.newParamNm);
										sqlQueryTextAreaEdit = sqlQueryTextAreaEdit.replace(regEx,_newNm.newParamNm);
										$.each(WISE.util.Object.toArray(gDashboard.datasetDesigner.tableDesigner.state.whereClauses),function(_id,_val){
                						    if(_val.PARAM_NM == _newNm.preParamNm){
                						    	_val.PARAM_NM = _newNm.newParamNm;
                						    	_val.COND_ID = _newNm.newParamNm.replace('@','');
                						    }
                					    });
									});
									gDashboard.datasetDesigner.tableDesigner.setState({
										whereClauses: gDashboard.datasetDesigner.tableDesigner.state.whereClauses
									});
									gDashboard.datasetDesigner.tableDesigner.state.onWhereClauseChange(gDashboard.datasetDesigner.tableDesigner.state.whereClauses);
									gDashboard.datasetDesigner.tableDesigner.components.whereClauseTable.option('dataSource', gDashboard.datasetDesigner.tableDesigner.state.whereClauses);
									gDashboard.datasetDesigner.state.dataset.DATASET_QUERY = dsQueryTextAreaEdit;
									gDashboard.datasetDesigner.state.dataset.SQL_QUERY = sqlQueryTextAreaEdit;
								}else{
									if(!WISE.Context.isCubeReport) {
										var dsQueryTextAreaEdit = ace.edit("dsQueryTextArea").getValue();
	
										$.each(paramNmChangeList,function(_index,_newNm){
											var regEx = new RegExp(_newNm.preParamNm, "gmi");
											dsQueryTextAreaEdit = dsQueryTextAreaEdit.replace(regEx,_newNm.newParamNm);
										});
										ace.edit("dsQueryTextArea").setValue(dsQueryTextAreaEdit);
									}
								}	
             		    	}
							// send param data back to dataset designer
							if (callback) {
								paramGridDatas = [];
								$.each(self.parameterInformation, function(i, param) {
									paramGridDatas.push(param);
								});
								paramGridDatas = _.sortBy(paramGridDatas, 'ORDER');
								callback(paramGridDatas);
							}
							/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
    						else if(editDisignerParam && !WISE.Context.isCubeReport && typeof directEdit == 'undefined') {

                				var paramGridDatas = new Array();
                				$.each(self.parameterInformation ,function(_i, _o){
                					var param_type;
                					if(_o['PARAM_TYPE'] == 'CAND') {
                						param_type = '달력';
                					} else if(_o['PARAM_TYPE'] == 'LIST') {
                						param_type = '리스트';
                					} else if(_o['PARAM_TYPE'] == 'INPUT') {
                						param_type = '입력창';
                					} else if(_o['PARAM_TYPE'] == 'BETWEEN_LIST'){
                						param_type = 'Between 리스트'
                					} else if(_o['PARAM_TYPE'] == 'BETWEEN_INPUT'){
                						param_type = 'Between 입력창'
                					} else if(_o['PARAM_TYPE'] == 'BETWEEN_CAND'){
                						param_type = 'Between 달력'
                					}
                					var paramGridData = [{
                						/* DOGFOOT hsshim 1210 */
                						'매개변수 명' : _o['UNI_NM'],
    									'매개변수 Caption' : _o['PARAM_CAPTION'],
    									'데이터 유형' : _o['DATA_TYPE'],
    									'매개변수 유형' : param_type, 
    									'Visible' : _o['VISIBLE'],
    									'다중선택' : _o['MULTI_SEL'],
    									'순서' : _o['ORDER'],
    									'조건' : _o['OPER']
    								}];
    								paramGridDatas = paramGridDatas.concat(paramGridData);
								});
								var paramGridIns;
                				if($('#param_grid').hasClass('active')){
									paramGridIns = $('#param_grid').dxDataGrid('instance');
								}else{
									if($('#edit_param_grid').length != 0){
										paramGridIns = $('#edit_param_grid').dxDataGrid('instance');
									}else{
										
										var conditionDataSource = $('#ConditionArea').dxDataGrid('instance').option('dataSource');
										$.each(self.parameterInformation,function(_i,_o){
											for(var i=0;i<conditionDataSource.length;i++){
												if(_o.UNI_NM === conditionDataSource[i].UNI_NM){
													if(conditionDataSource[i].PARAM_YN === 'True' || conditionDataSource[i].PARAM_YN === true){
														conditionDataSource[i].VALUES = _o.DEFAULT_VALUE;
														if(_o.DEFAULT_VALUE == '[All]')
															conditionDataSource[i].VALUES_CAPTION = '전체';
														else
															conditionDataSource[i].VALUES_CAPTION = _o.DEFAULT_VALUE;
													}
												}
											}
										});
										$('#ConditionArea').dxDataGrid('instance').option('dataSource',conditionDataSource);
									}
									
								}
								// var paramGridIns = $('#param_grid').dxDataGrid('instance');
                				if(paramGridIns != undefined)
                					paramGridIns.option('dataSource', paramGridDatas);
                			/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
                			}else if(WISE.Context.isCubeReport || (typeof directEdit != 'undefined'  && directEdit == true)) {              				
                				$('#report-filter-item').empty();
                				/* DOGFOOT ktkang 주제영역 필터 중복 오류 수정  20200705 */
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
                			}
            			}else{
            				$('#editFilterPopup').dxPopup('hide');
            				$('#editFilterPopup').remove();
            			}
            		}
            	});
            	$('#paramBtnCancel').dxButton({
            		onClick:function(){
            			$('#editFilterPopup').dxPopup('hide');
            			$('#editFilterPopup').remove();
            		}
            	});
            }
		});
	};
	
	this.initParamInformation = function(_targetId){
		
		var html = "";
		html +="<div id='paramInfoSetting' style='height:auto;'></div>";
		html +="<div id='paramShowing'></div>";
		html +="<div id='paramTypeSetting' style='height:auto;width:95%;float:left;display:none'></div>";
		$('#'+_targetId).append(html);
		html = '';
		html += '<div id="nameArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
		html += '<div id="captionArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
		html += '<div id="dataTypeArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
		html += '<div id="paramTypeArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
		html += '<div id="etcArea" style="width:100%;height:20%;float:left;padding:5px"></div>'
		$('#paramInfoSetting').append(html);
		html ='';
		html += '<div id="paramNameArea" style="width:50%;float:left;"></div>';
//		html += '<div id="warning" style="width:50%;float:left;padding-left:10px;">* 매개변수 명은 영문으로 설정하세요</div>';
		html += '<div id="warning" style="width:50%;float:left;padding-left:10px;"></div>';
		html += '<div id="dataInputArea" style="width:50%;float:left;padding-left:10px;"><div id="dataInputEdit"  style="padding: 8px 15px 9px 0;"></div></div>';
		$('#nameArea').append(html);
		
		html = '';
		html += '<div id="paramCaptionArea" style="width:50%;float:left;"></div>';
		html += '<div id="dataSearchArea" style="width:50%;float:left;padding-left:10px;"><div id="dataSearch" style="padding: 8px 15px 9px 0;"></div></div>';
		$('#captionArea').append(html);
		
		html = '';
		html += '<div id="dataTypeListArea" style="width:50%;float:left;"></div>';
		html += '<div id="dataBindingArea" style="width:50%;float:left;padding-left:10px;"><div id="dataBind"  style="padding: 8px 15px 9px 0;"></div></div>';

		html += '<div id="dataEditArea" style="width:50%;float:left;padding-left:10px;"><div id="dataEdit"  style="padding: 8px 15px 9px 0;"></div></div>';
		
		$('#dataTypeArea').append(html);
		
		html = '';
		html += '<div id="paramTypeListArea" style="width:50%;float:left;"></div>';
		/*dogfoot shlim 20210415*/
		html += '<div id="dataLineBreak" style="width:50%;float:left;padding-left:10px;"><div id="lineBreak"  style="padding: 8px 15px 9px 0;"></div></div>';
//		html += '<div id="paramDelArea" style="width:50%;float:left;padding-left:10px;"><div id="paramDelYN"  style="padding: 8px 15px 9px 0;"></div></div>';
		$('#paramTypeArea').append(html);
		
		html = '';
		html += '<div id="paramETCAreaA" style="width:45%;float:left;">';
		html += '<div id="orderArea" style="width:45%;float:left;"></div><div id="widthArea" style="width:45%;float:right;"></div>';
		html += '</div>';
		html += '<div id="paramETCAreaB" style="width:50%;float:left;margin-left:30px;">';
		html += '<div id="visibleArea" style="width:45%;float:left;"><div id="visibleYN" style="padding: 8px 15px 9px 0;"/></div>';
		html += '<div id="conditionArea" style="width:45%;float:left;"></div>';
		html += '</div>';
		
		//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
		html += '<div id="paramETCAreaC" style="width:50%;float:left;">';
		html += '<div id="captionWidthVisibleArea" style="float:left;"></div>';
		html += '<div id="captionWidthArea" style="width:55%;float:left;margin-left:30px;"></div>';
		html += '</div>';
		html += '</div>';
		$('#etcArea').append(html);
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 명</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="paramName"></div>';
		html += '</div>';
		html += '</div>';
		$('#paramNameArea').append(html);
		$('#paramName').dxTextBox({
			/*dogfoot 매개변수명 변경  오류 수정 shlim 20200625*/
			//readOnly:true
		});
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 Caption *</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="paramCaption"></div>';
		html += '</div>';
		html += '</div>';
		$('#paramCaptionArea').append(html);
		$('#paramCaption').dxTextBox();
		$('#dataSearch').dxCheckBox({text:'데이터 검색'});
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">데이터 유형 *</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="dataType"></div>';
		html += '</div>';
		html += '</div>';
		$('#dataTypeListArea').append(html);
		
		$('#dataType').dxSelectBox({
			dataSource:[{key:'STRING', caption:'String'},{key:'NUMERIC', caption:'Numeric'},{key:'DATETIME', caption:'DateTime'}],
			displayExpr:'caption',
			valueExpr:'key'
		});
		$('#dataBind').dxCheckBox({text:'데이터 바인딩',visible:false,value: true});
		
		if(WISE.Context.isCubeReport){
			$('#dataEdit').dxCheckBox({text:'매개변수 삭제 유무',value: true});
		}else{
			$('#dataEdit').dxCheckBox({text:'매개변수 삭제 유무',visible:false,value: true});
		}
		/*dogfoot shlim 20210415*/
		$('#lineBreak').dxCheckBox({text:'줄바꿈',value: false});
	
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 유형 *</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="paramType"></div>';
		html += '</div>';
		html += '</div>';
		$('#paramTypeListArea').append(html);
		
		$('#paramType').dxSelectBox({
			dataSource:commonParamType,
			displayExpr:'caption',
			valueExpr:'key',
			onSelectionChanged:function(_e){
				$('#paramShowing').empty();
				$('#paramTypeSetting').empty();
				$('#paramTypeSetting').css('display','none');
				if(_e.selectedItem != null){
					var param_name = $('#paramName').dxTextBox('instance').option('value');
					$.each(self.parameterInformation,function(_key,_val){
						if(_val.PARAM_NM === param_name){
							self.paramTypeSetting(_e.selectedItem.key,self.parameterInformation[_key]);
							return false;
						}
					});

//					self.paramTypeSetting(_e.selectedItem.key,self.parameterInformation[$('#paramName').dxTextBox('instance').option('value')]);
					
					
				}
			}
		});
		
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">순서</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="orderInput"></div>';
		html += '</div>';
		html += '</div>';
		$('#orderArea').append(html);
		$('#orderInput').dxNumberBox({
			showSpinButtons: true
		});
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">넓이</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="widthInput"></div>';
		html += '</div>';
		html += '</div>';
		$('#widthArea').append(html);
		$('#widthInput').dxNumberBox({
			showSpinButtons: true
		});
		
		
		$('#visibleYN').dxCheckBox({text:'Visible'});
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">조건 명</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="conditionInput"></div>';
		html += '</div>';
		html += '</div>';
		$('#conditionArea').append(html);
		/* DOGFOOT ktkang 필터 NotIn 추가  20200716  */
//		$('#conditionInput').dxTextBox({
//			text:'',
//			readOnly:true,
//		});
		
		//20210305 AJKIM 주제영역 Between 필터 추가 dogfoot
		$('#conditionInput').dxSelectBox({
			dataSource:commonOperationList,
			displayExpr:'caption',
			valueExpr:'key',
			onValueChanged: function(e){
				$('#paramType').dxSelectBox('instance').option('value','');
				selectedItem = $("#paramItemListArea").dxDataGrid('instance').getSelectedRowsData();
				if(e.value === 'Between'){
					$('#paramType').dxSelectBox('instance').option('dataSource',betweenParamType);
				}else{
					$('#paramType').dxSelectBox('instance').option('dataSource',commonParamType);
				}
			}
		});
		
		//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
		html = '';
		html += '<div class="dx-field">';
		//html += '<div class="dx-field-label" style="width:90px;">캡션 visible</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="captionWidthVisible"></div>';
		html += '</div>';
		html += '</div>';
		$("#captionWidthVisibleArea").append(html);
		
		$("#captionWidthVisible").dxCheckBox({
			//text:'Visible',
			onValueChanged: function(e){
				if(e.value){
					$("#captionWidth").dxNumberBox('instance').option('disabled',false);
				}else{
					$("#captionWidth").dxNumberBox('instance').option('disabled',true);
				}
			}
		});
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label" style="width:80px;">캡션 넓이</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="captionWidth"></div>';
		html += '</div>';
		html += '</div>';
		$("#captionWidthArea").append(html);
		
		$("#captionWidth").dxNumberBox({
			showSpinButtons: true,
			disabled: $("#captionWidthVisible").dxCheckBox('instance').option('value')?false:true
			//width:63
		})
		
//		$('#paramShowing').on('click',function(){
//			if($('#paramTypeSetting').css('display') == 'none'){
//				$('#paramTypeSetting').css('display','block');
//			}else{
//				$('#paramTypeSetting').css('display','none');
//			}
//		});
	};
	
	this.setParamInfo = function(_paramItem){
		/* DOGFOOT ktkang 필터 NotIn 추가  20200716  */
		$('#conditionInput').dxSelectBox('instance').option('value', _paramItem['OPER']);
		var typeList = $('#paramType').dxSelectBox('instance').option('dataSource');
		var dataList = $('#dataType').dxSelectBox('instance').option('dataSource');
		$('#paramName').dxTextBox('instance').option('value',_paramItem['PARAM_NM']);
		$('#paramCaption').dxTextBox('instance').option('value',_paramItem['PARAM_CAPTION']);
		$('#dataType').dxSelectBox('instance').option('value',_paramItem['DATA_TYPE']);
		$('#paramType').dxSelectBox('instance').option('value',_paramItem['PARAM_TYPE']);
//		if(_paramItem['OPER'] == 'Between'){
//			$('#paramType').dxSelectBox('instance').option('dataSource',betweenParamType);
//		}
//		$.each($('#dataType').dxSelectBox('instance').option('dataSource'),function(_i,_items){
//			if(_paramItem['DATA_TYPE'] == _items['key']){
//				$('#dataType').dxSelectBox('instance').option('value',dataList[_i].key);
//				return false;
//			}
//		});
		
//		$.each($('#paramType').dxSelectBox('instance').option('dataSource'),function(_i,_items){
//			if(_paramItem['PARAM_TYPE'] == _items['key']){
//				$('#paramType').dxSelectBox('instance').option('value',typeList[_i].key);
//				return false;
//			}
//		});
		
		$('#orderInput').dxNumberBox('instance').option('value', _paramItem['ORDER']);
		$('#widthInput').dxNumberBox('instance').option('value', _paramItem['WIDTH']);
		$('#visibleYN').dxCheckBox('instance').option('value',_paramItem['VISIBLE'] == 'Y'? true:false);
		//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
		$('#captionWidthVisible').dxCheckBox('instance').option('value',_paramItem['CAPTION_WIDTH_VISIBLE'] == 'Y'? true:false);
		$('#dataSearch').dxCheckBox('instance').option('value',_paramItem['SEARCH_YN'] == 'Y'? true:false);
		$('#dataEdit').dxCheckBox('instance').option('value',_paramItem['EDIT_YN'] == 'Y'? true:false);
		if(_paramItem.PARAM_TYPE == 'INPUT') {
			var INPUT_EDIT_YN = false;
			if(typeof _paramItem['INPUT_EDIT_YN'] == 'undefined') {
				INPUT_EDIT_YN = true;
			} else if(_paramItem['INPUT_EDIT_YN'] == 'Y') {
				INPUT_EDIT_YN = true;
			}
			$('#dataInputEdit').dxCheckBox('instance').option('value',INPUT_EDIT_YN);
		}
		$('#lineBreak').dxCheckBox('instance').option('value',_paramItem['LINE_BREAK'] == 'Y'? true:false);
		$('#dataBind').dxCheckBox('instance').option('value',_paramItem['BIND_YN'] == 'Y'? true:false);
	};
	
	this.paramTypeSetting = function(_paramType,_paramItem){
		var html = '';
		var showinghtml = '';
		switch(_paramType){
		case 'INPUT':
			showinghtml += '<div id="toggleSpecific"></div>'
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터원본 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOriginType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터 원본</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOrigin" style="width:90%;float:left"></div>';
			html += '<div id="TableSearchButton" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption 항목</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="captionSearchButton"  style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key 항목</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '<div id="keySearchButton" style="float:left"></div>';
			html += '<div id="orderByButton" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">매개변수 기본값</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="DefaultValue"></div>';
			/*dogfoot 매개변수 기본값 설정 CS문구 추가 20200724*/
			html += '<div> ※ Key Value 항목 값을 설정하십시오. 전체 항목을 기본 값으로 할 경우 [All] 입력</div>';
			html += '<div id="UseSqlScriptYN" style="float:left"></div>';
			html += '<div id="MultiSelectYN" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">[전체]항목 표시</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="AllArea"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">조건절 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="whereArea" style="float:left;width:60%"></div><div id="maintainArea" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'입력창 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
			$('#paramTypeSetting').append(html);

			
			$('#dataOriginType').dxSelectBox({
				readOnly:true,
				disabled:true
			});
			
			$('#dataOrigin').dxTextArea({
				readOnly:true,
				disabled:true
			});
			
			$('#CaptionType').dxTextBox({
				readOnly:true,
				disabled:true
			});
			
			$('#KeyType').dxTextBox({
				readOnly:true,
				disabled:true
			});
			
			$('#orderByButton').dxSelectBox({
				readOnly:true,
				disabled:true
			});
			
			$('#MultiSelectYN').dxCheckBox({
				text:'다중 선택',
				readOnly:true,
				disabled:true
			});
			
			/* DOGFOOT ktkang 필터 선택 변경시 기본 값 부분이 초기화 되는 현상 수정  20200205*/
			var defaultVal = '';
			if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'){
				if(_paramItem['HIDDEN_VALUE'] != '') {
					defaultVal = _paramItem['HIDDEN_VALUE'];
				} else {
					defaultVal = _paramItem['DEFAULT_VALUE'];
				}
			}else{
				if(_paramItem['DEFAULT_VALUE']  == '_ALL_VALUE_'){
					defaultVal = '[All]';
				}else{
					defaultVal = _paramItem['DEFAULT_VALUE'];
				}
			}
			
			$('#DefaultValue').dxTextArea({
				value: defaultVal
			});
			$('#UseSqlScriptYN').dxCheckBox({
				text:'기본 값 SQL 쿼리 사용',
				value:_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'? true:false
			});
			
			$('#AllArea').append("<div id='allCheck' style='float:left'></div>");
			
			$('#allCheck').dxCheckBox({
				readOnly:true,
				disabled:true
			});
			$('#whereArea').dxTextBox({
				value:_paramItem['WHERE_CLAUSE']
			});
			$('#maintainArea').dxCheckBox({
				text:'기본값유지',
				value:_paramItem['DEFAULT_VALUE_MAINTAIN']=='Y'? true:false
			});


			$('#dataInputEdit').dxCheckBox({
		    	text:'입력창 수정 여부',
		    	visible:true
		    	,value:_paramItem['INPUT_EDIT_YN']=='Y'? true: typeof _paramItem['INPUT_EDIT_YN']=='undefined' ? true :false
		    });
			
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:true,disabled:true});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',visible:false,readOnly:true});
			$('#paramTypeSetting').css('display','block');
			break;
		case 'LIST':
			showinghtml += '<div id="toggleSpecific"></div>'
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터원본 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOriginType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터 원본 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOrigin" style="width:90%;float:left"></div>';
			html += '<div id="TableSearchButton" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption 항목 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="captionSearchButton"  style="float:left"></div>';
			/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
			html += '<div id="orderByKeySearchButton"  style="float:right"></div>';
			html += '<div id="orderByKey"  style="float:right"></div>';
			html += '<div class="dx-field-label" style="width:50px !important;margin-left:50px;float:right">정렬</div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key 항목 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '<div id="keySearchButton" style="float:left"></div>';
			html += '<div id="orderByButton" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">매개변수 기본값</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="DefaultValue"></div>';
			/*dogfoot 매개변수 기본값 설정 CS문구 추가 20200724*/
			html += '<div> ※ Key Value 항목 값을 설정하십시오. 전체 항목을 기본 값으로 할 경우 [All] 입력</div>';
			html += '<div id="UseSqlScriptYN" style="float:left"></div>';
			html += '<div id="MultiSelectYN" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
//			html += '<div class="dx-field">';
//			
//			html += '</div>';
//			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">[전체]항목 표시</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="AllArea"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">조건절 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="whereArea" style="float:left;width:60%"></div><div id="maintainArea" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'리스트 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
			$('#paramTypeSetting').append(html);
			
			$('#dataOriginType').dxSelectBox({
				dataSource:[{key:'TBL', caption:'테이블'},/*{key:'StoredProcedure', caption:'StoredProcedure'},*/{key:'QUERY', caption:'쿼리'}],
				displayExpr:'caption',
				valueExpr:'key',
				onSelectionChanged:function(_selection){
					if(_selection.selectedItem.key == "QUERY"){
						$('#TableSearchButton').css('display','none');
						$('#keySearchButton').css('display','none');
						$('#captionSearchButton').css('display','none');
						/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
						$('#orderByKeySearchButton').css('display','none');
						$('#orderByKey').dxTextBox('instance').option('value',"");
						$('#orderByKey').dxTextBox('instance').option('readOnly',true);
						
					}
					else{
						$('#TableSearchButton').css('display','block');
						$('#keySearchButton').css('display','block');
						$('#captionSearchButton').css('display','block');
						/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
						$('#orderByKeySearchButton').css('display','block');
						$('#orderByKey').dxTextBox('instance').option('readOnly',false);
					}
				}
			});
			
			$('#dataOrigin').dxTextArea({
				value:_paramItem['DATASRC']
			});
			
			$('#TableSearchButton').dxButton({
				icon:'search',
				onClick:function(_e){
				  	var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
				  	var dsType = 'DS';
				  	/* DOGFOOT ktkang 주제영역 오류 수정  20200707 */
//				  	if(WISE.Context.isCubeReport) {
//				  		dsType = 'CUBE';
//				  	}
					var param = {
						'dsid':selectedItem.DS_ID,
						'dstype':dsType
					}
					$.ajax({
						type : 'post',
						data:param,
						url : WISE.Constants.context + '/report/getTableList.do',
						success: function(_data) {
							gProgressbar.hide();
							var html = "<div id='paramTableSelect'></div>";
							$(".filter-bar").append(html);
							$('#paramTableSelect').dxPopup({
								title:'대상 테이블 목록',
								visible:true,
								width:600,
								height:700,
								contentTemplate:function() {
									return "<div style='height:90%'>" +
											"<div id='overflowScroll' style='height:100%;overflow:auto'>" +
											"<div id='paramTableList'>" +
											"</div>" +
											"</div>" +
											"</div>" +
											"<div style='width:100%;height:8%;text-align:center'>" +
											"<div id='tblApply'>" +
											"</div>" +
											"</div>"
								},
								onShown:function(){
									$('#paramTableList').dxDataGrid({
										height:'500px',
										dataSource:_data.data,
										paging:{
											enabled:false
										},
										selection:{
											mode:'single'
										},
										/* DOGFOOT ktkang 매개변수 테이블 및 컬럼 검색 기능 추가  20200727 */
										searchPanel: {
								            visible: true,
								            width: 240,
								            placeholder: "검색"
										},
										columns: [{
								            dataField: "TBL_NM",
								            caption: "테이블 물리명"
								        },
								        {
								            dataField: "TBL_CAPTION",
								            caption: "테이블 논리명"
								        }]
									});
									$('#tblApply').dxButton({
										text:"확인",
										onClick:function(){
											var selected = $('#paramTableList').dxDataGrid('getSelectedRowsData')[0];
											if(typeof selected != 'undefined'){
												$('#paramTableSelect').dxPopup('hide');
												$('#dataOrigin').dxTextArea('instance').option('value',selected.TBL_NM);
												_paramItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
												/* DOGFOOT ktkang 확인 눌러도 창 안닫히는 부분 수정  20200214 */
											} else {
												$('#paramTableSelect').dxPopup('hide');
											}
										}
									});
//									$('#overflowScroll').dxScrollView({
//										width:'100%',
//										height:'100%',
//									});
								}
							});
						}
					});
				}
			})
			
			$('#CaptionType').dxTextBox({
				value:_paramItem['CAPTION_VALUE_ITEM']
			});
			
			$('#captionSearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var dsType = 'DS';
						/* DOGFOOT ktkang 주제영역 오류 수정  20200707 */
//					  	if(WISE.Context.isCubeReport) {
//					  		dsType = 'CUBE';
//					  	}
						var param = {
								'dsid':selectedItem.DS_ID,
								'dstype':dsType,
								'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
							};
							$.ajax({
								type : 'post',
								data:param,
								url : WISE.Constants.context + '/report/getColumnList.do',
								success: function(_data) {
									gProgressbar.hide();
									var html = "<div id='paramColumnSelect'></div>";
									$(".filter-bar").append(html);
									$('#paramColumnSelect').dxPopup({
										title:'컬럼 선택',
										visible:true,
										width:600,
										height:700,
										contentTemplate:function() {
											return "<div style='height:90%'>" +
													"<div id='overflowScroll' style='height:100%;overflow:auto'>" +
													"<div id='paramColumnList'>" +
													"</div>" +
													"</div>" +
													"</div>" +
													"<div style='width:100%;height:8%;text-align:center'>" +
													"<div id='colApply'>" +
													"</div>" +
													"</div>"
										},
										onShown:function(){
											$('#overflowScroll').dxScrollView({
												width:'100%',
												height:'100%',
											});
											$('#paramColumnList').dxDataGrid({
												dataSource:_data.data,
												columns:[
													{
														dataField:"COL_NM",
														caption:"컬럼 물리명"
													},
													{
														dataField:"COL_CAPTION",
														caption:"컬럼 논리명"
													}
												],
												paging:{
													enabled:false
												},
												selection:{
													mode:'single'
												},
												/* DOGFOOT ktkang 매개변수 테이블 및 컬럼 검색 기능 추가  20200727 */
												searchPanel: {
										            visible: true,
										            width: 240,
										            placeholder: "검색"
												}
											});
											$('#colApply').dxButton({
												text:"확인",
												onClick:function(){
													var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
													if(typeof selected != 'undefined'){
														$('#paramColumnSelect').dxPopup('hide');
														$('#CaptionType').dxTextBox('instance').option('value',selected.COL_NM);
														_paramItem.CAPTION_VALUE_ITEM =$('#CaptionType').dxTextBox('instance').option('value');
													/* DOGFOOT ktkang 확인 눌러도 창 안닫히는 부분 수정  20200214 */
													} else {
														$('#paramColumnSelect').dxPopup('hide');
													}
												}
											});
										}
									});
								}
							});
					}else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
				}
			});
			
			$('#keySearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var dsType = 'DS';
						/* DOGFOOT ktkang 주제영역 오류 수정  20200707 */
//					  	if(WISE.Context.isCubeReport) {
//					  		dsType = 'CUBE';
//					  	}
						var param = {
								'dsid':selectedItem.DS_ID,
								'dstype':dsType,
								'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
							};
							$.ajax({
								type : 'post',
								data:param,
								url : WISE.Constants.context + '/report/getColumnList.do',
								success: function(_data) {
									gProgressbar.hide();
									var html = "<div id='paramColumnSelect'></div>";
									$(".filter-bar").append(html);
									$('#paramColumnSelect').dxPopup({
										title:'컬럼 선택',
										visible:true,
										width:600,
										height:700,
										contentTemplate:function() {
											return "<div style='height:90%'>" +
													"<div id='overflowScroll' style='height:100%;overflow:auto'>" +
													"<div id='paramColumnList'>" +
													"</div>" +
													"</div>" +
													"</div>" +
													"<div style='width:100%;height:8%;text-align:center'>" +
													"<div id='colApply'>" +
													"</div>" +
													"</div>"
										},
										onShown:function(){
											$('#overflowScroll').dxScrollView({
												width:'100%',
												height:'100%',
											});
											$('#paramColumnList').dxDataGrid({
												dataSource:_data.data,
												columns:[
													{
														dataField:"COL_NM",
														caption:"컬럼 물리명"
													},
													{
														dataField:"COL_CAPTION",
														caption:"컬럼 논리명"
													}
												],
												paging:{
													enabled:false
												},
												selection:{
													mode:'single'
												},
												/* DOGFOOT ktkang 매개변수 테이블 및 컬럼 검색 기능 추가  20200727 */
												searchPanel: {
										            visible: true,
										            width: 240,
										            placeholder: "검색"
												}
											});
											$('#colApply').dxButton({
												text:"확인",
												onClick:function(){
													var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
													if(typeof selected != 'undefined'){
														$('#paramColumnSelect').dxPopup('hide');
														$('#KeyType').dxTextBox('instance').option('value',selected.COL_NM);
														_paramItem.KEY_VALUE_ITEM =$('#KeyType').dxTextBox('instance').option('value');
													/* DOGFOOT ktkang 확인 눌러도 창 안닫히는 부분 수정  20200214 */
													} else {
														$('#paramColumnSelect').dxPopup('hide');
													}
												}
											});
										}
									});
								}
							});
					}else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
				}
			});
			/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
			$('#orderByKeySearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var dsType = 'DS';
						/* DOGFOOT ktkang 주제영역 오류 수정  20200707 */
//					  	if(WISE.Context.isCubeReport) {
//					  		dsType = 'CUBE';
//					  	}
						var param = {
								'dsid':selectedItem.DS_ID,
								'dstype':dsType,
								'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
							};
							$.ajax({
								type : 'post',
								data:param,
								url : WISE.Constants.context + '/report/getColumnList.do',
								success: function(_data) {
									gProgressbar.hide();
									var html = "<div id='paramColumnSelect'></div>";
									$(".filter-bar").append(html);
									$('#paramColumnSelect').dxPopup({
										title:'컬럼 선택',
										visible:true,
										width:600,
										height:700,
										contentTemplate:function() {
											return "<div style='height:90%'>" +
													"<div id='overflowScroll' style='height:100%;overflow:auto'>" +
													"<div id='paramColumnList'>" +
													"</div>" +
													"</div>" +
													"</div>" +
													"<div style='width:100%;height:8%;text-align:center'>" +
													"<div id='colApply'>" +
													"</div>" +
													"</div>"
										},
										onShown:function(){
											$('#overflowScroll').dxScrollView({
												width:'100%',
												height:'100%',
											});
											$('#paramColumnList').dxDataGrid({
												dataSource:_data.data,
												columns:[
													{
														dataField:"COL_NM",
														caption:"컬럼 물리명"
													},
													{
														dataField:"COL_CAPTION",
														caption:"컬럼 논리명"
													}
												],
												paging:{
													enabled:false
												},
												selection:{
													mode:'single'
												},
												/* DOGFOOT ktkang 매개변수 테이블 및 컬럼 검색 기능 추가  20200727 */
												searchPanel: {
										            visible: true,
										            width: 240,
										            placeholder: "검색"
												}
											});
											$('#colApply').dxButton({
												text:"확인",
												onClick:function(){
													var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
													if(typeof selected != 'undefined'){
														$('#paramColumnSelect').dxPopup('hide');
														$('#orderByKey').dxTextBox('instance').option('value',selected.COL_NM);
														_paramItem.KEY_VALUE_ITEM =$('#KeyType').dxTextBox('instance').option('value');
													/* DOGFOOT ktkang 확인 눌러도 창 안닫히는 부분 수정  20200214 */
													} else {
														$('#paramColumnSelect').dxPopup('hide');
													}
												}
											});
										}
									});
								}
							});
					}else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
				}
			});
			
			$('#KeyType').dxTextBox({
				value:_paramItem['KEY_VALUE_ITEM']
			});
			/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
			$('#orderByKey').dxTextBox({
				width:"32%",
				value:_paramItem['ORDERBY_KEY'] ? _paramItem['ORDERBY_KEY']:"",
				readOnly: true,
			});
			var orderByButtonDataSource = [{key:'ASC',caption:'오름차순'},{key:'DESC',caption:'내림차순'}];
			$('#orderByButton').dxSelectBox({
				dataSource: orderByButtonDataSource,
				displayExpr:'caption',
				valueExpr:'key',
				value:'ASC'
			});
			
			$('#MultiSelectYN').dxCheckBox({
				text:'다중 선택',
				value:_paramItem['MULTI_SEL'] == 'Y'? true:false
			})
			
			var defaultVal = '';
			if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'){
			/* DOGFOOT ktkang 필터 선택 변경시 기본 값 부분이 초기화 되는 현상 수정  20200116*/
				if(_paramItem['HIDDEN_VALUE'] != '') {
					defaultVal = _paramItem['HIDDEN_VALUE'];
				} else {
					defaultVal = _paramItem['DEFAULT_VALUE'];
				}
			}else{
				if(_paramItem['DEFAULT_VALUE']  == '_ALL_VALUE_'){
					defaultVal = '[All]';
				}else{
					defaultVal = _paramItem['DEFAULT_VALUE'];
				}
			}
			$('#DefaultValue').dxTextArea({
				value: defaultVal
				
			});
			$('#UseSqlScriptYN').dxCheckBox({
				text:'기본 값 SQL 쿼리 사용',
				value:_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'? true:false
			});
			
			$('#AllArea').append("<div id='allCheck' style='float:left'></div>");
			
			$('#allCheck').dxCheckBox({
				value:_paramItem['ALL_YN'] == 'Y'? true:false
			});
			
			
			$('#whereArea').dxTextBox({
				value:_paramItem['WHERE_CLAUSE']
			});
			$('#maintainArea').dxCheckBox({
				text:'기본값유지',
				value:_paramItem['DEFAULT_VALUE_MAINTAIN']=='Y'? true:false
			});
			$.each($('#dataOriginType').dxSelectBox('instance').option('dataSource'),function(_i,_items){
				if(_paramItem['DATASRC_TYPE'] == _items['key']){
					$('#dataOriginType').dxSelectBox('instance').option('value',_items['key']);
					return false;
				}
				else if(_paramItem['DATASRC_TYPE'].length == 0){
					$('#dataOriginType').dxSelectBox('instance').option('value','TBL');
					return false;
				}
			});

			$.each($('#orderByButton').dxSelectBox('instance').option('dataSource'),function(_i,_items){
				if(_paramItem['SORT_TYPE'] == _items['key']){
					$('#orderByButton').dxSelectBox('instance').option('value',_items['key']);
					return false;
				}
			});
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:false,disabled:false});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',visible:false,readOnly:false});
			$('#dataInputEdit').dxCheckBox({text:'입력창 수정 여부',visible:false,readOnly:false});
			$('#paramTypeSetting').css('display','block');
			break;
		case 'CAND':
			showinghtml += '<div id="toggleSpecific"></div>'
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">기본 값 유형 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="candDefaultType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div id="nowSettingArea">' 
			html += '<div class="dx-field">';
			html += '<div id="defaultValueCaption" class="dx-field-label">기본 값 계산 *</div>';
			html += '<div id="candInputArea" class="dx-field-value">';
			html += '<div id="DefaultValueNow" style="float:left"></div><span style="float:left">을 기준으로 </span><div id="candMoveValue" style="float:left"></div><span>이동 값을 기본 값으로 합니다</span><div><br/>* 기본 계산 값 계산 앞 부분을 [년도]를 선택하고 뒤 부분의 숫자를 -1로 설정하면 매개변수 기본 값 유형에서 선택 한 기본 값을 기준으로 전년도 값을 자동으로 가져옵니다.</div><div>년도, 월, 주, 일을 기준으로 기간을 설정할 수 있습니다.</div>'
			html += '</div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div id="querySettingArea">' 
			html += '<div class="dx-field">';
			html += '<div id="defaultValueCaption" class="dx-field-label">기본 값 *</div>';
			html += '<div id="candInputArea" class="dx-field-value">';
			html += '<div id="DefaultValueQuery" style="width:90%;float:left"></div>';
			html += '<div id="defaultQuery" style="float:left"/>';
			html += '</div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption Value 형식 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="defaultValueMaintain" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key Value 형식 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'달력 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
//			$('#candDefaultType').dxSelectBox('instance').option('value',_paramItem['CAND_DEFAULT_TYPE'] == "" ? "NOW":_paramItem['CAND_DEFAULT_TYPE']  );
			$('#paramTypeSetting').append(html);
			var candDefaultTypeArr = [{key:'NOW', caption:'현재'},{key:'QUERY', caption:'쿼리'}];
			$('#candDefaultType').dxSelectBox({
				dataSource:[{key:'NOW', caption:'현재'},{key:'QUERY', caption:'쿼리'}],
				displayExpr:'caption',
				valueExpr:'key',
				value : _paramItem['CAND_DEFAULT_TYPE'] == "" ? "NOW":_paramItem['CAND_DEFAULT_TYPE'],  
				onSelectionChanged:function(_selection){
					if(_selection.selectedItem.key == "QUERY"){
						$('#nowSettingArea').css('display','none');
						$('#querySettingArea').css('display','block');
					}
					else{
						$('#nowSettingArea').css('display','block');
						$('#querySettingArea').css('display','none');
					}
				}
			});
			
			$('#DefaultValueQuery').dxTextArea();
			
			$('#DefaultValueNow').dxSelectBox({
				dataSource:[{key:'YEAR', caption:'년도'},{key:'MONTH', caption:'월'},{key:'DAY', caption:'일'}],
				displayExpr:'caption',
				valueExpr:'key',
				width:'100px'
			});
			
			$('#candMoveValue').dxNumberBox({
				width:'100px',
				showSpinButtons: true,
			});
			
			$('#defaultQuery').dxCheckBox({
				text:'use SQL Script',
				value : _paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y' ? true : false
			});
			$('#KeyType').dxSelectBox({
				dataSource:[{key:'yyyy', caption:'yyyy'},{key:'yyyyMM', caption:'yyyyMM'},{key:'yyyyMMdd', caption:'yyyyMMdd'},{key:'yyyy-MM', caption:'yyyy-MM'},{key:'yyyy-MM-dd', caption:'yyyy-MM-dd'}],
				displayExpr:'caption',
				valueExpr:'key'
			});
			$('#CaptionType').dxSelectBox({
				dataSource:[{key:'yyyy', caption:'yyyy'},{key:'yyyyMM', caption:'yyyyMM'},{key:'yyyyMMdd', caption:'yyyyMMdd'},{key:'yyyy-MM', caption:'yyyy-MM'},{key:'yyyy-MM-dd', caption:'yyyy-MM-dd'}],
				displayExpr:'caption',
				valueExpr:'key'
			});
			
			
			$('#KeyType').dxSelectBox('instance').option('value',_paramItem['KEY_FORMAT']);
			$('#CaptionType').dxSelectBox('instance').option('value',_paramItem['CAPTION_FORMAT']);
			
			if(_paramItem['CAND_DEFAULT_TYPE'] == 'QUERY'){
				/* DOGFOOT ktkang 필터 선택 변경시 기본 값 부분이 초기화 되는 현상 수정  20200116*/
				if(_paramItem['HIDDEN_VALUE'] != '') {
					$('#DefaultValueQuery').dxTextArea('instance').option('value',_paramItem['HIDDEN_VALUE']);
				} else {
					$('#DefaultValueQuery').dxTextArea('instance').option('value',_paramItem['DEFAULT_VALUE']);
				}
			}else{
				$('#DefaultValueNow').dxSelectBox('instance').option('value',_paramItem['CAND_PERIOD_BASE']);
				$('#candMoveValue').dxNumberBox('instance').option('value',_paramItem['CAND_PERIOD_VALUE']);
			}
			$('#paramTypeSetting').css('display','block');
			break;
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:false,disabled:false});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',visible:false,readOnly:false});
			$('#dataInputEdit').dxCheckBox({text:'입력창 수정 여부',visible:false,readOnly:false});
			
		case 'BETWEEN_INPUT':
			showinghtml += '<div id="toggleSpecific"></div>'
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">데이터원본 유형</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="dataOriginType" style="float:left"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">데이터 원본 *</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="dataOrigin" style="width:90%;float:left"></div>';
				html += '<div id="TableSearchButton" style="float:left"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">Caption 항목 *</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="CaptionType" style="float:left"></div>';
				html += '<div id="captionSearchButton"  style="float:left"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">Key 항목 *</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="KeyType" style="float:left"></div>';
				html += '<div id="keySearchButton" style="float:left"></div>';
				html += '<div id="orderByButton" style="float:right"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">매개변수 기본값</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="DefaultValueFrom" style="width:48%;float:left"></div>';
				html += '<div id="DefaultValueTo" style="width:48%;float:right"></div>';
				/*dogfoot 매개변수 기본값 설정 CS문구 추가 20200724*/
				html += '<div style="width:95%;float:left"> ※ Key Value 항목 값을 설정하십시오. 전체 항목을 기본 값으로 할 경우 [All] 입력</div>';
				html += '<div id="UseSqlScriptYN" style="float:left"></div>';
				html += '<div id="MultiSelectYN" style="float:right"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">[전체]항목 표시</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="AllArea"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">조건절 *</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="whereArea" style="float:left;width:60%"></div><div id="maintainArea" style="float:right"></div>';
				html += '</div>';
				html += '</div>';
				
				$('#paramShowing').append(showinghtml);
				$('#toggleSpecific').dxButton({
					text:'입력창 상세 설정',
					onClick:function(){
						if($('#paramTypeSetting').css('display') == 'none'){
							$('#paramTypeSetting').css('display','block');
						}else{
							$('#paramTypeSetting').css('display','none');
						}
					}
				});
				$('#paramTypeSetting').append(html);
				
				var defaultToVal = '',defaultFromVal = '';
				
				var betweenDefault;
				
				
				if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'){
					if(_paramItem['HIDDEN_VALUE'] == "") {
						betweenDefault = _paramItem['DEFAULT_VALUE'].split(',');
						defaultFromVal = Base64.decode(betweenDefault[0]);
						defaultToVal =  Base64.decode(betweenDefault[1]);
					} else {
						betweenDefault = _paramItem['HIDDEN_VALUE'].split(',');
						defaultFromVal = Base64.decode(betweenDefault[0]);
						defaultToVal = Base64.decode(betweenDefault[1]);
					}
				}else{
					var splitVal = _paramItem['HIDDEN_VALUE'].split(',');
					if(splitVal[0]  == '_ALL_VALUE_'){
						defaultFromVal = '[All]';
					}else{
						defaultFromVal = _paramItem['DEFAULT_VALUE'][0];
					}
					if(splitVal[1]  == '_ALL_VALUE_'){
						defaultToVal = '[All]';
					}else{
						defaultToVal = _paramItem['DEFAULT_VALUE'][1];
					}
				}
				
				$('#dataOriginType').dxSelectBox({
					readOnly:true,
					disabled:true
				});
				
				$('#dataOrigin').dxTextArea({
					readOnly:true,
					disabled:true
				});
				
				$('#CaptionType').dxTextBox({
					readOnly:true,
					disabled:true
				});
				
				$('#KeyType').dxTextBox({
					readOnly:true,
					disabled:true
				});
				
				$('#orderByButton').dxSelectBox({
					readOnly:true,
					disabled:true
				});
				
				$('#MultiSelectYN').dxCheckBox({
					text:'다중 선택',
					readOnly:true,
					disabled:true
				});

				$('#DefaultValueFrom').dxTextArea({
					value:defaultFromVal
				});
				$('#DefaultValueTo').dxTextArea({
					value:defaultToVal
				});
				$('#UseSqlScriptYN').dxCheckBox({
					text:'기본 값 SQL 쿼리 사용',
					value:_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'? true:false
				});
				
				$('#AllArea').append("<div id='allCheck' style='float:left'></div>");
				
				$('#allCheck').dxCheckBox({
					readOnly:true,
					disabled:true
				});
				$('#whereArea').dxTextBox({
					value:_paramItem['WHERE_CLAUSE']
				});
				$('#maintainArea').dxCheckBox({
					text:'기본값유지',
					value:_paramItem['DEFAULT_VALUE_MAINTAIN']=='Y'? true:false
				});
				$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:true,disabled:true});
				$('#dataBind').dxCheckBox({text:'데이터 바인딩',visible:false,readOnly:true});
				$('#dataInputEdit').dxCheckBox({text:'입력창 수정 여부',visible:false,readOnly:false});
				$('#paramTypeSetting').css('display','block');
				break;
			break;
		case 'BETWEEN_LIST':
			showinghtml += '<div id="toggleSpecific"></div>'
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터원본 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOriginType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터 원본 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOrigin" style="width:80%;float:left"></div>';
			html += '<div id="TableSearchButton" style="float:left;margin-left:5px;"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption 항목 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="captionSearchButton"  style="float:left;margin-left:5px;"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key 항목 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '<div id="keySearchButton" style="float:left;margin-left:5px;"></div>';
			html += '<div id="orderByButton" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">매개변수 기본값</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="DefaultValueFrom" style="width:48%;float:left"></div>';
			html += '<div id="DefaultValueTo" style="width:48%;float:right"></div>';
			/*dogfoot 매개변수 기본값 설정 CS문구 추가 20200724*/
			html += '<div style="width:95%;float:left"> ※ Key Value 항목 값을 설정하십시오. 전체 항목을 기본 값으로 할 경우 [All] 입력</div>';
			html += '<div id="UseSqlScriptYN" style="float:left"></div>';
			html += '<div id="MultiSelectYN" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
//				html += '<div class="dx-field">';
//				
//				html += '</div>';
//				html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">[전체]항목 표시</div>';
			html += '<div class="dx-field-value" style="margin-top: 5px;">';
			html += '<div id="AllArea"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">조건절</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="whereArea" style="float:left;width:60%"></div><div id="maintainArea" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'리스트 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
			$('#paramTypeSetting').append(html);
			
			$('#dataOriginType').dxSelectBox({
				dataSource:[{key:'TBL', caption:'테이블'},/*{key:'StoredProcedure', caption:'StoredProcedure'},*/{key:'QUERY', caption:'쿼리'}],
				displayExpr:'caption',
				valueExpr:'key',
				onSelectionChanged:function(_selection){
					if(_selection.selectedItem.key == "QUERY"){
						$('#TableSearchButton').css('display','none');
						$('#keySearchButton').css('display','none');
						$('#captionSearchButton').css('display','none');
					}
					else{
						$('#TableSearchButton').css('display','block');
						$('#keySearchButton').css('display','block');
						$('#captionSearchButton').css('display','block');
					}
				}
			});
			
			$('#dataOrigin').dxTextArea({
				value:_paramItem['DATASRC']
			});
			
			$('#TableSearchButton').dxButton({
				icon:'search',
				onClick:function(_e){
				  	var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					var param = {
						'dsid':selectedItem.DS_ID,
						'dstype':'DS'
					}
					$.ajax({
						type : 'post',
						data:param,
						url : WISE.Constants.context + '/report/getTableList.do',
						success: function(_data) {
							gProgressbar.hide();
							var html = "<div id='paramTableSelect'></div>";
							$(".filter-bar").append(html);
							$('#paramTableSelect').dxPopup({
								title:'대상 테이블 목록',
								visible:true,
								width:600,
								height:700,
								contentTemplate:function() {
									return "<div style='height:90%'><div id='overflowScroll' style='height:100%;overflow:auto'><div id='paramTableList'></div></div></div><div style='width:100%;height:8%;text-align:center'><div id='tblApply'></div></div>"
								},
								onShown:function(){
									$('#paramTableList').dxDataGrid({
										height:'500px',
										dataSource:_data.data,
										paging:{
											enabled:false
										},
										selection:{
											mode:'single'
										},
										/* DOGFOOT ktkang 매개변수 테이블 및 컬럼 검색 기능 추가  20200727 */
										searchPanel: {
								            visible: true,
								            width: 240,
								            placeholder: "검색"
										},
										columns: [{
								            dataField: "TBL_NM",
								            caption: "테이블 물리명"
								        },
								        {
								            dataField: "TBL_CAPTION",
								            caption: "테이블 논리명"
								        }]
									});
									$('#tblApply').dxButton({
										text:"확인",
										onClick:function(){
											var selected = $('#paramTableList').dxDataGrid('getSelectedRowsData')[0];
											if(typeof selected != 'undefined'){
												$('#paramTableSelect').dxPopup('hide');
												$('#dataOrigin').dxTextArea('instance').option('value',selected.TBL_NM);
												_paramItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
											/* DOGFOOT ktkang 확인 눌러도 창 안닫히는 부분 수정  20200214 */
											} else {
												$('#paramTableSelect').dxPopup('hide');
											}
										}
									});
//									$('#overflowScroll').dxScrollView({
//										width:'100%',
//										height:'100%',
//									});
								}
							});
						}
					});
				}
			})
			
			$('#CaptionType').dxTextBox({
				value:_paramItem['CAPTION_VALUE_ITEM']
			});
			
			$('#captionSearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var param = {
							'dsid':selectedItem.DS_ID,
							'dstype':'DS',
							'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
						};
						$.ajax({
							type : 'post',
							data:param,
							url : WISE.Constants.context + '/report/getColumnList.do',
							success: function(_data) {
								gProgressbar.hide();
								var html = "<div id='paramColumnSelect'></div>";
								$(".filter-bar").append(html);
								$('#paramColumnSelect').dxPopup({
									title:'컬럼 선택',
									visible:true,
									width:600,
									height:700,
									contentTemplate:function() {
										return "<div style='height:90%'><div id='overflowScroll'><div id='paramColumnList'></div></div></div><div style='width:100%;height:8%;text-align:center'><div id='colApply'></div></div>"
									},
									onShown:function(){
										$('#overflowScroll').dxScrollView({
											width:'100%',
											height:'100%',
										});
										$('#paramColumnList').dxDataGrid({
											dataSource:_data.data,
											columns:[
												{
													dataField:"COL_NM",
													caption:"컬럼 물리명"
												},
												{
													dataField:"COL_CAPTION",
													caption:"컬럼 논리명"
												}
											],
											paging:{
												enabled:false
											},
											selection:{
												mode:'single'
											},
											/* DOGFOOT ktkang 매개변수 테이블 및 컬럼 검색 기능 추가  20200727 */
											searchPanel: {
									            visible: true,
									            width: 240,
									            placeholder: "검색"
											}
										});
										$('#colApply').dxButton({
											text:"확인",
											onClick:function(){
												var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
												if(typeof selected != 'undefined'){
													$('#paramColumnSelect').dxPopup('hide');
													$('#CaptionType').dxTextBox('instance').option('value',selected.COL_NM);
													_paramItem.CAPTION_VALUE_ITEM =$('#CaptionType').dxTextBox('instance').option('value');
												/* DOGFOOT ktkang 확인 눌러도 창 안닫히는 부분 수정  20200214 */
												} else {
													$('#paramColumnSelect').dxPopup('hide');
												}
											}
										});
									}
								});
							}
						});
					}
					else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
					
				}
			});
			
			$('#keySearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var param = {
							'dsid':selectedItem.DS_ID,
							'dstype':'DS',
							'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
						};
						$.ajax({
							type : 'post',
							data:param,
							url : WISE.Constants.context + '/report/getColumnList.do',
							success: function(_data) {
								gProgressbar.hide();
								var html = "<div id='paramColumnSelect'></div>";
								$(".filter-bar").append(html);
								$('#paramColumnSelect').dxPopup({
									title:'컬럼 선택',
									visible:true,
									width:600,
									height:700,
									contentTemplate:function() {
										return "<div style='height:90%'><div id='overflowScroll'><div id='paramColumnList'></div></div></div><div style='width:100%;height:8%;text-align:center'><div id='colApply'></div></div>"
									},
									onShown:function(){
										$('#overflowScroll').dxScrollView({
											width:'100%',
											height:'100%',
										});
										$('#paramColumnList').dxDataGrid({
											dataSource:_data.data,
											columns:[
												{
													dataField:"COL_NM",
													caption:"컬럼 물리명"
												},
												{
													dataField:"COL_CAPTION",
													caption:"컬럼 논리명"
												}
											],
											paging:{
												enabled:false
											},
											selection:{
												mode:'single'
											},
											/* DOGFOOT ktkang 매개변수 테이블 및 컬럼 검색 기능 추가  20200727 */
											searchPanel: {
									            visible: true,
									            width: 240,
									            placeholder: "검색"
											}
										});
										$('#colApply').dxButton({
											text:"확인",
											onClick:function(){
												var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
												if(typeof selected != 'undefined'){
													$('#paramColumnSelect').dxPopup('hide');
													$('#KeyType').dxTextBox('instance').option('value',selected.COL_NM);
													_paramItem.KEY_VALUE_ITEM =$('#KeyType').dxTextBox('instance').option('value');
												/* DOGFOOT ktkang 확인 눌러도 창 안닫히는 부분 수정  20200214 */
												} else {
													$('#paramColumnSelect').dxPopup('hide');
												}
											}
										});
									}
								});
							}
						});
					}else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
				}
			});
			
			$('#KeyType').dxTextBox({
				value:_paramItem['KEY_VALUE_ITEM']
			});
			var orderByButtonDataSource = [{key:'ASC',caption:'오름차순'},{key:'DESC',caption:'내림차순'}];
			$('#orderByButton').dxSelectBox({
				dataSource: orderByButtonDataSource,
				displayExpr:'caption',
				valueExpr:'key',
				value:'ASC'
			});
			
			var defaultToVal = '',defaultFromVal = '';
			if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'){
				if(_paramItem['HIDDEN_VALUE'] == "") {
					betweenDefault = _paramItem['DEFAULT_VALUE'].split(',');
					defaultFromVal = Base64.decode(betweenDefault[0]);
					defaultToVal =  Base64.decode(betweenDefault[1]);
				} else {
					betweenDefault = _paramItem['HIDDEN_VALUE'].split(',');
					defaultFromVal = Base64.decode(betweenDefault[0]);
					defaultToVal = Base64.decode(betweenDefault[1]);
				}
			}else{
				var splitVal = _paramItem['HIDDEN_VALUE'].split(',');
				if(splitVal[0]  == '_ALL_VALUE_'){
					defaultFromVal = '[All]';
				}else{
					defaultFromVal = _paramItem['DEFAULT_VALUE'][0];
				}
				if(splitVal[1]  == '_ALL_VALUE_'){
					defaultToVal = '[All]';
				}else{
					defaultToVal = _paramItem['DEFAULT_VALUE'][1];
				}
			}
			
			
			$('#DefaultValueFrom').dxTextArea({
				value: defaultFromVal
			});
			$('#DefaultValueTo').dxTextArea({
				value: defaultToVal
			});
			$('#UseSqlScriptYN').dxCheckBox({
				text:'기본 값 SQL 쿼리 사용',
				value:_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'? true:false
			});
			
			$('#AllArea').append("<div id='allCheck' style='float:left'></div>");
			
			$('#allCheck').dxCheckBox({
				value:_paramItem['ALL_YN'] == 'Y'? true:false
			});
			$('#whereArea').dxTextBox({
				value:_paramItem['WHERE_CLAUSE']
			});
			$('#maintainArea').dxCheckBox({
				text:'기본값유지',
				value:_paramItem['DEFAULT_VALUE_MAINTAIN']=='Y'? true:false
			});
			$.each($('#dataOriginType').dxSelectBox('instance').option('dataSource'),function(_i,_items){
				if(_paramItem['DATASRC_TYPE'] == _items['key']){
					$('#dataOriginType').dxSelectBox('instance').option('value',_items['key']);
					return false;
				}
				else if(_paramItem['DATASRC_TYPE'].length == 0){
					$('#dataOriginType').dxSelectBox('instance').option('value','TBL');
					return false;
				}
			});

			$.each($('#orderByButton').dxSelectBox('instance').option('dataSource'),function(_i,_items){
				if(_paramItem['SORT_TYPE'] == _items['key']){
					$('#orderByButton').dxSelectBox('instance').option('value',_items['key']);
					return false;
				}
			});
			
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:false,disabled:false});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',visible:false,readOnly:false});
			$('#dataInputEdit').dxCheckBox({text:'입력창 수정 여부',visible:false,readOnly:false});
			$('#paramTypeSetting').css('display','block');
			break;
		case 'BETWEEN_CAND':
			showinghtml += '<div id="toggleSpecific"></div>';
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">기본 값 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="candDefaultType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div id="nowSettingArea">';
			html += '<div class="dx-field">';
			html += '<div id="defaultValueCaption" class="dx-field-label">기본 값 계산</div>';
			html += '<div id="candInputArea" class="dx-field-value">';
			html += '<div>From : </div><div id="DefaultValueNowFrom" style="width:90%;float:left"></div>';
			html += '<span style="float:left">을 기준으로 </span>';
			html += '<div id="candMoveValueFrom" style="float:left"></div>';
			/*dogfoot 캘린더 기간 설정 shlim 20210427*/
			html += '<span>이동 값을 기본 값으로 합니다</span></br>';
			/* DOGFOOT syjin 비트윈 달력에서 화면 수정  20200716 */
			html += '<div style="margin-top:10px;">To : </div><div id="DefaultValueNowTo" style="width:90%;float:left"></div>';
			html += '<span style="float:left">을 기준으로 </span>';
			html += '<div id="candMoveValueTo" style="float:left"></div>';
			/*dogfoot 캘린더 기간 설정 shlim 20210427*/
			html += '<span>이동 값을 기본 값으로 합니다</span><div style="margin-top:10px;">* 기본 계산 값 계산 앞 부분을 [년도]를 선택하고 뒤 부분의 숫자를 -1로 설정하면 매개변수 기본 값 유형에서 선택 한 기본 값을 기준으로 전년도 값을 자동으로 가져옵니다.</div><div>년도, 월, 주, 일을 기준으로 기간을 설정할 수 있습니다.</div></br>';
			html += '</div>';
			html += '</div>';
			html += '</div>';
            /*dogfoot 캘린더 기간 설정 shlim 20210427*/
            html += '<div id="maxSettingArea">';
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">최대 조회 기간 설정</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="candFromToGap" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div id="querySettingArea">';
			html += '<div class="dx-field">';
			html += '<div id="defaultValueCaption" class="dx-field-label">기본 값 </div>';
			html += '<div id="candInputArea" class="dx-field-value">';
			html += '<div id="DefaultValueQueryFrom" style="width:49%;float:left"></div>';
			html += '<div id="DefaultValueQueryTo" style="width:49%;float:right"></div>';
			html += '<div id="defaultQuery" style="float:left"/>';
			html += '</div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption Value 형식 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="defaultValueMaintain" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key Value 형식 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'달력 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
			
			$('#paramTypeSetting').append(html);
			var candDefaultTypeArr = [{key:'NOW', caption:'현재'},{key:'QUERY', caption:'쿼리'}];
			$('#candDefaultType').dxSelectBox({
				dataSource:[{key:'NOW', caption:'현재'},{key:'QUERY', caption:'쿼리'}],
				displayExpr:'caption',
				valueExpr:'key',
				value:"NOW",
				onSelectionChanged:function(_selection){
					if(_selection.selectedItem.key == "QUERY"){
						$('#querySettingArea').css('display','block');
						$('#nowSettingArea').css('display','none');
					}
					else{
						$('#querySettingArea').css('display','none');
						$('#nowSettingArea').css('display','block');
					}
				}
			});
			/*dogfoot 캘린더 기간 설정 shlim 20210427*/
			$('#candFromToGap').dxNumberBox({
				width:150,
				showSpinButtons: true,
				onValueChanged: function(e){
					if(e.value < 0){
					    this.option("value",0)
					    WISE.alert("최대기간설정 값은 0보다 커야 합니다. ")	
					}
				},
			}).dxNumberBox('instance');
			
			$('#KeyType').dxSelectBox({
				dataSource:[{key:'yyyy', caption:'yyyy'},{key:'yyyyMM', caption:'yyyyMM'},{key:'yyyyMMdd', caption:'yyyyMMdd'},{key:'yyyy-MM', caption:'yyyy-MM'},{key:'yyyy-MM-dd', caption:'yyyy-MM-dd'}],
				displayExpr:'caption',
				valueExpr:'key'
			});
			$('#CaptionType').dxSelectBox({
				dataSource:[{key:'yyyy', caption:'yyyy'},{key:'yyyyMM', caption:'yyyyMM'},{key:'yyyyMMdd', caption:'yyyyMMdd'},{key:'yyyy-MM', caption:'yyyy-MM'},{key:'yyyy-MM-dd', caption:'yyyy-MM-dd'}],
				displayExpr:'caption',
				valueExpr:'key'
			});
			
			$('#candDefaultType').dxSelectBox('instance').option('value',_paramItem['CAND_DEFAULT_TYPE'] == "" ? "NOW":_paramItem['CAND_DEFAULT_TYPE']  );
			/*dogfoot 캘린더 기간 설정 shlim 20210427*/
			$('#candFromToGap').dxNumberBox('instance').option('value',_paramItem['CAND_MAX_GAP'] == "" ? 0 : _paramItem['CAND_MAX_GAP'] ? _paramItem['CAND_MAX_GAP'] : 0 );
			$('#KeyType').dxSelectBox('instance').option('value',_paramItem['KEY_FORMAT']);
			$('#CaptionType').dxSelectBox('instance').option('value',_paramItem['CAPTION_FORMAT']);
			
			
			$('#DefaultValueNowFrom').dxSelectBox({
				dataSource:[{key:'YEAR', caption:'년도'},{key:'MONTH', caption:'월'},{key:'DAY', caption:'일'}],
				displayExpr:'caption',
				valueExpr:'key',
				width:100,
				height:25,
			});
			$('#DefaultValueNowTo').dxSelectBox({
				dataSource:[{key:'YEAR', caption:'년도'},{key:'MONTH', caption:'월'},{key:'DAY', caption:'일'}],
				displayExpr:'caption',
				valueExpr:'key',
				width:100,
				height:25,
			});
			$('#candMoveValueFrom').dxNumberBox({
				width:150,
				height:25,
				showSpinButtons: true,
			});
			$('#candMoveValueTo').dxNumberBox({
				width:150,
				height:25,
				showSpinButtons: true,
			});
			
			$('#DefaultValueQueryFrom').dxTextArea({
			});
			$('#DefaultValueQueryTo').dxTextArea({
			});
			$('#defaultQuery').dxCheckBox({
				text:'use SQL Script',
				value : _paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y' ? true : false
			});
			self.BetweenCandSetting(_paramItem);
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:false,disabled:false});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',visible:false,readOnly:false});
			$('#dataInputEdit').dxCheckBox({text:'입력창 수정 여부',visible:false,readOnly:false});
			$('#paramTypeSetting').css('display','block');
			break;
		};
	};
	
	/* goyong ktkang 달력 필터 현재 기본값 오류 수정  20210517 */
	this.getFormatDate = function(date, period)
	{ 
		var year = date.getFullYear();	//yyyy 
		var month = (1 + date.getMonth());	//M 
		month = month >= 10 ? month : '0' + month;	//month 두자리로 저장 
		var day = date.getDate();	//d 
		day = day >= 10 ? day : '0' + day;	//day 두자리로 저장 
		
		if(period == 'YEAR') {
			return year; 
		} else if(period == 'MONTH') {
			return year + '' + month; 
		} else {
			return year + '' + month + '' + day; 
		}
	}

	this.BetweenCandSetting = function(_paramItem){
		if(_paramItem['CAND_DEFAULT_TYPE'] == 'QUERY'){
			if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] =='Y'){
				/* DOGFOOT ktkang 비트윈 달력 필터 오류 수정  20200702 */
				var betweenDefault;
				if(_paramItem['HIDDEN_VALUE'] == "") {
					betweenDefault = _paramItem['DEFAULT_VALUE'].split(',');
					$('#DefaultValueQueryFrom').dxTextArea('instance').option('value',Base64.decode(betweenDefault[0]));
					$('#DefaultValueQueryTo').dxTextArea('instance').option('value',Base64.decode(betweenDefault[1]));
				} else {
					betweenDefault = _paramItem['HIDDEN_VALUE'].split(',');
					$('#DefaultValueQueryFrom').dxTextArea('instance').option('value',Base64.decode(betweenDefault[0]));
					$('#DefaultValueQueryTo').dxTextArea('instance').option('value',Base64.decode(betweenDefault[1]));
				}
				
			}else{
				/* DOGFOOT ktkang 비트윈 캘린더 기본값 오류 수정   20200924*/
				if(typeof _paramItem.DEFAULT_VALUE == 'string'){
					var betweenCandVal = _paramItem.DEFAULT_VALUE.split(',');
					$('#DefaultValueQueryFrom').dxTextArea('instance').option('value',betweenCandVal[0].replace('[', '').replace(/\"/gi, ''));
				    $('#DefaultValueQueryTo').dxTextArea('instance').option('value',betweenCandVal[1].replace(']', '').replace(/\"/gi, ''));
				}else{
					$('#DefaultValueQueryFrom').dxTextArea('instance').option('value',_paramItem.DEFAULT_VALUE[0].replace('[', '').replace(/\"/gi, ''));
				    $('#DefaultValueQueryTo').dxTextArea('instance').option('value',_paramItem.DEFAULT_VALUE[1].replace(']', '').replace(/\"/gi, ''));
				}
			}
			
		}else if(_paramItem['CAND_DEFAULT_TYPE'] == 'NOW'){
			var betweenDefault = _paramItem['CAND_PERIOD_BASE'].split(',');
			var betweenMoveValue = _paramItem['CAND_PERIOD_VALUE'].split(',');
			$('#DefaultValueNowFrom').dxSelectBox('instance').option('value',betweenDefault[0]);
			$('#DefaultValueNowTo').dxSelectBox('instance').option('value',betweenDefault[1]);
			$('#candMoveValueFrom').dxNumberBox('instance').option('value',betweenMoveValue[0]);
			$('#candMoveValueTo').dxNumberBox('instance').option('value',betweenMoveValue[1]);
		}
	}
}
