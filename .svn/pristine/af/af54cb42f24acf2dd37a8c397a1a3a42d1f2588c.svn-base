/**
 * 데이터집합 디자이너 팝업 컴포넌트 클래스
 * Datasource selector popup component class.
 */
WISE.libs.Dashboard.DatasetDesigner = function() {
	var __erdFlag = (Number(DevExpress.VERSION.split('.')[0])>=20);
    var self = this;
    this.utility = WISE.libs.Dashboard.item.DatasetUtility;
    this.nameEditor = new WISE.libs.Dashboard.DatasetNameEditor;
    this.queryDesigner = new WISE.libs.Dashboard.DatasetQueryDesigner;
    this.tableDesigner = new WISE.libs.Dashboard.DatasetTableDesigner;
    this.queryTester = new WISE.libs.Dashboard.DatasetQueryTester;
    this.erdDesigner = new WISE.libs.Dashboard.DatasetErdDesigner;
    this.parameterEditor = new WISE.libs.Dashboard.DatasetParameterEditor;
    this.state = {
        datasource: {},
        dataset: {},
		dslist: [],
        params: [],
        selectedParam: '',
        onPopupClose: function() {},
    };
    this.container = null;
    this.components = {
        dsInfoForm: null,
        dsDesignerTableTree: null,
        dsNameText: null,
        dsNameChangeBtn: null,
        dsNameChangePopover: null,
        dsQueryBtn: null,
        dsDesignerOkBtn: null,
        dsDesignerCancelBtn: null,
    };

    /**
     * Update component state.
     */
    this.setState = function(state, action) {
        switch (action) {
            case 'DATASET':
                $.extend(self.state.dataset, state);
                break;
            default:
                $.extend(self.state, state);
        }
    }

    /**
     * Renders dataset designer component.
     * @param props { datasource: object, dataset: object }
     */
    this.render = function(props) {
        self.setState(props);

        $('body').remove('#dsDesignerPopup').append('<div id="dsDesignerPopup" />');
        self.container = $('#dsDesignerPopup').dxPopup({
            showCloseButton: false,
            showTitle: true,
            title: '데이터 집합 디자이너',
            visible: true,
            closeOnOutsideClick: false,
            width: '100vw',
            height: '90vh',
            maxWidth: 1500,
            maxHeight: 900,
            onShowing: function () {
                self.components = {
                    dsInfoForm: dsInfoForm(),
                    dsDesignerTableTree: dsDesignerTableTree(),
                    dsNameText: dsNameText(),
                    dsNameChangeBtn: dsNameChangeBtn(),
                    dsNameChangePopover: dsNameChangePopover(),
                    dsErdBtn: dsErdBtn(),
                    //dsFileUplaodBtn: dsFileUploadBtn(),
                    dsQueryBtn: dsQueryBtn(),
                    //20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
                    dsInMemoryCheck: dsInMemoryCheck(),
                    designerContainer: designerContainer(),
                    dsDesignerOkBtn: dsDesignerOkBtn(),
                    dsDesignerCancelBtn: dsDesignerCancelBtn(),
                    // 20211102 AJKIM 필드 제외 데이터 집합 수정 추가 dogfoot
                    dsExceptFieldCheck: dsExceptFieldCheck(),
                };
            },
            onContentReady: function() {
            	gDashboard.fontManager.setFontConfigForListPopup('dsDesignerPopup')
		        /* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
		        if(self.state.dataset.DATASET_TYPE=='DataSetDs' && __erdFlag && (typeof self.state.dataset.JOIN_TYPE != 'undefined' 
		        	/*&& self.state.dataset.JOIN_TYPE == 'Y'*/)) {
					$('#dsErdBtn').show();
				} else {
					$('#dsErdBtn').hide();
				}
				//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
            	$("#inMemoryCheck").dxCheckBox({text:"인메모리"})
            },
            contentTemplate: function() {
                return  '<div class="modal-inner" style="height: 100%; width: 100%;">' + 
                            '<div class="modal-body" style="height: calc(100% - 85px);">' + 
                                '<div class="row" style="height: 100%;">' + 
                                    '<div class="column" style="height: 100%; width: 25%">' + 
                                        '<div class="modal-article" style="height: 36%;">' + 
                                            '<div class="modal-tit" style="height: 40px;">' + 
                                                '<span>데이터 원본 정보</span>' + 
                                            '</div>' + 
                                            // dataset info component (form)
                                            '<div id="dsInfoForm"></div>' + 
                                        '</div>' +
                                        '<div class="modal-article" style="height: 64%;">' + 
                                            '<div class="modal-tit" style="height: 40px;">' + 
                                                '<span>데이터 항목</span>' + 
                                            '</div>' + 
                                            // dataset table tree component (treeList)
                                            '<div id="dsDesignerTableTree"></div>' + 
                                        '</div>' +
                                    '</div>' + 
                                    '<div class="column" style="height: 100%; width:75%">' +
                                        '<div class="row horizen">' + 
                                            '<div class="column" style="height: 55px; padding-bottom: 0;">' +
                                                '<div class="modal-article">' + 
                                                    '<div class="modal-tit">' +
                                                        '<div class="left-item">' +
                                                            // dataset name component (text)
                                                            '<p id="dsNameText" style="display: inline-block; font-size: 1.3rem;"></p>' +
                                                            // dataset name edit toggler component (button)
                                                            '<a id="dsNameChangeBtn" class="gui edit minPop-btn" href="#"' +
                                                                'style="display: inline-block; vertical-align: 0;">데이터 집합 명 변경</a>' +
                                                            // dataset name editor component (popover)
                                                            '<div id="dsNameChangePopover"></div>' +
                                                        '</div>' +
                                                        '<div class="right-item">' +
                                                     // 20211102 AJKIM 필드 제외 데이터 집합 수정 추가 dogfoot
                                                        (self.state.dataset.DATASET_TYPE == 'DataSetSQL' && menuConfigManager.getMenuConfig.Menu.MODIFY_EXCEPT_FIELD?
                                                    		'<div id="exceptFieldCheck" style="margin-right:10px"></div>'
                                                        :''
                                                        )+
                                                      //20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
                                                        (self.state.dataset.DATASET_TYPE == 'DataSetDs' && self.state.dataset.JOIN_TYPE != 'Y' && (typeof self.menuConfig != 'undefined' && self.menuConfig.IN_MEMORY)?
                                                        	'<div id="inMemoryCheck" style="margin-right:10px"></div>' +
                                                        	'<a id="dsFileUploadBtn" class="btn crud neutral">파일 업로드</a>': '') +
                                                        	//'<a id="dsFileUploadBtn" class="btn crud neutral">파일 업로드</a>' +
                                                            '<a id="dsErdBtn" class="btn crud neutral">ERD</a>' +
                                                            // dataset query view redirector component (button)
                                                            '<a id="dsQueryBtn" class="btn crud neutral" style="float:right;">쿼리보기</a>' +
                                                        '</div>'+
                                                    '</div>' +
                                                '</div>' +
                                            '</div>' +
                                            // designer container component
                                            '<div id="designerContainer" class="column"' +
                                                'style="height: calc(100% - 35px); padding: 0; border-top: 0;" />' +
                                        '</div>' +
                                    '</div>' +
                                '</div>' +
                            '</div>' +
                            '<div class="modal-footer" style="height: 45px; padding-bottom: 0;">' + 
                                '<div class="row center">' + 
                                    // confirm button component (button)
                                    '<a id="dsDesignerOkBtn" class="btn positive ok-hide" href="#">확인</a>' + 
                                    // cancel button component (button)
                                    '<a id="dsDesignerCancelBtn" class="btn neutral close" href="#">취소</a>' + 
                                '</div>' + 
                            '</div>' + 
                        '</div>';
            },
        }).dxPopup('instance');
    }

    /**
     * Returns dataset type caption according to state's dataset type.
     */
    function datasetTypeCaption() {
        switch(self.state.dataset.DATASET_TYPE) {
            case 'DataSetSQL':
                return '직접 쿼리';
            case 'DataSetDs':
                return '데이터 원본';
            case 'DataSetSingleDs':
                return '단일 테이블';
            case 'DataSetCube':
                return '주제영역';
            default:
                return '';
        }
    }

    /**
     * Update state and components with new dataset name.
     * @param {String} name 
     */
    function onNameChangeConfirm(name) {
        self.setState({ DATASET_NM: name }, 'DATASET');
        self.components.dsNameText.text(name);
        self.components.dsNameChangePopover.hide();
    }

    /**
     * Update state with new updated query string.
     * @param {String} text 
     */
    function onQueryChange(text) {
        self.setState({ DATASET_QUERY: text }, 'DATASET');
        self.setState({ SQL_QUERY: text }, 'DATASET');
    }
    
    //20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
    function onInMemoryChange(inmemory){
    	self.setState({ IN_MEMORY: inmemory }, 'DATASET');
    }

    /**
     * Search query text for parameters and add new params to param list.
     */
    function onQueryParamSearch() {
        var newParams = [];
        var paramNameList = [];
        //var whereQuery = self.state.dataset.DATASET_QUERY.match(/where[\s\S]*(?=[\s\S]select|from|group by|order by[\s\S])?/gmi);
        /*dogfoot 매개변수 생성 동작 쿼리 전체 에서 동작할수 있도록 변경 shlim 20200811*/
        var whereQuery = self.state.dataset.DATASET_QUERY.match(/select[\s\S]*(?=[\s\S]select|from|group by|order by[\s\S])?/gmi);
        if (whereQuery) {
            var paramTypeMap = {};
            whereQuery.forEach(function(whereStr) {
                var paramStr = whereStr.match(/\s\S*\(*@\w*/gmi);
                if (paramStr) {
                    paramStr.forEach(function(paramStrMatch) {
                        var matches = /\s(\S*)\(*(@\w*)/gmi.exec(paramStrMatch);
                        paramNameList = _.uniq(paramNameList.concat(matches[2]));
                        paramTypeMap[matches[2]] = matches[1];
                    });
                }
            });
            
            paramNameList.forEach(function(param) {
                var savedParam = getParam(param);
                if (!savedParam) {
                    newParams.push({
                        DS_ID: self.state.datasource.ORG_DS_ID || self.state.datasource.DS_ID,
                        UNI_NM: param,
                        PARAM_NM: param,
                        PARAM_CAPTION: param.replace('@', ''),
                        DATA_TYPE: '',
                        PARAM_TYPE: '',
                        SEARCH_YN: 'N',
                        BIND_YN: 'N',
                        ORDER: newParams.length,
                        WIDTH: 300,
                        VISIBLE: 'Y',
                        OPER: self.utility.getParamType(paramTypeMap[param]),
                        // "list" settings
                        DATASRC_TYPE: '',
                        DATASRC: '',
                        CAPTION_VALUE_ITEM: '',
                        KEY_VALUE_ITEM: '',
                        SORT_VALUE_ITEM: '',
                        SORT_TYPE: '',
                        DEFAULT_VALUE: '',
                        DEFAULT_VALUE_USE_SQL_SCRIPT: '',
                        MULTI_SEL: 'N',
                        ALL_YN : 'N',
                        WHERE_CLAUSE: '',
                        DEFAULT_VALUE_MAINTAIN: '',
                        // "between" settings
                        CAND_DEFAULT_TYPE: '',
                        /*dogfoot 캘린더 기간 설정 shlim 20210427*/
                        CAND_MAX_GAP:'',
                        CAND_PERIOD_BASE: '',
                        CAND_PERIOD_VALUE: 0,
                        CAPTION_FORMAT: '',
                        HIDDEN_VALUE: '',
                        KEY_FORMAT: '',
                        RANGE_VALUE: '',
                        EDIT_YN: 'N',
                        INPUT_EDIT_YN:'Y',
                        LINE_BREAK: 'N',/*dogfoot shlim 20210415*/
                        RANGE_YN: 'N',
                        TYPE_CHANGE_YN: 'N'
                    });
                } else {
                    savedParam.OPER = self.utility.getParamType(paramTypeMap[param]);
                    newParams.push(savedParam);
                }
            });
        }
        self.queryDesigner.updateParamList(newParams);
        self.setState({ params: newParams });
        self.setState({ params: paramNameList }, 'DATASET');
    }

    /**
     * Generate new param info with row info and update state.
     * @param {object} row 
     */
    function onTableParamChange(row) {
        var newParams = _.clone(self.state.params);
        var found = false;
        for (var i = 0; i < newParams.length; i++) {
            if (newParams[i].PARAM_NM === row.PARAM_NM) {
                newParams[i].OPER = self.utility.getParamType(row.OPER);
                found = true;
            }
        }
        if (!found && row.PARAM_YN) {
            newParams.push({
                DS_ID: row.DATASET_SRC || self.state.datasource.ORG_DS_ID || self.state.datasource.DS_ID,
                UNI_NM: row.PARAM_NM,
                PARAM_NM: row.PARAM_NM,
                PARAM_CAPTION: row.COL_NM,
                DATA_TYPE: 'STRING',
                PARAM_TYPE: 'LIST',
                SEARCH_YN: 'N',
                BIND_YN: 'Y',
                ORDER: newParams.length,
                WIDTH: 300,
                VISIBLE: 'Y',
                OPER: self.utility.getParamType(row.OPER),
                // "list" settings
                DATASRC_TYPE: 'TBL',
                DATASRC: row.TBL_NM,
                CAPTION_VALUE_ITEM: row.COL_NM,
                KEY_VALUE_ITEM: row.COL_NM,
                SORT_VALUE_ITEM: row.COL_NM,
                SORT_TYPE: 'ASC',
                DEFAULT_VALUE: '[All]',
                DEFAULT_VALUE_USE_SQL_SCRIPT: 'N',
                MULTI_SEL: 'Y',
                ALL_YN : 'N',
                WHERE_CLAUSE: row.TBL_NM + '.' + row.COL_NM,
                DEFAULT_VALUE_MAINTAIN: 'N',
                // "between" settings
                CAND_DEFAULT_TYPE: '',
                /*dogfoot 캘린더 기간 설정 shlim 20210427*/
                CAND_MAX_GAP:'',
                CAND_PERIOD_BASE: '',
                CAND_PERIOD_VALUE: 0,
                CAPTION_FORMAT: '',
                HIDDEN_VALUE: '',
                KEY_FORMAT: '',
                RANGE_VALUE: '',
                EDIT_YN: 'N',
                INPUT_EDIT_YN:'Y',
                LINE_BREAK: 'N',/*dogfoot shlim 20210415*/
                RANGE_YN: 'N',
                TYPE_CHANGE_YN: 'N'
            });
        }
        self.setState({ params: newParams });
    }

    /**
     * Delete selected param row from state and param list.
     * @param {string} paramName
     */
    function onParamDelete(paramNames) {
        var newParams = _.filter(self.state.params, function(param) {
            return paramNames.indexOf(param.PARAM_NM) === -1;
        });
        if (self.state.dataset.DATASET_TYPE === 'DataSetSQL') {
            self.queryDesigner.updateParamList(newParams);
        }
        self.setState({ params: newParams });
    }

    /**
     * Update state with the selected parameter name of the lowest index.
     * @param {string} firstSelected 
     */
    function onQueryParamSelect(firstSelected) {
        self.setState({ selectedParam: firstSelected });
    }

    /**
     * Render parameter editor popup component.
     * @param {string} paramName
     */
    function onParamEdit(paramNames) {
        // self.parameterEditor.render({
        //     dsId: self.state.datasource.DS_ID,
        //     dsType: self.state.dataset.DATASRC_TYPE,
        //     params: self.state.params,
        //     selectedParam: self.state.selectedParam,
        //     onConfirm: onParamEditConfirm
        // });
        gDashboard.FieldFilter.editFilter(true, self.state.datasource.DS_ID, self.state.params, onParamEditConfirm);
    }

    function onParamEditConfirm(params) {
        self.setState({ params: params });
        switch (self.state.dataset.DATASET_TYPE) {
            case 'DataSetSQL':
                self.queryDesigner.updateParamList(params);
                break;
            case 'DataSetDs':
            case 'DataSetCube':
                self.tableDesigner.updateParamList(params);
                break;
            default:
        }
    }

    function onSelectClauseChange(selectClauses) {
        self.setState({ SEL_CLAUSE: selectClauses }, 'DATASET');
    }

    function onFromClauseChange(fromClauses) {
        self.setState({ FROM_CLAUSE: fromClauses }, 'DATASET');
    }
    
    function onWhereClauseChange(whereClauses) {
        self.setState({ WHERE_CLAUSE: whereClauses }, 'DATASET');
    }

    function onOrderClauseChange(orderClauses) {
        self.setState({ ORDER_CLAUSE: orderClauses }, 'DATASET');
    }

    function onParamChange(params) {
        self.setState({ params: params });
    }

    function onQueryChange(query) {
        self.setState({ DATASET_QUERY: query }, 'DATASET');
        self.setState({ SQL_QUERY: query }, 'DATASET');
    }

    function onCondChange(cond) {
    	self.setState({ CHANGE_COND: cond }, 'DATASET');
    }

    /**
     * Close name editor popover.
     */
    function onNameChangeCancel() {
        self.components.dsNameChangePopover.hide();
    }

    /**
     * Finish creating the dataset.
     */
    function onDatasetConfirm() {
        // dataset name is empty
        if (self.state.dataset.DATASET_NM.length === 0) {
            WISE.alert('데이터 집합명을 입력하십시오.');
        } 
        // dataset name is already taken
        else if (self.utility.datasetExists(self.state.dataset)) {
            WISE.alert('현재 같은 이름의 데이터 집합명이 존재합니다.');
        } 
        // query is empty
        else if (self.state.dataset.DATASET_QUERY.length === 0) {
            WISE.alert("쿼리가 없습니다.");
        } 
        // all is good
        else {
        	var fieldSearch = true;
        	
        	if($("#exceptFieldCheck").length > 0){
        		fieldSearch = $("#exceptFieldCheck").dxCheckBox('instance').option('value');
        	}
        	
        	if(fieldSearch){
        		$.ajax({
                    method : 'POST',
                    url: WISE.Constants.context + '/report/getDatasetTableColumnList.do',
                    data: {
                        DATASRC_ID: self.state.dataset.DATASRC_ID,
                        DATASRC_TYPE: self.state.dataset.DATASRC_TYPE,
                        SQL_QUERY: self.state.dataset.DATASET_QUERY,
                        PARAMS: JSON.stringify(self.utility.generateNewParamValues(self.state.params)),
    					TBL_LIST: $.toJSON(dsMultiTblList()),
    					//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
    					IN_MEMORY: self.state.dataset.IN_MEMORY
                    },
                    beforeSend: function() {
                        gProgressbar.show();
                    },
                    complete: function() {
                        gProgressbar.hide();
                    },
                    success: function(response) {
                        // server error occurred
                        if (response.error) {
                        	//2020.09.18 mksong 검색제한시간 초과 오류 문구 수정 dogfoot
    						if(response.error == 422){
    							WISE.alert('검색제한시간을 초과하였습니다.');							
    						}else{
    							//20210802 AJKIM 에러 로그 표시 dogfoot
    							var errorText = '쿼리가 부적합 합니다.';
    							if(userJsonObject.menuconfig.Menu.SQL_ERROR_LOG && response.errorContent){
    								errorText += '\n';
    								errorText += response.errorContent;
    							}
    							WISE.alert(errorText);
    							gProgressbar.setStopngoProgress(true);
    							gProgressbar.hide();
    						}
                        } 
                        // no problem
                        else {
                            // adhoc can have only one dataset
                            if (gDashboard.dataSourceQuantity > 0 && gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode != 'viewer') {
    							var confirmOk;
    							if(gDashboard.dataSourceQuantity > 0) {
    								if(gDashboard.adhocEditDatasource){
    									confirmOk = true;
    								}else{
    									confirmOk = confirm('비정형모드에서는 데이터 집합이 1개만 사용됩니다. 기존 데이터집합을 삭제하고 추가하시겠습니까?');
    								}
                                	
                                } else {
    								confirmOk = true;
    							}
                                if (confirmOk) {
                                	/* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
                                	WISE.Constants.isCubeReport = false;
                                	if(gDashboard.adhocEditDatasource){
                                		gDashboard.adhocEditDatasource = false;
    								}else{
    									gDashboard.datasetMaster.resetData();
    	                                $('.panelClear').click();
    									var pivot = gDashboard.itemGenerateManager.dxItemBasten[0].type === 'PIVOT_GRID'? gDashboard.itemGenerateManager.dxItemBasten[0] : gDashboard.itemGenerateManager.dxItemBasten[1];
    									pivot.deltaItems=[];
    									gDashboard.itemGenerateManager.clearItemData();
    									$('.wise-area-deltaval').css('display', 'none');
    								}
                                    
                                } else {
                                    return false;
                                }
                            }
                            /* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
                            WISE.Constants.isCubeReport = false;
                            self.setState({ data: response.data }, 'DATASET');

    						var dsIds = dsMultiDataSourceId();
    						if(dsIds.length>1) {
    							self.state.dataset.DATASRC_ID = dsIds.join(',');
    						}

                            gDashboard.datasetMaster.addDatasetToState(self.state.datasource, self.state.dataset, self.state.params);
                            // close dataset designer windows
                            self.state.onPopupClose();
                            closePopup();
                        }
                    }
                });
        	}else {
        		if (gDashboard.dataSourceQuantity > 0 && gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode != 'viewer') {
					var confirmOk;
					if(gDashboard.dataSourceQuantity > 0) {
						if(gDashboard.adhocEditDatasource){
							confirmOk = true;
						}else{
							confirmOk = confirm('비정형모드에서는 데이터 집합이 1개만 사용됩니다. 기존 데이터집합을 삭제하고 추가하시겠습니까?');
						}
                    	
                    } else {
						confirmOk = true;
					}
                    if (confirmOk) {
                    	/* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
                    	WISE.Constants.isCubeReport = false;
                    	if(gDashboard.adhocEditDatasource){
                    		gDashboard.adhocEditDatasource = false;
						}else{
							gDashboard.datasetMaster.resetData();
                            $('.panelClear').click();
							var pivot = gDashboard.itemGenerateManager.dxItemBasten[0].type === 'PIVOT_GRID'? gDashboard.itemGenerateManager.dxItemBasten[0] : gDashboard.itemGenerateManager.dxItemBasten[1];
							pivot.deltaItems=[];
							gDashboard.itemGenerateManager.clearItemData();
							$('.wise-area-deltaval').css('display', 'none');
						}
                        
                    } else {
                        return false;
                    }
                }
                /* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
                WISE.Constants.isCubeReport = false;

				var dsIds = dsMultiDataSourceId();
				if(dsIds.length>1) {
					self.state.dataset.DATASRC_ID = dsIds.join(',');
				}

                gDashboard.datasetMaster.addDatasetToState(self.state.datasource, self.state.dataset, self.state.params, true);
                // close dataset designer windows
                self.state.onPopupClose();
                closePopup();
        	}
        }
    }

    /**
     * Close dataset designer popup.
     */
    function closePopup() {
        self.components.dsInfoForm.dispose();
        self.components.dsDesignerTableTree.dispose();
        self.container.hide();
    }

    /**
     * Return param object that has a given parameter name.
     * @param {string} paramName 
     */
    function getParam(paramName) {
        for (var i = 0; i < self.state.params.length; i++) {
            if (self.state.params[i] && self.state.params[i].PARAM_NM === paramName) {
                return _.clone(self.state.params[i]);
            }
        }
        return null;
    }

    /**
     * Return an image URL of the column data's data type.
     * @param {object} colData 
     */
    function getColumnTemplate(colInfo) {
        if (colInfo.data.DATA_TYPE) {
            switch (colInfo.data.DATA_TYPE.toUpperCase()) {
                case 'NUMBER':
                case 'INT':
                case 'INTEGER':
                case 'DECIMAL':
                case 'FLOAT':
                case 'DOUBLE':
                case 'BIGINT':
				case 'NUMERIC':
                    return  '<img src="' + WISE.Constants.context + '/resources/main/images/ico_sigma.png"' +
                                'style="display: inline-block; height: 20px; vertical-align: bottom;"></a>' +
                            '<p style="display: inline-block;">' + colInfo.text + '</p>';
                default:
                    return  '<img src="' + WISE.Constants.context + '/resources/main/images/ico-blockFolder.png"' +
                                'style="display: inline-block; height: 20px; vertical-align: bottom;"></a>' +
                            '<p style="display: inline-block;">' + colInfo.text + '</p>';
            }
        } else {
            return '<p>' + colInfo.text + '</p>';
        }
    }

	function dsListForm() {
		if(self.state.dslist.length==0) {
			$.ajax({
				method: 'GET',
				async: false,
		        url: WISE.Constants.context + '/report/datasourceList.do',
		        data: {
	                userId: userJsonObject.userId,
	                userNo: userJsonObject.userNo,
	                dsType: 'DS'
		        },
	            beforeSend: function() {
	                gProgressbar.show();
	            },
	            complete: function() {
	                gProgressbar.hide();
	            },
				success: function(result) {
	                self.setState({ dslist: result.data });
				}
			});
		}
		
        return $('#dsInfoForm').dxForm({
            height: 'calc(100% - 40px)',
            formData: $.extend(
                self.state.datasource, 
                { DS_TYPE: datasetTypeCaption() }
            ),
            items: [{
                dataField: 'DS_TYPE',
                label: {
                    text: '데이터 원본 유형',
                },
				editorOptions: {
					readOnly: true,						
				},
            }, {
                dataField: 'DS_NM2',
                label: {
                    text: '데이터 원본 명', 
                },
                editorType: "dxSelectBox",
                editorOptions: {
                    items: self.state.dslist,
                    displayExpr: 'DS_NM',
					valueExpr: 'DS_ID',
					value: self.state.datasource.DS_ID,
                }
            }, {
                dataField: 'IP',
                label: {
                    text: '서버 주소(명)',
                },
				editorOptions: {
					readOnly: true,						
				},
            }, {
                dataField: 'DB_NM',
                label: {
                    text: 'DB 명',
                },
				editorOptions: {
					readOnly: true,						
				},
            }, {
                dataField: 'DBMS_TYPE',
                label: {
                    text: 'DB 유형',
                },
				editorOptions: {
					readOnly: true,						
				},
            }],
			onFieldDataChanged: function(e) {
				if(e.dataField==='DS_NM2') {
					var DS_ID = e.value;
					$.each(self.state.dslist, function(i,d){
						if(d.DS_ID===DS_ID) {
							e.component.updateData("IP", d.IP);
							e.component.updateData("DB_NM", d.DB_NM);
							e.component.updateData("DBMS_TYPE", d.DBMS_TYPE);
							self.setState({datasource: d});
							self.setState({DATASRC_ID: DS_ID}, 'DATASET');
							if(self.components.dsDesignerTableTree) {
								self.components.dsDesignerTableTree.dispose();
								self.components.dsDesignerTableTree = dsDesignerTableTree();
								self.tableDesigner.setState({dsId: DS_ID});
								self.tableDesigner.generateRelationList();
							}
						}
					});
				}
			}
        }).dxForm('instance');
	}

    /**
     * dataset info component (form)
     */
    function dsInfoForm() {
    	/* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
		if(self.state.dataset.DATASET_TYPE=='DataSetDs' && __erdFlag && (typeof self.state.dataset.JOIN_TYPE != 'undefined' && self.state.dataset.JOIN_TYPE == 'Y')) {
			return dsListForm();
		} else {
	        return $('#dsInfoForm').dxForm({
	            height: 'calc(100% - 40px)',
	            readOnly: true,
	            formData: $.extend(
	                self.state.datasource, 
	                { DS_TYPE: datasetTypeCaption() }
	            ),
	            items: [{
	                dataField: 'DS_TYPE',
	                label: {
	                    text: '데이터 원본 유형',
	                },
	            }, {
	                dataField: 'DS_NM',
	                label: {
	                    text: '데이터 원본 명', 
	                },
	            }, {
	                dataField: 'IP',
	                label: {
	                    text: '서버 주소(명)',
	                },
	            }, {
	                dataField: 'DB_NM',
	                label: {
	                    text: 'DB 명',
	                },
	            }, {
	                dataField: 'DBMS_TYPE',
	                label: {
	                    text: 'DB 유형',
	                },
	            }]
	        }).dxForm('instance');			
		}
    }

    /**
     * dataset table tree component (treeList)
     */
    function dsDesignerTableTree() {
        switch (self.state.dataset.DATASET_TYPE) {
            // cube table
            case 'DataSetCube':
                var tableLoaded = false;
                return $('#dsDesignerTableTree').dxTreeList({
                    height: 'calc(100% - 80px)',
                    columns: [{
                        dataField: 'text',
                        cellTemplate: function(element, info) {
                            element.append(getColumnTemplate(info));
                        }
                    }],
                    keyExpr: 'id',
                    parentIdExpr: 'parent',
                    rootValue: '',
                    wordWrapEnabled: true,
                    showBorders: false,
                    searchPanel: {
                        visible: true,
                        searchVisibleColumnsOnly: true,
                        highlightSearchText: true,
                        width: '100%',
                    },
                    expandNodesOnFiltering: false,
                    filterMode: 'fullBranch',
                    showColumnHeaders: false,
                    selection: {
                        mode: 'none'
                    },
                    onRowPrepared: function(e) {
                        e.rowElement
                            .data('column', e.data)
                            .draggable({
                                appendTo: document.body, 
                                helper: 'clone',
                                cancel: '',
                                revertDuration : 300,
                                scroll: false,
                                zIndex: 10000,
                            });
                    },
                    onContentReady: function(e) {
                    	gDashboard.fontManager.setFontConfigForListPopup('dsDesignerTableTree');
                        if (!tableLoaded) {
                            $.ajax({
                                method: 'GET',
                                url: WISE.Constants.context + '/report/getCubeDatasetTableColumns.do',
                                data: {
                                    cubeId: self.state.datasource.CUBE_ID,
                                },
                                success: function(data) {
                                    e.component.option('dataSource', data);
                                }
                            });
                            tableLoaded = true;
                        }
                    }
                }).dxTreeList('instance');
            // non-cube table
            default:
            	var selectedTableName = '';
                return $('#dsDesignerTableTree').dxTreeList({
                    height: 'calc(100% - 80px)',
                    dataSource: {
                        load: function(options) {
                            // default params to search for all tables
                            var key = '';
                            var request = 'TABLE';
                            var search = '';
                            // call for selected table's columns
                            if (options.filter[0] === 'parent' && options.parentIds[0] !== '') {
                                //key = options.parentIds[options.parentIds.length - 1];
                            	key = selectedTableName;
                                request = 'COLUMN';
                            }
                            // filter tables by input
                            else if (options.filter[0] === 'text') {
                                request = 'SEARCH';
                                search = options.filter[options.filter.length - 1];
                            }
                            // send fetch request to server if needed
                            return $.ajax({
                                method: 'POST',
                                url: WISE.Constants.context + '/report/getDatasetTableColumns2.do',
                                data: {
                                    id: self.state.dataset.DATASRC_ID,
                                    type: self.state.dataset.DATASRC_TYPE,
                                    table: key,
                                    request: request,
                                    search: search,
                                },
                            });
                        }
                    },
                    remoteOperations: {
                        filtering: true
                    },
                    columns: [{
                        dataField: 'text',
                        cellTemplate: function(element, info) {
                            element.append(getColumnTemplate(info));
                        }
                    },{
                        dataField: 'TBL_NM',
                        visible: false,
                    }],
                    keyExpr: 'id',
                    parentIdExpr: 'parent',
                    hasItemsExpr: 'hasItems',
                    rootValue: '',
                    wordWrapEnabled: true,
                    showBorders: false,
                    searchPanel: {
                        visible: true,
                        searchVisibleColumnsOnly: true,
                        highlightSearchText: true,
                        width: '100%',
                    },
                    expandNodesOnFiltering: false,
                    filterMode: 'matchOnly',
                    showColumnHeaders: false,
                    selection: {
                        mode: 'none'
                    },
                    onContentReady: function() {
                    	gDashboard.fontManager.setFontConfigForListPopup('dsDesignerTableTree');
                    },
                    onRowPrepared: function(e) {
                        e.rowElement
                            .data('column', e.data)
                            .draggable({
                                appendTo: document.body, 
                                helper: 'clone',
                                cancel: '',
                                revertDuration : 300,
                                scroll: false,
                                zIndex: 10000,
                            });
                    },
					onRowExpanding: function(e) {
                    	selectedTableName = e.key;
					},
					onEditorPreparing: function(e) {
						if (e.parentType === "searchPanel") {
							e.editorOptions.onValueChanged = function(arg) {
								if(arg.value=='') {
									e.component.clearFilter();
									e.component.searchByText('');
								}
							}
							e.editorOptions.onEnterKey = function(arg) {
								e.component.forEachNode(function(node) {
									e.component.collapseRow(node.key);
								});								
								e.component.searchByText(arg.component.option("value"));
							}
							
						}
					},
					scrolling: {
						mode: "standard",
					}					
                }).dxTreeList('instance');
        }
        
    }

    /**
     * dataset name component (text)
     */
    function dsNameText() {
        return $('#dsNameText').text(self.state.dataset.DATASET_NM);
    }

    /**
     * dataset name editor component (popover)
     */
    function dsNameChangePopover() {
        return self.nameEditor.render({ 
            element: $('#dsNameChangePopover'),
            target: $('#dsNameChangeBtn'),
            name: self.state.dataset.DATASET_NM,
            onNameChangeConfirm: onNameChangeConfirm,
            onNameChangeCancel: onNameChangeCancel
        });
    }

    /**
     * dataset name edit toggler component (button)
     */
    function dsNameChangeBtn() {
        return $('#dsNameChangeBtn').click(function() {
            self.components.dsNameChangePopover.show();
        });
    }

	function dsMultiTblList() {
		var rtnArr = [];
		$.each(self.state.dataset.SEL_CLAUSE,function(i,d){
			rtnArr.push({
				dsid: d.DATASET_SRC,
				tblnm: d.TBL_NM
			});
		});
		var FROM_CLAUSE = [];
		if(typeof self.state.dataset.FROM_CLAUSE.FK_DATASET_SRC != 'undefined') {
			FROM_CLAUSE.push(self.state.dataset.FROM_CLAUSE);
		} else {
			FROM_CLAUSE = self.state.dataset.FROM_CLAUSE;
		}
		$.each(FROM_CLAUSE,function(i,d){
			rtnArr.push({
				dsid: d.FK_DATASET_SRC,
				tblnm: d.FK_TBL_NM
			});
			rtnArr.push({
				dsid: d.PK_DATASET_SRC,
				tblnm: d.PK_TBL_NM
			});
		});
		var WHERE_CLAUSE = [];
		if(typeof self.state.dataset.WHERE_CLAUSE.TBL_NM != 'undefined') {
			WHERE_CLAUSE.push(self.state.dataset.WHERE_CLAUSE);
		} else {
			WHERE_CLAUSE = self.state.dataset.WHERE_CLAUSE;
		}
		$.each(WHERE_CLAUSE,function(i,d){
			rtnArr.push({
				dsid: d.DATASET_SRC,
				tblnm: d.TBL_NM
			});
		});
		var ORDER_CLAUSE = [];
		if(typeof self.state.dataset.ORDER_CLAUSE.TBL_NM != 'undefined') {
			ORDER_CLAUSE.push(self.state.dataset.ORDER_CLAUSE);
		} else {
			ORDER_CLAUSE = self.state.dataset.ORDER_CLAUSE;
		}
		$.each(self.state.dataset.ORDER_CLAUSE,function(i,d){
			rtnArr.push({
				dsid: d.DATASET_SRC,
				tblnm: d.TBL_NM
			});
		});
		//delete duplication
		rtnArr = rtnArr.filter(function(arr, index, self){
			var findTblNm = _.findIndex(self,function(t){
				return t.dsid === arr.dsid && t.tblnm === arr.tblnm; 
			});
	    	return index === findTblNm;
		});
		return rtnArr;
	} 
	
	function dsMultiDataSourceId() {
		var dsIdsArr = [];
		$.each(self.state.dataset.SEL_CLAUSE,function(i,d){
			dsIdsArr.push(d.DATASET_SRC);
		});
		var FROM_CLAUSE = [];
		if(typeof self.state.dataset.FROM_CLAUSE.FK_DATASET_SRC != 'undefined') {
			FROM_CLAUSE.push(self.state.dataset.FROM_CLAUSE);
		} else {
			FROM_CLAUSE = self.state.dataset.FROM_CLAUSE;
		}
		$.each(FROM_CLAUSE,function(i,d){
			dsIdsArr.push(d.FK_DATASET_SRC);
			dsIdsArr.push(d.PK_DATASET_SRC);
		});
		var WHERE_CLAUSE = [];
		if(typeof self.state.dataset.WHERE_CLAUSE.TBL_NM != 'undefined') {
			WHERE_CLAUSE.push(self.state.dataset.WHERE_CLAUSE);
		} else {
			WHERE_CLAUSE = self.state.dataset.WHERE_CLAUSE;
		}
		$.each(WHERE_CLAUSE,function(i,d){
			dsIdsArr.push(d.DATASET_SRC);
		});
		var ORDER_CLAUSE = [];
		if(typeof self.state.dataset.ORDER_CLAUSE.TBL_NM != 'undefined') {
			ORDER_CLAUSE.push(self.state.dataset.ORDER_CLAUSE);
		} else {
			ORDER_CLAUSE = self.state.dataset.ORDER_CLAUSE;
		}
		$.each(ORDER_CLAUSE,function(i,d){
			dsIdsArr.push(d.DATASET_SRC);
		});
		return _.uniq(dsIdsArr);
	} 	

    /**
     * dataset query view redirector component (button)
     */
    function dsQueryBtn() {
        return $('#dsQueryBtn').dxButton({
            height: 30,
            type: 'normal',
            onClick: function() {
                var renderQueryTester = function() {
                	/* DOGFOOT 20201022 ajkim setTimeout 제거*/
                    self.queryTester.render({
                        dsId: self.state.datasource.DS_ID,
						dsList: self.state.dslist,
                        dsType: self.state.dataset.DATASRC_TYPE,
                        queryText: self.state.dataset.DATASET_QUERY,
                        params: self.state.params,
                        paramValues: self.utility.generateNewParamValues(self.state.params),
						dsMultiTblList: dsMultiTblList()
                    });  
                }
                switch (self.state.dataset.DATASET_TYPE) {
                    case 'DataSetDs':
                    case 'DataSetCube':
                        self.tableDesigner.saveEditData(renderQueryTester);
                        break;
                    default:
                        renderQueryTester();
                }
            }
        }).dxButton('instance');
    }
    
    //20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
    function dsInMemoryCheck(){
    	return $("#inMemoryCheck").dxCheckBox({
    		text:"인메모리",
    		value : self.state.dataset.IN_MEMORY? true : false,
    		onValueChanged : function(e){
    			onInMemoryChange(e.value);
    		}
			})
    }

	function onErdConfirm(fromClauses) {
		self.setState({ FROM_CLAUSE: fromClauses }, 'DATASET');
		self.tableDesigner.updateErdRelationList(fromClauses);
	}
	
    // 20211102 AJKIM 필드 제외 데이터 집합 수정 추가 dogfoot
    function dsExceptFieldCheck(){
    	return $("#exceptFieldCheck").dxCheckBox({
    		text:"필드 조회",
    		value : true,
		});
    }

    function dsErdBtn() {
        return $('#dsErdBtn').dxButton({
            height: 30,
            type: 'normal',
            onClick: function() {
                var renderErdDesigner = function() {
                	/* DOGFOOT 20201022 ajkim setTimeout 시간 변경 300 > 50*/
                	setTimeout(function(){
						var dsIdList = [];
						dsIdList.push(self.state.datasource.DS_ID);
						dsIdList = _.uniq(dsIdList.concat(self.tableDesigner.getUniqDsList()));
	                    self.erdDesigner.render({
	                        dsId: self.state.datasource.DS_ID,
							dsIdList: dsIdList,
							dsList: self.state.dslist,
	                        dsType: self.state.dataset.DATASRC_TYPE,
		                    selectClauses: self.state.dataset.SEL_CLAUSE,
		                    fromClauses: self.state.dataset.FROM_CLAUSE,
		                    whereClauses: self.state.dataset.WHERE_CLAUSE,
		                    orderClauses: self.state.dataset.ORDER_CLAUSE,
		                    /* dogfoot shlim erd state 추가 20210201*/
							onConfirm: onErdConfirm,
							tableDesigner : self.tableDesigner,
							relateionTblList:{},
	                    });  
                	},50);
                }
                renderErdDesigner();
            }
        }).dxButton('instance');
    }
    
    function dsFileUploadBtn() {
    	return $('#dsFileUploadBtn').dxButton({
            height: 30,
            type: 'normal',
            onClick:function(){
				var html = "";
				html += '<div class="modal-inner" style="height:100%">';
				html += '	<div class="modal-body" style="height:calc(100% - 65px)">';
				html += '		<div class="row" style="height:100%">';
				html += '			<div class="column" style="width:100%">';
				html += '				<div class="row horizen">';
				html += '					<div class="column" style="padding-bottom:0px;">';
				html += '						<div class="modal-article">';
				html += '							<div class="modal-tit">';
				html += '								<span>테이블 명</span>';
				html += '								<div>'
				/* DOGFOOT ktkang 사용자 업로드 UI 수정  20200923 */
				html += '									<div id="dataNm" style="float:left; margin-top:5px;"></div>';
				html += '									<div id="tableDeleteYN" style="float:right"></div>';
				html += '								</div>'
				html += '							</div>';
				html += '						</div>';
				html += '					</div>';
				html += '					<div class="column" style="padding-top:0px;-bottom:0px;border-top:0px solid;height:200px">';
				html += '						<div class="modal-article">';
				html += '							<div id="upload_area" class="param_area modal-tit">';
				html += '								<span>업로드 파일 선택</span>';
				html += '								<div>'
				html += '									<div id="chkEncode"></div>';
				html += '									<div id="fileUploader"></div>';
				html += '								</div>'
				html += '							</div>';
				html += '						</div>';
				html += '					</div>';
				html += '					<div class="column" style="padding-top:0px;padding-bottom:0px;border-top:0px solid; height: 45%;">';
				html += '						<div class="modal-article" style="height: 100%;">';
				html += '							<div id="param_area" class="param_area modal-tit" style="height: 100%;">';
				html += '								<span>컬럼 정보</span>';
				html += '								<div id="columnInfo"></div>';
				html += '							</div>';
				html += '						</div>';
				html += '					</div>';
				html += '				</div>';
				html += '			</div>';
				html += '		</div>';
				html += '	</div>';
				html += '	<div class="modal-footer" style="padding-top:15px; border:none !important;">';
				html += '		<div class="row center">';
				html += '			<a id="btn_Upload_OK" class="btn positive ok-hide" href="#" >확인</a>';
				html += '			<a id="btn_Upload_cancel" class="btn neutral close" href="#">취소</a>';
				html += '		</div>';
				html += '	</div>';
				html += '</div>';
				$('#ds_popup').dxPopup({
					contentTemplate: html,
					visible:true,
					title:'업로드 파일 선택',
					width: '90vw',
		            height: '90vh',
		            maxWidth: 700,
		            maxHeight: 900,
					onContentReady: function(){
						gDashboard.fontManager.setFontConfigForListPopup('ds_popup')
					},
					onShown: function(e){
						/*dogfoot 스프레드시트 데이터 연동시 알림창 뜨는 오류 shlim 20200717*/
						if(e.component.option('title') === '업로드 파일 선택'){
						    WISE.alert('업로드 알림<br>업로드 할 파일은 첫번째 시트만 업로드 되고 1행에 헤더가 있어야 하며 .xls .xlsx .csv 파일만 가능합니다.');	
						}
						var dataNm = "",appendTable="",targetTable="";

						$('#dataNm').dxTextBox({
							visible:true,
							value:dataNm,
							/* DOGFOOT ktkang 사용자 업로드 UI 수정  20200923 */
							width:'100%',
							readOnly:targetTable === "" ? false:true
						});
						
						$("#chkEncode").dxCheckBox({
							text:"UTF-8",
							onValueChanged: function(e){
								var uploader = $("#fileUploader").dxFileUploader("instance");  
								var url = WISE.Constants.context + '/report/Upload/data.do?ckutf='+e.value;  
								uploader.option("uploadUrl", url);
							},
						});
						var lookupData = [{
												caption: 'String',
												value: 'String'
											},{
												caption: 'Int',
												value: 'int'
											},{
												caption: 'Float',
												value: 'float'
											},{
												caption: 'Double',
												value: 'double'
											}];
						
						$('#columnInfo').dxDataGrid({
							columns:[
								{
										dataField: "colNm",
										caption:"컬럼명",
										allowEditing: false
								},
								{
										dataField: "colPhysicalNm",
										caption:"컬럼 물리명",
										allowEditing: false
								},
								/*{
										dataField: "colType",
										caption:"데이터유형",
										cellTemplate: function (container, options) {
											
												$("<div style='width:15px; height:15px;margin-right:5px'>")

											
										}
								},*/
								{
										dataField: "colType",
										caption:"데이터유형",
								},
								{
										dataField: "colSize",
										caption:"길이"
								},
							],
							height:'350px',
							dataSource:[],
							editing: {
								mode: 'cell',
								allowUpdating: true,
								texts: {
									confirmDeleteMessage: ''
								},
								useIcons: false,
							},
							onRowUpdating:function(e){
								console.log();
							}
						});
						$('#btn_Upload_cancel').dxButton({
							onClick:function(){
								$('#columnInfo').dxDataGrid('instance').option('dataSource',[]);
								$("#ds_popup").dxPopup("instance").hide();
								$('#fileUploader').dxFileUploader('instance').reset();
							}
						})
						/*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 shlim 20210120*/
						$('#fileUploader').dxFileUploader({
							multiple: false,
							selectButtonText:'선택하세요',
							labelText:'',
							uploadedMessage:"업로드 완료",

							allowedFileExtensions: ['.xls','.xlsx','.csv'],
							uploadUrl: WISE.Constants.context + '/report/Upload/data.do?ckutf=false',
							onUploadStarted:function(){
//								gProgressbar.show();
							},
							onUploadError:function(e){
								WISE.alert(e.request.status+ ", " + e.request.statusText,'error');
//								gProgressbar.hide();
							},
							onUploaded:function(_e){
								var data = JSON.parse(_e.request.responseText);
								gProgressbar.hide();
								$('#columnInfo').dxDataGrid('instance').option('dataSource',data);
								$('#btn_Upload_OK').dxButton({
									text:"업로드 시작",
									onClick:function(){
										if($('#dataNm').dxTextBox("instance").option("value") != ""){
											
//											var datasetInfo = $("#dataset_info").dxForm('instance').option('formData');
//											var datasetInfo = subjectInfos[indexId];
											var datasetInfo = uploadSubjectsTarget;
											var dataName = $('#dataNm').dxTextBox("instance").option("value");
											var sameDsName = false;
											$.each(gDashboard.datasetMaster.state.datasets, function(id, ds) {
												if (ds.DATASET_NM === dataName) {
													sameDsName = true;
												}
											});
											if(sameDsName) {
												WISE.alert('현재 같은 이름의 데이터 집합명이 존재합니다.');
											} else {
												$("#ds_popup").dxPopup("instance").hide();
												gProgressbar.show();
												if(appendTable != ""){
													if($('#tableDeleteYN').dxCheckBox('instance').option('value') == true){
														tableDeleteYN = "Y";
													}
												}
												var dataparam = {
													"DS_ID" : globalDSData.DS_ID,
													"ID" : globalDSData.USER_ID,
													"IP" : globalDSData.IP,
													"DB_TYPE" : globalDSData.DB_TYPE,
													"DB_NM" : globalDSData.DB_NM,
													"PORT" : globalDSData.PORT,
													"OWNER" : globalDSData.OWNER,
													"TBL_CAPTION":dataName,
													/*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 shlim 20210120*/
													/*dogfoot 사용자업로드데이터 데이터 컬럼 21개 이상 일때 업로드 오류 수정 shlim 20210219*/
													"colList" : $.toJSON($('#columnInfo').dxDataGrid('instance').getDataSource()._store._array),
													"appendTable" : appendTable,
													'targetTable':Base64.encode(targetTable),
													'tableDeleteYN' : tableDeleteYN,
													'userId':userJsonObject.userId,
													'ckutf': $('#chkEncode').dxCheckBox('instance').option('value'),
												}
												/* DOGFOOT 20201021 ajkim setTimeout 제거*/
												$.ajax({
													type:"POST",
													url :  WISE.Constants.context + '/report/Upload/save.do',
													/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
													async : false,
													cache: false,
													data: (dataparam),
													beforeSend:function(){
														gProgressbar.show();
													},
													success: function(_data){
														gProgressbar.hide();
														_data = JSON.parse(_data);
														if(_data.code == 200){
															
															$('#fileUploader').dxFileUploader('instance').reset();
															var options = {
																	buttons: {
																		confirm: {
																			id: 'confirm',
																			className: 'blue',
																			text: '확인',
																			action: function() {
																				$AlertPopup.hide();
																				gProgressbar.show();
																				self.openUploadTable(globalDSData.DS_ID,datasetInfo,dataName,_data.TableName,appendTable);
																				return false;
																			}
																		}
																	}
															};
														
															WISE.alert('사용자 데이터 업로드 정보 성공<br>대상테이블 논리명 : '+_data.dataName+'<br>대상테이블 물리명 : '+_data.TableName+'<br>테이블 총 레코드 건수 : '+_data.REC_count,'', options);
															
														}else{
															/* DOGFOOT ktkang 사용자 데이터 업로드 알림창 구현  20200904 */
															alert("분석에 실패했습니다.관리자에게 문의하세요.");
															gProgressbar.hide();
														}
													}
												});													}
										} else {
											WISE.alert('데이터집합명을 입력해주세요.');
										}
									}
								});
							}
						});
					}
				});

			}
        }).dxButton('instance');
    }

    /**
     * dataset designer (query, datasource or single-table) component
     */
    function designerContainer() {
        var cont = $('#designerContainer');
        switch (self.state.dataset.DATASET_TYPE) {
            case 'DataSetSQL':
                self.queryDesigner.render({ 
                    element: cont,
                    initialQueryText: self.state.dataset.DATASET_QUERY,
                    initialParams: self.state.params,
                    onChange: onQueryChange,
                    onParamSearch: onQueryParamSearch,
                    onParamEdit: onParamEdit,
                    onParamDelete: onParamDelete,
                    onParamSelect: onQueryParamSelect,
                });
                break;
            case 'DataSetDs':
                self.tableDesigner.render({
                    element: cont,
                    dsId: self.state.datasource.DS_ID,
                    dsType: self.state.dataset.DATASRC_TYPE,
                    relations: [],
                    selectClauses: self.state.dataset.SEL_CLAUSE,
                    fromClauses: self.state.dataset.FROM_CLAUSE,
                    whereClauses: self.state.dataset.WHERE_CLAUSE,
                    orderClauses: self.state.dataset.ORDER_CLAUSE,
                    selectInc: self.state.dataset.SEL_CLAUSE.length,
                    whereInc: self.state.dataset.WHERE_CLAUSE.length,
                    orderInc: self.state.dataset.ORDER_CLAUSE.length,
                    onSelectClauseChange: onSelectClauseChange,
                    onFromClauseChange: onFromClauseChange,
                    onWhereClauseChange: onWhereClauseChange,
                    onOrderClauseChange: onOrderClauseChange,
                    onParamChange: onParamChange,
                    onQueryChange: onQueryChange,
                    onParamEdit: onParamEdit,
                    onParamDelete: onParamDelete,
                    onTableParamChange: onTableParamChange,
                    onCondChange: onCondChange,
					changeCond: self.state.dataset.CHANGE_COND,
                });
                break;
            case 'DataSetCube':
                self.tableDesigner.render({
                    element: cont,
                    dsId: self.state.datasource.DS_ID,
                    dsType: self.state.dataset.DATASRC_TYPE,
                    cubeId: self.state.datasource.CUBE_ID,
                    dsViewId: self.state.datasource.DS_VIEW_ID,
                    relations: [],
                    selectClauses: self.state.dataset.SEL_CLAUSE,
                    fromClauses: self.state.dataset.FROM_CLAUSE,
                    whereClauses: self.state.dataset.WHERE_CLAUSE,
                    orderClauses: self.state.dataset.ORDER_CLAUSE,
                    selectInc: self.state.dataset.SEL_CLAUSE.length,
                    whereInc: self.state.dataset.WHERE_CLAUSE.length,
                    orderInc: self.state.dataset.ORDER_CLAUSE.length,
                    onSelectClauseChange: onSelectClauseChange,
                    onFromClauseChange: onFromClauseChange,
                    onWhereClauseChange: onWhereClauseChange,
                    onOrderClauseChange: onOrderClauseChange,
                    onParamChange: onParamChange,
                    onQueryChange: onQueryChange,
                    onParamEdit: onParamEdit,
                    onParamDelete: onParamDelete,
                    onTableParamChange: onTableParamChange,
					changeCond: self.state.dataset.CHANGE_COND,
                });
                break;
            default:
                cont.append($('<p>').text('Dataset type not found!'));
        }
    }

    /**
     * confirm button component (button)
     */
    function dsDesignerOkBtn() {
        return $('#dsDesignerOkBtn').dxButton({
            text: '확인',
            type: 'normal',
            onClick: function() {
                switch (self.state.dataset.DATASET_TYPE) {
                    case 'DataSetDs':
                    case 'DataSetCube':
                        self.tableDesigner.saveEditData(onDatasetConfirm);
                        break;
                    default:
                        onDatasetConfirm();
                }
            }
        }).dxButton('instance'); 
    }

    /**
     * cancel button component (button)
     */
    function dsDesignerCancelBtn() {
        return $('#dsDesignerCancelBtn').dxButton({
            text: '취소',
            type: 'normal',
            onClick: function() {
            	self.state.onPopupClose();
            	closePopup();
            }
        }).dxButton('instance');
    }
}