/**
 * 데이터집합 및 매개변수 정보 마스터 클래스
 * Dataset info master class.
 */
WISE.libs.Dashboard.DatasetMaster = function() {
    var self = this;
    this.utility = WISE.libs.Dashboard.item.DatasetUtility;
    this.state = {
        datasources: {},
        datasets: {},
        params: [],
        fields: {},
        selectedDataset: '',
        loaded: false,
    };
    this.components = {
        lookup: null,
    };

    /**
     * Get component state.
     * If you need to MODIFY resulting data then use this instead of calling state directly.
     * @param {string} action
     */
    this.getState = function(action) {
        switch (action) {
            case 'DATASOURCES':
                return _.cloneDeep(self.state.datasources);
            case 'DATASETS':
                return _.cloneDeep(self.state.datasets);
            case 'FIELDS':
                return _.cloneDeep(self.state.fields);
            case 'PARAMS':
                return _.cloneDeep(self.state.params);
            default:
                return _.cloneDeep(self.state);
        }
    };

    /**
     * Update component state.
     * @param {object} state
     * @param {string} action
     */
    this.setState = function(state, action) {
        switch (action) {
            case 'DATASOURCES':
                $.extend(self.state.datasources, state);
                break;
            case 'DATASETS':
                $.extend(self.state.datasets, state);
                break;
            case 'FIELDS':
                $.extend(self.state.fields, state);
                break;
            case 'DELETE_DATASET':
            	//20200807 yhkim 데이터집합 삭제 시 미삭제 항목 처리(datasetInformation, infoTreeList, lookUpItems) dogfoot
                delete gDashboard.dataSourceManager.datasetInformation[state];
                delete gDashboard.dataSetCreate.infoTreeList[self.state.datasets[state].DATASET_NM];
                delete self.state.datasources[state];
                delete self.state.datasets[state];
                delete self.state.fields[state];
                gDashboard.dataSetCreate.lookUpItems.pop(state);
                gDashboard.dataSourceQuantity--;
                $.extend(self.state, { 
                    params: self.utility.getUpdatedParameterList(state, []),
                    selectedDataset: Object.keys(self.state.datasets)[0] || ''
                });
                
                //20200720 ajkim 데이터셋 삭제시 데이터 항목 및 아이템 삭제 dogfoot
                if(gDashboard.itemGenerateManager && gDashboard.reportType === 'AdHoc')
	                $.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item){
	                	if(item.dataSourceId === state){
	                		$('.panelClear').click();
	                	}
	                });
                /*dogfoot 통계 분석 추가 shlim 20201102*/
                else if(gDashboard.itemGenerateManager && (gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis')){
                	var delItemList = [];
                	$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item){
	                	if(item && item.dataSourceId === state){
	                		delItemList.push(item.ComponentName)
	                	}
	                });
                	
                	for(var i = 0; i < delItemList.length; i++){
                		$('#' + delItemList[i] +' .lm_close').click();
                	}
                }
                break;
            default:
                $.extend(self.state, state);
        }
        // save dataset master info to other classes
        self.saveToOtherClasses();
    };

    /**
     * Restore state to initial (empty) values.
     */
    this.resetData = function() {
        self.state = {
            datasources: {},
            datasets: {},
            params: [],
            fields: {},
            selectedDataset: '',
            loaded: false,
        };
        self.components = {
            lookup: null,
        };
		gDashboard.dataSourceQuantity = 0;
    }

    /**
     * Allow a user to select and receive data from a saved dataset.
     */
    this.openDataset = function() {
        $('#data_popup').empty();
        var showFlag = true;
        $("#data_popup").dxPopup({
            showCloseButton: false,
            showTitle: true,
            visible: true,
            title: "데이터 집합 불러오기",
            closeOnOutsideClick: false,
            contentTemplate: function() {
                return $(
                    '<div class="modal-inner scrollbar">' + 
                        '<div class="modal-body">' + 
                            '<div class="row">' +
                                '<div class="column" style="height: 630px;">' +
                                    '<div class="modal-article">' + 
                                        '<div class="modal-tit">' + 
                                            '<span>데이터집합 목록</span>' + 
                                        '</div>' + 
                                        '<div id="data_list" class="data_list" style="float:left; margin-right:20px;"></div>' +
                                    '</div>' + 
                                '</div>' + 
                            '</div>' + 
                        '</div>' + 
                        '<div class="modal-footer" style="position:absolute; bottom: 0; width: 100%;">' + 
                            '<div class="row center">' + 
                                '<a id="btn_subject_check" href="#" class="btn positive ok-hide">확인</a>' + 
                                '<a id="btn_subject_cancel" href="#" class="btn neutral close">취소</a>' + 
                            '</div>' + 
                        '</div>' + 
                    '</div>'
                );
            },
            onContentReady: function(){
            	gDashboard.fontManager.setFontConfigForListPopup('data_list');
			},
            width: '90vw',
            height: '88vh',
            maxWidth: 600,
            maxHeight: 850,
            onShown: function () {
				//두번호출안되게
				if(showFlag) {            	
	                $.ajax({
	                    method: 'POST',
	                    data: {
	                        userId: userJsonObject.userId
	                    },
	                    beforeSend: function() {
	                    	//20210223 AJKIM cancelqueries.do 작동하지 않을 때 작업 취소 버튼 제거 DOGFOOT
	                        gProgressbar.show();
	                    },
	                    complete: function() {
	                        gProgressbar.hide();
	                    },
	                    url: WISE.Constants.context + '/report/dataSetList.do',
	                    success: function(data) {
	                        var DATASET_ID;
	                        var DATASET_NAME;
	
	                        data = jQuery.parseJSON(data);
	
	                        var dataSetFolders = data["dataSetFolders"];
	
	                        $("#data_list").dxTreeView({ 
	                            dataSource: dataSetFolders,
	                            dataStructure: "plain",
	                            parentIdExpr: "PARENT_FLD_ID",
	                            keyExpr: "FLD_ID",
	                            displayExpr: "FLD_NM",
	                            width: 500,
	                            height: 550,
	                            /* DOGFOOT hsshim 2020-02-03 데이터 집합 불러오기 UI에 탐색박스 추가 */
	                            searchEnabled: true,
	                            searchMode: 'contains',
	                            onInitialized:function(_e){
	                                $.each(_e.component.option('dataSource'),function(_i,_items){
	                                    if(typeof _items['DATASET_ID'] == 'undefined') {
	                                        _items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
	                                    } else {
	                                        _items['icon']= WISE.Constants.context + '/resources/main/images/ico_dataset.png';
	                                    }
	                                });
	                            },
	                            onItemClick: function(e) {
	                                DATASET_ID = e.itemData['DATASET_ID'];
	                                DATASET_NAME = e.itemData['FLD_NM'];
	                            }
	                        });
	
	                        $("#btn_subject_check").dxButton({
	                            text: "확인",
	                            type: "normal",
	                            onClick: function(e) {
	                                if(DATASET_ID != null){
	
	                                    var sameName = 0;
	                                    $.each(self.state.datasets, function(id, dataset) {
	                                        if(DATASET_NAME == dataset.DATASET_NM){
	                                            sameName = 1;
	                                        }
	                                    });
	                                    
	                                    if(sameName == 1) {
	                                        WISE.alert('현재 같은 이름의 데이터 집합명이 존재합니다.');
	                                        return false;
	                                    }
	                                    
	                                    /* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
	                                    WISE.Context.isCubeReport = false;
	                                    var confirmOk;
	                                    //2020.02.12 mksong 뷰어 비정형 컬럼선택기 오류 수정 dogfoot
	                                    if(gDashboard.dataSourceQuantity > 0 && gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode != 'viewer') {
											if(gDashboard.dataSourceQuantity > 0) {
	                                        	confirmOk = confirm('비정형모드에서는 데이터 집합이 1개만 사용됩니다. 기존 데이터집합을 삭제하고 추가하시겠습니까?');
	                                        } else {
												confirmOk = true;
											}
	                                        if(confirmOk){
	                                        	$('.panelClear').click();
												var pivot = gDashboard.itemGenerateManager.dxItemBasten[0].type === 'PIVOT_GRID'? gDashboard.itemGenerateManager.dxItemBasten[0] : gDashboard.itemGenerateManager.dxItemBasten[1];
												pivot.deltaItems=[];
												gDashboard.itemGenerateManager.clearItemData();
												$('.wise-area-deltaval').css('display', 'none');
	                                            self.resetData();
	                                        } else {
	                                            return false;
	                                        }
	                                    } else {
	                                        confirmOk = true;
	                                    }
	                                    
	                                    
	                                    if(confirmOk){
	                                        $.ajax({
	                                            method: 'POST',
	                                            url: WISE.Constants.context + '/report/dataSetInfo.do',
	                                            data: {
	                                                DATASET_ID: DATASET_ID
	                                            },
	                                            beforeSend: function() {
	                                                gProgressbar.show();
	                                            },
	                                            complete: function() {
	                                                gProgressbar.hide();
	                                            },
	                                            success: function(data) {
	                                                data = jQuery.parseJSON(data); 
	                                                // generate dataset info
	                                                var mapid = 'dataSource' + (gDashboard.dataSourceQuantity + 1);
	                                                var dataset = {
	                                                    DATASET_SEQ: data.DATASET_SEQ,
	                                                    DATASET_NM: data.DATASET_NM,
	                                                    DATASET_TYPE: data.DATASET_TYPE,
	                                                    DATASRC_ID: data.DATASRC_ID,
	                                                    DATASRC_TYPE: data.DATASRC_TYPE,
	                                                    DATASET_QUERY: data.DATASET_QUERY || data.SQL_QUERY,
	                                                    SQL_QUERY: data.DATASET_QUERY || data.SQL_QUERY,
	                                                    DATASET_XML: data.DATASET_XML,
	                                                    SHEET_ID: data.SHEET_ID,
	                                                    data: data.data,
	                                                    mapid: mapid,
	                                                    PARAM: data.PARAM_ELEMENT || data.param_element,
	                                                };                           
	                                                switch (data.DATASET_TYPE) {
	                                                    case 'DataSetCube':
	                                                        var datasetInfo = data.DATASET_JSON ? data.DATASET_JSON.DATA_SET : data;
	                                                        $.extend(dataset, {
	                                                            SEL_CLAUSE: $.isPlainObject(datasetInfo.SEL_ELEMENT) 
	                                                                ? self.utility.convertSelectClauseToNonCubeFormat(datasetInfo.SEL_ELEMENT.SELECT_CLAUSE) 
	                                                                : [],
	                                                            FROM_CLAUSE: [],
	                                                            WHERE_CLAUSE: $.isPlainObject(datasetInfo.WHERE_ELEMENT) 
	                                                                ? self.utility.convertWhereClauseToNonCubeFormat(datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE)
	                                                                : [],
	                                                            ORDER_CLAUSE: $.isPlainObject(datasetInfo.ORDER_ELEMENT) 
	                                                                ? self.utility.convertOrderClauseToNonCubeFormat(datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE)
	                                                                : [],
	                                                        });
	                                                        break;
	                                                    case 'DataSetDs':
	                                                        var datasetInfo = data.DATASET_JSON ? data.DATASET_JSON.DATA_SET : data;
	                                                        /* DOGFOOT ktkang 데이터 원본 기준 불러오기 오류 수정  20200713 */
	                                                        var selClause = [];
	                                                        if(typeof datasetInfo.SEL_ELEMENT != 'undefined' && typeof datasetInfo.SEL_ELEMENT.SELECT_CLAUSE != 'array') {
	                                                        	selClause.push(datasetInfo.SEL_ELEMENT.SELECT_CLAUSE);
	                                                        } else {
	                                                        	selClause = $.isPlainObject(datasetInfo.SEL_ELEMENT) ? datasetInfo.SEL_ELEMENT.SELECT_CLAUSE : [];
	                                                        }
	                                                        var fromClause = [];
	                                                        if(typeof datasetInfo.REL_ELEMENT != 'undefined' && typeof datasetInfo.REL_ELEMENT.JOIN_CLAUSE != 'array') {
	                                                        	fromClause.push(datasetInfo.REL_ELEMENT.JOIN_CLAUSE);
	                                                        } else {
	                                                        	fromClause = $.isPlainObject(datasetInfo.REL_ELEMENT) ? datasetInfo.REL_ELEMENT.JOIN_CLAUSE : [];
	                                                        }
	                                                        var whereClause = [];
	                                                        if(typeof datasetInfo.WHERE_ELEMENT != 'undefined' && typeof datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE != 'array') {
	                                                        	whereClause.push(datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE);
	                                                        } else {
	                                                        	whereClause = $.isPlainObject(datasetInfo.WHERE_ELEMENT) ? datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE : [];
	                                                        }
	                                                        var orderClause = [];
	                                                        if(typeof datasetInfo.ORDER_ELEMENT != 'undefined' && typeof datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE != 'array') {
	                                                        	orderClause.push(datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE);
	                                                        } else {
	                                                        	orderClause = $.isPlainObject(datasetInfo.ORDER_ELEMENT) ? datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE : [];
	                                                        }
	                                                        var changeCond = '';
	                                                        if(typeof datasetInfo.ETC_ELEMENT != 'undefined' && typeof datasetInfo.ETC_ELEMENT.CHANGE_COND != 'array') {
	                                                        	changeCond = $.isPlainObject(datasetInfo.ETC_ELEMENT) ? datasetInfo.ETC_ELEMENT.CHANGE_COND : '';
	                                                        }
	                                                        $.extend(dataset, {
	                                                            SEL_CLAUSE: selClause,
	                                                            FROM_CLAUSE: fromClause,
	                                                            WHERE_CLAUSE: whereClause,
	                                                            ORDER_CLAUSE: orderClause,
																CHANGE_COND: changeCond,
	                                                        });
	                                                        break;
	                                                    /* DOGFOOT ktkang 기본데이터 집합 단일테이블 기능 구현  20201112 */
	                                                    case 'DataSetSingleDs':
	                                                    case 'DataSetSingleDsView':
	                                                    	var colElement = [];
	                                                    	var colEle = data.col_element;
	                                                        if(typeof colEle != 'undefined') {
	                                                        	colElement.push(colEle);
	                                                        } else {
	                                                        	colElement = $.isPlainObject(colEle) ? colEle : [];
	                                                        }
	                                                        
	                                                        var etcElement = [];
	                                                    	var etcEle = data.etc_element;
	                                                        if(typeof etcEle != 'undefined') {
	                                                        	etcElement.push(etcEle);
	                                                        } else {
	                                                        	etcElement = $.isPlainObject(etcEle) ? etcEle : [];
	                                                        }
	                                                        
	                                                        var tblElement = [];
	                                                    	var tblEle = data.tbl_element;
	                                                        if(typeof tblEle != 'undefined') {
	                                                        	tblElement.push(tblEle);
	                                                        } else {
	                                                        	tblElement = $.isPlainObject(tblEle) ? tblEle : [];
	                                                        }	    
	                                                        
	                                                        $.extend(dataset, {
	                                                    		SEL_CLAUSE: [],
	                                                    		FROM_CLAUSE: [],
	                                                    		WHERE_CLAUSE: [],
	                                                    		ORDER_CLAUSE: [],
	                                                    		COL_ELEMENT: colElement,
	                                                    		ETC_ELEMENT: etcElement,
	                                                    		TBL_ELEMENT: tblElement
	                                                    	});
	                                                    default:
	                                                        $.extend(dataset, {
	                                                            SEL_CLAUSE: [],
	                                                            FROM_CLAUSE: [],
	                                                            WHERE_CLAUSE: [],
	                                                            ORDER_CLAUSE: [],
	                                                        });
	                                                }
	     
	                                                // generate datasource info
	                                                var dsRequestHeader = [{ mapid: mapid, dsid: dataset.DATASRC_ID, dstype: dataset.DATASRC_TYPE }];
	                                                $.ajax({
	                                                    method: 'GET',
	                                                    url: WISE.Constants.context + '/report/getDatasourceInfoById.do',
	                                                    data: { ids: $.toJSON(dsRequestHeader) },
	                                                    success: function(response) {
	                                                        if (response.status === 200) {
		                                                        /*dogfoot 데이터집합 between 달력 기본값 쿼리입력 복호화 shlim 20200728*/
	                                                        	if(typeof dataset.PARAM != 'undefined' && dataset.PARAM.length > 0){
	                                                        		$.each(dataset.PARAM,function(_i,_param){
	                                                        			if(_param.PARAM_TYPE == 'BETWEEN_CAND' && _param.DEFAULT_VALUE_USE_SQL_SCRIPT === 'Y'){
	                                                        				if(!(_param.DEFAULT_VALUE.trim() == '')){
	                                                        					var encodeSqlArr = _param.DEFAULT_VALUE.split(',');
																				_param.DEFAULT_VALUE = Base64.decode(encodeSqlArr[0])+','+Base64.decode(encodeSqlArr[1]);
																				_param.HIDDEN_VALUE = encodeSqlArr[0]+','+encodeSqlArr[1];
																				_param.defaultValue = Base64.decode(encodeSqlArr[0])+','+Base64.decode(encodeSqlArr[1]);
	                                                        				}
		                                                        		}
	                                                        		})
	                                                        		
	                                                        	}
	                                                            self.addDatasetToState(response.data[mapid], dataset, dataset.PARAM);
	                                                            $("#data_popup").dxPopup("instance").hide();
	                                                        } else {
	                                                            WISE.alert('Error finding datasources');
	                                                        }
	                                                    },
	                                                    error: function() {
	                                                        WISE.alert('Error finding datasources');
	                                                    },
	                                                });
	                                            }
	                                        });
	                                    }else{
	                                        $("#data_popup").dxPopup("instance").hide();
	                                    }
	
	                                }
	                            }
	                        });
	
	                        $("#btn_subject_cancel").dxButton({
	                            text: "취소",
	                            type: "normal",
	                            onClick: function(e) {
	                                $("#data_popup").dxPopup("instance").hide();
	                            },
	                            onContentReady: function(){
	                            	gDashboard.fontManager.setFontConfigForListPopup('data_list');
	                            	gDashboard.scrollbar();
	                			},
	                        });
	                        
	                        
	                    }
	                });
				}
				showFlag = false;
            }
        });
    }

    /**
     * Add new dataset or overwrite existing dataset to state and update components accordingly.
     * @param {object} datasource
     * @param {object} dataset
     * @param {object} params
     */
    this.addDatasetToState = function(datasource, dataset, params, useNotField) {
        // Before we add, check if this datset is new.
        // If so, then increment dataset count.
        if (!self.state.datasets[dataset.mapid]) {
            gDashboard.dataSourceQuantity++;
        }
        // create the dataset's value tree
        var datasetFieldTree = [{
            CAPTION: dataset.DATASET_NM, 
            ORDER: 0, 
            expanded: true, 
            DATASOURCE: dataset.mapid, 
            DATASET_TYPE: dataset.DATASET_TYPE 
        }];       
        
        if(!useNotField){
        	 var i = 1;
             $.each(dataset.data[0], function(key, val) {
                 var type;
                 var iconPath;
                 var dataType;
     			var visible = true;
     			/* DOGFOOT ktkang 데이터 원본 기준 불러오기 오류 수정  20200713 */
     			if(typeof val == 'number' || typeof val == 'bigint') {
     				type = 'MEA';
                     iconPath = '../images/icon_measure.png';
                     dataType = 'decimal';
     			} else {
     				switch (val) {
     				case 'number':
     				case 'decimal':
     					type = 'MEA';
     					iconPath = '../images/icon_measure.png';
     					dataType = 'decimal';
     					break;
     				default:
     					type = 'DIM';
     					iconPath = '../images/icon_dimension.png';
     					dataType = 'varchar';
     					break;
     				}
     			}
                 
                 datasetFieldTree.push({
                     CAPTION: key, 
                     ORDER: i + 1, 
                     PARENT_ID: "0", 
                     TYPE: type,  
                     icon: iconPath, 
                     DATA_TYPE: dataType, 
                     UNI_NM: key,
     				VISIBLE: visible,
     				// 2021-07-07 yyb 정렬설정 관련 추가
     				ORDBY_COL: '',
     				ORDBY: 'ASC'
                 });
                 i++;
             });
        }
       
        // update dataset master class
        var newState = {
            datasources: {},
            datasets: {},
            fields: {},
            params: []
        };
        newState.datasources[dataset.mapid] = datasource;
        newState.datasets[dataset.mapid] = dataset;
        newState.params = self.utility.getUpdatedParameterList(dataset.mapid, params);
        if(!useNotField){
        	newState.fields[dataset.mapid] = datasetFieldTree;
        }
        // save to state
        self.setState(newState.datasources, 'DATASOURCES');
        self.setState(newState.datasets, 'DATASETS');
        if(!useNotField){
        	self.setState(newState.fields, 'FIELDS');
        }
        self.setState({ params: newState.params });
        // save to other classes
        self.saveToOtherClasses();
        // render dataset lookup and drag & drop fields
        self.renderDatasetLookup(dataset.DATASET_NM);
        // render parameter filter bar
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
            params: self.state.params,
        });
        // add query event to "play" button
        $('#btn_query').off('click').on('click', function() {
        	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
        	if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab) {
				gDashboard.itemGenerateManager.selectedTabList = [];
				gDashboard.tabQuery = true;
			}
        	
            gDashboard.query();
        });
    };

    /**
     * Update state with information from gDashboard.structure.
     */
    this.setDataFromStructure = function() {
        self.resetData();
        /*dogfoot 집합 여러개 불러오기 오류 수정 shlim 20200729*/
//        var datasetNameInfo = gDashboard.structure.DataSources.DataSource;
        var datasetNameInfo = typeof gDashboard.structure.DataSources.DataSource !== 'undefined' ? gDashboard.structure.DataSources.DataSource : gDashboard.structure.DataSources;
        var reportInfo = gDashboard.structure.ReportMasterInfo;

        // set datasets
        var datasets = {};
        $.each(reportInfo.datasetJson.DATASET_ELEMENT, function(i, dataset) {
        	// 2021-07-07 yyb 필드정보 추가(데이터집합의 항목)
            var dataSetFields = isNull(dataset.DATASET_FIELD) ? null : dataset.DATASET_FIELD.LIST;
            for (var j = 0; j < datasetNameInfo.length; j++) {
				//replace xml tag to html tag
				var dataSetNm = dataset.DATASET_NM.replace(/&lt;/g, "<").replace(/&gt;/g, ">");
                if (datasetNameInfo[j].Name === dataSetNm) {
                    var componentName = datasetNameInfo[j].ComponentName;
                    datasets[componentName] = {
                        DATASET_SEQ: dataset.DATASET_SEQ,
                        DATASET_NM: dataSetNm,
                        DATASET_TYPE: dataset.DATASET_TYPE,
                        DATASRC_ID: dataset.DATASRC_ID,
                        DATASRC_TYPE: dataset.DATASRC_TYPE,
                        DATASET_QUERY: dataset.DATASET_QUERY || dataset.SQL_QUERY,
                        SQL_QUERY: dataset.DATASET_QUERY || dataset.SQL_QUERY,
                        DATASET_XML: dataset.DATASET_XML,
                        DATASET_JSON: dataset.DATASET_JSON,
                        //20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
                        IN_MEMORY: dataset.IN_MEMORY,
                        SHEET_ID: dataset.SHEET_ID,
                        data: [],
                        mapid: 'dataSource' + ++gDashboard.dataSourceQuantity,
                        PARAM: [],
                        /* dogfoot shlim erd JoinType 저장 추가 20210201*/
                        JOIN_TYPE: typeof dataset.JOIN_TYPE === "undefined" ? 'N':dataset.JOIN_TYPE,
                        DATASET_FIELDS: dataSetFields
                    };

					//테이블이 깨져도 집합수정이 가능하게
					self.setState({selectedDataset: componentName});

                    switch (dataset.DATASET_TYPE) {
                        case 'DataSetCube':
                            var datasetInfo = dataset.DATASET_JSON.DATA_SET;
                            $.extend(datasets[componentName], {
                                SEL_CLAUSE: $.isPlainObject(datasetInfo.SEL_ELEMENT) 
                                    ? self.utility.convertSelectClauseToNonCubeFormat(datasetInfo.SEL_ELEMENT.SELECT_CLAUSE) 
                                    : [],
                                FROM_CLAUSE: [],
                                WHERE_CLAUSE: $.isPlainObject(datasetInfo.WHERE_ELEMENT) 
                                    ? self.utility.convertWhereClauseToNonCubeFormat(datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE)
                                    : [],
                                ORDER_CLAUSE: $.isPlainObject(datasetInfo.ORDER_ELEMENT) 
                                    ? self.utility.convertOrderClauseToNonCubeFormat(datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE)
                                    : [],
                            });
                            break;
                        case 'DataSetDs':
                            var datasetInfo = dataset.DATASET_JSON.DATA_SET;
                            $.extend(datasets[componentName], {
                                SEL_CLAUSE: $.isPlainObject(datasetInfo.SEL_ELEMENT) ? datasetInfo.SEL_ELEMENT.SELECT_CLAUSE : [],
                                FROM_CLAUSE: $.isPlainObject(datasetInfo.REL_ELEMENT) ? datasetInfo.REL_ELEMENT.JOIN_CLAUSE : [],
                                WHERE_CLAUSE: $.isPlainObject(datasetInfo.WHERE_ELEMENT) ? datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE : [],
                                ORDER_CLAUSE: $.isPlainObject(datasetInfo.ORDER_ELEMENT) ? datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE : [],
								CHANGE_COND: $.isPlainObject(datasetInfo.ETC_ELEMENT) ? datasetInfo.ETC_ELEMENT.CHANGE_COND : '',
                            });
                            break;
                        default:
                            $.extend(datasets[componentName], {
                                SEL_CLAUSE: [],
                                FROM_CLAUSE: [],
                                WHERE_CLAUSE: [],
                                ORDER_CLAUSE: [],
                            });
                    }

                    datasets[componentName].mapid = componentName;
                    if (!datasets[componentName].DATASET_QUERY) {
                        datasets[componentName].DATASET_QUERY = datasets[componentName].SQL_QUERY;
                    }
                    break;
                }
            }
        });
        self.setState({ datasets: datasets });

        // set datasources
        var dsRequestHeader = _.map(self.state.datasets, function(dataset, mapid) {
        	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
        	if(dataset.DATASRC_TYPE == 'CUBE') {
        		WISE.Context.isCubeReport = true;
        	}
            return { mapid: mapid, dsid: dataset.DATASRC_ID, dstype: dataset.DATASRC_TYPE };
        });
        $.ajax({
            method: 'GET',
            url: WISE.Constants.context + '/report/getDatasourceInfoById.do',
            data: { ids: $.toJSON(dsRequestHeader) },
            success: function(response) {
                if (response.status === 200) {
                    self.setState({ datasources: response.data });
                } else {
                    WISE.alert('Error finding datasources');
                }
            },
            error: function() {
                WISE.alert('Error finding datasources');
            },
        });

        // set params
        var datasetCount = Object.keys(self.state.datasets).length;
        var fieldCount = 0;
        // set linked report default values
        if (WISE.Constants.editmode === 'viewer') {
            for (var i = 0; i < WISE.Constants.conditions.length; i++) {
                var pd = WISE.Constants.conditions[i];
                if(reportInfo.paramJson[pd.key]!=undefined) {
                	reportInfo.paramJson[pd.key].DEFAULT_VALUE = pd.value.split(',');
                    reportInfo.paramJson[pd.key].OVERRIDE_DEFAULT = true;
                }
            }
        }
        self.setState({ params: self.utility.getParamArray(reportInfo.paramJson) });
		/* dogfoot WHATIF 분석 매개변수 상태 설정 shlim 20201022 */        
        gDashboard.customParameterHandler.setState({ params: self.utility.getCalcParamArray(reportInfo.paramJson) });
        
        switch (WISE.Constants.editmode) {
            case 'designer':
                gDashboard.parameterFilterBar.render({
                    element: $('#report-filter-item'),
                    params: self.state.params,
                });
                break;
            case 'viewer':
                filterBarElement = $('<div id="' + reportInfo.id + '_paramContainer" class="filter-item" report_id = "' + reportInfo.id + '"></div>');
                $('.filter-row').append(filterBarElement);
                gDashboard.viewerParameterBars[reportInfo.id] = new WISE.libs.Dashboard.ParameterBar();
                gDashboard.viewerParameterBars[reportInfo.id].render({
                    element: filterBarElement,
                    params: self.state.params,
                });
                break;
            default:
                gDashboard.parameterFilterBar.render({
                    element: $('.filter-item'),
                    params: self.state.params,
                });
        }

        // set fields (for editor and viewer adhoc reports only)
        /* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
        if(WISE.Constants.editmode !== 'viewer' && WISE.Context.isCubeReport) {
			/* DOGFOOT hjkim 비정형에서 주제영역 불러올때 confirm창이 나와 주석처리함 20200701 */
        	//$.each(self.state.datasets, function(i, dataset) {
        	//	gDashboard.dataSetCreate.cubeListInfo(dataset.DATASRC_ID, 'CUBE'); 
        	//});
        }
        else if (WISE.Constants.editmode !== 'viewer' || gDashboard.reportType === 'AdHoc') {
        	if(WISE.Constants.editmode != 'viewer'){
        		$('.drop-down.tree-menu > ul').empty().append('<p class="loading-indicator">Loading...</p>');	
        	}else{
        		$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty().append('<p class="loading-indicator">Loading...</p>');
        	}
            $.each(self.state.datasets, function(id, dataset) {
                // looks like we already have sample data. no need to call the server to determine column data types
                if (dataset.data && dataset.data.length > 0) {
                    var metadata = {};
                    $.each(dataset.data[0], function(key, val) {
                        switch (typeof val) {
                            case 'number':
                                metadata[key] = 'decimal';
                                break;
                            default:
                                metadata[key] = 'varchar';
                        }
                    });
                                   
                    var datasetFieldTree = generateFieldTreeList(dataset, metadata);
                    var newState = {};
                    newState[dataset.mapid] = datasetFieldTree;
                    self.setState(newState, 'FIELDS');

                    // once all fields are loaded, signal that dataset is ready
                    fieldCount++;
                    if (fieldCount >= datasetCount) {
                        self.renderDatasetLookup(dataset.DATASET_NM, id, datasetFieldTree);
                        self.setState({ loaded: true });
                        // query data immediately if we are in viewer page
                        if (WISE.Constants.editmode === 'viewer') {
                        	/* goyong ktkang 뷰어 데이터 항목 오류 수정  20210603 */
                        	if(gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
                        		/* DOGFOOT ktkang 고용정보원09  바로조회 기능 오류 수정  */
								self.addBetParam();
							} else {
								gProgressbar.stopngo = true;
								gProgressbar.hide();
							}
                        }
                    }
                } 
                // obtain metadata and generate value tree list accordingly
                else {
                	var fields = self.state.datasets[dataset.mapid].DATASET_FIELDS;
                	if (isNull(fields)) {
                		if (dataset.DATASRC_TYPE != 'CUBE') {
                			if (!isNull(menuConfigManager.getMenuConfig.Menu.DSSAVE_CHECK) && menuConfigManager.getMenuConfig.Menu.DSSAVE_CHECK) {
	                			WISE.alert('현재 데이터집합 정보가 저장되어 있지 않아 기존 방식대로 조회하는 보고서 입니다.');
	                		}
		                    $.ajax({
		                        method: 'POST',
		                        url: WISE.Constants.context + '/report/getDatasetTableColumnList.do',
		                        data: {
		                            DATASRC_ID: dataset.DATASRC_ID,
		                            DATASRC_TYPE: dataset.DATASRC_TYPE,
		                            SQL_QUERY: dataset.DATASET_QUERY,
		                            PARAMS: $.toJSON(self.utility.generateNewParamValues(self.utility.getParamByMapId(dataset.mapid))),
									TBL_LIST: $.toJSON(self.utility.getCurrentTableList(dataset.DATASET_NM)),
									//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
									IN_MEMORY: dataset.IN_MEMORY
									
		                        },
		                        success: function(response) {
		                            // server error occurred
		                            if (response.error) {
		                            	//2020.09.18 mksong 검색제한시간 초과 오류 문구 수정 dogfoot
										if(response.error == 422){
											WISE.alert('검색제한시간을 초과하였습니다.');							
										}else{
											WISE.alert('쿼리가 부적합 합니다.');
										}
				                    }
		                            // no problem
		                            else {
		                                // create the dataset's field tree
		                                var datasetFieldTree = generateFieldTreeList(dataset, response.data[0]);
		                                var newState = {};
		                                newState[dataset.mapid] = datasetFieldTree;
		                                self.setState(newState, 'FIELDS');
		                                
		                                fieldCount++;
		                                if (fieldCount >= datasetCount) {
		                                	self.finRenderFields(dataset, id, datasetFieldTree, true);
		                                }
		                                
		                                if(gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode == 'viewer'){
		                            		var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(gDashboard.structure.ReportMasterInfo.cube_nm);
		                            		if(gDashboard.dataSourceManager.datasetInformation[dataSrcId].DATASRC_TYPE == 'CUBE'){
		                            			//gDashboard.dataSetCreate.cubeListInfo(gDashboard.dataSourceManager.datasetInformation['dataSource1'].DATASRC_ID, 'CUBE');
		                            		}else{
		                                    	gDashboard.dataSetCreate.columnListInfo(gDashboard.dataSourceManager.datasetInformation['dataSource1'].DATASRC_ID);
		                                    	
		                                    	var data = gDashboard.dataSourceManager.datasetInformation[dataSrcId];
		                                    	var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE' : 'dataSource' + gDashboard.dataSourceQuantity}];
		
		                                    	var i = 1;
		                                    	if(data['data']){
		                            				for(var key in data['data'][0]) {
		                            					var type;
		                            					var iconPath;
		                            					var dataType;
		                            					switch($.type(data['data'][0][key])) {
		                            					case 'number': 
		                            						type = 'MEA';
		                            						iconPath = '../images/icon_measure.png';
		                            						dataType = 'decimal';
		                            						break;
		                            					default:
		                            						type = 'DIM';
		                            						iconPath = '../images/icon_dimension.png';
		                            						dataType = 'varchar';
		                            					}
		
		                            					var infoTree = [{'CAPTION': key, 'ORDER': i, 'PARENT_ID': "0", 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType, 'UNI_NM':key}];
		
		                            					dataSetInfoTree = dataSetInfoTree.concat(infoTree);
		                            					i++;
		                            				}
		                                    	}
		                        				
		                        				
		                        				/* DOGFOOT hsshim 1216
		                        				 * 조회시 집합 중복되는 오류 수정
		                        				 */
		//                        				$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
		                        				/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
		                        	            gDashboard.dataSetCreate.insertDataSet(dataSetInfoTree, dataSrcId);
		                        			}
		                            	}
		                            }
		                        },
		                    });
                		}
                		else {
                			// 2021-07-16 yyb 조회속도 개선을위한 비정형 주제영역시 예외처리
							if (gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode == 'viewer') {
								// 위에서 ajax를 타지 않기 때문에 부득이하게 timeout을 걸었음
								// 먼저처리되고 cubeListInfo가 호출되어야 함...
								setTimeout(function() {
									var data = gDashboard.dataSourceManager.datasetInformation[id];
									var dataSetInfoTree = generateFieldTreeList(dataset, data);
									var newState = {};
									newState[dataset.mapid] = datasetFieldTree;
									self.setState(newState, 'FIELDS');
									self.finRenderFields(dataset, id, datasetFieldTree, true);	// 여기서는 true
									gDashboard.dataSetCreate.cubeListInfo(gDashboard.dataSourceManager.datasetInformation[id].DATASRC_ID, 'CUBE');
								}, 10);
							}
                		}
                	}
                	else {
                		var newState = {};
                        newState[dataset.mapid] = fields;
                		self.setState(newState, 'FIELDS');
                		fieldCount++;
                        if (fieldCount >= datasetCount) {
                        	self.finRenderFields(dataset, id, fields, false);
                        }
                	}
                }
            });
        } else if (WISE.Constants.editmode === 'viewer') {
            $.each(self.state.datasets, function(id, dataset) {
                // looks like we already have sample data. no need to call the server to determine column data types
                if (dataset.data && dataset.data.length > 0) {
                    var metadata = {};
                    $.each(dataset.data[0], function(key, val) {
                        switch (typeof val) {
                            case 'number':
                                metadata[key] = 'decimal';
                                break;
                            default:
                                metadata[key] = 'varchar';
                        }
                    });
                                   
                    var datasetFieldTree = generateFieldTreeList(dataset, metadata);
                    var newState = {};
                    newState[dataset.mapid] = datasetFieldTree;
                    self.setState(newState, 'FIELDS');

                    // once all fields are loaded, signal that dataset is ready
                    fieldCount++;
                    if (fieldCount >= datasetCount) {
                        self.setState({ loaded: true });
                        /* DOGFOOT ktkang 보고서 바로 조회 기능 옵션 추가  20201015 */
                        if (WISE.Constants.editmode === 'viewer') {
							if(gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
								/* DOGFOOT ktkang 고용정보원09  바로조회 기능 오류 수정  */
								self.addBetParam();
							} else {
								gProgressbar.stopngo = true;
								gProgressbar.hide();
							}
                        }
                    }
                } 
                // obtain metadata and generate value tree list accordingly
                else {
                	var fields = self.state.datasets[dataset.mapid].DATASET_FIELDS;
                	if (dataset.DATASRC_TYPE != 'CUBE') {
                		if (isNull(fields)) {
                			if (!isNull(menuConfigManager.getMenuConfig.Menu.DSSAVE_CHECK) && menuConfigManager.getMenuConfig.Menu.DSSAVE_CHECK) {
	                			WISE.alert('현재 데이터집합 정보가 저장되어 있지 않아 기존 방식대로 조회하는 보고서 입니다.');
	                		}
                			param = {
                					DATASRC_ID: dataset.DATASRC_ID,
                					DATASRC_TYPE: dataset.DATASRC_TYPE,
                					SQL_QUERY: dataset.DATASET_QUERY,
                					IN_MEMORY: dataset.IN_MEMORY,
                					PARAMS: $.toJSON(self.utility.generateNewParamValues(self.utility.getParamByMapId(dataset.mapid)))
                			};

                			if(param.IN_MEMORY){
                				param.TBL_LIST = $.toJSON(self.utility.getCurrentTableList(dataset.DATASET_NM));
                			}
                			$.ajax({
                				method: 'POST',
                				/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
                				async: dataset.IN_MEMORY? false : true,
                						url: WISE.Constants.context + '/report/getDatasetTableColumnList.do',
                						data: param,
                						success: function(response) {
                							// server error occurred
                							if (response.error) {
                								//2020.09.18 mksong 검색제한시간 초과 오류 문구 수정 dogfoot
                								if(response.error == 422){
                									WISE.alert('검색제한시간을 초과하였습니다.');							
                								}else{
                									WISE.alert('쿼리가 부적합 합니다.');
                								}
                							} 
                							// no problem
                							else {
                								// create the dataset's field tree
                								var datasetFieldTree = generateFieldTreeList(dataset, response.data[0]);
                								var newState = {};
                								newState[dataset.mapid] = datasetFieldTree;
                								self.setState(newState, 'FIELDS');

                								// once all fields are loaded, signal that dataset is ready
                								fieldCount++;
                								if (fieldCount >= datasetCount) {
                									self.setState({ loaded: true });
                									// query data immediately if we are in viewer page
                									if (WISE.Constants.editmode === 'viewer') {
                										/* DOGFOOT ktkang 대시보드 주제영역 및 데이터 집합 2개 이상 불러오기 오류 수정  20200921 */
                										setTimeout(function(){
//              											/* DOGFOOT ktkang 뷰어에서 보고서 바로 조회 기능 옵션 추가  20201015 */
                											if(gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
                												/* DOGFOOT ktkang 고용정보원09  바로조회 기능 오류 수정  */
                												self.addBetParam();
                											} else {
                												/* goyong ktkang 뷰어 데이터 항목 오류 수정  20210603 */
                												if(dataset.DATASRC_TYPE == 'CUBE') {
                													gDashboard.dataSetCreate.cubeListInfo(dataset.DATASRC_ID, 'CUBE');
                												}
                												$('#progress_box').css('display','none');
                											}
                										},10);
                									}
                								}
                							}
                						},
                			});
                		}else {
                    		var newState = {};
                            newState[dataset.mapid] = fields;
                    		self.setState(newState, 'FIELDS');

                            fieldCount++;
                            if (fieldCount >= datasetCount) {
                            	self.finRenderFields(dataset, id, fields, false);
                            }
                    	}
                	} else {
                		if(gDashboard.reportType != 'Adhoc') {
                			self.finRenderFields(dataset, id, fields, false);
                		}
                	}
                }
            });
        }

        // add query evernt to query button
        $('#btn_query').off('click').on('click', function() {
        	if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab) {
				gDashboard.itemGenerateManager.selectedTabList = [];
				gDashboard.tabQuery = true;
			}
        	
            if (self.state.loaded) {
                gDashboard.query();
            } else {
            	/* DOGFOOT ktkang 주택공사용 임시 에러메세지 변경  20200903 */
            	WISE.alert('데이터집합을 불러오지 못했습니다. 확인 후 조회하시기 바랍니다.');
//              WISE.alert('데이터집합이 로딩 중 입니다. 잠시후 다시 시도해주시기 바랍니다.');
            }
        });
    };

 // 2021-07-07 yyb 저장된 데이터항목 마지막으로 그리기
    this.finRenderFields = function (dataset, id, fields, isGetDsTblColList) {
    	if (WISE.Constants.editmode !== 'viewer' || gDashboard.reportType === 'AdHoc') {
	    	// 데이터항목 db 조회(기존거)
	    	if (isGetDsTblColList) {
	    		self.renderDatasetLookup(dataset.DATASET_NM, id, fields);
	            self.setState({ loaded: true });
	            // query data immediately if we are in viewer page
	            if (WISE.Constants.editmode === 'viewer') {
	            	// 20210408 AJKIM 비정형 바로조회 오류 수정 dogfoot
	            	if(gDashboard.structure.ReportMasterInfo.direct_view == "Y"){
	            		self.addBetParam();
	            	}
	            	else{
	            		gProgressbar.setStopngoProgress(true)
	            		gProgressbar.hide();
	            	}
	            }
	    	}
	    	else {
	    		if (gDashboard.reportType == 'AdHoc') {
                	setTimeout(function(){
                		self.renderDatasetLookup(dataset.DATASET_NM, id, fields);
                        self.setState({ loaded: true });
                        // query data immediately if we are in viewer page
                        if (WISE.Constants.editmode === 'viewer') {
                        	// 20210408 AJKIM 비정형 바로조회 오류 수정 dogfoot
                        	if(gDashboard.structure.ReportMasterInfo.direct_view == "Y"){
                        		self.addBetParam();
                        	}
                        	else{
                        		gProgressbar.setStopngoProgress(true)
                        		gProgressbar.hide();
                        	}
                        	gDashboard.dataSetCreate.insertDataSet(fields, id);
                        }
					}, 10);
            	}
            	else {
            		self.renderDatasetLookup(dataset.DATASET_NM, id, fields);
                    self.setState({ loaded: true });
                }
	    	}
    	}
    	else if (WISE.Constants.editmode === 'viewer') {
			self.setState({ loaded: true });
             /* DOGFOOT ktkang 대시보드 주제영역 및 데이터 집합 2개 이상 불러오기 오류 수정  20200921 */
     		setTimeout(function(){
				if (gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
					self.addBetParam();
				}
				else {
					$('#progress_box').css('display','none');
				}
			},10);
	   }
    }
    
    this.addBetParam = function() {
    	var countParams = 0;
		
		$.each(gDashboard.parameterFilterBar.parameterInformation, function(i, param){
			countParams++;
		});
		
		var paramFinishFunc = setInterval(function () {
			if(countParams <= gDashboard.finishParams && gDashboard.contentReadyParamList.length == 0) {
				gDashboard.query();
				clearInterval(paramFinishFunc);
			}
		},100);
    }
    
    /**
     * Save dataset data to other classes that need them.
     * 
     * PS. This method is called to make legacy code work.
     *     Data saved to the locations below are deprecated and unreliable.
     *     For any future development, read data from DatasetMaster's state object
     *     or by calling DatasetMaster's getState() function.
     */
    this.saveToOtherClasses = function() {
        // save dataset info
		gDashboard.structure.DataSources = WISE.libs.Dashboard.item.DatasetUtility.getDatasourcesForLayoutXml();
		var copyDataSets = self.state.datasets;
		$.each(copyDataSets,function(i, obj) {
			if(typeof obj.data != undefined) delete obj.data;
		});
        $.extend(gDashboard.dataSourceManager.datasetInformation, copyDataSets);
        // save subject info list info
        $.extend(gDashboard.dataSetCreate.subjectInfoList, self.state.datasources);
        // save value tree list info
        $.extend(gDashboard.dataSetCreate.infoTreeList, self.utility.generateInfoTreeList());
        // save lookup item info
        /* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
//        $.extend(gDashboard.dataSetCreate.lookUpItems, self.utility.generateLookUpItems());
        // save param tree list info
        $.extend(gDashboard.dataSetCreate.paramTreeList, self.utility.generateParamTreeList());
        // save parameter information
        $.extend(gDashboard.parameterFilterBar.parameterInformation, self.utility.getParamObject(self.state.params));
    };

    /**
     * Return dataset info of currently selected dataset.
     * If no dataset is selected, return null.
     */
    this.getSelectedDataset = function() {
        var result = self.state.datasets[self.state.selectedDataset];
        if (result) {
            return _.cloneDeep(result);
        }
        return null;
    };

    /**
     * Return dataset name of currently selected dataset.
     * If no dataset is selected, return null.
     */
    this.getSelectedDatasetName = function() {
        var result = self.state.datasets[self.state.selectedDataset];
        if (result) {
            return result.DATASET_NM;
        }
        return '';
    };

    /**
     * Delete selected dataset info and update the page accordingly.
     */
    this.deleteSelectedDataset = function() {
        self.setState(self.state.selectedDataset, 'DELETE_DATASET');
        if (WISE.Constants.editmode === 'designer' || WISE.Constants.editmode === 'spreadsheet') {
            self.updateEditorUI();
        }
    }

    /**
     * Render dataset lookup component.
     * If tree list is not rendered, render one with given mapid and valueTree.
     * @param {string} datasetName
     * @param {string} mapid
     * @param {object[]} valueTree
     */
    this.renderDatasetLookup = function(datasetName, mapid, valueTree) {
        // initialize lookup component if it doesnt exist
        if (!self.components.lookup) {
            self.components.lookup = $("#dataSetLookUp").dxLookup({
                showPopupTitle: false,
                searchEnabled: false,
                showPopupTitle: false,
                showCancelButton: false,
                closeOnOutsideClick: true,
                onValueChanged: function(e) {
                    if (e.value !== '') {
                        var valueTrees = self.getState('FIELDS');
                        var dsId = self.utility.getMapIdByDatasetName(e.value);
                        if (dsId && valueTrees[dsId]) {
                            self.setState({ selectedDataset: dsId });
                            self.createDatasetFieldTree(valueTrees[dsId], dsId);	
                        }
                    }
                }
            }).dxLookup('instance');
        }
        // when a report is opened 보고서 불러오기 할때만 통하는 것
        if (mapid && datasetName && valueTree) {
            self.createDatasetFieldTree(valueTree, mapid);
            self.components.lookup.option({ 
                items: self.utility.getDatasetNames(), 
                value: datasetName 
            });
            self.setState({ selectedDataset: mapid });
        } 
        // when there are no datasets
        else if (!datasetName || datasetName === '') {
            self.components.lookup.option({ items: [], value: '' });
            if(WISE.Constants.editmode != 'viewer'){
            	$('.drop-down.tree-menu > ul').empty();	
            }else{
            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
            }
        }
        // when a dataset is created/modified via dataset designer 보고서 생성/편집 할때 통하는 것
        else {
            var items = self.utility.getDatasetNames();
            var value = datasetName || items[0];
            // reset field list
            self.components.lookup.option('value', '');
            self.components.lookup.option({ items: items, value: value });
        }
    }

    this.renderDatasetForViewer = function(dsId, reportId) {
    	var valueTrees = self.getState('FIELDS');
        if (dsId && valueTrees[dsId]) {
            self.setState({ selectedDataset: dsId });
            self.createDatasetFieldTree(valueTrees[dsId], dsId);	
        }
    	
    	self.createDatasetFieldTree(valueTrees[dsId], dsId, reportId);
    }
    
    /**
     * Create a dataset field tree and add it to the tree menu container.
     * @param {object} valueTree
     * @param {string} dsId
     * dogfoot 분석항목 폴더 그룹화 shlim 20210319
     */
    this.createDatasetFieldTree = function(valueTree, dsId, reportId) {
    	var treeUl;
    	if(WISE.Constants.editmode == 'viewer'){
    		treeUl = $('#dataArea_'+reportId).find($('.drop-down.tree-menu > ul'));
    	}else{
    		treeUl = $('.drop-down.tree-menu > ul');
    		treeUl.empty();
    	}
    	/*dogfoot 분석항목 정렬  shlim 20210329 */
    	if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
    		valueTree.sort(function(a,b){
        		if(typeof a.DATASOURCE != "undefined"){
        			return -1;
                }
                if(typeof b.DATASOURCE != "undefined"){
        			return 1;
                }
    			return a.CAPTION.localeCompare(b.CAPTION);
    			//return a.CAPTION < b.CAPTION ? -1 : a.CAPTION < b.CAPTION ? 1 : 0;
    		})
		}
    	
    	
		var html = '<li class="active">';
		var meaCount = 0, dimCount = 0, sortCount = 0, meaHtml = "", dimHtml = "",sortHtml="";
		$.each(valueTree,function(i, value) {
			if (i === 0) {
				html += '<a href="#" class="ico arrow">' + value.CAPTION + '</a>' +
				        '<ul class="dep dataset" style="display:block">';
			} else {
				if(value.VISIBLE!==false) {
	                var fieldType;
	                var icon;
					if (value.TYPE == 'MEA') {
	                    fieldType = 'measure';
	                    icon = 'sigma';
					} else {
	                    fieldType = 'dimension';
	                    icon = 'block';
	                }
					/*dogfoot shlim 20210414*/
					var _hideColumn = false;
					if(WISE.Constants.companyname == "고용정보원"){
						if(WISE.Constants.editmode == "viewer" && value.CAPTION.indexOf("H_") > -1 && value.CAPTION.indexOf("H_") == 0){
							_hideColumn = true;
						}
					}
					if(!_hideColumn){
						if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
							if(value.CAPTION.indexOf('S_') == 0 || value.CAPTION.indexOf('H_') == 0) {
								if(sortCount == 0){
									sortHtml += '<li id="정렬항목" class="wise-fld-area" >';
									sortHtml += '<a href="#" class="ico arrow" dataset-caption="정렬항목">정렬항목</a>';
									sortHtml += '<ul class="dep dataset" style="display:none">';
								}
								sortCount++;
								
								if(value.VISIBLE == undefined || value.VISIBLE == true){
									if(value.UNI_NM != undefined){
										if(value.CUSTOM_DATA){
											sortHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+fieldType+'" data-source-id="'+dsId+'" CUSTOM_DATA="Y" UNI_NM="'+ value.UNI_NM +'" TABLE_NM="'+ value.UNI_NM.substr(value.UNI_NM.indexOf('[')+1,value.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ value.UNI_NM +'" title="'+ value.CAPTION +'"><a href="#" class="ico custom '+icon+'"><div class="fieldName">'+value.CAPTION+'</div></a></li>';	
										}else{
											sortHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+fieldType+'" data-source-id="'+dsId+'" UNI_NM="'+ value.UNI_NM +'" TABLE_NM="'+ value.UNI_NM.substr(value.UNI_NM.indexOf('[')+1,value.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ value.UNI_NM +'" title="'+ value.CAPTION +'"><a href="#" class="ico '+icon+'"><div class="fieldName">'+value.CAPTION+'</div></a></li>';		
										}	
									}else{
										sortHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+fieldType+'" data-source-id="'+dsId+'" UNI_NM="'+ value.UNI_NM +'" title="'+ value.CAPTION +'"><a href="#" class="ico '+icon+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
									}
								}
							}else if(value.TYPE == 'MEA'){
								if(meaCount == 0){
									meaHtml += '<li id="측정값" class="wise-fld-area active" >';
									meaHtml += '<a href="#" class="ico arrow" dataset-caption="측정값">측정값</a>';
									meaHtml += '<ul class="dep dataset" style="display:block">';
								}
								meaCount++;
								if(value.VISIBLE == undefined || value.VISIBLE == true){
									if(value.UNI_NM != undefined){
										
										meaHtml += '<li class="wise-column-chooser wise-area-field" ' +
							                            'prev-container="allList" ' +
							                            'data-field-type="' + fieldType + '" ' +
							                            'data-source-id="' + dsId + '" ' +
							                            'UNI_NM="' + value.UNI_NM + '" ' +
							                            'title="' + value.CAPTION + '">' +
							                            '<a href="#" class="ico ' + icon + '">' +
							                                '<div class="fieldName">' + value.CAPTION + '</div>' +
							                            '</a>' +
							                        '</li>';
										
									}
								}
							} else {
								if(dimCount == 0){
									dimHtml += '<li id="분석항목" class="wise-fld-area active" >';
									dimHtml += '<a href="#" class="ico arrow" dataset-caption="분석항목(행, 열)">분석항목(행, 열)</a>';
									dimHtml += '<ul class="dep dataset" style="display:block">';
										
								}
								dimCount++;
								dimHtml += '<li class="wise-column-chooser wise-area-field" ' +
						                        'prev-container="allList" ' +
						                        'data-field-type="' + fieldType + '" ' +
						                        'data-source-id="' + dsId + '" ' +
						                        'UNI_NM="' + value.UNI_NM + '" ' +
						                        'title="' + value.CAPTION + '">' +
						                        '<a href="#" class="ico ' + icon + '">' +
						                            '<div class="fieldName">' + value.CAPTION + '</div>' +
						                        '</a>' +
						                    '</li>';
							}
						}else{
			                html += '<li class="wise-column-chooser wise-area-field" ' +
		                        'prev-container="allList" ' +
		                        'data-field-type="' + fieldType + '" ' +
		                        'data-source-id="' + dsId + '" ' +
		                        'UNI_NM="' + value.UNI_NM + '" ' +
		                        'title="' + value.CAPTION + '">' +
		                        '<a href="#" class="ico ' + icon + '">' +
		                            '<div class="fieldName">' + value.CAPTION + '</div>' +
		                        '</a>' +
		                    '</li>';
						}
					}
				}
			}
		});
		if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
			dimHtml += '</ul></li>';
			sortHtml += '</ul></li>';
			meaHtml += '</ul></li>';
			html += dimHtml;
			html += sortHtml;
			html += meaHtml;
		}
		html += '</ul></li>';
		
		if(gDashboard.customFieldManager.fieldInfo[dsId]) {
			gDashboard.customFieldManager.setCustomFieldsForOpen(dsId);
		} else {
			treeUl.append(html);
			treeUl.find($('.dataset > li')).not('.wise-fld-area').draggable(gDashboard.dragNdropController.draggableOptions);
			treeMenuUi();
		}
    };
    
    /**
     * Create a dataset field tree and add it to the tree menu container.
     * @param {object} valueTree
     * @param {string} dsId
     */
//    this.createDatasetFieldTree = function(valueTree, dsId, reportId) {
//    	var treeUl;
//    	if(WISE.Constants.editmode == 'viewer'){
//    		treeUl = $('#dataArea_'+reportId).find($('.drop-down.tree-menu > ul'));
//    	}else{
//    		treeUl = $('.drop-down.tree-menu > ul');
//    		treeUl.empty();
//    	}
//    	
//		var html = '<li class="active">';
//		$.each(valueTree,function(i, value) {
//			if (i === 0) {
//				html += '<a href="#" class="ico arrow">' + value.CAPTION + '</a>' +
//				        '<ul class="dep dataset" style="display:block">';
//			} else {
//				if(value.VISIBLE!==false) {
//	                var fieldType;
//	                var icon;
//					if (value.TYPE == 'MEA') {
//	                    fieldType = 'measure';
//	                    icon = 'sigma';
//					} else {
//	                    fieldType = 'dimension';
//	                    icon = 'block';
//	                }
//	                html += '<li class="wise-column-chooser wise-area-field" ' +
//	                            'prev-container="allList" ' +
//	                            'data-field-type="' + fieldType + '" ' +
//	                            'data-source-id="' + dsId + '" ' +
//	                            'UNI_NM="' + value.UNI_NM + '" ' +
//	                            'title="' + value.CAPTION + '">' +
//	                            '<a href="#" class="ico ' + icon + '">' +
//	                                '<div class="fieldName">' + value.CAPTION + '</div>' +
//	                            '</a>' +
//	                        '</li>';
//				}
//			}
//		});
//		
//		html += '</ul></li>';
//		
//		if(gDashboard.customFieldManager.fieldInfo[dsId]) {
//			gDashboard.customFieldManager.setCustomFieldsForOpen(dsId);
//		} else {
//			treeUl.append(html);
//			treeUl.find($('.dataset > li')).draggable(gDashboard.dragNdropController.draggableOptions);
//			treeMenuUi();
//		}
//    };

    /**
     * Update editor page with current state info.
     */
    this.updateEditorUI = function() {
        gDashboard.parameterFilterBar.render({
            element: $('#report-filter-item'),
            params: self.state.params,
        });
        self.renderDatasetLookup(self.getSelectedDatasetName());
    }
    
    /**
     * Return a value tree list generated with dataset info and metadata.
     * @param {object} dataset 
     * @param {object[]} metadata 
     */
    function generateFieldTreeList(dataset, metadata) {
        var datasetFieldTree = [{
            CAPTION: dataset.DATASET_NM, 
            ORDER: 0, 
            expanded: true, 
            DATASOURCE: dataset.mapid, 
            DATASET_TYPE: dataset.DATASET_TYPE 
        }];                        
        var i = 1;
        $.each(metadata, function(key, val) {
            var type;
            var iconPath;
            var dataType;
			var visible = true;
            switch (val) {
                case 'number':
                case 'decimal':
                    type = 'MEA';
                    iconPath = '../images/icon_measure.png';
                    dataType = 'decimal';
                    break;
                default:
                    type = 'DIM';
                    iconPath = '../images/icon_dimension.png';
                    dataType = 'varchar';
            }
            datasetFieldTree.push({
                CAPTION: key, 
                ORDER: i + 1, 
                PARENT_ID: "0", 
                TYPE: type,  
                icon: iconPath, 
                DATA_TYPE: dataType, 
                UNI_NM: key,
				VISIBLE: visible
            });
            i++;
        });

        return datasetFieldTree;
    }
    
    //기존 DataSource,DataSet,Field,Param정보를 신규state로 복사한다.
    this.migDatasetToState = function(mapid) {
        var newState = {
            datasources: {},
            datasets: {},
            fields: {},
            params: []
        };

        var oldDataSource = gDashboard.dataSetCreate.subjectInfoList[mapid];
    	var oldDataSet = gDashboard.dataSourceManager.datasetInformation[mapid];
    	var oldField = gDashboard.dataSetCreate.infoTreeList[oldDataSet.DATASET_NM];
    	var oldParam = gDashboard.parameterFilterBar.parameterInformation[mapid]; 
    	
    	oldDataSource['DS_TYPE'] = oldDataSource['dataType'];
    	oldDataSet['DATASET_QUERY'] = oldDataSet['SQL_QUERY'];
    	oldField[0]['DATASET_TYPE'] = oldDataSet['DATASET_TYPE'];
    	
        newState.datasources[mapid] = oldDataSource;
        newState.datasets[mapid] = oldDataSet;
        newState.fields[mapid] = oldField;
        newState.params[mapid] = oldParam;
        
    	$.extend(self.state.datasources, newState.datasources);
    	$.extend(self.state.datasets, newState.datasets);
    	$.extend(self.state.fields, newState.fields);
    	$.extend(self.state.params, newState.params);
    	
    	self.state.selectedDataset = mapid;
    }
}