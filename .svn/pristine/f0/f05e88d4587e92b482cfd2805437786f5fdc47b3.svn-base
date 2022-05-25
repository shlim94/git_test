/**
 * 데이터집합 디자이너에 쿼리 직접 입력 컴포넌트 클래스
 * Dataset table designer component class.
 */
WISE.libs.Dashboard.DatasetTableDesigner = function() {
    var self = this;
    this.utility = WISE.libs.Dashboard.item.DatasetUtility;
    this.state = {
        element: null,
        dsId: null,
        dsType: '',
        cubeId: null,
        dsViewId: null,
        selectClauses: [],
        fromClauses: [],
        whereClauses: [],
        orderClauses: [],
        relations: [],
        selectInc: 0,
        whereInc: 0,
        orderInc: 0,
        onSelectClauseChange: null,
        onFromClauseChange: null,
        onWhereClauseChange: null,
        onOrderClauseChange: null,
        onParamChange: null,
        onQueryChange: null,
        onParamEdit: null,
        onParamDelete: null,
        onTableParamChange: null,
		onCondChange: null,
		changeCond: '',
    };
    this.container = null;
    this.components = {
        selectClauseTable: null,
        whereClauseTable: null,
        relationClauseTable: null,
        orderClauseTable: null,
        paramEditBtn: null,
		relationOrderTabPanel: null,
		logicArea: null,
		checkLogic: null,
    };

    /**
     * Update component state.
     */
    this.setState = function(state) {
        $.extend(self.state, state);
    }

    /**
     * Renders query designer component.
     * @param props
     */
    this.render = function(props) {
        self.setState(props);
        self.state.element.append(
            '<div class="row horizen" style="height: 100%;">' + 
                '<div class="column" style="height:30%; padding-bottom: 0;">' +
                    '<div class="modal-tit" style="height: 37px; margin-bottom: 0;"><span>표시 항목</span></div>' +
                    // select clause table component (DataGrid)
                    '<div id="selectClauseTable"></div>' +
                '</div>' +
                '<div class="column" style="height:40%; padding-bottom: 0;">' +
                    '<div class="modal-tit" style="height: 37px; margin-bottom: 0; border-bottom: 0 !important;">' +
                        '<span>조건 항목</span>' +
                    '</div>' +
					'<div style="height:50px;">' +
						'<span style="float:left;margin-top: 10px;margin-right: 10px;">조건식 변경</span>' +
						'<div id="logicArea" style="float:left"></div>' +
                        '<div class="right-item" style="float:left;margin-top: 10px;margin-left: 10px;">' +
                            '<a id="checkLogic" class="btn crud positive">조건식 점검</a>' +
                            '<a id="paramEditBtn" class="btn crud positive">매개변수 편집</a>' +
                        '</div>' +						
					'</div>' +
                    // where clause table component (DataGrid)
                    '<div id="whereClauseTable"></div>' +
                '</div>' +
                '<div class="column" style="height:30%; padding-bottom: 0;">' +
                	'<div id="relationOrderTabPanel"></div>' +
                '</div>' +
            '</div>'
        );

        self.components = {
            selectClauseTable: selectClauseTable(),
            whereClauseTable: whereClauseTable(),
			relationOrderTabPanel: relationOrderTabPanel(),
            relationClauseTable: relationClauseTable(),
            orderClauseTable: orderClauseTable(),
            paramEditBtn: paramEditBtn(),
			logicArea: logicArea(),
			checkLogic: checkLogic(),
        };

        addDropListeners();
        self.generateRelationList();
    };

    /**
     * If clause tables' data has been modified and not saved, save them.
     * Then, execute the callback function.
     * @
     */
    this.saveEditData = function(callback) {
        self.components.selectClauseTable.saveEditData().done(function() {
            self.components.whereClauseTable.saveEditData().done(function() {
                self.components.orderClauseTable.saveEditData().done(function() {
                    callback && callback();
                });
            });
        });
    }

    /**
     * Update "WHERE" clause table with updated parameter info.
     * @param {object[]} params
     */
    this.updateParamList = function(params) {
        // not needed right now
        // use this when you need to modify "WHERE" clause with updated param info
    }

    /**
     * Gather relations metadata from the database.
     */
    this.generateRelationList = function() {
        switch (self.state.dsType) {
            case 'CUBE':
                $.ajax({
                    method: 'POST',
                    url: WISE.Constants.context + '/report/getCubeConstraintList.do',
                    data: {
                        cubeId: self.state.cubeId,
                        dsViewId: self.state.dsViewId,
                    },
                    success: function(data) {
                        if (!data || data.length === 0) {
                            WISE.alert('데이터 원본 테이블이 관계가 없습니다.');
                        } else {
                            self.setState({ relations: data.data });
                            updateFromClauses(self.state.selectClauses);
                        }
                    }
                });
                break;
            default:
				var dsMap = [];
				dsMap.push(self.state.dsId);  
		        var selectMap = _.map(self.state.selectClauses, 'DATASET_SRC');
		        var whereMap = _.map(self.state.whereClauses, 'DATASET_SRC');
		        var orderMap = _.map(self.state.orderClauses, 'DATASET_SRC');
				var dsIds = _.uniq(dsMap.concat(selectMap.concat(whereMap.concat(orderMap))));
                $.ajax({
                    method: 'POST',
                    url: WISE.Constants.context + '/report/getMultiConstraintList.do',
                    data: {
                        dsid: dsIds.join(','),
                        dstype: self.state.dsType,
                        tableNm: ''
                    },
                    success: function(data) {
                        if (!data || data.length === 0) {
                            WISE.alert('데이터 원본 테이블이 관계가 없습니다.');
                        } else {
                            self.setState({ relations: data.data });
                        }
                    }
                });
        }
    }

	this.getUniqDsList = function() {
        var selectDsMap = _.map(self.state.selectClauses, 'DATASET_SRC');
        var whereDsMap = _.map(self.state.whereClauses, 'DATASET_SRC');
        var orderDsMap = _.map(self.state.orderClauses, 'DATASET_SRC');
		return _.uniq(selectDsMap.concat(whereDsMap.concat(orderDsMap)));
	}
	
	this.updateErdRelationList = function(newFromClauses) {
		self.state.fromClauses = [];
		newFromClauses = newFromClauses.concat(self.state.fromClauses);
		
		// Delete Duplication
		newFromClauses = newFromClauses.filter(function(arr, index, self){
			var findConstNm = _.findIndex(self,function(t){
				return t.PK_DATASET_SRC === arr.PK_DATASET_SRC 
					&& t.FK_DATASET_SRC === arr.FK_DATASET_SRC 
					&& t.PK_TBL_NM === arr.PK_TBL_NM 
					&& t.FK_TBL_NM === arr.FK_TBL_NM 
					&& t.PK_COL_NM === arr.PK_COL_NM 
					&& t.FK_COL_NM === arr.FK_COL_NM; 
			});
	    	return index === findConstNm;
		});

        if (newFromClauses.length>0) {
            self.components.relationClauseTable.option('dataSource', newFromClauses);
            self.setState({ fromClauses: newFromClauses });
            self.state.onFromClauseChange(self.state.fromClauses);
			generateQuery();
        }		
	}

    /**
     * Add a drop listener for table columns.
     */
    function addDropListeners() {
        // select clause table
        $('#selectClauseTable').droppable({
            drop: function(e, ui) {
                var data = ui.draggable.data('column');
                if (data && data.TYPE === 'COLUMN') {
                    // duplicate check
                    var duplicateMarker = '';
                    var colNames = _.map(self.state.selectClauses, 'COL_NM');
                    if (colNames.indexOf(data.COL_NM) !== -1) {
                        var dupCount = _.filter(colNames, function(col) { 
                            return col === data.COL_NM;
                        }).length;
                        duplicateMarker = '_' + (dupCount + 1);
                    }
                    // add new select clause to select table
                    var dataType = getDataType(data.DATA_TYPE);
                    var newSelectClause = {
                        UNI_NM: data.id,
                        AGG: dataType === 'decimal' ? 'Sum' : '',
                        COL_NM: data.COL_NM,
                        COL_CAPTION: data.text + duplicateMarker,
                        STRATIFIED_YN: false,
                        DATA_TYPE: dataType,
                        TBL_NM: data.TBL_NM,
                        TBL_CAPTION: data.TBL_CAPTION||data.TBL_NM,
                        TYPE: dataType === 'decimal' ? 'MEA' : 'DIM',
                        COL_EXPRESS: '',
                        ORDER: self.state.selectInc + 1,
						DATASET_SRC: data.dataset_src
                    };
                    var selectClauses = self.state.selectClauses.concat([newSelectClause]);
                    if (updateFromClauses(selectClauses)) {
                        self.setState({
                            selectClauses: selectClauses,
                            selectInc: self.state.selectInc + 1
                        });
                        self.state.onSelectClauseChange(self.state.selectClauses);
                        self.components.selectClauseTable.option('dataSource', self.state.selectClauses);
                        generateQuery();
                    }
                }
            }
        });
        // where clause table
        $('#whereClauseTable').droppable({
            drop: function(e, ui) {
                var data = ui.draggable.data('column');
                if (data && data.TYPE === 'COLUMN') {
                    // don't drop if column is not in "SELECT" clause table
                    var found = false;
                    for (var i = 0; i < self.state.selectClauses.length; i++) {
                        if (self.state.selectClauses[i].TBL_NM === data.TBL_NM 
                                && self.state.selectClauses[i].COL_NM === data.COL_NM) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                    	//테이블항목에 넣기
                    }
                    var dataType = getDataType(data.DATA_TYPE);
                    var newWhereClause = {
                        UNI_NM: data.id,
                        COND_ID: self.utility.getWhereClauseId(self.state.whereClauses),
                        COL_NM: data.COL_NM,
                        COL_CAPTION: data.text,
                        TBL_CAPTION: data.parent,
                        OPER: dataType === 'decimal' ? '=' : 'In',
                        VALUES: '전체',
                        VALUES_CAPTION: '',
                        DATA_BIND_YN: true,
                        AGG: dataType === 'decimal' ? 'Sum' : '',
                        TBL_NM: data.TBL_NM,
                        TBL_CAPTION: data.TBL_CAPTION||data.TBL_NM,
                        DATA_TYPE: dataType,
                        PARAM_YN: false,
                        PARAM_NM: '',
                        TYPE: dataType === 'decimal' ? 'MEA' : 'DIM',
                        COL_EXPRESS: '',
                        ORDER: self.state.whereInc + 1,
						DATASET_SRC: data.dataset_src
                    };
                    var whereClauses = self.state.whereClauses.concat([newWhereClause]);
                    if (updateFromClauses(whereClauses)) {
                        self.setState({
                            whereClauses: whereClauses,
                            whereInc: self.state.whereInc + 1
                        });
                        self.state.onWhereClauseChange(self.state.whereClauses);
                        self.components.whereClauseTable.option('dataSource', self.state.whereClauses);
                        generateQuery();
                    }
                }
            }
        });
        // order by clause table
        $('#orderClauseTable').droppable({
            drop: function(e, ui) {
                var data = ui.draggable.data('column');
                if (data && data.TYPE === 'COLUMN') {
                    // don't drop if column is not in "SELECT" clause table
                    var found = false;
                    for (var i = 0; i < self.state.selectClauses.length; i++) {
                        if (self.state.selectClauses[i].TBL_NM === data.TBL_NM 
                                && self.state.selectClauses[i].COL_NM === data.COL_NM) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                    	//테이블항목에 넣기
                    }
                    var dataType = getDataType(data.DATA_TYPE);
                    var newOrderClause = {
                        UNI_NM: data.id,
                        COL_NM: data.COL_NM,
                        COL_CAPTION: data.text,
                        SORT_TYPE: 'ASC',
                        TBL_NM: data.TBL_NM,
                        TBL_CAPTION: data.TBL_CAPTION||data.TBL_NM,
                        TYPE: dataType === 'decimal' ? 'MEA' : 'DIM',
                        ORDER: self.state.orderInc + 1,
						DATASET_SRC: data.dataset_src
                    };
                    var orderClauses = self.state.orderClauses.concat([newOrderClause]);
                    if (updateFromClauses(orderClauses)) {
                        self.setState({
                        	orderClauses: orderClauses,
                        	orderInc: self.state.orderInc + 1
                        });
                        self.state.onOrderClauseChange(self.state.orderClauses);
                        self.components.orderClauseTable.option('dataSource', self.state.orderClauses);
                        generateQuery();
                    }
                }
            }
        });
		// 조건식변경
		$('#logicArea').droppable({
			drop: function(e, ui) {
				var data = ui.draggable.data('column');
				self.components.logicArea.option('value', self.components.logicArea.option('value')+' ['+data.COND_ID+']');
			}
		});
    }

    /**
     * Generate and change "FROM" clauses state.
     * @param {object[]} clauses
     */
    function updateFromClauses(clauses) {
		// 단일 관계 정보 
		var paramDsMap = _.map(clauses, 'DATASET_SRC');
        var selectDsMap = _.map(self.state.selectClauses, 'DATASET_SRC');
        var whereDsMap = _.map(self.state.whereClauses, 'DATASET_SRC');
        var orderDsMap = _.map(self.state.orderClauses, 'DATASET_SRC');
		var dsIds = _.uniq(paramDsMap.concat(selectDsMap.concat(whereDsMap.concat(orderDsMap))));
        var newFromClauses = [];
		for(var i=0;i<dsIds.length;i++) {
			var dsId = dsIds[i];
	        var paramMap =  _.map(_.filter(clauses, function(d){
				return dsId == d.DATASET_SRC;
			}), 'TBL_NM');
	        var selectMap = _.map(_.filter(self.state.selectClauses, function(d){
				return dsId == d.DATASET_SRC;
			}), 'TBL_NM');
	        var whereMap = _.map(_.filter(self.state.whereClauses, function(d){
				return dsId == d.DATASET_SRC;
			}), 'TBL_NM');
	        var orderMap = _.map(_.filter(self.state.orderClauses, function(d){
				return dsId == d.DATASET_SRC;
			}), 'TBL_NM');
	        var tableNames = _.uniq(paramMap.concat(selectMap.concat(whereMap.concat(orderMap))));

			if(tableNames.length>1) {
		        for (var i = 0; i < tableNames.length; i++) {
					for (var j = 0; j < tableNames.length; j++) {
						if(i!=j) newFromClauses = newFromClauses.concat(findRelationTable(dsId, tableNames[i], tableNames[j]));
					}
		        }
			}
		}
		
		// 이기종 관계 정보
		var multiTblMap = [];
		$.each(clauses.concat(self.state.selectClauses.concat(self.state.whereClauses.concat(self.state.orderClauses))), function(i,d){
			multiTblMap.push({
				DATASET_SRC : d.DATASET_SRC,
				TBL_NM : d.TBL_NM 
			});
		});
		var diffFromClauses = [];
    	var fromClauses = [];
    	if(typeof self.state.fromClauses.CONST_NM != 'undefined') {
    		fromClauses.push(self.state.fromClauses);
    	} else {
    		fromClauses = self.state.fromClauses
    	}
		$.each(fromClauses, function(i, relation) {
			if (relation.FK_DATASET_SRC != relation.PK_DATASET_SRC) {
				var pkFlag = false;
				$.each(multiTblMap,function(j, multi){
					if(relation.PK_DATASET_SRC === multi.DATASET_SRC && relation.PK_TBL_NM === multi.TBL_NM) pkFlag = true; 
				});
				var fkFlag = false;
				$.each(multiTblMap,function(j, multi){
					if(relation.FK_DATASET_SRC === multi.DATASET_SRC && relation.FK_TBL_NM === multi.TBL_NM) fkFlag = true; 
				});
				if(pkFlag && fkFlag) diffFromClauses.push(relation);
			}
		});
		
		newFromClauses = newFromClauses.concat(diffFromClauses);
		/* dogfoot shlim erd FROM 절 저장 추가 20210201*/		
		newFromClauses = newFromClauses.concat(self.state.fromClauses)
		// Delete Duplication
		newFromClauses = newFromClauses.filter(function(arr, index, self){
			var findConstNm = _.findIndex(self,function(t){
				return t.PK_DATASET_SRC === arr.PK_DATASET_SRC 
					&& t.FK_DATASET_SRC === arr.FK_DATASET_SRC
					&& t.PK_TBL_NM === arr.PK_TBL_NM
					&& t.FK_TBL_NM === arr.FK_TBL_NM
					&& t.PK_COL_NM === arr.PK_COL_NM
					&& t.FK_COL_NM === arr.FK_COL_NM; 
			});
	    	return index === findConstNm;
		});

		if(newFromClauses.length>0) {
	        self.components.relationClauseTable.option('dataSource', newFromClauses);
	        self.setState({ fromClauses: newFromClauses });
	    	self.state.onFromClauseChange(self.state.fromClauses);
		}

        return true;
    }

	// Relation Table Recursion Function
	function findRelationTable(DS_ID, TBL_NM1, TBL_NM2) {
		var returnFromClauses = []; 
		$.each(self.state.relations, function(i, relation) {
			if (DS_ID === relation.DATASET_SRC && TBL_NM1 === relation.FK_TBL_NM && TBL_NM2 === relation.PK_TBL_NM) {
				returnFromClauses.push({
                    CONST_NM : relation.CONST_NM,
                    FK_TBL_NM : relation.FK_TBL_NM,
                    FK_COL_NM : relation.FK_COL_NM,
                    PK_TBL_NM : relation.PK_TBL_NM,
                    PK_COL_NM : relation.PK_COL_NM,
                    JOIN_TYPE : relation.JOIN_TYPE,
                    JOIN_SET_OWNER : relation.JOIN_SET_OWNER,
					FK_DATASET_SRC : relation.DATASET_SRC,
					PK_DATASET_SRC : relation.DATASET_SRC,
				});
			}
		});
	
		if(returnFromClauses.length==0) {
			return findSnowFlake2Depth(DS_ID, TBL_NM1, TBL_NM2);
		}
		return returnFromClauses;
	}
	
	function findSnowFlake2Depth(DS_ID, TBL_NM1, TBL_NM2) {
		var returnFromClauses = [];	
		$.each(self.state.relations, function(i, relation1) {
			if(DS_ID === relation1.DATASET_SRC && TBL_NM1 === relation1.FK_TBL_NM) {
				$.each(self.state.relations, function(j, relation2) {
					if(DS_ID === relation2.DATASET_SRC && relation1.PK_TBL_NM === relation2.FK_TBL_NM && TBL_NM2 === relation2.PK_TBL_NM) {
						returnFromClauses.push({
		                    CONST_NM : relation1.CONST_NM,
		                    FK_TBL_NM : relation1.FK_TBL_NM,
		                    FK_COL_NM : relation1.FK_COL_NM,
		                    PK_TBL_NM : relation1.PK_TBL_NM,
		                    PK_COL_NM : relation1.PK_COL_NM,
		                    JOIN_TYPE : relation1.JOIN_TYPE,
		                    JOIN_SET_OWNER : relation1.JOIN_SET_OWNER,
							FK_DATASET_SRC : relation1.DATASET_SRC,
							PK_DATASET_SRC : relation1.DATASET_SRC,
						});
						returnFromClauses.push({
		                    CONST_NM : relation2.CONST_NM,
		                    FK_TBL_NM : relation2.FK_TBL_NM,
		                    FK_COL_NM : relation2.FK_COL_NM,
		                    PK_TBL_NM : relation2.PK_TBL_NM,
		                    PK_COL_NM : relation2.PK_COL_NM,
		                    JOIN_TYPE : relation2.JOIN_TYPE,
		                    JOIN_SET_OWNER : relation2.JOIN_SET_OWNER,
							FK_DATASET_SRC : relation2.DATASET_SRC,
							PK_DATASET_SRC : relation2.DATASET_SRC,
						});
					}
				});
			}
		});
		return returnFromClauses;
	}

    /**
     * Generate a query string using select, from, where, and order by clauses.
     */
    function generateQuery() {
        // exit if there is no select clause
        if (self.state.selectClauses.length === 0 && self.state.whereClauses.length === 0 && self.state.orderClauses.length === 0) {
            return;
        }
        var result = '';
        var tableSet = [];
        var groupBySet = [];
        // generate "SELECT" query string
        self.state.selectClauses.forEach(function(sel, i) {
            var selectPrefix = i === 0 ? 'SELECT      ' : '            ';
            var selectSuffix = (i < self.state.selectClauses.length - 1) ? ',\n' : '\n';
            switch (sel.TYPE) {
                case 'MEA':
                    result += selectPrefix + sel.AGG + '(' + sel.TBL_NM + '.' + sel.COL_NM + ') AS ' + sel.COL_CAPTION + selectSuffix;
                    break;
                default: 
                    result += selectPrefix + sel.TBL_NM + '.' + sel.COL_NM + ' AS ' + sel.COL_CAPTION + selectSuffix;
                    groupBySet.push(sel.TBL_NM + '.' + sel.COL_NM);
            }
        });
        if(self.state.selectClauses.length === 0) result += 'SELECT * \n';
        // generate "FROM" query string
        if (self.state.fromClauses.length > 0) {
            self.state.fromClauses.forEach(function(from, i) {
                if (i === 0) {
                    result += 'FROM        ' + from.FK_TBL_NM + '\n            ' + from.JOIN_TYPE + ' ' + from.PK_TBL_NM + 
                        ' ON ' + from.FK_TBL_NM + '.' + from.FK_COL_NM + ' = ' + from.PK_TBL_NM + '.' + from.PK_COL_NM + '\n';
                    tableSet.push(from.FK_TBL_NM);
                    tableSet.push(from.PK_TBL_NM);
                } else {
                    var tblNm = (tableSet.indexOf(from.PK_TBL_NM) !== -1) ? from.FK_TBL_NM : from.PK_TBL_NM;
                    result += '            ' + from.JOIN_TYPE + ' ' + tblNm + 
                        ' ON ' + from.FK_TBL_NM + '.' + from.FK_COL_NM + ' = ' + from.PK_TBL_NM + '.' + from.PK_COL_NM + '\n';
                    tableSet.push(tblNm);
                }
            });
        } else {
        	var tblNm = '';
        	if(self.state.orderClauses.length > 0) tblNm = self.state.orderClauses[0].TBL_NM; 
        	if(self.state.whereClauses.length > 0) tblNm = self.state.whereClauses[0].TBL_NM; 
        	if(self.state.selectClauses.length > 0) tblNm = self.state.selectClauses[0].TBL_NM;
            result += 'FROM        ' + tblNm + '\n';
            tableSet.push(tblNm);
        }
        // generate "WHERE" query string
        var firstWhere = true;
		var keepFlag = false;
		var logicAreaVal = self.components.logicArea.option('value');
		var nonWhereClauses = [];
        self.state.whereClauses.forEach(function(where, i) {
			if(logicAreaVal.indexOf('['+where.COND_ID+']')>-1) {
                var whereName = where.TBL_NM + '.' + where.COL_NM;
                var whereValue = where.PARAM_NM;
                if (!where.PARAM_YN) {
                    if(where.VALUES==='전체') {
                    	whereValue = where.TBL_NM + '.' + where.COL_NM;
                    } else {
	                    whereValue = _.map(
	                        where.VALUES.replace(/[\[\]]/g, '').split(','), 
	                        function(v) {
	                            if (where.TYPE === 'MEA') {
	                                return parseInt(v.trim());
	                            } else {
	                                return "'" + v.trim() + "'";
	                            }
	                        }
	                    );
                    }
                }
                if (where.OPER === 'In') {
                    whereValue = '(' + whereValue + ')';
                }
                var changePrefix = whereName + ' ' + where.OPER.toUpperCase() + ' ' + whereValue;
				logicAreaVal = logicAreaVal.replace('['+where.COND_ID+']', changePrefix); 
				firstWhere = false;
				keepFlag = true;
			} else {
				nonWhereClauses.push(where);
			}
		});
		if(keepFlag) {
			result += 'WHERE       ' + logicAreaVal + ' ';
		}
		
        nonWhereClauses.forEach(function(where, i) {
            if (where.AGG === '') {
                var wherePrefix = firstWhere ? 'WHERE       ' : '            AND ';
                var whereName = where.TBL_NM + '.' + where.COL_NM;
                var whereValue = where.PARAM_NM;
                if (!where.PARAM_YN) {
                    if(where.VALUES==='전체') {
                    	whereValue = where.TBL_NM + '.' + where.COL_NM;
                    } else {
	                    whereValue = _.map(
	                        where.VALUES.replace(/[\[\]]/g, '').split(','), 
	                        function(v) {
	                            if (where.TYPE === 'MEA') {
	                                return parseInt(v.trim());
	                            } else {
	                                return "'" + v.trim() + "'";
	                            }
	                        }
	                    );
                    }
                }
                if (where.OPER === 'In') {
                    whereValue = '(' + whereValue + ')';
                }
                result += wherePrefix + whereName + ' ' + where.OPER.toUpperCase() + ' ' + whereValue + '\n';
                firstWhere = false;
            }
        });
        // generate "GROUP BY" query string
        if (groupBySet.length > 0) {
            result += 'GROUP BY    ' + groupBySet.join(',\n            ') + '\n';
        }
        // generate "HAVING" query string
        var firstHaving = true;
        nonWhereClauses.forEach(function(where, i) {
            if (where.AGG !== '') {
                var wherePrefix = firstHaving ? 'HAVING      ' : '            AND ';
                var whereName = where.AGG + '(' + where.TBL_NM + '.' + where.COL_NM + ')';
                var whereValue = where.PARAM_NM;
                if (!where.PARAM_YN) {
                    if(where.VALUES==='전체') {
                    	whereValue = where.TBL_NM + '.' + where.COL_NM;
                    } else {
	                    whereValue = _.map(
	                        where.VALUES.replace(/[\[\]]/g, '').split(','), 
	                        function(v) { return parseInt(v.trim()); }
	                    );
                    }
                }
                if (where.OPER === 'In') {
                    whereValue = '(' + whereValue + ')';
                }
                result += wherePrefix + whereName + ' ' + where.OPER + ' ' + whereValue + '\n';
                firstHaving = false;
            }
        });
        // generate "ORDER BY" query string
        self.state.orderClauses.forEach(function(order, i) {
            var orderPrefix = i === 0 ? 'ORDER BY    ' : '            ';
            var orderSuffix = (i < self.state.orderClauses.length - 1) ? ',\n' : '\n';
            result += orderPrefix += order.TBL_NM + '.' + order.COL_NM + ' ' + order.SORT_TYPE + orderSuffix;
        });
        // send generated query string to dataset designer via callback
        self.state.onQueryChange(result);
    }

    /**
     * Return "decimal" if the data type is numeric. Otherwise, return "varchar".
     * @param {string} type 
     */
    function getDataType(type) {
        switch (type.toUpperCase()) {
            case 'NUMBER':
            case 'INT':
            case 'INTEGER':
            case 'DECIMAL':
            case 'FLOAT':
            case 'DOUBLE':
            case 'BIGINT':
			case 'NUMERIC':
                return 'decimal';
            default:
                return 'varchar';
        }
    }

    /**
     * select clause table component
     */
    function selectClauseTable() {
        return $('#selectClauseTable').dxDataGrid({
            height: 'calc(100% - 37px)',
            width: '100%',
            columnAutoWidth: true,
            noDataText: '',
            dataSource: self.state.selectClauses,
			editing: {
	            mode: 'cell',
                allowUpdating: true,
                allowDeleting: true,
	            texts: {
	                confirmDeleteMessage: ''
                },
                useIcons: true,
            },
            onRowUpdated: function(e) {
                var selectClauses = e.component.getDataSource().items();
                self.setState({ selectClauses: selectClauses });
                self.state.onSelectClauseChange(selectClauses);
                generateQuery();
            },
            onRowRemoved: function(e) {
                var selectClauses = e.component.getDataSource().items();
                self.setState({ selectClauses: selectClauses });
                self.state.onSelectClauseChange(selectClauses);
                updateFromClauses(selectClauses);
                generateQuery();
            },
			columns:[{
                caption: '집계',
                dataField: 'AGG',
                lookup: {
                    dataSource: ['', 'Sum', 'Avg', 'Count', 'Distinct Count', 'Max', 'Min']
                }
            }, {
                caption: '컬럼 물리명',
                dataField: 'COL_NM',
                allowEditing: false,
            }, {
                caption: 'Alias',
                dataField: 'COL_CAPTION',
                allowEditing: true,
            }, {
                caption: '데이터 유형',
                dataField: 'DATA_TYPE',
                allowEditing: false,
            }, {
                caption: '테이블 물리명',
                dataField: 'TBL_NM',
                allowEditing: false,
                visible: false,
            }, {
                caption: '테이블 논리명',
                dataField: 'TBL_CAPTION',
                allowEditing: false,
            }, {
                caption: '유형',
                dataField: 'TYPE',
                lookup:{
                    dataSource: [{
                        caption: '측정값',
                        value: 'MEA'
                    },{
                        caption: '차원',
                        value: 'DIM'
                    }],
                    displayExpr: 'caption',
                    valueExpr: 'value',
                }
            }],
		}).dxDataGrid('instance');
    }

	//조건절팝업
    function whereValuePopOver(cellInfo) {
		$('body').append('<div id="param_popup"></div>')
        $("#param_popup").dxPopup({
            showCloseButton: false,
            showTitle: true,
            visible: true,
            title: "컬럼 값 선택",
            closeOnOutsideClick: false,
			position: {
		         my: 'center',  
		         at: 'center',  
		         of: 'body'  
		    },
	        contentTemplate: function() {
                return $(
                    '<div class="modal-inner scrollbar">' + 
                        '<div class="modal-body">' + 
                            '<div class="row">' +
                                '<div class="column" style="height: 679px;">' +
                                    '<div class="modal-article">' + 
                                        '<div id="param_list" class="param_list" style="float:left; margin-right:20px;"></div>' +
                                    '</div>' + 
                                '</div>' + 
                            '</div>' + 
                        '</div>' + 
                        '<div class="modal-footer">' + 
                            '<div class="row center">' + 
                                '<a id="btn_param_check" href="#" class="btn positive ok-hide">확인</a>' + 
                                '<a id="btn_param_cancel" href="#" class="btn neutral close">취소</a>' + 
                            '</div>' + 
                        '</div>' + 
                    '</div>'
                );
            },
            onContentReady: function(){
            	gDashboard.fontManager.setFontConfigForListPopup('param_popup');
			},
            width: '90vw',
            height: '88vh',
            maxWidth: 600,
            maxHeight: 850,
            onShown: function(){
				var dsArr = [];
				if(cellInfo.data.DATA_BIND_YN) {
	                $.ajax({
						url: WISE.Constants.context + '/report/getConditionValues.do',
						method: 'POST',
						async: false,
						data: { 
							dsid: self.state.dsId,
							dstype: self.state.dsType,
							tblNm: cellInfo.data.TBL_NM,
							colNm: cellInfo.data.COL_NM
						},
	                    success: function(json) {
			                $.each(json.data,function(i,d){
								dsArr.push({val: d[cellInfo.data.COL_NM]});
							});
	                    }
	                });
				}

                $("#param_list").dxDataGrid({
		            height: 'calc(100% - 37px)',
		            width: '100%',
					height: 650,
		            noDataText: '',
		            dataSource: dsArr,
					columns:[{
		                caption: '컬럼 Caption 값',
		                dataField: 'val',
		            }],
		            showBorders: true,
					searchPanel: {
						visible: true,
						width: 518,
					},
					selection: {
						mode: "multiple"
					},			
					paging: {
						enabled: false
					},
					onContentReady: function(e) {
						if(cellInfo.value==='전체') {
							e.component.selectAll();
						} else {
							var valArr = cellInfo.value.split(',');
							var setVal = [];
							$.each(valArr,function(i,d){
								setVal.push({val: d});
							});
							e.component.selectRows(setVal, true);
						}
					}
		        }).dxDataGrid('instance');

                $("#btn_param_check").dxButton({
                    text: "확인",
                    type: "normal",
                    onClick: function(e) {
						var totalCnt = $("#param_list").dxDataGrid('instance').totalCount();
						var valArr = $("#param_list").dxDataGrid('instance').getSelectedRowsData();
						var setVal = ''; 
						if(valArr.length === totalCnt) {
							setVal = '전체';
						} else {
							$.each(valArr,function(i,d){
								setVal += (i==0)?d.val:','+d.val;
							});
						}
						cellInfo.setValue(setVal);
						self.components.whereClauseTable.refresh();
						$("#param_popup").remove();
                    }
                });

                $("#btn_param_cancel").dxButton({
                    text: "취소",
                    type: "normal",
                    onClick: function(e) {
						$("#param_popup").remove();
                    },
                });
            }
        });
	}
	
    /**
     * where clause table component
     */
    function whereClauseTable() {
     	/* DOGFOOT ktkang 아이템이 1개일때 array로 변경  20200717 */
    	var whereClauses = [];
    	if(typeof self.state.whereClauses.COL_NM != 'undefined') {
    		whereClauses.push(self.state.whereClauses);
    	} else {
    		whereClauses = self.state.whereClauses
    	}
        return $('#whereClauseTable').dxDataGrid({
            height: 'calc(100% - 87px)',
            width: '100%',
            columnAutoWidth: true,
            noDataText: '',
            keyExpr: 'COL_NM',
            dataSource: whereClauses,
			editing: {
	            mode: 'cell',
                allowUpdating: true,
                allowDeleting: true,
	            texts: {
	                confirmDeleteMessage: ''
                },
                useIcons: true,
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
						start: function(_event, _ui) {
							$(_ui.helper).text($($(_ui.helper.prevObject[0]).children()[1]).text());
							$(_ui.helper).css('background-color','#337AB7');
							$(_ui.helper).css('color','#ffffff');
							$(_ui.helper).css('font-size','15px');
							$(_ui.helper).css('width','250px');
							$(_ui.helper).css('height','22px');
							$(_ui.helper).css('vertical-align','middle');
							//$(_ui.helper).css('left', window.event.screenX);
						}
                    });
            },
            onRowUpdated: function(e) {
                var whereClauses = e.component.getDataSource().items();
                // update params state
                var row = {};
                for (var i = 0; i < whereClauses.length; i++) {
                    if (whereClauses[i].COL_NM === e.key) {
                        row = whereClauses[i];
                    }
                }
                if (typeof e.data.PARAM_YN !== 'undefined') {
                    if (e.data.PARAM_YN) {
                        if (row.PARAM_NM === '') {
                            row.PARAM_NM = '@' + row.COND_ID;
                        }
                        self.state.onTableParamChange(row);

                    } else {
                        self.state.onParamDelete([row.PARAM_NM]);
                    }
                } else if (typeof e.data.OPER !== 'undefined') {
                    self.state.onTableParamChange(row);
                }
                // update "WHERE" clause state
                self.setState({ whereClauses: whereClauses });
                self.state.onWhereClauseChange(whereClauses);
                generateQuery();
            },
            onRowRemoved: function(e) {
                self.state.onParamDelete([e.data.PARAM_NM]);
                var whereClauses = e.component.getDataSource().items();
                self.setState({ whereClauses: whereClauses });
                self.state.onWhereClauseChange(whereClauses);
				updateFromClauses(whereClauses);
                generateQuery();
            },
			columns:[{
                caption: '조건 ID',
                dataField: 'COND_ID',
                allowEditing: false,
            }, {
                caption: '컬럼 물리명',
                dataField: 'COL_NM',
                allowEditing: false,
                visible: false,
            }, {
                caption: '컬럼 논리명',
                dataField: 'COL_CAPTION',
                allowEditing: false,
            }, {
                caption: '테이블 물리명',
                dataField: 'TBL_NM',
                allowEditing: false,
                visible: false,
            }, {
                caption: '테이블 논리명',
                dataField: 'TBL_CAPTION',
                allowEditing: false,
            }, {
                caption: '조건',
                dataField: 'OPER',
                width: 100,
                lookup: {
                    dataSource: ['In', 'Between', 'Equals', '=', '>', '>=', '<', '<=', '<>'],
                }
            }, {
                caption: '조건 값',
                dataField: 'VALUES',
	            editCellTemplate: function(cellElement, cellInfo) {
					var divEle = $("<div />");
	                $("<span />").dxTextBox({
				        elementAttr: {
				            style: "float: left;"
				        },
						readonly: true,
						text: cellInfo.value,
	                    width: 'calc(100% - 30px)',
	                }).appendTo(divEle);
	                $("<span />").dxButton({
				        elementAttr: {
				            id: "dsCondition",
							style: "margin-top: 2px;",
				        },
						text: '…',
	                    width: 30,
						height: 30,
						onClick: function(e) {
							whereValuePopOver(cellInfo);	
						},
	                }).appendTo(divEle);
					divEle.appendTo(cellElement);
	            },
            }, {
                caption: '조회',
                dataField: 'DATA_BIND_YN',
                alignment: 'center',
                dataType: 'boolean',
				width: 50,
            }, {
                caption: '집계',
                dataField: 'AGG',
                width: 120,
                lookup:{
                    dataSource: ['', 'Sum', 'Avg', 'Count', 'Distinct Count', 'Max', 'Min'],
                }       
            }, {
                caption: '매개변수',
                dataField: 'PARAM_YN',
                alignment: 'center',
                dataType: 'boolean',
				width: 80,
            }, {
                caption: '유형',
                dataField: 'TYPE',
                lookup:{
                    dataSource: [{
                        caption: '측정값',
                        value: 'MEA'
                    },{
                        caption: '차원',
                        value: 'DIM'
                    }],
                    displayExpr: "caption",
                    valueExpr: "value"
                }
            }]
        }).dxDataGrid('instance');
    }
    
    /**
     * relation by clause table component
     */
    function relationClauseTable() {
    	/* DOGFOOT ktkang 아이템이 1개일때 array로 변경  20200717 */
    	var fromClauses = [];
    	if(typeof self.state.fromClauses.CONST_NM != 'undefined') {
    		fromClauses.push(self.state.fromClauses);
    	} else {
    		fromClauses = self.state.fromClauses
    	}
        return $('#relationClauseTable').dxDataGrid({
            height: '100%',
            width: '100%',
            columnAutoWidth: true,
            noDataText: '',
            dataSource: fromClauses,
			editing: {
	            mode: 'cell',
                allowUpdating: true,
	            texts: {
	                confirmDeleteMessage: ''
                },
                useIcons: true,
            },
            onRowUpdated: function(e) {
                var relationClauses = e.component.getDataSource().items();
                self.setState({ fromClauses: relationClauses });
                self.state.onFromClauseChange(self.state.fromClauses);                
                generateQuery();
            },
            columnAutoWidth: true,
            columns:[{
                caption: '원본 테이블',
                dataField: 'PK_TBL_NM',
                allowEditing: false,
            },{
                caption: '원본 컬럼',
                dataField: 'PK_COL_NM',
                allowEditing: false,
            },{
                caption: '대상 테이블',
                dataField: 'FK_TBL_NM',
                allowEditing: false,
            },{
                caption: '대상 컬럼',
                dataField: 'FK_COL_NM',
                allowEditing: false,
            },{
                caption: '연결 유형',
                dataField: 'JOIN_TYPE',
                lookup:{
                    dataSource: [{
                    	caption: 'INNER JOIN',
                    	value: 'INNER JOIN'
                    },{
                    	caption: 'OUTER JOIN',
                    	value: 'FULL OUTER JOIN'
                    },{
                    	caption: 'LEFT JOIN',
                    	value: 'LEFT JOIN'
                    },{
                    	caption: 'RIGHT JOIN',
                    	value: 'RIGHT JOIN'
                    }],
                    displayExpr: "caption",
                    valueExpr: "value"
                }
            },{
                caption: '외래키명',
                dataField: 'CONST_NM',
                allowEditing: false,
                visible: false,
            },{
                caption: '연결 유형 소유자',
                dataField: 'JOIN_SET_OWNER',
                allowEditing: false,
                visible: false,
            },{
                caption: '원본 데이터 소스 ID',
                dataField: 'PK_DATASET_SRC',
                allowEditing: false,
                visible: false,
            },{
                caption: '대상 데이터 소스 ID',
                dataField: 'FK_DATASET_SRC',
                allowEditing: false,
                visible: false,
            }],
        }).dxDataGrid('instance');
    }

    /**
     * order by clause table component
     */
    function orderClauseTable() {
    	/* DOGFOOT ktkang 아이템이 1개일때 array로 변경  20200717 */
    	var orderClauses = [];
    	if(typeof self.state.orderClauses.COL_NM != 'undefined') {
    		orderClauses.push(self.state.orderClauses);
    	} else {
    		orderClauses = self.state.orderClauses
    	}
        return $('#orderClauseTable').dxDataGrid({
            height: '100%',
            width: '100%',
            columnAutoWidth: true,
            noDataText: '',
            dataSource: orderClauses,
			editing: {
	            mode: 'cell',
                allowUpdating: true,
                allowDeleting: true,
	            texts: {
	                confirmDeleteMessage: ''
                },
                useIcons: true,
            },
            onRowUpdated: function(e) {
                var orderClauses = e.component.getDataSource().items();
                self.setState({ orderClauses: orderClauses });
                self.state.onOrderClauseChange(orderClauses);
                generateQuery();
            },
            onRowRemoved: function(e) {
                var orderClauses = e.component.getDataSource().items();
                self.setState({ orderClauses: orderClauses });
                self.state.onOrderClauseChange(orderClauses);
				updateFromClauses(orderClauses);
                generateQuery();
            },
            columnAutoWidth: true,
            columns:[{
                caption: '테이블 논리명',
                dataField: 'TBL_CAPTION',
                allowEditing: false,
            },{
                caption: '테이블 물리명',
                dataField: 'TBL_NM',
                allowEditing: false,
                visible: false,
            },{
                caption: '컬럼 논리명',
                dataField: 'COL_CAPTION',
                allowEditing: false,
            },{
                caption: '컬럼 물리명',
                dataField: 'COL_NM',
                allowEditing: false,
                visible: false,
            },{
                caption: '정렬',
                dataField: 'SORT_TYPE',
                lookup:{
                    dataSource: ['ASC', 'DESC'],
                }
            },{
                caption: '유형',
                dataField: 'TYPE',
                lookup:{
                    dataSource: [{
                        caption: '측정값',
                        value: 'MEA'
                    },{
                        caption: '차원',
                        value: 'DIM'
                    }],
                    displayExpr: "caption",
                    valueExpr: "value"
                },                
                allowEditing: false,
            }],
        }).dxDataGrid('instance');
    }

    /**
     * param edit button component (button)
     */
    function paramEditBtn() {
        return $('#paramEditBtn').dxButton({
            type: 'normal',
            onClick: function() {
                self.saveEditData(self.state.onParamEdit);
            }
        }).dxButton('instance');
    }

	function logicArea() {
		return $('#logicArea').dxTextArea({
			width: '60%',
			height: 40,
			value: self.state.changeCond,
			onValueChanged: function(e) {
		        self.setState({
                	changeCond: e.value
                });
				self.state.onCondChange(e.value);
				generateQuery();
			},
			onChange: function(e) {
		        self.setState({
                	changeCond: e.value
                });
				self.state.onCondChange(e.value);
				generateQuery();
			},
		}).dxTextArea('instance');
	}

	function checkLogic() {		
		return $('#checkLogic').dxButton({
			onClick:function(){
				var logic = self.components.logicArea.option('value');
				var conditionList = self.components.whereClauseTable.option('dataSource');
				var logicBoolean = true;
				$.each(conditionList,function(_i,_list){
					if(logic.indexOf("["+_list.COND_ID+"]") == -1){
						logicBoolean = false;
						return false;
					}
				});
				
				if(logicBoolean){
					WISE.alert("누락된 조건식이 없습니다.");
				}else{
					WISE.alert("사용되지 않은 조건식이 있습니다.<br>조건식을 다시 확인하세요.",'error');
				}
				
			}
		}).dxButton('instance');
	}
	
	function relationOrderTabPanel() {	
        return $('#relationOrderTabPanel').dxTabPanel({
            height: '100%',
            selectedIndex: 0,
            loop: false,
            animationEnabled: false,
            swipeEnabled: false,
            deferRendering: false,
            dataSource: [{
                title: '연결정보',
            }, {
                title: '정렬',
            }],
            itemTemplate: function(item) {
                switch (item.title) {
                    case '연결정보':
                        return $(
                            '<div style="height: 100%;">' +
                                '<div id="relationClauseTable" style="height: 100%; width: 100%;"></div>' + 
                            '</div>'
                        );
                    case '정렬':
                        return $(
                            '<div style="height: 100%;">' +
                            	'<div id="orderClauseTable" style="height: 100%; width: 100%;"></div>' + 
                            '</div>'
                        );
                    default:
                        return $('<p>').text('No template specified.');
                }
            },
        }).dxTabPanel('instance');
	}
}
