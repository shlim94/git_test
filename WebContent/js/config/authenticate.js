var authenticationManager = (function() {
	/* private variables and functions */
	var Auth_Cubes, Auth_Dim, Auth_Mem;

	function toArray(_o) {
		if (_o) {
			return $.type(_o) === 'array' ? _o : [_o];
		} else {
			return [];
		}
	}

	function getAllSelectedNodes(treeListInstance, parentKeys, skipParent) {
		var result = [];

		parentKeys.forEach(function(key) {
			var insertIndex = result.length,
				node = treeListInstance.getNodeByKey(key),
				parentNode = node.parent,
				childKeys = node.children.map(function(child) {
					return child.key;
				});

			while(parentNode.level >= 0 && !skipParent) {
				if(result.filter(function(nodeItem) { return nodeItem.key === parentNode.key }).length === 0 && treeListInstance.isRowSelected(parentNode.key)) {
					result.splice(insertIndex, 0, parentNode);
					parentNode = parentNode.parent;
				} else {
					break;
				}
			}

			result.push(node);
			/* DOGFOOT ktkang 주제영역 권한 저장 오류 수정  20200811 */
			var result2 = getAllSelectedNodes(treeListInstance, childKeys, true);
			if(result2.length != 0) {
				result = result.concat(result2);
			}
		});

		return result;
	};

	/**
	 * Initialize functions for user dataset authentication page.
	 */
	function initAuthUserData() {
		$.ajax({
			url : './getAuthUserDataList.do',
			async: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);

				$('#userDataSelectTable').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField: "사용자NO",
							visible:false
						},
						{
							dataField: "사용자ID",
						},
						{
							dataField: "사용자명",
						},
						{
							dataField: "그룹명",
						}
					],
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					dataSource:_data.userArrayList,
					selection: {
						mode: "single",
					},
					keyExpr:"사용자NO",
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('userDataSelectTable');
						gProgressbar.hide();
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userdata') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick:function(_e){
						var param = {};
						param['userNo'] = _e.data["사용자NO"];
						$.ajax({
							url:'./getUserDSViewAuth.do',
							data:param,
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							success:function(_authDSdata){
								_authDSdata = JSON.parse(_authDSdata);
	//							renderDSList(_authDSdata);
								if(_authDSdata.dsViewResult.length != 0){
									if(typeof _authDSdata.dsViewResult[0] != 'undefined'){
										Auth_Cubes = toArray(_authDSdata.dsViewResult[0].DataJson.NewDataSet.Auth_Cubes);
										Auth_Dim = toArray(_authDSdata.dsViewResult[0].DataJson.NewDataSet.Auth_Dim);
										Auth_Mem = toArray(_authDSdata.dsViewResult[0].DataJson.NewDataSet.Auth_Mem);
									}
									else if(_e.data["사용자NO"] != _authDSdata.dsViewResult[0].userId){
										Auth_Cubes = [];
										Auth_Dim = [];
										Auth_Mem = [];
									}
									var DsListDataSource = $('#userDsList').dxDataGrid('getDataSource')._items;
									// AUTH_YN 확인
									$.each(DsListDataSource,function(_i,_items){
										_items.AUTH_YN = '';
										var isAuth = false;
										// 주제 영역
										$.each(toArray(Auth_Cubes),function(_i,_cubes){
											if(_items.DS_VIEW_ID === _cubes.DS_VIEW_ID.toString()){
												_items.AUTH_YN = 'Y';
												isAuth = true;
												return false;
											}
										});
										if (isAuth) return;
										// 차원
										$.each(toArray(Auth_Dim),function(_i,_dim){
											if(_items.DS_VIEW_ID === _dim.DS_VIEW_ID.toString()){
												_items.AUTH_YN = 'Y';
												isAuth = true;
												return false;
											}
										});
										if (isAuth) return;
										// 멤버
										$.each(toArray(Auth_Mem),function(_i,_mem){
											if(_items.DS_VIEW_ID === _mem.DS_VIEW_ID.toString()){
												_items.AUTH_YN = 'Y';
												return false;
											}
										});
									});
									$('#userDsList').dxDataGrid('instance').option('dataSource',DsListDataSource);
									$('#userDsList').dxDataGrid('repaint');
								}else{
									var DsListDataSource = $('#userDsList').dxDataGrid('getDataSource')._items;
									$.each(DsListDataSource,function(_i,_items){
										_items.AUTH_YN = '';
									});
									$('#userDsList').dxDataGrid('instance').option('dataSource',DsListDataSource);
									$('#userDsList').dxDataGrid('repaint');
								}
								
							}
						});
						$('#userDsViewArea').dxTreeList('instance').option('dataSource','');
						$('#userDsDimensionArea').dxTreeList('instance').option('dataSource','');
						$('#userMemberArea').dxTreeList('instance').option('dataSource','');
					}
				});
				$('#userDsList').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField:"DS_VIEW_ID",
							visible:false
						},
						{
							dataField:"DS_VIEW_NM",
							caption:"데이터 원본 뷰 명"
						},
						{
							dataField:"DS_NM",
							caption:"데이터 원본 명",
							sortOrder: 'asc'
						},
						{
							dataField:"DBMS_TYPE",
							caption:"DB 유형"
						},
						{
							dataField:"OWNER_NM",
							caption:"소유자"
						},
						{
							dataField:"IP",
							caption:"서버 주소(명)"
						},
						{
							dataField:"DS_NM",
							caption:"DB 명"
						},
					],
					showColumnLines: true,
					columnAutoWidth: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					dataSource:_data.DSViewArrayList,
					paging:{
						enabled:false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('userDsList')
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userdata') {
								e.component.updateDimensions();
							}
						});
					},
					keyExpr:"DS_VIEW_ID",
					selection: {
						mode: "single",
					},
					onRowClick:function(_e){
						var authParam = {};
						authParam['userNo'] = $('#userDataSelectTable').dxDataGrid('getSelectedRowKeys')[0];
						$.ajax({
							url:'./getUserDSViewAuth.do',
							data:authParam,
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							success:function(_authDSdata){
								_authDSdata = JSON.parse(_authDSdata);
								if(_authDSdata.dsViewResult[0] != undefined){
									var DsInformationParam = {};
									DsInformationParam['userNo'] = $('#userDataSelectTable').dxDataGrid('getSelectedRowKeys')[0];
									DsInformationParam['dsViewId'] = _e.key;
									
									$.ajax({
										url:'./getDsInformation.do',
										data:DsInformationParam,
										contentType: "application/x-www-form-urlencoded; charset=UTF-8",
										success:function(_data){
											_data = JSON.parse(_data);
											$('#userDsViewArea').dxTreeList('instance').option('dataSource',_data.cubeArray);
											$('#userDsViewArea').dxTreeList('repaint');
											$('#userDsDimensionArea').dxTreeList('instance').option('dataSource',_data.DSViewDimArray);
											$('#userDsDimensionArea').dxTreeList('repaint');
											var memberTableArray = [];
											var memberKeyCol = [];
											
											$.each(_data.DSViewHieArray,function(_i,_arr){
												if(_arr.KEY_COL != '멤버' && _arr.IS_AUTH == 1){
													memberKeyCol.push(_arr.DIM_UNI_NM.replace(/[[\]]/g,''));
													memberTableArray.push(_arr);
												}
											});
											var DsViewData = ($('#userDsList').dxDataGrid('getSelectedRowsData'))[0];
											var params = {
												'DS_VIEW_ID': DsViewData.DS_VIEW_ID,
												'IP': DsViewData.IP,
												'DS_NM': DsViewData.DS_NM,
												'DB_NM' : DsViewData.DB_NM,
												'DBMS_TYPE': DsViewData.DBMS_TYPE,
												'OWNER_NM': DsViewData.OWNER_NM,
												'PASSWD': DsViewData.PASSWD,
												'PORT': DsViewData.PORT,
												'USER_ID': DsViewData.USER_ID,
												'data': btoa(unescape(encodeURIComponent(JSON.stringify(memberTableArray)))),
												'CONN_TYPE': DsViewData.CONN_TYPE
											};
											$.ajax({
												type: "POST",
												url:'./getMemberDataList.do',
												data:params,
												success:function(_data){
													_data = JSON.parse(_data);
													var result = [];
													$.each(_data.dataResult, function(i, member) {
														result = result.concat(member);
													});
													$('#userMemberArea').dxTreeList('instance').option('dataSource', result);
													$('#userMemberArea').dxTreeList('repaint');
												}
											});
											
										}
									});
								}else{
									var DsInformationParam = {};
									Auth_Cubes = [];
									Auth_Dim = [];
									Auth_Mem = [];
									DsInformationParam['userNo'] = $('#userDataSelectTable').dxDataGrid('getSelectedRowKeys')[0];
									DsInformationParam['dsViewId'] = _e.key;
									$.ajax({
										url:'./getDsInformation.do',
										data:DsInformationParam,
										contentType: "application/x-www-form-urlencoded; charset=UTF-8",
										success:function(_data){
											_data = JSON.parse(_data);
											$('#userDsViewArea').dxTreeList('instance').option('dataSource',_data.cubeArray);
											$('#userDsViewArea').dxTreeList('repaint');
											$('#userDsDimensionArea').dxTreeList('instance').option('dataSource',_data.DSViewDimArray);
											$('#uesrDsDimensionArea').dxTreeList('repaint');
											
											var memberTableArray = [];
											var memberKeyCol = [];
											
											$.each(_data.DSViewHieArray,function(_i,_arr){
												if(_arr.KEY_COL != '멤버' && _arr.IS_AUTH == 1){
													memberKeyCol.push(_arr.DIM_UNI_NM.replace(/[[\]]/g,''));
													memberTableArray.push(_arr);
												}
											});
											var DsViewData = ($('#userDsList').dxDataGrid('getSelectedRowsData'))[0];
											var params = {
												'DS_VIEW_ID': DsViewData.DS_VIEW_ID,
												'IP': DsViewData.IP,
												'DS_NM': DsViewData.DS_NM,
												'DB_NM' : DsViewData.DB_NM,
												'DBMS_TYPE': DsViewData.DBMS_TYPE,
												'OWNER_NM': DsViewData.OWNER_NM,
												'PASSWD': DsViewData.PASSWD,
												'PORT': DsViewData.PORT,
												'USER_ID': DsViewData.USER_ID,
												'data': btoa(unescape(encodeURIComponent(JSON.stringify(memberTableArray)))),
												'CONN_TYPE': DsViewData.CONN_TYPE
											};
											$.ajax({
												type: "POST",
												url:'./getMemberDataList.do',
												data:params,
												success:function(_data){
													_data = JSON.parse(_data);
													var result = [];
													$.each(_data.dataResult, function(i, member) {
														result = result.concat(member);
													});
													$('#userMemberArea').dxTreeList('instance').option('dataSource', result);
													$('#userMemberArea').dxTreeList('repaint');
												}
											});
											
										}
									});
	//								$('#dsViewArea').dxTreeList('instance').option('dataSource','');
	//								$('#dsDimensionArea').dxTreeList('instance').option('dataSource','');
	//								$('#memberArea').dxTreeList('instance').option('dataSource','');
								}
								
							}
						});
					}
				});
				
				//20210813 AJKIM 주제영역 권한 불러오기 오류 수정 dogfoot
				var dataSourceChanged = false;
				$('#userDsViewArea').dxTreeList({
					columns:[
						{
							dataField:'cubeNm',
							caption:"주제영역"
						},
					],
					autoExpandAll: true,
					keyExpr: "cubeId",
					parentIdExpr:"parentId",
					rootValue: "0",
					dataStructure: "plain",
					dataSource:'',
					visible: true,
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					selection: {
						mode: "multiple",
						recursive: true 
					},
					onOptionChanged:function(_e){
						if(_e.name=="dataSource"){
							$(_e.element).dxTreeList('instance').deselectAll();
							dataSourceChanged = true;
						}
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userdata') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady:function(_e){
						if(dataSourceChanged){
							var datasource = _e.component.option('dataSource');
							var selectRow = [];
							if(datasource != undefined){
								$.each(datasource,function(_i,_items){
									$.each(Auth_Cubes,function(_i,_dimCube){
										if(_items.dsViewId == _dimCube.DS_VIEW_ID && _items.cubeId == _dimCube.CUBE_ID){
											selectRow.push(_items.cubeId); 
										} 
									});
								});
								_e.component.selectRows(selectRow, false); 
							}
							dataSourceChanged = false;
						}
						gDashboard.fontManager.setFontConfigForList('userDsViewArea');
					}
				});
				
				$('#userDsDimensionArea').dxTreeList({
					columns:[
						{
							dataField:'DIM_TBL_NM',
							caption:"차원"
						},
					],
					autoExpandAll: true,
					keyExpr: "ordering",
					parentIdExpr:"parentId",
					rootValue: "0",
					dataStructure: "plain",
					dataSource:'',
					visible: true,
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					selection: {
						mode: "multiple",
						recursive: true 
					},
					onOptionChanged:function(_e){
						if(_e.name=="dataSource"){
							$(_e.element).dxTreeList('instance').deselectAll();
						}
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userdata') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady:function(_e){
						var datasource = $(_e.element).dxTreeList('instance').getDataSource();
						var selectRow = [];
						if(datasource != undefined){
							$.each(datasource._store._array,function(_i,_items){
								$.each(Auth_Dim,function(_i,_DimCol){
									if(_items.DIM_UNI_NM == _DimCol.DIM_UNI_NM && _items.DS_VIEW_ID ==_DimCol.DS_VIEW_ID){
	//			        				$(_e.element).dxTreeList('instance').selectRows(_items.key,true);
										selectRow.push(_items.ordering);
									}
								});
							});
							$(_e.element).dxTreeList('instance').selectRows(selectRow,false);
						}
						gDashboard.fontManager.setFontConfigForList('userDsDimensionArea');
					}
				});
				$('#userMemberArea').dxTreeList({
					columns:[
						{
							dataField:'CAPTION_COL',
							caption:'멤버'
						}
					],
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					autoExpandAll: true,
					dataStructure: "plain",
					keyExpr: "ID",
					parentIdExpr:"ParentId",
					dataSource:'',
					rootValue: "0",
					selection: {
						mode: "multiple",
						recursive: true 
					},
					onOptionChanged:function(_e){
						if(_e.name=="dataSource"){
							$(_e.element).dxTreeList('instance').deselectAll();
						}
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userdata') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady:function(_e){
						var datasource = $(_e.element).dxTreeList('instance').getDataSource();
						var selectRow = [];
						if(datasource != undefined){

							$.each(datasource._store._array,function(_i,_items){
								$.each(Auth_Mem,function(_i,_auth){
									if(_items.KEY_COL == _auth.MEMBER_NM && _items.DS_VIEW_ID ==_auth.DS_VIEW_ID){
										selectRow.push(_items.ID);
									}
								});
							});
							$(_e.element).dxTreeList('instance').selectRows(selectRow,false);
						}
					}
				});
			}
		});
	}

	/**
	 * Initialize functions for group data authentication page.
	 */
	function initAuthGroupData() {
		$.ajax({
			url : './getAuthGroupDataList.do',
			async: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);

				$('#groupDataSelectTable').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField: "그룹NO",
							visible:false
						},
						{
							dataField: "그룹명",
						},
						{
							dataField: "설명",
						}
					],
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					dataSource:_data.groupArrayList,
					selection: {
						mode: "single",
					},
					keyExpr:"그룹NO",
					onContentReady: function() {
						gProgressbar.hide();
					},
					paging:{
						enabled:false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('groupDataSelectTable')
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupdata') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick:function(_e){
						var param = {};
						param['groupNo'] = _e.data["그룹NO"];
						$.ajax({
							url:'./getGroupDSViewAuth.do',
							data:param,
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							success:function(_authDSdata){
								_authDSdata = JSON.parse(_authDSdata);
								if(_authDSdata.dsViewResult.length != 0){
									if(typeof _authDSdata.dsViewResult[0] != 'undefined'){
										Auth_Cubes = toArray(_authDSdata.dsViewResult[0].DataJson.NewDataSet.Auth_Cubes);
										Auth_Dim = toArray(_authDSdata.dsViewResult[0].DataJson.NewDataSet.Auth_Dim);
										Auth_Mem = toArray(_authDSdata.dsViewResult[0].DataJson.NewDataSet.Auth_Mem);
									}
									else if(_e.data["그룹NO"] != _authDSdata.dsViewResult[0].groupId){
										Auth_Cubes = [];
										Auth_Dim = [];
										Auth_Mem = [];
									}
									var DsListDataSource = $('#groupDsList').dxDataGrid('getDataSource')._items;
									// AUTH_YN 확인
									$.each(DsListDataSource,function(_i,_items){
										_items.AUTH_YN = '';
										var isAuth = false;
										// 주제 영역
										$.each(toArray(Auth_Cubes),function(_i,_cubes){
											if(_items.DS_VIEW_ID === _cubes.DS_VIEW_ID.toString()){
												_items.AUTH_YN = 'Y';
												isAuth = true;
												return false;
											}
										});
										if (isAuth) return;
										// 차원
										$.each(toArray(Auth_Dim),function(_i,_dim){
											if(_items.DS_VIEW_ID === _dim.DS_VIEW_ID.toString()){
												_items.AUTH_YN = 'Y';
												isAuth = true;
												return false;
											}
										});
										if (isAuth) return;
										// 멤버
										$.each(toArray(Auth_Mem),function(_i,_mem){
											if(_items.DS_VIEW_ID === _mem.DS_VIEW_ID.toString()){
												_items.AUTH_YN = 'Y';
												return false;
											}
										});
									});
									$('#groupDsList').dxDataGrid('instance').option('dataSource',DsListDataSource);
									$('#groupDsList').dxDataGrid('repaint');
								}else{
									var DsListDataSource = $('#groupDsList').dxDataGrid('getDataSource')._items;
									$.each(DsListDataSource,function(_i,_items){
										_items.AUTH_YN = '';
									});
									$('#groupDsList').dxDataGrid('instance').option('dataSource',DsListDataSource);
									$('#groupDsList').dxDataGrid('repaint');
								}
								
							}
						});
						$('#groupDsViewArea').dxTreeList('instance').option('dataSource','');
						$('#groupDsDimensionArea').dxTreeList('instance').option('dataSource','');
						$('#groupMemberArea').dxTreeList('instance').option('dataSource','');
					}
				});
				$('#groupDsList').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField:"DS_VIEW_ID",
							visible:false
						},
						{
							dataField:"DS_VIEW_NM",
							caption:"데이터 원본 뷰 명"
						},
						{
							dataField:"DS_NM",
							caption:"데이터 원본 명",
							sortOrder: 'asc'
						},
						{
							dataField:"DBMS_TYPE",
							caption:"DB 유형"
						},
						{
							dataField:"OWNER_NM",
							caption:"소유자"
						},
						{
							dataField:"IP",
							caption:"서버 주소(명)"
						},
						{
							dataField:"DS_NM",
							caption:"DB 명"
						},
					],
					showColumnLines: true,
					columnAutoWidth: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					dataSource:_data.DSViewArrayList,
					paging:{
						enabled:false
					},
					keyExpr:"DS_VIEW_ID",
					selection: {
						mode: "single",
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupdata') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('groupDsList');
						gProgressbar.hide();
					},
					onRowClick:function(_e){
						var authParam = {};
						authParam['groupNo'] = $('#groupDataSelectTable').dxDataGrid('getSelectedRowKeys')[0];
						$.ajax({
							url:'./getGroupDSViewAuth.do',
							data:authParam,
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							success:function(_authDSdata){
								_authDSdata = JSON.parse(_authDSdata);
								if(_authDSdata.dsViewResult[0] != undefined){
									var DsInformationParam = {};
									DsInformationParam['groupNo'] = $('#groupDataSelectTable').dxDataGrid('getSelectedRowKeys')[0];
									DsInformationParam['dsViewId'] = _e.key;
									
									$.ajax({
										url:'./getDsInformation.do',
										data:DsInformationParam,
										contentType: "application/x-www-form-urlencoded; charset=UTF-8",
										success:function(_data){
											_data = JSON.parse(_data);
//											for(var i = 0; i < 100; i++){
//												_data.cubeArray.push({
//													cubeId: i+100,
//													dsViewId: _data.cubeArray[0].dsViewId,
//													cubeNm: 'testCubeNm'+i,
//													parentId: 1,
//													cubeOrdinal: 0
//												})
//											} 
											$('#groupDsViewArea').dxTreeList('instance').option('dataSource',_data.cubeArray);
											$('#groupDsViewArea').dxTreeList('repaint');
											$('#groupDsDimensionArea').dxTreeList('instance').option('dataSource',_data.DSViewDimArray);
											$('#groupDsDimensionArea').dxTreeList('repaint');
											var memberTableArray = [];
											var memberKeyCol = [];
											
											$.each(_data.DSViewHieArray,function(_i,_arr){
												if(_arr.KEY_COL != '멤버' && _arr.IS_AUTH == 1){
													memberKeyCol.push(_arr.DIM_UNI_NM.replace(/[[\]]/g,''));
													memberTableArray.push(_arr);
												}
											});
											var DsViewData = ($('#groupDsList').dxDataGrid('getSelectedRowsData'))[0];
											var params = {
												'DS_VIEW_ID': DsViewData.DS_VIEW_ID,
												'IP': DsViewData.IP,
												'DS_NM': DsViewData.DS_NM,
												'DB_NM' : DsViewData.DB_NM,
												'DBMS_TYPE': DsViewData.DBMS_TYPE,
												'OWNER_NM': DsViewData.OWNER_NM,
												'PASSWD': DsViewData.PASSWD,
												'PORT': DsViewData.PORT,
												'USER_ID': DsViewData.USER_ID,
												'data': btoa(unescape(encodeURIComponent(JSON.stringify(memberTableArray)))),
												'CONN_TYPE': DsViewData.CONN_TYPE
											};
											$.ajax({
												type: "POST",
												url:'./getMemberDataList.do',
												data:params,
												success:function(_data){
													_data = JSON.parse(_data);
													var result = [];
													$.each(_data.dataResult, function(i, member) {
														result = result.concat(member);
													});
													$('#groupMemberArea').dxTreeList('instance').option('dataSource', result);
													$('#groupMemberArea').dxTreeList('repaint');
												}
											});
											
										}
									});
								}else{
									var DsInformationParam = {};
									Auth_Cubes = [];
									Auth_Dim = [];
									Auth_Mem = [];
									DsInformationParam['groupNo'] = $('#groupDataSelectTable').dxDataGrid('getSelectedRowKeys')[0];
									DsInformationParam['dsViewId'] = _e.key;
									$.ajax({
										url:'./getDsInformation.do',
										data:DsInformationParam,
										contentType: "application/x-www-form-urlencoded; charset=UTF-8",
										success:function(_data){
											_data = JSON.parse(_data);
											$('#groupDsViewArea').dxTreeList('instance').option('dataSource',_data.cubeArray);
											$('#groupDsViewArea').dxTreeList('repaint');
											$('#groupDsDimensionArea').dxTreeList('instance').option('dataSource',_data.DSViewDimArray);
											$('#uesrDsDimensionArea').dxTreeList('repaint');
											
											var memberTableArray = [];
											var memberKeyCol = [];
											
											$.each(_data.DSViewHieArray,function(_i,_arr){
												if(_arr.KEY_COL != '멤버' && _arr.IS_AUTH == 1){
													memberKeyCol.push(_arr.DIM_UNI_NM.replace(/[[\]]/g,''));
													memberTableArray.push(_arr);
												}
											});
											var DsViewData = ($('#groupDsList').dxDataGrid('getSelectedRowsData'))[0];
											var params = {
												'DS_VIEW_ID': DsViewData.DS_VIEW_ID,
												'IP': DsViewData.IP,
												'DS_NM': DsViewData.DS_NM,
												'DB_NM' : DsViewData.DB_NM,
												'DBMS_TYPE': DsViewData.DBMS_TYPE,
												'OWNER_NM': DsViewData.OWNER_NM,
												'PASSWD': DsViewData.PASSWD,
												'PORT': DsViewData.PORT,
												'USER_ID': DsViewData.USER_ID,
												'data': btoa(unescape(encodeURIComponent(JSON.stringify(memberTableArray)))),
												'CONN_TYPE': DsViewData.CONN_TYPE
											};
											$.ajax({
												type: "POST",
												url:'./getMemberDataList.do',
												data:params,
												success:function(_data){
													_data = JSON.parse(_data);
													var result = [];
													$.each(_data.dataResult, function(i, member) {
														result = result.concat(member);
													});
													$('#userMemberArea').dxTreeList('instance').option('dataSource', result);
													$('#userMemberArea').dxTreeList('repaint');
												}
											});
											
										}
									});
	//								$('#dsViewArea').dxTreeList('instance').option('dataSource','');
	//								$('#dsDimensionArea').dxTreeList('instance').option('dataSource','');
	//								$('#memberArea').dxTreeList('instance').option('dataSource','');
								}
								
							}
						});
					}
				});
				//20210813 AJKIM 주제영역 권한 불러오기 오류 수정 dogfoot
				var dataSourceChanged = false;
				$('#groupDsViewArea').dxTreeList({
					columns:[
						{
							dataField:'cubeNm',
							caption:"주제영역"
						},
					],
					autoExpandAll: true,
					keyExpr: "cubeId",
					parentIdExpr:"parentId",
					rootValue: "0",
					dataStructure: "plain",
					dataSource:'',
					visible: true,
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					selection: {
						mode: "multiple",
						recursive: true 
					},
					onOptionChanged:function(_e){
						if(_e.name=="dataSource"){
							$(_e.element).dxTreeList('instance').deselectAll();
							dataSourceChanged = true;
						}
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupdata') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady:function(_e){
						if(dataSourceChanged){
							var datasource = _e.component.option('dataSource');
							var selectRow = [];
							if(datasource != undefined){
								$.each(datasource,function(_i,_items){
									$.each(Auth_Cubes,function(_i,_dimCube){
										if(_items.dsViewId == _dimCube.DS_VIEW_ID && _items.cubeId == _dimCube.CUBE_ID){
											selectRow.push(_items.cubeId); 
										} 
									});
								});
								_e.component.selectRows(selectRow, false); 
							}
							dataSourceChanged = false;
						}
						gDashboard.fontManager.setFontConfigForList('groupDsViewArea');
					}
				});
				
				$('#groupDsDimensionArea').dxTreeList({
					columns:[
						{
							/* DOGFOOT 권한-그룹데이터 차원 매칭 오류 수정  20210804 */
							dataField:'DIM_TBL_NM',
//							dataField:'DIM_CAPTION',
							caption:"차원"
						},
					],
					autoExpandAll: true,
					keyExpr: "ordering",
					parentIdExpr:"parentId",
					rootValue: "0",
					dataStructure: "plain",
					dataSource:'',
					visible: true,
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					selection: {
						mode: "multiple",
						recursive: true 
					},
					onOptionChanged:function(_e){
						if(_e.name=="dataSource"){
							$(_e.element).dxTreeList('instance').deselectAll();
						}
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupdata') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady:function(_e){
						var datasource = $(_e.element).dxTreeList('instance').getDataSource();
						var selectRow = [];
						if(datasource != undefined){
							$.each(datasource._store._array,function(_i,_items){
								$.each(Auth_Dim,function(_i,_DimCol){
									if(_items.DIM_UNI_NM == _DimCol.DIM_UNI_NM && _items.DS_VIEW_ID ==_DimCol.DS_VIEW_ID){
	//			        				$(_e.element).dxTreeList('instance').selectRows(_items.key,true);
										selectRow.push(_items.ordering);
									}
								});
							});
							$(_e.element).dxTreeList('instance').selectRows(selectRow,false);
						}
						gDashboard.fontManager.setFontConfigForList('groupDsDimensionArea');
					}
				});
				$('#groupMemberArea').dxTreeList({
					columns:[
						{
							dataField:'CAPTION_COL',
							caption:'멤버'
						}
					],
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					autoExpandAll: true,
					dataStructure: "plain",
					keyExpr: "ID",
					parentIdExpr:"ParentId",
					dataSource:'',
					rootValue: "0",
					selection: {
						mode: "multiple",
						recursive: true 
					},
					onOptionChanged:function(_e){
						if(_e.name=="dataSource"){
							$(_e.element).dxTreeList('instance').deselectAll();
						}
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupdata') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady:function(_e){
						var datasource = $(_e.element).dxTreeList('instance').getDataSource();
						var selectRow = [];
						if(datasource != undefined){

							$.each(datasource._store._array,function(_i,_items){
								$.each(Auth_Mem,function(_i,_auth){
									if(_items.KEY_COL == _auth.MEMBER_NM && _items.DS_VIEW_ID ==_auth.DS_VIEW_ID){
										selectRow.push(_items.ID);
									}
								});
							});
							$(_e.element).dxTreeList('instance').selectRows(selectRow,false);
						}
						gDashboard.fontManager.setFontConfigForList('groupMemberArea');
					}
				});
			}
		});
	}
	
	//20210520 AJKIM 데이터 원본 권한 추가 dogfoot
	function initAuthGroupDs() {
		$.ajax({
			url : './getAuthGroupDsList.do',
			async: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);

				$('#groupDsSelectTable').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField: "그룹NO",
							visible:false
						},
						{
							dataField: "그룹명",
						},
						{
							dataField: "설명",
						}
					],
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					dataSource:_data.groupArrayList,
					selection: {
						mode: "single",
					},
					keyExpr:"그룹NO",
					onContentReady: function() {
						gProgressbar.hide();
					},
					paging:{
						enabled:false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('groupDsSelectTable')
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupds') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick:function(_e){
						gProgressbar.show();

						var param = {
							'grpId':_e.data['그룹NO']
						}
						$.ajax({
							url:'./getGrpDsAuth.do',
							data:param,
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							success:function(_authdata){
								_authdata = JSON.parse(_authdata);
								var groupDsResult = $('#groupDsResult').dxDataGrid('instance');
								groupDsResult.deselectAll();
								var authIndexList = [];
								$.each(_authdata.authDsList, function(i, dsId){
									var dsIndex = groupDsResult.getRowIndexByKey(dsId);
									authIndexList.push(dsIndex);
//									groupDsResult.cellValue(dsIndex, 'AUTH_YN', true);
//									groupDsResult.selectRows(dsId)
								});
								groupDsResult.selectRowsByIndexes(authIndexList);
								gProgressbar.hide();
							}
						});
					}
				});
				$('#groupDsResult').dxDataGrid({
					columns:[
//						{
//							dataField:"AUTH_YN",
//							width:'30px',
//							caption: '',
//							dataType: 'boolean'
////							cellTemplate: function(element, options) {
////								if (options.value === 'Y') {
////									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
////										.appendTo(element);
////								}
////							}
//						},
						{
							dataField:"DS_ID",
							visible:false,
							allowEditing: false
						},
						{
							dataField:"DS_NM",
							caption:"데이터 원본 명",
							sortOrder: 'asc',
							allowEditing: false
						},
						{
							dataField:"DBMS_TYPE",
							caption:"DB 유형",
							allowEditing: false
						},
						{
							dataField:"OWNER_NM",
							caption:"소유자",
							allowEditing: false
						},
						{
							dataField:"IP",
							caption:"서버 주소(명)",
							allowEditing: false
						},
						{
							dataField:"DS_NM",
							caption:"DB 명",
							allowEditing: false
						},
					],
					selection: {
			            mode: "multiple",
			            showCheckBoxesMode: "always"
			        },
					showColumnLines: true,
					columnAutoWidth: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					dataSource:_data.dsArrayList,
					height: '100%',
					paging:{
						enabled:false
					},
					keyExpr:"DS_ID",
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupds') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function(e) {
						gDashboard.fontManager.setFontConfigForList('groupDsResult');
						gProgressbar.hide();
						//e.component.columnOption("command:select", "visibleWidth", 35);
					},
				});				
			}
		});
	}
	
	function initAuthUserDs() {
		$.ajax({
			url : './getAuthUserDsList.do',
			async: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);

				$('#userDsSelectTable').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField: "사용자NO",
							visible:false
						},
						{
							dataField: "사용자명",
						},
						{
							dataField: "설명",
						}
					],
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					dataSource:_data.userArrayList,
					selection: {
						mode: "single",
					},
					keyExpr:"사용자NO",
					onContentReady: function() {
						gProgressbar.hide();
					},
					paging:{
						enabled:false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('userDsSelectTable')
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userds') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick:function(_e){
						gProgressbar.show();

						var param = {
							'userNo':_e.data['사용자NO']
						}
						$.ajax({
							url:'./getUserDsAuth.do',
							data:param,
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							success:function(_authdata){
								_authdata = JSON.parse(_authdata);
								var userDsResult = $('#userDsResult').dxDataGrid('instance');
								userDsResult.deselectAll();
								var authIndexList = [];
								$.each(_authdata.authDsList, function(i, dsId){
									var dsIndex = userDsResult.getRowIndexByKey(dsId);
									authIndexList.push(dsIndex);
//									groupDsResult.cellValue(dsIndex, 'AUTH_YN', true);
//									groupDsResult.selectRows(dsId)
								});
								userDsResult.selectRowsByIndexes(authIndexList);
								gProgressbar.hide();
							}
						});
					}
				});
				$('#userDsResult').dxDataGrid({
					columns:[
//						{
//							dataField:"AUTH_YN",
//							width:'30px',
//							caption: '',
//							dataType: 'boolean'
////							cellTemplate: function(element, options) {
////								if (options.value === 'Y') {
////									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
////										.appendTo(element);
////								}
////							}
//						},
						{
							dataField:"DS_ID",
							visible:false,
							allowEditing: false
						},
						{
							dataField:"DS_NM",
							caption:"데이터 원본 명",
							sortOrder: 'asc',
							allowEditing: false
						},
						{
							dataField:"DBMS_TYPE",
							caption:"DB 유형",
							allowEditing: false
						},
						{
							dataField:"OWNER_NM",
							caption:"소유자",
							allowEditing: false
						},
						{
							dataField:"IP",
							caption:"서버 주소(명)",
							allowEditing: false
						},
						{
							dataField:"DS_NM",
							caption:"DB 명",
							allowEditing: false
						},
					],
					selection: {
			            mode: "multiple",
			            showCheckBoxesMode: "always"
			        },
					showColumnLines: true,
					columnAutoWidth: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					dataSource:_data.dsArrayList,
					height: '100%',
					paging:{
						enabled:false
					},
					keyExpr:"DS_ID",
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupuser') {
								e.component.updateDimensions();
							}
						});
						
						e.component.columnOption("command:select", "visibleWidth", 35);
					},
					onContentReady: function(e) {
						gDashboard.fontManager.setFontConfigForList('userDsResult');
						gProgressbar.hide();
						//e.component.columnOption("command:select", "visibleWidth", 35);
					},
				});				
			}
		});
	}

	/**
	 * Initialize functions for report authentication page.
	 */
	function initAuthUserReport() {
		if ($('#userReportList').hasClass('dx-treelist')) {
			$('#userReportList').dxTreeList('dispose');
		}
		$.ajax({
			url : './getUserPublicReportList.do',
			// beforeSend: function() {
			// 	gProgressbar.show();
			// },
			success: function(_data){
				_data = JSON.parse(_data);
				$.each(_data.folderResult, function(_i,_items) {
					switch (_items.TYPE) {
						case 'REPORT':
							if (_items.REPORT_TYPE === 'DashAny') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_squariFied.png';
							} else if (_items.REPORT_TYPE === 'AdHoc') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_atypical01.png';	            						
							} else if (_items.REPORT_TYPE === 'Spread' || _items.REPORT_TYPE === 'Excel') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msexcell.png';
							} else if (_items.REPORT_TYPE === 'Word' || _items.REPORT_TYPE === 'WordGrp') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msword.png';
							}
							break;
						case 'FOLDER':
							_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
							break;
						default: break;
					}
				});
				$('#userReportSelectTable').dxDataGrid({
					columns:[
						{
							dataField: "사용자NO",
							visible: false
						},
						{
							dataField: "사용자ID"
						},
						{
							dataField: "사용자명"
						},
						{
							dataField: "그룹명"
						}
					],
					dataSource:_data.userResult,
					keyExpr: "사용자NO",
					selection: {
						mode: "single",
					},
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userreport') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('userReportSelectTable');
					},
					onRowClick:function(_e){
						gProgressbar.show();

						var param = {
							'userNo':_e.data['사용자NO']
						}
						$.ajax({
							url:'./getUserAuthReport.do',
							data:param,
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							success:function(_authdata){
								_authdata = JSON.parse(_authdata);
								var treeList = $('#userReportList').dxTreeList('instance');
								treeList.option('editing.allowUpdating', true);
								treeList.forEachNode(function(node) {
									node.data.FLD_SHOW = false;
									node.data.FLD_PUBLISH = false;
									node.data.FLD_DATAITEM = false;
									node.data.FLD_EXPORT = false;
								});
								$.each(_authdata.authFolderList,function(_i,_item){
									var folderNode = treeList.getNodeByKey(_item.FLD_ID);
									if (folderNode) {
										folderNode.data.FLD_SHOW = _item.AUTH_VIEW;
										folderNode.data.FLD_PUBLISH = _item.AUTH_PUBLISH;
										folderNode.data.FLD_DATAITEM = _item.AUTH_DATAITEM;
										folderNode.data.FLD_EXPORT = _item.AUTH_EXPORT;
									}
								});
								$.each(_authdata.authResult,function(_i,_item){
									var reportNode = treeList.getNodeByKey(_item.FLD_ID);
									if (reportNode) {
										reportNode.data.FLD_SHOW = _item.AUTH_VIEW;
										reportNode.data.FLD_PUBLISH = _item.AUTH_PUBLISH;
										reportNode.data.FLD_DATAITEM = _item.AUTH_DATAITEM;
										reportNode.data.FLD_EXPORT = _item.AUTH_EXPORT;
									}
								});
								treeList.refresh(true);
							}
						});
					}
					
				});
				var contentReady = 0;
				$('#userReportList').dxTreeList({
					columns:[
						{
							dataField:'FLD_NM',
							caption:'폴더이름',
							allowEditing: false,
							cellTemplate: function(container, options) {
								if (typeof options.data.icon !== 'undefined') {
									container.append('<img src="' + options.data.icon + '" class="auth-report-icon">');
								}
								container.append('<span>' + options.data.FLD_NM + '</span>');
							}
						},
						{
							dataField:'FLD_SHOW',
							dataType: 'boolean',
							caption:'조회'
						},
						{
							dataField:'FLD_PUBLISH',
							dataType: 'boolean',
							caption:'보고서작성/배포'
						},
						{
							dataField:'FLD_DATAITEM',
							dataType: 'boolean',
							caption:'데이터 항목 사용'
						},
						{
							dataField:'FLD_EXPORT',
							dataType: 'boolean',
							caption:'보고서 내려받기'
						},
						{
							dataField:'PARENT_FLD_ID',
							visible:false
						}
					],
					autoExpandAll: true,
					dataSource:_data.folderResult,
					keyExpr: "FLD_ID",
					parentIdExpr:"PARENT_FLD_ID",
					rootValue: "0",
					visible: true,
					showColumnLines: true,
					columnAutoWidth: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('userReportList')
						gProgressbar.hide();
						if(contentReady < 2)
							contentReady++;
					},
					selection: {
						mode: 'none',
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userreport') {
								e.component.updateDimensions();
							}
						});
					},
					/*dogfoot dev 18.ver / 20.ver 동일 하게 동작하도록 오류 수정 shlim 20201014*/
					onRowUpdating: function(e) {
						this.userDataField= []
						this.userDataField = _.keys(e.newData);
					},
					//20200722 ajkim 권한 상위 아이템 체크시 하위 아이템 모두 체크 / 하위 아이템 체크시 상위 폴더 모드 체크 dogfoot
					onRowUpdated: function(e){
						var node = e.component.getNodeByKey(e.key);
						var dataField = this.userDataField
						var value = e.data[dataField];
						
						var setParentNodeTrue = function(_node){
							if(!_node.data || _node.data[dataField]) return;
							_node.data[dataField] = true;
							
							if(_node.parent.data)
								setParentNodeTrue(_node.parent);
						}
						
						var setChildrenNode = function(_node){
							$.each(_node.children, function(i, child){
								child.data[dataField] = value;
								if(child.hasChildren)
									setChildrenNode(child);
							})
						}
						if(value){
							setParentNodeTrue(node.parent);
						}if(node.hasChildren){
							setChildrenNode(node);
						}
						 $('#userReportList').dxTreeList('instance').refresh(true);
					},
					editing: {
						mode: 'cell',
						allowUpdating: false,
						refreshMode: 'repaint'
					},
					repaintChangesOnly: true
				});
			}
			
		});
	}

	/**
	 * Initialize functions for report authentication page.
	 */
	function initAuthGroupReport() {
		if ($('#groupReportList').hasClass('dx-treelist')) {
			$('#groupReportList').dxTreeList('dispose');
		}
		$.ajax({
			url : './getGrpPublicReportList.do',
			// beforeSend: function() {
			// 	gProgressbar.show();
			// },
			cache: false,
			success: function(_data){
				_data = JSON.parse(_data);
				$.each(_data.folderResult, function(_i,_items) {
					switch (_items.TYPE) {
						case 'REPORT':
							if (_items.REPORT_TYPE === 'DashAny') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_squariFied.png';
							} else if (_items.REPORT_TYPE === 'AdHoc') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_atypical01.png';	            						
							} else if (_items.REPORT_TYPE === 'Spread' || _items.REPORT_TYPE === 'Excel') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msexcell.png';
							} else if (_items.REPORT_TYPE === 'Word' || _items.REPORT_TYPE === 'WordGrp') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msword.png';
							}
							break;
						case 'FOLDER':
							_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
							break;
						default: break;
					}
				});
				$('#groupReportSelectTable').dxDataGrid({
					columns:[
						{
							dataField: "그룹명",
						},
						{
							dataField: "그룹설명",
						}
					],
					dataSource:_data.groupResult,
					selection: {
						mode: "single",
					},
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					paging:{
						enabled:false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('groupReportSelectTable');
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupreport') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick:function(_e){
						gProgressbar.show();

						var param = {
							'grp_id':_e.data.그룹ID
						}
						$.ajax({
							url:'./getGrpAuthReport.do',
							data:param,
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							success:function(_authdata){

								_authdata = JSON.parse(_authdata);
								var treeList = $('#groupReportList').dxTreeList('instance');
								treeList.option('editing.allowUpdating', true);
								treeList.forEachNode(function(node) {
									node.data.FLD_SHOW = false;
									node.data.FLD_PUBLISH = false;
									node.data.FLD_DATAITEM = false;
									node.data.FLD_EXPORT = false;
								});
								$.each(_authdata.authFolderList,function(_i,_item){
									var folderNode = treeList.getNodeByKey(_item.FLD_ID);
									if (folderNode) {
										folderNode.data.FLD_SHOW = _item.AUTH_VIEW;
										folderNode.data.FLD_PUBLISH = _item.AUTH_PUBLISH;
										folderNode.data.FLD_DATAITEM = _item.AUTH_DATAITEM;
										folderNode.data.FLD_EXPORT = _item.AUTH_EXPORT;
									}
								});
								$.each(_authdata.authResult,function(_i,_item){
									var reportNode = treeList.getNodeByKey(_item.FLD_ID);
									if (reportNode) {
										reportNode.data.FLD_SHOW = _item.AUTH_VIEW;
										reportNode.data.FLD_PUBLISH = _item.AUTH_PUBLISH;
										reportNode.data.FLD_DATAITEM = _item.AUTH_DATAITEM;
										reportNode.data.FLD_EXPORT = _item.AUTH_EXPORT;
									}
								});
								treeList.refresh(true);
							}
						});
					}
					
				});

				$('#groupReportList').dxTreeList({
					columns:[
						{
							dataField:'FLD_NM',
							caption:'폴더이름',
							allowEditing: false,
							cellTemplate: function(container, options) {
								if (typeof options.data.icon !== 'undefined') {
									container.append('<img src="' + options.data.icon + '" class="auth-report-icon">');
								}
								container.append('<span>' + options.data.FLD_NM + '</span>');
							}
						},
						{
							dataField:'FLD_SHOW',
							dataType: 'boolean',
							caption:'조회'
						},
						{
							dataField:'FLD_PUBLISH',
							dataType: 'boolean',
							caption:'보고서작성/배포'
						},
						{
							dataField:'FLD_DATAITEM',
							dataType: 'boolean',
							caption:'데이터 항목 사용'
						},
						{
							dataField:'FLD_EXPORT',
							dataType: 'boolean',
							caption:'보고서 내려받기'
						},
						{
							dataField:'PARENT_FLD_ID',
							visible:false
						}
					],
					autoExpandAll: true,
					dataSource:_data.folderResult,
					keyExpr: "FLD_ID",
					parentIdExpr:"PARENT_FLD_ID",
					rootValue: "0",
					visible: true,
					showColumnLines: true,
					columnAutoWidth: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					scrolling:{
						mode : "virtual"
					},
					//20200722 ajkim 권한 상위 아이템 체크시 하위 아이템 모두 체크 / 하위 아이템 체크시 상위 폴더 모드 체크 dogfoot
					/*dogfoot dev 18.ver / 20.ver 동일 하게 동작하도록 오류 수정 shlim 20201014*/	
					onRowUpdating: function(e) {
						this.dataField= []
						this.dataField = _.keys(e.newData);
					},
					onRowUpdated: function(e){
						var node = e.component.getNodeByKey(e.key);
						//2020.09.16 MKSONG dev 20.ver 체크시  오류 발생 수정 DOGFOOT
						var dataField = this.dataField;
//						var dataField = 'FLD_SHOW';
                        var value,dataFieldNm;
                        
                        var setParentNodeTrue = function(_node){
							if(!_node.data || _node.data[dataFieldNm]) return;
							_node.data[dataFieldNm] = true;
							
							if(_node.parent.data)
								setParentNodeTrue(_node.parent);
						}
						
						var setChildrenNode = function(_node){
							$.each(_node.children, function(i, child){
								child.data[dataFieldNm] = value;
								if(child.hasChildren)
									setChildrenNode(child);
							})
						}

                        $.each(dataField,function(_i,_field){
                        	value = e.data[_field];
                            if(typeof value === "boolean"){
                            	dataFieldNm = _field;
                            	if(value){
									setParentNodeTrue(node.parent);
								}if(node.hasChildren){
									setChildrenNode(node);
								}
                            }

                        })
					
						 $('#groupReportList').dxTreeList('instance').refresh(true);
					},
					paging:{
						enabled:false
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupreport') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('groupReportList');
						gProgressbar.hide();
					},
					selection: {
						mode: 'none'
					},
					editing: {
						mode: 'cell',
						allowUpdating: false,
						refreshMode: 'repaint'
					},
					repaintChangesOnly: true
				});
			}
			
		});
	}

	/**
	 * Initialize functions for user dataset authentication page.
	 */
	function initAuthUserDataset() {
		$.ajax({
			url : './getUserDatasetList.do',
			async: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				$.each(_data.folderResult, function(_i,_items) {
					_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
				});
				$('#userDatasetSelectTable').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField: "사용자NO",
							visible: false
						},
						{
							dataField: "사용자ID"
						},
						{
							dataField: "사용자명"
						},
						{
							dataField: "그룹명"
						}
					],
					keyExpr: '사용자NO',
					dataSource:_data.userResult,
					selection: {
						mode: "single",
					},
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					paging: {
						enabled: false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('userDatasetSelectTable');
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userdataset') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick: function(_e) {
						$.ajax({
							url: WISE.Constants.context + '/report/getUserDatasetAuth.do',
							data: {
								'userNo':_e.data['사용자NO']
							},
							success: function(_authdata) {
								var selected = JSON.parse(_authdata).authFolderList;
								var datasets = $('#userDatasetResult').dxTreeView('instance');
								datasets.unselectAll();
								selected.forEach(function(fld) {
									datasets.selectItem(fld);
								});
							}
						});
					}
					
				});

				$('#userDatasetResult').dxTreeView({
					dataSource: _data.folderResult,
					dataStructure: 'plain',
					keyExpr: "FLD_ID",
					parentIdExpr:"PARENT_FLD_ID",
					displayExpr: "FLD_NM",
					visible: true,
					selectionMode: 'multiple',
					showCheckBoxesMode: 'selectAll',
					selectNodesRecursive: false,
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userdataset') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function(e) {
						gDashboard.fontManager.setFontConfigForList('userDatasetResult');
						//dogfoot syjin 사용자데이터 집합 무한로딩 오류 수정
						//e.component.expandAll();
						gProgressbar.hide();
					}
				});
			}
			
		});
	}

	/**
	 * Initialize functions for group dataset authentication page.
	 */
	function initAuthGroupDataset() {
		$.ajax({
			url : './getGrpDatasetList.do',
			async: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				$.each(_data.folderResult, function(_i,_items) {
					_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
				});
				$('#groupDatasetSelectTable').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField: "그룹명",
						},
						{
							dataField: "그룹설명",
						}
					],
					dataSource:_data.groupResult,
					selection: {
						mode: "single",
					},
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					paging: {
						enabled: false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('groupDatasetSelectTable');
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupdataset') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick: function(_e) {
						$.ajax({
							url: WISE.Constants.context + '/report/getGrpDatasetAuth.do',
							data: {
								'grp_id':_e.data['그룹ID']
							},
							success: function(_authdata) {
								var selected = JSON.parse(_authdata).authFolderList;
								var datasets = $('#groupDatasetResult').dxTreeView('instance');
								datasets.unselectAll();
								selected.forEach(function(fld) {
									datasets.selectItem(fld);
								});
							}
						});
					}
					
				});

				$('#groupDatasetResult').dxTreeView({
					dataSource: _data.folderResult,
					dataStructure: 'plain',
					keyExpr: "FLD_ID",
					parentIdExpr:"PARENT_FLD_ID",
					displayExpr: "FLD_NM",
					visible: true,
					selectionMode: 'multiple',
					showCheckBoxesMode: 'selectAll',
					selectNodesRecursive: false,
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupdataset') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function(e) {
						gDashboard.fontManager.setFontConfigForList('groupDatasetResult');
						//dogfoot syjin 20210323 권한(그룹 데이터 집합) epxanded 옵션 추가
						//e.component.expandAll();
						gProgressbar.hide();
					}
				});
			}
			
		});
	}
	//20210705 AJKIM 메뉴 권한 추가 dogfoot
	function initAuthUserWebApp() {
		$.ajax({
			url : './getUserWbList.do',
			async: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				$.each(_data.folderResult, function(_i,_items) {
					_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
				});
				$('#userWbSelectTable').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField: "사용자NO",
							visible: false
						},
						{
							dataField: "사용자ID"
						},
						{
							dataField: "사용자명"
						},
						{
							dataField: "그룹명"
						}
					],
					keyExpr: '사용자NO',
					dataSource:_data.userResult,
					selection: {
						mode: "single",
					},
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					paging: {
						enabled: false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('userDatasetSelectTable');
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userdataset') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick: function(_e) {
						$.ajax({
							url: WISE.Constants.context + '/report/getUserWbAuth.do',
							data: {
								'userNo':_e.data['사용자NO']
							},
							success: function(_authdata) {
								var selected = JSON.parse(_authdata);
								var apps = $('#userWbResult').dxTreeView('instance');
								apps.unselectAll();
								
								$.each(selected, function(key, value){
									if(key != "DS" && value === 'Y'){
										apps.selectItem(key)
									}
								});
								
								if(selected.DS_DETAIL){
									var detail = selected.DS_DETAIL;
									$.each(detail, function(key, value){
										if(value === true){
											apps.selectItem(key)
										}
									});
								}

							}
						});
					}
					
				});

				
var menuConfig = menuConfigManager.getMenuConfig.Menu;
				
				var menuTreeData = [
					{
						id: "ADHOC",
						caption: "비정형 보고서",
						visible : menuConfig.PROG_MENU_TYPE.AdHoc.visible
					},
					{
						id: "DASH",
						caption: "대시보드",
						visible : menuConfig.PROG_MENU_TYPE.DashAny.visible
					},
					{
						id: "EXCEL",
						caption: "스프레드시트",
						visible : menuConfig.PROG_MENU_TYPE.Excel.visible
					},
					{
						id: "ANAL",
						caption: "통계분석",
						visible : menuConfig.PROG_MENU_TYPE.Analysis.visible
					},
					{
						id: "DS",
						caption: "데이터집합",
						visible : menuConfig.PROG_MENU_TYPE.DataSet.visible,
						expanded: true
					},
					{
						id: "CONFIG",
						caption: "환경설정",
						visible : menuConfig.PROG_MENU_TYPE.Config.visible
					},
					{
						id: "DSVIEWER",
						caption: "데이터집합 뷰어",
						visible : menuConfig.PROG_MENU_TYPE.DSViewer.visible
					},
					{
						id: "CUBE",
						parentId: "DS",
						caption: "주제 영역 데이터",
						visible : menuConfig.DATASET_MENU_TYPE.CUBE
					},
					{
						id: "DataSetCube",
						parentId: "DS",
						caption: "신규 데이터 집합(주제 영역 기준)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetCube
					},
					{
						id: "DataSetDs",
						parentId: "DS",
						caption: "신규 데이터 집합(데이터 원본 기준)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetDs
					},
					{
						id: "DataSetDsJoin",
						parentId: "DS",
						caption: "신규 데이터 집합(이기종 조인)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetDsJoin
					},
					{
						id: "DataSetSQL",
						parentId: "DS",
						caption: "신규 데이터 집합(쿼리 직접 입력)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetSQL
					},
					{
						id: "DataSetSingleDs",
						parentId: "DS",
						caption: "신규 데이터 집합(단일 테이블)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetSingleDs
					},
					{
						id: "DataSetUser",
						parentId: "DS",
						caption: "사용자 데이터 업로드",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetUser
					},
					{
						id: "DataSetLoad",
						parentId: "DS",
						caption: "기존 데이터 집합",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetLoad
					}
				]
				$('#userWbResult').dxTreeView({
					dataSource: menuTreeData,
					dataStructure: 'plain',
					keyExpr: "id",
					parentIdExpr:"parentId",
					displayExpr: "caption",
					visible: true,
					selectionMode: 'multiple',
					showCheckBoxesMode: 'selectAll',
					selectNodesRecursive: true,
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-userwb') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function(e) {
						gDashboard.fontManager.setFontConfigForList('userWbResult');
						//dogfoot syjin 사용자데이터 집합 무한로딩 오류 수정
						//e.component.expandAll();
						gProgressbar.hide();
					}
				});
			}
			
		});
	}
	
	function initAuthGroupWebApp() {
		$.ajax({
			url : './getGrpWbList.do',
			async: false,
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				$.each(_data.folderResult, function(_i,_items) {
					_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
				});
				$('#groupWbSelectTable').dxDataGrid({
					columns:[
						{
							dataField:"AUTH_YN",
							width:'30px',
							caption: '',
							cellTemplate: function(element, options) {
								if (options.value === 'Y') {
									$('<img src="' + WISE.Constants.context + '/resources/main/images/ico_password.png" style="height:15px;">')
										.appendTo(element);
								}
							}
						},
						{
							dataField: "그룹명",
						},
						{
							dataField: "그룹설명",
						}
					],
					dataSource:_data.groupResult,
					selection: {
						mode: "single",
					},
					showColumnLines: true,
					showRowLines: true,
					rowAlternationEnabled: true,
					showBorders: true,
					paging: {
						enabled: false
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('groupDatasetSelectTable');
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupdataset') {
								e.component.updateDimensions();
							}
						});
					},
					onRowClick: function(_e) {
						$.ajax({
							url: WISE.Constants.context + '/report/getGrpWbAuth.do',
							data: {
								'grp_id':_e.data['그룹ID']
							},
							success: function(_authdata) {
								var selected = JSON.parse(_authdata);
								var apps = $('#groupWbResult').dxTreeView('instance');
								apps.unselectAll();
								
								$.each(selected, function(key, value){
									if(key != "DS" && value === 'Y'){
										apps.selectItem(key)
									}
								});
								
								if(selected.DS_DETAIL){
									var detail = selected.DS_DETAIL;
									$.each(detail, function(key, value){
										if(value === true){
											apps.selectItem(key)
										}
									});
								}
							}
						});
					}
					
				});
				
var menuConfig = menuConfigManager.getMenuConfig.Menu;
				
				var menuTreeData = [
					{
						id: "ADHOC",
						caption: "비정형 보고서",
						visible : menuConfig.PROG_MENU_TYPE.AdHoc.visible
					},
					{
						id: "DASH",
						caption: "대시보드",
						visible : menuConfig.PROG_MENU_TYPE.DashAny.visible
					},
					{
						id: "EXCEL",
						caption: "스프레드시트",
						visible : menuConfig.PROG_MENU_TYPE.Excel.visible
					},
					{
						id: "ANAL",
						caption: "통계분석",
						visible : menuConfig.PROG_MENU_TYPE.Analysis.visible
					},
					{
						id: "DS",
						caption: "데이터집합",
						visible : menuConfig.PROG_MENU_TYPE.DataSet.visible,
						expanded: true
					},
					{
						id: "CONFIG",
						caption: "환경설정",
						visible : menuConfig.PROG_MENU_TYPE.Config.visible
					},
					{
						id: "DSVIEWER",
						caption: "데이터집합 뷰어",
						visible : menuConfig.PROG_MENU_TYPE.DSViewer.visible
					},
					{
						id: "CUBE",
						parentId: "DS",
						caption: "주제 영역 데이터",
						visible : menuConfig.DATASET_MENU_TYPE.CUBE
					},
					{
						id: "DataSetCube",
						parentId: "DS",
						caption: "신규 데이터 집합(주제 영역 기준)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetCube
					},
					{
						id: "DataSetDs",
						parentId: "DS",
						caption: "신규 데이터 집합(데이터 원본 기준)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetDs
					},
					{
						id: "DataSetDsJoin",
						parentId: "DS",
						caption: "신규 데이터 집합(이기종 조인)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetDsJoin
					},
					{
						id: "DataSetSQL",
						parentId: "DS",
						caption: "신규 데이터 집합(쿼리 직접 입력)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetSQL
					},
					{
						id: "DataSetSingleDs",
						parentId: "DS",
						caption: "신규 데이터 집합(단일 테이블)",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetSingleDs
					},
					{
						id: "DataSetUser",
						parentId: "DS",
						caption: "사용자 데이터 업로드",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetUser
					},
					{
						id: "DataSetLoad",
						parentId: "DS",
						caption: "기존 데이터 집합",
						visible : menuConfig.DATASET_MENU_TYPE.DataSetLoad
					}
				]

				$('#groupWbResult').dxTreeView({
					dataSource: menuTreeData,
					dataStructure: 'plain',
					keyExpr: "id",
					parentIdExpr:"parentId",
					displayExpr: "caption",
					visible: true,
					selectionMode: 'multiple',
					showCheckBoxesMode: 'selectAll',
					selectNodesRecursive: true,
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'authentication-groupwb') {
								e.component.updateDimensions();
							}
						});
					},
					onContentReady: function(e) {
						gDashboard.fontManager.setFontConfigForList('groupWbResult');
						//dogfoot syjin 20210323 권한(그룹 데이터 집합) epxanded 옵션 추가
						//e.component.expandAll();
						gProgressbar.hide();
					}
				});
			}
			
		});
	}

	/* public methods */
	return {
		loadAuthUserData: function() {
			gProgressbar.show();
			Auth_Cubes = []; 
			Auth_Dim = [];
			Auth_Mem = [];
			initAuthUserData();
		},

		loadAuthGroupData: function() {
			gProgressbar.show();
			Auth_Cubes = []; 
			Auth_Dim = [];
			Auth_Mem = [];
			initAuthGroupData();
		},

		loadAuthUserReport: function() {
			gProgressbar.show();
			initAuthUserReport();
		},
		
		loadAuthUserDs: function() {
			gProgressbar.show();
			initAuthUserDs();
		},

		loadAuthGroupReport: function() {
			gProgressbar.show();
			initAuthGroupReport();
		},

		loadAuthUserDataset: function() {
			gProgressbar.show();
			initAuthUserDataset();
		},

		loadAuthGroupDataset: function() {
			gProgressbar.show();
			initAuthGroupDataset();
		},
		
		loadAuthGroupDs: function() {
			gProgressbar.show();
			initAuthGroupDs();
		},
		//20210705 AJKIM 메뉴 권한 추가 dogfoot
		loadAuthUserWebApp: function() {
			gProgressbar.show();
			initAuthUserWebApp();
		},
		
		loadAuthGroupWebApp: function() {
			gProgressbar.show();
			initAuthGroupWebApp();
		},

		/**
		 * Initialize user report authentication select/deselect all functionality.
		 */
		initAuthUserReportSelectDeselect: function() {
			$('#filterContainer').append(
				'<div id="colSelector"></div>' +
				'<div id="selectAll"></div>' +
				'<div id="deselectAll"></div>'
			).show();
			/* DOGFOOT HSSHIM 200107 환경설정 필터바 UI 수정 */
			$('#filterContainer').css('width', 'calc(100% - 154px)');
			$('#colSelector').dxSelectBox({
				dataSource: [
					'조회',
					'보고서 작성/배포',
					'데이터 항목 사용',
					'보고서 내려받기'
				],
				value: '조회'
			});
			$('#selectAll').dxButton({
				text: '전체 선택',
				onClick: function() {
					var treeList = $('#userReportList').dxTreeList('instance');
					switch($('#colSelector').dxSelectBox('instance').option('value')) {
						case '조회':
							treeList.forEachNode(function(node) {
								node.data.FLD_SHOW = true;
							});
							break;
						case '보고서 작성/배포':
							treeList.forEachNode(function(node) {
								node.data.FLD_PUBLISH = true;
							});
							break;
						case '데이터 항목 사용':
							treeList.forEachNode(function(node) {
								node.data.FLD_DATAITEM = true;
							});
							break;
						case '보고서 내려받기':
							treeList.forEachNode(function(node) {
								node.data.FLD_EXPORT = true;
							});
							break;
						default: break;
					}
					treeList.refresh(true);
				}
			});
			$('#deselectAll').dxButton({
				text: '전체 해제',
				onClick: function() {
					var treeList = $('#userReportList').dxTreeList('instance');
					switch($('#colSelector').dxSelectBox('instance').option('value')) {
						case '조회':
							treeList.forEachNode(function(node) {
								node.data.FLD_SHOW = false;
							});
							break;
						case '보고서 작성/배포':
							treeList.forEachNode(function(node) {
								node.data.FLD_PUBLISH = false;
							});
							break;
						case '데이터 항목 사용':
							treeList.forEachNode(function(node) {
								node.data.FLD_DATAITEM = false;
							});
							break;
						case '보고서 내려받기':
							treeList.forEachNode(function(node) {
								node.data.FLD_EXPORT = false;
							});
							break;
						default: break;
					}
					treeList.refresh(true);
				}
			});
		},

		/**
		 * Initialize group report authentication select/deselect all functionality.
		 */
		initAuthGroupReportSelectDeselect: function() {
			$('#filterContainer').append(
				'<div id="colSelector"></div>' +
				'<div id="selectAll"></div>' +
				'<div id="deselectAll"></div>'
			).show();
			/* DOGFOOT HSSHIM 200107 환경설정 필터바 UI 수정 */
			$('#filterContainer').css('width', 'calc(100% - 154px)');
			$('#colSelector').dxSelectBox({
				dataSource: [
					'조회',
					'보고서 작성/배포',
					'데이터 항목 사용',
					'보고서 내려받기'
				],
				value: '조회'
			});
			$('#selectAll').dxButton({
				text: '전체 선택',
				onClick: function() {
					var treeList = $('#groupReportList').dxTreeList('instance');
					switch($('#colSelector').dxSelectBox('instance').option('value')) {
						case '조회':
							treeList.forEachNode(function(node) {
								node.data.FLD_SHOW = true;
							});
							break;
						case '보고서 작성/배포':
							treeList.forEachNode(function(node) {
								node.data.FLD_PUBLISH = true;
							});
							break;
						case '데이터 항목 사용':
							treeList.forEachNode(function(node) {
								node.data.FLD_DATAITEM = true;
							});
							break;
						case '보고서 내려받기':
							treeList.forEachNode(function(node) {
								node.data.FLD_EXPORT = true;
							});
							break;
						default: break;
					}
					treeList.refresh(true);
				}
			});
			$('#deselectAll').dxButton({
				text: '전체 해제',
				onClick: function() {
					var treeList = $('#groupReportList').dxTreeList('instance');
					switch($('#colSelector').dxSelectBox('instance').option('value')) {
						case '조회':
							treeList.forEachNode(function(node) {
								node.data.FLD_SHOW = false;
							});
							break;
						case '보고서 작성/배포':
							treeList.forEachNode(function(node) {
								node.data.FLD_PUBLISH = false;
							});
							break;
						case '데이터 항목 사용':
							treeList.forEachNode(function(node) {
								node.data.FLD_DATAITEM = false;
							});
							break;
						case '보고서 내려받기':
							treeList.forEachNode(function(node) {
								node.data.FLD_EXPORT = false;
							});
							break;
						default: break;
					}
					treeList.refresh(true);
				}
			});
		},

		/**
		 * Save user data authentication settings.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handleAuthUserDataSave: function(event) {
			event.preventDefault();
			var selected = $('#userDsList').dxDataGrid('getSelectedRowsData');
			if (selected.length === 0) {
				return;
			}
			var editingDsViewId = (selected[0].DS_VIEW_ID);
			var saveDS = [];
		//	var saveDSRows = $('#dsViewArea').dxTreeList('getSelectedRowsData');
			var saveDSRows = [];
			var recursiveDsRow = $('#userDsViewArea').dxTreeList('getSelectedRowKeys');
			var DstreeListInstance = $('#userDsViewArea').dxTreeList('instance');
			
			var getDsrow = getAllSelectedNodes(DstreeListInstance, recursiveDsRow);
			
			$.each(getDsrow,function(_i,_e){
				if(_e.level != 0){
					saveDSRows.push(_e.data);
				}
			});
			
			//원본 옮겨 담기
			$.each(Auth_Cubes,function(_i,_cube){
				if(_cube.DS_VIEW_ID != editingDsViewId){
					saveDS.push(_cube);
				}
			});
			
			//기존에 생성된 데이터 추가&삭제
			// 20210805 AJKIM 주제영역 저장 오류 수정 dogfoot
//			$.each(saveDSRows,function(_i,_saveDS){
//				$.each(Auth_Cubes,function(_j,_cube){
//					if(typeof _saveDS == 'undefined')
//						return false;
//					if(_saveDS.dsViewId == _cube.DS_VIEW_ID){
//						var obj = {};
//						obj['DS_VIEW_ID'] = _saveDS.dsViewId;
//						obj['CUBE_ID'] = _saveDS.cubeId;
//						saveDS.push(obj);
//						saveDSRows.splice(_i,1);
//		//				return false;
//					}
//				});
//			});
			
			//완전 신규 데이터 추가&삭제
			$.each(saveDSRows,function(_i,_saveDS){
		//		if(_saveDS.dsViewId != editingDsViewId){
					var obj = {};
					obj['DS_VIEW_ID'] = _saveDS.dsViewId;
					obj['CUBE_ID'] = _saveDS.cubeId;
					saveDS.push(obj);
		//		}
			});

			
			var saveDim = [];
		//	var saveDimRow = $('#dsDimensionArea').dxTreeList('getSelectedRowsData');
			var saveDimRow = [];
			var recursiveDimRow = $('#userDsDimensionArea').dxTreeList('getSelectedRowKeys');
			var DimtreeListInstance = $('#userDsDimensionArea').dxTreeList('instance');
			
			var getDimrow = getAllSelectedNodes(DimtreeListInstance, recursiveDimRow);
			
			$.each(getDimrow,function(_i,_e){
				if(_e.level != 0){
					saveDimRow.push(_e.data);
				}
			});
			
			//원본 옮겨 담기
			$.each(Auth_Dim,function(_i,_dim){
				if(_dim.DS_VIEW_ID != editingDsViewId){
					saveDim.push(_dim);
				}
			});
			
			//기존에 생성된 데이터 추가&삭제
			$.each(saveDimRow,function(_i,_saveDim){
				$.each(Auth_Dim,function(_j,_dim){
					if(typeof _saveDim == 'undefined')
						return false;
					if(_dim.DS_VIEW_ID == _saveDim.DS_VIEW_ID){
						var obj = {};
						obj['DS_VIEW_ID'] = _saveDim.DS_VIEW_ID;
						obj['DIM_UNI_NM'] = _saveDim.DIM_UNI_NM;
						saveDim.push(obj);
						saveDimRow.splice(_i,1);
						return false;
					}
				});
			});
			
			//완전 신규 데이터 추가&삭제
			$.each(saveDimRow,function(_j,_saveDim){
				var obj = {};
				obj['DS_VIEW_ID'] = _saveDim.DS_VIEW_ID;
				obj['DIM_UNI_NM'] = _saveDim.DIM_UNI_NM;
				saveDim.push(obj);
			});
			



			var saveMem = [];
			var saveMemRow = [];
			var recursiveMemRow = $('#userMemberArea').dxTreeList('getSelectedRowKeys');
			var MemtreeListInstance = $('#userMemberArea').dxTreeList('instance');
			
			var getMemrow = getAllSelectedNodes(MemtreeListInstance, recursiveMemRow);
			
			$.each(getMemrow,function(_i,_e){
				if(_e.level != 0){
					saveMemRow.push(_e.data);
				}
			});
			
			// 원본 옮겨 담기
			$.each(Auth_Mem, function(_i, _mem) {
				if (_mem.DS_VIEW_ID != editingDsViewId) {
					saveMem.push(_mem);
				}
			});

			// 기존에 생성된 데이터 추가&삭제
			$.each(saveMemRow, function(_j, _saveMem) {
				$.each(Auth_Mem, function(_i, _mem) {
					if (typeof _saveMem == 'undefined')
						return false;
					if (_mem.DS_VIEW_ID == _saveMem.DS_VIEW_ID) {
						var obj = {};
						obj['DIM_UNI_NM'] = _saveMem.DIM_UNI_NM;
						obj['DS_VIEW_ID'] = _saveMem.DS_VIEW_ID;
						obj['HIE_UNI_NM'] = _saveMem.HIE_UNI_NM;
						// obj['KEY_COL'] = _saveMem.KEY_COL;
						obj['MEMBER_NM'] = _saveMem.MEMBER_NM;
						saveMem.push(obj);
						saveMemRow.splice(_j,1);
						return false;
					}
				});
			});
			//완전 신규 데이터 추가&삭제
			$.each(saveMemRow,function(_j,_saveMem){
				var obj = {};
				obj['DIM_UNI_NM'] = _saveMem.DIM_UNI_NM;
				obj['DS_VIEW_ID'] = _saveMem.DS_VIEW_ID;
				obj['HIE_UNI_NM'] = _saveMem.HIE_UNI_NM;
				obj['MEMBER_NM'] = _saveMem.MEMBER_NM;
				saveMem.push(obj);
			});
			
			var dataSetParam;
			if (saveDS.length > 0 || saveDim.length > 0 || saveMem.length > 0) {
				dataSetParam = $.toJSON({
					'Auth_Cubes':saveDS,
					'Auth_Dim':saveDim,
					'Auth_Mem':saveMem
				});
			} else {
				dataSetParam = '';
			}
			var dataParam = {
				userId: $('#userDataSelectTable').dxDataGrid('getSelectedRowKeys')[0],
				NewDataSet: dataSetParam
			}

			
			$.ajax({
				type:"POST",
				url:'./saveAuthUserData.do',
				data: dataParam,
				contentType: "application/x-www-form-urlencoded; charset=UTF-8",
				success:function(_data){
					_data =JSON.parse(_data);

					if(_data.code == 200){
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					}else{
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				}
			});
		},

		/**
		 * Refreshes user data authentication page.
		 * @listens click
		 */
		handleAuthUserDataRefresh: function() {
			$('#userDataSelectTable').dxDataGrid('dispose');
			$('#userDsList').dxDataGrid('dispose');
			$('#userDsViewArea').dxTreeList('dispose');
			$('#userDsDimensionArea').dxTreeList('dispose');
			$('#userMemberArea').dxTreeList('dispose');
			Auth_Cubes = []; 
			Auth_Dim = [];
			Auth_Mem = [];
			initAuthUserData();
		},

		/**
		 * Save group data authentication settings.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handleAuthGroupDataSave: function(event) {
			event.preventDefault();
			var selected = $('#groupDsList').dxDataGrid('getSelectedRowsData');
			if (selected.length === 0) {
				return;
			}
			var editingDsViewId = (selected[0].DS_VIEW_ID);
			var saveDS = [];
		//	var saveDSRows = $('#dsViewArea').dxTreeList('getSelectedRowsData');
			var saveDSRows = [];
			var recursiveDsRow = $('#groupDsViewArea').dxTreeList('getSelectedRowKeys');
			var DstreeListInstance = $('#groupDsViewArea').dxTreeList('instance');
			
			var getDsrow = getAllSelectedNodes(DstreeListInstance, recursiveDsRow);
			
			$.each(getDsrow,function(_i,_e){
				if(_e.level != 0){
					saveDSRows.push(_e.data);
				}
			});
			
			//원본 옮겨 담기
			$.each(Auth_Cubes,function(_i,_cube){
				if(_cube.DS_VIEW_ID != editingDsViewId){
					saveDS.push(_cube);
				}
			});
			
			//기존에 생성된 데이터 추가&삭제
			// 20210805 AJKIM 주제영역 저장 오류 수정 dogfoot
//			$.each(saveDSRows,function(_i,_saveDS){
//				$.each(Auth_Cubes,function(_j,_cube){
//					if(typeof _saveDS == 'undefined')
//						return false;
//					if(_saveDS.dsViewId == _cube.DS_VIEW_ID){
//						var obj = {};
//						obj['DS_VIEW_ID'] = _saveDS.dsViewId;
//						obj['CUBE_ID'] = _saveDS.cubeId;
//						saveDS.push(obj);
//						saveDSRows.splice(_i,1);
//		//				return false;
//					}
//				});
//			});
			
			//완전 신규 데이터 추가&삭제
			$.each(saveDSRows,function(_i,_saveDS){
		//		if(_saveDS.dsViewId != editingDsViewId){
					var obj = {};
					obj['DS_VIEW_ID'] = _saveDS.dsViewId;
					obj['CUBE_ID'] = _saveDS.cubeId;
					saveDS.push(obj);
		//		}
			});

			
			var saveDim = [];
		//	var saveDimRow = $('#dsDimensionArea').dxTreeList('getSelectedRowsData');
			var saveDimRow = [];
			var recursiveDimRow = $('#groupDsDimensionArea').dxTreeList('getSelectedRowKeys');
			var DimtreeListInstance = $('#groupDsDimensionArea').dxTreeList('instance');
			
			var getDimrow = getAllSelectedNodes(DimtreeListInstance, recursiveDimRow);
			
			$.each(getDimrow,function(_i,_e){
				if(_e.level != 0){
					saveDimRow.push(_e.data);
				}
			});
			
			//원본 옮겨 담기
			$.each(Auth_Dim,function(_i,_dim){
				if(_dim.DS_VIEW_ID != editingDsViewId){
					saveDim.push(_dim);
				}
			});
			
			//기존에 생성된 데이터 추가&삭제
			$.each(saveDimRow,function(_i,_saveDim){
				$.each(Auth_Dim,function(_j,_dim){
					if(typeof _saveDim == 'undefined')
						return false;
					if(_dim.DS_VIEW_ID == _saveDim.DS_VIEW_ID){
						var obj = {};
						obj['DS_VIEW_ID'] = _saveDim.DS_VIEW_ID;
						obj['DIM_UNI_NM'] = _saveDim.DIM_UNI_NM;
						saveDim.push(obj);
						saveDimRow.splice(_i,1);
						return false;
					}
				});
			});
			
			//완전 신규 데이터 추가&삭제
			$.each(saveDimRow,function(_j,_saveDim){
				var obj = {};
				obj['DS_VIEW_ID'] = _saveDim.DS_VIEW_ID;
				obj['DIM_UNI_NM'] = _saveDim.DIM_UNI_NM;
				saveDim.push(obj);
			});
			


			var saveMem = [];
			var saveMemRow = [];
			var recursiveMemRow = $('#groupMemberArea').dxTreeList('getSelectedRowKeys');
			var MemtreeListInstance = $('#groupMemberArea').dxTreeList('instance');
			
			var getMemrow = getAllSelectedNodes(MemtreeListInstance, recursiveMemRow);
			
			$.each(getMemrow,function(_i,_e){
				if(_e.level != 0){
					saveMemRow.push(_e.data);
				}
			});
			
			// 원본 옮겨 담기
			$.each(Auth_Mem, function(_i, _mem) {
				if (_mem.DS_VIEW_ID != editingDsViewId) {
					saveMem.push(_mem);
				}
			});

			// 기존에 생성된 데이터 추가&삭제
			$.each(saveMemRow, function(_j, _saveMem) {
				$.each(Auth_Mem, function(_i, _mem) {
					if (typeof _saveMem == 'undefined')
						return false;
					if (_mem.DS_VIEW_ID == _saveMem.DS_VIEW_ID) {
						var obj = {};
						obj['DIM_UNI_NM'] = _saveMem.DIM_UNI_NM;
						obj['DS_VIEW_ID'] = _saveMem.DS_VIEW_ID;
						obj['HIE_UNI_NM'] = _saveMem.HIE_UNI_NM;
						// obj['KEY_COL'] = _saveMem.KEY_COL;
						obj['MEMBER_NM'] = _saveMem.MEMBER_NM;
						saveMem.push(obj);
						saveMemRow.splice(_j,1);
						return false;
					}
				});
			});
			//완전 신규 데이터 추가&삭제
			$.each(saveMemRow,function(_j,_saveMem){
				var obj = {};
				obj['DIM_UNI_NM'] = _saveMem.DIM_UNI_NM;
				obj['DS_VIEW_ID'] = _saveMem.DS_VIEW_ID;
				obj['HIE_UNI_NM'] = _saveMem.HIE_UNI_NM;
				obj['MEMBER_NM'] = _saveMem.MEMBER_NM;
				saveMem.push(obj);
			});
			var dataSetParam;
			if (saveDS.length > 0 || saveDim.length > 0 || saveMem.length > 0) {
				dataSetParam = $.toJSON({
					'Auth_Cubes':saveDS,
					'Auth_Dim':saveDim,
					'Auth_Mem':saveMem
				});
			} else {
				dataSetParam = '';
			}
			var dataParam = {
				groupId: $('#groupDataSelectTable').dxDataGrid('getSelectedRowKeys')[0],
				NewDataSet: dataSetParam
			}

			
			$.ajax({
				type:"POST",
				url:'./saveAuthGroupData.do',
				data: dataParam,
				contentType: "application/x-www-form-urlencoded; charset=UTF-8",
				success:function(_data){
					_data =JSON.parse(_data);

					if(_data.code == 200){
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					}else{
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				}
			});
		},

		/**
		 * Refreshes group data authentication page.
		 * @listens click
		 */
		handleAuthGroupDataRefresh: function() {
			$('#groupDataSelectTable').dxDataGrid('dispose');
			$('#groupDsList').dxDataGrid('dispose');
			$('#groupDsViewArea').dxTreeList('dispose');
			$('#groupDsDimensionArea').dxTreeList('dispose');
			$('#groupMemberArea').dxTreeList('dispose');
			Auth_Cubes = []; 
			Auth_Dim = [];
			Auth_Mem = [];
			initAuthGroupData();
		},
		
		/**
		 * Save user report authentication settings.
		 * @param {MouseEvent} event
		 * @listens click 
		 */
		handleAuthUserReportSave: function(event) {
			event.preventDefault();
			var arr = [];
			var fldArr = [];
			var userObj = {};
			var selected = $('#userReportSelectTable').dxDataGrid('getSelectedRowsData');
			if (selected.length === 0) {
				return;
			}
			userObj['masterObj'] = selected[0]['사용자NO'];
			arr.push(userObj);
			fldArr.push(userObj);
			$('#userReportList').dxTreeList('instance').forEachNode(function(node) {
				var obj = {};
				if (node.data.FLD_SHOW || node.data.FLD_PUBLISH || node.data.FLD_DATAITEM || node.data.FLD_EXPORT) {
					if (node.data.TYPE === 'FOLDER') {
						obj['userNo'] = $('#userReportSelectTable').dxDataGrid('getSelectedRowsData')[0]['사용자NO'];
						obj['fldId'] = node.data.FLD_ID;
						obj['authShow'] = node.data.FLD_SHOW ? 'Y' : 'N';
						obj['authPublish'] = node.data.FLD_PUBLISH ? 'Y' : 'N';
						obj['authDataItem'] = node.data.FLD_DATAITEM ? 'Y' : 'N';
						obj['authExport'] = node.data.FLD_EXPORT ? 'Y' : 'N';
						fldArr.push(obj);
					} else if (node.data.TYPE === 'REPORT') {
						obj['userNo'] = $('#userReportSelectTable').dxDataGrid('getSelectedRowsData')[0]['사용자NO'];
						obj['reportId'] = node.data.FLD_ID;
						obj['fldId'] = node.data.PARENT_FLD_ID;
						obj['authShow'] = node.data.FLD_SHOW ? 'Y' : 'N';
						obj['authPublish'] = node.data.FLD_PUBLISH ? 'Y' : 'N';
						obj['authDataItem'] = node.data.FLD_DATAITEM ? 'Y' : 'N';
						obj['authExport'] = node.data.FLD_EXPORT ? 'Y' : 'N';
						arr.push(obj);
					}
				}
			});


			$.ajax({
				type: "POST",
				url : './saveUserFldAuth.do',
				data:JSON.stringify(fldArr),
				dataType: "json",
				contentType : 'application/json',
				success: function(_data){

					if(_data.code == 200){
						$.ajax({
							type: "POST",
							url : './saveUserReportAuth.do',
							data:JSON.stringify(arr),
							dataType: "json",
							contentType : 'application/json',
							success: function(_data){

								if(_data.code == 200){
									// 2020.01.07 mksong 경고창 UI 변경 dogfoot
									WISE.alert(gMessage.get('config.save.success'),'success');
								}
								else{
									// 2020.01.07 mksong 경고창 UI 변경 dogfoot
									WISE.alert(gMessage.get('config.save.failed'),'error');
								}
							}
						});
					}
					else{
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				}
			});
		},

		/**
		 * Refreshes user report authentication page.
		 * @listens click
		 */
		handleAuthUserReportRefresh: function() {
			gProgressbar.show();
			setTimeout(function() {
				$('#userReportSelectTable').dxDataGrid('dispose');
				$('#userReportList').dxTreeList('dispose');
				initAuthUserReport();
			}, 10);
		},

		/**
		 * Save group report authentication settings.
		 * @param {MouseEvent} event
		 * @listens click 
		 */
		handleAuthGroupReportSave: function(event) {
			event.preventDefault();
			var arr = [];
			var fldArr = [];
			var userObj = {};
			var selected = $('#groupReportSelectTable').dxDataGrid('getSelectedRowsData');
			if (selected.length === 0) {
				return;
			}
			userObj['masterObj'] = selected[0].그룹ID;
			arr.push(userObj);
			fldArr.push(userObj);
			$('#groupReportList').dxTreeList('instance').forEachNode(function(node) {
				var obj = {};
				if (node.data.FLD_SHOW || node.data.FLD_PUBLISH || node.data.FLD_DATAITEM || node.data.FLD_EXPORT) {
					if (node.data.TYPE === 'FOLDER') {
						obj['grpId'] = $('#groupReportSelectTable').dxDataGrid('getSelectedRowsData')[0].그룹ID;
						obj['fldId'] = node.data.FLD_ID;
						obj['authShow'] = node.data.FLD_SHOW ? 'Y' : 'N';
						obj['authPublish'] = node.data.FLD_PUBLISH ? 'Y' : 'N';
						obj['authDataItem'] = node.data.FLD_DATAITEM ? 'Y' : 'N';
						obj['authExport'] = node.data.FLD_EXPORT ? 'Y' : 'N';
						fldArr.push(obj);
					} else if (node.data.TYPE === 'REPORT') {
						obj['grpId'] = $('#groupReportSelectTable').dxDataGrid('getSelectedRowsData')[0].그룹ID;
						obj['reportId'] = node.data.FLD_ID;
						obj['fldId'] = node.data.PARENT_FLD_ID;
						obj['authShow'] = node.data.FLD_SHOW ? 'Y' : 'N';
						obj['authPublish'] = node.data.FLD_PUBLISH ? 'Y' : 'N';
						obj['authDataItem'] = node.data.FLD_DATAITEM ? 'Y' : 'N';
						obj['authExport'] = node.data.FLD_EXPORT ? 'Y' : 'N';
						arr.push(obj);
					}
				}
			});


			$.ajax({
				type: "POST",
				url : './saveGrpFldAuth.do',
				data:JSON.stringify(fldArr),
				dataType: "json",
				contentType : 'application/json',
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(_data){

					if(_data.code == 200){
						$.ajax({
							type: "POST",
							url : './saveGrpReportAuth.do',
							data:JSON.stringify(arr),
							dataType: "json",
							contentType : 'application/json',
							success: function(_data){

								if(_data.code == 200){
									// 2020.01.07 mksong 경고창 UI 변경 dogfoot
									WISE.alert(gMessage.get('config.save.success'),'success');
								}
								else{
									// 2020.01.07 mksong 경고창 UI 변경 dogfoot
									WISE.alert(gMessage.get('config.save.failed'),'error');
								}
							},
							complete: function() {
								gProgressbar.hide();
							}
						});
					}
					else{
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				}
			});
		},

		/**
		 * Refreshes group report authentication page.
		 * @listens click
		 */
		handleAuthGroupReportRefresh: function() {
			gProgressbar.show();
			setTimeout(function() {
				$('#groupReportSelectTable').dxDataGrid('dispose');
				$('#groupReportList').dxTreeList('dispose');
				initAuthGroupReport();
			}, 10);
		},

		/**
		 * Save dataset authentication settings.
		 * @param {MouseEvent} event
		 * @listens click 
		 */
		handleAuthUserDatasetSave: function(event) {
			event.preventDefault();
			var selectedUser = $('#userDatasetSelectTable').dxDataGrid('getSelectedRowsData')[0];
			if (selectedUser) {
				var selected = [];
				$('#userDatasetResult .dx-treeview-node.dx-state-selected').each(function(i, node) {
					selected.push($(node).data('item-id'));
				});
				$.ajax({
					url: WISE.Constants.context + '/report/saveUserDatasetAuth.do',
					method: 'POST',
					data: {
						selectedUser: selectedUser['사용자NO'],
						selectedFolders: selected
					},
					success: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					},
					error: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				});
			}
		},

		/**
		 * Refreshes user report authentication page.
		 * @listens click
		 */
		handleAuthUserDatasetRefresh: function() {
			gProgressbar.show();
			setTimeout(function() {
				$('#userDatasetSelectTable').dxDataGrid('dispose');
				$('#userDatasetResult').dxTreeView('dispose');
				initAuthUserDataset();
			}, 10);
		},

		/**
		 * Save group dataset authentication settings.
		 * @param {MouseEvent} event
		 * @listens click 
		 */
		handleAuthGroupDatasetSave: function(event) {
			event.preventDefault();
			var selectedGroup = $('#groupDatasetSelectTable').dxDataGrid('getSelectedRowsData')[0];
			if (selectedGroup) {
				var selected = [];
				$('#groupDatasetResult .dx-treeview-node.dx-state-selected').each(function(i, node) {
					selected.push($(node).data('item-id'));
				});
				$.ajax({
					url: WISE.Constants.context + '/report/saveGrpDatasetAuth.do',
					method: 'POST',
					data: {
						selectedGroup: selectedGroup['그룹ID'],
						selectedFolders: selected
					},
					success: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					},
					error: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				});
			}
		},

		/**
		 * Refreshes group report authentication page.
		 * @listens click
		 */
		handleAuthGroupDatasetRefresh: function() {
			gProgressbar.show();
			setTimeout(function() {
				$('#groupDatasetSelectTable').dxDataGrid('dispose');
				$('#groupDatasetResult').dxTreeView('dispose');
				initAuthGroupDataset();
			}, 10);
		},
		handleAuthUserDsSave: function(event) {
			event.preventDefault();
			var selectedUser = $('#userDsSelectTable').dxDataGrid('getSelectedRowsData')[0];
			if (selectedUser) {
				var selected = $('#userDsResult').dxDataGrid('getSelectedRowKeys');
				$.ajax({
					url: WISE.Constants.context + '/report/saveUserDsAuth.do',
					method: 'POST',
					data: {
						selectedUser: selectedUser['사용자NO'],
						selectedDs: selected
					},
					success: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					},
					error: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				});
			}
		},
		handleAuthGroupDsSave: function(event) {
			event.preventDefault();
			var selectedGroup = $('#groupDsSelectTable').dxDataGrid('getSelectedRowsData')[0];
			if (selectedGroup) {
				var selected = $('#groupDsResult').dxDataGrid('getSelectedRowKeys');
				$.ajax({
					url: WISE.Constants.context + '/report/saveGrpDsAuth.do',
					method: 'POST',
					data: {
						selectedGroup: selectedGroup['그룹NO'],
						selectedDs: selected
					},
					success: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					},
					error: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				});
			}
		},
		//20210705 AJKIM 메뉴 권한 추가 dogfoot
		handleAuthGroupWbSave: function(event) {
			event.preventDefault();
			var selectedGroup = $('#groupWbSelectTable').dxDataGrid('getSelectedRowsData')[0];
			if (selectedGroup) {
				var items =  $("#groupWbResult").dxTreeView("instance").option('items')
				var data = {};
				var tempData = {};
				$.each(items, function(key, value){
				    if(value.parentId){
				    	tempData[value.id] = value.selected? value.visible? true : false : false;
				    	if(tempData[value.id]){
				    		data[value.parentId] = true;
				    	}
				    }
				    else
				    	data[value.id] = value.selected? true : false;
				});
				data.DS_DETAIL = JSON.stringify(tempData);
				
				$.ajax({
					url: WISE.Constants.context + '/report/saveGrpWbAuth.do',
					method: 'POST',
					data: {
						selectedGroup: selectedGroup['그룹ID'],
						data: JSON.stringify(data),
						resetConfig: (DevExpress.VERSION.substr(0, 2) == '18'? $("#groupWbResult").dxTreeView("instance").getSelectedNodesKeys().length : $("#groupWbResult").dxTreeView("instance").getSelectedNodeKeys().length) == 0? "true" : "false"
					},
					success: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					},
					error: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				});
			}
		},
		handleAuthUserWbSave: function(event) {
			event.preventDefault();
			var selectedUser = $('#userWbSelectTable').dxDataGrid('getSelectedRowsData')[0];
			if (selectedUser) {
				var items =  $("#userWbResult").dxTreeView("instance").option('items')
				var data = {};
				var tempData = {};
				$.each(items, function(key, value){
					if(value.parentId){
				    	tempData[value.id] = value.selected? value.visible? true : false : false;
				    	if(tempData[value.id]){
				    		data[value.parentId] = true;
				    	}
				    }
				    else
				    	data[value.id] = value.selected? true : false;
				});
				data.DS_DETAIL = JSON.stringify(tempData);
				
				$.ajax({
					url: WISE.Constants.context + '/report/saveUserWbAuth.do',
					method: 'POST',
					data: {
						selectedUser: selectedUser['사용자NO'],
						data: JSON.stringify(data),
						resetConfig: (DevExpress.VERSION.substr(0, 2) == '18'? $("#userWbResult").dxTreeView("instance").getSelectedNodesKeys().length : $("#userWbResult").dxTreeView("instance").getSelectedNodeKeys().length) == 0? "true" : "false"
					},
					success: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					},
					error: function() {
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				});
			}
		},

		/**
		 * Refreshes group report authentication page.
		 * @listens click
		 */
		handleAuthGroupWbRefresh: function() {
			gProgressbar.show();
			setTimeout(function() {
				$('#groupWbSelectTable').dxDataGrid('dispose');
				$('#groupWbResult').dxTreeView('dispose');
				initAuthGroupWebApp();
			}, 10);
		},
		handleAuthUserWbRefresh: function() {
			gProgressbar.show();
			setTimeout(function() {
				$('#userWbSelectTable').dxDataGrid('dispose');
				$('#userWbResult').dxTreeView('dispose');
				initAuthUserWebApp();
			}, 10);
		},
		handleAuthGroupDsRefresh: function() {
			gProgressbar.show();
			setTimeout(function() {
				$('#groupDsSelectTable').dxDataGrid('dispose');
				$('#groupDsResult').dxDataGrid('dispose');
				initAuthGroupDs();
			}, 10);
		},
		handleAuthUserDsRefresh: function() {
			gProgressbar.show();
			setTimeout(function() {
				$('#userDsSelectTable').dxDataGrid('dispose');
				$('#userDsResult').dxDataGrid('dispose');
				initAuthUserDs();
			}, 10);
		},
	}
})();