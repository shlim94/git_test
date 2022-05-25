/**
 * 데이터집합 ERD 팝업 컴포넌트 클래스
 * Dataset ERD popup component class.
 */
WISE.libs.Dashboard.DatasetErdDesigner = function() {
    var self = this;
    this.state = {
        dsId: null,
		dsIdList: [],
		dsList: [],
        dsType: '',
		selectClauses: [],
		fromClauses: [],
		whereClauses: [],
		orderClauses: [],
		onConfirm: null,
		shapes:[],
		connectors:[],
		relateionTblList:{},
    };
    this.container = null;
    this.components = {
		dsSelect: null,
        erdDiagram: null,
		erdConfirmBtn : null,
        erdCancelBtn: null,
        dsSetConnectInfo:null,
    };

    /**
     * Update component state.
     */
    this.setState = function(state, action) {
        $.extend(self.state, state);
    }
    this.renderCheck = false;

    /**
     * Renders erd diagram component.
     */
    this.render = function(props) {
        self.setState(props);

        $('body').remove('#dsErdDesingerPopup').append('<div id="dsErdDesingerPopup" />');
        self.container = $('#dsErdDesingerPopup').dxPopup({
            showCloseButton: false,
            showTitle: true,
            title: '관계 편집',
            visible: true,
            closeOnOutsideClick: false,
            width: '90vw',
            height: 'calc(100% - 20px)',
            maxWidth: 1600,
            maxHeight: 880,
            onShowing: function () {
				self.components = {
					dsSelect: dsSelect(),
					erdDiagram: erdDiagram(),
					erdConfirmBtn: erdConfirmBtn(),
					erdCancelBtn: erdCancelBtn(),
					dsSetConnectInfo: dsSetConnectInfo(),
					dsDelConnect: dsDelConnect(),
				};
				
				loadDataItem().then(importData);
            },
            contentTemplate: function() {
                return  '<div style="height: 100%; width: 100%;">' +
                            '<div style="width:100%;height:45px;margin-bottom:10px;">'+
							//'<div id="dsSelect" style="width:300px;margin-bottom:10px;margin-right:10px;display: inline-block;"></div>' +
							'<div id="dsSetConnectInfo"  style="margin-top:7px;margin-right:10px;display: inline-block;"></div>' +
							'<div id="dsDelConnect"  style="margin-top:7px;margin-right:10px;display: inline-block;"></div>' +
							'</div>'+
                            // erd diagram component
                            '<div id="erdDiagram"></div>' +
                            '<div class="modal-footer" style="height: 45px; padding-bottom: 0;">' + 
                                '<div class="row center">' + 
                                    // confirm button component (button)
                                    '<a id="erdConfirmBtn" class="btn positive ok-hide" href="#">확인</a>' + 
                                    // cancel button component (button)
                                    '<a id="erdCancelBtn" class="btn positive ok-hide" href="#">취소</a>' + 
                                '</div>' + 
                            '</div>' + 
                        '</div>';
            },
        }).dxPopup('instance');

		setInterval(function(){
			$('.dx-diagram-toolbox-popup .dx-overlay-content').css('width','240px');
			$('.dx-diagram-toolbox-popup .dx-accordion').css('width','280px');
			$('.dx-diagram-toolbox-input').css('width','230px');
		},1000);
    }

    /**
     * Close erd diagram popup.
     */
    function onConfirmClose() {
		var exportJson = JSON.parse(self.components.erdDiagram.export());
		var fromClauses = [];
		self.state.connectors = [];
		$.each(exportJson.connectors,function(i,d){
			if(d.beginConnectionPointIndex != -1 && d.endConnectionPointIndex != -1 && 
			    d.beginConnectionPointIndex != undefined && d.endConnectionPointIndex != undefined){
				var fkInfoArr = d.beginItemKey.split("_");
				var pkInfoArr = d.endItemKey.split("_");
				var fkTblNm = d.beginItemKey.substr(("table_"+fkInfoArr[1]+"_").length, d.beginItemKey.length);
				var pkTblNm = d.endItemKey.substr(("table_"+pkInfoArr[1]+"_").length, d.endItemKey.length);
				var fkColNm = "";
				var pkColNm = "";
				var fkDataSetSrc = Number(fkInfoArr[1]);
				var pkDataSetSrc = Number(pkInfoArr[1]);
				var tblJoinType;

				$.each(self.state.tables,function(j,t){
					if(fkInfoArr[1]==t.DS_ID && fkTblNm==t.ID) {
						$.each(t.Columns,function(k,c){
							if(k==Math.floor(d.beginConnectionPointIndex/2)) {
								fkColNm = c.Column_Name;
							}
						})
					}
					if(pkInfoArr[1]==t.DS_ID && pkTblNm==t.ID) {
						$.each(t.Columns,function(k,c){
							if(k==Math.floor(d.endConnectionPointIndex/2)) {
								pkColNm = c.Column_Name;
							}
						})
					}
				});
                //tblJoinType = self.state.relateionTblList["FK_"+fkTblNm+"_"+pkTblNm+"_"+fkDataSetSrc+"_"+pkDataSetSrc].JOIN_TYPE
				$.each(WISE.util.Object.toArray(self.state.relateionTblList),function(_g,_z){
					if(_z["FK_"+fkTblNm+"_"+pkTblNm+"_"+fkDataSetSrc+"_"+pkDataSetSrc]){
                        tblJoinType = _z["FK_"+fkTblNm+"_"+pkTblNm+"_"+fkDataSetSrc+"_"+pkDataSetSrc].JOIN_TYPE;
					}
				});
				var fromItem = {
					"CONST_NM": "FK_"+fkTblNm+"_"+pkTblNm,
					"FK_TBL_NM": fkTblNm,
					"FK_COL_NM": fkColNm,
					"PK_TBL_NM": pkTblNm,
					"PK_COL_NM": pkColNm,
					"JOIN_TYPE": typeof tblJoinType === "undefined" ? "INNER JOIN":tblJoinType,
					"JOIN_SET_OWNER": "SYSTEM",
					"FK_DATASET_SRC": fkDataSetSrc,
					"PK_DATASET_SRC": pkDataSetSrc
				}
                d.CONST_NM = "FK_"+fkTblNm+"_"+pkTblNm+"_"+fkColNm+"_"+pkColNm
				var connectorItem = {
					"CONST_NM": "FK_"+fkTblNm+"_"+pkTblNm+"_"+fkColNm+"_"+pkColNm,
					"FK_TBL_NM": fkTblNm,
					"FK_COL_NM": fkColNm,
					"PK_TBL_NM": pkTblNm,
					"PK_COL_NM": pkColNm,
					"FK_DATASET_SRC": fkDataSetSrc,
					"PK_DATASET_SRC": pkDataSetSrc,
					"TBL_BEGIN_POINT": d.beginConnectionPointIndex,
					"TBL_END_POINT" : d.endConnectionPointIndex,
					"TBL_POINTS"	: d.points,
				}
                
				
				fromClauses.push(fromItem);
				self.state.connectors.push(d);
			}
		});
		
		self.state.onConfirm(fromClauses);
		self.state.shapes = exportJson.shapes;
		
		self.components.erdDiagram.dispose();
		self.components.erdConfirmBtn.dispose();
		self.components.erdCancelBtn.dispose();
        self.container.hide();
    }

    /**
     * Close erd diagram popup.
     */
    function onCancelClose() {
		self.components.erdDiagram.dispose();
		self.components.erdConfirmBtn.dispose();
		self.components.erdCancelBtn.dispose();
        self.container.hide();
    }

	function dsSelect() {
		return $("#dsSelect").dxSelectBox({
			dataSource: self.state.dsList,
            displayExpr: 'DS_NM',
			valueExpr: 'DS_ID',
			value: self.state.dsId,
			onValueChanged: function(e) {
				self.setState({dsId: e.value});
				self.state.dsIdList.push(e.value);
				self.setState({dsIdList: _.uniq(self.state.dsIdList)});
				loadDataItem();
			},
		})
	}
	

	function dsSetConnectInfo(show,id) {
		return $("#dsSetConnectInfo").dxButton({
			icon: "plus",
			text:"관계 추가",
			visible: typeof show === "undefined"? false : show,
			onClick:function(){
				var exportJson = JSON.parse(self.components.erdDiagram.export());

        	    //document.getElementById("dsSetConnectInfo").click();
                self.openErdConnectPopup(id,exportJson,true);
			}
		}).dxButton('instance');
	}

	function dsDelConnect(show,id) {
		return $("#dsDelConnect").dxButton({
			icon: "minus",
			text:"관계 삭제",
			visible: typeof show === "undefined"? false : show,
			onClick:function(){
				var exportJson = JSON.parse(self.components.erdDiagram.export());
                $.each(exportJson.connectors,function(i,d){
					if(id === d.key){
					   exportJson.connectors.splice(i,1);
					   //self.components.erdDiagram.import(JSON.stringify(_erdJson));
					    self.components.erdDiagram.import(JSON.stringify(exportJson));		
                        self.setGridFromTables();
					}
				});
               
        	    //document.getElementById("dsSetConnectInfo").click();
                //self.openErdConnectPopup(id,exportJson,true);
			}
		}).dxButton('instance');
	}
	

    function erdDiagram() {
        return $("#erdDiagram").dxDiagram({
	        //fullScreen: true,
			showGrid: false,
			height: '680px',
	        simpleView: true,
	        units: 'cm',
	        viewUnits: 'cm',
	        contextMenu: {
	            enabled: true
	        },
	        contextToolbox: {
	            enabled: false
	        },
	        historyToolbar: {
                commands: [{name: "undo", icon: "undo"}, "redo"]
			}, 
	        propertiesPanel: {
	            visibility: 'disabled',
                //visibility: 'auto',
	            tabs: [
					{
						groups: [ { 
							title: "Line Style", 
							commands: ["lineStyle", "lineColor","lineWidth"] 
						}, 
						{ 
							title: "Connector", 
							commands: ["connectorLineType", "connectorLineStart", "connectorLineEnd"] 
						}]
					}
				]
	        },
	        mainToolbar: {
	            visible: false,
	            commands: [
	                { name: "clear", icon: "clearsquare", text: "전체 삭제" },
	                { name: "export", icon: "clearsquare", text: "내보내기" },
	                { name: "showJson", icon: "clearsquare", text: "내용보기" },
	            ]
	        },
			toolbox: {
				    visibility:"disabled",
					groups: []
			},
			defaultItemProperties: {
				connectorLineStart: "none",
				connectorLineEnd: "filledTriangle",
				//connectorLineType: "straight",
				style: "fill: #4e71f2; stroke: #4e71f2",
				textStyle: "font-weight: bold; text-decoration: underline"
			},
			autoZoomMode:'fitContent',
	        onCustomCommand: function(e) {
				console.log("onCustomCommand:",e);
	            if(e.name === "clear") {
	                var result = DevExpress.ui.dialog.confirm("정말 삭제하시겠습니까?", "확인");
	                result.done(
	                    function(dialogResult) {
	                        if(dialogResult) {
	                            e.component.import("");
	                        }
	                    }
	                );
	            } else if(e.name === 'export') {
	                console.log(e.component.exportTo('png',function(){}));
	            } else if(e.name === 'showJson') {
	                console.log(e.component.export());
	            }

	            var exportJson = JSON.parse(e.component.export());
	        	 
	        },
	        viewToolbar: {
				commands: ["zoomLevel", "fullScreen"]
			}, 
	        onOptionChanged:function(_e,_d){
	        	console.log(_e)
        	
	        },
	        onSelectionChanged:function(_e){
	        	 self.setGridFromTables();
	        	 
	        	 var  conCheck = true;
	        	 var exportJson = JSON.parse(_e.component.export());
	        	 $.each(exportJson.connectors,function(i,d){
					if(d.beginConnectionPointIndex == undefined || d.endConnectionPointIndex == undefined || d.beginConnectionPointIndex == -1 || d.endConnectionPointIndex == -1){
                        erdAlert();
                        conCheck = false;
					}
	        	 });

				if(_e.items.length === 0 || _e.items[0].itemType == "shape"){
					dsSetConnectInfo(false,undefined);
					dsDelConnect(false,undefined);
				}else if(_e.items[0].itemType == "connector"){
					dsSetConnectInfo(true,_e.items[0].id);
                    dsDelConnect(true,_e.items[0].id);
                    if(conCheck){
                        var conData = self.setConnectorData(_e.items[0].id,exportJson);
                        self.setGridFromTables(conData);	
                    }
                }
	        },
	        onItemClick:function(_e){
	        	if(_e.item.itemType=="connector"){
	        	    var exportJson = JSON.parse(_e.component.export());
                    dsSetConnectInfo(true,_e.item.id);
                    dsDelConnect(true,_e.item.id);
                    var conData = self.setConnectorData(_e.item.id,exportJson);
                    self.setGridFromTables(conData);
                }else{
                	dsSetConnectInfo(false,undefined);
                	dsDelConnect(false,undefined);
                	self.setGridFromTables();
                }
	        },
	        onItemDblClick:function(_e){
	        	if(_e.item.itemType=="connector"){
	        	    var exportJson = JSON.parse(_e.component.export());
                    self.openErdConnectPopup(_e.item.id,exportJson,true);	
                }
	        },
	        onContentReady:function(_e){
                console.log(_e);
            }
	    }).dxDiagram('instance');
        
        function linkStyleExpr(obj) {
			return { "stroke": "#444444" };
		}
    }
    
    

	function loadDataItem(){
		return new Promise(function(resolve, reject){
			$.ajax({
		        method: 'POST',
		        url: WISE.Constants.context + '/report/getMultiDatasetTableColumns.do',
		        data: {
		            dsid: self.state.dsIdList.join(","),
		            type: self.state.dsType,
		            /*dogfoot ERD 전체 테이블이 아닌 선택된 테이블만 가져오도록 수정 shlim 20210402*/
		            selectedTableList : self.getSelectedTableNmList().join(","),
		        },
	            beforeSend: function() {
	                gProgressbar.show();
	            },
	            complete: function() {
	                gProgressbar.hide();
	            },
				success: function(data) {
					var toolbox = {
						visibility:"disabled",
						groups: []
					};
					$.each(self.state.dsIdList,function(i,d1){
						$.each(self.state.dsList,function(j,d2){
							if(d1 == d2.DS_ID) {
								toolbox.groups.push({
									category: 'tables_'+d2.DS_ID,
									title: d2.DS_NM,
									displayMode: "texts"
								});
							}
						});
					});
					toolbox.groups.reverse();
					self.components.erdDiagram.option('toolbox', toolbox);
					var tables = [];
					var duplicheck=false;
					$.each(data,function(i,d){
						if(d.TYPE=='TABLE') {
							$.each(self.state.selectClauses,function(k,l){
								if(d.TBL_NM === l.TBL_NM && d.DATASET_SRC === l.DATASET_SRC){
									duplicheck = false;
									$.each(tables,function(j,t){
										if(l.DATASET_SRC==t.DS_ID && l.TBL_NM==t.ID) {
											duplicheck = true;
										} 
									});
									if(!duplicheck){
										tables.push({
											"ID": d.id, 
											"DS_ID": d.DATASET_SRC,
											"Table_Name": d.TBL_NM,
											"Table_Caption": d.TBL_CAPTION,
											"Table_Text": d.text,
											"Columns": [] 
										});
									}
								}
							})			
						} else {
							$.each(tables,function(j,t){
								if(d.DATASET_SRC==t.DS_ID && d.parent==t.ID) {
									t.Columns.push({
										"Column_Name": d.COL_NM,
										"Column_Caption": d.COL_CAPTION,
										"Column_Text": d.text,
										"Primary_Key": d.PK_YN
									});
								} 
							});
						}
					});

                    tables = tables.filter(function(element, index) {
                               

						return tables.indexOf(element) === index;
					});

					self.state.tables = tables;

					String.prototype.width = function(font) {
					  var f = font || '12px arial',
						  o = $('<div></div>')
								.text(this)
								.css({'position': 'absolute', 'float': 'left', 'white-space': 'nowrap', 'visibility': 'hidden', 'font': f})
								.appendTo($('body')),
						  w = o.width();

					  o.remove();

					  return w;
					}
					self.components.erdDiagram.option('customShapes', tables.map(function(tab){
			            var defaultHeightVal = 1;
			            var connections = [];
			            var colCnt = tab.Columns.length;
			            defaultHeightVal = colCnt * 0.655 + 1;
			            for(var i=0;i<colCnt;i++) {
			                connections.push({x: 0, y: (i+2)/(colCnt+1.8), aaa: 'bbbb'});
			                connections.push({x: 1, y: (i+2)/(colCnt+1.8), aaa: 'bbbb'});
			            }
			            return {
			                category: "tables_"+tab.DS_ID,
			                type: "table_" + tab.DS_ID + "_" + tab.ID,
			                baseType: "rectangle",
			                defaultText: tab.Table_Text,
			                defaultWidth: tab.Table_Name.width()/30 > 4.5 ? tab.Table_Name.width()/30 : 4.5,
			                minWidth: tab.Table_Name.width()/30 > 4.5 ? tab.Table_Name.width()/30 : 4.5,
			                defaultHeight: defaultHeightVal,
			                maxHeight: defaultHeightVal,
			                minHeight: defaultHeightVal,
			                allowEditText: false,
			                allowResize: true,
			                connectionPoints: connections,
							template: function(item, $container){
								var arrTableItem = item.type.split("_");
								var dsId = arrTableItem[1];
								var columns;
								var tbl_nm_tmp = item.type.replace("table_","");
								var tbl_nm = tbl_nm_tmp.substring(tbl_nm_tmp.indexOf("_")+1);
								$.each(self.state.tables,function(i,d){
									if(dsId==d.DS_ID && tbl_nm==d.ID) {
										columns = d.Columns;
									}
								});
								 var content = "<svg>";

								    content += "<rect  width='100%' height='30' style='fill:#4e71f2; stroke:#4e71f2'>";
						            content += "</rect>";
								    
						            content += "<text x='10' y='20' style='fill:#fff'>" + item.text + "</text>";
						            content += "<line x1='0' y1='30' x2='100%' y2='30' style='fill:#999999; stroke:#4e71f2'></line>";
						        
					            
								if((navigator.userAgent.indexOf("MSIE") != -1 ) || (!!document.documentMode == true )) //IF IE > 10
								{
									$.each(columns,function(i,d){
										content += "<svg class='svg-hover'>";
										content += "<rect class='svg-hover' id='"+item.id+'_'+d.Column_Text+"' x='3' y='"+(i*24.3+35)+"' width='96%' height='20' style='fill:#none;stroke:none'>";
							            content += "</rect>";
							            if(d.Primary_Key == 1) {
											content += "<image xlink:href='"+WISE.Constants.context + "/resources/main/images/ico_password.png"+"' x='5' y='"+(i*24.1+40)+"' width=15 height=15/>";
										}else{
//											content += "<image xlink:href='"+WISE.Constants.context + "/resources/main/images/ico_document.svg"+"' x='5' y='"+(i*24.1+40)+"' width=15 height=15/>";
											content += "<image xlink:href='"+WISE.Constants.context + "/resources/main/images/ico_dbtable.png"+"' x='5' y='"+(i*24.1+40)+"' width=15 height=15/>";
										}
						                content += "<text class='svg-hover' x='25' y='"+(i*24.3+50)+"'>" + d.Column_Text + "</text>";
						                content += "</svg>";
//						                content += "<text x='25' y='"+(i*24.1+50)+"'>" + d.Column_Text + "</text>";
						            });
								}else{
									
									content += '<foreignobject class="node" x="3" y="35" width="97%" height="95%">'
						            content += "<div xmlns='http://www.w3.org/1999/xhtml' id="+item.type +'_grid'+"  width='95%' height='95%'>";
									content += '</div>';
						            content += ' </foreignobject>';
								} 
						                
					            content += "</svg>";
					            
					            $container.append(content);
					        }
			            }
			        }));
			        
					resolve();
				}
			});
		});
	}
	
	function importData() {
		var loadJson = 
		{
			"page": {
				"width": 16782,
				"height": 23812,
				"pageColor": -1,
				"pageWidth": 8391,
				"pageHeight": 11906,
				"pageLandscape": false,
				"units": 1
			},
			"shapes": [],
			"connectors": []
		};
		
		var heightTableShape = [
			938,1310,1681,2052,2424,2795,3166,3538,3909,4280,
			4652,5023,5394,5766,6137,6508,6880,7251,7622,7994
		];

		var tables = self.getSelectedTable();
		var fromClauses = self.getFromClauses();
		$.each(tables,function(i,d){
			var colCnt = 0;
			$.each(self.state.tables,function(j,t){
				if(d.DATASET_SRC==t.DS_ID && d.TABLE_NAME==t.ID) {
					colCnt = t.Columns.length;
				}
			});
            var tblx,tbly,style,tblwidth,tblheight
            $.each(self.state.shapes,function(j,t){
				if(d.TABLE_NAME==t.text) {
					tblx = t.x;
					tbly = t.y;
					style = t.style
					tblwidth = t.width
					tblheight = t.height
				}
			});
			
			loadJson.shapes.push({
				"key": "table_"+d.DATASET_SRC+"_"+d.TABLE_NAME,
				"locked": false,
				"zIndex": 0,
				"type": "table_"+d.DATASET_SRC+"_"+d.TABLE_NAME,
				"text": d.TABLE_NAME,
				"x": typeof tblx != 'undefined'? tblx : 6611+(i*4000),
				"y": typeof tbly != 'undefined'? tbly : 8126,
				"width":  typeof tblwidth != 'undefined'? tblwidth : 2551,
				"height": typeof tblheight != 'undefined'? tblheight : (colCnt<21)?heightTableShape[colCnt-1]:500+(colCnt*350),
				"style" : typeof style != 'undefined'? style: {"stroke": "#999999"},
			});
		});

		$.each(fromClauses,function(i,d){
			var beginConnectionPointIndex
			,endConnectionPointIndex
			,tblPoints
			,tblStyle
			,tblProperties
			$.each(self.state.tables,function(j,t){
				if(d.FK_DATASET_SRC==t.DS_ID && d.FK_TBL_NM==t.ID) {
					$.each(t.Columns,function(k,c){
						if(d.FK_COL_NM==c.Column_Name) {
							beginConnectionPointIndex = ((k+1)*2)-1;
						}
					});
				}
				if(d.PK_DATASET_SRC==t.DS_ID && d.PK_TBL_NM==t.ID) {
					$.each(t.Columns,function(k,c){
						if(d.PK_COL_NM==c.Column_Name) {
							endConnectionPointIndex =  ((k+1)*2)-2;
						}
					});
				}
			});

			$.each(self.state.connectors,function(j,t){
				
				if(d.CONST_NM+"_"+d.FK_COL_NM+"_"+d.PK_COL_NM == t.CONST_NM) {
					beginConnectionPointIndex = typeof t.beginConnectionPointIndex != 'undefined'? t.beginConnectionPointIndex :beginConnectionPointIndex;
					endConnectionPointIndex =  typeof t.endConnectionPointIndex != 'undefined'? t.endConnectionPointIndex :endConnectionPointIndex;
					tblPoints = typeof t.points != "undefined" ? t.points : [{"x": 1, "y": 1},{"x": 1, "y": 1},]
					tblStyle = typeof t.style != "undefined" ? t.style : {"fill":"#4e71f2","stroke": "#4e71f2"};
					tblProperties = typeof t.properties != "undefined" ? t.properties :{"endLineEnding": 3 };
				}
			});

			$.each(self.state.tableDesigner.state.relations,function(_i,relation){
				if (d.FK_DATASET_SRC === relation.DATASET_SRC && d.FK_TBL_NM === relation.FK_TBL_NM && d.PK_TBL_NM === relation.PK_TBL_NM
				&& d.FK_COL_NM === relation.FK_COL_NM && d.PK_COL_NM === relation.PK_COL_NM) {
					tblStyle = {"stroke": "#999999"};
				}
			})
            

            
			
			loadJson.connectors.push({
				"key": i.toString(),
				"locked": false,
				"zIndex": 0,
				"points": typeof tblPoints != 'undefined' ? tblPoints:[
					{"x": 1, "y": 1},
					{"x": 1, "y": 1},
				],
				"beginItemKey": "table_"+d.FK_DATASET_SRC+"_"+d.FK_TBL_NM,
				"beginConnectionPointIndex": beginConnectionPointIndex,
				"endItemKey": "table_"+d.PK_DATASET_SRC+"_"+d.PK_TBL_NM,
				"endConnectionPointIndex": endConnectionPointIndex,
				"tableColumns": d.FK_TBL_NM,
				"style" : typeof tblStyle != "undefined" ? tblStyle : {"fill":"#4e71f2","stroke": "#4e71f2"},
				"properties": typeof tblProperties != "undefined" ? tblProperties :{"endLineEnding": 3 },
			});
		});

		self.components.erdDiagram.import(JSON.stringify(loadJson));		
		 
        
        self.setGridFromTables();

        
	}


	
	this.resetERD = function() {
		var _erdJson =  self.components.erdDiagram.export()
    	$.each(_erdJson.connectors,function(i,d){
			if(d.beginConnectionPointIndex == undefined || d.endConnectionPointIndex == undefined || d.beginConnectionPointIndex == -1 || d.endConnectionPointIndex == -1){
			   _erdJson.connectors.splice(i,1);
			   self.components.erdDiagram.import(JSON.stringify(_erdJson));
			   self.setGridFromTables();
			}
		 });
    }

    this.getFromClauses = function(){
    	var fromClauses = [];
    	if(typeof self.state.fromClauses.CONST_NM != 'undefined') {
    		fromClauses.push(self.state.fromClauses);
    	} else {
    		fromClauses = self.state.fromClauses
    	}
    	return fromClauses;
    }
    
    this.getSelectedTable = function(){
    	var tables = [];
    	$.each(self.state.selectClauses,function(i,d){
			tables.push({TABLE_NAME: d.TBL_NM, DATASET_SRC: d.DATASET_SRC});
		});
		
    	var fromClauses = self.getFromClauses();
    	
		$.each(fromClauses,function(i,d){
			tables.push({TABLE_NAME: d.FK_TBL_NM, DATASET_SRC: d.FK_DATASET_SRC});
			tables.push({TABLE_NAME: d.PK_TBL_NM, DATASET_SRC: d.PK_DATASET_SRC});
		});
    	var whereClauses = [];
    	if(typeof self.state.whereClauses.TBL_NM != 'undefined') {
    		whereClauses.push(self.state.whereClauses);
    	} else {
    		whereClauses = self.state.whereClauses
    	}
		$.each(whereClauses,function(i,d){
			tables.push({TABLE_NAME: d.TBL_NM, DATASET_SRC: d.DATASET_SRC});
		});
    	var orderClauses = [];
    	if(typeof self.state.orderClauses.TBL_NM != 'undefined') {
    		orderClauses.push(self.state.orderClauses);
    	} else {
    		orderClauses = self.state.orderClauses
    	}
		$.each(orderClauses,function(i,d){
			tables.push({TABLE_NAME: d.TBL_NM, DATASET_SRC: d.DATASET_SRC});
		});
		tables = tables.filter(function(arr, index, self){
			var findTblNm = _.findIndex(self,function(t){
				return t.TABLE_NAME === arr.TABLE_NAME && t.DATASET_SRC === arr.DATASET_SRC; 
			});
	    	return index === findTblNm;
		});

		return tables;
    }
    
    
    this.getSelectedTableNmList = function(){
    	var tables = [];
    	$.each(self.state.selectClauses,function(i,d){
			tables.push(d.TBL_NM);
		});
		
    	var fromClauses = self.getFromClauses();
    	
		$.each(fromClauses,function(i,d){
			tables.push(d.FK_TBL_NM);
			tables.push(d.PK_TBL_NM);
		});
    	var whereClauses = [];
    	if(typeof self.state.whereClauses.TBL_NM != 'undefined') {
    		whereClauses.push(self.state.whereClauses);
    	} else {
    		whereClauses = self.state.whereClauses
    	}
		$.each(whereClauses,function(i,d){
			tables.push(d.TBL_NM);
		});
    	var orderClauses = [];
    	if(typeof self.state.orderClauses.TBL_NM != 'undefined') {
    		orderClauses.push(self.state.orderClauses);
    	} else {
    		orderClauses = self.state.orderClauses
    	}
		$.each(orderClauses,function(i,d){
			tables.push( d.TBL_NM );
		});
		tables = tables.filter(function(arr, index, self){
			var findTblNm = _.findIndex(self,function(t){
				return t === arr; 
			});
	    	return index === findTblNm;
		});

		return tables;
    }

    this.setGridFromTables = function(_conData) {
    	$.each(self.state.tables,function(i,d){
			$("#"+"table_" + d.DS_ID + "_" + d.ID+'_grid').dxDataGrid({
				dataSource: d.Columns,
				columns: [{
					dataField : "Primary_Key",
					width : '15%',
					alignment:'center',
					cellTemplate: function (container, options) {
						if(options.value === "1"){
							$("<div style='width:15px; height:15px;margin-right:5px'>")
							.append($("<img>", { "src": WISE.Constants.context + "/resources/main/images/ico_password.png" }))
							.appendTo(container);	
						}else{
							$("<div style='width:15px; height:15px;margin-right:5px'>")
							.append($("<img>", { "src": WISE.Constants.context + "/resources/main/images/ico_dbtable.png" }))
							.appendTo(container);
						}
					}
				},{
					dataField : "Column_Text",
					width : '80%'
				}],
				showBorders: false,
				showScrollbar:'never',
				showRowLines: false,
				hoverStateEnabled: true,
				showColumnHeaders:false,
				//width:"95%",
				scrolling: {
					useNative: false 
				},
				onCellPrepared: function(e) {
					 if (e.rowType === "data") {
						   if (e.column.dataField != "Primary_Key" && e.key.Primary_Key  == "1")  { //condition where the column requires the coloring
								 e.cellElement[0].style.backgroundColor = "yellow"; //set the background color based on the data
						   }
						   var sdsd = d
						   if(typeof _conData != "undefined" ){
						       $.each(_conData,function(_conDataIndex,_data){
						           if(_data.dsId === d.DS_ID && _data.tableNm === d.ID &&
						                _data.colNm === e.key.Column_Name && _data.colIndex === e.rowIndex){
						           	    e.cellElement[0].style.border = "dotted"
                                   }
						       })   
						   }
					 }
				},
				onRowPrepared: function(e) {  
						e.rowElement.css({ height: 24.3});  
						e.rowElement.find('td').css({ 'padding':3.3})
				 }  
			});
			$("#"+"table_" + d.DS_ID + "_" + d.ID+'_grid').css('font-size', '13px')
		});
    }

    this.setConnectorData = function(_conKey,_exportJson){
            var fkInfoArr,pkInfoArr,fkTblNm ,pkTblNm ,fkColNm ,pkColNm,fkDataSetSrc
            ,pkDataSetSrc,tblconstNM
    	    
            var columnsData =[]    
        	,table = [];
        
			$.each(self.getSelectedTable(),function(i,d){
				$.each(self.state.tables,function(j,t){
					if(d.DATASET_SRC==t.DS_ID && d.TABLE_NAME==t.ID) {
						table.push(t);
					}
				});
			})

    	    $.each(_exportJson.connectors,function(i,d){
        		if(d.key == _conKey){
        			var _fkInfoArr = d.beginItemKey.split("_");
					var _pkInfoArr = d.endItemKey.split("_");
					var _fkTblNm = d.beginItemKey.substr(("table_"+_fkInfoArr[1]+"_").length, d.beginItemKey.length);
					var _pkTblNm = d.endItemKey.substr(("table_"+_pkInfoArr[1]+"_").length, d.endItemKey.length);

					tblconstNM = "FK_"+_fkTblNm+"_"+_pkTblNm;
        		}
        	});

        	$.each(_exportJson.connectors,function(i,d){
        		    
				var _fkInfoArr = d.beginItemKey.split("_");
				var _pkInfoArr = d.endItemKey.split("_");
				var _fkTblNm = d.beginItemKey.substr(("table_"+_fkInfoArr[1]+"_").length, d.beginItemKey.length);
				var _pkTblNm = d.endItemKey.substr(("table_"+_pkInfoArr[1]+"_").length, d.endItemKey.length);
					
        		if(d.key == _conKey){
        			fkInfoArr = d.beginItemKey.split("_");
					pkInfoArr = d.endItemKey.split("_");
					fkTblNm = d.beginItemKey.substr(("table_"+fkInfoArr[1]+"_").length, d.beginItemKey.length);
					pkTblNm = d.endItemKey.substr(("table_"+pkInfoArr[1]+"_").length, d.endItemKey.length);
					fkColNm = "";
					pkColNm = "";
					fkDataSetSrc = Number(fkInfoArr[1]);
					pkDataSetSrc = Number(pkInfoArr[1]);

					$.each(table,function(j,t){
						if(fkInfoArr[1]==t.DS_ID && fkTblNm==t.ID) {
							$.each(t.Columns,function(k,c){
								if(k==Math.floor(d.beginConnectionPointIndex/2)) {
									fkColNm = c.Column_Name;
									fkIndex = k;
								}
							});
						}
						if(pkInfoArr[1]==t.DS_ID && pkTblNm==t.ID) {
							$.each(t.Columns,function(k,c){
								if(k==Math.floor(d.endConnectionPointIndex/2)) {
									pkColNm = c.Column_Name;
									pkIndex = k;
								}
							})
						}
					});
        		}
        	});
        	
        	return [{
        		        "tableNm":fkTblNm,
        		        "colNm":fkColNm,
        		        "colIndex":fkIndex,
        		        "dsId":fkDataSetSrc
        	        },
        	        {
        	        	"tableNm":pkTblNm,
        	            "colNm":pkColNm,
        		        "colIndex":pkIndex,
        		        "dsId":pkDataSetSrc
        	        }];
        	
    }

    this.openErdConnectPopup = function(_conKey,_exportJson,_readonly){
        
        var fkInfoArr,pkInfoArr,fkTblNm ,pkTblNm ,fkColNm ,pkColNm,fkColList,pkColList ,fkDataSetSrc
            ,pkDataSetSrc,tblJoinType,tblconstNM,relationClauses,deleterelClauses,updateConfirm
        
        var columnsData =[]    
        	,table = [];
        
        $.each(self.getSelectedTable(),function(i,d){
        	$.each(self.state.tables,function(j,t){
    			if(d.DATASET_SRC==t.DS_ID && d.TABLE_NAME==t.ID) {
    				table.push(t);
    			}
    		});
        })
        
       
        
        if(_readonly){
        	$.each(_exportJson.connectors,function(i,d){
        		if(d.key == _conKey){
        			var _fkInfoArr = d.beginItemKey.split("_");
					var _pkInfoArr = d.endItemKey.split("_");
					var _fkTblNm = d.beginItemKey.substr(("table_"+_fkInfoArr[1]+"_").length, d.beginItemKey.length);
					var _pkTblNm = d.endItemKey.substr(("table_"+_pkInfoArr[1]+"_").length, d.endItemKey.length);

					tblconstNM = "FK_"+_fkTblNm+"_"+_pkTblNm;
        		}
        	});

        	$.each(_exportJson.connectors,function(i,d){
        		    
				var _fkInfoArr = d.beginItemKey.split("_");
				var _pkInfoArr = d.endItemKey.split("_");
				var _fkTblNm = d.beginItemKey.substr(("table_"+_fkInfoArr[1]+"_").length, d.beginItemKey.length);
				var _pkTblNm = d.endItemKey.substr(("table_"+_pkInfoArr[1]+"_").length, d.endItemKey.length);
					
        		if(tblconstNM == "FK_"+_fkTblNm+"_"+_pkTblNm){
        			fkInfoArr = d.beginItemKey.split("_");
					pkInfoArr = d.endItemKey.split("_");
					fkTblNm = d.beginItemKey.substr(("table_"+fkInfoArr[1]+"_").length, d.beginItemKey.length);
					pkTblNm = d.endItemKey.substr(("table_"+pkInfoArr[1]+"_").length, d.endItemKey.length);
					fkColNm = "";
					pkColNm = "";
					fkDataSetSrc = Number(fkInfoArr[1]);
					pkDataSetSrc = Number(pkInfoArr[1]);

					$.each(table,function(j,t){
						if(fkInfoArr[1]==t.DS_ID && fkTblNm==t.ID) {
							$.each(t.Columns,function(k,c){
								if(k==Math.floor(d.beginConnectionPointIndex/2)) {
									fkColNm = c.Column_Name;
								}
							});
							fkColList = t.Columns
						}
						if(pkInfoArr[1]==t.DS_ID && pkTblNm==t.ID) {
							$.each(t.Columns,function(k,c){
								if(k==Math.floor(d.endConnectionPointIndex/2)) {
									pkColNm = c.Column_Name;
								}
							})
							pkColList = t.Columns
						}
					});

					$.each(self.state.fromClauses,function(j,t){
						if(t.CONST_NM == "FK_"+fkTblNm+"_"+pkTblNm){
							tblJoinType=t.JOIN_TYPE;
						}
					});
					
					columnsData.push({
						"FkColumn": fkColNm,
						"PkColumn": pkColNm,
						"connectorKey":d.key,
						"fkTable": fkTblNm,
						"pkTable": pkTblNm,
						"fkDataSetSrc": fkDataSetSrc,
						"pkDataSetSrc": pkDataSetSrc,
						"fkColList": fkColList,
						"pkColList": pkColList,
					})
        		}
        	});
        }

    	$('body').remove('#dsErdConnectPopup').append('<div id="dsErdConnectPopup" />');
		$('#dsErdConnectPopup').dxPopup({
			showCloseButton: false,
			showTitle: true,
			title: '연결 편집',
			visible: true,
			closeOnOutsideClick: false,
			width: '40vw',
			height: 'calc(50% - 20px)',
			maxWidth: 1600,
			maxHeight: 880,
			onShowing: function () {

			},
			contentTemplate: function() {
				return  '<div style="height: 100%; width: 100%;">' +
							'<div style="width:100%;float:left;padding:3px">'+
								'<div style="width:50%;float:left;">'+
									'<div class="dx-field" style="padding-top:10px;">원본(외래키) 테이블</div>'+
								'</div>'+
								'<div style="width:50%;float:left;">'+
									'<div class="dx-field" style="padding-top:10px;">대상(기본키) 테이블</div>'+
								'</div>'+
							'</div>'+

							'<div style="width:100%;float:left;padding:3px">'+
								'<div style="width:50%;float:left;">'+
									'<div id="table_fk" class="dx-field" style="width:80%;float:left;">원본(외래키) 테이블</div>'+
								'</div>'+
								'<div style="width:50%;float:left;">'+
									'<div id="table_pk" class="dx-field" style="width:80%;float:left;">대상(기본키) 테이블</div>'+
								'</div>'+
							'</div>'+

							/*'<div style="width:100%;float:right;padding:3px; padding-bottom: 10px;"">'+
							    '<div id="removeConnection" style="float:right;margin-right:5px;"></div>' +
							    '<div id="addConnection" style="float:right;margin-right:5px;"></div>' +
							'</div>'+*/

							'<div style="width:100%;height:200px;float:left;padding:3px">'+
								'<div id="erdDiagramgrid"></div>' +
							'</div>'+

							'<div style="width:100%;float:right;padding:3px; padding-bottom: 10px;"">'+
							    '<div id="joinSelectBox" style="float:right;"></div>' +
							    '<div style="float:right;padding-top:10px;padding-right:10px;">테이블 연결 방법</div>' +
							'</div>'+

							'<div class="modal-footer" style="height: 45px; padding-bottom: 0;">' + 
                                '<div class="row center">' + 
                                    // confirm button component (button)
                                    '<a id="connectConfirmBtn" class="btn positive ok-hide" href="#">확인</a>' + 
                                    // cancel button component (button)
                                    '<a id="connectCancelBtn" class="btn positive ok-hide" href="#">취소</a>' + 
                                '</div>' + 
                            '</div>' + 
						'</div>';
			},
		}).dxPopup('instance');

		

		$("#erdDiagramgrid").dxDataGrid({
			dataSource: columnsData,
			height:190,
			editing: {
	            mode: 'cell',
                allowUpdating: true,
                allowAdding: true,
                allowDeleting:true,
	            texts: {
	                confirmDeleteMessage: ''
                },
                useIcons: true,
            },
			columns: [{
				caption: '원본 컬럼',
				dataField : 'FkColumn',
				width : '50%',
				alignment:'center',
				lookup:{
                    dataSource: fkColList,
                    displayExpr: "Column_Name",
                    valueExpr: "Column_Name"
                }
			},{
				caption: '대상 컬럼',
				dataField : "PkColumn",
				width : '50%',
				alignment:'center',
				lookup:{
                    dataSource: pkColList,
                    displayExpr: "Column_Name",
                    valueExpr: "Column_Name"
                }
			},{
				dataField:'connectorKey'
			},{
				dataField:'fkTable'
			},{
				dataField:'pkTable'
			},{
				dataField:'fkDataSetSrc'
			},{
				dataField:'pkDataSetSrc'
			},{
				dataField:'fkColList'
			},{
				dataField:'pkColList'
			}],
			onRowInserted:function(e){
				relationClauses = e.component.getDataSource().items();
			},
			onRowInserting:function(e){
				e.data.fkTable = fkTblNm;
				e.data.pkTable = pkTblNm;
				e.data.fkDataSetSrc = fkDataSetSrc;
				e.data.pkDataSetSrc = pkDataSetSrc;
				e.data.fkColList = fkColList;
				e.data.pkColList = pkColList;

				relationClauses = e.component.getDataSource().items();
			},
			onRowRemoving:function(e){
				deleterelClauses = e.data;
			},
			onRowUpdated: function(e) {
                relationClauses = e.component.getDataSource().items(); 
            },
            onRowUpdating: function(e) {
            	e.key.fkTable = fkTblNm;
				e.key.PkTable = pkTblNm;
				e.key.fkDataSetSrc = fkDataSetSrc;
				e.key.pkDataSetSrc = pkDataSetSrc;
				e.key.fkColList = fkColList;
				e.key.pkColList = pkColList;
				
                relationClauses = e.component.getDataSource().items(); 
            },
            onEditorPreparing: function(e) {
				
			},
			showBorders: false,
			showScrollbar:'never',
			showRowLines: false,
			hoverStateEnabled: true,
			showColumnHeaders:true,
			scrolling: {
				useNative: false 
			},
			onRowPrepared: function(e) {  
					
			 }  
		}).dxDataGrid('instance');

		$("#table_fk").dxSelectBox({
			dataSource: table,
            displayExpr: 'Table_Name',
			valueExpr: 'ID',
			value: fkTblNm,
			readOnly:_readonly,
			onValueChanged: function(e) {
				console.log(e)
				$.each(self.state.tables,function(j,t){
					if(e.value==t.ID) {
						fkColList = t.Columns;
						fkTblNm = t.ID;
						fkDataSetSrc = t.DS_ID;
						$("#erdDiagramgrid").dxDataGrid('instance').option("columns",
							[{
								caption: '원본 컬럼',
								dataField : 'FkColumn',
								width : '50%',
								alignment:'center',
								lookup:{
									dataSource: fkColList,
									displayExpr: "Column_Name",
									valueExpr: "Column_Name"
								}
							},{
								caption: '대상 컬럼',
								dataField : "PkColumn",
								width : '50%',
								alignment:'center',
								lookup:{
									dataSource: pkColList,
									displayExpr: "Column_Name",
									valueExpr: "Column_Name"
								}
							},{
								dataField:'connectorKey'
							},{
								dataField:'fkTable'
							},{
								dataField:'pkTable'
							},{
								dataField:'fkDataSetSrc'
							},{
								dataField:'pkDataSetSrc'
							},{
								dataField:'fkColList'
							},{
								dataField:'pkColList'
							}]
						);
					}
				});
			},
		})

		$("#table_pk").dxSelectBox({
			dataSource: table,
            displayExpr: 'Table_Name',
			valueExpr: 'ID',
			value: pkTblNm,
			readOnly:_readonly,
			onValueChanged: function(e) {
				$.each(self.state.tables,function(j,t){
					if(e.value==t.ID) {
						pkColList = t.Columns;
                        pkTblNm = t.ID;
                        pkDataSetSrc = t.DS_ID;
						$("#erdDiagramgrid").dxDataGrid('instance').option("columns",
							[{
								caption: '원본 컬럼',
								dataField : 'FkColumn',
								width : '50%',
								alignment:'center',
								lookup:{
									dataSource: fkColList,
									displayExpr: "Column_Name",
									valueExpr: "Column_Name"
								}
							},{
								caption: '대상 컬럼',
								dataField : "PkColumn",
								width : '50%',
								alignment:'center',
								lookup:{
									dataSource: pkColList,
									displayExpr: "Column_Name",
									valueExpr: "Column_Name"
								}
							},{
								dataField:'connectorKey'
							},{
								dataField:'fkTable'
							},{
								dataField:'pkTable'
							},{
								dataField:'fkDataSetSrc'
							},{
								dataField:'pkDataSetSrc'
							},{
								dataField:'fkColList'
							},{
								dataField:'pkColList'
							}]
						);
					}
				});
			},
		})

		$("#joinSelectBox").dxSelectBox({
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
            displayExpr: 'caption',
			valueExpr: 'value',
			value: tblJoinType == undefined ? 'INNER JOIN' : tblJoinType,
			width:150,
			onValueChanged: function(e) {
				tblJoinType = e.value
			},
		})

		

		$('#connectConfirmBtn').dxButton({
            text: '확인',
            type: 'normal',
            onClick: function(){
                updateConfirm= false;
				$.each(relationClauses,function(j,relkey){
					if(relkey.FkColumn == undefined || relkey.PkColumn == undefined){
						updateConfirm = true;
						return false;
					}
					if(relkey.connectorKey == undefined){
						var beginconPointindex,endconPointindex;
                        var max = _exportJson.connectors.reduce(function(previous, current) { 
                            return previous.key > current.key ? previous.key:current.key; 
                        });

                        var addconjson = {
							"key": typeof max ==="object" ? "1" :(parseInt(max)+1).toString(),
							"locked": false,
							"zIndex": 0,
							"points": typeof tblPoints != 'undefined' ? tblPoints:[
								{"x": 1, "y": 1},
								{"x": 1, "y": 1},
							],
							"beginItemKey": "table_"+relkey.fkDataSetSrc+"_"+relkey.fkTable,
							"beginConnectionPointIndex": "",
							"endItemKey": "table_"+relkey.pkDataSetSrc+"_"+relkey.pkTable,
							"endConnectionPointIndex": "",
							"tableColumns": "",
							"style" : typeof tblStyle != "undefined" ? tblStyle : {"stroke": "#4e71f2"},
							"properties": typeof tblProperties != "undefined" ? tblProperties :{"endLineEnding": 3 },
						}
                        
                        
                         $.each(_exportJson.shapes,function(k,c){
							if(c.key == "table_"+relkey.fkDataSetSrc+"_"+relkey.fkTable) {
								beginconPointindex = c.x
							}

							if(c.key == "table_"+relkey.pkDataSetSrc+"_"+relkey.pkTable) {
								endconPointindex = c.x
							}
						});

                        $.each(relkey.fkColList,function(k,c){
							if(relkey.FkColumn == c.Column_Name) {
								var kidx = k;
								if(kidx==0){
									if(beginconPointindex < endconPointindex ){
										addconjson.beginConnectionPointIndex = 1
									}else{
										addconjson.beginConnectionPointIndex = kidx
									}
								}else{
									if(beginconPointindex < endconPointindex){
										addconjson.beginConnectionPointIndex = (kidx*2 +1);
									}else{
										addconjson.beginConnectionPointIndex = kidx*2;
									}

								}

							}
						});

						$.each(relkey.pkColList,function(k,c){
							if(relkey.PkColumn == c.Column_Name) {
								var kidx = k;
								if(kidx==0){
									if(beginconPointindex > endconPointindex){
										addconjson.endConnectionPointIndex = 1
									}else{
										addconjson.endConnectionPointIndex = kidx
									}
								}else{
									if(beginconPointindex > endconPointindex){
										addconjson.endConnectionPointIndex = (kidx*2 +1);
									}else{
										addconjson.endConnectionPointIndex = kidx*2;
									}

								}

							}
						});	

                        _exportJson.connectors.push(addconjson)
					}else{
						$.each(_exportJson.connectors,function(i,d){
							if(d.key == relkey.connectorKey){

								$.each(relkey.fkColList,function(k,c){
									if(relkey.FkColumn == c.Column_Name) {
										var kidx = k;
										if(kidx==0){
											if(d.beginConnectionPointIndex%2 == 1){
												d.beginConnectionPointIndex = 1
											}else{
												d.beginConnectionPointIndex = kidx
											}
										}else{
											if(d.beginConnectionPointIndex%2 == 1){
												d.beginConnectionPointIndex = (kidx*2 +1);
											}else{
												d.beginConnectionPointIndex = kidx*2;
											}

										}

									}
								});

								$.each(relkey.pkColList,function(k,c){
									if(relkey.PkColumn == c.Column_Name) {
										var kidx = k;
										if(kidx==0){
											if(d.endConnectionPointIndex%2 == 1){
												d.endConnectionPointIndex = 1
											}else{
												d.endConnectionPointIndex = kidx
											}
										}else{
											if(d.endConnectionPointIndex%2 == 1){
												d.endConnectionPointIndex = (kidx*2 +1);
											}else{
												d.endConnectionPointIndex = kidx*2;
											}

										}
									}
								});	
                                var tblStyle;
								$.each(self.state.tableDesigner.state.relations,function(_i,relation){
									if (relkey.fkDataSetSrc === relation.DATASET_SRC && relkey.fkTable === relation.FK_TBL_NM && relkey.pkTable === relation.PK_TBL_NM
									&& relkey.FkColumn === relation.FK_COL_NM && relkey.PkColumn === relation.PK_COL_NM) {
										tblStyle = {"stroke": "#999999"};
									}
								})

								d.style  = typeof tblStyle === "undefined" ? {"stroke": "#4e71f2"} : tblStyle
							}
						});
					}	
				});

				$.each(WISE.util.Object.toArray(deleterelClauses),function(_delidx,_delinfo){
					$.each(_exportJson.connectors,function(i,d){
						if(d.key === _delinfo.connectorKey){
						   _exportJson.connectors.splice(i,1);
						}
					 });
				});
				$.each(self.state.fromClauses,function(_fromC,_fromD){
					if(tblconstNM === _fromD.CONST_NM && fkDataSetSrc === _fromD.FK_DATASET_SRC && 
					pkDataSetSrc === _fromD.PK_DATASET_SRC){
                        _fromD.JOIN_TYPE = typeof tblJoinType === "undefined" ? "INNER JOIN" : tblJoinType
					}
				})
				
                self.state.relateionTblList[tblconstNM+"_"+fkDataSetSrc+"_"+pkDataSetSrc] = {
                	CONST_NM : tblconstNM,
					FK_DATASET_SRC : fkDataSetSrc,
					PK_DATASET_SRC : pkDataSetSrc,
					JOIN_TYPE : typeof tblJoinType === "undefined" ? "INNER JOIN" : tblJoinType,
                }

			    if(updateConfirm){
                    WISE.alert("대상 및 원본 컬럼을 지정해주세요");
			    }else{
					self.components.erdDiagram.import(JSON.stringify(_exportJson));
					self.setGridFromTables();
					$('#dsErdConnectPopup').dxPopup('instance').hide()
			    }
               
            }
        }).dxButton('instance');


		$('#connectCancelBtn').dxButton({
            text: '취소',
            type: 'normal',
            onClick: function(){
            	$('#dsErdConnectPopup').dxPopup('instance').hide()
            }
        }).dxButton('instance');
    }
    
    function erdAlert(obj) {

        $('body').remove('#alert-container-erd').append('<div id="alert-container-erd" class="alert-container" style="width:330px"></div>');
	
		$bodyErd = $('body');
		$windowErd = $(window);

		$AlertErd = $('#alert-container-erd');

		var contentHtml = '	<div class="modal-inner">';
		contentHtml += '		<div class="modal-body">';
		contentHtml += '			<div class="alert-inner">';
		contentHtml += '				<strong class="alert-strong"></strong>';
		contentHtml += '				<p class="alertContent" style="width:100%"></p>';
		contentHtml += '			</div>';
		contentHtml += '		</div>';
		contentHtml += '		<div class="modal-footer">';
		contentHtml += '			<div class="row center">';
		contentHtml += '				<a href="#" class="btn close ok green">확인</a>';
		contentHtml += '			</div>';
		contentHtml += '		</div>';
		contentHtml += '	</div>';
		contentHtml += '	</div>';

		$('#alert-container-erd').dxPopup({
			width:300,
			height:'auto',
			visible:true,
			showTitle:false,
			onContentReady: function(){
				gDashboard.fontManager.setFontConfigForEditText('alert-container-erd');
			},
			contentTemplate: function() {
				return contentHtml;
			},
			onHiding:function(e){
				console.log(e);
				var exportJson = JSON.parse(self.components.erdDiagram.export());
				$.each(exportJson.connectors,function(i,d){
					if(d.beginConnectionPointIndex == undefined || d.endConnectionPointIndex == undefined || d.beginConnectionPointIndex == -1 || d.endConnectionPointIndex == -1){
					   $('.dx-item-content.dx-toolbar-item-content').find(".dx-icon.dx-icon-undo").parent().parent().click();
					}
				});
			}
		});

		$AlertErdPopup = $('#alert-container-erd').dxPopup('instance');
        
        

		function Alert(text, state, _options){
			if(text===undefined || !text) {
				return false;
			}
			$AlertErd.removeClass("success");
			$AlertErd.removeClass("error");
			$AlertErd.removeClass("alert");

			$AlertErdPopup.option('onShowing', function(){
				
			});
            
            $okErd = $AlertErd.find('.ok');
            $alertErdStrong = $('.alert-strong');
			$alertErdContent = $('.alertContent');

			$exitErd = $AlertErd.find('.exit');
            
            $okErd.off('click').on('click',function(e){
			  e.preventDefault();
			  $AlertErdPopup.hide();
			});

			$okErd.removeClass('positive');
			$okErd.removeClass('red');
			$okErd.removeClass('green');

			$exitErd.css('display','none');

			$alertErdStrong.empty();
			
			$AlertErd.addClass("alert");
			$okErd.addClass('green');
			$alertErdStrong.append('알림 !');
			

			$alertErdContent.empty();
			$alertErdContent.append(text);
		}

		Alert("잘못된 연결 입니다.")

						
		return 
    }
    /**
     * confirm button component (button)
     */
    function erdConfirmBtn() {
        return $('#erdConfirmBtn').dxButton({
            text: '확인',
            type: 'normal',
            onClick: onConfirmClose
        }).dxButton('instance');
    }

    /**
     * cancel button component (button)
     */
    function erdCancelBtn() {
        return $('#erdCancelBtn').dxButton({
            text: '취소',
            type: 'normal',
            onClick: onCancelClose
        }).dxButton('instance');
    }
}