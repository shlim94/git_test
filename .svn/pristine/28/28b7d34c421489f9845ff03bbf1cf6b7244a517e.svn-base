/*
 * Table Binding Version
 * */
WISE.libs.Dashboard.item.SpreadsheetManager = function() {
	var self = this;
	this.reportId;
	this.sheets;
	this.spreadJS;
	this.sheetArea;
	this.queryComleteCount = 0;
	this.GC;
	this.blob = null;
	this.saveParam;
	this.bindingXY = [];
	this.bindingColumn = 0;
	this.bindingRow = 0;
	
	this.init = function(){
		if(self.reportId == undefined) {
			self.reportId ="";
		}
		
		var SheetId = document.getElementById("ss"+self.reportId);
		if(SheetId.contentWindow.GC && SheetId.contentWindow.designer.wrapper.spread){
			self.GC = SheetId.contentWindow.GC;
			self.spreadJS = SheetId.contentWindow.designer.wrapper.spread;
			self.sheetArea = self.GC.Spread.Sheets.SheetArea;
			self.spreadJS.options.grayAreaBackColor = 'white';
		}

		self.spreadJS.getActiveSheet().addColumns(self.spreadJS.getActiveSheet().getRowCount(self.sheetArea.viewport), 100);
		self.spreadJS.getActiveSheet().addRows(self.spreadJS.getActiveSheet().getRowCount(self.sheetArea.viewport), 10000);

		//self.spreadJS.getActiveSheet().addColumns(self.spreadJS.getActiveSheet().getRowCount(self.sheetArea.viewport), 20);
		//self.spreadJS.getActiveSheet().addRows(self.spreadJS.getActiveSheet().getRowCount(self.sheetArea.viewport), 20);
		// SheetID만 사용하게되서 필요없어진 기능 
		// CS에서 Spread 보고서 저장시 Sheet ID가 0,1이 아닌 Sheet1,Sheet2로 되어있어서 
		// SheetName을 Key로 사용하는줄 알고 만든 기능이지만 향후 이벤트 리스너 필요시 활용가능한 코드이기 때문에 주석처리
		/* Sheet이름 변경시 datasetInformation에 연동(이벤트 리스너 사용 예)
		 *  
		self.spreadJS.bind(self.GC.Spread.Sheets.Events.SheetNameChanged, function (sender, args) {
		    if(!_.isUndefined(gDashboard.dataSourceManager.datasetInformation)){
		    	$.each(gDashboard.dataSourceManager.datasetInformation, function(_id, _ds) {
		    		if(args.oldValue == _ds['SHEET_ID']){
		    			gDashboard.dataSourceManager.datasetInformation[_id].SHEET_ID = args.newValue;
		    		}
				});
		    } 
		});
		*/
	}
	
	//보고서 열때 XML에서 xy 정보 가져오기
	this.setReportXml = function(_xml){
		$.each(_xml.EXCEL_XML.SHEET_ELEMENT,function(_i,_d){
			if(_d.START_POS == undefined){
				_d.START_POS = 'A1';
			}			
			self.setXYtoColumnRow(_d.START_POS, _d.SHEET_ID);			
		});
	};
	
	//보고서 저장할때 XML에 xy 정보 저장
	this.getReportXml = function(){		
		var result= '<EXCEL_XML><FILE_EXT_ELEMENT><FILE_EXT>xlsx</FILE_EXT></FILE_EXT_ELEMENT><SHEET_ELEMENT>';
		$.each(gDashboard.dataSourceManager.datasetInformation ,function(_i, _d){
			result +='<VISIBLE_SHEET><SHEET_ID>'+_d.SHEET_ID+'</SHEET_ID><VISIBLE>Y</VISIBLE><SHEET_NM>'+_d.SHEET_NM+'</SHEET_NM><START_POS>'+self.bindingXY[_d.SHEET_ID]+'</START_POS></VISIBLE_SHEET>'
		});		
		result += '</SHEET_ELEMENT></EXCEL_XML>';		
		return result;
	};
	
	this.setXYtoColumnRow = function(_xy,_id){		
		if(self.bindingXY.length > 1){
			$.each(self.bindingXY, function(_i, _d){
				if(_d == _id){
					delete self.bindingXY[_d];
				}
			})
		}
		self.bindingXY[_id] = _xy;
		self.bindingColumn =  Number(_xy.replace(/[^0-9]/g,''))-1;
		self.bindingRow = self.fromLetters(_xy.replace(/[0-9]/g,""));	
	};
	
	// ABCDEF... -> 숫자로 변환
	this.fromLetters = function(str){
	    var out = 0, len = str.length, pos = len, result = 0;
	    while (--pos > -1) {
	        out += (str.charCodeAt(pos) - 64) * Math.pow(26, len - 1 - pos);
	    }	    
	    if(Number(out) >= 0){
	    	result = Number(out)-1;
	    }	    
	    return result;
	}
	
	// 데이터 집합 연동 -> Sheet명 Lookup Item 
	this.sheetNameData = function(){
		var dataSheetNameJson;
		var sheetNameData = [];
		for(var i = 0 ; i < self.spreadJS.getSheetCount(); i++){
			dataSheetNameJson = new Object();
			dataSheetNameJson.sheetNames = self.spreadJS.sheets[i].name();
			sheetNameData.push(dataSheetNameJson);
		}
		return sheetNameData; //default value setting
	}
	
	//tbchoi 데이터 바인딩 시 헤더 변경을 위한 함수 20200204 (Table Binding 사용시 필요 없음)
	this.getJsonKey2ColInfos = function(_dataSource){
		if(_.isEmpty(_dataSource)) return;
		var key = Object.keys(_dataSource[0]);
		var str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		var disName='';
		var colInfos =[];
		var dataSourceHearder = {};
		$.each(key,function(_i,_val){
			if(_i < str.length){
				disName = str.charAt(_i);
			}else if(_i < (str.lengthx2)){
				disName = 'A' + str.charAt(_i - 25);
			}else{
				disName = 'B' + str.charAt(_i - 50);
			}
			colInfos.push({name:key[_i] ,displayName:disName});
			dataSourceHearder[key[_i]] = key[_i];
		});
		return {colInfos:colInfos, dataSourceHearder:dataSourceHearder};
	}
	
	this.getJsonKey2ColInfosTable = function(_dataSource){
		if(_.isEmpty(_dataSource)) return;
		var key = Object.keys(_dataSource[0]);
		var str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		var disName='';
		var colInfos =[];
		var dataSourceHearder = {};
		$.each(key,function(_i,_val){
            var tableColumn1 = new self.GC.Spread.Sheets.Tables.TableColumn();
			if(_i < str.length){
				disName = str.charAt(_i);
			}else if(_i < (str.lengthx2)){
				disName = 'A' + str.charAt(_i - 25);
			}else{
				disName = 'B' + str.charAt(_i - 50);
			}
			tableColumn1.name(key[_i]);
            tableColumn1.dataField(key[_i]);
			colInfos.push(tableColumn1);
			dataSourceHearder[key[_i]] = key[_i];
		});
		return {colInfos:colInfos, dataSourceHearder:dataSourceHearder};
	}
	
	this.getTempRow = function(_row, _data){
		var result = _data;
		if(_row > 0){
			for(var i = 0 ; i < _row ; i++){
				_data.unshift([{}]);
			}			
			result =  _data;
		}
		return result;
	}
	
	this.record = function(_data){			
		for(var key in _data){
			this[key] = _data[key]
		}
	}
	
	this.invoice = function(records){
		this.records = records;
	}
	
	this.getTableStyleCustom = function(){
		var tableStyle = new self.GC.Spread.Sheets.Tables.TableTheme();
		//var thinBorder = new self.GC.Spread.Sheets.LineBorder();
		var thinBorder = undefined;
		tableStyle.wholeTableStyle(new self.GC.Spread.Sheets.Tables.TableStyle(undefined, "black", "light 11pt arial", thinBorder, thinBorder, thinBorder, thinBorder, thinBorder, thinBorder));
		var tableStyleInfo = new self.GC.Spread.Sheets.Tables.TableStyle(
			undefined,
		    "black",
		    "light 11pt arial",
		    new self.GC.Spread.Sheets.LineBorder("black", thinBorder),
		    new self.GC.Spread.Sheets.LineBorder("black", thinBorder),
		    new self.GC.Spread.Sheets.LineBorder("black", thinBorder),
		    new self.GC.Spread.Sheets.LineBorder("black", thinBorder));		
		tableStyle.headerRowStyle(tableStyleInfo);
		return tableStyle;		
	}

	this.bindSpreadJS = function(_datasetCount,_data,_sheetId){
		_sheetId = Number(_sheetId.substring(5))-1;
		
		if(_.isEmpty(_data)){
			gProgressbar.hide();
			return;
		}
		
		var activeSheet = self.spreadJS.getSheet(Number(_sheetId));		
		//self.spreadJS.getActiveSheet().addColumns(self.spreadJS.getActiveSheet().getRowCount(self.sheetArea.viewport), 100);		
		if(_data.length > 200){
			activeSheet.addRows(self.spreadJS.getActiveSheet().getRowCount(self.sheetArea.viewport), _data.length+50);
		}
		
		self.spreadJS.getSheet(Number(_sheetId)).clear(0,0,activeSheet.getRowCount(),activeSheet.getColumnCount(),self.sheetArea.viewport,self.GC.Spread.Sheets.StorageType.data);
		var ds = this.getJsonKey2ColInfosTable(_data);
		var tempData = [];
		$.each(_data, function(_i,_d){
			tempData[_i] = new self.record(_d); 
		});		
		var invoice = new self.invoice(tempData);		
		var dataSource = new self.GC.Spread.Sheets.Bindings.CellBindingSource(invoice);		
		
		//테이블 생성 및 데이터 바인딩 설정
        self.spreadJS.suspendPaint();
        var table;
        
        if(activeSheet.tables.findByName('table'+_sheetId)){
        	activeSheet.tables.move('table'+_sheetId,self.bindingColumn,self.bindingRow);
        	table = activeSheet.tables.findByName('table'+_sheetId);
        }else{
        	table = activeSheet.tables.add('table'+_sheetId, self.bindingColumn, self.bindingRow, ds.colInfos.length, ds.colInfos.length, self.getTableStyleCustom());        	
        }
        
        table.autoGenerateColumns(false); //테이블 컬럼 자동 생성
        table.bindColumns(ds.colInfos);
        table.bindingPath("records");
        table.bandRows(false);
        
        //그리드 라인 설정 옵션
        activeSheet.options.gridline.showHorizontalGridline = true;
        activeSheet.options.gridline.showVerticalGridline = true;
        activeSheet.invalidateLayout();
        self.spreadJS.resumePaint();
        
        activeSheet.setDataSource(dataSource);
        table.filterButtonVisible(false);
        
    	self.queryComleteCount++;
		if(!_.isEmpty(_data)){
			if (self.queryComleteCount === _datasetCount) {
				self.queryComleteCount = 0;
			}
			self.spreadJS.resumePaint();
		}
		self.defaultSheetSetting();
		
		// load time code
		window.endTime = window.performance.now();
		var time = window.endTime - window.startTime;
        //alert((time/1000).toFixed(3)+"sec");        
		gProgressbar.hide();
				
	}
	
	this.defaultSheetSetting = function(){		
		self.spreadJS.options.grayAreaBackColor = 'white';
		for(var i = 0; i < self.spreadJS.getSheetCount(); i++){			
			//self.spreadJS.getSheet(i).addColumns(self.spreadJS.getSheet(i).getColumnCount(self.sheetArea.viewport), 20);
			//self.spreadJS.getSheet(i).addRows(self.spreadJS.getSheet(i).getRowCount(self.sheetArea.viewport), 20);
		}
	}
	
	this.getSpreadId = function() {
		return WISE.Constants.editmode === 'viewer' ? WISE.Constants.pid : 'wiseZss';
	}

	this.getParams = function() {
		var spreadId = this.getSpreadId();
		return  {
			pid: self.reportId,
			userId: userJsonObject.userId,
			dataSources: JSON.stringify(self.sheets),
			params: JSON.stringify(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues()),
		};
	}
	
	this.getSheetId = function(_sheetName){
		return (self.spreadJS.getSheetIndex(_sheetName))+"";
	}
	
	this.getSheetNameFromID = function(_id){
		return self.spreadJS.getSheet(Number(_id)).name();
	}
	
	
	this.getBlobFromSpreadJS = function(param){
		gProgressbar.show();
		self.saveParam = param;
		self.save();
	}
	
	 this.save = function(){
		var excelIo = new self.GC.Spread.Excel.IO();
		
		//Binding data 파일에 저장 유무
		var json = self.spreadJS.toJSON({includeBindingSource: true});
		
		//console.log(json);
		excelIo.save(JSON.stringify(json), function (_blob) {
			self.blob = _blob;
		}, function (e) {
		    console.log('file save error',e);
		});
		
		return start(0);
	}
	 
	function start(counter){
	 if(counter < 10){
		 setTimeout(function(){
				 if(self.blob !== null){
					 self.saveSpreadReport();
					 counter = 11;
				 }else{
					 counter++;
				 }
			 start(counter);
		 }, 1000);
	 }
	}
	
	
	 this.saveSpreadReport = function(){
			
			var formData = new FormData();
				formData.append("JSON_REPORT", self.saveParam);
				formData.append("file",self.blob, WISE.Constants.pid+".xles");
			
			$.ajax({
	        	type : 'POST',
	            url: WISE.Constants.context + '/report/saveSpreadReport.do',
	            data:formData,
	            contentType: false,
	            processData: false,
	            success: function(result) {	            	
	            	result = JSON.parse(result);
	            	if(result['return_status'] == 200){
	            		self.saveParam = JSON.parse(self.saveParam);
	            		
	            		if(self.saveParam.isNew == 'true'){
	            			$('#savePopup').dxPopup('instance').hide();
		            		$('#savePopup').remove();
	            		}
	            		
	            		var reportTabLi= $('.report-tab ul').find('li');
	            	    var reportTabLiL = reportTabLi.length;
	            		var reportTab = $('.report-tab');
				        var reportTabUl = $('.report-tab ul');
				            reportTabLiL = reportTabLiL +1;
				        var createTab='';
				            createTab+='<li><span><em>'+ self.saveParam.report_nm +'</em></span></li>';

				        reportTab.find('ul').empty().append(createTab);
				        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
				        reportTab.find('li').width(100 / reportTabLiL + '%');

				        $('.report-tab ul').find('li').each(function(){
				            var createTabCustomData = $(this).find('em').text();
				        });

				        $(document).on('click', '.report-tab li', function(e){
				            $(this).addClass('on').siblings().removeClass('on');
				        });
	            		
	    				if(result['report_id'] != 1){
	    					WISE.Constants.pid = result['report_id'];
	    				}
	    				
	    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.ordinal = result['report_ordinal']+"";
	    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.name = self.saveParam.report_nm;
	    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.report_sub_title = self.saveParam.report_sub_title;
	    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.tag = self.saveParam.report_tag;
	    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.fld_id = self.saveParam.fld_id;
	    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.fld_type = self.saveParam.fld_type;
	    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.fld_nm = self.saveParam.fld_nm;
	    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.description = self.saveParam.report_desc;
						gDashboard.isNewReport = false;
						gProgressbar.hide();
	            		WISE.alert("보고서를 저장하였습니다",'success');
	            	}
	            	else if(result['return_status'] == 422){
	            		WISE.alert(result.return_msg,'error');
	            	}
	            	else{
	            		WISE.alert("보고서 저장에 실패하였습니다.<br>관리자에게 문의하세요.",'error');
	            	}
	            }
			});
			self.blob = null;
			
		}
	 
	 
	
	this.fileOpenFromServer = function(){		
		gProgressbar.show();
		gProgressbar.setStopngoProgress(false);
		
		initStart(true);
		
		function initStart(counter){
			 if(counter){
				 setTimeout(function(){
					 if(self.GC && self.spreadJS){
						counter = false;
						
						if(WISE.Constants.editmode == 'viewer'){
							self.init();					
						}

						var pid = self.reportId
						var url = WISE.Constants.domain + WISE.Constants.context + '/UploadFiles/ReportFile/'+pid+'.xlsx';
						if(WISE.Constants.domain.indexOf('localhost')>0) {
							url = WISE.Constants.domain + WISE.Constants.context + '/UploadFiles/local.xlsx';
						}
						var excelIo = new self.GC.Spread.Excel.IO();
						var xhr = new XMLHttpRequest();
						xhr.onreadystatechange = function() {
						  if (this.readyState == 4 && this.status == 200) {
						    var _data = this.response;
							//2020.11.03 mksong resource Import 동적 구현 dogfoot

						    var _blob = new Blob([_data], {type : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
						    var object = window.URL.createObjectURL(_blob);
						    //console.log('_blob: ',_blob);		    
						    self.spreadJS.suspendPaint();
						    var options = {
					    		excelOpenFlags:{
							    	ignoreStyle: false,
							    	ignoreFormula: false,
							    	frozenColumnsAsRowHeaders: false,
							    	frozenRowsAsColumnHeaders: false,
							    	doNotRecalculateAfterLoad: true
							    },
						    	password: ""
							};
						    excelIo.open(_blob, function (json) {
								self.spreadJS.clearSheets();
						        var workbookObj = json;
						        
						        self.spreadJS.fromJSON(workbookObj);		        
						        
						        self.defaultSheetSetting();		     	     
						        
						    	gProgressbar.setStopngoProgress(true);
							    gProgressbar.hide();					
							    
							 // load time code
								window.endTime = window.performance.now();
								var time = window.endTime - window.startTime;
						        //alert((time/1000).toFixed(3)+"sec");
						        
								if(window.location.href.indexOf('viewer') > 0){
									try {
										gDashboard.query();
									} catch (e) {
										console.error(e.stack);
									}
									
									 $.each(gDashboard.dataSourceManager.datasetInformation, function(_i, _d){ 
										if(!_d.data){
											gProgressbar.show();
										}
									});
								}							
							    
						    }, function (e) {
						        // process error
						    	gProgressbar.setStopngoProgress(true);
							    gProgressbar.hide();
						        console.log(e);
						    }, options);
						    
						    self.spreadJS.resumePaint();
						  };
						};

						xhr.open('POST', url);
						xhr.responseType = 'blob';
						xhr.setRequestHeader('Content-type', 'application/json');
						xhr.send();	 						
					 }else{
						 self.init();						 
					 }
					 initStart(counter);
				 }, 1000);
			 }
		}
	}

	this.getSingleDatasetParams = function(_ds) {
		var spreadId = this.getSpreadId();
		for (var i = 0; i < self.sheets.length; i++) {
			return {
				pid: self.reportId,
				userId: userJsonObject.userId,
				dataSources: JSON.stringify([self.sheets[i]]),
				params: JSON.stringify(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues())
			};
			
		}
		return {};
	}
	/* DOGFOOT hsshim 200107 끝 */

	this.loadDatasetInfo = function() {
		self.sheets = [];
		$.each(gDashboard.dataSourceManager.datasetInformation, function(_id, _ds) {
			self.sheets.push({
				datasetNm: _ds['DATASET_NM'],
				sheetId: _ds['SHEET_ID'],
				dsid: _ds['DATASRC_ID'], 
				dstype: _ds['DATASRC_TYPE'],
				sql: _ds['SQL_QUERY']
			});
		});
	}

	this.linkDatasetToSheet = function(gridRowData) {
		self.sheets = [];
		var dataSourcesId = 0;
		$.each(gDashboard.dataSourceManager.datasetInformation, function(_id, _ds) {
			self.sheets.push({
				'sheetId': _ds['SHEET_ID'],
				'datasetNm': _ds['DATASET_NM'],
				'dsid': _ds['DATASRC_ID'], 
				'dstype' : _ds['DATASRC_TYPE'],
				'sql': _ds['SQL_QUERY']
			});
			dataSourcesId++;
		});
	}
	
	//tbchoi 클릭 or 드레그 선택영역정보 가져오기 20200305
	this.bindClickAndDragCell = function(){
		self.spreadJS.getActiveSheet().bind(self.GC.Spread.Sheets.Events.CellClick, function (sender, args) {
		        var sheet = args.sheet;
		        var selection = sheet.getSelections()[0];
		        document.getElementById('reference').value = self.GC.Spread.Sheets.CalcEngine.rangeToFormula(selection);
		        var customNames = sheet.getCustomNames();
		        for (var i = 0; i < customNames.length; i++) {
		            var customName = customNames[i];
		            var range = customName.getExpression().getRange();
		            if (range.row === selection.row && range.col === selection.col && range.rowCount === selection.rowCount && range.colCount === selection.colCount) {
		                //var name = customName.getName();
		                //var comment = customName.getComment();
		                break;
		            }
		        }
		  });
	}
	
	this.setCustomNameSpreadJS = function(){
	    var activeSheet = self.spreadJS.getActiveSheet();
        var name = document.getElementById('customName').value;
        if (name === '') {
            alert("name should not be empty");
            return;
        }
        var comment = '';
        var formula = self.GC.Spread.Sheets.CalcEngine.rangeToFormula(activeSheet.getSelections()[0], 0, 0, self.GC.Spread.Sheets.CalcEngine.RangeReferenceRelative.allAbsolute);
        activeSheet.addCustomName(name, formula, activeSheet.getActiveRowIndex(), activeSheet.getActiveColumnIndex(), comment);
        this.printNames();
	}

	this.printNames = function(){
	    var namesInfo = self.spreadJS.getActiveSheet().getCustomNames();
        var str = "";
        namesInfo.forEach(function (nameInfo) {
            var name = nameInfo.getName();
            var reference = self.GC.Spread.Sheets.CalcEngine.rangeToFormula(nameInfo.getExpression().getRange());
            str += name + "     " + reference + '\n';
        });
        document.getElementById('reference').value = str;
	}
	
	this.printSpreadJS = function(){
		var activeSheet = self.spreadJS.getActiveSheet();
		var printInfo = activeSheet.printInfo();
		var index = self.spreadJS.getActiveSheetIndex();
		printInfo.margin({top:10, bottom:10, left:10, right:10, header:10, footer:10});
	   // printInfo.columnStart(activeSheet.getCustomNames()[0].Lf.column);
	   //printInfo.columnEnd(activeSheet.getCustomNames()[0].Lf.endColumn);
	   // printInfo.rowStart(activeSheet.getCustomNames()[0].Lf.row);
	   // printInfo.rowEnd(activeSheet.getCustomNames()[0].Lf.endRow);
	    
	    self.spreadJS.print(index);
	}
	
	this.savePdf = function(){
		var activeSheet = self.spreadJS.getActiveSheet();
		var printInfo = activeSheet.printInfo();
		var index = self.spreadJS.getActiveSheetIndex();
		printInfo.margin({top:20, bottom:20, left:20, right:20, header:20, footer:20});
	    
		//2020.11.03 mksong resource Import 동적 구현 dogfoot

	    self.spreadJS.savePDF(function (blob) {
	            saveAs(blob, 'download.pdf');
	    }, console.log);   
	}
	
	//뷰어 버튼 렌더링
	this.renderButtons = function(reportId){
		if(window.location.href.indexOf('USER') > 0){
			//console.log('page: ',page);
			//console.log('page: ',parent.gDashboard);
			
			var exportHtml = '<li id="spread_download" title="내보내기" class="img"><img src="' + parent.WISE.Constants.context + '/resources/main/images/ico-download_new.png" alt="이미지 다운로드"></li>';
			if($('#spread-top-icon').children().length === 0){
				$('#spread-top-icon').append(exportHtml);
//				$('#spread_download').on('click', function() {
//					document.getElementById("ss"+reportId).contentWindow.document.getElementById('export-excel').click();
//					$('#saveAsFileName').val(gDashboard.structure.ReportMasterInfo.name);
//				});
				$('#export_popover').dxPopover({
					height: 'auto',
					width: 195,
					position: 'bottom',
					visible: false,
				});
				
				$('#spread_download').off('click').click(function(){
					var p = $('#export_popover').dxPopover('instance');
					p.option({
						target: $('#spread-top-icon'),
						contentTemplate: function() {
							var html = '';
							html += '<div class="add-item noitem" style="padding:0px;">';
							html += '	<span class="add-item-head on">다운로드</span>';
							html += '	<ul class="add-item-body">';
							html += '		<li id="typeXlsx" class="exportFunction" title="XLSX 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xlsx.png" alt="XLSX 다운로드"><span>XLSX 다운로드</span></a></li>';
							html += '		<li id="typeCsv" class="exportFunction" title="CSV 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcexcell.png" alt="CSV 다운로드"><span>CSV 다운로드</span></a></li>';
							html += '	</ul>';
							html += '</div>';
	                        return html;
						},
						onContentReady: function() {
							$('.exportFunction').each(function(){
								$(this).click(function(){
									var exportType = $(this).attr('id');
									if(exportType == 'typeXlsx'){
										document.getElementById("ss"+reportId).contentWindow.document.getElementById('export-excel').click();
										$('#saveAsFileName').val(gDashboard.structure.ReportMasterInfo.name);
									}else if(exportType == 'typeCsv'){
										document.getElementById("ss"+reportId).contentWindow.document.getElementById('export-csv').click();
										$('#saveAsFileName').val(gDashboard.structure.ReportMasterInfo.name);
									}
									p.hide();
								});
							});
							
						}
					});
					p.show();
				});
			}
			$('.lm_title').text(gDashboard.structure.ReportMasterInfo.name);
			$("#ss"+reportId).css('height', 'calc(100% - 30px)');
		}else if(window.location.href.indexOf('viewer') > 0){
			$('.lm_title').hide();
			$('.lm_header').hide();
			
			$('.fill-spread-content').removeAttr("style"); 
			$('.fill-spread-content').attr("style",'top:40px !important');
		}
	}
	
	
	
	
}