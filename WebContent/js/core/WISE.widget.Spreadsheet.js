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
	/*dogfoot 스프레드 시트 테이블 바인드 테스트 용 shlim 20200721*/
	this.bindingXY = [];
	this.bindingColRow = [];
	/*dogfoot 테이블 헤더 표시 여부 추가 shlim 20200805*/
	this.showTableHeader = [];
	this.showCheck=[];
	this.bindingColumn = 0;
	this.bindingRow = 0;
	this.predataLen = 0;
	this.precolLen = 0;
	
	this.init = function(){
		if(self.reportId == undefined){
			self.reportId ="";
		}
		
		var SheetId = document.getElementById("ss"+self.reportId);
		//20210713 AJKIM 루프 에러때문에 탈출하지 않게 수정 dogfoot
		try{
			if(SheetId.contentWindow.GC && SheetId.contentWindow.designer.wrapper.spread){
				self.GC = SheetId.contentWindow.GC;
				self.spreadJS = SheetId.contentWindow.designer.wrapper.spread;
				self.sheetArea = self.GC.Spread.Sheets.SheetArea;
				self.spreadJS.options.grayAreaBackColor = 'white';
			}
		} catch(e){
			//console.error(e);
		}
		

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
	/*dogfoot 스프레드 시트 테이블 바인드 테스트 용 shlim 20200721*/
	//보고서 열때 XML에서 xy 정보 가져오기
	this.setReportXml = function(_xml){
		self.bindingColRow = [];
		//20210729 AJKIM 스프레드시트 데이터 집합 여러개 불러올 때 오류 수정 dogfoot
		$.each(WISE.util.Object.toArray(_xml.EXCEL_XML.SHEET_ELEMENT.VISIBLE_SHEET),function(_i,_d){
			/*dogfoot 엑셀 스프레드시트 저장불러오기 오류 수정 shlim 20201123*/
			if(_d.BIND_CHECK == "true"){
				if(_d.START_POS == undefined){
				_d.START_POS = 'A1';
				}			
				if(_d.BIND_TYPE != undefined){
					gDashboard.queryHandler.spreadtable = _d.BIND_TYPE == 'false' ? false : true;
				}else{
					gDashboard.queryHandler.spreadtable = false;
				}

				if(_d.SHOW_HEADER != undefined){
					self.setTableShowHeader(_d.SHOW_HEADER, _d.SHEET_ID);
				}

				self.setXYtoColumnRow(_d.START_POS, _d.SHEET_ID);			
			}
		});
	};
	
	//보고서 저장할때 XML에 xy 정보 저장
	this.getReportXml = function(){		
		var result= '<EXCEL_XML><FILE_EXT_ELEMENT><FILE_EXT>xlsx</FILE_EXT></FILE_EXT_ELEMENT><SHEET_ELEMENT>';
		$.each(gDashboard.dataSourceManager.datasetInformation ,function(_i, _d){
//			result +='<VISIBLE_SHEET><SHEET_ID>'+_d.SHEET_ID+'</SHEET_ID><VISIBLE>Y</VISIBLE><SHEET_NM>'+_d.SHEET_NM+'</SHEET_NM><START_POS>'+self.bindingXY[_d.SHEET_ID]+'</START_POS></VISIBLE_SHEET>'
			result +='<VISIBLE_SHEET>';
			/*dogfoot 엑셀 스프레드시트 저장불러오기 오류 수정 shlim 20201123*/
			if(_d.SHEET_ID && _d.SHEET_ID != "undefined" && _d.SHEET_ID != ""){
				result +='<BIND_CHECK>'+true+'</BIND_CHECK>';	
			}else{
				result +='<BIND_CHECK>'+false+'</BIND_CHECK>';	
			}
			result +='<SHEET_ID>'+_d.SHEET_ID+'</SHEET_ID>';
			result +='<VISIBLE>Y</VISIBLE>';
			result +='<SHEET_NM>'+_d.SHEET_NM+'</SHEET_NM>';
			result +='<START_POS>'+self.bindingXY[_d.SHEET_ID]+'</START_POS>';
			result +='<BIND_TYPE>'+gDashboard.queryHandler.spreadtable+'</BIND_TYPE>';
			result +='<SHOW_HEADER>'+self.showTableHeader[_d.SHEET_ID]+'</SHOW_HEADER>';
			result +='</VISIBLE_SHEET>'
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
		/*dogfoot 테이블 바인드 바인드 위치 설정 shlim 20200727*/
		self.bindingColumn =  self.fromLetters(_xy.replace(/[0-9]/g,""));	
		self.bindingRow = Number(_xy.replace(/[^0-9]/g,''))-1;
		self.bindingColRow[_id] = {'columns':self.bindingColumn,'rows' : self.bindingRow } 
	};
	this.setTableShowHeader = function(_show,_id){		
		if(self.showTableHeader.length > 1){
			$.each(self.showTableHeader, function(_i, _d){
				if(_d == _id){
					delete self.showTableHeader[_d];
				}
			})
		}
		if(_show === '표시안함'){
            self.showTableHeader[_id] = _show;
            self.showCheck[_id] = false;
		}else {
			self.showTableHeader[_id] = '표시';
			self.showCheck[_id] = true;
		}
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
	/*dogfoot 스프레드 시트 테이블 바인드 테스트 용 shlim end 20200721*/
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
	
	//tbchoi 데이터 바인딩 시 헤더 변경을 위한 함수 20200204
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
	/*dogfoot 스프레드 시트 테이블 바인드 테스트 용 shlim 20200721*/
	this.getJsonKey2ColInfosTable = function(_dataSource){
		if(_.isEmpty(_dataSource)) return;
		var key = Object.keys(_dataSource[0]);
		var str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		var disName='';
		var tempData = _dataSource[0];
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
			
			if(userJsonObject.siteNm == "KAMKO"){
				if(typeof tempData[_val] == "number"){
	            	tableColumn1.formatter("#,##0");
	            }
			}
			
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
		var thinBorder = undefined;
		if(userJsonObject.siteNm == "KAMKO"){
			thinBorder = new self.GC.Spread.Sheets.LineBorder("black", 1);
		}
		tableStyle.wholeTableStyle(new self.GC.Spread.Sheets.Tables.TableStyle(undefined, undefined, undefined, thinBorder, thinBorder, thinBorder, thinBorder, thinBorder, thinBorder));
		var tableStyleInfo = new self.GC.Spread.Sheets.Tables.TableStyle(
			undefined,
			undefined,
			undefined,
		    thinBorder,
		    thinBorder,
		    thinBorder,
		    thinBorder,
		    thinBorder,
		    thinBorder);		
//		tableStyle.headerRowStyle(tableStyleInfo);
		return tableStyle;		
	}
	
	this.bindSpreadJSTABLE = function(_datasetCount,_data,_sheetId, _sheetNm, _mapId){
		window.queryStartTime = window.performance.now();
		var sheetNm = _sheetId,isNewTable;
		_sheetId = Number(_sheetId.substring(5))-1;

		//20210908 AJKIM 데이터 없을 때 로직 수정 dogfoot
		if(_.isEmpty(_data)){
			var fields = gDashboard.datasetMaster.state.fields[_mapId];

			var tempData = {};
			$.each(fields, function(index, field){
				if(field.TYPE){
					tempData[field.CAPTION] = '';
				}
			})

			_data = [tempData];
			//20210913 AJKIM 스프레드시트 데이터 없을 경우 경고문 추가 dogfoot
			WISE.alert("조회된 데이터가 없습니다.");
		}
// 		if(_.isEmpty(_data)){
// 			/*dogfoot 데이터 없을 시 시트 초기화 shlim 20200610 */
//             if(_.isNull(self.spreadJS.getSheet(Number(_sheetId)))){
// 				activeSheet = self.spreadJS.getActiveSheet();
// 			}else{
// 				activeSheet = self.spreadJS.getSheet(Number(_sheetId));
// 			}
            
//             activeSheet.setDataSource();
// 			gProgressbar.hide();
// 			return;
// 		}
		var ds = this.getJsonKey2ColInfosTable(_data);
		var activeSheet = self.spreadJS.getSheet(Number(_sheetId));
		
		// 데이터집합이 변경되었을때 시트에 데이터가 남아있으면 바인딩이 꼬이므로 초기화하게 변경
		//self.spreadJS.getSheet(Number(_sheetId)).clear(0, 0, activeSheet.getRowCount(), activeSheet.getColumnCount()
		//		, self.sheetArea.viewport, self.GC.Spread.Sheets.StorageType.data);
		
		//self.spreadJS.getActiveSheet().addColumns(0, 100);
//		activeSheet.addColumns(0, 100);
//		if(_data.length > 200){
//			activeSheet.addRows(0, _data.length+50);
//		}
		
//		self.spreadJS.getSheet(Number(_sheetId)).clear(0,0,activeSheet.getRowCount(),activeSheet.getColumnCount(),self.sheetArea.viewport,self.GC.Spread.Sheets.StorageType.data);
//		self.spreadJS.getSheet(Number(_sheetId)).clear(0,0,-1,-1,self.sheetArea.viewport,self.GC.Spread.Sheets.StorageType.data);
		//self.spreadJS.getSheet(Number(_sheetId)).clear(0,0,activeSheet.getRowCount(),activeSheet.getColumnCount(),self.sheetArea.viewport,self.GC.Spread.Sheets.StorageType.data);
		/*dogfoot 테이블 바인드 바인드 위치 설정 shlim 20200727*/
		if((ds.colInfos.length + self.bindingColRow[sheetNm].columns + 1) > activeSheet.getColumnCount() || (_data.length + self.bindingColRow[sheetNm].rows + 1) > activeSheet.getRowCount()){
			if((ds.colInfos.length + self.bindingColRow[sheetNm].columns + 1) > activeSheet.getColumnCount() ){
				activeSheet.addColumns(activeSheet.getColumnCount(), ((ds.colInfos.length + self.bindingColRow[sheetNm].columns + 1) - activeSheet.getColumnCount()));
			}
			
			if( (_data.length + self.bindingColRow[sheetNm].rows + 1) > activeSheet.getRowCount() ){
				activeSheet.addRows(activeSheet.getRowCount(), ((_data.length + self.bindingColRow[sheetNm].rows + 1) - activeSheet.getRowCount()));
			}
		}
		
		var tempData = [];
//		$.each(_data, function(_i,_d){
//			tempData[_i] = new self.record(_d); 
//		});
		if(_data.length > self.predataLen) self.predataLen = _data.length ;
        if(ds.colInfos.length> self.precolLen) self.precolLen = ds.colInfos.length ;
		
        //20210414 AJKIM records에 null값 들어가면 오류 predataLen -> _data.length로 변경 dogfoot
		for(var i=0; i < _data.length;i++){
            tempData[i] = new self.record(_data[i]); 	
		}
		var invoice = new self.invoice(tempData);		
		var dataSource = new self.GC.Spread.Sheets.Bindings.CellBindingSource(invoice);		
		
		//테이블 생성 및 데이터 바인딩 설정
        self.spreadJS.suspendPaint();
        //self.spreadJS.suspendEvent();
        var table;
        
        if(activeSheet.tables.findByName('table'+_sheetId)){
        	activeSheet.tables.remove('table'+_sheetId)
        }
//        	table = activeSheet.tables.findByName('table'+_sheetId);
//        	table.showHeader(self.showCheck[sheetNm]);
//        	activeSheet.tables.move('table'+_sheetId, self.bindingColRow[sheetNm].rows, self.bindingColRow[sheetNm].columns);
//        	activeSheet.tables.resize('table'+_sheetId, self.GC.Spread.Sheets.Range(self.bindingColRow[sheetNm].rows,self.bindingColRow[sheetNm].columns,_data.length,ds.colInfos.length));
//        	isNewTable = false;
//        }else{
        	/* DOGFOOT syjin 스프레드 시트 불러오기 서식 적용 밀리는 현상 수정 20211116*/
        	table = activeSheet.tables.add('table'+_sheetId, self.bindingColRow[sheetNm].rows, self.bindingColRow[sheetNm].columns, invoice.records.length+1, ds.colInfos.length, self.getTableStyleCustom());
        	table.showHeader(self.showCheck[sheetNm]);
        	isNewTable = true;
//        }
        
        table.autoGenerateColumns(false); //테이블 컬럼 자동 생성
        table.bindColumns(ds.colInfos);
        table.bindingPath("records");
        table.bandRows(false);
        table.bandColumns(false);
        
        //그리드 라인 설정 옵션
        activeSheet.options.gridline.showHorizontalGridline = true;
        activeSheet.options.gridline.showVerticalGridline = true;
        activeSheet.invalidateLayout();
        //self.spreadJS.resumePaint();
        
        activeSheet.setDataSource(dataSource);
        table.filterButtonVisible(false);
        
    	self.queryComleteCount++;
		if(!_.isEmpty(_data)){
			if (self.queryComleteCount === _datasetCount) {
				self.queryComleteCount = 0;
			}
			//self.spreadJS.resumePaint();
		}
		self.defaultSheetSetting();
		if(!self.showCheck[sheetNm] && isNewTable){
			activeSheet.tables.move('table'+_sheetId, self.bindingColRow[sheetNm].rows, self.bindingColRow[sheetNm].columns);		
		} 
		// load time code
		window.endTime = window.performance.now();
		window.queryEndTime = window.performance.now();
		console.log("테이블 바인딩 보고서 열기 실행시간 : " + (window.endTime - window.startTime)+'ms');
		console.log("테이블 바인딩 단순 조회 실행시간 : " + (window.queryEndTime - window.queryStartTime)+'ms');
		self.time = window.endTime - window.startTime;
        //alert((time/1000).toFixed(3)+"sec");
		//self.spreadJS.resumeEvent();
		self.spreadJS.resumePaint();
		gProgressbar.hide();
				
	}
	

	
	this.bindSpreadJS = function(_datasetCount,_data,_sheetId,_sheetNm){		
		//console.log('_datasetCount : ',_datasetCount);
		//console.log('_data:',_data);
		//console.log('_sheetId:',_sheetId);		
		//20200702 AJKIM SHEET_NM값 SHEET_ID로 대체 dogfoot
		window.queryStartTime = window.performance.now();
		_sheetId = Number(_sheetId.substring(5))-1;
		
//		if(_.isEmpty(_data)){
//			gProgressbar.hide();
//			return;
//		}	
		if(_.isEmpty(_data)){
			/*dogfoot 데이터 없을 시 시트 초기화 shlim 20200610 */
            if(_.isNull(self.spreadJS.getSheet(Number(_sheetId)))){
				activeSheet = self.spreadJS.getActiveSheet();
			}else{
				activeSheet = self.spreadJS.getSheet(Number(_sheetId));
			}
            
            self.spreadJS.getSheet(Number(_sheetId)).clear(0,0,activeSheet.getRowCount(),activeSheet.getColumnCount(),self.sheetArea.viewport,self.GC.Spread.Sheets.StorageType.data);
			gProgressbar.hide();
			return;
		}
		

		var activeSheet = self.spreadJS.getActiveSheet();
		activeSheet.autoGenerateColumns = true;
		self.spreadJS.suspendPaint();
		//self.spreadJS.suspendEvent();
		
		if(_.isNull(_sheetId)){
			activeSheet.setDataSource(_data);
		}else{
			var ds = this.getJsonKey2ColInfos(_data);
			_data.unshift(ds.dataSourceHearder);
				
			if(_.isNull(self.spreadJS.getSheet(Number(_sheetId)))){
				activeSheet = self.spreadJS.getActiveSheet();
			}else{
				activeSheet = self.spreadJS.getSheet(Number(_sheetId));
			}
//			if(_.isNull(self.spreadJS.getSheetFromName(_sheetNm))){
//				activeSheet = self.spreadJS.getActiveSheet();
//			}else{
//				activeSheet = self.spreadJS.getSheetFromName(_sheetNm);
//			}
			activeSheet.setDataSource(_data);			
			activeSheet.bindColumns(ds.colInfos);
			
			
			// 활성 시트 선택
			//self.spreadJS.setActiveSheet(_sheetName);
		}
		self.queryComleteCount++;
		if(!_.isEmpty(_data)){
			if (self.queryComleteCount === _datasetCount) {
				self.queryComleteCount = 0;
			}
		}		
		self.defaultSheetSetting();
		// load time code
		window.endTime = window.performance.now();
		window.queryEndTime = window.performance.now();
		console.log("보고서 열기 실행시간 : " + (window.endTime - window.startTime)+'ms');
		console.log("단순 조회 실행시간 : " + (window.queryEndTime - window.queryStartTime)+'ms');
		self.time = window.endTime - window.startTime;
        //alert((time/1000).toFixed(3)+"sec");
        
        window.startTime = undefined;
        //self.spreadJS.resumeEvent();
        self.spreadJS.resumePaint();
        
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
		var json = self.spreadJS.toJSON({includeBindingSource: false});		
		//console.log(json);
		excelIo.save(JSON.stringify(json), function (_blob) {
			self.blob = _blob;
		}, function (e) {
		    console.log('file save error',e);
		});		
		return startSave(true);
	}
	 
	function startSave(_loop){
	 if(_loop){
		 setTimeout(function(){
			 if(self.blob !== null){
				 self.saveSpreadReport();
				 _loop = false;
			 }
			 startSave(_loop);
		 }, 500);
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
            		
            		//20210826 AJKIM 저장하자마자 보고서 속성 누르면 일부 값이 정상적으로 입력되지 않던 오류 수정 dogfoot
    				if(result['report_id'] != 1){
    					WISE.Constants.pid = result['report_id'];
    					gDashboard.structure.ReportMasterInfo.id = result['report_id'];
    				}
    				
    				gDashboard.reportUtility.reportInfo.ReportMasterInfo.all_fld_nm = result['all_fld_nm'];
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

						var pid = self.reportId;
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
						    //self.spreadJS.suspendEvent();
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
							    /*dogfoot 스프레드시트 보고서바로조회 기능 추가 shlim 20210625*/							  
							    if(userJsonObject.reportDirectView == 'Y') {
							    //20210913 AJKIM 스프레드 시트 뷰어에서 쿼리 두번 도는 오류 수정 dogfoot
							    	gDashboard.datasetMaster.addBetParam();						
									if(window.location.href.indexOf('viewer') > 0){									
										 $.each(gDashboard.dataSourceManager.datasetInformation, function(_i, _d){ 
											if(!_d.data){
												gProgressbar.show();
											}
										});
									}	
								} else {
									gProgressbar.stopngo = true;
									gProgressbar.hide();
								}						
							    
						    }, function (e) {
						        // process error
						    	gProgressbar.setStopngoProgress(true);
							    gProgressbar.hide();
						        console.log(e);
						    }, options);
						    
						    //self.spreadJS.resumeEvent();
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
				 }, 100);
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
            WISE.alert("name should not be empty");
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
	    
	    self.spreadJS.savePDF(function (blob) {
	            saveAs(blob, 'download.pdf');
	    }, console.log);   
	}
	
	//뷰어 버튼 렌더링
	this.renderButtons = function(reportId){
		if(window.location.href.indexOf('USER') > 0){
			//console.log('page: ',page);
			//console.log('page: ',parent.gDashboard);
			
			var exportHtml = '<li id="spread_download" title="내보내기" class="img"><img src="' + (WISE? WISE.Constants.context : parent.WISE.Constants.context) + '/resources/main/images/ico-download_new.png" alt="이미지 다운로드"></li>';
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
			//202210913 AJKIM 자산관리공사 직접경로 URL 보고서명 제거
			if(userJsonObject.siteNm == "KAMKO"){
				$('.lm_tab').hide();
			}else {
				$('.lm_title').text(gDashboard.structure.ReportMasterInfo.name);
				$("#ss"+reportId).css('height', 'calc(100% - 30px)');
			}
		}else if(window.location.href.indexOf('viewer') > 0){
			$('.lm_title').hide();
			$('.lm_header').hide();
			
			$('.fill-spread-content').removeAttr("style"); 
			$('.fill-spread-content').attr("style",'top:40px !important');
		}
	}
	
	
	
	
}