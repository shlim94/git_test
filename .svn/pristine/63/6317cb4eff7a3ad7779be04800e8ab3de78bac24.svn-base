// ymbin
WISE.libs.Dashboard.item.TextBoxGenerator = function() {
	var self = this;
	
	this.type = 'TEXTBOX';
	this.dashboardid;
	this.itemid;
	this.dataSourceId;
	this.layoutManager;
	this.dxItem;
	
	// TextBox는 측정값과 숨겨진 데이터 항목의 측정값만 포함
	this.values = [];
	this.dimensions = [];
	this.measures = [];
	this.HiddenMeasures = [];
	this.fieldManager;
	this.TextBox = [];
	this.initialized;
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	this.rScript = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	this.panelManager;
	//2020.02.05 mksong 텍스트박스 내용 저장 오류 수정 dogfoot
	this.TextBox.HTML_DATA;
	this.isReadOnly;
	
	//2019.12.27 ktkang 텍스트박스 내용 누적저장 오류 수정 dogfoot
	this.defaultHTML_DATA = '' +
	'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">' +
	'<html xmlns="http://www.w3.org/1999/xhtml">' +
		'<head>' +
			'<meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><title>' +
			'</title>' +
			'<style type="text/css">' +
			'</style>' +
		'</head>' +
		'<body>' +
		'</body>' +
	'</html>';
	
	
	this.setTextBox = function(){
		if(this.fieldManager){
			this.fieldManager.init();
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.TextBox.DataItems = this.fieldManager.DataItems;
			this.TextBox.Values = this.fieldManager.Values;
			this.TextBox.Panes = this.fieldManager.Panes;
			this.TextBox.HiddenMeasures = this.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
		}

		// default settings 기본값 맞춤
		if (!(this.TextBox.ComponentName)) {
			this.TextBox.ComponentName = this.ComponentName;
		}
		if (!(this.TextBox.DataSource)) {
			this.TextBox.DataSource = this.dataSourceId;
		}else if(this.TextBox.DataSource != this.dataSourceId){
			this.TextBox.DataSource = this.dataSourceId;
		}
		if (!(this.TextBox.Name)) {
			this.TextBox.Name = this.Name;
		}
		if (this.TextBox.InteractivityOptions) {
			if (!(this.TextBox.InteractivityOptions.IgnoreMasterFilters)) {
				this.TextBox.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.TextBox.InteractivityOptions = {
				IgnoreMasterFilters: false
			};
		}
		if ((this.TextBox.ShowCaption)) {
			this.TextBox.ShowCaption = true;
		}
		
		//2020.02.05 mksong 텍스트박스 내용 저장 오류 수정 dogfoot
		if (!(this.TextBox.HTML_DATA)) {
			//2019.12.27 ktkang 텍스트박스 내용 누적저장 오류 수정 dogfoot
			this.TextBox.HTML_DATA = this.defaultHTML_DATA;
		}
		
		this.meta = this.TextBox;
	};
	
	this.setTextBoxForOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setTextBox();
		}
		else{
			this.TextBox = this.meta;
		}
		
		if(this.fieldManager != undefined) {
			//2020.02.05 mksong 텍스트박스 내용 저장 오류 수정 dogfoot
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.TextBox.DataItems = this.meta.DataItems = this.fieldManager.DataItems;
			this.TextBox.Values = this.meta.Values = this.fieldManager.Values;
			this.TextBox.HiddenMeasures =  this.meta.HiddenMeasures = this.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			if(gDashboard.reportType === 'RAnalysis'){
				this.dimensions = this.fieldManager.dimensions;
			}
		}
		
		if(this.TextBox.HiddenMeasures != undefined)
			this.TextBox.HiddenMeasures.Measure = WISE.util.Object.toArray(this.TextBox.HiddenMeasures.Measure);

		// default settings 기본값 맞춤
		if (!(this.TextBox.ComponentName)) {
			this.TextBox.ComponentName = this.ComponentName;
		}
		if (!(this.TextBox.DataSource)) {
			this.TextBox.DataSource = this.dataSourceId;
		}else if(this.TextBox.DataSource = this.dataSourceId){
			this.TextBox.DataSource = this.dataSourceId;
		}
		if (!(this.TextBox.Name)) {
			this.TextBox.Name = this.Name;
		}
		if (this.TextBox.InteractivityOptions) {
			if (!(this.TextBox.InteractivityOptions.IgnoreMasterFilters)) {
				this.TextBox.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.TextBox.InteractivityOptions = {
				IgnoreMasterFilters: false
			};
		}
		if (this.TextBox.ShowCaption == undefined) {
			this.TextBox.ShowCaption = true;
		}
		
		var textBoxDataElement;

		$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.TEXTBOX_DATA_ELEMENT), function(i, ele){
			if(ele.CTRL_NM == self.ComponentName.split('_')[0]){
				textBoxDataElement = ele;
				return false;
			} 
		})
		//2020.01.31 MKSONG UNDEFINED 오류 수정 DOGFOOT
		if(textBoxDataElement.HTML_DATA) {
			//2020.02.05 mksong 텍스트박스 내용 저장 오류 수정 dogfoot
			this.TextBox.HTML_DATA = Base64.decode(textBoxDataElement.HTML_DATA); // base64 decoding
			
			var style = this.TextBox.HTML_DATA.substring(this.TextBox.HTML_DATA.indexOf('<style type="text/css">'), this.TextBox.HTML_DATA.indexOf('</style>')+8);
			var styleCss = this.TextBox.HTML_DATA.substring(this.TextBox.HTML_DATA.indexOf('/css">')+6, this.TextBox.HTML_DATA.indexOf('</style>')); // style 태그 안
			if(styleCss != "") {
				$('head').append(style.trim()); // head에 style 추가
			}
			
			var body = this.TextBox.HTML_DATA.substring(this.TextBox.HTML_DATA.indexOf('<body>')+6, this.TextBox.HTML_DATA.indexOf('</body>'));// body 태그 안
			//2020.02.05 mksong 텍스트박스 내용 저장 오류 수정 끝 dogfoot
			if(body != "") {
				this.TextBox.Text = body.trim();
			}
		}
		
		this.meta = this.TextBox;
		
	};
	
	this.setTextBoxForViewer = function() {
		if(typeof this.meta == 'undefined'){
			this.setTextBox();
		}
		else{
			this.TextBox = this.meta;
			this.TextBox.Initialized = true;
		}
		
		this.TextBox.ComponentName = this.meta.ComponentName;
		this.TextBox.DataSource = this.meta.dataSourceId != undefined ? this.meta.dataSourceId:this.meta.DataSource;
		this.TextBox.Name = this.meta.Name;
		if (this.TextBox.InteractivityOptions) {
			if (!(this.TextBox.InteractivityOptions.IgnoreMasterFilters)) {
				this.TextBox.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.TextBox.InteractivityOptions = {
				IgnoreMasterFilters: false
			};
		}
		if (this.TextBox.ShowCaption == undefined) {
			this.TextBox.ShowCaption = true;
		}
		
        var textBoxDataElement;

		$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.TEXTBOX_DATA_ELEMENT), function(i, ele){
			if(ele.CTRL_NM == self.ComponentName.split('_')[0]){
				textBoxDataElement = ele;
				return false;
			}
		})

		if(textBoxDataElement.HTML_DATA) {
			//2020.02.05 mksong 텍스트박스 내용 저장 오류 수정 dogfoot
			this.TextBox.HTML_DATA = Base64.decode(textBoxDataElement.HTML_DATA);
			
			var style = this.TextBox.HTML_DATA.substring(this.TextBox.HTML_DATA.indexOf('<style type="text/css">'), this.TextBox.HTML_DATA.indexOf('</style>')+8);
			var styleCss = this.TextBox.HTML_DATA.substring(this.TextBox.HTML_DATA.indexOf('/css">')+6, this.TextBox.HTML_DATA.indexOf('</style>')); // style 태그 안
			if(styleCss != "") {
				$('head').append(style.trim()); // head에 style 추가
			}
			
			var body = this.TextBox.HTML_DATA.substring(this.TextBox.HTML_DATA.indexOf('<body>')+6, this.TextBox.HTML_DATA.indexOf('</body>'));// body 태그 안
			//2020.02.05 mksong 텍스트박스 내용 저장 오류 수정 끝 dogfoot
			if(body != "") {
				this.TextBox.Text = body.trim();
			}
		}
		
		this.isReadOnly = true;
		
		this.meta = this.TextBox;
	};
	
	
	//** @Override *//*
	this.bindData = function(_data) {
//		this.setTextBox();
//		this.renderTextBox();
		//2020.02.05 mksong 텍스트박스 불필요한 부분 제거 dogfoot
//		var page = window.location.pathname.split('/');
//		if (page[page.length - 1] === 'viewer.do' || page[page.length - 1] ==='view.do') {
//			this.setTextBoxForViewer();
			//2020.02.06 mksong 중복 소스 주석 dogfoot
//			this.renderTextBox();
			// 이것을 해주지 않으면 viewer 에서 오류남
//		}
//		else{
//			this.setTextBox();
			this.renderTextBox();
//		}
			
		//2020.02.05 mksong 텍스트박스 불러오기 수정 dogfoot
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'viewer.do' || page[page.length - 1] ==='view.do') {
			this.viewerRenderButtons();
		} else {
			gDashboard.itemGenerateManager.renderButtons(self);
		}
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			/* DOGFOOT ktkang 뷰어에서 텍스트박스 무한로딩 오류 수정  20200731 */
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
	};
	
	this.renderTextBox = function() {
		if(gDashboard.isNewReport == true){ // 신규 생성
			self.setTextBox();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.TextBox);
			gDashboard.itemGenerateManager.generateItem(self, self.TextBox);
		}
		else if(gDashboard.isNewReport == false){ // 레포트 열기
		    var textBoxDataElement;

			$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.TEXTBOX_DATA_ELEMENT), function(i, ele){
				if(ele.CTRL_NM == self.ComponentName.split('_')[0]){
					textBoxDataElement = ele;
					return false;
				}
			})
			//2020.02.07 mksong 텍스트박스 보고서 열기에 신규 추가시 오류 수정 dogfoot
			if(!textBoxDataElement){
				self.setTextBox();	
			}else{
				self.setTextBoxForOpen();
			}
			
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.TextBox);
			gDashboard.itemGenerateManager.generateItem(self, self.TextBox);
		}
		else if(self.meta && $.isEmptyObject(self.TextBox)) {
			this.setTextBoxForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.TextBox);
			gDashboard.itemGenerateManager.generateItem(self, self.TextBox);
		}
		
	};
	
	this.renderButtons = function() {
		gDashboard.itemGenerateManager.renderButtons(self);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
//		$('#'+self.itemid).css('display','block');
//		//2020.02.05 mksong 텍스트박스 불러오기 수정 dogfoot
//		self.dxItem = $('#'+self.itemid).dxHtmlEditor({
//			 value: self.meta ? self.meta.Text : '',
//			 toolbar: {
//	            items: [
//	                "undo", "redo", "separator",
//	                {
//	                    formatName: "font",
//	                    formatValues: ["Arial", "Courier New", "Georgia", "Impact", "Lucida Console", "Tahoma", "Times New Roman", "Verdana"]
//	                },
//	                {
//	                    formatName: "size",
//	                    formatValues: ["8pt", "10pt", "12pt", "14pt", "18pt", "24pt", "36pt"]
//	                },
//	                
//	                "separator", "bold", "italic", "strike", "underline", "separator",
//	                "alignLeft", "alignCenter", "alignRight", "alignJustify", "separator",
//	                "orderedList", "bulletList", "separator",
//	                "color", "background", "separator",
//	                "link", "image", "separator",
//	                "clear", "codeBlock", "blockquote"
//	            ]
//	        },
//	        mediaResizing: {
//	            enabled: true
//	        },
//	        onFocusOut: function(e) {
//	        	var text = "";
//	        	$('#'+self.ComponentName).find('p').each(function(_i, _e) { // texteditor 안의  내용 추가
//	        		text += _e.outerHTML.toString();
//	        	});
//	        	
//	        	self.Text = text;
//	        	self.setTextBox();
//	        	self.TextBox.Text = text;
//	        	
//	        	// chart_xml 형식에 맞춤
//	        	//2019.12.27 ktkang 텍스트박스 내용 누적저장 오류 수정 dogfoot
//	        	var html = self.defaultHTML_DATA;
//	        	self.TextBox.HTML_DATA = html.substring(0, html.indexOf("</body>")) + text + html.substring(html.indexOf("</body>"));
//	        }
////	        mentions: [{
////	            dataSource: self.DataItems,
////	            searchExpr: "text",
////	            displayExpr: "text"
////	        }]
//	 	}).dxHtmlEditor('instance');
//		
//		if(self.TextBox) {
//			if(self.TextBox.Text != undefined) {
//				$('#' + self.itemid).find('.dx-htmleditor-content').html(self.TextBox.Text);
//			}
//		}
		
	};
	
	this.viewerRenderButtons = function() {
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		self.dxItem = $('#'+self.itemid).dxHtmlEditor({
			value: self.TextBox.HTML_DATA,
	        mediaResizing: {
	            enabled: true
	        },
	        readOnly: true,
	        onContentReady: function(e){
	        	console.log(e);
	        }
	 	}).dxHtmlEditor('instance');
		
		if(self.TextBox) {
			if(self.TextBox.Text != undefined) {
				$('#' + self.itemid).find('.dx-htmleditor-content').html(self.TextBox.Text);
			}
		}
	}
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
		
//		if($('#data').length > 0){
//			$('#data').remove();
//		}
//	   
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));   
//		}
//		
//		if($('#design').length > 0){
//			$('#design').remove();
//		}
//		
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
//	    }
//	   
//		$('#tab5primary').empty();
//	   
//		$('<li class="slide-ui-item"><a href="#" id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));	
//		menuItemSlideUi();
//	   
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));
//		}
//	   
//		var filter = "" +
//		"<h4 class=\"tit-level3\">필터링</h4>" + 
//		"<div class=\"panel-body\">" + 
//		"	<div class=\"design-menu rowColumn\">" + 
//		"		<ul class=\"desing-menu-list col-2\">" + 
//		"			<li>" + 
//		"				<a href=\"#\" id=\"editFilter\" class=\"functiondo\">" +
//		"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_basicFilter.png\" alt=\"\"><span>필터 편집</span>" + 
//		"				</a>" + 
//		"			</li>" + 
//		"			<li>" + 
//		"				<a href=\"#\" id=\"clearFilter\" class=\"functiondo\">" + 
//		"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>초기화</span>" + 
//		"				</a>" + 
//		"			</li>" + 
//		"		</ul>" + 
//		"	</div>" + 
//		"</div>" +
//		"<h4 class=\"tit-level3\">Interactivity Options</h4>" + 
//		"<div class=\"panel-body\">" + 
//		"	<div class=\"design-menu rowColumn\">" + 
//		"		<ul class=\"desing-menu-list col-1\">" + 
//		"			<li>" + 
//		"				<a href=\"#\" id=\"ignoreMasterFilter\" class=\"single-toggle-button functiondo\">" + 
//		"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>마스터 필터<br>무시</span>" + 
//		"				</a>" + 
//		"			</li>" + 
//		"		</ul>" + 
//		"	</div>" + 
//		"</div>";
//	   
//		$(filter).appendTo($('#tab4primary'));
//	   
//		$('#menulist').find('li').removeClass('on');
//	   
//		tabUi();
//		designMenuUi();
//		compMoreMenuUi();
//	   
//		$('.single-toggle-button').on('click', function(e) {
//			e.preventDefault();
//			$(this).toggleClass('on');
//		});
//		
//		// 필터 편집
//		if(self.meta && self.meta.FilterString && self.meta.FilterString.length > 0) {
//			$('#editFilter').addClass('on');
//		}
//		// 필터
//		if (self.IO) {
//			if (self.IO['IgnoreMasterFilters']) {
//				$('#ignoreMasterFilter').addClass('on');
//			}
//		}
//		
//		// edit name
//		$('<div id="editPopup">').dxPopup({
//            height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('#tab5primary')
//		// edit filter
//		$('<div id="editPopup2">').dxPopup({
//			height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('body');
//		
//		// editFunctionDo Class 활성화
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);
//		});
//		
//		//2020.02.05 mksong 텍스트박스 불필요한 부분 제거 dogfoot
//    	// textbox의 field option 에서는 format 불필요
////    	$('#'+self.ComponentName+'fieldManager').find('.setFormat').hide();
		
	};
	
	
	this.resize = function() {
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'viewer.do' || page[page.length - 1] ==='view.do') {
			// 이것을 해주지 않으면 viewer 에서 오류남
		}
		else{
			//2020.02.05 mksong 텍스트박스 불필요한 부분 제거 dogfoot
//			self.renderButtons();
			var text = "";
			$('#'+self.ComponentName).find('p').each(function(_i, _e) { // texteditor 안의  내용 추가
				text += _e.outerHTML.toString();
			});
			
			self.Text = text;
			//self.setTextBox();
			self.TextBox.Text = text;
			
			// chart_xml 형식에 맞춤
			//2019.12.27 ktkang 텍스트박스 내용 누적저장 오류 수정 dogfoot
			var html = self.defaultHTML_DATA;
			self.TextBox.HTML_DATA = html.substring(0, html.indexOf("</body>")) + text + html.substring(html.indexOf("</body>"));
			self.bindData()
			//2019.12.27 ktkang 텍스트 박스 저장 dogfoot
			if(typeof self.dxItem != 'undefined'){
//				self.dxItem._options.mediaResizing();	
			}
			
			if(gDashboard.reportType === 'RAnalysis'){
				$('#rscript').css('height', $('.panel-inner').height() * .7+'px');
			}
		}
	};
	
	this.functionDo = function(_f) {
	   switch(_f) {
	   case 'captionVisible': {
			var titleBar = $('#' + self.itemid + '_title');
			if (titleBar.css('display') === 'none') {
				titleBar.css('display', 'block');
				self.TextBox.ShowCaption = true;
			} else {
				titleBar.css('display', 'none');
				self.TextBox.ShowCaption = false;
			}
			break;
		}
		case 'editName': {
			var p = $('#editPopup').dxPopup('instance');
			p.option({
				title: '이름 편집',
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForEditText('editPopup');
				},
				contentTemplate: function(contentElement) {
					// initialize title input box
					contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput"></div>');
                   var html = 	'<div style="padding-bottom:20px;"></div>' +
								'<div class="modal-footer" style="padding-bottom:0px;">' +
									'<div class="row center">' +
										'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
										'<a id="close" href="#" class="btn neutral close">취소</a>' +
									'</div>' +
								'</div>';
					contentElement.append(html);
                   
                   $('#' + self.itemid + '_titleInput').dxTextBox({
						text: $('#' + self.itemid + '_title').text()
                   });
                                           
                   // confirm and cancel
                   $('#ok-hide').on('click', function() {
                	   var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
                	   if(newName.trim() == '') {
                		   WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                		   $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('value', self.Name);
                	   } else {
                		   /* DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류 수정  20191223 */

//              		   var goldenLayout = gDashboard.goldenLayoutManager;
//              		   goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);

                		   var ele = $('#' + self.itemid + '_title');
                		   ele.attr( 'title', newName)
                		   ele.find( '.lm_title' ).html(newName);

                		   self.TextBox.Name = newName;
                		   self.Name = newName;
                		   p.hide();
                	   }
                   });
					$('#close').on('click', function() {
						p.hide();
					});
				}
			});
			// show popup
			p.show();
			break;
		}
	   case 'editFilter': {
			if (!(self.dxItem)) {
				break;
			}
			var p = $('#editPopup2').dxPopup('instance');
			p.option({
				title: '필터 편집',
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForEditText('editPopup2');
				},
				contentTemplate: function() {
					var html = 	'<div id="filterContent"></div>' +
								'<div style="padding-bottom:20px;"></div>' +
								'<div class="modal-footer" style="padding-bottom:0px;">' +
									'<div class="row center">' +
										'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
										'<a id="close" href="#" class="btn neutral close">취소</a>' +
									'</div>' +
								'</div>';
                   return html;
				},
				onContentReady: function() {
					var field = [];
					$.each(self.seriesDimensions, function(_i, series) {
						field.push({ dataField: series.name, dataType: 'string' });
					});
					$.each(self.dimensions, function(_i, dimension) {
						field.push({ dataField: dimension.name, dataType: 'string' });
					});

					$('#filterContent').append('<div id="' + self.itemid + '_editFilter">');
					$('#' + self.itemid + '_editFilter').dxFilterBuilder({
						fields: field,
						value: self.meta.FilterString
                   });
                                           
                   // confirm and cancel
					$('#ok-hide').on('click', function() {
//                       var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').getFilterExpression();
						var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').option('value');
                       var newDataSource = new DevExpress.data.DataSource({
                           store: self.filteredData,
                           paginate: false
                       });
                       newDataSource.filter(filter);
						newDataSource.load();
						self.filteredData = newDataSource.items();
						self.meta.FilterString = filter;
						self.bindData(self.filteredData, true);
						if (self.IO.MasterFilterMode !== 'Off') {
							/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
							gDashboard.filterData(self.itemid, []);
						}
						if(self.meta.FilterString.length > 0){
							$('#editFilter').addClass('on');
						}else{
							$('#editFilter').removeClass('on');
						}
						p.hide();
					});
					$('#close').on('click', function() {
						p.hide();
					});
				}
			});
			p.show();
			break;
		}
		// clear filters
		case 'clearFilter': {
			if (!(self.dxItem)) {
				break;
			}
			self.meta.FilterString = [];
			$('#editFilter').removeClass('on');
			self.filteredData = self.globalData;
			self.bindData(self.globalData, true);
			if (self.IO.MasterFilterMode !== 'Off') {
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				gDashboard.filterData(self.itemid, []);
			}
			
			break;
		}
		case 'ignoreMasterFilter': {
			if (!(self.dxItem)) {
				break;
			}
			self.IO.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
			self.TextBox.InteractivityOptions.IgnoreMasterFilters = self.IO.IgnoreMasterFilters;
			self.tracked = !self.IO.IgnoreMasterFilters;
			if (self.IO.IgnoreMasterFilters) {
				self.bindData(self.globalData,true);
			} else {
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
					if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
						self.doTrackingCondition(item.itemid, item);
						return false;
					}
				});
			}
			break;
		}
	    default: 
	    	break;
	   	}
	};
	
}

WISE.libs.Dashboard.TextBoxFieldManager = function() {
	var self = this;
	
	this.initialized = false;
	this.alreadyFindOutMeta = false;
	
	this.searchDisable = false;
	this.searchMatchCompletely = true;
	
	this.dataItemNo = 0;
	
	this.meta;
	this.isChange = false;
	this.columnMeta = {};
	this.isColumnChooser = false;
	
	this.all = [];
	this.values = [];
	this.hide_column_list_dim = [];
	this.hide_column_list_mea = [];
	
	this.tables = [];
	
	this.Constants = {
		CUSTOMIZED: '계산된필드',
		DELTA: '변동측정필드',
		UNSELECTED_FIELD: 'UNSELECTED_FIELD'
	}

	this.init = function() {
		this.columnMeta = {};
		this.tables = [];
		this.all = [];
		this.values = [];
		this.hide_column_list_dim = [];
		this.hide_column_list_mea = [];
		this.meta = gDashboard.structure.ReportMasterInfo.dataSource;
		
		this.initialized = true;
	};

	this.setMetaTables = function(tables){
		this.meta.tables = tables;
	};
	
	this.setDataItemByFieldR = function(_fieldlist, _optionList){
		this.DataItems = {};
		self.DataItems['Dimension'] = [];
		self.DataItems['Measure'] = [];
		
		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('dataType') == 'dimension' || $(_fieldlist[i]).attr('dataType') == 'sparklineArgument'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				var sortMeaId;
				$.each(_fieldlist,function(_j,_f){
					if($(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem') === _f.attr('dataitem'))
					sortMeaId = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				})
				dataItem['SortByMeasure'] = sortMeaId;
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
                /*dogfoot 통계 분석 추가 shlim 20201103*/
				var ctype = ""
				if(typeof $(_fieldlist[i]).attr('containerType') != 'undefined' && $(_fieldlist[i]).attr('containerType') != ""){
					ctype = $(_fieldlist[i]).attr('containerType')
				}
				dataItem['ContainerType'] = ctype;

				self.DataItems['Dimension'].push(dataItem);
			} else if($(_fieldlist[i]).attr('dataType') == 'measure' || $(_fieldlist[i]).attr('dataType') == 'sparkline' || $(_fieldlist[i]).attr('dataType') == 'delta'){
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = NumericFormat;
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				/*dogfoot 통계 분석 추가 shlim 20201103*/
				var ctype = ""
				if(typeof $(_fieldlist[i]).attr('containerType') != 'undefined' && $(_fieldlist[i]).attr('containerType') != ""){
					ctype = $(_fieldlist[i]).attr('containerType')
				}
				dataItem['ContainerType'] = ctype;
				
				
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};

	this.setDataItemByField = function(_fieldlist){
		this.DataItems = {};
		self.DataItems['Measure'] = [];
		
		for(var i = 0; i < _fieldlist.length; i++){
			var listType = $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'textboxValueList' || 
			$(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'textbox_hide_measure_list' ? true : false;
			if(!listType){
				
			}else{
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['UNI_NM'] = $(_fieldlist[i]).attr('uni_nm');
				dataItem['NumericFormat'] = NumericFormat;
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};

	this.setValuesByField = function(_values){
		this.Values = {'Value' : []};
		_.each(_values,function(_v){
			var Value = {'UniqueName' : _v.uniqueName};
			self.Values['Value'].push(Value);
		});
		return self.Values;
	};
	
	this.setHiddenMeasuresByField = function(_hiddenMeasure){
		this.HiddenMeasures = {'Measure' : []};
		_.each(_hiddenMeasure,function(_a){
			/* DOGFOOT ktkang 대시보드 주제영역 정렬 기준 항목 오류 수정  20200707 */
			var Value = {'UniqueName' : _a.uniqueName, 'cubeUniqueName': _a.cubeUniqueName};
			self.HiddenMeasures['Measure'].push(Value);
		})
		return self.HiddenMeasures;
	};
};
