// ymbin
WISE.libs.Dashboard.item.ImageGenerator = function() {
	var self = this;
   
   	this.type = 'IMAGE';
   	this.dashboardid;
   	this.itemid;
   	this.dataSourceId;
   	this.dxItem;
   	this.layoutManager;
   
   	this.imgFilemeta;
   	this.Url;
   	
   	this.SizeMode;
	this.VerticalAlignment;
   	this.HorizontalAlignment;
	this.Alignment;
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
   
   this.Image = [];
   	
   this.setImage = function(){
		if (!(this.Image.ComponentName)) {
			this.Image.ComponentName = this.ComponentName;
		}
		if (!(this.Image.DataSource)) {
			this.Image.DataSource = this.dataSourceId;
		}else if(this.Image.DataSource != this.dataSourceId){
			this.Image.DataSource = this.dataSourceId;
		}
		if (!(this.Image.Name)) {
			this.Image.Name = this.Name;
		}
		if (!(this.Image.Url)) {
			this.Image.Name = this.Url;
		}
		if (!this.Image.SizeMode) {
			this.Image.SizeMode = this.SizeMode;
		}
		if (!this.Image.VerticalAlignment) {
			this.Image.VerticalAlignment = this.VerticalAlignment;
		}
		if (!this.Image.HorizontalAlignment) {
			this.Image.HorizontalAlignment = this.HorizontalAlignment;
		}
		if (this.Image.ShowCaption) {
			this.Image.ShowCaption = true;
		}
		
		this.meta = this.Image;
   };
   
   this.setImageForOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setImage();
		}
		else{
			this.Image = this.meta;
		}

		if (!(this.Image.ComponentName)) {
			this.Image.ComponentName = this.ComponentName;
		}
		if (!(this.Image.DataSource)) {
			this.Image.DataSource = this.dataSourceId;
		}else if(this.Image.DataSource = this.dataSourceId){
			this.Image.DataSource = this.dataSourceId;
		}
		if (!(this.Image.Name)) {
			this.Image.Name = this.Name;
		}
		if (!(this.Image.Url)) {
			this.Image.Name = this.Url;
		}
		if (!this.Image.SizeMode) {
			this.Image.SizeMode = this.SizeMode;
		}
		if (!this.Image.VerticalAlignment) {
			this.Image.VerticalAlignment = this.VerticalAlignment;
		}
		if (!this.Image.HorizontalAlignment) {
			this.Image.HorizontalAlignment = this.HorizontalAlignment;
		}
		if (this.Image.ShowCaption == undefined) {
			this.Image.ShowCaption = true;
		}
		
		this.meta = this.Image;
		
   };
   
   this.setImageForViewer = function() {
	   	if(typeof this.meta == 'undefined'){
			this.setImage();
		}
		else{
			this.Image = this.meta;
			this.Image.Initialized = true;
		}
		
		this.Image.ComponentName = this.meta.ComponentName;
		this.Image.DataSource = this.meta.dataSourceId != undefined ? this.meta.dataSourceId:this.meta.DataSource;
		this.Image.Name = this.meta.Name;
		this.Image.Url = this.meta.Url;
		this.Image.SizeMode = this.meta.SizeMode;
		this.Image.HorizontalAlignment = this.meta.HorizontalAlignment;
		this.Image.VerticalAlignment = this.meta.VerticalAlignment;
		this.Image.ShowCaption = true;
		
		this.meta = this.Image;
	};
	
   //** @Override *//*
	this.bindData = function(_data) {
		this.renderImage();
	};
	
	this.renderImage = function() {
		if(gDashboard.isNewReport == true){ // 신규 생성
			self.setImage();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Image);
			gDashboard.itemGenerateManager.generateItem(self, self.Image);
		}
		else if(gDashboard.isNewReport == false){ // 레포트 열기
			self.setImageForOpen();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Image);
			gDashboard.itemGenerateManager.generateItem(self, self.Image);
		}
//		else if(self.meta && $.isEmptyObject(self.Image)) {
//			this.setImageForViewer();
//			gDashboard.itemGenerateManager.itemCustomize(self,self.Image);
//			this.generate(self.Image);
//		}
		else if(self.meta != undefined && self.Image.length == 0){
			this.setImageForViewer();
			gDashboard.itemGenerateManager.generateItem(self, self.Image);
		}
		
		self.renderButtons();
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
	};
	
	this.renderButtons = function() {
		if(self.meta.Url == null)
			return;
		
		var path = (self.meta.Url.indexOf('\\')>-1)?self.meta.Url.split('\\'):self.meta.Url.split('/');
		var fileName = path[path.length-1];
		
		var url;
		if(path.length == 1) {
			url = self.meta.Url
		}
		else {
			url = WISE.Constants.context + "/UploadFiles/ReportFile/" + fileName
		}
  	  	var image = [{
  	  		ImageSrc: url
	  	}];
  	  	
	  	if(!self.SizeMode)
			self.SizeMode = 'Clip';
	  	if(!self.VerticalAlignment)
	  		self.VerticalAlignment = 'Center';
	  	if(!self.HorizontalAlignment)
	  		self.HorizontalAlignment = 'Center';
		
//	  	var sm = self.SM;
//	  	if(self.SM == 'Squeeze') {
//	  		$("#"+self.itemid).append("<div hidden='hidden'><img id='sqe' src='" + url + "'></img></div>");
//	  		var width = $('#sqe')[0].naturalWidth;
//	  		var height = $('#sqe')[0].naturalHeight;
//	  		$('#sqe').remove();
//	  		
//	  		if(_bwidth < naturalWidth || _bheight < naturalHeight)
//	  			sm = 'Zoom';
//	  		} else {
//	  			sm = 'Clip';
//	  		}
//	  	}
	  	
	  	//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
	  	$('#'+self.itemid).css('display','block');
		self.dxItem = $("#"+self.itemid).dxTileView({
			items: image,
//			baseItemWidth: _bwidth,
//			baseItemHight: _bheight,
			itemTemplate: function (itemData, itemIndex, itemElement) {
				itemElement.append("<div class=\"image" + self.SizeMode + "\" style=\"background-image: url(" + itemData.ImageSrc + "); background-position: " + self.VerticalAlignment.toLowerCase() + " " + self.HorizontalAlignment.toLowerCase() + "\"></div>");
			}
		}).dxTileView('instance');
		
		//default는 clip
		if(self.dxItem) {
//			self.setImage();
			var _bwidth = $("#"+self.itemid).parent().width();
		  	var _bheight = $("#"+self.itemid).parent().height();
		  	
		  	self.dxItem.option().baseItemWidth = _bwidth;
		  	self.dxItem.option().baseItemHeight = _bheight;
		  	self.dxItem.option().itemMargin = 0;
			self.dxItem.repaint();
		}
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
		
	};

   this.menuItemGenerate = function(){
	   gDashboard.itemGenerateManager.menuItemGenerate(self);
//      if($('#data').length > 0){
//         $('#data').remove();
//      }
//      
//      // 필드 숨기기
//      $('#menulist:first-child').find('li').hide();
//      
//      // col-2 부분 삭제함으로써 셀 합치기
//      $('#menulist').removeClass('col-2');
//      if($('#data').length == 0){
//      	$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));   
//      }
//      
//      if($('#design').length > 0){
//         $('#design').remove();
//      }
//      
//      // #tab5primary : slide_menu -> CS에서는 '디자인'
//      if($('#tab5primary').length == 0){
//		// 2020.01.16 mksong 영역 크기 조정 dogfoot
//		$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
//      }
//      
//      $('#tab5primary').empty();
//      
//      $('<li class="slide-ui-item"><a href="#" id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//      $('<li class="slide-ui-item"><a href="#" id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));	
//      menuItemSlideUi();
//      
//      $('#tab4primary').empty();
//      if($('#tab4primary').length == 0){
//         // append : 뒤 내용을 앞에 붙인다.
//         $('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));
//      }
//      
//      var open = "" +
//      "<h4 class=\"tit-level3\">Open</h4>" +
//      "<div class=\"panel-body\">" +
//      "   <div class=\"design-menu rowColumn\">" +
//      "      <ul class=\"desing-menu-list col-1\">" +
////      "      <ul class=\"desing-menu-list col-2\">" +
//      "         <li>" +
//      "            <a href=\"#\" id=\"loadImg\" class=\"functiondo\">" +
//      "               <img src=\"" + WISE.Constants.context + "/resources/main/images/ico_loadImages.png\" alt=\"\"><span>이미지 불러오기</span>" +
//      "            </a>" +
//      "         </li>" +
////      "         <li>" +
////      "            <a href=\"#\" id=\"imgportImg\" class=\"functiondo\">" +
////      "               <img src=\"" + WISE.Constants.context + "/resources/main/images/ico_importImages.png\" alt=\"\"><span>이미지 가져오기</span>" +
////      "            </a>" +
////      "         </li>" +
//      "      </ul>" +
//      "   </div>" +
//      "   <div hidden=\"hidden\">" +
//      "      <form id=\"IMG_FORM\" name=\"imgForm\" method=\"post\" enctype=\"multipart/form-data\" accept-charset=\"UTF-8`\">" +
//      "         <div id=\"IMG_BUTTON\" class=\"image-ui\">" +
//      "            <input id=\"imgInput\" name=\"imgInput\" class=\"real-image\" type=\"file\" ></div>" +
//      "            <span id=\"imageText\">파일 선택하세요.</span>"  +
//      "         </div>" +
//      "      </form>" +
//      "      <a id=\"imageOkButton\" hidden=\"hidden\">확인</a>" +
//      "   </div>" +
//      "</div>";
//      
//      var sizeMode = "" +
//      "<h4 class=\"tit-level3\">Size Mode</h4>" +
//        "<div class=\"panel-body\">" +
//        "   <div class=\"design-menu rowColumn\">" +
//        "      <ul class=\"desing-menu-list\">" +
//        "         <li>" +
//        "            <a href=\"#\" id=\"clip\" class=\"multi-toggle-button functiondo\">" +
//        "                <img src=\""+ WISE.Constants.context + "/resources/main/images/ico_clip.png\" alt=\"\"><span>클립</span>" +
//        "            </a>" +
//        "         </li>" +
//        "         <li>" +
//        "            <a href=\"#\" id=\"stretch\" class=\"multi-toggle-button functiondo\">" +
//        "               <img src=\"" + WISE.Constants.context + "/resources/main/images/ico_stretch.png\" alt=\"\"><span>늘리기</span>" +
//        "            </a>" +
//        "         </li>" +
//        "         <li>" +
//        "            <a href=\"#\" id=\"squeeze\" class=\"multi-toggle-button functiondo\">" +
//        "               <img src=\"" + WISE.Constants.context + "/resources/main/images/ico_squeeze.png\" alt=\"\"><span>밀어넣기</span>" +
//        "            </a>" +
//        "         </li>" +
//        "         <li>" +
//        "            <a href=\"#\" id=\"zoom\" class=\"multi-toggle-button functiondo\">" +
//        "               <img src=\"" + WISE.Constants.context + "/resources/main/images/ico_zoom.png\" alt=\"\"><span>확대/축소</span>" +
//        "            </a>" +
//        "         </li>" +
//        "      </ul>" +
//        "   </div>" +
//        "</div>";
//
//      // ico_alignmentCenterRIght.png RIght 부분 -> I 오타
//      var alignment = "" +
//      "<h4 class=\"tit-level3\">Alignment</h4>" +
//      "<div class=\"panel-body\">" +
//      "   <div class=\"design-menu rowColumn\">" +
//      "      <ul class=\"desing-menu-list\">" +
//      "         <li class=\"menu-item-more full\">" +
//      "            <div class=\"menu-item-box\">" +
//      "               <div class=\"scrollbar\">" +
//      "                  <ul class=\"menu-item-box-list\">" +
//      "                     <li>" +
//      "                        <a href=\"#\" id=\"alignmentTopLeft\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentTopLeft.png\" alt=\"\"><span>Alignment Top Left</span></a>" +
//      "                     </li>" +
//      "                     <li>" +
//      "                        <a href=\"#\" id=\"alignmentTopCenter\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentTopCenter.png\" alt=\"\"><span>Alignment Top Center</span></a>" +
//      "                     </li>" +
//      "                     <li>" +
//      "                        <a href=\"#\" id=\"alignmentTopRight\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentTopRight.png\" alt=\"\"><span>Alignment Top Right</span></a>" +
//      "                     </li>" +
//      "                     <li>" +
//      "                        <a href=\"#\" id=\"alignmentCenterLeft\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentCenterLeft.png\" alt=\"\"><span>Alignment Center Left</span></a>" +
//      "                     </li>" +
//      "                     <li>" +
//      "                        <a href=\"#\" id=\"alignmentCenterCenter\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentCenterCenter.png\" alt=\"\"><span>Alignment Center Center</span></a>" +
//      "                     </li>" +
//      "                     <li>" +
//      "                        <a href=\"#\" id=\"alignmentCenterRight\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentCenterRIght.png\" alt=\"\"><span>Alignment Center Right</span></a>" +
//      "                     </li>" +
//      "					</ul>" +
//      "				  </div>" +
//      "               <a href=\"#\" class=\"item-more\">more</a>" +
//      "               <div class=\"mini-box\">" +
//      "                  <div class=\"add-item noitem\">" +
//      "                     <span class=\"add-item-head on\">Alignment</span>" +
//      "                     <ul class=\"add-item-body\">" +
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentTopLeft\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentTopLeft.png\" alt=\"\"><span>Alignment Top Left</span></a>" +
//      "                        </li>" +
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentTopCenter\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentTopCenter.png\" alt=\"\"><span>Alignment Top Center</span></a>" +
//      "                        </li>" +
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentTopRight\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentTopRight.png\" alt=\"\"><span>Alignment Top Right</span></a>" +
//      "                        </li>" +
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentCenterLeft\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentCenterLeft.png\" alt=\"\"><span>Alignment Center Left</span></a>" +
//      "                        </li>" +
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentCenterCenter\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentCenterCenter.png\" alt=\"\"><span>Alignment Center Center</span></a>" +
//      "                        </li>" +
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentCenterRight\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentCenterRIght.png\" alt=\"\"><span>Alignment Center Right</span></a>" +
//      "                        </li>" +   
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentBottomLeft\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentLeftBottom.png\" alt=\"\"><span>Alignment Left Bottom</span></a>" +
//      "                        </li>" +
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentBottomCenter\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentCenterBottom.png\" alt=\"\"><span>Alignment Center Bottom</span></a>" +
//      "                        </li>" +
//      "                        <li>" +
//      "                           <a href=\"#\" id=\"alignmentBottomRight\" class=\"alignment-multi-toggle-button functiondo\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_alignmentRightBottom.png\" alt=\"\"><span>Alignment Right Bottom</span></a>" +
//      "                        </li>" +
//      "                     </ul>" +
//      "                  </div>" +
//      "               </div>" +
//      "            </div>" +
//      "         </li>" +
//      "      </ul>" +
//      "   </div>" +
//      "</div>";
//      
//      // appendTo : 앞 내용을 뒤에 붙인다.
//      $(open).appendTo($('#tab4primary'));
//      $(sizeMode).appendTo($('#tab4primary'));
//      $(alignment).appendTo($('#tab4primary'));
//      
//      // 필드의 on 없애기 (필드 창을 숨겨서 굳이 넣을 필요는 없다)
//      $('#menulist').find('li').removeClass('on');
//      
//      // scripts.js에 tabUi -> Image 버전으로 추가
//      tabPropertyUi(); // 아이템 생성 and 포커스 맞춤
//      designMenuUi(); // 클릭 시 on
//      compMoreMenuUi();
//      
//      // editName popup
//      $('<div id="editPopup">').dxPopup({
//    	  height: 'auto',
//    	  width: 500,
//    	  visible: false,
//    	  showCloseButton: false
//      }).appendTo('#tab5primary');
//      
//      // 클릭 시 on
////      $('.single-toggle-button').on('click', function(e) {
////    	  e.preventDefault();
////    	  $(this).toggleClass('on');
////      });
//      // 클릭 시 하나만 on 적용
//      $('.multi-toggle-button').on('click', function(e) {
//          e.preventDefault();
//          var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
//          if ($(this)[0] !== currentlyOn[0]) {
//              currentlyOn.removeClass('on');
//          } else {
//        	  return; // 같은 것 클릭 시 사라지지 않게 함
//          }
//          $(this).toggleClass('on');
//      });
//      // Alignment의 경우 하나 클릭 시 두개 클릭
//      $('.alignment-multi-toggle-button').on('click', function(e) {
//          e.preventDefault();
//          var currentlyOn = $(this).parent().parent().parent().parent().parent().find('.multi-toggle-button.on'); // 클릭이 두군데 되야 한다.
//          $.each(currentlyOn, function(i, e) {
//        	  if ($(this)[i] !== e) {
//                  currentlyOn.removeClass('on');
//              }
//        	  $(this).toggleClass('on');
//          });
//      });
//      if(self.SizeMode) {
//    	  if(self.SizeMode === 'Clip') {
//    		  $('#clip').addClass('on');
//    	  } else if(self.SizeMode === 'Squeeze') {
//    		  $('#squeeze').addClass('on');
//    	  } else if(self.SizeMode === 'Zoom') {
//    		  $('#zoom').addClass('on');
//    	  } else{
//    		  $('#stretch').addClass('on');
//    	  }
//      } else { // default: Clip
//    	  $('#clip').addClass('on');
//      }
//      
//      var vertical;
//      if(self.VerticalAlignment) {
//    	  	vertical = self.VerticalAlignment;
//      } else {
//    	  	vertical = "Center";
//      }
//      var horizontal;
//      if(self.HorizontalAlignment) {
//    	  	horizontal = self.HorizontalAlignment;
//      } else {
//    	  	horizontal = "Center";
//      }
//      var alignment = "alignment" + vertical + horizontal;
//      self.Alignment = alignment;
//      $('#' + alignment).addClass('on');
//      
//      $('#imgInput').change(function(){
//         $('#imageOkButton').on('click', function(){
//            //gProgressbar.show();
//            var _imgFile = document.getElementById('imgInput').files[0];
//            $('#imageText').html(_imgFile.name);
//            if (_imgFile) {
//               self.imgFilemeta = _imgFile;
//               self.onLoadImage(_imgFile);
//            }
//         });
//         $('#imageOkButton').click();
//      });
//      
//      // functionDo Class 활성화
//      $('.functiondo').on('click',function(e){
//	        // preventDefault : 이벤트 동작 막는다.
//	        // stopPropagation : 상위 레벨 이벤트가 전파되지 않도록 중단
//	        // stopImmediatePropagation : 상위 뿐 아니라 같은 레벨로도 이벤트가 전파되지 않도록 중단한다.
//	        //_e.stopImmediatePropagation();
//	        self.functionDo(this.id);
//      });
      
   };
   
   
   this.resize = function() {
//	   self.renderButtons();
		/* DOGFOOT ktkang 이미지 불러오기 안되는 오류 수정  20200618 */
	   if(typeof self.dxItem != 'undefined') {
		   self.dxItem.repaint();
	   }
   };
   
   this.functionDo = function(_f) {
      switch(_f) {
      // default
      case 'captionVisible': {
			var titleBar = $('#' + self.itemid + '_title');
			if (titleBar.css('display') === 'none') {
				titleBar.css('display', 'block');
				self.Image.ShowCaption = true;
			} else {
				titleBar.css('display', 'none');
				self.Image.ShowCaption = false;
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

//              		  var goldenLayout = gDashboard.goldenLayoutManager;
//              		  goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);

                		  var ele = $('#' + self.itemid + '_title');
                		  ele.attr( 'title', newName)
                		  ele.find( '.lm_title' ).html(newName);

                		  self.Image.Name = newName;
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
	    case 'loadImg': {
	    	$('#imgInput').click();
	        break;
	    }
         case 'imgportImg': {

            break;
         }
         // Size Mode
         case 'clip': {
        	if (!(self.dxItem)) {
 				break;
 			}
        	this.SizeMode = this.Image.SizeMode = 'Clip';
        	
        	self.resize();
        	
            break;
         }
         case 'stretch': {
        	if (!(self.dxItem)) {
  				break;
  			 }
        	this.SizeMode = this.Image.SizeMode = 'Stretch';

        	self.resize();
        	
        	break;
         }
         case 'squeeze': {
        	if (!(self.dxItem)) {
  				break;
        	}
        	this.SizeMode = this.Image.SizeMode = 'Squeeze';

        	self.resize();
        	
		    break;
		 }
         case 'zoom': {
        	if (!(self.dxItem)) {
        		break;
  			}
        	this.SizeMode = this.Image.SizeMode = 'Zoom';
         	
         	self.resize();
			break;
         }
         // Alignment
         case 'alignmentTopLeft': {
        	if (!(self.dxItem)) {
         		break;
   			}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Top';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Left';
 			 
        	self.resize();
        	 
            break;
         }
         case 'alignmentTopCenter': {
        	if (!(self.dxItem)) {
          		break;
    		}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Top';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Center';
  			 
         	self.resize();
         	 
            break;
         }
         case 'alignmentTopRight': {
        	if (!(self.dxItem)) {
           		break;
     		}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Top';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Right';
   			 
          	self.resize();
          	
            break;
         }
         case 'alignmentCenterLeft': {
        	if (!(self.dxItem)) {
           		break;
     		}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Center';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Left';
   			 
          	self.resize();
          	
            break;
         }
         case 'alignmentCenterCenter': {
        	if (!(self.dxItem)) {
            		break;
      		}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Center';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Center';
    			 
           	self.resize();
           	
             break;
         }
         case 'alignmentCenterRight': {
        	if (!(self.dxItem)) {
            		break;
      		}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Center';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Right';
    			 
           	self.resize();
           	
             break;
         }
         case 'alignmentBottomLeft': {
        	if (!(self.dxItem)) {
         		break;
        	}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Bottom';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Left';
 			 
        	self.resize();
        	
             break;
         }
         case 'alignmentBottomCenter': {
        	if (!(self.dxItem)) {
          		break;
         	}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Bottom';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Center';
  			 
         	self.resize();
         	
             break;
         }
         case 'alignmentBottomRight': {
        	if (!(self.dxItem)) {
          		break;
         	}
        	this.VerticalAlignment = this.Image.VerticalAlignment = 'Bottom';
        	this.HorizontalAlignment = this.Image.HorizontalAlignment = 'Right';
  			 
         	self.resize();
         	
             break;
         }
         default: 
            break;
      }
   };
   
   this.onLoadImage= function(imgFile){
	  var self = this;
      var imgreader = new FileReader();
      imgreader.onload = (function(that){
          return function(e){
             this.imgFilemeta = e.target.result;
            var form = $('#IMG_FORM')[0];
            var formData = new FormData(form);
            $.ajax({
               cache: false,
               url: WISE.Constants.context + '/report/loadImage.do',
               async:false,
               enctype: 'multipart/form-data',
               processData: false,
               contentType: false,
               data: formData,
               type: 'POST',
               success: function(result){
            	  self.Image.Url = Base64.decode(result);
            	  self.setImage();
               },
               error:function(error){

               }
            }).done(function() {
            	self.renderButtons(); // 요청 성공 시 전공
            });
          }
      })(this);
      imgreader.readAsArrayBuffer(imgFile);
   };
                  
   
}

WISE.libs.Dashboard.ImageFieldManager = function() {
   
};
