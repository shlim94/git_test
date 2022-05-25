WISE.libs.Dashboard.FontManager = function() {
	var self = this;
	this.fontSize = 0;
	this.fontFamily;
	this.fontCoverage;
	
	this.init = function(){
		var fontConfigJson;
		if(userJsonObject.fontConfig){
			if(userJsonObject.fontConfig.FONT_SIZE)
				fontConfigJson = userJsonObject.fontConfig;
			else
				fontConfigJson = fontConfigManager.getFontConfig;
		}
		else
			fontConfigJson = fontConfigManager.getFontConfig;
		
		self.fontSize = fontConfigJson.FONT_SIZE * 1;
		self.fontFamily = fontConfigJson.FONT_FAMILY;
		self.fontCoverage = fontConfigJson.FONT_COVERAGE;
		
		if(!self.fontCoverage.Menu && !self.fontCoverage.Item){
			self.fontSize = 0;
			self.fontFamily = 'Basic';
		}
	}
	
	this.getDxItemLabelFont = function() {
		return self.getDxItemCustomFont(12);
	}
	
	this.getDxItemAxisTitleFont = function() {
		return self.getDxItemCustomFont(16);
	}
	
	this.getDxItemTitleFont = function() {
		return self.getDxItemCustomFont(18);
	}
	
	this.getDxItemCustomFont = function(_fontSize){
		if(!self.fontCoverage.Item)
			return { size: _fontSize + "px" };
		if(self.fontFamily !== 'Basic')
			return { size: (_fontSize * 1 + self.fontSize)+"px", family: self.fontFamily };
		else
			return { size: (_fontSize * 1 + self.fontSize)+"px" };
	}
	
	this.getCustomFontStringForItem = function(_fontSize){
		if(self.fontCoverage.Item)
			return (self.fontFamily==='Basic'?'font-family: "맑은 고딕"; ':"font-family:"+self.fontFamily+"; ") + ("font-size:"+ (_fontSize * 1 + self.fontSize) + "px;");
		else
			return 'font-family: Noto Sans KR, sans-serif; font-size: ' + _fontSize + "px";
	}
	
	this.getCustomFontStringForMenu = function(_fontSize){
		if(self.fontCoverage.Menu)
			return (self.fontFamily==='Basic'?'':"font-family:"+self.fontFamily+"; ") + ("font-size:"+ (_fontSize * 1 + self.fontSize) + "px;");
		else
			return 'font-family: Noto Sans KR, sans-serif; font-size: ' + _fontSize + "px";
	}
	
	this.getFontSize = function(_fontSize, _coverage){
		if(self.fontCoverage[_coverage])
			return (_fontSize * 1 + self.fontSize)+"px";
		else
			return _fontSize+"px";
	}
	
	this.getFontSizeNumber = function(_fontSize, _coverage){
		if(self.fontCoverage[_coverage])
			return (_fontSize * 1 + self.fontSize);
		else
			return _fontSize;
	}
	
	this.getFontFamily = function(_coverage){
		if(self.fontCoverage[_coverage])
			return self.fontFamily;
		else if(_coverage === 'Item')
			return "맑은 고딕";
		else
			return '"Noto Sans KR", sans-serif';
	}
	
	this.setFontConfigForListPopup = function(id){
		$('#' + id).css('font-size', self.getFontSize(14, 'Menu'));
		$('#' + id).css('font-family', self.getFontFamily('Menu'));
		$('#' + id + ' .dx-texteditor-input').css('font-size', self.getFontSize(14, 'Menu'));
		$('#' + id + ' .dx-texteditor-input').css('font-family', self.getFontFamily('Menu'));
		$('.dx-popup-content .dx-widget').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-popup-content .dx-widget').css('font-family', self.getFontFamily('Menu'));
		$('.dx-popup-content .modal-tit').css('font-size', self.getFontSize(18, 'Menu'));
		$('.dx-popup-content .modal-tit').css('font-family', self.getFontFamily('Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('font-size', self.getFontSize(20, 'Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('font-family', self.getFontFamily('Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('max-width', '');
		$('.dx-popup-content .dx-texteditor-container').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-popup-content .dx-texteditor-container').css('font-family', self.getFontFamily('Menu'));
		$('.dx-popup-content input').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-popup-content input').css('font-family', self.getFontFamily('Menu'));
		$('#' + id + ' .dx-header-row').children().css("text-align", "center");
		/* DOGFOOT syjin 연결 보고서 보고서 목록 스크롤 표시 오류 수정  20210309 */
		if(WISE.Constants.editmode != 'viewer'){
			$(".dx-treeview-with-search > .dx-scrollable").css('height', "383px");
		}
		/* DOGFOOT jhseo 데이터 집합 기존 데이터 집합 레이아웃 중간에 잘리는 오류 수정 20210319 */
		$("#data_list > .dx-scrollable").css('height', "480px");
		
	}
	
	this.setFontConfigForList = function(id){
		$('#' + id).css('font-size', gDashboard.fontManager.getFontSize(14, 'Menu'));
		$('#' + id).css('font-family', gDashboard.fontManager.getFontFamily('Menu'));
		$('#' + id + ' .dx-texteditor-input').css('font-size', gDashboard.fontManager.getFontSize(14, 'Menu'));
		$('#' + id + ' .dx-texteditor-input').css('font-family', gDashboard.fontManager.getFontFamily('Menu'));
		$('#' + id + ' .dx-texteditor-container').css('font-size', gDashboard.fontManager.getFontSize(14, 'Menu'));
		$('#' + id + ' .dx-texteditor-container').css('font-family', gDashboard.fontManager.getFontFamily('Menu'));
		$('#' + id + ' .dx-header-row').children().css("text-align", "center");
	}
	
	this.setFontConfigForOption = function(id){
		$('.dx-overlay-wrapper').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-overlay-wrapper').css('font-family', self.getFontFamily('Menu'));
		$('#' + id + ' select').css('font-size', self.getFontSize(14, 'Menu'));
		$('#' + id + ' select').css('font-family', self.getFontFamily('Menu'));
		$('.dx-popup-content .dx-widget').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-popup-content .dx-widget').css('font-family', self.getFontFamily('Menu'));
		$('.dx-popup-content .modal-tit').css('font-size', self.getFontSize(18, 'Menu'));
		$('.dx-popup-content .modal-tit').css('font-family', self.getFontFamily('Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('font-size', self.getFontSize(20, 'Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('font-family', self.getFontFamily('Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('max-width', '');
		$('.dx-popup-content input').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-popup-content input').css('font-family', self.getFontFamily('Menu'));
		$('#' + id + ' .dx-header-row').children().css("text-align", "center");
	}
	
	this.setFontConfigForEditText = function(id){
		$('.dx-overlay-wrapper input').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-overlay-wrapper input').css('font-family', self.getFontFamily('Menu'));
		$('.dx-popup-content p').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-popup-content p').css('font-family', self.getFontFamily('Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('font-size', self.getFontSize(20, 'Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('font-family', self.getFontFamily('Menu'));
		$('.dx-overlay-content .dx-toolbar-label').css('max-width', '');
		$('.dx-popup-content .dx-widget').css('font-size', self.getFontSize(14, 'Menu'));
		$('.dx-popup-content .dx-widget').css('font-family', self.getFontFamily('Menu'));
		$('#' + id + ' .dx-header-row').children().css("text-align", "center");
	}
}