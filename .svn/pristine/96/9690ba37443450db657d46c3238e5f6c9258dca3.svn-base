/**
 * 2020.05.12 MKSON DOGFOOT
 * 모든 아이템의 데이터 항목 영역은 이곳에서 관리
 */

WISE.libs.Dashboard.item.FieldChooser = function() {
	var self = this;
	var $fieldChooser;

	this.$content;
	this.panelManager = {};
	this.fieldManager;
	this.fieldChooserQuantity = 1;
	
	var $l, $r;
	
	(function() {
		//필터
//		self.fieldFilter = new WISE.libs.Dashboard.FieldFilter();
	})();
	
	this.init = function(){
		self.panelManager['left'] = $l = $('#wise-area-all');
	}
	
	this.setFieldArea = function(){
		if(WISE.Constants.editmode != 'viewer'){
			$l.empty();	
		}
		/* DOGFOOT ktkang KERIS IE에서 UI 오류 수정  20200310 */
		var $at = self.panelManager['allTitle'] = $('<div id="dataSetLookUp" style="width:calc(100% - 15px);"/>').appendTo($l);
		
//		var $ac = self.panelManager['allContent'] = $('<div class="wise-area-content" />').appendTo($l);
//		var $acp = self.panelManager['allContentPanel'] = $('<ul id="allList" class="wise-area-content-pane wise-area-content-pane-all drop-panel scrollbar" />').appendTo($ac);
		var $acp = self.panelManager['allContentPanel'] = $('#allList'); 

		// all area title
//		$('<span class="wise-area-icon wise-area-icon-dimension" />').appendTo($at);
//		$('<span>&nbsp;</span>').appendTo($at);
//		$('<span class="wise-area-caption">' + gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.allfiled') + '</span>').appendTo($at);
		
		//검색2
		var $as = self.panelManager['allContentSearch'] = $('<div id="allListSearchContainer" class="wise-area-content-search" />').appendTo($l);
		$('<input id="allListSearchWord" class="dx-texteditor-input" type="text" />')
			.appendTo($as)
			.on('keyup',function() {
				self.allListSearch();
			});
		
//		if(self.fieldManager.searchDisable) {
//			$as.css('display','none');
//			$acp.css('height','95.2%');
//		}
		//검색2
		self.onWheel($acp);
	}
	
	this.resetAnalysisFieldArea = function (_item){
		if ($r) {
			$r.css('display','none');
			self.panelManager['right']= $r = $(_item.fieldManager.stateFieldChooser).children();
			$r.css('display','block');
		}
	};
	
	//2020.05.21 ajkim 변동측정값 필드 생성 메소드 dogfoot
	this.setDeltaFieldArea = function(_item){
		var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;
		
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $dva = $('<div class="panel-body wise-area wise-area-deltaval" style="display:none;"/>').appendTo($r);
		var $dvt = self.panelManager['deltaValueTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.deltavaluefiled')+'</span>').appendTo($dva);
		var $dvcp = self.panelManager['deltaValueContentPanel'+index] = $('<div id="deltavalueList' + index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-row drop-panel" />').appendTo($dva);
	};
	
	//2020.05.21 ajkim 측정값 필드 생성 메소드 dogfoot
	this.setValueFieldArea = function(_title, _id, _item){
		var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;
		
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $da = $('<div class="panel-body wise-area wise-area-value" />').appendTo($r);
		//2020.07.22 mksong 카드 측정값 최대 2개 가능하도록 수정 dogfoot
		//DOGFOOT syjin 2020-12-04 카카오 지도 측정값 최대 1개 가능하도록 수정
		var valueListMessage = gMessage.get('WISE.message.page.widget.drop.data-field');
		switch(_id){
			case 'cardValueList' :
				valueListMessage += '(최대 2개 가능)';
				break;
			case 'scatterplotValueList' :
				valueListMessage += '(최대 3개 가능)';
				break;
			case 'kakaoMapValueList' :
                valueListMessage += '(최대 1개 가능)';
                break;
//			case 'timelinechartValueList' :
//				valueListMessage += '(2개 단위로 필요)';
//				break;
			default :
				break;
		}
//		if(_id == ){
//			valueListMessage += '(최대 2개 가능)';
//		}
		self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico_sigma.png" style="width:23px;height:23px;margin-bottom:2px;">' + valueListMessage + '<a id="' + _id + index + '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($da);
		var $dcp = self.panelManager[_title +'ContentPanel'+ index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel drop-data" />').appendTo($da);
		
		if(_item.dataFields != undefined){
			if(_item.dataFields.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
			}	
		}
		else if(_item.measures != undefined){
			if(_item.measures.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
			}	
		}else{
			$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
		}
		
		self.onWheel($dcp);
	}
	
	//2020.09.08 syjin 차트 측정값 생성 메소드 dogfoot
	this.setChartValueFieldArea = function(_title, _id, _item){
		var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;
		
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $da = $('<div class="panel-body wise-area wise-area-value" />').appendTo($r);
		//2020.07.22 mksong 카드 측정값 최대 2개 가능하도록 수정 dogfoot
		var chartValueListMessage = gMessage.get('WISE.message.page.widget.drop.chartValue');
		switch(_id){
			case 'cardValueList' :
				valueListMessage += '(최대 2개 가능)';
				break;
			case 'scatterplotValueList' :
				valueListMessage += '(최대 3개 가능)';
				break;
//			case 'timelinechartValueList' :
//				valueListMessage += '(2개 단위로 필요)';
//				break;
			default :
				break;
		}
//		if(_id == ){
//			valueListMessage += '(최대 2개 가능)';
//		}
		self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico_sigma.png" style="width:23px;height:23px;margin-bottom:2px;">' + chartValueListMessage + '<a id="' + _id + index + '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($da);
		var $dcp = self.panelManager[_title +'ContentPanel'+ index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel drop-data" />').appendTo($da);
		
		if(_item.dataFields != undefined){
			if(_item.dataFields.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newchartValue') + '</a></li></ul>').appendTo($dcp);
			}	
		}
		else if(_item.measures != undefined){
			//2020.09.18 syjin dogfoot	카카오 불러오기 임시 세팅
			if(_item.measures.length == 0 || _item.type == 'KAKAO_MAP'){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newchartValue') + '</a></li></ul>').appendTo($dcp);
			}	
		}else{
			$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newchartValue') + '</a></li></ul>').appendTo($dcp);
		}
		
		self.onWheel($dcp);
	}
	
	//2020.05.21 ajkim 차원 필드 생성 메소드 dogfoot
	this.setDimensionFieldArea = function(_title, _id, _item){
		//2020.07.22 mksong 카드 측정값 최대 2개 가능하도록 수정 dogfoot
		var dimensionListMessage = gMessage.get('WISE.message.page.widget.drop.parameter');
		
		switch(_id){
			case 'heatmapParameterList' :
			case 'heatmap2ParameterList' :
			/*dogfoot 버블팩 차원 2개 필요 메세지 출력 shlim 20201123*/
			case 'bubblepackchartParameterList' :
			case 'bipartitechartParameterList' :
				dimensionListMessage += '(2개 필요)';
				break;
			case 'sankeychartParameterList' :
				dimensionListMessage += '(최대 4개 가능)';
				break;
			default :
				break;
		}
		if(_title === 'timelinechartStartDate'){
			dimensionListMessage = '날짜 차원 (시작)';
		}else if(_title === 'timelinechartEndDate'){
			dimensionListMessage = '날짜 차원 (끝)';
		}
//		if(_id == 'heatmapParameterList' || _id == 'bipartitechartParameterList'){
//			dimensionListMessage += '(최대 2개 가능)';
//		}else if(_id == 'sankeychartParameterList'){
//			dimensionListMessage += '(최대 4개 가능)';
//		}
		
		var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;
		
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $hp = $('<div class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);
		var $hpt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + dimensionListMessage + '<a id="' + _id + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($hp);
		var $hpcp = self.panelManager[_title + 'ContentPanel'+index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		if(_item.filterDimensions != undefined){
			if(_item.filterDimensions.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newparameter') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else if(_item.arguments != undefined){
			if(_item.arguments.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newparameter') +  '</a></li></ul>').appendTo($hpcp);
			}
			//2020.09.18 syjin 카카오맵 불러오기 수정 dogfoot
		}else if(_item.markerDimensions != undefined){
			if(_item.markerDimensions.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newparameter') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else if(_item.dimensions != undefined){
			if(_item.dimensions.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newparameter') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newparameter') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);
	}
	
	/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
	this.setVariableFieldArea = function(_title, _id, _item, variableNm){

		var index = _item.index;
		if(gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType === 'RAnalysis') {
			index = 1;
		}
		 
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var valueListMessage = variableNm;
		
		var $da = $('<div class="panel-body wise-area wise-area-value" />').appendTo($r);
		
		self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico_sigma.png" style="width:23px;height:23px;margin-bottom:2px;">' + valueListMessage + '<a id="' + _id + index + '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($da);
		var $dcp = self.panelManager[_title +'ContentPanel'+ index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel drop-data" />').appendTo($da);

		if(_item.dataFields != undefined){
			if(_item.dataFields.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + variableNm + '</a></li></ul>').appendTo($dcp);
			}	
		}
		else if(_item.measures != undefined){
			if(_item.measures.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + variableNm + '</a></li></ul>').appendTo($dcp);
			}else if(gDashboard.reportType == "StaticAnalysis" || gDashboard.reportType === 'RAnalysis'){
				var listCheck = false;
				$.each(_item.columns,function(_i,_contid){
					if(_id === _contid.ContainerType){
						listCheck = true;
					}
				})
				if(!listCheck){
					$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + variableNm + '</a></li></ul>').appendTo($dcp);
				}
			}	
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + variableNm + '</a></li></ul>').appendTo($dcp);
		}
		
		self.onWheel($dcp);
	}
	// EPAS merge용 
	//20210609 syjin 코로플레스 데이터항목 레이아웃 수정 dogfoot
	this.setStateFieldArea = function(_title, _id, _item){
		
		var StateListMessage = gMessage.get('WISE.message.page.widget.drop.state');
		
		//20210419 AJKIM 뷰어 대시보드 데이터 항목 추가 dogfoot
		var index = _item.index;
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $hp = $('<div id="'+_item.ComponentName+'_stateList" class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);
		var $hpt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + StateListMessage + '<a id="' + _id + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png"></a></span>').appendTo($hp);
		var $hpcp = self.panelManager[_title + 'ContentPanel'+index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		
		if(_item.states != undefined){
			if(_item.latitudes.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newstate') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newstate') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);	

	}
	
	this.setCityFieldArea = function(_title, _id, _item){
		
		var CityListMessage = gMessage.get('WISE.message.page.widget.drop.city');
		
		//20210419 AJKIM 뷰어 대시보드 데이터 항목 추가 dogfoot
		var index = _item.index;
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $hp = $('<div id="'+_item.ComponentName+'_stateList" class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);
		var $hpt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + CityListMessage + '<a id="' + _id + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png"></a></span>').appendTo($hp);
		var $hpcp = self.panelManager[_title + 'ContentPanel'+index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		
		if(_item.cities != undefined){
			if(_item.cities.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newcity') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newcity') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);	

	}

	this.setDongFieldArea = function(_title, _id, _item){
		
		var DongListMessage = gMessage.get('WISE.message.page.widget.drop.dong');
		
		//20210419 AJKIM 뷰어 대시보드 데이터 항목 추가 dogfoot
		var index = _item.index;
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $hp = $('<div id="'+_item.ComponentName+'_stateList" class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);
		var $hpt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + DongListMessage + '<a id="' + _id + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png"></a></span>').appendTo($hp);
		var $hpcp = self.panelManager[_title + 'ContentPanel'+index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		
		if(_item.dongs != undefined){
			if(_item.dongs.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdong') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdong') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);	

	}
	
	//2020.09.02 syjin 카카오맵 위도 추가 dogfoot
	this.setLatitudeFieldArea = function(_title, _id, _item){
		
		var LatitudeListMessage = gMessage.get('WISE.message.page.widget.drop.lattitude');
		
		//2020.09.22 mksong dogfoot 카카오지도 로케이션타입에 따른 동기화
		var $hp = $('<div id="'+_item.ComponentName+'_latitudeList" class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);
		var $hpt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + LatitudeListMessage + '<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($hp);
		var $hpcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		
		//2020.09.18 syjin 카카오맵 불러오기 수정 dogfoot
		if(_item.latitudes != undefined){
			if(_item.latitudes.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newlattitude') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newlattitude') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);	

	}
	
	//2020.09.02 syjin 카카오맵 경도 추가 dogfoot
	this.setLongitudeFieldArea = function(_title, _id, _item){
		var LongitudeListMessage = gMessage.get('WISE.message.page.widget.drop.longitude');
		
		var $hp = $('<div id="'+_item.ComponentName+'_longitudeList" class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);
		var $hpt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + LongitudeListMessage + '<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($hp);
		var $hpcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		//2020.09.18 syjin 카카오맵 불러오기 수정 dogfoot		
		if(_item.longitudes != undefined){
			if(_item.longitudes.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newlongtitude') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newlongtitude') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);
	}
	
	//2020.09.08 syjin 카카오맵 주소 추가 dogfoot
	this.setAddressFieldArea = function(_title, _id, _item){
		var AddressListMessage = gMessage.get('WISE.message.page.widget.drop.address');
		
		//2020.09.22 mksong dogfoot 카카오지도 로케이션타입에 따른 동기화
		var $hp = $('<div id="'+_item.ComponentName+'_addressList" class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);

		//2020.11.17 syjin dogfoot 카카오지도 selectBox ui 수정
		var $hpt = self.panelManager[_title + 'Title'] = 
		    $('<span style="margin:0px; display:flex; justify-content: space-between;" class="addressLabel label">'+
		        '<div style="display:flex; width:90%;">' +
		            '<div style="display:flex; width:50px; margin-right:10px;">' +
		                '<img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' +
		                    '<span style="display:block; width:100px;">' + AddressListMessage + '</span>'+
		            '</div>' +		            
		        '<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;">' +
		        '</div>' +
					'<img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화">' +
				'</a>' +				
		        '</span>' +		      
		        '<div style="margin-bottom:5px;" id="'+_item.ComponentName+'addressSelectLabel">' +
				'</div>').appendTo($hp);
		//2020.10.23 syjin dogfoot 카카오지도 selectBox 추가
		//2020.11.05 syjin dogfoot 카카오지도 item별 select box 생기도록 수정
		var dataSource = ['시도', '시도+시군구', '시도+시군구+읍면동'];
		
		//2020.10.28 mksong addressType 세팅 dogfoot
		var addressValue = dataSource[0];
		if(_item.addresses != undefined && _item.addresses.length!=0){
			if(_item.addresses[0].addressType != undefined){
				switch(_item.addresses[0].addressType){
					case 'Sido':
						addressValue = '시도';
						break;
					case 'SiGunGu':
						addressValue = '시도+시군구';
						break;
					case 'EupMyeonDong':
						addressValue = '시도+시군구+읍면동';
						break;
				}
			}
		}
		
		//2020.11.05 syjin dogfoot 카카오지도 item별 select box 생기도록 수정
		$("#"+_item.ComponentName+"addressSelectLabel").dxSelectBox({
			items : dataSource,
			value : addressValue,
			//2020.11.02 syjin 카카오맵 selectBox 반응형 처리 dogfoot
			//width : 100,
			height: 27
		}).dxSelectBox('instance');
		var $hpcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		//2020.09.18 syjin 카카오맵 불러오기 수정 dogfoot			
		if(_item.addresses != undefined){
			if(_item.addresses.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newaddress') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newaddress') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);
	}
	
	//2020.09.08 syjin 카카오맵 차트 차원 추가 dogfoot
	this.setChartDimensionFieldArea = function(_title, _id, _item){
		var chartDimensionListMessage = gMessage.get('WISE.message.page.widget.drop.chartDimension');
		
		var $hp = $('<div class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);
		var $hpt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + chartDimensionListMessage + '<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($hp);
		var $hpcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		if(_item.filterDimensions != undefined){
			if(_item.filterDimensions.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newchartDimension') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else if(_item.arguments != undefined){
			if(_item.arguments.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newchartDimension') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else if(_item.dimensions != undefined){
			//2020.09.18 syjin 카카오맵 불러오기 수정 dogfoot
			if(_item.dimensions.length == 0 || _item.type == 'KAKAO_MAP'){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newchartDimension') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newchartDimension') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);
	}
	
	//2020.09.08 syjin 카카오맵 필드 추가 dogfoot
	this.setKakaoFieldArea = function(_title, _id, _item){
		var fieldListMessage = gMessage.get('WISE.message.page.widget.drop.field');
		
		var $hp = $('<div class="panel-body wise-area wise-area-hyperparameter" />').appendTo($r);
		var $hpt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + fieldListMessage + '<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($hp);
		var $hpcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($hp);
		if(_item.filterDimensions != undefined){
			if(_item.filterDimensions.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfield') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else if(_item.arguments != undefined){
			if(_item.arguments.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfield') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else if(_item.dimensions != undefined){
			if(_item.dimensions.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfield') +  '</a></li></ul>').appendTo($hpcp);
			}
		}else{
			if(_item)
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfield') +  '</a></li></ul>').appendTo($hpcp);
		}

		self.onWheel($hpcp);
	}
	
	//2020.05.21 ajkim 차원 그룹 필드 생성 메소드 dogfoot
	this.setSeriesFieldArea = function(_title, _id, _item){
		var $sr = $('<div class="panel-body wise-area wise-area-series" />').appendTo($r);
		/* DOGFOOT syjin 뷰어 불러오기 수정  20211118*/
		var index = _item.index;
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
//		if(_title === 'timelinechartSeries'){
//            var $srt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;"> 날짜 차원<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png"></a></span>').appendTo($sr);
//		}else
		if(_title === 'divergingchartSeries'){
		    var $srt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;"> 카테고리 <a id="' + _id + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($sr);	
		}else{
		    var $srt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + gMessage.get('WISE.message.page.widget.drop.series') + '<a id="' + _id + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($sr);	
		}
//		var $src = self.panelManager['chartSeriesContent'] = $('<div class="wise-area-content" />').appendTo($sr);
		var $srcp = self.panelManager[_title + 'ContentPanel'+ index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($sr);
		
		if(_item.seriesDimensions != undefined){
			if(_item.seriesDimensions.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + (_title !== 'divergingchartSeries'? gMessage.get('WISE.message.page.widget.drop.newseries') : gMessage.get('WISE.message.page.widget.drop.newparameter')) +  '</a></li></ul>').appendTo($srcp);
			}	
		}else{
			$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + (_title !== 'divergingchartSeries'? gMessage.get('WISE.message.page.widget.drop.newseries') : gMessage.get('WISE.message.page.widget.drop.newparameter')) +  '</a></li></ul>').appendTo($srcp);
		}

		self.onWheel($srcp);
	}

	//2020.05.21 ajkim 행 필드 생성 메소드 dogfoot
	this.setRowFieldArea = function(title,_item){
		var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;
		
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $ro = $('<div class="panel-body wise-area wise-area-row" />').appendTo($r);
		var $rt = self.panelManager[title+'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.rowfiled')+'<a id="' + title + 'List' + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($ro);
		var $rcp = self.panelManager[title+'ContentPanel'+index] = $('<div id="'+title+'List' + index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-row drop-panel dimension drop-dimension" />').appendTo($ro);
		if(_item.rows != undefined){
			if(_item.rows.length == 0){
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newrowfiled') + '</a></li></ul>').appendTo($rcp);
			}	
		}else{
			$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newrowfiled') + '</a></li></ul>').appendTo($rcp);
		}
		
		self.onWheel($rcp);
	}
	
	//2020.05.21 ajkim 열 필드 생성 메소드 dogfoot
	this.setColumnFieldArea = function(title,_item){
		var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;
		
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $co = $('<div class="panel-body wise-area wise-area-col" />').appendTo($r);
		var $ct = self.panelManager[title+'Title'] = $('<span class="label"><img src ="'+ WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.columnfiled')+'<a id="'+title+'List' + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($co);
		var $ccp = self.panelManager[title+'ContentPanel'+index] = $('<div id="'+title+'List' + index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($co);
		
		if(_item.columns != undefined){
			if(_item.columns.length == 0){
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newcolumnfiled') + '</a></li></ul>').appendTo($ccp);
			}	
		}else{
			$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newcolumnfiled') + '</a></li></ul>').appendTo($ccp);
		}
		
		self.onWheel($ccp);
	}
	
	//2020.05.21 ajkim 일반 그리드 필드 생성 메소드 dogfoot
	this.setBasicFieldArea = function(_title, _id, _item){
		var $da = $('<div class="panel-body wise-area wise-area-datagrid-col"/>').appendTo($r);
		var $dt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">'+gMessage.get('WISE.message.page.widget.drop.column')+'<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($da);
		var $dcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-column drop-panel drop-data drop-dimension" />').appendTo($da);
		
		if(_item.columns != undefined){
			if(_item.columns.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
			}	
		}else{
			$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
		}
		self.onWheel($dcp);
	}
	
	this.setBubbleChartFieldArea = function(_title, _id, _item){
		var $da = $('<div class="panel-body wise-area wise-area-datagrid-col"/>').appendTo($r);
		var $dt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + _title.split("bubbleChart")[1] + '<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($da);
		var $dcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-column drop-panel drop-data drop-dimension" />').appendTo($da);
		
		if(_item.arguments != undefined){
			if(_item.arguments.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
			}	
		}else{
			$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
		}
		self.onWheel($dcp);
	}
	
	this.setScatterPlotFieldArea = function(_title, _id, _item){
		var t = _title.indexOf('X') > -1? 'X': _title.indexOf("Y") > -1? 'Y' : _title.indexOf("Z") > -1? 'Z' : '차원';
		if(_title.indexOf("Matrix") > -1){
			 t = _title.indexOf('X1') > -1? 'X1': _title.indexOf("X2") > -1? 'X2' : _title.indexOf("Y1") > -1? 'Y1' : _title.indexOf("Y2") > -1? 'Y2' : '차원';
		}
		
		if(t !== 'Z'){
			var $da = $('<div class="panel-body wise-area wise-area-datagrid-col"/>').appendTo($r);
			var $dt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/'+((_title.indexOf("coordinate") > -1&& (t === 'X' || t === 'Y'))? 'ico_sigma': 'ico-blockFolder')+'.png" style="width:23px;height:23px;margin-bottom:2px;">' + t + '<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($da);
			var $dcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-column drop-panel drop-data drop-dimension" />').appendTo($da);
			
			if(_title.indexOf("Matrix") === -1){
				if(_item.dimensions != undefined){
					if(_item.dimensions.length == 0 || (_item.dimensions.length == 1 && t !== 'X') || (_item.dimensions.length == 2 && t === '차원')){
						$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
					}
				}else{
					$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
				}
			}else{
				if(_item.dimensions != undefined){
					if(_item.dimensions.length == 0 || (_item.dimensions.length <= 0 && t === 'X1') || (_item.dimensions.length <= 1 && t === 'Y1') || (_item.dimensions.length <= 2 && t === 'X2') || (_item.dimensions.length <= 3 && t === 'Y2') || (_item.dimensions.length <= 4 && t === '차원')){
						$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
					}
				}else{
					$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
				}
			}
			
			self.onWheel($dcp);
		}else{
			var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;
			
			if(WISE.Constants.editmode == 'viewer'){
				index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
			}
			
			var $da = $('<div class="panel-body wise-area wise-area-value" />').appendTo($r);
			//2020.07.22 mksong 카드 측정값 최대 2개 가능하도록 수정 dogfoot
			var valueListMessage = "Z"

			self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico_sigma.png" style="width:23px;height:23px;margin-bottom:2px;">' + valueListMessage + '<a id="' + _id + index + '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($da);
			var $dcp = self.panelManager[_title +'ContentPanel'+ index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel drop-data" />').appendTo($da);
			
			if(_item.measures != undefined){
				if(_item.measures.length == 0){
					$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
				}	
			}else{
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
			}
			
			self.onWheel($dcp);
		}
	}
	
	this.setHistoryTimelineFieldArea = function(_title, _id, _item){
		var t = ""

		switch(_title){
		case 'historyTimelineStart' :
			t = '날짜 차원 (시작)';
			break;
		case 'historyTimelineEnd' :
			t = '날짜 차원 (끝)';
			break;
		case 'historyTimelineParameter' :
			t = '차원';
			break;
		}
		
		var $da = $('<div class="panel-body wise-area wise-area-datagrid-col"/>').appendTo($r);
		var $dt = self.panelManager[_title + 'Title'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">' + t + '<a id="' + _id + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($da);
		var $dcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="' + _id + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-column drop-panel drop-data drop-dimension" />').appendTo($da);

		if(_item.dimensions != undefined){
			if(_item.dimensions.length == 0 || (_item.dimensions.length <= 1 && _title === 'historyTimelineEnd') || (_item.dimensions.length <= 2 && _title === 'historyTimelineParameter')){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
			}
		}else{
			$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
		}
		
		self.onWheel($dcp);
	}
	
	//2020.05.21 ajkim 스파크라인 필드 생성 메소드 dogfoot
	this.setSparkLineFieldArea = function(_title, _id, _item, _invisible){
		/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
		if(gDashboard.reportType === 'DSViewer') return;
		var $sl;
		if(_invisible)
			$sl = $('<div class="panel-body wise-area wise-area-sparkline"/>').appendTo($r);
		else	
			$sl = $('<div class="panel-body wise-area wise-area-sparkline" />').appendTo($r);
		var $slt = self.panelManager[_title + 'Title'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.drop.sparkline')+'<a id="' + _title + _item.index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($sl);
		var slcp = self.panelManager[_title + 'ContentPanel'+_item.index] = $('<div id="'+ _title + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-column drop-panel " />').appendTo($sl);
		
		if(_item.sparklineElements != undefined){
			if(_item.sparklineElements.length == 0){
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newsparkline') + '</a></li></ul>').appendTo(slcp);
			}	
		}else{
			$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newsparkline') + '</a></li></ul>').appendTo(slcp);
		}
	}
	
	//2020.05.21 ajkim 정렬 기준 항목 필드 생성 메소드 dogfoot
	this.setHiddenMeasureFieldArea = function(_title, _id, _item){
		if(gDashboard.reportType === 'DSViewer') return;
		var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;
		
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		
		var $hda = $('<div class="panel-body wise-area wise-area-hidden" />').appendTo($r);
		var $hd = $('<div class="wise-area wise-area-hide_column_list" />').appendTo($hda);
		$('<span class="wise-area-icon wise-area-icon-hide_column_list" />').appendTo($hd);
		//jhseo 에디터에서만 정렬기준항목 나오게
		if(reportType != 'Editor'){
				var $hdmt = self.panelManager[_title + 'Title'] = $('<span style="display:none;" class="label">' + gMessage.get('WISE.message.page.widget.panel.hide_column_list') + '<a id="' + _id + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($hd);
				var $hdmcp = self.panelManager[_title + 'ContentPanel'+index] = $('<div style="display:none;" id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel drop-hiddendata" />').appendTo($hd);
			if(_item.HiddenMeasures != undefined){
				if(_item.HiddenMeasures.length == 0){
					$('<ul style="display:none;" class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
				}	
			}else{
				$('<ul style="display:none;" class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
			}
		}else{
			var $hdmt = self.panelManager[_title + 'Title'] = $('<span class="label">' + gMessage.get('WISE.message.page.widget.panel.hide_column_list') + '<a id="' + _id + index+ '_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png" title="초기화"></a></span>').appendTo($hd);
			var $hdmcp = self.panelManager[_title + 'ContentPanel'+index] = $('<div id="' + _id + index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel drop-hiddendata" />').appendTo($hd);
			if(_item.HiddenMeasures != undefined){
				if(_item.HiddenMeasures.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
			}
		}
	}
	
	//2020.05.21 ajkim 데이터 항목 set 공통처리 dogfoot
	this.setAnalysisFieldArea = function(_item, _isAdhoc){
		var setArea = function(){
			var measurePositionBottom = false;
			
			if(userJsonObject.menuconfig.Menu.MEASURE_POSITION_BOTTOM){
				measurePositionBottom = true;
			}
			
			//2020.09.22 mksong dogfoot 카카오지도 로케이션타입에 따른 동기화
			var setTitle;
			if(_item.type == 'KAKAO_MAP'){
				//2020.12.11 syjin 데이터 항목 주소 좌표 레이아웃 수정 수정  dogfoot
				setTitle = $('<h4 class="tit-level3" id="kakaoContentType" style="display:flex; padding-right:15px; justify-content: space-between; content:none;"><div>데이터 항목</div><div id="'+_item.ComponentName+'_locationType" style=""></div></h4>').appendTo($r);
				
				document.styleSheets[0].addRule('#kakaoContentType:after','content: none');
				
			}else{
				setTitle = $('<h4 class="tit-level3">데이터 항목</h4>').appendTo($r);
			}
			
			if(_isAdhoc){
//				self.setValueFieldArea('datafieldAdHoc', 'dataAdHocList', _item);
				if(!measurePositionBottom){
					self.setValueFieldArea('datafieldAdHoc', 'dataAdHocList', _item);
				}
				self.setRowFieldArea('rowAdHoc',_item);
				self.setColumnFieldArea('colAdHoc',_item);
				self.setDeltaFieldArea(_item);
				self.setHiddenMeasureFieldArea('adhoc_hide_column_list_mea', 'adhoc_hide_measure_list', _item);
				/*dogfoot 측정값 위치 변경 shlim 20210310*/ 
				if(measurePositionBottom){
					self.setValueFieldArea('datafieldAdHoc', 'dataAdHocList', _item);
				}
				$('.panelClear').off('click').on('click',function(e){
					var panel_id = e.currentTarget.id;
					panel_id = panel_id.substr(0,panel_id.lastIndexOf('_clear'));
					$('#'+panel_id).empty();
					gDashboard.dragNdropController.recovery($('#'+panel_id));
					/*dogfoot 주제영역 클리어시 관계있는 차원값 안사라지는 오류 수정 shlim 20200715*/
					if(WISE.Context.isCubeReport && panel_id.indexOf('dataAdHocList') > -1){
						gDashboard.dragNdropController.cubeRelationCheck(_item);
					}
				});
				
				return;
			}
			switch(_item.type){
				/* goyong ktkang 측정값 순서 변경(맨아래로)  20210518 */
				case 'SIMPLE_CHART':
					_item.fieldManager.focusItemType = 'chart';
					if(!measurePositionBottom){
						self.setValueFieldArea('chartValue', 'chartValueList', _item);
					}
					self.setDimensionFieldArea('chartParameter', 'chartParameterList', _item);
					self.setSeriesFieldArea('chartSeries', 'chartSeriesList', _item);
					self.setHiddenMeasureFieldArea('chart_hide_column_list_mea', 'chart_hide_measure_list', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('chartValue', 'chartValueList', _item);
					}
					break;
				case 'PIE_CHART':
					_item.fieldManager.focusItemType = 'pieChart'
					if(!measurePositionBottom){
						self.setValueFieldArea('pieValue', 'pieValueList', _item);
					}
					self.setDimensionFieldArea('pieParameter', 'pieParameterList', _item);
					self.setSeriesFieldArea('pieSeries', 'pieSeriesList', _item);
					self.setHiddenMeasureFieldArea('pie_hide_column_list_mea', 'pie_hide_measure_list', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('pieValue', 'pieValueList', _item);
					}
					break;
				case 'HISTOGRAM_CHART':
					_item.fieldManager.focusItemType = 'histogramchart';
					self.setValueFieldArea('histogramchartValue', 'histogramchartValueList', _item);
//					self.setDimensionFieldArea('histogramchartParameter', 'histogramchartParameterList', _item);
					break;
				case 'WORD_CLOUD':
					_item.fieldManager.focusItemType = 'wordcloud';
					if(!measurePositionBottom){
						self.setValueFieldArea('wordcloudValue', 'wordcloudValueList', _item);
					}
					self.setDimensionFieldArea('wordcloudParameter', 'wordcloudParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('wordcloudValue', 'wordcloudValueList', _item);
					}
					break;
				case 'RECTANGULAR_ARAREA_CHART':
					_item.fieldManager.focusItemType = 'RectangularAreaChart';
					if(!measurePositionBottom){
						self.setValueFieldArea('RectangularAreaChartValue', 'RectangularAreaChartValueList', _item);
					}
					self.setDimensionFieldArea('RectangularAreaChartParameter', 'RectangularAreaChartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('RectangularAreaChartValue', 'RectangularAreaChartValueList', _item);
					}
					break;
				case 'BUBBLE_D3':
					_item.fieldManager.focusItemType = 'bubbled3';
					if(!measurePositionBottom){
						self.setValueFieldArea('bubbled3Value', 'bubbled3ValueList', _item);
					}
					self.setDimensionFieldArea('bubbled3Parameter', 'bubbled3ParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('bubbled3Value', 'bubbled3ValueList', _item);
					}
					break;
				case 'BUBBLE_CHART':
					_item.fieldManager.focusItemType = 'bubbleChart';
					if(!measurePositionBottom){
						self.setValueFieldArea('bubbleChartValue', 'bubbleChartValueList', _item);
					}
					self.setBubbleChartFieldArea('bubbleChartX', 'bubbleChartXList', _item);
					self.setBubbleChartFieldArea('bubbleChartY', 'bubbleChartYList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('bubbleChartValue', 'bubbleChartValueList', _item);
					}
					break;
				case 'FUNNEL_CHART':
					_item.fieldManager.focusItemType = 'funnelchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('funnelchartValue', 'funnelchartValueList', _item);
					}
					self.setDimensionFieldArea('funnelchartParameter', 'funnelchartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('funnelchartValue', 'funnelchartValueList', _item);
					}
					break;
				case 'PYRAMID_CHART':
					_item.fieldManager.focusItemType = 'pyramidchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('pyramidchartValue', 'pyramidchartValueList', _item);
					}
					self.setDimensionFieldArea('pyramidchartParameter', 'pyramidchartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('pyramidchartValue', 'pyramidchartValueList', _item);
					}
					break;
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case 'KAKAO_MAP':
					_item.fieldManager.focusItemType = 'kakaoMap';
					if(!measurePositionBottom){
						self.setValueFieldArea('kakaoMapValue', 'kakaoMapValueList', _item);
					}
					/* DOGFOOT syjin 카카오 지도 위도, 경도 추가  20200902 */
					self.setLatitudeFieldArea('kakaoMapLatitude', 'kakaoMapLatitudeList', _item);
					self.setLongitudeFieldArea('kakaoMapLongitude', 'kakaoMapLongitudeList', _item);
					/* DOGFOOT syjin 카카오 지도 ui 설정 추가  20200908 */
					self.setAddressFieldArea('kakaoMapAddress', 'kakaoMapAddressList', _item);
					
					self.setDimensionFieldArea('kakaoMapParameter', 'kakaoMapParameterList', _item); //차원
					if(measurePositionBottom){
						self.setValueFieldArea('kakaoMapValue', 'kakaoMapValueList', _item);
					}
					
					//2020.09.22 mksong dogfoot 카카오지도 로케이션타입에 따른 동기화
					$('#' + _item.ComponentName + '_locationType').dxRadioGroup({
						layout: "horizontal",
						width: 134,
						dataSource: ['주소', '좌표'],
						value: _item.Map.LocationType == undefined && _item.meta == undefined ? '주소' : (_item.Map.LocationType == 'address' || (_item.Map.LocationType == undefined && _item.meta.LocationType == 'address') ? '주소' : '좌표'),
						onInitialized: function(e){
							changeDataList(_item.Map.LocationType == undefined && _item.meta == undefined ? 'address' : _item.Map.LocationType || _item.meta.LocationType);
						},
						onValueChanged: function(e) {
							_item.Map.LocationType = e.value === '주소' ? 'address' : 'coordinate';
							changeDataList(_item.Map.LocationType);
							
							//DOGFOOT syjin 2020-11-30 주소일 때는 폴리곤만, 좌표일 때는 마커만 나오도록 구현
							_item.Map.ShowPointType = e.value ==='주소' ? 'polygon' : 'marker';
							
							//2020.12.09 mksong 카카오맵 포인트타입에 따른 메뉴 동기화 dogfoot
							if(_item.Map.ShowPointType == 'polygon'){
								$('#editMarker').parent().css('display','none');
								$('#editPolygon').parent().css('display','');
							}else{
								$('#editPolygon').parent().css('display','none');
								$('#editMarker').parent().css('display','');
							}
						}
					});
					function changeDataList(_locationType){
						if(_locationType == 'address'){
							$('#'+_item.ComponentName + '_longitudeList').css('display','none');
							$('#'+_item.ComponentName + '_latitudeList').css('display','none');
							$('#'+_item.ComponentName + '_addressList').css('display','block');
						}else{
							$('#'+_item.ComponentName + '_addressList').css('display','none');
							$('#'+_item.ComponentName + '_longitudeList').css('display','block');
							$('#'+_item.ComponentName + '_latitudeList').css('display','block');
						}
						compMoreMenuUi();
					}
					break;
				case 'KAKAO_MAP2':
					_item.fieldManager.focusItemType = 'kakaoMap2';
					if(!measurePositionBottom){
						self.setValueFieldArea('kakaoMap2Value', 'kakaoMap2ValueList', _item);
					}
					self.setDimensionFieldArea('kakaoMap2Parameter', 'kakaoMap2ParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('kakaoMap2Value', 'kakaoMap2ValueList', _item);
					}
					break;
				case 'WATERFALL_CHART':
					_item.fieldManager.focusItemType = 'waterfallchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('waterfallchartValue', 'waterfallchartValueList', _item);
					}
					self.setDimensionFieldArea('waterfallchartParameter', 'waterfallchartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('waterfallchartValue', 'waterfallchartValueList', _item);
					}
					break;
				case 'BIPARTITE_CHART':
					_item.fieldManager.focusItemType = 'bipartitechart';
//					self.setValueFieldArea('bipartitechartValue', 'bipartitechartValueList', _item);
					self.setDimensionFieldArea('bipartitechartParameter', 'bipartitechartParameterList', _item);
					break;
				case 'SANKEY_CHART':
					_item.fieldManager.focusItemType = 'sankeychart';
//					self.setValueFieldArea('sankeychartValue', 'sankeychartValueList', _item);
					self.setDimensionFieldArea('sankeychartParameter', 'sankeychartParameterList', _item);
					break;
					//평행좌표계
				case 'PARALLEL_COORDINATE':
					_item.fieldManager.focusItemType = 'parallel';
					if(!measurePositionBottom){
						self.setValueFieldArea('parallelValue', 'parallelValueList', _item);
					}
					self.setDimensionFieldArea('parallelParameter', 'parallelParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('parallelValue', 'parallelValueList', _item);
					}
					break;
				case 'DEPENDENCY_WHEEL':
					_item.fieldManager.focusItemType = 'dependencywheel';
//					self.setValueFieldArea('dependencywheelValue', 'dependencywheelValueList', _item);
					self.setDimensionFieldArea('dependencywheelParameter', 'dependencywheelParameterList', _item);
					break;
				case 'SEQUENCES_SUNBURST':
					_item.fieldManager.focusItemType = 'sequencessunburst';
					if(!measurePositionBottom){
						self.setValueFieldArea('sequencessunburstValue', 'sequencessunburstValueList', _item);
					}
					self.setDimensionFieldArea('sequencessunburstParameter', 'sequencessunburstParameterList', _item);
					if(!measurePositionBottom){
						self.setValueFieldArea('sequencessunburstValue', 'sequencessunburstValueList', _item);
					}
					break;
				case 'BOX_PLOT':
					/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
					if(_item.fieldManager.focusItemType !== undefined && _item.fieldManager.focusItemType !== _item.kind) {
						if(_item.fieldManager.focusItemType.indexOf('Anova') > -1) {
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Observed', _item.fieldManager.focusItemType + 'ObservedList', _item, gMessage.get('WISE.message.page.widget.analysis.observed'));
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Factor', _item.fieldManager.focusItemType + 'FactorList', _item, gMessage.get('WISE.message.page.widget.analysis.factor'));
							/*if(_item.fieldManager.focusItemType === 'onewayAnova2') {
								self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Item', _item.fieldManager.focusItemType + 'ItemList', _item, gMessage.get('WISE.message.page.widget.analysis.item'));
							}*/
						/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
						} else if(_item.fieldManager.focusItemType.indexOf('Correlation') > -1 || _item.fieldManager.focusItemType.indexOf('Test') > -1) {
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Numerical', _item.fieldManager.focusItemType + 'NumericalList', _item, gMessage.get('WISE.message.page.widget.analysis.numerical'));
						} else if(_item.fieldManager.focusItemType.indexOf('Regression') > -1) {
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Indpn', _item.fieldManager.focusItemType + 'IndpnList', _item, gMessage.get('WISE.message.page.widget.analysis.independent'));
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Dpndn', _item.fieldManager.focusItemType + 'DpndnList', _item, gMessage.get('WISE.message.page.widget.analysis.dependent'));
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Vector', _item.fieldManager.focusItemType + 'VectorList', _item, gMessage.get('WISE.message.page.widget.analysis.vector'));
						}
					} else {
						_item.fieldManager.focusItemType = 'boxplot';
						if(!measurePositionBottom){
							self.setValueFieldArea('boxplotValue', 'boxplotValueList', _item);
						}
						self.setDimensionFieldArea('boxplotParameter', 'boxplotParameterList', _item);
						if(measurePositionBottom){
							self.setValueFieldArea('boxplotValue', 'boxplotValueList', _item);
						}
					}
					break;
				case 'SCATTER_PLOT':
					_item.fieldManager.focusItemType = 'scatterplot';
					self.setScatterPlotFieldArea('scatterplotX', 'scatterplotXList', _item);
					self.setScatterPlotFieldArea('scatterplotY', 'scatterplotYList', _item);
					self.setScatterPlotFieldArea('scatterplotParameter', 'scatterplotParameterList', _item);
					break;
				case 'COORDINATE_LINE':
					_item.fieldManager.focusItemType = 'coordinateline';
					self.setScatterPlotFieldArea('coordinatelineX', 'coordinatelineXList', _item);
					self.setScatterPlotFieldArea('coordinatelineY', 'coordinatelineYList', _item);
					self.setScatterPlotFieldArea('coordinatelineParameter', 'coordinatelineParameterList', _item);
					break;
				case 'COORDINATE_DOT':
					_item.fieldManager.focusItemType = 'coordinatedot';
					self.setScatterPlotFieldArea('coordinatedotX', 'coordinatedotXList', _item);
					self.setScatterPlotFieldArea('coordinatedotY', 'coordinatedotYList', _item);
					self.setScatterPlotFieldArea('coordinatedotParameter', 'coordinatedotParameterList', _item);
					break;
				case 'SCATTER_PLOT2':
					_item.fieldManager.focusItemType = 'scatterplot2';
//					self.setValueFieldArea('scatterplotValue', 'scatterplotValueList', _item);
//					self.setValueFieldArea('scatterplotZ', 'scatterplotValueList', _item);
//					self.setDimensionFieldArea('scatterplotParameter', 'scatterplotParameterList', _item);
					self.setScatterPlotFieldArea('scatterplot2X', 'scatterplot2XList', _item);
					self.setScatterPlotFieldArea('scatterplot2Y', 'scatterplot2YList', _item);
					self.setScatterPlotFieldArea('scatterplot2Z', 'scatterplot2ZList', _item);
					self.setScatterPlotFieldArea('scatterplot2Parameter', 'scatterplot2ParameterList', _item);
//					self.setHiddenMeasureFieldArea('scatterplot2_hide_column_list_mea', 'scatterplot2_hide_measure_list', _item)
					break;
				case 'RADIAL_TIDY_TREE':
					_item.fieldManager.focusItemType = 'radialtidytree';
					self.setDimensionFieldArea('radialTidyTreeParameter', 'radialTidyTreeParameterList', _item);
					break;
				case 'ARC_DIAGRAM':
					_item.fieldManager.focusItemType = 'arcdiagram';
					self.setDimensionFieldArea('arcdiagramParameter', 'arcdiagramParameterList', _item);
					break;
				case 'SCATTER_PLOT_MATRIX':
					_item.fieldManager.focusItemType = 'scatterplotmatrix';
					self.setScatterPlotFieldArea('scatterPlotMatrixX1', 'scatterPlotMatrixX1List', _item);
					self.setScatterPlotFieldArea('scatterPlotMatrixY1', 'scatterPlotMatrixY1List', _item);
					self.setScatterPlotFieldArea('scatterPlotMatrixX2', 'scatterPlotMatrixX2List', _item);
					self.setScatterPlotFieldArea('scatterPlotMatrixY2', 'scatterPlotMatrixY2List', _item);
					self.setScatterPlotFieldArea('scatterPlotMatrixParameter', 'scatterPlotMatrixParameterList', _item);
					break;
				case 'HISTORY_TIMELINE':
					_item.fieldManager.focusItemType = 'historytimeline';
					self.setHistoryTimelineFieldArea('historyTimelineStart', 'historyTimelineStartList', _item);
					self.setHistoryTimelineFieldArea('historyTimelineEnd', 'historyTimelineEndList', _item);
					self.setHistoryTimelineFieldArea('historyTimelineParameter', 'historyTimelineParameterList', _item);
					break;
				case 'LIQUID_FILL_GAUGE':
					_item.fieldManager.focusItemType = 'liquidfillgauge';
					if(!measurePositionBottom){
						self.setValueFieldArea('liquidfillgaugeValue', 'liquidfillgaugeValueList', _item);
					}
					self.setDimensionFieldArea('liquidfillgaugeParameter', 'liquidfillgaugeParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('liquidfillgaugeValue', 'liquidfillgaugeValueList', _item);
					}
					break;
				case 'DIVERGING_CHART':
					_item.fieldManager.focusItemType = 'divergingchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('divergingchartValue', 'divergingchartValueList', _item);
					}
					self.setDimensionFieldArea('divergingchartParameter', 'divergingchartParameterList', _item);
					self.setSeriesFieldArea('divergingchartSeries', 'divergingchartSeriesList', _item);
					self.setHiddenMeasureFieldArea('divergingchart_hide_column_list_mea', 'divergingchart_hide_measure_list', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('divergingchartValue', 'divergingchartValueList', _item);
					}
					break;
				case 'BUBBLE_PACK_CHART':
					_item.fieldManager.focusItemType = 'bubblepackchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('bubblepackchartValue', 'bubblepackchartValueList', _item);
					}
					self.setDimensionFieldArea('bubblepackchartParameter', 'bubblepackchartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('bubblepackchartValue', 'bubblepackchartValueList', _item);
					}
					break;
				case 'WORD_CLOUD_V2':
					_item.fieldManager.focusItemType = 'wordcloudv2';
					if(!measurePositionBottom){
						self.setValueFieldArea('wordcloudv2Value', 'wordcloudv2ValueList', _item);
					}
					self.setDimensionFieldArea('wordcloudv2Parameter', 'wordcloudv2ParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('wordcloudv2Value', 'wordcloudv2ValueList', _item);
					}
					break;
				case 'DENDROGRAM_BAR_CHART':
					_item.fieldManager.focusItemType = 'dendrogrambarchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('dendrogrambarchartValue', 'dendrogrambarchartValueList', _item);
					}
					self.setDimensionFieldArea('dendrogrambarchartParameter', 'dendrogrambarchartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('dendrogrambarchartValue', 'dendrogrambarchartValueList', _item);
					}
					break;
				case 'CALENDAR_VIEW_CHART':
					_item.fieldManager.focusItemType = 'calendarviewchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('calendarviewchartValue', 'calendarviewchartValueList', _item);
					}
					self.setDimensionFieldArea('calendarviewchartParameter', 'calendarviewchartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('calendarviewchartValue', 'calendarviewchartValueList', _item);
					}
					break;
				case 'CALENDAR_VIEW2_CHART':
					_item.fieldManager.focusItemType = 'calendarview2chart';
					if(!measurePositionBottom){
						self.setValueFieldArea('calendarview2chartValue', 'calendarview2chartValueList', _item);
					}
					self.setDimensionFieldArea('calendarview2chartParameter', 'calendarview2chartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('calendarview2chartValue', 'calendarview2chartValueList', _item);
					}
					break;
				case 'CALENDAR_VIEW3_CHART':
					_item.fieldManager.focusItemType = 'calendarview3chart';
					if(!measurePositionBottom){
						self.setValueFieldArea('calendarview3chartValue', 'calendarview3chartValueList', _item);
					}
					self.setDimensionFieldArea('calendarview3chartParameter', 'calendarview3chartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('calendarview3chartValue', 'calendarview3chartValueList', _item);
					}
					break;
				case 'COLLAPSIBLE_TREE_CHART':
					_item.fieldManager.focusItemType = 'collapsibletreechart';
					if(!measurePositionBottom){
						self.setValueFieldArea('collapsibletreechartValue', 'collapsibletreechartValueList', _item);
					}
					self.setDimensionFieldArea('collapsibletreechartParameter', 'collapsibletreechartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('collapsibletreechartValue', 'collapsibletreechartValueList', _item);
					}
					break;
				case 'RANGE_BAR_CHART':
					_item.fieldManager.focusItemType = 'rangebarchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('rangebarchartValue', 'rangebarchartValueList', _item);
					}
					self.setDimensionFieldArea('rangebarchartParameter', 'rangebarchartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('rangebarchartValue', 'rangebarchartValueList', _item);
					}
//					self.setSeriesFieldArea('rangebarchartSeries', 'rangebarchartSeriesList', _item);
//					self.setHiddenMeasureFieldArea('rangebarchart_hide_column_list_mea', 'rangebarchart_hide_measure_list', _item);
					break;
				case 'RANGE_AREA_CHART':
					_item.fieldManager.focusItemType = 'rangeareachart';
					if(!measurePositionBottom){
						self.setValueFieldArea('rangeareachartValue', 'rangeareachartValueList', _item);
					}
					self.setDimensionFieldArea('rangeareachartParameter', 'rangeareachartParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('rangeareachartValue', 'rangeareachartValueList', _item);
					}
					break;
				case 'TIME_LINE_CHART':
					_item.fieldManager.focusItemType = 'timelinechart';
					if(!measurePositionBottom){
						self.setValueFieldArea('timelinechartValue', 'timelinechartValueList', _item);
					}
					self.setDimensionFieldArea('timelinechartParameter', 'timelinechartParameterList', _item);
					self.setSeriesFieldArea('timelinechartSeries', 'timelinechartSeriesList', _item);
					self.setDimensionFieldArea('timelinechartStartDate', 'timelinechartStartDateList', _item);
					self.setDimensionFieldArea('timelinechartEndDate', 'timelinechartEndDateList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('timelinechartValue', 'timelinechartValueList', _item);
					}
//					self.setHiddenMeasureFieldArea('timelinechart_hide_column_list_mea', 'timelinechart_hide_measure_list', _item);
					break;
				case 'STAR_CHART':
					_item.fieldManager.focusItemType = 'Starchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('starchartValue', 'starchartValueList', _item);
					}
					self.setDimensionFieldArea('starchartParameter', 'starchartParameterList', _item);
					self.setSeriesFieldArea('starchartSeries', 'starchartSeriesList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('starchartValue', 'starchartValueList', _item);
					}
					break;
				case 'HEATMAP':
					_item.fieldManager.focusItemType = 'heatmap';
					if(!measurePositionBottom){
						self.setValueFieldArea('heatmapValue', 'heatmapValueList', _item);
					}
					self.setDimensionFieldArea('heatmapParameter', 'heatmapParameterList', _item);
					self.setHiddenMeasureFieldArea('heatmap_hide_measure_list', 'heatmap_hide_measure_list', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('heatmapValue', 'heatmapValueList', _item);
					}
					break;
				case 'HEATMAP2':
					_item.fieldManager.focusItemType = 'heatmap2';
					if(!measurePositionBottom){
						self.setValueFieldArea('heatmap2Value', 'heatmap2ValueList', _item);
					}
					self.setDimensionFieldArea('heatmap2Parameter', 'heatmap2ParameterList', _item);
					self.setHiddenMeasureFieldArea('heatmap2_hide_measure_list', 'heatmap2_hide_measure_list', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('heatmap2Value', 'heatmap2ValueList', _item);
					}
					break;
				case 'SYNCHRONIZED_CHARTS':
					_item.fieldManager.focusItemType = 'syncchart';
					if(!measurePositionBottom){
						self.setValueFieldArea('syncchartValue', 'syncchartValueList', _item);
					}
					self.setDimensionFieldArea('syncchartParameter', 'syncchartParameterList', _item);
					self.setHiddenMeasureFieldArea('syncchart_hide_measure_list', 'syncchart_hide_measure_list', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('syncchartValue', 'syncchartValueList', _item);
					}
					break;
				case 'COMBOBOX':
					_item.fieldManager.focusItemType = 'comboBox';
					self.setDimensionFieldArea('cb_dimfield', 'cb_dimList', _item);
					self.setHiddenMeasureFieldArea('combobox_hide_column_list_mea', 'combobox_hide_measure_list', _item);
					break;
				case 'LISTBOX':
					_item.fieldManager.focusItemType = 'listBox';
					self.setDimensionFieldArea('dimfield', 'dimList', _item);
					self.setHiddenMeasureFieldArea('listbox_hide_column_list_mea', 'listbox_hide_measure_list', _item);
					break;
				case 'TREEVIEW':
					_item.fieldManager.focusItemType = 'treeView';
					self.setDimensionFieldArea('tv_dimfield', 'tv_dimList', _item);
					self.setHiddenMeasureFieldArea('treeview_hide_column_list_mea', 'treeview_hide_measure_list', _item);
					break;
				case 'IMAGE':
					_item.fieldManager.focusItemType = 'image';
					break;
				case 'TEXTBOX':
					if(gDashboard.reportType === 'RAnalysis'){
						_item.fieldManager.focusItemType = 'textBox';
						self.setVariableFieldArea('rField', 'rFieldList', _item, "필드");
					}else{
						_item.fieldManager.focusItemType = 'textBox';
						self.setHiddenMeasureFieldArea('textbox_hide_column_list_mea', 'textbox_hide_measure_list', _item);
						self.setValueFieldArea('textboxValue', 'textboxValueList', _item);
					}
					break;
				case 'CHOROPLETH_MAP':
					// EPAS merge용
					_item.fieldManager.focusItemType = 'choroplethMap';
					if(!measurePositionBottom){
						self.setValueFieldArea('mapValue', 'mapValueList', _item);
					}
					//20210609 syjin 코로플레스 데이터항목 레이아웃 수정 dogfoot
					//self.setDimensionFieldArea('mapParameter', 'mapParameterList', _item);
					self.setStateFieldArea('mapState', 'mapStateList', _item);
					self.setCityFieldArea('mapCity', 'mapCityList', _item);
					self.setDongFieldArea('mapDong', 'mapDongList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('mapValue', 'mapValueList', _item);
					}
					break;
				case 'CARD_CHART':
					_item.fieldManager.focusItemType = 'card';
					if(!measurePositionBottom){
						self.setValueFieldArea('cardValue', 'cardValueList', _item);
					}
					self.setSeriesFieldArea('cardSeries', 'cardSeriesList', _item);
					self.setSparkLineFieldArea('cardSparkLine', 'cardSparkline', _item);
					//20200728 ajkim 카드 정렬 기준 항목 추가 dogfoot
					self.setHiddenMeasureFieldArea('card_hide_column_list_mea', 'card_hide_measure_list', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('cardValue', 'cardValueList', _item);
					}
					break;
				case 'DATA_GRID':
					/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
					if(_item.fieldManager.focusItemType !== undefined && _item.fieldManager.focusItemType !== _item.kind) {
						var alpha = 5;
						/* DOGFOOT ktkang 다변량분석 추가  20210215 */
						var paired = '일표본';
						var alternative = '양측검정';
						var varequal = '분산이 같다고 가정';
						var mutest = 0;
						var method = 'ward.D';
						var distance = 'euclidean';
						var cluster = 5;
						/* DOGFOOT syjin 카이검정 옵션 추가  20210312 */
						var chisqType = "적합도검정";
						/* DOGFOOT ktkang Z검정 옵션 추가  20210216 */
						var stdev = 0;
						if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined' && typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT !== 'undefined') {
							alpha = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].ALPHA_LEVEL;
							/* DOGFOOT syjin t test 데이터 항목 불러오기 수정  20210316 */
							paired = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].PAIRED;
							if(paired == "twoSample"){
                                paired = "독립표본";
							}else if(paired == "pairedSample"){
                                paired = "대응표본";
							}else{
								paired = "일표본";
							}
							alternative = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].ALTERNATIVE;
							if(alternative == "twoSided"){
                                alternative = "양측검정";
							}else if(alternative == "lessSided"){
                                alternative = "좌측검정";
							}else{
								alternative = "우측검정";
							}
							varequal = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].VAREQUAL;
							if(varequal == "true"){
								varequal = "분산이 같다고 가정";
							}else{
								varequal = "분산이 다르다고 가정";
							}					
							mutest = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].MUTEST;
							method = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].METHOD;
							distance = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].DISTANCE;
							cluster = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].CLUSTER;
							stdev = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].STDEV;
							/* DOGFOOT syjin chisq test 데이터 항목 불러오기 수정  20210316 */
							chisqType = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].CHISQTYPE;
							if(chisqType == "goodness"){
								chisqType = "적합도검정";
							}else if(chisqType =="homogeneity"){
								chisqType = "동질성검정";
							}else{
								chisqType = "독립성검정";
							}
						}
						if(_item.fieldManager.focusItemType.indexOf('Anova') > -1) {
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Observed', _item.fieldManager.focusItemType + 'ObservedList', _item, gMessage.get('WISE.message.page.widget.analysis.observed'));
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Factor', _item.fieldManager.focusItemType + 'FactorList', _item, gMessage.get('WISE.message.page.widget.analysis.factor'));
							/*$('<div class="panel-body wise-area"><span class="label">유의수준(%)<span id="significanceResult"></span></span><div id="alpha" style="width:100%; text-align:center;"></div>').appendTo($r);
							$("#alpha").dxNumberBox({
						        value: alpha,
						        min: 1,
						        max: 100,
						        showSpinButtons: true
						    });*/
						} else if(_item.fieldManager.focusItemType.indexOf('Correlation') > -1 || _item.fieldManager.focusItemType.indexOf('Test') > -1) {
							/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
							
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Numerical', _item.fieldManager.focusItemType + 'NumericalList', _item, gMessage.get('WISE.message.page.widget.analysis.numerical'));
							
							/* DOGFOOT syjin T-test 데이터항목 초기화 설정  20210317 */
							if(_item.fieldManager.focusItemType.indexOf('tTest') > -1) {
								$('<div class="panel-body wise-area"><span class="label">표본유형<span id="pairedResult"></span></span><div id="paired" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#paired").dxSelectBox({
									items: ['일표본', '독립표본', '대응표본'],
							        value: paired,
							        onValueChanged: function(data) {
							            if(data.value == '일표본') {
							            	$('#mutest').dxNumberBox('instance').option('disabled', false);
							            	$("#varequal").dxSelectBox('instance').option('disabled', true);
							            } else {
							            	$('#mutest').dxNumberBox('instance').option('disabled', true);
							            	
							            	if(data.value == '대응표본'){
							            		$("#varequal").dxSelectBox('instance').option('disabled', true);
							            	}else{
							            		$("#varequal").dxSelectBox('instance').option('disabled', false);
							            	}
							            }
							        }
							    });
								$('<div class="panel-body wise-area"><span class="label">가설유형<span id="alternativeResult"></span></span><div id="alternative" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#alternative").dxSelectBox({
									items: ['양측검정', '좌측검정', '우측검정'],
							        value: alternative
							    });
								$('<div class="panel-body wise-area"><span class="label">분산가정<span id="varequalResult"></span></span><div id="varequal" style="width:100%; text-align:center;"></div>').appendTo($r);
								var varequalDis = true;
								if(paired == "독립표본")	varequalDis = false;
								$("#varequal").dxSelectBox({
									items: ['분산이 같다고 가정', '분산이 다르다고 가정'],
							        value: varequal,
							        disabled : varequalDis
							    });
								var mutestDis = true;
								if(paired == "일표본") mutestDis = false;
								
								$('<div class="panel-body wise-area"><span class="label">모집단 평균<span id="mutestResult"></span></span><div id="mutest" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#mutest").dxNumberBox({
							        value: mutest,
							        disabled: mutestDis
							    });
								$('<div class="panel-body wise-area"><span class="label">유의수준(%)<span id="significanceResult"></span></span><div id="alpha" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#alpha").dxNumberBox({
							        value: alpha,
							        min: 1,
							        max: 100,
							        showSpinButtons: true
							    });
						    }
							/* DOGFOOT syjin 가설검정 Z-test 추가  20210209 */
							else if(_item.fieldManager.focusItemType.indexOf('zTest') > -1){
								/* DOGFOOT syjin Z검정 옵션 수정 */
								$('<div class="panel-body wise-area"><span class="label">가설유형<span id="alternativeResult"></span></span><div id="alternative" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#alternative").dxSelectBox({
									items: ['양측검정', '좌측검정', '우측검정'],
							        value: "양측검정"
							    });
								
								$('<div class="panel-body wise-area"><span class="label">모집단 평균<span id="mutestResult"></span></span><div id="mutest" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#mutest").dxNumberBox({
							        value: mutest
							    });
								
								$('<div class="panel-body wise-area"><span class="label">모집단 표준편차<span id="mutestResult"></span></span><div id="stdev" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#stdev").dxNumberBox({
							        value: stdev
							    });
								
								$('<div class="panel-body wise-area"><span class="label">유의수준(%)<span id="significanceResult"></span></span><div id="alpha" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#alpha").dxNumberBox({
							        value: alpha,
							        min: 1,
							        max: 100,
							        showSpinButtons: true
							    });						    
						    }
							/* DOGFOOT syjin 카이제곱 검정 chiTest 추가  20210210 */
							else if(_item.fieldManager.focusItemType.indexOf('chiTest') > -1){
								/* DOGFOOT syjin 카이제곱 검정 옵션 수정 */		
								/* DOGFOOT syjin 카이제곱 검정 관측도수, 기대도수 추가  20210312 */
								//self.setVariableFieldArea(_item.fieldManager.focusItemType + 'observe', _item.fieldManager.focusItemType + 'observeList', _item, gMessage.get('WISE.message.page.widget.analysis.observe'));
								//self.setVariableFieldArea(_item.fieldManager.focusItemType + 'expect', _item.fieldManager.focusItemType + 'expectList', _item, gMessage.get('WISE.message.page.widget.analysis.expect'));
								
								$('<div class="panel-body wise-area"><span class="label">검정 유형<span id="chisqTypeResult"></span></span><div id="chisqType" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#chisqType").dxSelectBox({
									items: ['적합도검정', '독립성검정', '동질성검정'],
							        value: chisqType,
							        onValueChanged: function (data) {
							            if(data.value == '적합도검정'){
							            	
							            }else{
							            	
							            }
							        }
							    });
							}
							/* DOGFOOT syjin f 검정 fTest 추가  20210215 */
							else if(_item.fieldManager.focusItemType.indexOf('fTest') > -1){
								/* DOGFOOT syjin f검정 검정 옵션 수정 */
								$('<div class="panel-body wise-area"><span class="label">가설유형<span id="alternativeResult"></span></span><div id="alternative" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#alternative").dxSelectBox({
									items: ['양측검정', '좌측검정', '우측검정'],
							        value: "양측검정"
							    });
							
//								$('<div class="panel-body wise-area"><span class="label">유의수준(%)<span id="significanceResult"></span></span><div id="alpha" style="width:100%; text-align:center;"></div>').appendTo($r);
//								$("#alpha").dxNumberBox({
//							        value: alpha,
//							        min: 1,
//							        max: 100,
//							        showSpinButtons: true
//							    });						    
						    }
						} else if(_item.fieldManager.focusItemType.indexOf('Regression') > -1) {
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Indpn', _item.fieldManager.focusItemType + 'IndpnList', _item, gMessage.get('WISE.message.page.widget.analysis.independent'));
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Dpndn', _item.fieldManager.focusItemType + 'DpndnList', _item, gMessage.get('WISE.message.page.widget.analysis.dependent'));
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Vector', _item.fieldManager.focusItemType + 'VectorList', _item, gMessage.get('WISE.message.page.widget.analysis.vector'));
							
							/* DOGFOOT yhkim 유의수준 설정 20201202 */
							if(_item.fieldManager.focusItemType.toLowerCase().indexOf('logistic') < 0) {
								$('<div class="panel-body wise-area"><span class="label">유의수준(%)<span id="significanceResult"></span></span><div id="alpha" style="width:100%; text-align:center;"></div>').appendTo($r);
								$("#alpha").dxNumberBox({
									value: alpha,
									min: 1,
									max: 100,
									showSpinButtons: true
								});
							}
						/* DOGFOOT ktkang 다변량분석 추가  20210215 */
						} else if(_item.fieldManager.focusItemType.indexOf('multivariate') > -1) {
							var cluster = 5;
							if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined' && typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT !== 'undefined') {
								cluster = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].CLUSTER_NUMBER;
							}
							
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Numerical', _item.fieldManager.focusItemType + 'NumericalList', _item, gMessage.get('WISE.message.page.widget.analysis.numerical'));
							self.setVariableFieldArea(_item.fieldManager.focusItemType + 'Parameter', _item.fieldManager.focusItemType + 'ParameterList', _item, gMessage.get('WISE.message.page.widget.analysis.dimension'));
							
							$('<div class="panel-body wise-area"><span class="label">분석방법<span id="alternativeResult"></span></span><div id="method" style="width:100%; text-align:center;"></div>').appendTo($r);
							$("#method").dxSelectBox({
								items: ['ward.D', 'ward.D2', 'single', 'complete', 'average', 'mcquitty', 'median', 'centroid', 'kmeans'],
						        value: "ward.D"
						    });
							
							$('<div class="panel-body wise-area"><span class="label">거리측정<span id="alternativeResult"></span></span><div id="distance" style="width:100%; text-align:center;"></div>').appendTo($r);
							$("#distance").dxSelectBox({
								items: ['euclidean', 'maximum', 'manhattan', 'canberra', 'binary', 'minkowski'],
						        value: "euclidean"
						    });

							$('<div class="panel-body wise-area"><span class="label">최소 클러스터 수<span id="significanceResult"></span></span><div id="cluster" style="width:100%; text-align:center;"></div>').appendTo($r);
							$("#cluster").dxNumberBox({
								value: cluster,
								min: 2,
								max: 15,
								showSpinButtons: true
							});
						}
					} else {
						_item.fieldManager.focusItemType = 'dataGrid';
						self.setBasicFieldArea('data', 'columnList', _item);
						self.setSparkLineFieldArea('sparkLine', 'sparkline', _item, true);
						self.setHiddenMeasureFieldArea('grid_hide_column_list_mea', 'grid_hide_measure_list', _item);
					}
					break;
				case 'PIVOT_GRID':
					_item.fieldManager.focusItemType = 'pivotGrid';
					if(!measurePositionBottom){
						self.setValueFieldArea('datafield', 'dataList', _item);
					}
					self.setRowFieldArea('row',_item);
					self.setColumnFieldArea('col',_item);
					self.setDeltaFieldArea(_item);
					self.setHiddenMeasureFieldArea('pivot_hide_column_list_mea', 'pivot_hide_measure_list', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('datafield', 'dataList', _item);
					}
					break;
				case 'TREEMAP':
					_item.fieldManager.focusItemType = 'Treemap';
					if(!measurePositionBottom){
						self.setValueFieldArea('treemapValue', 'treemapValueList', _item);
					}
					self.setDimensionFieldArea('treemapParameter', 'treemapParameterList', _item);
					if(measurePositionBottom){
						self.setValueFieldArea('treemapValue', 'treemapValueList', _item);
					}
					break;
				case 'HIERARCHICAL_EDGE':
					_item.fieldManager.focusItemType = 'hierarchical';
					self.setDimensionFieldArea('hierarchicalParameter', 'hierarchicalParameterList', _item);
					break;
				case 'FORCEDIRECT':
					_item.fieldManager.focusItemType = 'forceDirect';
					//self.setValueFieldArea('forceDirectValue', 'forceDirectValueList', _item);
					self.setDimensionFieldArea('forceDirectParameter', 'forceDirectParameterList', _item);
					break;
				case 'FORCEDIRECTEXPAND':
					_item.fieldManager.focusItemType = 'forceDirectExpand';
					//self.setValueFieldArea('forceDirectExpandValue', 'forceDirectExpandValueList', _item);
					self.setDimensionFieldArea('forceDirectExpandParameter', 'forceDirectExpandParameterList', _item);
					break;
			}

			$('.panelClear').off('click').on('click',function(e){
				var panel_id = e.currentTarget.id;
				panel_id = panel_id.substr(0,panel_id.lastIndexOf('_clear'));
				$('#'+panel_id).empty();
				gDashboard.dragNdropController.recovery($('#'+panel_id));
				/*dogfoot 그리드 데이터항목 클리어시 관계 오류 수정 shlim 20200717*/
				if(WISE.Context.isCubeReport && (panel_id.indexOf('ValueList') > -1 || panel_id.indexOf('columnList') > -1)){
					gDashboard.dragNdropController.cubeRelationCheck(_item);
				}
			});
		}
		
		if($r == undefined){
			if(WISE.Constants.editmode == 'viewer'){
				self.panelManager['right'] = $r = $('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.column-drop-body');
			}else{
				self.panelManager['right'] = $r = $('.column-drop-body');	
			}
			setArea();
		}else{
			$r.css('display','none');
			gDashboard.fieldChooser.fieldChooserQuantity++;
			
			if(WISE.Constants.editmode == 'viewer'){
//				$('<div id="column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity+'" class="column-drop-body column-set"></div>').appendTo($('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.panelDataA-1.tab-content'));
				self.panelManager['right']= $r = $('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.column-drop-body');
			}else{
				$('<div id="column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity+'" class="column-drop-body column-set"></div>').appendTo($('.panelDataA-1.tab-content'));
				self.panelManager['right']= $r = $('#column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity);	
			}
			
			setArea();
		}
		
		if(WISE.Constants.editmode != 'viewer'){
			if(!_isAdhoc){
				$r.wrap('<div id= "'+_item.ComponentName + 'fieldManager" type = '+ _item.type+ '/>');	
			}else{
				$r.wrap('<div id= "adhocItem'+ _item.adhocIndex + 'fieldManager" type = '+ _item.focusItemType+ '/>');
			}
		}else{
			$r.wrap('<div id= "adhocItem'+ _item.adhocIndex + 'fieldManager" type = '+ _item.focusItemType+ '/>');
		}
			
		
		_item.fieldManager.stateFieldChooser = $r.parent();
		_item.fieldManager.panelManager = self.panelManager;
	}
	
//	this.openPivotAnalysisFieldArea = function (_item,_itemMeta){
//		var setArea = function(_dxMeta){
//			_item.fieldManager.focusItemType = 'pivotGrid';
//			var $da = $('<div class="wise-area wise-area-data" />').appendTo($r);
//			$('<div class= "wise-area space"/>').appendTo($r);
//			$('<div class= "wise-area space"/>').appendTo($r);
//			var $ro = $('<div class="wise-area wise-area-row" />').appendTo($r);
//			$('<div class= "wise-area space"/>').appendTo($r);
//			$('<div class= "wise-area space"/>').appendTo($r);
//			var $co = $('<div class="wise-area wise-area-col" />').appendTo($r);
//			
//			var $dt = self.panelManager['datafieldTitle'] = $('<div class="wise-area-title" />').appendTo($da);
//			var $dc = self.panelManager['datafieldContent'] = $('<div class="wise-area-content" />').appendTo($da);
//			var $dcp = self.panelManager['datafieldContentPanel'+_item.index] = $('<ul id="dataList' + _item.index + '" class="wise-area-content-pane drop-data drop-panel scrollbar" />').appendTo($dc);
//			
//			var $rt = self.panelManager['rowTitle'] = $('<div class="wise-area-title" />').appendTo($ro);
//			var $rc = self.panelManager['rowContent'] = $('<div class="wise-area-content" />').appendTo($ro);
//			var $rcp = self.panelManager['rowContentPanel'+_item.index] = $('<ul id="rowList' + _item.index + '" class="wise-area-content-pane connectedSortableList drop-row drop-panel scrollbar" />').appendTo($rc);
//			
//			var $ct = self.panelManager['colTitle'] = $('<div class="wise-area-title" />').appendTo($co);
//			var $cc = self.panelManager['colContent'] = $('<div class="wise-area-content" />').appendTo($co);
//			var $ccp = self.panelManager['colContentPanel'+_item.index] = $('<ul id="colList' + _item.index + '" class="wise-area-content-pane connectedSortableList drop-column drop-panel scrollbar" />').appendTo($cc);
//			
//			// row area title
//			$('<span class="wise-area-icon wise-area-icon-dimension" />').appendTo($rt);
//			$('<span>&nbsp;</span>').appendTo($rt);
//			$('<span class="wise-area-caption">' + gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.rowfiled') + '</span>').appendTo($rt);
//			
//			// column area title
//			$('<span class="wise-area-icon wise-area-icon-dimension" />').appendTo($ct);
//			$('<span>&nbsp;</span>').appendTo($ct);
//			$('<span class="wise-area-caption">' + gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.columnfiled') + '</span>').appendTo($ct);
//			
////				// data area title
//			$('<span class="wise-area-icon wise-area-icon-measure" />').appendTo($dt);
//			$('<span>&nbsp;</span>').appendTo($dt);
//			$('<span class="wise-area-caption">' + gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.datafiled') + '</span>').appendTo($dt);
//			
//			//휠
//			self.onWheel($rcp);
//			self.onWheel($ccp);
//			self.onWheel($dcp);
//			
//			
//			var rows = new Array();
//			var columns = new Array();
//			var datas = new Array();
//			
//			if(_dxMeta.Rows){
//				$.each(WISE.util.Object.toArray(_dxMeta.Rows.Row),function(_i,_row){
//					$.each(WISE.util.Object.toArray(_dxMeta.DataItems.Dimension),function(_j,_dim){
//						if(_dim.UniqueName === _row.UniqueName){
//							rows.push(_dim);
//						}
//					});
//				});
//			}
//			
//			if(_dxMeta.Columns){
//				$.each(WISE.util.Object.toArray(_dxMeta.Columns.Column),function(_i,_column){
//					$.each(WISE.util.Object.toArray(_dxMeta.DataItems.Dimension),function(_j,_dim){
//						if(_dim.UniqueName === _column.UniqueName){
//							columns.push(_dim);
//						}
//					});
//				});
//			}
//			
//			if(_dxMeta.Values){
//				$.each(WISE.util.Object.toArray(_dxMeta.Values.Value),function(_i,_val){
//					$.each(WISE.util.Object.toArray(_dxMeta.DataItems.Measure),function(_j,_mea){
//						if(_mea.UniqueName === _val.UniqueName){
//							datas.push(_mea);
//						}
//					});
//				});
//			}
//			
//		}
//		
//		if($r == undefined){
//			self.panelManager['right'] = $r = $('.column-drop-body');
//			setArea(_itemMeta.meta);
//		}else{
//			$r.css('display','none');
//			gDashboard.fieldChooser.fieldChooserQuantity++;
//			var height = $r.height();
//			$('<div id="column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity+'" class="panel-body column-drop-body column-set" style="width: 100%; height: '+ height + 'px"></div>').appendTo($('.panelDataA-1.tab-content'));
//			self.panelManager['right']= $r = $('#column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity);
//			setArea(_itemMeta.meta);
//		}
//		
//		$r.wrap('<div id= "'+_item.ComponentName + 'fieldManager" type = '+ _item.type+ '/>');
//		_item.fieldManager.stateFieldChooser = $r.parent();
//		_item.fieldManager.panelManager = self.panelManager;
//		
//	};

	/* DOGFOOT hsshim 2020-02-03 게이지 데이터 항목 UI 및 기능 작업 */
	this.setGaugeAnalysisFieldArea = function(_item) {
		var setArea = function(){
			_item.fieldManager.focusItemType = 'gauge';
			var setTitle = $('<h4 class="tit-level3">데이터 항목</h4>').appendTo($r);
			var $da =  $('<div class="panel-body wise-area wise-area-value"/>').appendTo($r);
			var $dt = self.panelManager['gaugeValueTitle'] = $('<span class="label">' + gMessage.get('WISE.message.page.widget.drop.data-field') + '</span>').appendTo($da);
			var $dcp = self.panelManager['gaugeValueContentPanel'+_item.index] = $('<div id="gaugeValueList' + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel drop-data" />').appendTo($da);
			
			if(_item.measures != undefined){
				if(_item.measures.length == 0){
					$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
				}	
			}else{
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
			}
			
			var $sr = $('<div class="panel-body wise-area wise-area-series" />').appendTo($r);
			var $srt = self.panelManager['gaugeSeriesTitle'] = $('<span class="label">' + gMessage.get('WISE.message.page.widget.drop.series') + '</span>').appendTo($sr);
			var $srcp = self.panelManager['gaugeSeriesContentPanel'+_item.index] = $('<div id="gaugeSeriesList' + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-column drop-panel dimension drop-dimension" />').appendTo($sr);
			
			if(_item.seriesDimensions != undefined){
				if(_item.seriesDimensions.length == 0){
					$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newseries') +  '</a></li></ul>').appendTo($srcp);
				}	
			}else{
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newseries') +  '</a></li></ul>').appendTo($srcp);
			}

			// var $hda = $('<div class="panel-body wise-area wise-area-hidden" />').appendTo($r);
			// var $hd = $('<div class="wise-area wise-area-hide_column_list" />').appendTo($hda);
			// $('<span class="wise-area-icon wise-area-icon-hide_column_list" />').appendTo($hd);
			
			// var $hdmt = self.panelManager['gauge_hide_column_list_meaTitle'] = $('<span class="label">' + gMessage.get('WISE.message.page.widget.panel.hide_column_list') + '</span>').appendTo($hd);
			// var $hdmcp = self.panelManager['gauge_hide_column_list_meaContentPanel'+_item.index] = $('<div id="gauge_hide_measure_list' + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel" />').appendTo($hd);
			// if(_item.HiddenMeasures != undefined){
			// 	if(_item.HiddenMeasures.length == 0){
			// 		$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
			// 	}	
			// }else{
			// 	$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
			// }
			
			//20200427 ajkim 데이터 항목 초기화 버튼 추가 dogfoot
			$('.panelClear').off('click').on('click',function(e){
				var panel_id = e.currentTarget.id;
				panel_id = panel_id.substr(0,panel_id.lastIndexOf('_clear'));
				$('#'+panel_id).empty();
				gDashboard.dragNdropController.recovery($('#'+panel_id));
				if(WISE.Context.isCubeReport && panel_id.indexOf('ValueList') > -1){
					gDashboard.dragNdropController.cubeRelationCheck(_item);
				}
			});
			
			//휠
			self.onWheel($dcp);
			self.onWheel($srcp);
//			self.onWheel($hdmcp);	
		}
		
		if($r == undefined){
			self.panelManager['right'] = $r = $('.column-drop-body');
			setArea();
		}else{
			$r.css('display','none');
			gDashboard.fieldChooser.fieldChooserQuantity++;
			$('<div id="column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity+'" class="column-drop-body column-set"></div>').appendTo($('.panelDataA-1.tab-content'));
			self.panelManager['right']= $r = $('#column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity);
			setArea();
		}
		
		$r.wrap('<div id= "'+_item.ComponentName + 'fieldManager" type = '+ _item.type+ '/>');
		_item.fieldManager.stateFieldChooser = $r.parent();
		_item.fieldManager.panelManager = self.panelManager;
	}
	/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
	this.downloadExpandAnalysisFieldArea = function(_item){
		var setArea = function(){
			var setTitle;
			$rDE= $('#panelDataA_de .column-drop-body')
			setTitle = $('<h4 class="tit-level3">데이터 항목</h4>').appendTo($rDE);
			
			var $da = $('<div class="panel-body wise-area wise-area-datagrid-col"/>').appendTo($rDE);
			var $dt = self.panelManager['downloadexpandTitle'] = $('<span class="label"><img src ="'+WISE.Constants.context + '/resources/main/images/ico-blockFolder.png" style="width:23px;height:23px;margin-bottom:2px;">'+gMessage.get('WISE.message.page.widget.drop.column')+'<a id="downloadexpand_colList_clear" class="panelClear" href="#" style="float: right;width: 20px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_resetLayoutOption.png"></a></span>').appendTo($da);
			var $dcp = self.panelManager['downloadexpandContentPanel'] = $('<div id="downloadexpand_colList" class="display-move-wrap other wise-area-content connectedSortableListDE drop-column drop-panel drop-data drop-dimension" />').appendTo($da);
			
			if(_item.columns != undefined){
				if(_item.columns.length == 0){
					$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
				}	
			}else{
				$('<ul class="display-unmove ui-state-disabled unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newfiled') + '</a></li></ul>').appendTo($dcp);
			}
			self.onWheel($dcp);
			
			$('.panelClear').off('click').on('click',function(e){
				var panel_id = e.currentTarget.id;
				panel_id = panel_id.substr(0,panel_id.lastIndexOf('_clear'));
				$('#'+panel_id).empty();
				gDashboard.dragNdropController.recovery($('#'+panel_id));
				/*dogfoot 그리드 데이터항목 클리어시 관계 오류 수정 shlim 20200717*/
				if(WISE.Context.isCubeReport && (panel_id.indexOf('ValueList') > -1 || panel_id.indexOf('columnList') > -1)){
					gDashboard.dragNdropController.cubeRelationCheck(_item);
				}
			});
			
			_item.fieldManager.panelManager = self.panelManager;
			_item.fieldManager.stateFieldChooser = $rDE.parent();
		}
		
		setArea();
	}
	
	this.setAdhocAnalysisFieldArea2 = function (_item){
		var setArea = function(){
			_item.fieldManager.focusItemType = 'adhocItem';
			var $acp = self.panelManager['allContentPanel'] = $('#'+_item.itemid+'_dataset'); 
			var $da = $('<div class="panel-body wise-area wise-area-data" />').appendTo($r);
			var $ro = $('<div class="panel-body wise-area wise-area-row" />').appendTo($r);
			var $co = $('<div class="panel-body wise-area wise-area-col" />').appendTo($r);
			var $dva = $('<div class="panel-body wise-area wise-area-deltaval" style="display:none;" />').appendTo($r);
			
			var $dt = self.panelManager['datafieldTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.datafiled')+'</span>').appendTo($da);
			var $dcp = self.panelManager['datafieldContentPanel'+_item.adhocIndex] = $('<div id="dataList' + _item.adhocIndex + '" class="display-move-wrap other wise-area-content connectedSortableList drop-data drop-panel">').appendTo($da);
//			var $dcp = self.panelManager['datafieldContentPanel'+_item.index] = $('<ul id="dataList' + _item.index + '" class="wise-area-content-pane drop-data drop-panel scrollbar" />').appendTo($dc);
			if(_item.dataFields != undefined){
				if(_item.dataFields.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);	
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
			}
			
			var $ct = self.panelManager['colTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.columnfiled')+'</span>').appendTo($co);
//			var $cc = self.panelManager['colContent'] = $('<div class="wise-area-content" />').appendTo($co);
			var $ccp = self.panelManager['colContentPanel'+_item.adhocIndex] = $('<div id="colList' + _item.adhocIndex + '" class="display-move-wrap other wise-area-content connectedSortableList drop-column drop-panel" />').appendTo($co);
			
			if(_item.columns != undefined){
				if(_item.columns.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newcolumnfiled') + '</a></li></ul>').appendTo($ccp);
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newcolumnfiled') + '</a></li></ul>').appendTo($ccp);
			}
			
			var $rt = self.panelManager['rowTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.rowfiled')+'</span>').appendTo($ro);
//			var $rc = self.panelManager['rowContent'] = $('<div class="wise-area-content" />').appendTo($ro);
			var $rcp = self.panelManager['rowContentPanel'+_item.adhocIndex] = $('<div id="rowList' + _item.adhocIndex + '" class="display-move-wrap other wise-area-content connectedSortableList drop-row drop-panel" />').appendTo($ro);
			if(_item.rows != undefined){
				if(_item.rows.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newrowfiled') + '</a></li></ul>').appendTo($rcp);
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newrowfiled') + '</a></li></ul>').appendTo($rcp);
			}
			
			var $dvt = self.panelManager['deltaValueTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.deltavaluefiled')+'</span>').appendTo($dva);
			var $dvcp = self.panelManager['deltaValueContentPanel'+_item.adhocIndex] = $('<div id="deltavalueList' + _item.adhocIndex + '" class="display-move-wrap other wise-area-content connectedSortableList drop-row drop-panel" />').appendTo($dva);

			var $ht = $('<h4 class="tit-level3">' + gMessage.get('WISE.message.page.widget.panel.hide_column_list') + '</hr>').appendTo($r);
			var $hda = $('<div class="panel-body wise-area wise-area-hidden" />').appendTo($r);
			var $hd = $('<div class="wise-area wise-area-hide_column_list" />').appendTo($hda);
			$('<span class="wise-area-icon wise-area-icon-hide_column_list" />').appendTo($hd);
//			var $hddt = self.panelManager['hide_column_list_dimTitle'] = $('<span class="label">' + gMessage.get('WISE.message.page.widget.panel.dimension') + '</span>').appendTo($hd);
////			var $hddc = self.panelManager['hide_column_list_dimContent'] = $('<div class="wise-area-half-content" />').appendTo($hd);
//			var $hdcp = self.panelManager['hide_column_list_dimContentPanel'+_item.index] = $('<div id="pivot_hide_dimension_list' + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-row drop-panel" />').appendTo($ro);
//			var $hddcp = self.panelManager['hide_column_list_dimContentPanel'+_item.index] = $('<div id="hide_dimension_list' + _item.index + '" class="display-move-wrap wise-area-content-pane connectedSortableList drop-column drop-panel" />').appendTo($hd);
//			$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.panel.dimension') + '</a></li></ul>').appendTo($hddcp);
//
			
//			var $hdmt = self.panelManager['pivot_hide_column_list_meaTitle'] = $('<span class="label">' + gMessage.get('WISE.message.page.widget.panel.hide_column_list') + '</span>').appendTo($hd);
			//2020.04.21 AJKIM drop-hiddendata 클래스 추가 DOGFOOT
			var $hdmcp = self.panelManager['pivot_hide_column_list_meaContentPanel'+_item.adhocIndex] = $('<div id="pivot_hide_measure_list' + _item.adhocIndex + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel drop-hiddendata" />').appendTo($hd);
			if(_item.HiddenMeasures != undefined){
				if(_item.HiddenMeasures.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
			}
			
			//휠
			self.onWheel($rcp);
			self.onWheel($ccp);
			self.onWheel($dcp);
		}
		
		if($r == undefined){
			self.panelManager['right'] = $r = $('.column-drop-body');
			setArea();
		}else{
			$r.css('display','none');
//			gDashboard.fieldChooser.fieldChooserQuantity++;
//			var height = $r.height();
//			$('<div id="column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity+'" class="column-drop-body column-set"></div>').appendTo($('.panelDataA-1.tab-content'));
			self.panelManager['right']= $r = $('.column-drop-body');
			setArea();
		}
		
		$r.wrap('<div id= "'+_item.ComponentName + 'fieldManager" type = '+ _item.type+ '/>');
		_item.fieldManager.stateFieldChooser = $r.parent();
		_item.fieldManager.panelManager = self.panelManager;
	};
	
	// 2019.12.16 수정자 : mksong 뷰어 비정형 컬럼선택기 추가를 위한 수정 DOGFOOT
	this.setAdhocAnalysisFieldAreaForViewer = function (_item,reportId){
		var setArea = function(){
			_item.fieldManager.focusItemType = 'adhocItem';
			var setTitle = $('<h4 class="tit-level3">데이터 항목</h4>').appendTo($r);
			var $da = $('<div class="panel-body wise-area wise-area-data" />').appendTo($r);
			var $ro = $('<div class="panel-body wise-area wise-area-row" />').appendTo($r);
			var $co = $('<div class="panel-body wise-area wise-area-col" />').appendTo($r);
			var $dva = $('<div class="panel-body wise-area wise-area-deltaval" style="display:none;" />').appendTo($r);
			
			var $dt = self.panelManager['datafieldTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.datafiled')+'</span>').appendTo($da);
			var $dcp = self.panelManager['datafieldContentPanel'+_item.index] = $('<div id="dataList' + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-data drop-panel">').appendTo($da);
//			var $dcp = self.panelManager['datafieldContentPanel'+_item.index] = $('<ul id="dataList' + _item.index + '" class="wise-area-content-pane drop-data drop-panel scrollbar" />').appendTo($dc);
			if(_item.dataFields != undefined){
				if(_item.dataFields.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);	
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newdatafiled') + '</a></li></ul>').appendTo($dcp);
			}
			
			var $ct = self.panelManager['colTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.columnfiled')+'</span>').appendTo($co);
//			var $cc = self.panelManager['colContent'] = $('<div class="wise-area-content" />').appendTo($co);
			var $ccp = self.panelManager['colContentPanel'+_item.index] = $('<div id="colList' + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-column drop-panel" />').appendTo($co);
			
			if(_item.columns != undefined){
				if(_item.columns.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newcolumnfiled') + '</a></li></ul>').appendTo($ccp);
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newcolumnfiled') + '</a></li></ul>').appendTo($ccp);
			}
			
			var $rt = self.panelManager['rowTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.rowfiled')+'</span>').appendTo($ro);
//			var $rc = self.panelManager['rowContent'] = $('<div class="wise-area-content" />').appendTo($ro);
			var $rcp = self.panelManager['rowContentPanel'+_item.index] = $('<div id="rowList' + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-row drop-panel" />').appendTo($ro);
			if(_item.rows != undefined){
				if(_item.rows.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newrowfiled') + '</a></li></ul>').appendTo($rcp);
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newrowfiled') + '</a></li></ul>').appendTo($rcp);
			}
			
			
			var $dvt = self.panelManager['deltaValueTitle'] = $('<span class="label">'+gMessage.get('WISE.message.page.widget.pivot.columnchooser.caption.deltavaluefiled')+'</span>').appendTo($dva);
			var $dvcp = self.panelManager['deltaValueContentPanel'+_item.index] = $('<div id="deltavalueList' + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-row drop-panel" />').appendTo($dva);

			var $ht = $('<h4 class="tit-level3">' + gMessage.get('WISE.message.page.widget.panel.hide_column_list') + '</hr>').appendTo($r);
			var $hda = $('<div class="panel-body wise-area wise-area-hidden" />').appendTo($r);
			var $hd = $('<div class="wise-area wise-area-hide_column_list" />').appendTo($hda);
//			$('<span class="wise-area-icon wise-area-icon-hide_column_list" />').appendTo($hd);
//			var $hddt = self.panelManager['hide_column_list_dimTitle'] = $('<span class="label">' + gMessage.get('WISE.message.page.widget.panel.dimension') + '</span>').appendTo($hd);
////			var $hddc = self.panelManager['hide_column_list_dimContent'] = $('<div class="wise-area-half-content" />').appendTo($hd);
//			var $hdcp = self.panelManager['hide_column_list_dimContentPanel'+_item.index] = $('<div id="pivot_hide_dimension_list' + _item.index + '" class="display-move-wrap other wise-area-content connectedSortableList drop-row drop-panel" />').appendTo($ro);
//			var $hddcp = self.panelManager['hide_column_list_dimContentPanel'+_item.index] = $('<div id="hide_dimension_list' + _item.index + '" class="display-move-wrap wise-area-content-pane connectedSortableList drop-column drop-panel" />').appendTo($hd);
//			$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.panel.dimension') + '</a></li></ul>').appendTo($hddcp);
//
			
//			var $hdmt = self.panelManager['pivot_hide_column_list_meaTitle'] = $('<span class="label">' + gMessage.get('WISE.message.page.widget.panel.hide_column_list') + '</span>').appendTo($hd);
			//2020.04.21 AJKIM drop-hiddendata 클래스 추가 DOGFOOT
			var $hdmcp = self.panelManager['pivot_hide_column_list_meaContentPanel'+_item.index] = $('<div id="pivot_hide_measure_list' + _item.index + '" class="display-move-wrap other wise-area-content-pane connectedSortableList drop-panel drop-hiddendata" />').appendTo($hd);
			if(_item.HiddenMeasures != undefined){
				if(_item.HiddenMeasures.length == 0){
					$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
				}	
			}else{
				$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + gMessage.get('WISE.message.page.widget.drop.newitem') + '</a></li></ul>').appendTo($hdmcp);
			}
			
			//휠
			self.onWheel($rcp);
			self.onWheel($ccp);
			self.onWheel($dcp);
		}
		
		if($r == undefined){
			self.panelManager['right'] = $r = $('#dataArea_'+reportId).find('.column-drop-body');
			setArea();
		}else{
			$r.css('display','none');
			gDashboard.fieldChooser.fieldChooserQuantity++;
			var height = $r.height();
			$('<div id="column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity+'" class="column-drop-body column-set"></div>').appendTo($('.panelDataA-1.tab-content'));
			self.panelManager['right']= $r = $('#dataArea_'+reportId).find('.column-drop-body');
			setArea();
		}
		
		$r.wrap('<div id= "'+_item.ComponentName + 'fieldManager" type = '+ _item.type+ '/>');
		_item.fieldManager.stateFieldChooser = $r.parent();
		_item.fieldManager.panelManager = self.panelManager;
		
	};

	this.onWheel = function (_o){
		_o.on('mouseenter', function(_e){
			_e.target.onmousewheel=function(_ev){
				_o.scrollTop(_o.scrollTop() + _ev.deltaY);
			};
		})
		.on('mouseleave', function(_e){
			_e.target.onmousewheel=function(_ev){};
		});
	};
	//검색4
}; // end of FieldChooser Class