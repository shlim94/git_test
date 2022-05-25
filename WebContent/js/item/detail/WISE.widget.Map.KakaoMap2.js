WISE.libs.Dashboard.item.KakaoMap2Generator = function() {
	var self = this;
	
	this.type = 'KAKAO_MAP2';
	
	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
    this.palette;
	this.fieldManager;
	
	this.dimensions = [];
	this.measures = [];
	this.valueMaps = [];  // Maps-ValueMap node
	
	this.attributeDimension = {};
	this.tooltipMeasures = [];
	
	this.attributeName;
	this.shapeTitleAttributeName;
	//2020.10.08 MKSONG 오타 수정 DOGFOOT
	this.toolTipAttributeName;  // this.attributeName을 따른다
	this.tracked;
	this.legend;
	this.isMasterFilterCrossDataSource;
	this.CustomScale;
	this.GradientPalette;
	this.selectedValues =[];
	this.selectedText="";
	this.panelManager;
	this.backColor = "255,255,255"; 
	this.layerColor = '210,210,210';
	this.Map = [];
	this.shpFilemeta;
	this.dbfFilemeta;
	
	this.valueRange = {};
	
	this.CustomUrl = "";
//	this.CustomUrl = true;
	
	// jhkim - custom chart palette
	this.isCustomPalette = false;
	
	this.attrName = "";
	this.ShapefileArea = "";
	this.ViewArea = {}; 
	this.activePanel = "";
	this.shpReady = false;
	this.dbfReady = false;
	this.LockNavigation = true;
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	/**
	 * @param _map: meta object
	 */
	
	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	};
	
	this.getDxItemConfig = function(_map) {
		
		var viewArea = _map['ViewArea'];
		self.isMasterFilterCrossDataSource = _map.IsMasterFilterCrossDataSource ? true : false;
		/* legend definition */
		this.mapLegend = {
			source: { layer: "areaLayer", grouping: "color" },
			orientation: ((this.legend.Orientation || '').toLowerCase() || 'vertical'),
			markerType: "circle"
		};

		if(typeof window[self.dashboardid] != 'undefined'){
			var mapOption = typeof window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.DATA_ELEMENT);
		}
		else{
			var mapOption = '';
		}
		
		this.mapLegend = WISE.libs.Dashboard.item.MapGenerator.setLegendPostion(this.mapLegend, this.legend.Position);
//		var mapOption = typeof window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.DATA_ELEMENT);
		var selectionMode = this.IO ? (this.IO['MasterFilterMode'] ? WISE.util.String.toLowerCase(this.IO['MasterFilterMode']) : 'none') : 'none';
		if(mapOption != ''){
			$.each(mapOption,function(_i,_e){
				if(_e.CTRL_NM == _map.ComponentName){
					self.backColor = _e.BACK_COLOR;
					self.layerColor = _e.NULL_DATA_BACK_COLOR;
					return false;
				}
			})
		}
		
		//var paletteColor = _map.Palette;
		/*dogfoot 지도 팔레트 기본설정값 못찾을시 오류 수정 shlim 20200617*/
		var paletteColor=[];
		if(typeof _map.Palette != 'undefined'){
            $.each(WISE.util.Object.toArray(_map.Palette),function(_i,_color){
				if(typeof _color == 'string' && _color.indexOf('#') > -1){
					paletteColor.push(_color.toUpperCase());	
				}else{
					paletteColor.push(self.getHexColor(_color).toUpperCase());	
				}
			});
		}
		
		if(_map.Palette == 'Custom'){
			paletteColor = [];
			$.each(WISE.util.Object.toArray(_map.Maps.ValueMap)[0].CustomPalette.Color,function(_i,_color){
				if(typeof _color == 'string' && _color.indexOf('#') > -1){
					paletteColor.push(_color.toUpperCase());	
				}else{
					paletteColor.push(self.getHexColor(_color).toUpperCase());	
				}
			});
		}
		
		var dxConfigs = {
			background: {
				borderColor: 'white',
				color:"rgb("+self.backColor+")"
			},
//			colorGroups: [],
//			colorGroupingField: '',
			layers: [{
				type: 'area',
				name: 'areaLayer',
				hoverEnabled: true,
				color:"rgb("+self.layerColor+")",
				//palette: this.CUSTOMIZED.get('palette'),
				palette: paletteColor,
//				data: WISE.Constants.context+'/resources/mapdata/state.geojson',
				data:'',
				label: {
					enabled: this.shapeTitleAttributeName ? true : false,
					dataField: this.shapeTitleAttributeName
				}
			}],
			center: [Number(viewArea['CenterPointLongitude']), Number(viewArea['CenterPointLatitude'])],
			bounds: [Number(viewArea['LeftLongitude']), Number(viewArea['TopLatitude']), Number(viewArea['RightLongitude']), Number(viewArea['BottomLatitude'])],
			controlBar: {
			    enabled: false
		    },
		    wheelEnabled: _map['LockNavigation'],
		    panningEnabled: _map['LockNavigation'],
		    loadingIndicator: {
		    	show: true,
		    	backgroundColor: '#ededed',
		    	text: gMessage.get('WISE.message.page.common.loding')
			},
			tooltip: {
				enabled: true,
				customizeTooltip: function (_area) {
					if (_area.layer.type === 'area') {
						return {html: this.attribute('tooltipHtml')};
					}
					return '';
				}
			},
			onClick: function(_e) {
				if (selectionMode !== 'none') {
					if(_e.target){
						var imgSrc, overImgSrc, clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
			        	imgSrc = 'cont_box_icon_filter';
			        	overImgSrc = 'cont_box_icon_filter_';
			           	
			           	$(clearTrackingImg)
			           		.attr('src', WISE.Constants.context + '/images/' + imgSrc + '.png')
			           		.on('mouseover', function() {
			           			$(this).attr('src', WISE.Constants.context + '/images/' + overImgSrc + '.png');
			           		})
			           		.on('mouseout', function() {
			           			$(this).attr('src', WISE.Constants.context + '/images/' + imgSrc + '.png');
			           		});
			           
		           		var trackedDataName = _e.target.attribute(self.attributeName);
			           	
		           		var selected = {};
		           		if(self.selectedText.indexOf(trackedDataName) == -1){
		           			selected[self.attributeDimension.name] = trackedDataName;
		           			self.selectedValues.push(selected);
		           			_e.target.selected(true);
		           		}
		           		else{
		           			$.each(self.selectedValues,function(_i,_f){
		           				if(_f[self.attributeDimension.name] == trackedDataName){
		           					self.selectedValues.splice(_i,1);
		           					return false;
		           				}
		           			});
		           			_e.target.selected(false);
		           		}
//		           		selected[self.attributeDimension.name] = trackedDataName;
//		           		self.selectedValues.push(selected);

		           		self.selectedText = "";
		           		$.each(self.selectedValues,function(_i,_e){
		           			self.selectedText += _e[self.attributeDimension.name]+' ';
		           		})
		           		if(self.selectedText==""){
		           			var clearImg = $("#" + self.trackingClearId).find('img')[0];
		           			$(clearImg).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
		           		}
		           		$('#' + self.itemid + '_tracking_data_container').empty();
		           		$('#' + self.itemid + '_tracking_data_container').html('[ ' + self.selectedText + ']');
		           		
		           		
		           		
		           		window[self.dashboardid].filterData(self.itemid, self.selectedValues,self.isMasterFilterCrossDataSource);
		           	}
				}
			}
		};
		return dxConfigs;
	};
	
	this.setKakaoMap = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		
		this.Map['palette'] = this.palette;
		this.Map['ComponentName'] = this.ComponentName;
		this.Map['DataItems'] = this.fieldManager.DataItems;
		this.Map['DataSource'] = this.dataSourceId;
		this.Map['Name'] = this.Name;
		this.Map['AttributeDimension'] = this.fieldManager.attributeDimension;
		/*dogfoot 코로플레스 맵 안그려지는 오류 수정  shlim 20200612*/
		this.Map['Maps'] = typeof this.Map['Maps'] != 'undefined' && this.Map['Maps'] != "" ? this.Map['Maps'] : this.fieldManager.Values;
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.Map['IsMasterFilterCrossDataSource'] = false;
		this.Map['CustomShapefile'] = this.CustomUrl;
		/*디버그용*/
//		this.Map['CustomShapefile'] = {'Url': "http://localhost:11080/ds/UploadFiles/geojson/KOR_adm1_edit_kor.geojson"};
		this.Map['AttributeName'] = self.attrName;
		this.Map['ShapefileArea'] = self.ShapefileArea;
		this.Map['ViewArea'] = self.ViewArea;
//		this.Map['ShowCaption'] = true;
		this.Map['LockNavigation'] = self.LockNavigation;
		/*view.do 와 맞추기 위한 더미 Element 또는 모르는것*/
//		this.Map['MapLegend'] = "";
		/*dogfoot 지도 팔레트 첫 생성시 범례 못그리는 오류 수정 shlim 20200617*/
		this.Map['MapLegend'] = this.Map['MapLegend'] != undefined && this.Map['MapLegend'] !="" ? this.Map['MapLegend'] : {'Visible': false};
		this.Map['WeightedLegend'] = "";
		this.Map['InteractivityOptions'] = {
			MasterFilterMode: 'Off',
//			TargetDimensions: 'Argument',
			IsDrillDownEnabled: false,
			IgnoreMasterFilters: false
		};
		
		if (!(this.Map.Palette)) {
			this.Map.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		this.meta = this.Map;

	}
	
	this.setKakaoMapForOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setKakaoMap();
		}
		else{
			this.Map = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		this.Map['ComponentName'] = this.ComponentName;
		this.Map['DataSource'] = this.dataSourceId;
		this.Map['Name'] = this.Name;
		
		if(this.fieldManager != undefined){
			this.Map['DataItems'] = this.fieldManager.DataItems;
			this.Map['AttributeDimension'] = this.fieldManager.attributeDimension;
			/*dogfoot 코로플레스 맵 안그려지는 오류 수정  shlim 20200612*/
			this.Map['Maps'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		this.Map['CustomShapefile'] = this.meta['CustomShapefile'];
		if(this.meta['LockNavigation'] != undefined){
			this.Map['LockNavigation'] = self.LockNavigation = !this.meta['LockNavigation'];
			this.meta['LockNavigation'] = undefined;
		}
		if(this.meta['MapLegend'] != undefined){
			this.Map['MapLegend'] = this.meta['MapLegend'] == "" ? {'Visible': false} : this.meta['MapLegend']; 
		}
//		/*view.do 와 맞추기 위한 더미 Element 또는 모르는것*/
		if (!(this.Map.Palette)) {
			this.Map.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		this.meta = this.Map;

	};
	
	
	/** @Override */
	this.bindData = function(_data, _ativePanelId) {
		//2020.02.07 mksong sqllike 적용 dogfoot
//		if (!this.tracked) {
//			this.globalData = _.clone(_data);
//			this.filteredData = _.clone(_data);
//		}
		$("#" + this.itemid).empty();
		
		//2020.02.07 mksong sqllike 적용 dogfoot
//		if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
//			var nodataHtml = '<div class="nodata-layer"></div>';
//			$("#" + this.itemid).empty().append(nodataHtml);
//		}
//		else {
			if(self.shpFilemeta == null || self.dbfFilemeta == null){
				setTimeout(this.renderMap(_data, _ativePanelId),3000);
			}else{
				this.renderMap(_data, _ativePanelId);
			}
		
//		}
	};
	
	this.renderMap = function(_data, _ativePanelId) {
		//2020.02.07 mksong sqllike 적용 dogfoot
		
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var dataSourceId = this.dataSourceId;
		
//		self.attrName = 'NAME_1';//HASC_1
		var tempdata = _data;	
		var tempativePanelId = _ativePanelId;
		/*if(_functionDo){
			this.generate(self.meta);
		}else */if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setKakaoMap();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
			/*dogfoot 코로플레스 맵 안그려지는 오류 수정  shlim 20200617*/
			if(WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale != undefined){
				this.fieldManager.CustomScale = {'RangeStop': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale.RangeStop};
				/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
				this.fieldManager.CustomPalette = {'Color': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomPalette.Color};
				/*dogfoot 지도 생성,불러오기 오류 수정 shlim 20200617*/
				if(typeof WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] != 'undefined'){
				    this.fieldManager.CustomColorSet = {'CustomColorSetCheck' : WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet']['CustomColorSetCheck']};	
				}else{
					WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] = {'CustomColorSetCheck':'N'};
					this.fieldManager.CustomColorSet = {'CustomColorSetCheck':'N'};
				}
			}else if(WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale == undefined){
				
			}
		}
		else if(this.fieldManager != null && gDashboard.isNewReport == false){ // 레포트 열기
			if(WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale != undefined){
				this.fieldManager.CustomScale = {'RangeStop': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale.RangeStop};
				/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
				this.fieldManager.CustomPalette = {'Color': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomPalette.Color};
				/*dogfoot 지도 생성,불러오기 오류 수정 shlim 20200617*/
				if(typeof WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] != 'undefined'){
				    this.fieldManager.CustomColorSet = {'CustomColorSetCheck' : WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet']['CustomColorSetCheck']};	
				}else{
					WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] = {'CustomColorSetCheck':'N'};
					this.fieldManager.CustomColorSet = {'CustomColorSetCheck':'N'};
				}
			}
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setKakaoMapForOpen();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}
		/*
		if(this.fieldManager !=null && gDashboard.isNewReport == true){
			self.setChoroplethMap();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			this.generate(self.meta);
		}else{
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			this.generate(self.meta);
		}
		*/
		this.panelManager.empty();
		/*dogfoot 코로플레스 맵 안그려지는 오류 수정  shlim 20200616*/
//        this.VM = WISE.util.Object.toArray((self.meta['Maps'] && self.meta['Maps']['ValueMap']) || []);
//
//		this.valueMaps = [];
//		$.each(this.VM, function(_i0, _a0) {
//			var uniqueName = _a0['Value']['UniqueName'];
//			var dataMember = self.DU.getDataMember(uniqueName, self.DI, self.dimensions, self.measures);
//			dataMember.vmName = _a0['Name'];
//			dataMember.vmValueName = _a0['ValueName'];
//
//			var rangeStop = (_a0['CustomScale'] && _a0['CustomScale']['RangeStop']) || undefined;
//			if (rangeStop) {
//				rangeStop.push(self.CUSTOMIZED.get('rangeStopMaxValue'));
//			}
//
//			dataMember.colorGroups = (_a0['CustomScale'] && _a0['CustomScale']['RangeStop']) || self.CUSTOMIZED.get('CustomScale_RangeStop');
//			self.valueMaps.push(dataMember);
//		});
		this.attributeDimension = this.DU.getDataMember(self.meta['AttributeDimension']['UniqueName'], this.DI, this.dimensions);
		this.panelManager.makePanel(this.valueMaps, ['dummy_value']);
		
		var dataset, dimensions = self.dimensions, measures = self.measures;
			
		if ($.type(self.tooltipMeasures) === 'array' && self.tooltipMeasures.length > 0) {
			measures = measures.concat(self.tooltipMeasures);	
		}
		
		//2020.02.07 mksong sqllike 적용 dogfoot
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		var datasetConfig = self.SQLike.fromJson(dimensions, measures, self.filteredData);
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		var dataset = SQLikeUtil.doSqlLike(dataSourceId, datasetConfig, self);
		
		if (!dataset || ($.type(dataset) === 'array' && dataset.length === 0)) {
			$('#'+self.itemid + ' .nodata-layer').remove();
			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
			$("#" + self.itemid).children().css('display','none');
			$("#" + self.itemid).prepend(nodataHtml);
			$("#" + self.itemid).css('display', 'block');
			gProgressbar.hide();
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}

			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();		
				gDashboard.updateReportLog();
			}
			return;
		}else{
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
		
		self.filteredData = dataset; 
		self.csvData = self.filteredData;
		
		/*
		$.each(dimensions, function(d_i, d_v){
			console.log(d_v);
		});
		*/
/**************************** 09.02 polygon 시도, 시군구, 읍면동 출력
		var address = new Array();	//주소
		var addressValues = {};	//주소에 대한 측정 값
        
        //시도
        var locationZero = new Array();
		
		//군구
        var locationOne = new Array();
		
        //읍면동
        var locationTwo = new Array();
        
        $.each(self.csvData, function(index, value){
			var localAddress = '';

			$.each(dimensions, function(_i, _v){
                localAddress += value[_v.caption]+' ';
				if(_i == dimensions.length-1){
					address.push(localAddress);
				}
			});	
		})
		
		$.each(measures, function(m_i, m_v){
			addressValues[m_i] = {};
		});
		
		$.each(addressValues, function(av_i, av_v){
			$.each(measures, function(m_i, m_v){
				addressValues[m_i]['caption'] = m_v['caption'];
				addressValues[m_i]['summaryType'] = m_v['summaryType'];
				addressValues[m_i]['values'] = new Array();
			})
		});

		$.each(self.csvData, function(index, value){
       		$.each(measures, function(m_i, m_v){          
                    addressValues[m_i]['values'].push(value[m_v['nameBySummaryType']]);
         		});
         	});

		var locationName ={
        	location_1 : {},
        	location_2 : {},
        	location_3 : {}
        };
        
        $.each(address, function(_i, _v){
            array = _v.split(" ");
            
            for(var i=0; i<array.length-1; i++){
            	if(_i==0) locationName['location_'+(i+1)].name=new Array();
            	locationName['location_'+(i+1)].name.push(array[i]);
            }	
        });
		
		for(var i=0; i<array.length-1; i++){
            locationName['location_'+(i+1)].sort = new Set(locationName['location_'+(i+1)].name);
            locationName['location_'+(i+1)].size = locationName['location_'+(i+1)].sort.size;
            locationName['location_'+(i+1)].values= {};
		}


		 $.each(locationName, function(ln_i, ln_v){
		 	if(ln_v.sort){
		 		$.each(addressValues, function(av_i, av_v){
		 			ln_v['values'][av_v['caption']] = {};
		 		})
		 	}
		 });
	    
	    	$.each(locationName, function(ln_i, ln_v){
                if(ln_v.sort){
					arraySort = [...ln_v.sort];


					$.each(arraySort, function(as_i, as_v){
						var start=0;

						for(var i=0; i<ln_v.name.length; i++){
							console.log(as_v);

							if(as_v == ln_v.name[i]){
								start = i;
								break;
							}
						}

						console.log(start);
						var end = 0;    
						for(var i=start; i<ln_v.name.length; i++){
							if((as_v != ln_v.name[i]) || (i == ln_v.name.length-1)){
								end = i;
								break;
							}
						}	    		
                        
                        if(start==end){
                        	end++;
                        }
						console.log(end);


							$.each(addressValues, function(av_i, av_v){
								switch(av_v['summaryType']){
									case 'sum' :
										 var result = 0;
										 for(var i=start; i<end; i++){
											result += av_v['values'][i];
										 }
										 console.log(as_v);
										 locationName[ln_i].values[av_v['caption']][as_v] = result;
									break;
								}
							});

					});
	    	    }
	    	})

        var standard = 0;
        
        for(var k=0; k<address.length; k++){
			for(var i=0; i<dimensions.length; i++){
				var minSize = 999999999;  
				var locationIndex;

				 for(var j=0; j<dimensions.length; j++){
					if(locationName['location_'+(j+1)].size<minSize && locationName['location_'+(j+1)].size>standard){
						minSize = locationName['location_'+(j+1)].size;
						locationIndex = j+1;	        
					}
				 }

				 standard = minSize;
				 locationName['location_'+locationIndex].order = i;
			}
        }
		
		var locationOrder = new Array();
         var count = 0;
		$.each(locationName, function(ln_i, ln_v){
           
            $.each(locationName, function(ln_i2, ln_v2){
            	if(ln_v2.order == count){
            		locationOrder.push(ln_i2);
            		count++;
            	}
            });
            
		});
**********************************************************************/

		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		self.activePanel = _ativePanelId;
		self.panelManager.activeValuePanel(self.itemid,_ativePanelId);
		
		
		//self.dxItem = $("#" + self.itemid).dxVectorMap(dxConfigs).dxVectorMap('instance');
	
       	self.dxItem = $('#'+self.activePanel).dxVectorMap('instance');
		
       	
       	
       	
        /* DOGFOOT syjin 카카오 지도 그리기  20200824 */	
       	var container = document.getElementById(self.itemid); //지도를 담을 영역의 DOM 레퍼런스
				var options = { //지도를 생성할 때 필요한 기본 옵션
					center: new kakao.maps.LatLng(37.5668260054796, 126.978656785931), //지도의 중심좌표.
					level: 8 //지도의 레벨(확대, 축소 정도)
		};

		var map = new kakao.maps.Map(container, options); //지도 생성 및 객체 리턴
	
		/* DOGFOOT syjin 카카오 지도 마커 클러스터러 구현  20200902 */
	    //측정값 저장
		var measureNames = {};

		measureNames['name'] = [];
        measureNames['nameBySummaryType'] = [];

        $.each(measures, function(_mi, _mv){
            measureNames['name'].push(_mv['name']);
            measureNames['nameBySummaryType'].push(_mv['nameBySummaryType']);
        });

        
        //marker 객체배열 생성
		var markers = [];
        
        //위도 : _lat
        //경도 : _lon
		var createMarker = function(_map, _lat, _lon, _title, _info, _image){     //마커 객체 생성
			var marker = new kakao.maps.Marker({
				map : _map,
				position : new kakao.maps.LatLng(_lat, _lon),
				title : _title,
				image : _image
			});
			
//			//마커에 클릭 이벤트 추가
			kakao.maps.event.addListener(marker, 'click', function() {
			// 마커 위에 인포윈도우를 표시합니다
			    var position = marker.getPosition();
			    var title = marker.getTitle();
		      
			    var content = '';
			    
			    var name = _info['name'];
			    var values = _info['values'];
			    var latitude = _info['latitude'];
			    var longitude = _info['longitude'];
			    
			    content += 
			    	'<table class="tableInfo" style="border-collapse: collapse; text-align: left; line-height: 1.5; border: 1px solid #ccc; margin: 20px 17px; width:100%;">' +
			    		'<thead style= "border-right: 1px solid #ccc; border-left: 1px solid #ccc; background: #2b5eff;">' +
			    			'<tr>' +
			    				'<th scope="cols" colspan="2" style="padding: 5px; font-weight: bold; vertical-align: top; color: #fff;">' +
			    					'측정값' +
			    				'</th>' +
			    			'</tr>' +
			    		'</thead>'

			    		'<tbody>';
			    
			    for(var i=0; i<name.length; i++){
			    	content +=
			    		'<tr>' +
			    			'<th scope="row" style="padding: 5px; font-weight: bold; vertical-align: top; border-bottom: 1px solid #ccc; background: #fcf1f4;">' +
			    				name[i] +
			    			'</th>' +
			    			'<td style="padding: 5px; vertical-align: top; border-bottom: 1px solid #ccc;">' +
			    				values[i] +
			    			'</td>' +
			    		'</tr>';
			    }
			    
			    content +=
			    		'</tbody>' +
			    		
			    		
			    		'<thead style= " border-right: 1px solid #ccc; border-left: 1px solid #ccc; background: #2b5eff;">' +
			    			'<tr>' +
				    			'<th scope="cols" colspan="2" style="padding: 5px; font-weight: bold; vertical-align: top; color: #fff;">' +
			    					'위도' +
			    				'</th>' +
			    			'</tr>' +
			    		'</thead>' +
			    		
			    		'<tbody>' +
			    			'<tr>' +
			    				'<th scope="row" colspan="2" style="padding: 5px; font-weight: bold; vertical-align: top; border-bottom: 1px solid #ccc; background: #fcf1f4;">' +
			    					latitude +
			    				'</th>' +
			    			'</tr>' +
			    		'</tbody>' +
			    		
			    		'<thead style= " border-right: 1px solid #ccc; border-left: 1px solid #ccc; background: #2b5eff;">' +
			    			'<tr>' +
			    				'<th scope="cols" colspan="2" style="padding: 5px; font-weight: bold; vertical-align: top; color: #fff;">' +
			    					'경도' +
			    				'</th>' +
			    			'</tr>' +
			    		'</thead>' +
			    		
			    		'<tbody>' +
			    			'<tr>' +
			    				'<th scope="row" colspan="2" style="padding: 5px; font-weight: bold; vertical-align: top; border-bottom: 1px solid #ccc; background: #fcf1f4;">' +
			    					longitude +
			    				'</th>' +
			    			'</tr>' +
			    		'</tbody>' +
			    		
			    	'</table>';
			    	
				var infowindow = createInfoWindow(content, true);
				infowindow.open(_map, marker);
			})
			
//			var position = marker.getPosition();
//		    var content = marker.getTitle();
//			
//			var infowindow = createInfoWindow(content, true);
//			infowindow.open(_map, marker);
			
			markers.push(marker);
		}
		
		var createInfoWindow = function(_content, _removable){
			var infowindow = new kakao.maps.InfoWindow({
				content : _content,
				removable : _removable
			})
			
			return infowindow;
		}

		$.each(self.csvData, function(_i, _v){
			var title = '';
			var text = '';
			
			var info = {};

		    info['name'] = [];
		    info['values'] = [];
		    info['latitude'] = _v['위도'];
		    info['longitude'] = _v['경도'];
		    
			$.each(measureNames, function(mn_i, mn_v){
				//console.log(mn_v);
				if(mn_i == 'name'){
					title += mn_v + ' : ';
					info['name'].push(mn_v);
				}else if(mn_i == 'nameBySummaryType'){
					title += _v[mn_v] + '\n';
					info['values'].push(_v[mn_v]);
				}
			});		
		        
			createMarker(map, _v['위도'], _v['경도'], title, info);    //마커 객체 생성 함수 호출
		});  
		
		//마커 지도에 올리기
		var setMarker = function(_map, _markers){
			for(var i=0; i<_markers.length; i++){
				_markers[i].setMap(_map);
			}
		}  

		setMarker(map, markers);    //마커 지도에 생성 함수 호출

		var createClusterer = function(_map, _markers, _gridSize, _averageCenter, _minLevel, _disableClickZoom, _styles){
	    	var clusterer = new kakao.maps.MarkerClusterer({
	    		map : _map,
				markers : markers,
				gridSize : _gridSize,
 				averageCenter : _averageCenter,
 				minLevel : _minLevel,
 				disableClickZoom : _disableClickZoom,
 				styles : _styles
	    	})
	    }

	    createClusterer(map, markers);
	    
	    var zoomControl = function(){
	    	var zoom = new kakao.maps.ZoomControl();
	    	map.addControl(zoomControl, kakao.maps.ControlPosition.RIGHT);
	    }
	    
	    
// 2020.09.02 jsy 시도, 시군구, 읍면동 polygon 출력
/**************************************************
//       	var locationCode;
//       	
//       	var setCity; //시도
//       	var setState; //시군구
//       	var setDong; //읍면동
//       	
//       	$.each(locationName, function(_i,_v){
//       		if(_v['order']!=undefined){
//       			
//       		    locationCode = dimensions[_i.slice(-1)-1]['caption']
//       		
//       		
//			switch(locationCode){
//				case '시도':    //시도 일때
//					//setCity = function(){
//						function getZeroData(callbackFunc){
//					    	$.ajax({
//								url : WISE.Constants.context+'/resources/geoJson/TL_SCCO_CTPRVN.json',
//								type : 'get',
//								dataType:'json',
//								success: function(data){                             
//		                            callbackFunc(data);							
//								}
//						    });
//					    };
//		
//					    getZeroData(function(data){
//									
//									var arraySort = [..._v.sort];
//									
//									var arraySortNum = new Array();                             
//									
//	                                $.each(arraySort, function(as_i, as_v){
//	
//	                                	$.each(data.features, function(f_i, f_v){
//	                                		var jsonLocation = f_v.properties['CTP_KOR_NM'];
//	
//	                                		if(jsonLocation.includes(as_v)){
//	                                			locationZero[as_i] = new Array();
//	
//	                                			$.each(f_v.geometry.coordinates[0], function(c_i, c_v){
//							    					locationZero[as_i].push(c_v);
//							    				});
//	                                		}
//	                                	})
//	                                });
//	                                
//	                                console.log(_v.values);
//	                                const getPolygonCenterPath = function(_x, _y, lz_i, map){
//	                                	var maxX = Math.max.apply(null, _x);
//										var minX = Math.min.apply(null, _x);
//	
//										var maxY = Math.max.apply(null, _y);
//										var minY = Math.min.apply(null, _y);
//	
//										polygonCenter = new Array();
//	
//										polygonCenter.push((minX+maxX)/2);
//										polygonCenter.push((minY+maxY)/2);
//	                                    var locationContent = arraySort[lz_i];
//	                                    var valueContent = {};                          
//	                                    var valueContentResult = '';
//	
//										$.each(_v.values, function(_a, _b){
//											valueContent[_a] = _b[locationContent];
//											console.log(valueContent);
//										});                      
//								                          
//	                                    $.each(valueContent, function(vc_i, vc_v){
//	                                    	//result = vc_i + ': ' + vc_v+'\n';
//	                                    	result = vc_v + '\n';
//	                                    	valueContentResult += result;
//	                                    });
//	                                    
//								        var content = '<div class ="label" style="text-align:center;"><span class="left"></span><span class="center" style="font-size:50px; color:red;">'+locationContent+'</span><br><span style="font-size:30px; color:red;">'+
//								        valueContentResult+
//								        '</span><span class="right"></span></div>';
//	
//										// 커스텀 오버레이가 표시될 위치입니다 
//										var position = new kakao.maps.LatLng(polygonCenter[1], polygonCenter[0]);   
//	
//										// 커스텀 오버레이를 생성합니다
//										var customOverlay = new kakao.maps.CustomOverlay({
//											position: position,
//											content: content   
//										});
//	
//										// 커스텀 오버레이를 지도에 표시합니다
//										customOverlay.setMap(map);            
//										/*var markerPosition  = new kakao.maps.LatLng(polygonCenter[1], polygonCenter[0]); 
//	
//										// 마커를 생성합니다
//										var marker = new kakao.maps.Marker({
//										    position: markerPosition
//										});
//	
//										// 마커가 지도 위에 표시되도록 설정합니다
//										marker.setMap(map);*/
//	                                }
//	
//									const createPolygonPath = function(_x, _y){
//			                        	return new kakao.maps.LatLng(_y, _x);
//			                        }
//		                            
//							    	const createPolygon = function(map){
//										$.each(locationZero, function(lz_i, lz_v){
//											var polygonPath = [];
//	                                        var pathX = new Array();
//	                                        var pathY = new Array();
//	
//	                                        for(var i=0; i<lz_v.length; i++){
//	                                        	polygonPath.push(createPolygonPath(lz_v[i][0], lz_v[i][1]));
//	                                        	pathX.push(lz_v[i][0]);
//	                                        	pathY.push(lz_v[i][1]);
//	                                        }
//											
//	                                        getPolygonCenterPath(pathX, pathY, lz_i, map);
//	                                        
//											var polygon = new kakao.maps.Polygon({
//											path:polygonPath, // 그려질 다각형의 좌표 배열입니다
//											strokeWeight: 3, // 선의 두께입니다
//											strokeColor: '#75B8FA', // 선의 색깔입니다
//											strokeOpacity: 0.8, // 선의 불투명도 입니다 1에서 0 사이의 값이며 0에 가까울수록 투명합니다
//											strokeStyle: 'longdash', // 선의 스타일입니다
//											fillColor: '#CFE7FF', // 채우기 색깔입니다
//											fillOpacity: 0.7 // 채우기 불투명도 입니다
//										    });
//		
//										    polygon.setMap(map);
//										});
//								    } 
//		
//								    createPolygon(map);
//								    
//								    
//	// 								var sortArray = [..._v.sort];
//	// 								var valueArray = _v.values;
//	
//	// 								var result;
//	// 								var position;
//	//                                 var content;
//	
//	// 								createCustomOverlayPosition = function(_x, _y){
//	//                                     position = new kakao.maps.LatLng(_y, _x); 
//	// 								};
//	                                
//	//                                 createCustomOverlayContent = function(_content, _value){
//	//                                     content = 
//	//                                         '<div class ="label" style="text-align:center;><span class="left"></span><span class="center">'+ _content +'<br>' + _value + '</span><span class="right"></span></div>';                                     
//	//                                 };
//	
//	// 								createCustomOverlay = function(_x, _y, _content, _value, _map){
//	//                                     createCustomOverlayPosition(_x, _y);
//	//                                     createCustomOverlayContent(_content, _value);
//	
//	//                                     var customOverlay = new kakao.maps.CustomOverlay({
//	// 										position: position,
//	// 										content: content   
//	// 									});
//	                                    
//	//                                     customOverlay.setMap(_map);
//	// 								};
//	
//	// 								for(var i=0; i<sortArray.length; i++){
//	// 									result = await addressSearch(sortArray[i]);			
//	                                    
//	//                                     var resultX = result[0]['x'];
//	//                                     var resultY = result[0]['y'];
//					   			        
//	// 				   			        createCustomOverlay(resultX, resultY, sortArray[i], valueArray[i], map);
//	// 								}
//								
//								    
//					    });
//					//}
//					
//				break;
//
//				case '시군구':	//시군구 일때
//					//setState = function(){
//					function getOneData(callbackFunc){
//				    	$.ajax({
//								url : WISE.Constants.context+'/resources/geoJson/TL_SCCO_SIG.json',
//								type : 'get',
//								dataType:'json',
//								success: function(data){                             
//		                            callbackFunc(data);							
//								}
//						    });
//					    };
//		
//					    getOneData(function(data){						
//									var arraySort = [..._v.sort];
//	                                
//									 var arraySortNum = new Array();
//		                                $.each(arraySort, function(as_i, as_v){
//		                                    var count = 0;
//		                                	$.each(data.features, function(f_i, f_v){
//		                                		var jsonLocation = f_v.properties['SIG_KOR_NM'];
//		                                        
//		                                		if(jsonLocation.includes(as_v)){
//		                                			arraySortNum[as_i] = ++count;
//		                                		}
//		                                	});
//		                                });						
//	                                var code = ' ';
//	                                
//	                                $.each(arraySort, function(as_i, as_v){                            
//	                                	$.each(data.features, function(f_i, f_v){
//	                                		var jsonLocation = f_v.properties['SIG_KOR_NM'];
//	                                		
//	                                		if(jsonLocation.includes(as_v)){
//	                                			if(arraySortNum[as_i] == 1){
//													//f_v.properties['']
//													locationOne[as_i] = new Array();
//
//													$.each(f_v.geometry.coordinates[0], function(c_i, c_v){
//														locationOne[as_i].push(c_v);
//													});
//													code = f_v.properties['SIG_CD'].substr(0,2);
//												}else{
//													if(code == f_v.properties['SIG_CD'].substr(0,2)){
//														locationOne[as_i] = new Array();
//
//														$.each(f_v.geometry.coordinates[0], function(c_i, c_v){
//															locationOne[as_i].push(c_v);
//														});
//													}
//												}
//	                                			
//	                                		}
//	                                	})
//	                                });
//	                                
//	                                const getPolygonCenterPath = function(_x, _y, lz_i, map){
//	                                	var maxX = Math.max.apply(null, _x);
//										var minX = Math.min.apply(null, _x);
//
//										var maxY = Math.max.apply(null, _y);
//										var minY = Math.min.apply(null, _y);
//
//										polygonCenter = new Array();
//
//										polygonCenter.push((minX+maxX)/2);
//										polygonCenter.push((minY+maxY)/2);
//	                                    var locationContent = arraySort[lz_i];
//	                                    var valueContent = {};                          
//	                                    var valueContentResult = '';
//
//										$.each(_v.values, function(_a, _b){
//											valueContent[_a] = _b[locationContent];
//											console.log(valueContent);
//										});                      
//								                          
//										$.each(valueContent, function(vc_i, vc_v){
//	                                    	//result = vc_i + ': ' + vc_v+'\n';
//	                                    	result = vc_v + '\n';
//	                                    	valueContentResult += result;
//	                                    });
//	                                    
//								        var content = '<div class ="label" style="text-align:center;"><span class="left"></span><span class="center" style="font-size:25px; color:blue;">'+locationContent+'</span><br><span style="font-size:15px; color:blue;">'+
//								        valueContentResult+
//								        '</span><span class="right"></span></div>';
//
//										// 커스텀 오버레이가 표시될 위치입니다 
//										var position = new kakao.maps.LatLng(polygonCenter[1], polygonCenter[0]);   
//
//										// 커스텀 오버레이를 생성합니다
//										var customOverlay = new kakao.maps.CustomOverlay({
//											position: position,
//											content: content   
//										});
//
//										// 커스텀 오버레이를 지도에 표시합니다
//										customOverlay.setMap(map);            
//	                                }
//
//			                        const createPolygonPath = function(_x, _y){
//			                        	return new kakao.maps.LatLng(_y, _x);
//			                        }
//		
//							    	const createPolygon = function(map){
//										$.each(locationOne, function(lz_i, lz_v){
//											var polygonPath = [];
//											var pathX = new Array();
//	                                        var pathY = new Array();
//	                                        
//	                                        for(var i=0; i<lz_v.length; i++){
//	                                        	polygonPath.push(createPolygonPath(lz_v[i][0], lz_v[i][1]));
//	                                        	pathX.push(lz_v[i][0]);
//	                                        	pathY.push(lz_v[i][1]);
//	                                        }
//											
//	                                        getPolygonCenterPath(pathX, pathY, lz_i, map);
//	                                        
//											var polygon = new kakao.maps.Polygon({
//											path:polygonPath, // 그려질 다각형의 좌표 배열입니다
//											strokeWeight: 3, // 선의 두께입니다
//											strokeColor: '#FF3DE5', // 선의 색깔입니다
//											strokeOpacity: 0.8, // 선의 불투명도 입니다 1에서 0 사이의 값이며 0에 가까울수록 투명합니다
//											strokeStyle: 'longdash', // 선의 스타일입니다
//											fillColor: '#FF8AEF', // 채우기 색깔입니다
//											fillOpacity: 0.7 // 채우기 불투명도 입니다
//										    });
//		
//										    polygon.setMap(map);
//										});
//								    } 
//		
//								    createPolygon(map);							    								
//									    
//					    });
//					//}
//					
//				break;
//
//				case '읍면동':
//					//setDong = function(){
//					function getTwoData(callbackFunc){
//				    	$.ajax({
//								url : WISE.Constants.context+'/resources/geoJson/EMD.zip.geojson',
//								type : 'get',
//								dataType:'json',
//								success: function(data){                             
//		                            callbackFunc(data);							
//								}
//						    });
//					    };
//		
//					    getTwoData(function(data){						
//									var arraySort = [..._v.sort];
//	                                
//									 var arraySortNum = new Array();
//		                                $.each(arraySort, function(as_i, as_v){
//		                                    var count = 0;
////		                                    for(var i=0; i<data.features.length; i++){
////		                                    	var jsonLocation = data.features[i].properties['EMD_KOR_NM'];
//	//
////		                                    	if(jsonLocation.includes(as_v)){
////		                                    		arraySortNum[as_i] = ++count;
////		                                    		break;
////		                                    	}
////		                                    }
////		                                    if(count==0){
////		                                    	console.log(as_v);
////		                                    }
//	 	                                	$.each(data.features, function(f_i, f_v){
//	 	                                		var jsonLocation = f_v.properties['EMD_KOR_NM'];
//		                                        
//	 	                                		if(jsonLocation.includes(as_v)){
//	 	                                			arraySortNum[as_i] = ++count;
//	 	                                		}
//	 	                                	});
//		                                });						
//	                               
//	                              
//	                                $.each(arraySort, function(as_i, as_v){                            
////	                                	var start;
////	                                	var end;
////	                                	for(var i=0; i<_v.name.length; i++){
////	                                		if(v.name[i] == as_v){
////	                                			start = i;
////	                                			break;
////	                                		}
////	                                	};
////	                                	
////	                                	for(var i=start; i<_v.name.length; i++){
////	                                		if(v.name[i] != as_v){
////	                                			end = i;
////	                                			break;
////	                                		}
////	                                	}
//	                                	
//	                                	var code = '';
//	                                	
////	                            		$.each(data.features, function(f_i, f_v){
////	                            			var jsonLocation = f_v.properties['END_KOR_NM'];
////	                            			
////	                            			if(jsonLocation.includes(as_v)){
////	                            				for(var i=start; i<end; i++){
////	                            					if(arraySortNum[i] == 1){
////	                            						code = f_v.properties['EMD_CD'].substr(0,2);
////	                            						break;
////	                            					}
////	                            				}
////	                            			}
////	                            		});
//	                                		
//	                                	
//	                                	$.each(data.features, function(f_i, f_v){
//	                                		var jsonLocation = f_v.properties['EMD_KOR_NM'];
//	                                		
//	                                		if(jsonLocation.includes(as_v)){
//	                                			if(arraySortNum[as_i] == 1){
//													//f_v.properties['']
//													locationTwo[as_i] = new Array();
//
//													$.each(f_v.geometry.coordinates[0], function(c_i, c_v){
//														locationTwo[as_i].push(c_v);
//													});
//													code = f_v.properties['EMD_CD'].substr(0,2);
//												}else{
//													if(code == f_v.properties['EMD_CD'].substr(0,2)){
//														locationTwo[as_i] = new Array();
//
//														$.each(f_v.geometry.coordinates[0], function(c_i, c_v){
//															locationTwo[as_i].push(c_v);
//														});
//													}
//												}
//	                                			
//	                                		}
//	                                	})
//	                                });
//	                                
//	                                const getPolygonCenterPath = function(_x, _y, lz_i, map){
//	                                	var maxX = Math.max.apply(null, _x);
//										var minX = Math.min.apply(null, _x);
//
//										var maxY = Math.max.apply(null, _y);
//										var minY = Math.min.apply(null, _y);
//
//										polygonCenter = new Array();
//
//										polygonCenter.push((minX+maxX)/2);
//										polygonCenter.push((minY+maxY)/2);
//	                                    var locationContent = arraySort[lz_i];
//	                                    var valueContent = {};                          
//	                                    var valueContentResult = '';
//
//										$.each(_v.values, function(_a, _b){
//											valueContent[_a] = _b[locationContent];
//											console.log(valueContent);
//										});                      
//								                          
//										$.each(valueContent, function(vc_i, vc_v){
//	                                    	//result = vc_i + ': ' + vc_v+'\n';
//	                                    	result = vc_v + '\n';
//	                                    	valueContentResult += result;
//	                                    });
//	                                    
//								        var content = '<div class ="label" style="text-align:center;"><span class="left"></span><span class="center" style="font-size:25px; color:blue;">'+locationContent+'</span><br><span style="font-size:15px; color:blue;">'+
//								        valueContentResult+
//								        '</span><span class="right"></span></div>';
//
//										// 커스텀 오버레이가 표시될 위치입니다 
//										var position = new kakao.maps.LatLng(polygonCenter[1], polygonCenter[0]);   
//
//										// 커스텀 오버레이를 생성합니다
//										var customOverlay = new kakao.maps.CustomOverlay({
//											position: position,
//											content: content   
//										});
//
//										// 커스텀 오버레이를 지도에 표시합니다
//										customOverlay.setMap(map);            
//	                                }
//
//			                        const createPolygonPath = function(_x, _y){
//			                        	return new kakao.maps.LatLng(_y, _x);
//			                        }
//		
//							    	const createPolygon = function(map){
//										$.each(locationTwo, function(lz_i, lz_v){
//											var polygonPath = [];
//											var pathX = new Array();
//	                                        var pathY = new Array();
//	                                        
//	                                        if(lz_v){		
//		                                        for(var i=0; i<lz_v.length; i++){
//		                                        	
//														polygonPath.push(createPolygonPath(lz_v[i][0], lz_v[i][1]));
//														pathX.push(lz_v[i][0]);
//														pathY.push(lz_v[i][1]);
//		                                        	
//		                                        }
//	                                        }
//	                                        
//	                                        getPolygonCenterPath(pathX, pathY, lz_i, map);
//	                                        
//											var polygon = new kakao.maps.Polygon({
//											path:polygonPath, // 그려질 다각형의 좌표 배열입니다
//											strokeWeight: 3, // 선의 두께입니다
//											strokeColor: '#39DE2A', // 선의 색깔입니다
//											strokeOpacity: 0.8, // 선의 불투명도 입니다 1에서 0 사이의 값이며 0에 가까울수록 투명합니다
//											strokeStyle: 'longdash', // 선의 스타일입니다
//											fillColor: '#A2FF99', // 채우기 색깔입니다
//											fillOpacity: 0.7 // 채우기 불투명도 입니다
//										    });
//		
//										    polygon.setMap(map);
//										});
//								    } 
//		
//								    createPolygon(map);							    								
//									    
//					    });
//				//}
//					
//				break;
//			}
//       	}
//		});		
/*////////////////////////////////////////////////////////////////////	

		///////////////////////////////////////////////////////jsy
		/*var tooltipFirstyColumnStyle = 'font-weight:bold; padding-right:5px; text-align:right;';

		
		//generate map chart
		$.each(this.panelManager.valuePanel, function(_pn, _ovp) {
			var dxConfigs = self.getDxItemConfig(self.meta);
			var areaLayer = dxConfigs.layers[0];
			var currentTarget = {};
			
			$.each(WISE.util.Object.toArray(self.meta.Maps.ValueMap),function(_i,_Maparr){
				if(_ovp.value.uniqueName == _Maparr.Value.UniqueName){
					currentTarget = _Maparr;
				}
			});
			dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616
			var colorGroupArray = self.gradientValue(dataset, currentTarget.CustomScale, currentTarget.GradientPalette, _ovp.value.nameBySummaryType,currentTarget.CustomColorSet);
			if(typeof currentTarget.CustomScale == 'undefined'){

				areaLayer.colorGroups = colorGroupArray;
			}
			else if(typeof currentTarget.CustomScale.PercentScale == 'undefined'){

				areaLayer.colorGroups = colorGroupArray;
			}
			else{
				areaLayer.colorGroups = _ovp.value.colorGroups;
			}
			
			areaLayer.colorGroupingField = _ovp.value.nameBySummaryType;
			
			if(typeof currentTarget.GradientPalette != 'undefined'){
				var startColor = self.getHexColor(currentTarget.GradientPalette.StartColor).toUpperCase(), endColor = self.getHexColor(currentTarget.GradientPalette.EndColor).toUpperCase();
				areaLayer.palette = [startColor,endColor];
			}
			else if(typeof currentTarget.CustomPalette != 'undefined'){
				if(self.meta.Palette == 'Custom'){
					if(currentTarget.CustomPalette.Color != ""){
					    var colorArray = new Array();
						$.each(currentTarget.CustomPalette.Color,function(_i,_colorItems){
							if(typeof _colorItems == 'string' && _colorItems.indexOf('#') > -1){
								colorArray.push(_colorItems.toUpperCase());	
							}else{
								colorArray.push(self.getHexColor(_colorItems).toUpperCase());
							}
						});
						areaLayer.palette = colorArray;	
					}else{
						areaLayer.palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
					}
					
				}else{

						if(typeof self.meta.Palette == 'string'){
							areaLayer.palette = self.meta.Palette;
						}					
					
				}
			}
			else{
				if(typeof self.meta.Palette == 'string'){
					areaLayer.palette = self.meta.Palette;
				}else{
				    areaLayer.palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;	
				}
				dogfoot 지도 팔레트 기본값이 뷰어랑 다른 오류 수정 shlim 20200616
				
			}
			
			var selectedMeasures
			$.each(measures, function(_i,_measures){
				if(_ovp.value.uniqueName == _measures.uniqueName){
					selectedMeasures = _measures;
					return;
				}
			});
			areaLayer.customize = function (_elements) {
				$.each(_elements, function (_i0, _element) {
					var name = _element.attribute(self.attributeName);
					$.each(dataset, function(_i1, _d1) {

						if ($.type(self.attributeDimension) === 'object' && (name == _d1[self.attributeDimension.name])) {
							var d = _d1[_ovp.value.nameBySummaryType];
							
							if (d !== undefined) {
								_element.attribute(_ovp.value.nameBySummaryType, d);
								var formatVal = "";
								if(selectedMeasures.format.type == undefined){
									formatVal = selectedMeasures.format.substring(0,1) == 'd'? undefined:selectedMeasures.format.substring(0,1);
								}else{
									formatVal = selectedMeasures.format.type.substring(0,1) == 'd'? undefined:selectedMeasures.format.type.substring(0,1);
								}
								var tooltipHtml = '<b style = "' + gDashboard.fontManager.getCustomFontStringForItem(12) + '">'+name+'</b><br/>';
								tooltipHtml += '<b style = "' + gDashboard.fontManager.getCustomFontStringForItem(12) + '">' + (_ovp.value.vmValueName || _ovp.value.caption) + ':</b> ' + WISE.util.Number.unit(d,'Number',undefined,selectedMeasures.precision,undefined,undefined,undefined,undefined);
								_element.attribute('tooltipHtml', tooltipHtml);
							} 
							return false;
						}
						
					});
				});
			};
			 legend 
			if (self.legend && self.legend.Visible) {
				var legend = {customizeText: function (_arg) {
//					return WISE.util.Number.unit(_arg.start,selectedMeasures.format.substring(0,1),selectedMeasures.precision);
//					if(_arg.index == (areaLayer.palette.length-1)){
//						return _arg.start + ' ~ ';
//					}else{
//						return _arg.start + ' ~ ' + (_arg.end - 1);
//					}
					dogfoot 범례 표기 변경 shlim 20200617
					return _arg.start + ' ~ ';
					
				}};
				// extend parent object
				WISE.util.Object.overrideExtend(legend, self.mapLegend);

				dxConfigs.legends = [legend];
			}
			switch(self.shapefileArea) {
			case 'Europe':
				areaLayer.dataSource = DevExpress.viz.map.sources.europe;
				break;
			case 'Asia':
				dxConfigs.zoomFactor = 1.41; 
				dxConfigs.center = [117.993, 57.500]; 
				dxConfigs.bounds = [-180, 85, 180, -60]; 
				areaLayer.dataSource = DevExpress.viz.map.sources.world;
				break;
			case 'NorthAmerica':
				dxConfigs.zoomFactor = 1.45; 
				dxConfigs.center = [-109.971, 64.990]; 
				dxConfigs.bounds = [-180, 85, 180, -60]; 
				areaLayer.dataSource = DevExpress.viz.map.sources.world;
				break;
			case 'SouthAmerica':
				dxConfigs.zoomFactor = 3.00; 
				dxConfigs.center = [-69.995, -26.998]; 
				dxConfigs.bounds = [-180, 85, 180, -60]; 
				areaLayer.dataSource = DevExpress.viz.map.sources.world;
				break;
			case 'Africa':
				areaLayer.dataSource = DevExpress.viz.map.sources.africa;
				break;
			case 'USA':
				dxConfigs.zoomFactor = 0.5;
				areaLayer.dataSource = DevExpress.viz.map.sources.usa;
				break;
			case 'Canada':
				areaLayer.dataSource = DevExpress.viz.map.sources.canada;
				break;
			default:
				if (self.customShapefile) {
					 load shp 일 경우
					if(self.shpFilemeta != undefined && self.dbfFilemeta != undefined){
//						var parseSources = { shp: self.shpFilemeta, dbf: self.dbfFilemeta},
//					    parseOptions = { precision: 2 }, 
//					    data = DevExpress.viz.vectormaputils.parse(parseSources, parseOptions);
//						areaLayer.dataSource = data;
						areaLayer.dataSource = self.CustomUrl.Url;
						dxConfigs.bounds[0] = dxConfigs.bounds[0] - 5;
						dxConfigs.bounds[1] = dxConfigs.bounds[1] + 0.5;
					}else{
//						areaLayer.data = WISE.Constants.context+'/UploadFiles/geojson/'+mapdata;
						//디버깅용
						if(self.CustomUrl == ""){
							self.CustomUrl = {'Url':self.meta.CustomShapefile.Url.replace(/shp/gi,"geojson")};
//							self.CustomUrl = {'Url':WISE.Constants.context+'/UploadFiles/geojson/.geojson'};
						}
						var fileName = self.CustomUrl.Url.substring(self.CustomUrl.Url.lastIndexOf('/')+1,self.CustomUrl.Url.length);
						$.ajax({
							type:'post',
							url:WISE.Constants.context + '/report/getGeoJSon.do',
							data:{geojsonUrl:fileName},
							async:false,
							success:function(_data){
								areaLayer.dataSource = _data.geoJsonMeta
							}
						});
						dxConfigs.bounds[0] = dxConfigs.bounds[0] - 5;
						dxConfigs.bounds[1] = dxConfigs.bounds[1] + 0.5;
//						areaLayer.dataSource = self.CustomUrl.Url;
					// 	dxConfigs.bounds[0] = 120.081787109375;
					// 	dxConfigs.bounds[1] = 39.112152099609375;
					// 	dxConfigs.bounds[2] = 130.9403076171875;
					// 	dxConfigs.bounds[3] = 33.112060546875;
					}
					
					

					if (self.CUSTOMIZED.get('useShapeFile')) {
						_ovp.useShapeFile = true;
						_ovp.shapelocation = self.shapelocation;
					} else {
						 var mapdata = WISE.widget.getCustom(WISE.Constants.pid, this.type);
						 var itemdata = WISE.widget.getCustom(WISE.Constants.pid, this.type);
						 var commondata = WISE.widget.getCustom('common','KAKAO_MAP');
						 if(typeof mapdata != 'undefined')
							 mapdata= mapdata['KAKAO2_MAP']['data'];
						 else if(typeof itemdata != 'undefined')
							 mapdata= itemdata['KAKAO2_MAP']['data'];
						 else{
							 mapdata = self.CUSTOMIZED.get('data');
						 }
					}
				} else {
					월드 맵
					dxConfigs.zoomFactor = 1.00;
					dxConfigs.center = [0.000, 46.036];
					dxConfigs.bounds = [-180, 85, 180, -60]; 
					areaLayer.dataSource = DevExpress.viz.map.sources.world;
				}
			}

			_ovp.dxConfigs = dxConfigs;

		});
		if (!_ativePanelId) {
			// 맨 처음 value-panel만 active 시킨다.
			$.each(this.panelManager.valuePanel, function(_pn, _ovp) {
				_ativePanelId = _pn;
				return false;
			});
		}*/
		////////////////////////////////////////////////////jsy
		
		
		
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();	
			gDashboard.updateReportLog();
		}
	};
	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO['MasterFilterMode']) {
			
			var item = $('#'+self.itemid+'_DataItem1').dxVectorMap('instance');
			if(item){
				item.clearSelection();
				self.selectedText = "";
			}
			
			$('#' + self.itemid + '_tracking_data_container').html('');
			
			self.selectedValues = [];
			var clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
       		$(clearTrackingImg)
       			.attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png')
       			.on('mouseover', function() {
       				$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
       			})
       			.on('mouseout', function() {
       				$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
       			});
		}
	};
	
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
		//tracking data text area
//		$('#'+_itemid + '_tracking_data_container').empty();
//		if (this.valueMaps && this.valueMaps.length > 1) {
//			// value-panel selection
//			var valueListId = _itemid + '_topicon_vl';
//			var popoverid = _itemid + '_topicon_vl_popover';
//			
//			var listHtml = '<li><a id="' + valueListId + '" href="#"><img src="' + WISE.Constants.context + '/images/cont_box_icon_layer.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer.png\'" alt="Select Panel" title="Select Panel"></a></li>';
//			$('#' + _itemid + '_tracking_data_container').append(listHtml);
//			
//			var p = $('#editPopover').dxPopover('instance');
//			
//			var temphtml = "<div style='width:150px;'>";
//			temphtml += '<div class="add-item noitem">';
//			$.each(this.valueMaps, function(_i, _vo) {
//				temphtml += '<div class="select-style" data-key="' + (self.itemid + '_' + _vo.uniqueName) + '"><span data-key="' + (self.itemid + '_' + _vo.uniqueName) + '">' + _vo.caption + '</span></a>';
//			});
//			temphtml += '</div>';
//			temphtml += '</div>'; 
//			
//			p.option({
//				target: '#'+valueListId,
//				contentTemplate: function(contentElement) {
//					$(temphtml).appendTo(contentElement);
//					$('.select-style').on('click',function(_e){
//						p.hide();
//						var targetPanelId = _e.target.getAttribute('data-key');
//						self.panelManager.activeValuePanel(self.itemid,targetPanelId);
//					});
//				},
////				visible:false
//			})
//			$('#' + _itemid + '_topicon').off('click').on('click',function(){
//				p.option('visible', !(p.option('visible')));
//			});
//		}
//		
//		// tracking conditions clear
//		if (self.IO && self.IO['MasterFilterMode']) {
//			if(self.IO['MasterFilterMode'] != "Off"){
//				self.trackingClearId = self.itemid + '_topicon_tracking_clear';
//				
//				var trackingClearHtml = '';
//				trackingClearHtml += '<li><a id="' + self.trackingClearId + '" href="#">';
//				trackingClearHtml += '<img src="' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png" ';
//				trackingClearHtml += 'onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png\'" '; 
//				trackingClearHtml += 'onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png\'" ';
//				trackingClearHtml += 'alt="Clear Filters" title="Clear Filters"></a></li>';
//				topIconPanel.append(trackingClearHtml);
//				
//				$("#" + self.trackingClearId).click(function(_e) {
//					var clearTrackingImg = $(this).find('img')[0];
//					if(clearTrackingImg.src.indexOf('cont_box_icon_filter_.png') > -1 ) {
//						$('#' + self.itemid + '_tracking_data_container').html('');
//						window[self.dashboardid].filterData(self.itemid, []);
//						self.clearTrackingConditions();
//					}
//				});
//			}
//			
//		}
	};
	
	this.getHexColor = function(number){
	    return "#"+((number)>>>0).toString(16).slice(-6);
	};
	/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
	this.gradientValue = function(_data,range,colorList,summaryCol,customChck){
		self.valueRange = {}; 
//		self.valueRange['rangeStop'] = typeof range == 'undefined' ? [0,10,20,30,40,50,60,70,80,90] :range.RangeStop.slice(0,range.RangeStop.length-1);
		self.valueRange['rangeStop'] = [0,10,20,30,40,50,60,70,80,90];
		/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
		var ColorSetCheck =  typeof customChck != 'undefined' ? customChck.CustomColorSetCheck : 'N';
        if(ColorSetCheck == 'Y'){
            self.valueRange['customRangeStop'] = range['RangeStop'];
        }		
		self.valueRange['PercentScale'] = typeof range == 'undefined' ? true : range.PercentScale;
		var returnGroup = new Array();
		if(self.valueRange.PercentScale == false){
			returnGroup = self.valueRange['rangeStop'];
//			더미코드. 만약을 위해 삭제 안함.

//			var startR = self.hextoDec(startColor.substring(1,3)), startG = self.hextoDec(startColor.substring(3,5)), startB= self.hextoDec(startColor.substring(5,7));
//			var endR = self.hextoDec(endColor.substring(1,3)), endG = self.hextoDec(endColor.substring(3,5)), endB = self.hextoDec(endColor.substring(5,7));



//			var RedDiffer = startR > endR ? startR-endR : endR-startR;
//			var GreenDiffer = startG > endG ? startG-endG : endG-startG;
//			var BlueDiffer = startB > endB ? startB-endB : endB-startB;

//			var returnColor = new Array();
//			var RedReturn = startR > endR ?  endR : startR;
//			var GreenReturn = startG > endG ? endG : startG;
//			var BlueReturn = startB > endB ? endB : startB;
//			returnColor.push(startColor);
//			for(var i=0;i<valueRange.length;i++){
//				RedReturn = RedReturn  +  Math.round(RedDiffer/valueRange.length);
//				GreenReturn = GreenReturn +  Math.round(GreenDiffer/valueRange.length);
//				BlueReturn = BlueReturn +  Math.round(BlueDiffer/valueRange.length);

//				var str = "";
//				str += "#"+self.decimalToHex(RedReturn)+""+self.decimalToHex(GreenReturn)+""+self.decimalToHex(BlueReturn)+"";
//				returnColor.push(str);
//			}

		}
		else{
			/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
			if(ColorSetCheck == 'Y'){
				/*dogfoot 지도 팔레트 설정 후 조회시 최대 범위값 추가 shlim 20200617*/
                self.valueRange['customRangeStop'].forEach(function(range, index) {
					returnGroup.push(range);
				});

                returnGroup.push(self.CUSTOMIZED.get('rangeStopMaxValue'));
			}else{
				var maxJson = (self.getJSONArrayMax(_data,summaryCol)),minJson = (self.getJSONArrayMin(_data,summaryCol));
				var minVal = minJson[summaryCol], gap = maxJson[summaryCol] - minJson[summaryCol];
				returnGroup.push(minVal);
				for(var i=1;i<self.valueRange['rangeStop'].length;i++){
					returnGroup.push(Math.round(minVal+gap*(self.valueRange['rangeStop'][i]/100)));
				}
				returnGroup.push(maxJson[summaryCol]);
			}
		}
		return returnGroup;
	};
	
	this.hextoDec = function(val) {
	    var hex = val.split('').reverse().join('');
	    var dec = 0;
	    for (var i = 0; i < hex.length; i++) {
	        var conv = '0123456789ABCDEF'.indexOf(hex[i]);
	        dec += conv * Math.pow(16, i);
	    }
	    return dec;
	};
	
	this.decimalToHex = function(d, padding) {
	    var hex = Number(d).toString(16);
	    padding = typeof (padding) === "undefined" || padding === null ? padding = 2 : padding;

	    while (hex.length < padding) {
	        hex = "0" + hex;
	    }

	    return hex;
	};
	
	this.getJSONArrayMax = function(arr, prop) {
	    var max;
	    for (var i=0 ; i<arr.length ; i++) {
	        if (!max || parseInt(arr[i][prop]) > parseInt(max[prop]))
	            max = arr[i];
	    }
	    return max;
	};
	
	this.getJSONArrayMin = function(arr, prop) {
	    var min;
	    for (var i=arr.length ; i>0 ; i--) {
	        if (!min || parseInt(arr[i][prop]) < parseInt(min[prop]))
	            min = arr[i];
	    }
	    return min;
	};
	
	this._base64ToArrayBuffer = function(base64) {
		var binary_string;
		if(WISE.Constants.browser =='IE7' || WISE.Constants.browser =='IE8' || WISE.Constants.browser =='IE9'){
			binary_string = atob(base64);
		}
		else{
			binary_string = window.atob(base64);
		}
		var len = binary_string.length;
		var bytes = new Uint8Array( len );
		for (var i = 0; i < len; i++)        {
		    bytes[i] = binary_string.charCodeAt(i);
		}
		return bytes.buffer;
	};
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
//		if($('#data').length > 0){
//			$('#data').remove();
//		}
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			$('#menulist').append($('<li id="data" rel="panelDataA-2"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
//		}
//		
//		if($('#design').length > 0){
//			$('#design').remove();
//		}
//		
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
//		}
//		
//		$('#tab5primary').empty();
//		$('#tab5primary').append('<span class="drag-line"></span>');
//		
//		$('<li class="slide-ui-item"><a href="#" id="captionVisible" class="lnb-link slide-ui-item more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="editName" class="lnb-link slide-ui-item more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="loadMap" class="lnb-link slide-ui-item more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_importMap.png" alt=""><span>지도 불러오기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="lockNavigation" class="lnb-link slide-ui-item more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_lockNavigation.png" alt=""><span>탐색 잠금</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="Showlegend" class="lnb-link slide-ui-item more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_showColorLegend.png" alt=""><span>범레</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item" title="팔레트"><a href="#" id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item" title="색상 편집"><a href="#" id="customPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_editColor.png" alt=""><span>색상 편집</span></a></li>').appendTo($('#tab5primary'));
//			
//		
//		
//		//		$('<a id="setBackColor" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_color.png" alt=""><span>지도 배경색</span></a>').appendTo($('#tab5primary'));
//		
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content"><div id ="data-menu" class="panel-body"></div></div>'));	
//		}
//		
////		$('<a id="editFilter" class="btn point">필터편집</a>').appendTo($('#tab4primary'));
////		$('<a id="clearFilter" class="btn point">초기화</a>').appendTo($('#tab4primary'));
////		$('<a id="masterFilter" class="btn point">마스터 필터</a>').appendTo($('#tab4primary'));
////		$('<a id="drillDown" class="btn point">드릴 다운</a>').appendTo($('#tab4primary'));
////		$('<a id="crossDataSourceFiltering" class="btn point">교차 데이터 소스 필터링</a>').appendTo($('#tab4primary'));
////		$('<a id="ignoreMasterFilter" class="btn point">마스터 필터 무시</a>').appendTo($('#tab4primary'));
//		
//		$(  "<h4 class=\"tit-level3\">필터링</h4>" + 
//				"<div class=\"panel-body\">" + 
//				"	<div class=\"design-menu rowColumn\">" + 
//				"		<ul class=\"desing-menu-list col-2\">" + 
//				"			<li>" + 
//				"				<a href=\"#\" id=\"editFilter\" class=\"functiondo\">" +
//				"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_basicFilter.png\" alt=\"\"><span>필터 편집</span>" + 
//				"				</a>" + 
//				"			</li>" + 
//				"			<li>" + 
//				"				<a href=\"#\" id=\"clearFilter\" class=\"functiondo\">" + 
//				"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>초기화</span>" + 
//				"				</a>" + 
//				"			</li>" + 
//				"		</ul>" + 
//				"	</div>" + 
//				"</div>" +
//				"<h4 class=\"tit-level3\">상호 작용</h4>" + 
//				"<div class=\"panel-body\">" + 
//				"	<div class=\"design-menu rowColumn\">" + 
//				"		<ul class=\"desing-menu-list col-3\">" + 
//				"			<li>" + 
//				"				<a href=\"#\" id=\"singleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
//				"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_singleMasterFilter.png\" alt=\"\"><span>단일 마스터<br>필터</span>" + 
//				"				</a>" + 
//				"			</li>" + 
//				"			<li>" + 
//				"				<a href=\"#\" id=\"multipleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
//				"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_multipleMasterFilter.png\" alt=\"\"><span>다중 마스터<br>필터</span>" + 
//				"				</a>" + 
//				"			</li>" + 
//				"			<li>" + 
//				"				<a href=\"#\" id=\"drillDown\" class=\"multi-toggle-button functiondo\">" + 
//				"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_drillDown.png\" alt=\"\"><span>드릴<br>다운</span>" + 
//				"				</a>" + 
//				"			</li>" + 
//				"		</ul>" + 
//				"	</div>" + 
//				"</div>" + 
//				"<h4 class=\"tit-level3\">상호 작용 설정</h4>" + 
//				"<div class=\"panel-body\">" + 
//				"	<div class=\"design-menu rowColumn\">" + 
//				"		<ul class=\"desing-menu-list col-2\">" + 
//				"			<li>" + 
//				"				<a href=\"#\" id=\"crossFilter\" class=\"single-toggle-button functiondo\">" + 
//				"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_crossDataSourceFiltering.png\" alt=\"\"><span>교차 데이터<br>소스 필터링</span>" + 
//				"				</a>" + 
//				"			</li>" + 
//				"			<li>" + 
//				"				<a href=\"#\" id=\"ignoreMasterFilter\" class=\"single-toggle-button functiondo\">" + 
//				"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>마스터 필터<br>무시</span>" + 
//				"				</a>" + 
//				"			</li>" + 
//				"		</ul>" + 
//				"	</div>" + 
//				"</div>"
//			).appendTo($('#tab4primary'));
//		tabUi();
//		designMenuUi();
//		compMoreMenuUi();
//		
//		$('.single-toggle-button').on('click', function(e) {
//            e.preventDefault();
//            $(this).toggleClass('on');
//        });
//        $('.multi-toggle-button').on('click', function(e) {
//            e.preventDefault();
//            var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
//            if ($(this)[0] !== currentlyOn[0]) {
//                currentlyOn.removeClass('on');
//            }
//            $(this).toggleClass('on');
//        });
//
//		// toggle 'on' status according to chart options
//		if (self.IO) {
//			if (self.IO['MasterFilterMode'] === 'Single') {
//				$('#singleMasterFilter').addClass('on');
//			} else if (self.IO['MasterFilterMode'] === 'Multiple') {
//				$('#multipleMasterFilter').addClass('on');
//			}
//			if (self.IO['IsDrillDownEnabled']) {
//				$('#drillDown').addClass('on');
//			}
//			if (self['isMasterFilterCrossDataSource']) {
//				$('#crossFilter').addClass('on');
//			}
//			if (self.IO['IgnoreMasterFilters']) {
//				$('#ignoreMasterFilter').addClass('on');
//			}
//			if (self.IO['TargetDimensions'] === 'Argument') {
//				$('#targetArgument').addClass('on');
//			} else if (self.IO['TargetDimensions'] === 'Series') {
//				$('#targetSeries').addClass('on');
//			}
//        }
//		
//		
//		$('<div id="editPopup">').dxPopup({
//			height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('#tab5primary');
//		// settings popover
//		$('<div id="editPopover">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//		}).appendTo('#tab5primary');
//		
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);
//		});
		
	};
	
	this.functionDo = function(_f) {
		switch(_f) {
		/* DATA OPTIONS */
//			case 'editFilter': {
////				if (!(self.dxItem)) {
////					break;
////				}
//				var p = $('#editPopup').dxPopup('instance');
//				p.option({
//					title: '필터 편집',
//					contentTemplate: function(contentElement) {
//						var field = [];
//						$.each(self.seriesDimensions, function(_i, series) {
//							field.push({ dataField: series['name'], dataType: 'string' });
//						});
//						$.each(self.dimensions, function(_i, dimension) {
//							field.push({ dataField: dimension['name'], dataType: 'string' });
//						});

//						contentElement.append('<div id="' + self.itemid + '_editFilter">');
//						$('#' + self.itemid + '_editFilter').dxFilterBuilder({
//							fields: field,
//							value: self.filter
//						});
//					}
//				});
//				// apply filter to current item
//				p.option('toolbarItems[0].options.onClick', function() {
//					var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').getFilterExpression();
//					var newDataSource = new DevExpress.data.DataSource({
//						store: self.globalData,
//						paginate: false
//					});
//					newDataSource.filter(filter);
//					newDataSource.load();
//					
//					self.filter = filter;
//					self.bindData(newDataSource.items());
//					
//					p.hide();
//				});
//				p.show();
//				break;
//			}
			// clear filters
//			case 'clearFilter': {
////				if (!(self.dxItem)) {
////					break;
////				}
//				if (self.filter) {
//					self.filter = null;
//					self.bindData(self.globalData);
//				}
//				break;
//			}
			// toggle master filter mode
//			case 'singleMasterFilter': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				if (self.IO['MasterFilterMode'] === 'Single') {
//					self.Map['InteractivityOptions']['MasterFilterMode'] = 'Off';
//					self.IO['MasterFilterMode'] = 'Off';
//				} else {
//					self.Map['InteractivityOptions']['MasterFilterMode'] = 'Single';
//					self.IO['MasterFilterMode'] = 'Single';
//				}
//				gDashboard.filterData(self.itemid, [], self.dataSourceId, self.isMasterFilterCrossDataSource);
////				filterArray = new Array();
//				self.clearTrackingConditions();
//				break;
//			}
			// toggle multiple master filter mode
//			case 'multipleMasterFilter': {
////				if (!(self.dxItem)) {
////					break;
////				}
//				if (self.IO['MasterFilterMode'] === 'Multiple') {
//					self.Map['InteractivityOptions']['MasterFilterMode'] = 'Off';
//					self.IO['MasterFilterMode'] = 'Off';
//				} else {
//					self.Map['InteractivityOptions']['MasterFilterMode'] = 'Multiple';
//					self.IO['MasterFilterMode'] = 'Multiple';
//				}			
//				gDashboard.filterData(self.itemid, [], self.dataSourceId, self.isMasterFilterCrossDataSource);
////				filterArray = new Array();
//				self.clearTrackingConditions();
//				break;
//			}
			// enable drill down
//			case 'drillDown': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var p = $('#editPopover').dxPopover('instance');
//				p.option({
//					target: '#drillDown',
//					contentTemplate: function(contentElement) {
//						contentElement.append('<div id="' + self.itemid + '_drillDown">');
//						$('#' + self.itemid + '_drillDown').dxRadioGroup({
//							dataSource: ['On', 'Off'],
//							value: self.IO['IsDrillDownEnabled'] ? 'On' : 'Off',
//							onValueChanged: function(e) {
//								self.IO['IsDrillDownEnabled'] = e.value ==='On' ? true : false;
//								var newData = self.__getChartData();
//								self.dxItem.option({dataSource: newData});

//							}
//						});
//					}
//				});
//				p.option('visible', !(p.option('visible')));
//				break;
//			}
			// enable cross data source filtering
//			case 'crossFilter': {
////				if (!(self.dxItem)) {
////					break;
////				}
//				var p = $('#editPopover').dxPopover('instance');
//				p.option({
//					target: '#crossFilter',
//					contentTemplate: function(contentElement) {
//						contentElement.append('<div id="' + self.itemid + '_crossFiltering">');
//						$('#' + self.itemid + '_crossFiltering').dxRadioGroup({
//							dataSource: ['On', 'Off'],
//							value: self.isMasterFilterCrossDataSource ? 'On' : 'Off',
//							onValueChanged: function(e) {
//								self.isMasterFilterCrossDataSource = e.value === 'On' ? true : false;
//								self.meta['IsMasterFilterCrossDataSource'] = self.isMasterFilterCrossDataSource;
//							}
//						});
//					}
//				});
//				p.option('visible', !(p.option('visible')));
//				break;
//			}
			// ignore master filter
//			case 'ignoreMasterFilter': {
////				if (!(self.dxItem)) {
////					break;
////				}
//				var p = $('#editPopover').dxPopover('instance');
//				p.option({
//					target: '#ignoreMasterFilter',
//					contentTemplate: function(contentElement) {
//						contentElement.append('<div id="' + self.itemid + '_ignoreMasterFilters">');
//						$('#' + self.itemid + '_ignoreMasterFilters').dxRadioGroup({
//							dataSource: ['On', 'Off'],
//							value: self.IO['IgnoreMasterFilters'] ? 'On' : 'Off',
//							onValueChanged: function(e) {
//								self.IO['IgnoreMasterFilters'] = e.value === 'On' ? true : false;
//								self.tracked = !self.IO['IgnoreMasterFilters'];
//								self.bindData(self.globalData);
//							}
//						});
//					}
//				});
//				p.option('visible', !(p.option('visible')));
//				break;
//			}
			// edit target dimensions
//			case 'targetDimension': {
////				if (!(self.dxItem)) {
////					break;
////				}
//				var p = $('#editPopover').dxPopover('instance');
//				p.option({
//					target: '#targetDimension',
//					contentTemplate: function(contentElement) {
//						contentElement.append('<div id="' + self.itemid + '_targetDimensions">');
//						$('#' + self.itemid + '_targetDimensions').dxRadioGroup({
//							dataSource: ['Argument', 'Series'],
//							value: self.IO['TargetDimensions'],
//							onValueChanged: function(e) {
//								self.IO['TargetDimensions'] = e.value;
//								window[self.dashboardid].filterData(self.itemid, [], self.dataSourceId, self.isMasterFilterCrossDataSource);
//								filterArray = new Array();
//								self.clearTrackingConditions();
//								selectedPoint = null;
//							}
//						});
//					}
//				});
//				p.option('visible', !(p.option('visible')));
//				break;
//			}
		
			// edit filter builder
			case 'captionVisible': {
//				if (!(self.activePanel)) {
//					break;
//				}
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.Map['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.Map['ShowCaption'] = false;
				}
				break;
			}
			// edit chart title
			case 'editName': {
//				if (!(self.activePanel)) {
//					break;
//				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '이름 편집',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize title input box
						contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput">');
						$('#' + self.itemid + '_titleInput').dxTextBox({
//							text: $('#' + self.itemid + '_title').text()
//							text: self.Map['Name']
							text: self.Name
						});
					}
				});
				// change title and series names on '확인' click
				p.option('toolbarItems[0].options.onClick', function() {
					var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
					if(newName.trim() == '') {
						WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                    	$('#' + self.itemid + '_titleInput').dxTextBox('instance').option('value', self.Name);
                    } else {
                    	var text = $('#' + self.itemid + '_title').text();
                    	/* DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류 수정  20191223 */
                    	
//                    	var goldenLayout = gDashboard.goldenLayoutManager;
//                    	goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);
                    	
                    	var ele = $('#' + self.itemid + '_title');
                    	ele.attr( 'title', newName)
                        ele.find( '.lm_title' ).html(newName);

//    					$('#' + self.itemid + '_title').text(text.replace(self.Name,newName));
//    					$('#' + self.itemid + '_title').text(self.Map['Name']);
//    					 $(this).text(text.replace(self.Map['Name'], newName)); 
    					self.Map['Name'] = newName;
    					self.Name = self.Map['Name'];
    					p.hide();
                    }
				});
				// show popup
				p.show();
				break;
			}
			case 'loadMap': {
				$('#wrapper').append('<div id="loadMapPopup"></div>');
				var html = "";
				html += '<div class="modal-inner">';
				html += '	<div class="modal-body">';
				html += '		<div class="row">'
				html += '			<div class="column" style="width:100%;">';
				html += ' 				<div class="layout-row">';
				html += '					<form id="frm" name="frm" enctype="multipart/form-data" accept-charset="UTF-8">';
				html += '						<div class="layout-col">'
	            html += '           			     <div class="modal-article">';
	            html += '           			         <div id="shpButton" class="file-ui">'
	            html += '									<input id="shpInput" type="file" name=".shp" class="real-file" accept=".shp" hidden="hidden"/>';
	            html += '									<input type="button" class="btn positive crud custom-button" value="SHP파일 선택" style="float:left;display:inline-block;overflow:hidden;text-align:center;border-radius:5px;vertical-align:top;"/>';
	            html += '           	  		          	<span id="shpCaption" class="custom-text" style="width:150px">파일을 선택 해주세요.</span>';
	            html += '	        		            </div>';
	            html += '							</div>';
	            html += '  		   		     	</div>';
	            html += '     			     	<div class="layout-col">';
	            html += '							<div class="modal-article">';
	            html += '								<div id="dbfButton" class="file-ui">';
	            html += '									<input id="dbfInput" type="file" name=".dbf" class="real-file" accept=".dbf"  hidden="hidden"/>';
	            html += '									<input type="button" class="btn positive crud custom-button" value="DBF파일 선택" style="float:left;display:inline-block;overflow:hidden;text-align:center;border-radius:5px;vertical-align:top;"/>';
	            html += '									<span id="dbfCaption" class="custom-text"  style="width:150px">파일을 선택 해주세요.</span>';
	            html += '								</div>';
	            html += '							</div>';
	            html += '						</div>';
	            html += '					</form>';
	            html += '        		</div>';
	            html += '				<div class="modal-article mt20">';
	            html += '					<div id="popUpRedraw"></div>';
	            html += '					<div id="shpAttrPreview" class="line-area scrollbar h300 mt10"></div>';
	            html += '				</div>';
	            html += '			</div>';
	            html += '		</div>';
	            html += '	</div>';
	            html += '	<div class="modal-footer">';
				html += '		<div id="ActionArea" class="row center">';
				html += '			<a id="okButton" href="#" class="btn positive ok-hide">확인</a>';
				html += '			<a id="cancelButton" href="#" class="btn neutral close">취소</a>';
				html += '		</div>';
				html += '		<div id="ApplyArea" class="row center" style="display:none">';
				html += '		</div>';
				html += '	</div>';
				html += '</div>';
				$('#loadMapPopup').dxPopup({
					width:600,
					height:580,
					visible:true,
					title: "지도 불러오기",
					contentTemplate: function() {
		                return html;
		            },
		            onContentReady: function() {
		            	gDashboard.fontManager.setFontConfigForOption('loadMapPopup')
		            },
		            onShown:function(){
		            	$('#popUpRedraw').dxLookup({
 	                	   dataSource:[],
 	                	   onValueChanged:function(_e){
 	                		   self.attrName = _e.value;
 	                	   },
 	                	   onOptionChanged:function(_e){
	                		   if(_e.fullName == 'dataSource'){
	                			  $('#popUpRedraw').dxLookup('repaint');
	                		   }
	                	   },
 	                	   title:"속성 선택",
 	                	   searchEnabled: false,
 	                   	});
		            	$('#shpAttrPreview').dxDataGrid({
 	                	   dataSource : [],
 	                	   columnMinWidth: 80,
 	                	   onOptionChanged:function(_e){
 	                		   if(_e.fullName == 'dataSource'){
 	                			  $('#shpAttrPreview').dxDataGrid('refresh');
 	                		   }
 	                	   }
 	                   	});
		            	$('.file-ui').each(function(){
		                    var realFileBtn = $(this).find(".real-file");
		                    var customBtn = $(this).find(".custom-button");
		                    var customTxt = $(this).find(".custom-text");
		                    customBtn.on("click", function() {
		                        realFileBtn.click();
		                    });

		                    realFileBtn.on("change", function() {
		                        if (realFileBtn.val()) {
		                            customTxt.html(realFileBtn.val().match(
		                              /[\/\\]([\w\d\s\.\-\(\)]+)$/
		                            )[1])
		                        } else {
		                            customTxt.html("No file chosen, yet.");
		                        }
		                    });
		                });
//		            	$('#shpButton').on('click',function(){
//		            		$('#shpInput').click();
//		            	});
//		            	$('#dbfButton').on('click',function(){
//		            		$('#dbfInput').click(); 
//		            	});
		            	$('#okButton').dxButton({
		            		type: "success",
		            		onClick:function(){
		            			gProgressbar.show();
		            			
		            			var shpFile = document.getElementById('shpInput').files[0];
		            			var dbfFile = document.getElementById('dbfInput').files[0];
		            			if (shpFile) {
		            				self.shpFilemeta = shpFile;
		            				self.dbfFilemeta = dbfFile;
		            				setTimeout(self.convertGeoJson(shpFile,dbfFile),4000);
		                        }
		            		}
		            	});
		            	$('#cancelButton').dxButton({
		            		text: "취소",
		            		type: "danger",
		            		onClick:function(){
		            			$('#loadMapPopup').hide();
		            			$('#loadMapPopup').remove();
		            		}
		            	});
		            }
				});
				break;
			}
			case 'lockNavigation':{
				if (!(self.dxItem)) {
					break;
				}

				var wheelCheck = self.dxItem.option('panningEnabled');
				if(wheelCheck == true || typeof wheelCheck == 'undefined'){
					self.dxItem.option('panningEnabled',false);
					self.dxItem.option('zoomingEnabled',false);
					self.LockNavigation=false
				}else{
					self.dxItem.option('panningEnabled',true);
					self.dxItem.option('zoomingEnabled',true);
					self.LockNavigation=true
				}
				
				break;
			}
			case 'Showlegend':{
				if (!(self.dxItem)) {
					break;
				}
				if(self.meta.MapLegend.Visible == true){
					self.meta.MapLegend.Visible = false;
					self.dxItem.option('legends',[]);
				}
				else{
					self.meta.MapLegend.Visible = true;
					self.dxItem.option('legends',
							[
								{
									horizontalAlignment: "left",
									orientation: "vertical",
									source:
									{
										grouping: "color",
										layer: "areaLayer"
									},
									verticalAlignment: "top",
									font: gDashboard.fontManager.getDxItemLabelFont(),
									customizeText:function(_arg){
										/*dogfoot 지도 범례 표기 형식 변경 shlim 20200617*/
										return _arg.start + ' ~ ';
//										if(_arg.index == (areaLayer.palette.length-1)){
//											return _arg.start + ' ~ ';
//										}else{
//											return _arg.start + ' ~ ' + (_arg.end - 1);
//										}
									}
								}
							]
					);
				}
				break;
			}
			case 'setBackColor':{
				if (!(self.dxItem)) {
					break;
				}
				self.dxItem.option('background',{'borderColor': "white", 'color': "rgb(25,25,25)"});
				break;
			}
			case 'editPalette': {
				if (!(self.dxItem)) {
					break;
				}
				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office'];
				//2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 DOGFOOT
				var paletteCollection2 = ['밝음', '발광체', '바다', '파스텔', '부드러움', '연한 파스텔', '나무', '포도', 
					'단색', '우주', '진보라', '안개숲', '연파랑', '기본값', '사무실 테마'];
				var paletteObject = {
						'Bright':'밝음',
						'Harmony Light':'발광체',
						'Ocean':'바다',
						'Pastel':'파스텔',
						'Soft':'부드러움',
						'Soft Pastel':'연한 파스텔',
						'Vintage':'나무',
						'Violet':'포도',
						'Carmine':'단색',
						'Dark Moon':'우주',
						'Dark Violet':'진보라',
						'Green Mist':'안개숲',
						'Soft Blue':'연파랑',
						'Material':'기본값',
						'Office':'사무실 테마',
						'Custom':'사용자 정의 테마',
					};
				var paletteObject2 = {
					'밝음':'Bright',
					'발광체':'Harmony Light',
					'바다':'Ocean',
					'파스텔':'Pastel',
					'부드러움':'Soft',
					'연한 파스텔':'Soft Pastel',
					'나무':'Vintage',
					'포도':'Violet',
					'단색':'Carmine',
					'우주':'Dark Moon',
					'진보라':'Dark Violet',
					'안개숲':'Green Mist',
					'연파랑':'Soft Blue',
					'기본값':'Material',
					'사무실 테마':'Office',
					'사용자 정의 테마':'Custom',
				};
				
				if (self.meta.Maps.ValueMap[0].CustomPalette != undefined){  
					if(self.meta.Maps.ValueMap[0].CustomPalette.Color.length > 0) {
						paletteCollection.push('Custom');
						paletteCollection2.push('사용자 정의 테마');	
					}
				}
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chagePalette = self.Map.Palette;
				p.option({
                    target: '#editPalette',
                    onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // create html layout
                        var html = 	'<div id="' + self.itemid + '_paletteBox"></div>' +
								 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="save-ok" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="save-cancel" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        var select = $('#' + self.itemid + '_paletteBox');
                        // palette select
                        var originalPalette = paletteCollection.indexOf(self.Map.Palette) != -1
										? self.Map.Palette
										: 'Custom';
						select.dxSelectBox({
                            width: 400,
                            items: paletteCollection2,
                            itemTemplate: function(data) {
                                var html = $('<div />');
                                $('<p />').text(data).css({
                                    display: 'inline-block',
                                    float: 'left'
                                }).appendTo(html);
                                
                                var colorArray = [];
                                if(data === '사용자 정의 테마'){
                                	$.each(self.meta.Maps.ValueMap[0].CustomPalette.Color,function(_i,_color){
     									if(typeof _color == 'string' && _color.indexOf('#') > -1){
     										colorArray.push(_color.toUpperCase());	
     									}else{
     										colorArray.push(self.getHexColor(_color).toUpperCase());
     									}	
     								});
                                }
                                
                                var itemPalette = data === '사용자 정의 테마'
										? colorArray
										: DevExpress.viz.getPalette(paletteObject2[data]).simpleSet;
                                for (var i = 5; i >= 0; i--) {
                                    $('<div />').css({
                                        backgroundColor: itemPalette[i],
                                        height: 30,
                                        width: 30,
                                        display: 'inline-block',
                                        float: 'right'
                                    }).appendTo(html);
                                }
                                return html;
                            },
							value: paletteObject[originalPalette],
							onValueChanged: function(e) {
								if (e.value == '사용자 정의 테마') {
                                    self.isCustomPalette = true;
                                    var colorArray = [];
                                	$.each(self.meta.Maps.ValueMap[0].CustomPalette.Color,function(_i,_color){
     									if(typeof _color == 'string' && _color.indexOf('#') > -1){
     										colorArray.push(_color.toUpperCase());	
     									}else{
     										colorArray.push(self.getHexColor(_color).toUpperCase());
     									}	
     								});
                                    self.dxItem.option('layers[0].palette', colorArray);
								} else {
                                    self.isCustomPalette = false;
                                    self.dxItem.option('layers[0].palette',paletteObject2[e.value]);
                                    //self.dxItem.option('palette', paletteObject2[e.value]);
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.meta.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	if(self.meta.Palette == 'Custom'){
                        		var colorArray = [];
                            	$.each(self.meta.Maps.ValueMap[0].CustomPalette.Color,function(_i,_color){
 									if(typeof _color == 'string' && _color.indexOf('#') > -1){
 										colorArray.push(_color.toUpperCase());	
 									}else{
 										colorArray.push(self.getHexColor(_color).toUpperCase());
 									}	
 								});
                        		self.dxItem.option('layers[0].palette', colorArray);
                        	}else{
                        		self.dxItem.option('layers[0].palette', self.meta.Palette);
                        	}
                            chagePalette = self.meta.Palette;
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.meta.Palette = chagePalette;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
			// set custom colors
			case 'customPalette': {
				if (!(self.dxItem)) {
					break;
				}
					/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
				var html = '<div id="color_tabpanel" class="color_tabpanel" style="height: calc(100% - 45px);"></div>';
				html += "<div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
				"	<div class=\"row center\">\r\n" + 
				"		<a id=\"btn_tabpanel_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
				'		<a id="btn_tabpanel_close" href="#" class="btn neutral close">취소</a>' +
				"	</div>\r\n" + 
				"</div>\r\n";
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '색상 편집',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						contentElement.append(html);
						var customListCnt = [];
						var item =  [{ 'title' : '% 기준'}, {'title' : '값 기준'}];
						var tabPanel = $("#color_tabpanel").dxTabPanel({
					        height: 'calc(100% - 45px)',
					        selectedIndex: 0,
					        loop: false,
					        animationEnabled: false,
					        swipeEnabled: true,
					        items: item,
					        onContentReady: function(e) {
					        		$('.dx-multiview-item-content').attr('id', 'color_percent');
					        		//var contentColorElement = $('#color_percent');
			                        var colorContainer = $('.dx-multiview-item-content').attr('id', 'color_percent');
									self.valueRange['rangeStop'].forEach(function(range, index) {
										if(index < self.valueRange['rangeStop'].length-1){
											colorContainer.append('<p>' + self.valueRange['rangeStop'][index] + '% ~ ' + self.valueRange['rangeStop'][index+1] + '%</p><div id="' + self.activePanel + '_seriesColor' + index + '"></div>');	
										}else{
											colorContainer.append('<p>' + self.valueRange['rangeStop'][index] + '% ~</p><div id="' + self.activePanel + '_seriesColor' + index + '"></div>');
										}
									});
			                        colorContainer.dxScrollView({
			                            height: 600,
			                            width: '100%'
			                        })

//									contentElement.append(html);

                                    if(self.meta.Maps.ValueMap[0].CustomPalette != undefined && self.meta.Maps.ValueMap[0].CustomPalette.Color.length > 0){
										
										self.valueRange['rangeStop'].forEach(function(range, index) {
											/*dogfoot 지도 % 범위 팔레트 수정 shlim 20200617*/
											var colorArray = [];
											$.each(self.meta.Maps.ValueMap[0].CustomPalette.Color,function(_i,_color){
												if(typeof _color == 'string' && _color.indexOf('#') > -1){
													colorArray.push(_color.toUpperCase());	
												}else{
													colorArray.push(self.getHexColor(_color).toUpperCase());
												}	
											});
											/*dogfoot 지도 팔레트 사용자 지정 선택시 범위 초기화 shlim 20200617*/
											var colorValue;
                                            if(self.meta.Maps.ValueMap[0]['CustomColorSet']['CustomColorSetCheck'] == 'Y'){
                                                colorValue = '#1DB2F5'   
											}else{
											    colorValue = colorArray[index];   
											}
											$('#'+self.activePanel + '_seriesColor' + index).dxColorBox({
												value: colorValue
											});	 
											
										});	
									}else{
										self.valueRange['rangeStop'].forEach(function(range, index) {
											$('#'+self.activePanel + '_seriesColor' + index).dxColorBox({
												value: DevExpress.viz.getPalette().accentColor
											});
										});
									}
					        },
					        onSelectionChanged: function(e) {
					        	if($('.dx-multiview-item-content').eq(1).attr('id') == null) {
					        			//$('.dx-multiview-item-content').eq(1).attr('id', 'color_value');
                                        var colorContainer2 = $('.dx-multiview-item-content').eq(1).attr('id', 'color_value');
                                        /*dogfoot 지도 첫 사용자 지정 범위 수정 shlim 20200618*/
                                        if(typeof self.valueRange['customRangeStop'] == 'undefined'){
                                        	self.valueRange['customRangeStop'] = [];
                                        	if(typeof self.dxItem.option('layers[0].colorGroups') != 'undefined'){
                                        		self.dxItem.option('layers[0].colorGroups').forEach(function(range,index){
                                        			if(index != (self.dxItem.option('layers[0].colorGroups').length -1)){
                                        				self.valueRange['customRangeStop'].push(range)
                                        			}
                                        		})
                                        	}else{
                                        		self.valueRange['customRangeStop'] = self.valueRange['rangeStop'];	
                                        	}
                                        	
                                        }
                                        
                                        self.valueRange['customRangeStop'].forEach(function(range, index) {
	                                        /*dogfoot 지도 팔레트 UI 수정 shlim 20200617*/
                                        	var colorValueHtml = '<div id="' + self.activePanel + '_seriesDiv' + index + '" style="text-align:center; margin: 5px 0 5px 0;" >';
                                        	colorValueHtml += '<div id="' + self.activePanel + '_seriesColorInput' + index + '" ></div>' +
                                        	'<div id="' + self.activePanel + '_seriesColordefalut' + index + '" ></div>'+
                                        	'<div id="' + self.activePanel + '_seriesColordelete' + index + '" ></div>'+
                                        	'</div>'
											colorContainer2.append(colorValueHtml);
//                                        	colorContainer2.append('<p>'+(index +1)+'.</p><div id="' + self.activePanel + '_seriesColorInput' + index + '"></div><div id="' + self.activePanel + '_seriesColordefalut' + index + '"></div>');
											$('#'+self.activePanel + '_seriesColorInput' + index).css('display','inline-block');
											$('#'+self.activePanel + '_seriesColordefalut' + index).css('display','inline-block');
											$('#'+self.activePanel + '_seriesColordelete' + index).css('display','inline-block');

											$('#'+self.activePanel + '_seriesColorInput' + index).css('vertical-align','middle');
											$('#'+self.activePanel + '_seriesColordefalut' + index).css('vertical-align','middle');
											$('#'+self.activePanel + '_seriesColordelete' + index).css('vertical-align','middle');
											customListCnt.push(range);
										});

										var colorAddBtnHtml = '<div id="' + self.activePanel + '_seriesDiv" style="text-align:center">';
                                        	colorAddBtnHtml += '<div id="' + self.activePanel + '_seriesColoradd"></div>'+
                                        	'</div>'
                                        colorContainer2.append(colorAddBtnHtml);
                                        	
										colorContainer2.dxScrollView({
											height: 600,
											width: '100%'
										})
										
	//									contentElement.append(html);
										var colorArray = [];
										if(self.meta.Maps.ValueMap[0].CustomPalette != undefined && self.meta.Maps.ValueMap[0].CustomPalette.Color.length > 0){
											self.valueRange['customRangeStop'].forEach(function(range, index) {
												$.each(self.meta.Maps.ValueMap[0].CustomPalette.Color,function(_i,_color){
													if(typeof _color == 'string' && _color.indexOf('#') > -1){
														colorArray.push(_color.toUpperCase());	
													}else{
														colorArray.push(self.getHexColor(_color).toUpperCase());
													}	
												});
												
												$('#'+self.activePanel + '_seriesColorInput' + index).dxTextBox({
													value: self.valueRange['customRangeStop'][index],
													/*dogfoot 지도 사용자지정 팔레트 숫자만 입력,빈값입력시 초기화 수정 shlim 20200617*/
													width: '45%',
													onChange : function(e){
														if(e.component.option('value').trim() == ''){
															e.component.option('value',0);
														}else{
															e.component.option('value',e.component.option('value').replace(/[^0-9]/g,""));
														}
														
													}
												});	

												$('#'+self.activePanel + '_seriesColordefalut' + index).dxColorBox({
													value: colorArray[index],
													/*dogfoot 지도 사용자지정 팔레트 빈값입력시 초기화 수정 shlim 20200617*/
												    width: '45%',
												    onChange : function(e){
														if(e.component.option('value').trim() == ''){
															e.component.option('value','#EEEEFF');
														}
													}
												});
												
												$('#'+self.activePanel + '_seriesColordelete' + index).dxButton({
											        icon: "close",
											        type: "normal",
											        id: index,
											        onClick: function(e) { 
											            var deleteBtnIdx = e.component.option('id');
											            $('#'+self.activePanel+'_seriesDiv' + deleteBtnIdx).remove();
											            customListCnt[deleteBtnIdx] = "del";
											        },
											        width: '9%'
											        
											    });
											});	
										}else{
											self.valueRange['customRangeStop'].forEach(function(range, index) {
												/*dogfoot 지도 사용자지정 팔레트 빈값입력시 초기화 수정 shlim 20200617*/
												$('#'+self.activePanel + '_seriesColorInput' + index).dxTextBox({
													value: self.valueRange['customRangeStop'][index],
													width: '45%',
													onChange : function(e){
														if(e.component.option('value').trim() == ''){
															e.component.option('value',0);
														}else{
															e.component.option('value',e.component.option('value').replace(/[^0-9]/g,""));
														}
														
													}
												});
												
												$('#'+self.activePanel + '_seriesColordefalut' + index).dxColorBox({
													value: DevExpress.viz.getPalette().accentColor,
													width: '45%',
													onChange : function(e){
														if(e.component.option('value').trim() == ''){
															e.component.option('value','#EEEEFF');
														}
													}
												});

												$('#'+self.activePanel + '_seriesColordelete' + index).dxButton({
											        icon: "close",
											        type: "normal",
											        id: index,
											        onClick: function(e) { 
											            var deleteBtnIdx = e.component.option('id');
											            $('#'+self.activePanel+'_seriesDiv' + deleteBtnIdx).remove();
											            customListCnt[deleteBtnIdx] = "del";
											        },
											        width: '9%'
											    });
											});
										}
					        			$('#'+self.activePanel + '_seriesColoradd').dxButton({
											icon: "plus",
											width: '9%',
											onClick: function(e) { 
												var addLen = customListCnt.length;
												customListCnt.push('0');
												colorArray.push('#EEEEEE');
												/*dogfoot 지도 사용자지정 팔레트 UI 수정 shlim 20200617*/
												var colorAddHtml = '<div id="' + self.activePanel + '_seriesDiv' + addLen + '" style="text-align:center; margin: 5px 0 5px 0;" >';
												colorAddHtml += '<div id="' + self.activePanel + '_seriesColorInput' + addLen + '" ></div>' +
					                        	'<div id="' + self.activePanel + '_seriesColordefalut' + addLen + '" ></div>'+
					                        	'<div id="' + self.activePanel + '_seriesColordelete' + addLen + '" ></div>'+
					                        	'</div>';
												
												$('#'+self.activePanel + '_seriesColoradd').before(colorAddHtml);
												
												$('#'+self.activePanel + '_seriesColorInput' + addLen).dxTextBox({
													value: customListCnt[addLen],
													width: '45%',
													onChange : function(e){
														if(e.component.option('value').trim() == ''){
															e.component.option('value',0);
														}else{
															e.component.option('value',e.component.option('value').replace(/[^0-9]/g,""));
														}
														
													}
												});	

												
												$('#'+self.activePanel + '_seriesColordefalut' + addLen).dxColorBox({
													value: colorArray[addLen],
												    width: '45%',
												    onChange : function(e){
														if(e.component.option('value').trim() == ''){
															e.component.option('value','#EEEEFF');
														}
													}
												});
												
												$('#'+self.activePanel + '_seriesColordelete' + addLen).dxButton({
											        icon: "close",
											        type: "normal",
											        id: addLen,
											        onClick: function(e) { 
											            var deleteBtnIdx = e.component.option('id');
											            $('#'+self.activePanel+'_seriesDiv' + deleteBtnIdx).remove();
											            customListCnt[deleteBtnIdx] = "del";
											        },
											        width: '9%'
											        
											    });
												$('#'+self.activePanel + '_seriesColorInput' + addLen).css('display','inline-block');
												$('#'+self.activePanel + '_seriesColordefalut' + addLen).css('display','inline-block');
												$('#'+self.activePanel + '_seriesColordelete' + addLen).css('display','inline-block');

												$('#'+self.activePanel + '_seriesColorInput' + addLen).css('vertical-align','middle');
												$('#'+self.activePanel + '_seriesColordefalut' + addLen).css('vertical-align','middle');
												$('#'+self.activePanel + '_seriesColordelete' + addLen).css('vertical-align','middle');			
										    }

										});
					        	}
					        }
					    }).dxTabPanel("instance");
						
					    $("#btn_tabpanel_ok").dxButton({
							text: "확인",
							type: "normal",
							onClick: function(e) {
								var selectedTabVal = $("#color_tabpanel").dxTabPanel('instance').option('selectedIndex');
								if(typeof selectedTabVal != 'undefined' && selectedTabVal == '0'){
									var newPalette = [];
									self.valueRange['rangeStop'].forEach(function(range, index) {
										/*dogfoot 지정한 색이 바뀌는 오류 수정 shlim 20200617*/
										newPalette[index] = $('#' + self.activePanel + '_seriesColor' + index).dxColorBox('instance').option('value').toUpperCase();
									});

									var colorDecimalArray = [];
									$.each(newPalette, function(_i,_color){
										colorDecimalArray.push(self.hextoDec(_color));
									});
									self.Map['Palette'] = colorDecimalArray;

									self.meta.Maps.ValueMap.forEach(function(valueMap, index){
										valueMap['CustomScale'] = {'RangeStop':self.valueRange['rangeStop']};
										valueMap['CustomPalette'] = {'Color':self.Map['Palette']};
										valueMap['CustomColorSet'] = {'CustomColorSetCheck':'N'};
									});
									self.dxItem.option('layers[0].palette', newPalette);
	//	                            self.customPalette = newPalette;
									self.isCustomPalette = true;
								}else if (typeof selectedTabVal != 'undefined' && selectedTabVal == '1'){
									var newPalette = [];
									var colorInputArray = [];
									/*dogfoot 지정값에 영향없도록 변수 분리 shlim 20200617*/
									self.valueRange['customRangeStop'] = [];
									customListCnt.forEach(function(range, index) {
										if(range == "del"){

										}else{
											/*dogfoot 지정한 색이 바뀌는 오류 수정 shlim 20200617*/
										    newPalette.push($('#' + self.activePanel + '_seriesColordefalut' + index).dxColorBox('instance').option('value').toUpperCase());
										    colorInputArray.push(Number($('#' + self.activePanel + '_seriesColorInput' + index).dxTextBox('instance').option('value')));
										    self.valueRange['customRangeStop'].push(Number($('#' + self.activePanel + '_seriesColorInput' + index).dxTextBox('instance').option('value')));
										}
										
									});

									if(colorInputArray.length == 0){
                                        self.meta.Maps.ValueMap.forEach(function(valueMap, index){
											valueMap['CustomScale'] = {'RangeStop':self.valueRange['rangeStop']};
											valueMap['CustomPalette'] = {'Color':""};
											valueMap['CustomColorSet'] = {'CustomColorSetCheck':'N'};
										});
									}else{
										var colorDecimalArray = [];
										$.each(newPalette, function(_i,_color){
											colorDecimalArray.push(self.hextoDec(_color));
										});
										self.Map['Palette'] = colorDecimalArray;
										/*dogfoot 사용자정의 팔레트 범위 최대값 추가 shlim 20200617*/
										colorInputArray.push(self.CUSTOMIZED.get('rangeStopMaxValue'));
										self.meta.Maps.ValueMap.forEach(function(valueMap, index){
											valueMap['CustomScale'] = {'RangeStop':self.valueRange['customRangeStop']};
											valueMap['CustomPalette'] = {'Color':self.Map['Palette']};
											valueMap['CustomColorSet'] = {'CustomColorSetCheck':'Y'};
										});
										self.dxItem.option('layers[0].palette', newPalette);
										self.dxItem.option('layers[0].colorGroups', colorInputArray);
		//	                            self.customPalette = newPalette;
										self.isCustomPalette = true;
									}
									
								}
	                            
	                            p.hide();
							}
						});
					    $('#btn_tabpanel_close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
		}
	};
	this.convertGeoJson = function(shpFile,dbfFile){
		var shpreader = new FileReader();
		shpreader.onload = (function(that){
            return function(e){
            	gProgressbar.show();
            	self.shpFilemeta = e.target.result;
            	var dbfreader = new FileReader();
	        	dbfreader.onload = (function(that){
		            return function(e){
		            	self.dbfFilemeta = e.target.result;
		            	var parseSources = { shp: self.shpFilemeta, dbf: self.dbfFilemeta},
					    parseOptions = { precision: 2 }, 
					    data = DevExpress.viz.vectormaputils.parse(parseSources, parseOptions);
						var param = {'fileName':shpFile.name,'geojson':data};

						$.ajax({
                    	   cache: false,
          	               url: WISE.Constants.context + '/report/uploadGeoJSON.do',
          	               async:false,
          	               data: JSON.stringify(param),
          	               contentType: "application/json",
          	               type: 'POST',
          	               success: function(result){
//        	                   alert("geojson 업로드 성공!!");
        	                   var form = $('#frm')[0];
		            	       var formData = new FormData(form);
        	                   $.ajax({
	            	               cache: false,
	            	               url: WISE.Constants.context + '/report/uploadSHP.do',
	            	               async:false,
	            	               processData: false,
	            	               contentType: false,
	            	               data: formData,
	            	               type: 'POST',
	            	               success: function(result){
	            	                   gProgressbar.hide();
	            	                   var coulmnHead = new Array();
	            	                   
	            	                   $.each(data.features["0"].properties,function(_i,_field){
	            	                	   coulmnHead.push(_i);
	            	                   });
	            	                   $('#ActionArea').css('display','none');
	            	                   $('#popUpRedraw').dxLookup('instance').option('dataSource',coulmnHead);
	            	                   var featuresArray = [];
	            	                   $.each(data.features,function(_i,_features){
	            	                	   var obj = _features.properties;
	            	                	   featuresArray.push(obj);
	            	                   });
	            	                   $('#shpAttrPreview').dxDataGrid('instance').option('dataSource',featuresArray);
	            	                   $('#ApplyArea').css('display','block')
	            	                   $('#ApplyArea').append("<a id='applyOK' class='btn positive ok-hide' href='#'>적용</a>");
	            	                   $('#applyOK').dxButton({
							            	text: "확인",
						            		type: "default",
						            		onClick:function(){	
						            			if(self.attrName != ""){
						            				$('#loadMapPopup').dxPopup('hide');
						            				$('#loadMapPopup').remove();
						            				self.ShapefileArea = "Custom";
						            				
						            				self.ViewArea = {
						            					'BottomLatitude': data.bbox[1],
						            					'TopLatitude':  data.bbox[3],
						            					'LeftLongitude':  data.bbox[0],
						            					'RightLongitude':  data.bbox[2],
						            					'CenterPointLatitude': (data.bbox[1] + data.bbox[3])/2,
					            						'CenterPointLongitude': (data.bbox[0] + data.bbox[2])/2,
						            				};
						            			}
						            		}
	            	                   });
//	            	                   self.CustomUrl = true;
//	            	                   self.CustomUrl = {'Url': "http://localhost:8080/ds/UploadFiles/geojson/"+(shpFile.name).replace('.shp','.geojson')};
	            	                   self.CustomUrl =  {'Url': WISE.Constants.context+'/UploadFiles/geojson/'+(shpFile.name).replace('.shp','.geojson')};
	            	               },
	            	               error:function(error){
	            	            	   console.log(error);
	            	            	   WISE.alert('error'+ajax_error_message(error),'error');
	            	               }
	            	           });
        	               },
        	               error:function(error){
        	            	   console.log(error);
        	            	   WISE.alert('error'+ajax_error_message(error),'error');
        	               }
                       });
		            }
			    })(this);
	        	dbfreader.readAsArrayBuffer(dbfFile);
            }
	    })(this);
    	shpreader.readAsArrayBuffer(shpFile);
	}
};
WISE.libs.Dashboard.KakaoMap2FieldManager = function() {
	var self = this;
	
	this.initialized = false;
	this.alreadyFindOutMeta = false;
	
	//검색 - searchDisable
	this.searchDisable = false;
	//검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	//검색
	
	this.dataItemNo=0;
	
	this.meta;
	this.isChange = false; // 사용자가 필드를 변경했는지 여부 체크
	this.columnMeta = {}; // 쿼리된 모든 컬럼정보 저장
	this.isColumnChooser = false;
	
	this.all = [];
	this.values = [];
	this.arguments = [];
	this.series = [];
//	this.hide_column_list_dim = [];
//	this.hide_column_list_mea = [];
	
	this.tables = [];
	
	this.palette;
	this.CustomScale = {};
	this.CustomPalette =  {};
	/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
	this.CustomColorSet;
	
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
		this.arguments = [];
		this.series = [];
//		this.hide_column_list_dim = [];
//		this.hide_column_list_mea = [];
		this.meta = gDashboard.structure.ReportMasterInfo.dataSource;
		
		this.initialized = true;
	};
	
	this.setMetaTables = function(tables){
		this.meta.tables = tables;
	}
	
	this.setDataItemByField = function(_fieldlist){
		this.DataItems = {};
		self.DataItems['Dimension'] = [];
		self.DataItems['Measure'] = [];
		var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
		
		for(var i = 0; i < _fieldlist.length; i++){
			var dataFieldType = $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1);
//			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
			if(dataFieldType=='kakaoMap2ParameterList'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
//				dataItem['DataMember'] = $(_fieldlist[i]).children().get(0).innerText; 
//				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				if (self.seriesType === 'Bubble') {
					dataItem['ColoringMode'] = 'Hue';
				}
				self.DataItems['Dimension'].push(dataItem);
//			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
			} else if(dataFieldType=='kakaoMap2ValueList') {
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
//				dataItem['DataMember'] = $(_fieldlist[i]).children().get(0).innerText;
//				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
//				dataItem['NumericFormat'] = NumericFormat;
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = NumericFormat;
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};
	
	this.setValuesByField = function(_values){
		this.Values = {'ValueMap' : []};
		_.each(_values,function(_v){
			var Value = {'UniqueName' : _v.uniqueName};
			if(self.CustomScale.RangeStop != undefined){
				/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
				self.Values['ValueMap'].push({'Value':Value,'UniformScale': "",'CustomScale':self.CustomScale,'CustomPalette':self.CustomPalette,'CustomColorSet':self.CustomColorSet});				
			}else{
				self.Values['ValueMap'].push({'Value':Value,'UniformScale': ""});
			}
		});
		return self.Values;
	};
	
//	this.setSeriesDimensionsByField = function(_series){
//		this.SeriesDimensions = {'SeriesDimension' : []};
//		_.each(_series,function(_s){
//			var Value = {'UniqueName' : _s.uniqueName};
//			self.SeriesDimensions['SeriesDimension'].push(Value);
//		})
//		return self.SeriesDimensions;
//	};
	
	this.setArgumentsByField = function(_argument){
		this.attributeDimension = {};
//		_.each(_argument,function(_a){
			/*dogfoot 코로플레스 맵 안그려지는 오류 수정  shlim 20200612*/
			var Value = {'UniqueName' : _argument[0].uniqueName};
//			self.Arguments['Argument'].push(Value);
			self.attributeDimension = Value;
//		})
		return self.attributeDimension;
	};
};
