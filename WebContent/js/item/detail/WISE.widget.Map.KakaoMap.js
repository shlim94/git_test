WISE.libs.Dashboard.item.KakaoMapGenerator = function() {
	var self = this;
	
	this.type = 'KAKAO_MAP';
	
	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
    this.palette;
	this.fieldManager;
	
	this.measures = [];
	
	this.valueMaps = [];  // Maps-ValueMap node
	
	this.attributeDimension = {};
	this.tooltipMeasures = [];
	
	//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
	this.dataSetGroupByAddressType = {
		'sidoDataSet': {},
		'siGunGuDataSet': {},
		'eupMyeonDongDataSet': {}
	};
	
	//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
	this.SidoJson = {};
	this.SiGunGuJson = {};
	this.EupMyeonDongJson = {};
	
	 /* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 구분 id 설정 20201112 */
	this.polygonTextCount = 0;

	//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
	this.locationObject = {
		'locationSido' : {},
		'locationSiGunGu' : {},
		'locationEupMyeonDong' : {}
	};
	
	//2020.09.29 mksong 줌 레벨에 따른 addressType 동기화 dogfoot
	this.polygonList = [];
	this.polygons = {
		Sido : [],
		SiGunGu : [],
		EupMyeonDong : []
	};
	this.customOverlayList = [];
	
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
	
	//2020.11.05 MKSONG 데이터 타입 오류 수정 DOGFOOT
	this.Map = {};
	this.shpFilemeta;
	this.dbfFilemeta;
	//2020.11.19 syjin 리사이즈 함수 한번만 실행되도록 DOGFOOT
	this.resizeCheck = true;
	this.valueRange = {};
	
	this.CustomUrl = "";
//	this.CustomUrl = true;
	
	// custom pie palette
	//2020.10.19 mksong dogfoot 카카오지도 팔레트 편집
	this.customPalette = [];
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
	
	this.selectValue = 'kakao';
	
	//2020.09.29 syjin 카카오맵 이미지 변경 dogfoot
	this.markerImage = "https://t1.daumcdn.net/mapjsapi/images/marker.png";
	//this.markerImage = "https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png";
	//2020.09.29 syjin 카카오맵 마스터 필터 이미지 설정 dogfoot
	this.masterFilterImage = "data:image/png;base64,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";
	
	this.markers;
	this.markersInfo = new Array();

    //2020.09.29 syjin 카카오맵 마스터 필터 trackingData 추가 dogfoot
    this.trackingData = [];
	
	//2020.11.23 syjin dogfoot 마커 투명도 초기화
	this.initMarkerOpacity = function(){
		$.each(self.markers, function(m_i, m_v){
			m_v.setOpacity(1);
		})
	}

	//DOGFOOT syjin 2020-11-27 geojson 파일 스크립트로 처리
	//2020.11.20 mksong geojson 전역처리 dogfoot
	if(gDashboard.SidoJson == undefined){
		var locationTypeArray = ['Sido', 'SiGunGu', 'EupMyeonDong'];
		$.each(locationTypeArray, function(_i, _type){
			switch (_type){
				case 'Sido':
					jsonUrl = 'TL_SCCO_CTPRVN.json';
					break;
				case 'SiGunGu':
					jsonUrl = 'TL_SCCO_SIG.json';
					break;
				case 'EupMyeonDong':
					jsonUrl = 'EMD.zip.geojson';
					break;
			}
			
			$.ajax({
				url : WISE.Constants.context+'/resources/geoJson/'+ jsonUrl,
				type : 'get',
				//2020.11.19 syjin geojson 속도 개선 dogfoot
				//async: false,
				dataType:'json',
				success: function(data){
	                switch (_type){
						case 'Sido':
							gDashboard.SidoJson = data;
							break;
						case 'SiGunGu':
							gDashboard.SiGunGuJson = data;
							break;
						case 'EupMyeonDong':
							gDashboard.EupMyeonDongJson = data;
							break;
					}
				}
		    });
		});	
	}
	
//	gDashboard.SidoJson = WISE.sido;
//	gDashboard.SiGunGuJson = WISE.sigungu;
//	gDashboard.EupMyeonDongJson = WISE.eupmyeondong;
	
	this.sidoExceptCoordinateList = {
		'전라북도' : [0,2],
		'전라남도' : [33,34,35],
		'충청북도' : [],
		'충청남도' : [],
		'경기도' : [1],
		'서울특별시' : [],
		'광주광역시': [0]
	};
	
	this.siGunGuExceptCoordinateList = {
		//2020.11.17 mksong 카카오맵 시군구 시 포함하는 구 영역 오류 수정 dogfoot
		'경기도:안산시 단원구':[0,1],
		'해남군' : [2]
	};
	
	this.eupMyeonDongExceptCoordinateList = {
		
	};
	
	this.SidoCenterPath = {
		'서울특별시' : [126.979230045707, 37.5731222636304],
		'세종특별자치시' : [127.289195324698, 36.5990649113762],
		'인천광역시' : [126.52148773974, 37.4473487903571],
		'대전광역시' : [127.383789715873, 36.3554987200544],
		'대구광역시' : [128.606220516052, 35.8693892533552],
		'광주광역시' : [126.890107526298, 35.1523722691304],
		'부산광역시' : [129.07971968354, 35.176215249662],
		'울산광역시' : [129.330091790832, 35.5438097037164],
		'경기도' : [127.435089282738, 37.2772675901776],
		'강원도' : [128.498684130433, 37.6971673162731],
		'충청북도' : [127.690480041094, 36.9303218849121],
		'충청남도' : [126.80200021685, 36.5092146952303],
		'전라북도' : [127.119796025934, 35.8122369480273],
		'전라남도' : [127.079977043574, 34.9454607621149],
		'경상북도' : [128.697077816076, 36.3527164442425],
		'경상남도' : [128.261686482096, 35.3222352197819],
		'제주특별자치도' : [126.55956346911, 33.35406462955037]
	}
	
	//2020.11.17 mksong 카카오맵 시군구 시 포함하는 구 영역 오류 수정 dogfoot
	this.siGunGuIntegrationCodeList = [];

	this.exceptCoordinateCheck = function(_locationType, _key, _index){
		var check = false;
		switch(_locationType){
			case 'Sido':
				if(self.sidoExceptCoordinateList[_key] != undefined){
					if(self.sidoExceptCoordinateList[_key].indexOf(_index) != -1){
						check = true;
					}					
				} 
				break;
			case 'SiGunGu': 
				if(self.siGunGuExceptCoordinateList[_key] != undefined){
					if(self.siGunGuExceptCoordinateList[_key].indexOf(_index) != -1){
						check = true;
					}					
				} 
				break;
			case 'EupMyeonDong': 
				if(self.eupMyeonDongExceptCoordinateList[_key] != undefined){
					if(self.eupMyeonDongExceptCoordinateList[_key].indexOf(_index) != -1){
						check = true;
					}					
				}
				break;			
		}
		return check;
	};
	
	this.customOverlay = [];
	this.setCustomOverlay = function(customOverlay, map, flag){
		if(flag){					
			//2020.11.24 syjin dogfoot 툴팁 클릭시 한 화면에 나오도록 수정
			var position = customOverlay.getPosition();
			var lat =position.getLat();
			var lng = position.getLng();
			var moveLatLon;
			self.beforClickTooltipCenter = self.map.getCenter();
            
            if(self.Map.ShowPointType == 'polygon'){
                switch(self.map.getLevel()){
            		case 13:
            		    lat += 1.5;
            		break;

            		case 12:
            		    lat += 0.8;
            		break;

            		case 11:
            		    lat += 0.42;
            		break;

            		case 10:
            		    lat += 0.2;
            		break;

            		case 9:
            		    lat += 0.1;
            		break;

            		case 8:
            		    lat += 0.05;
                    break;

            		case 7:
            		    lat += 0.025;
            		break;

            		case 6:
            		    lat += 0.015;
            		break;
            		
                    case 5:
                        lat += 0.009;
                    break;

                    default:
                        lat += 0.0005;
                    break;
            	}  
            }else{
            	switch(self.map.getLevel()){
            		case 13:
            		    lat += 1.5;
            		break;

            		case 12:
            		    lat += 0.8;
            		break;

            		case 11:
            		    lat += 0.42;
            		break;

            		case 10:
            		    lat += 0.2;
            		break;

            		case 9:
            		    lat += 0.1;
            		break;

            		case 8:
            		    lat += 0.05;
                    break;

            		case 7:
            		    lat += 0.025;
            		break;

            		case 6:
            		    lat += 0.015;
            		break;
            		
                    case 5:
                        lat += 0.009;
                    break;

                    default:
                        lat += 0.0005;
                    break;
            	}
            }

			moveLatLon = new kakao.maps.LatLng(lat, lng);
			
			//DOGFOOT syjin 2020-11-27 툴팁 표시 시 폴리곤 load 오류 수정
			if(self.Map.ShowPointType == 'marker'){
				self.map.panTo(moveLatLon);	
			}else{	
				self.drawByChanged();
				self.map.setCenter(moveLatLon);	
			}
			
			customOverlay.setMap(map);
		}
	}
	
	
	this. clickMarkerMasterFilter = function(marker, _info){

		/* DOGFOOT syjin 마스터 필터 선택 체크 여부 20201019*/
		var markerMasterFilterCheck = self.markersInfo[marker.index-1]['masterFilterSelected'];

		if(self.meta.LocationType == 'address'){
			if (self.IO && self.IO.MasterFilterMode !== 'Off') {
				//2020.11.27 mksong 마스터필터 마커 수정 dogfoot
				var locationFullName = _info.address[0];
				switch(self.IO.MasterFilterMode){
					case 'Multiple':
						if(markerMasterFilterCheck){
							//var markerImage = new kakao.maps.MarkerImage('https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png', new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));			
							var markerImage = new kakao.maps.MarkerImage("https://t1.daumcdn.net/mapjsapi/images/marker.png", new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));
							$.each(self.markersInfo, function(mi_i, mi_v){
								if(_info['address'][0] == mi_v['address'][0]){
									self.markers[mi_i].setImage(markerImage); 

									mi_v['masterFilterSelected'] = false;
									_info['masterFilterSelected'] = false;
								}
							})	

							var start = _info['start'];
							var end = _info['end'];

							for(var i=start; i<end; i++){
								delete self.trackingData[i];
							}                                                     

						}else{
							//2020.11.26 syjin dogfoot 마커 마스터 필터 이미지 변경
							var markerImage = new kakao.maps.MarkerImage("data:image/png;base64,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",
									new kakao.maps.Size(43, 47),
									new kakao.maps.Point(13, 34)
							);
							$.each(self.markersInfo, function(mi_i, mi_v){
								if(_info['address'][0] == mi_v['address'][0]){
									self.markers[mi_i].setImage(markerImage);


									mi_v['masterFilterSelected'] = true;
									_info['masterFilterSelected'] = true;
								}
							})
 							
							if(self.trackingData.length == 0){
								var md = _.cloneDeep(_info['markerDimensions']);
								
								//2020.11.27 mksong 마스터필터 마커 수정 dogfoot
								if(self.IO.TargetDimensions == 'Address'){
									var trackingKey;
									$.each(self.addresses, function(d_i, d_v){
										trackingKey = d_v['name'];
		                            });
		
									var trackingDataObject = {};
									trackingDataObject[trackingKey] = 'LIKEDATA:' + locationFullName.replace(':',' '); 
		                        	self.trackingData.push(trackingDataObject);
								}else{
									self.trackingData = md;
								}
								
								_info['start'] = 0;
								_info['end'] = self.trackingData.length;
							}
							else{                                     
								_info['start'] = self.trackingData.length;
								
								//2020.11.27 mksong 마스터필터 마커 수정 dogfoot
								if(self.IO.TargetDimensions == 'Address'){
									var trackingKey;
									$.each(self.addresses, function(d_i, d_v){
										trackingKey = d_v['name'];
		                            });
		
									var trackingDataObject = {};
									trackingDataObject[trackingKey] = 'LIKEDATA:' + locationFullName.replace(':',' '); 
		                        	self.trackingData.push(trackingDataObject);
								}else{
									$.each(_info['markerDimensions'], function(md_i, md_v){
										self.trackingData.push(md_v);
									});
								}
								_info['end'] = self.trackingData.length;
							}
						}
						break;

					case 'Single':
						/* DOGFOOT syjin 카카오 지도 마커 마스터 필터 선택 여부 분기 처리  20200925 */
						if(markerMasterFilterCheck){
							self.trackingData = [];

							var markerImage = new kakao.maps.MarkerImage(self.markerImage, new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));

							$.each(self.markersInfo, function(mi_i, mi_v){
								mi_v['masterFilterSelected'] = false;
								self.markers[mi_i].setImage(markerImage);
							})
						}else{
							$.each(self.markersInfo, function(mi_i, mi_v){
								if(_info['address'][0] == mi_v['address'][0]){
									mi_v['masterFilterSelected'] = true;
									
									//2020.11.26 syjin dogfoot 마커 마스터 필터 이미지 변경
									var markerImage = new kakao.maps.MarkerImage("data:image/png;base64,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",
											new kakao.maps.Size(43, 47),
											new kakao.maps.Point(13, 34)
									);
									self.markers[mi_i].setImage(markerImage);
								}else{
									mi_v['masterFilterSelected'] = false;

									//2020.10.05 syjin 카카오맵 마커 이미지 초기화 수정 dogfoot
									var markerInfoImage = self.markersInfo[mi_i]['image'];

									var markerImage = new kakao.maps.MarkerImage(markerInfoImage, new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));
									self.markers[mi_i].setImage(markerImage);
								}
							})

							//2020.11.27 mksong 마스터필터 마커 수정 dogfoot
							if(self.IO.TargetDimensions == 'Address'){
								var trackingKey;
								self.trackingData = [];
								
								$.each(self.addresses, function(d_i, d_v){
									trackingKey = d_v['name'];
	                            });
	
								var trackingDataObject = {};
								trackingDataObject[trackingKey] = 'LIKEDATA:' + locationFullName.replace(':',' '); 
	                        	self.trackingData.push(trackingDataObject);
							}else{
								self.trackingData = _info['markerDimensions'];
							}
						}

						break;
				}
			}
		}else{
			if (self.IO && self.IO.MasterFilterMode !== 'Off') {
				switch(self.IO.MasterFilterMode){
					case 'Multiple':
						if(markerMasterFilterCheck){
							//var markerImage = new kakao.maps.MarkerImage('https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png', new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));
							var markerImage = new kakao.maps.MarkerImage("https://t1.daumcdn.net/mapjsapi/images/marker.png", new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));

							self.markers[_info['index']].setImage(markerImage);

							var start = _info['start'];
							var end = _info['end'];

							for(var i=start; i<end; i++){
								delete self.trackingData[i];
							} 

							self.markersInfo[_info['index']]['masterFilterSelected'] = false;
							_info['masterFilterSelected'] = false;
						}else{
							//2020.11.26 syjin dogfoot 마커 마스터 필터 이미지 변경
							var markerImage = new kakao.maps.MarkerImage("data:image/png;base64,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",
									new kakao.maps.Size(43, 47),
									new kakao.maps.Point(13, 34)
							);
							self.markers[_info['index']].setImage(markerImage);

							_info['start'] = self.trackingData.length;

							//2020.11.27 mksong 마스터필터 마커 수정 dogfoot
							if(self.IO.TargetDimensions == 'Address'){
								var latitudeKey = self.latitudes[0].caption;
								var longitudeKey = self.longitudes[0].caption;
								
								var latitudeTrackingDataObject = {};
								latitudeTrackingDataObject[latitudeKey] = 'LIKEDATA:' + _info.latitude;
								var longitudeTrackingDataObject = {};
								longitudeTrackingDataObject[longitudeKey] = 'LIKEDATA:' + _info.longitude; 
	                        	self.trackingData.push(latitudeTrackingDataObject);
								self.trackingData.push(longitudeTrackingDataObject);
							}else{
								$.each(_info['markerDimensions'], function(_i, _v){
									self.trackingData.push(_v);
								});
							}

							_info['end'] = self.trackingData.length;

							self.markersInfo[_info['index']]['masterFilterSelected'] = true;
							_info['masterFilterSelected'] = true;
						}
						break;

					case 'Single':
						if(markerMasterFilterCheck){
							self.trackingData = [];

							var markerImage = new kakao.maps.MarkerImage(self.markerImage, new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));

							$.each(self.markersInfo, function(mi_i, mi_v){
								mi_v['masterFilterSelected'] = false;
								self.markers[mi_i].setImage(markerImage);
							})
						}else{
							self.trackingData = [];

							$.each(self.markersInfo, function(mi_i, mi_v){
								if(_info['index'] == mi_i){
									mi_v['masterFilterSelected'] = true;
									
									//2020.11.26 syjin dogfoot 마커 마스터 필터 이미지 변경
									var markerImage = new kakao.maps.MarkerImage("data:image/png;base64,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",
											new kakao.maps.Size(43, 47),
											new kakao.maps.Point(13, 34)
									);
									self.markers[mi_i].setImage(markerImage);
								}else{
									mi_v['masterFilterSelected'] = false;

									//2020.10.05 syjin 카카오맵 마커 이미지 초기화 수정 dogfoot
									var markerInfoImage = self.markersInfo[mi_i]['image'];

									var markerImage = new kakao.maps.MarkerImage(markerInfoImage, new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));
									self.markers[mi_i].setImage(markerImage);
								}
							})

							//2020.11.27 mksong 마스터필터 마커 수정 dogfoot
							if(self.IO.TargetDimensions == 'Address'){
								self.trackingData = [];
								
								var latitudeKey = self.latitudes[0].caption;
								var longitudeKey = self.longitudes[0].caption;
								
								var latitudeTrackingDataObject = {};
								latitudeTrackingDataObject[latitudeKey] = 'LIKEDATA:' + _info.latitude;
								var longitudeTrackingDataObject = {};
								longitudeTrackingDataObject[longitudeKey] = 'LIKEDATA:' + _info.longitude; 
	                        	self.trackingData.push(latitudeTrackingDataObject);
								self.trackingData.push(longitudeTrackingDataObject);
							}else{
								$.each(_info['markerDimensions'], function(_i, _v){
									self.trackingData.push(_v);
								});
							}
					   }
				}
			}
		}

		var trackingData = self.trackingData.filter(function(item) {
		  return item !== null && item !== undefined && item !== '';
		})

		//최종적으로 filterData 호출
		if (self.IO && self.IO.MasterFilterMode !== 'Off') {
			//2020.11.12 MKSONG 카카오맵 마스터필터 취소 오류 수정 DOGFOOT
			if(self.trackingData != '' || self.trackingData.length==0 || trackingData.length == 0){
				gDashboard.filterData(self.itemid, trackingData);
			}
		}								
	}
	
	this.polygonMfList = [];
	
	//2020.11.20 mksong 카카오맵 colorindex 추가 dogfoot
	this.getColorIndex = function(_locationFullName){
		var index = 0;
		var locationObject;
		switch(self.stateAddressType){
			case 'Sido':
				locationObject = self.locationObject.locationSido;
				break;
			case 'SiGunGu':
				locationObject = self.locationObject.locationSiGunGu;
				break;
			case 'EupMyeonDong':
				locationObject = self.locationObject.locationEupMyeonDong;
				break;
		}
		
		$.each(locationObject,function(_key, _locationData){
			if(_key.indexOf('total') == -1){
				index++;
				if(_key == _locationFullName){
					return false;
				}	
			}
		});
		return index;
	};
	
	this.getPolygonLength = function(){		
		//2020.11.02 syjin 카카오맵 selectBox 반응형 처리 dogfoot
        
        /*dogfoot 카카오맵 뷰어 불러오기 오류 수정 syjin 20201106*/
        var stateAddressType; 
            if($("#"+self.ComponentName+"addressSelectLabel").dxSelectBox('instance') == undefined){
                stateAddressType = self.dimensions[0]['name'].substr(self.dimensions[0]['name'].indexOf("(")+1, self.dimensions[0]['name'].length-4);
            }else{
                stateAddressType= $("#"+self.ComponentName+"addressSelectLabel").dxSelectBox('instance').option('value');
            }

        var sidoLength = 0;
        var siGunGuLength = 0;
        var eupMyeonDongLength = 0;
        var lengthObj = {};

        $.each(self.polygons, function(_i, _v){
            switch(_i){
                case 'Sido':
                    sidoLength = Object.keys(self.dataSetGroupByAddressType.sidoDataSet).length;
                    if(stateAddressType != '시도'){
                        sidoLength /= 2;
                    }
                break;

                case 'SiGunGu':
                    siGunGuLength = Object.keys(self.dataSetGroupByAddressType.siGunGuDataSet).length;
                    if(stateAddressType == '시도+시군구+읍면동'){
                        siGunGuLength /= 2;
                    }
                break;

                case 'EupMyeonDong':
                    eupMyeonDongLength = Object.keys(self.dataSetGroupByAddressType.eupMyeonDongDataSet).length;
                break;
            }
        })
        
        lengthObj['Sido'] = sidoLength;
        lengthObj['SiGunGu'] = siGunGuLength;
        lengthObj['EupMyeonDong'] = eupMyeonDongLength;
        
        return lengthObj;    
    }
	
	 //2020.11.03 syjin 카카오맵 조회 시 이미지 범례 표시 함수화 dogfoot
	this.displayImageLegend = function(_value){
		if(_value){
			$("#imageCategory"+self.itemid).css("display","");
			var imageLegendSet = new Set();

			$.each(self.markersInfo, function(_i, _v){
				imageLegendSet.add(_v['image']);
			});

			//var imageLegendArray = [...imageLegendSet];
			//2020.11.13 syjin 카카오맵 Set을 Array로 변환 IE 지원 수정 dogfoot
			var imageLegendArray = Array.from(imageLegendSet);

			var legendList = "";

			for(var i=0; i<imageLegendArray.length; i++){
				legendList += 
					 '<li class="imageLegend" style="padding:10px; background-color:#ffffff;">' +
						 '<img src="' + imageLegendArray[i] +'" style="width:29px; height:42px;"/>' +
					 '</li>'; 
			}

			var allSelection = 
				'<li id="imageLegendAll'+self.itemid+'" style="padding:10px; background-color:#8173ed;">' +
					'<span style="width:29px; height:42px; font-weight:bolder; color:#ffffff;">전체<br>선택</span>';
				'</li>';
			/* DOGFOOT syjin 이미지 범례에 마커 즐겨찾기 추가 20201015 */
			var favoriteSelection =
				'<li id="imageLegendFavorite'+self.itemid+'" style="padding:10px; background-color:#ffffff;">' +
					'<img style="width:29px; height:42px;" src="data:image/png;base64,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"/>';
				'</li>';

			$("#imageLegendContainer"+self.itemid).children().remove();
			$("#imageLegendContainer"+self.itemid).append(legendList);
			$("#imageLegendContainer"+self.itemid).append(favoriteSelection);
			$("#imageLegendContainer"+self.itemid).append(allSelection);

			//image legend click event
			$("#imageLegendContainer"+self.itemid+" .imageLegend").click(function(e){
				//2020.11.10 syjin 이미지 범례 가장자리 클릭 시 오류 수정 dogfoot
				var clickImage = e.target.tagName=='LI'?e.target.firstElementChild.src:e.target.src;
				var newMarkers = new Array();
				//2020.12.07 syjin 마커 이미지 범례 클릭시 값에 따른 마커표시 오류
                var valueMin = self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMin;
                var valueMax = self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMax;

				self.clusterer.clear();

				var copyMarkers = _.cloneDeep(self.markers);

				for(var i=0; i<self.markersInfo.length; i++){
					if(clickImage == self.markersInfo[i]['image']){
						//2020.12.07 syjin 마커 이미지 범례 클릭시 값에 따른 마커표시 오류
                        if(self.markerEditOptions[self.Map.LocationType].valueMarkerCheck){
                            if((self.markersInfo[i].value >= valueMin) && (self.markersInfo[i].value <= valueMax)){
                            	copyMarkers[i].setMap(self.map);
						        newMarkers.push(copyMarkers[i]);
                            }
                        }else{
                        	copyMarkers[i].setMap(self.map);
						    newMarkers.push(copyMarkers[i]);
                        }						
					}else{
						copyMarkers[i].setMap(null);
					}
				}

				self.clusterer.addMarkers(newMarkers);
                
                //2020.11.10 syjin 이미지 범례 가장자리 클릭 시 오류 수정 dogfoot
				e.target.tagName=='LI'?$(e.target).css("background-color", "#8173ed"):$(e.target).parent().css("background-color", "#8173ed");
				e.target.tagName=='LI'?$(e.target).siblings().css("background-color", "#ffffff"):$(e.target).parent().siblings().css("background-color", "#ffffff");
				//$(e.target).parent().siblings("li[id=imageLegendAll]").children()[0].style['color']="#000000"
				//2020.11.10 syjin 이미지 범례 전체선택 폰트 색상 오류 수정 dogfoot
				$("#imageLegendAll"+self.itemid).find("span").css('color', '#000000');
			});

			//image legend allSelection click event
			$("#imageLegendAll"+self.itemid).click(function(e){
				var newMarkers = new Array();

				self.clusterer.clear();

				for(var i=0; i<self.markersInfo.length; i++){
					//2020.12.07 syjin 마커 이미지 범례 클릭시 값에 따른 마커표시 오류
					if(self.markerEditOptions[self.Map.LocationType].valueMarkerCheck){
                        var max = self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMax;
                        var min = self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMin;

                        if((self.markersInfo[i].value >= min) && (self.markersInfo[i].value <= max)){
                            self.markers[i].setMap(self.map);
						    newMarkers.push(self.markers[i]);	
                        }
					}else{
						self.markers[i].setMap(self.map);
						newMarkers.push(self.markers[i]);
					}
				}

				self.clusterer.addMarkers(newMarkers);
                
                //2020.11.10 syjin 이미지 범례 가장자리 클릭 시 오류 수정 dogfoot
				$("#imageLegendAll"+self.itemid).css("background-color", "#8173ed");
				$("#imageLegendAll"+self.itemid).siblings().css("background-color", "#ffffff");
				//2020.11.10 syjin 이미지 범례 전체선택 폰트 색상 오류 수정 dogfoot
				$("#imageLegendAll"+self.itemid).find("span").css("color", "#ffffff");
			});

			$("#imageLegendFavorite"+self.itemid).click(function(e){
				var newMarkers = new Array();

				self.clusterer.clear();
                
                //2020.12.07 syjin 마커 이미지 범례 클릭시 값에 따른 마커표시 오류
				for(var i=0; i<self.markersInfo.length; i++){
					if(self.markerEditOptions[self.Map.LocationType].valueMarkerCheck){
                        var max = self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMax;
                        var min = self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMin;

                        if((self.markersInfo[i].value >= min) && (max >= self.markersInfo[i].value)){
                        	if(self.markersInfo[i]['favorite']){
								self.markers[i].setMap(self.map);
								newMarkers.push(self.markers[i]);
							}
                        }
					}else{
						if(self.markersInfo[i]['favorite']){
							self.markers[i].setMap(self.map);
							newMarkers.push(self.markers[i]);
						}
					}
				}

				self.clusterer.addMarkers(newMarkers);
                
                //2020.11.10 syjin 이미지 범례 가장자리 클릭 시 오류 수정 dogfoot
				$("#imageLegendFavorite"+self.itemid).css("background-color", "#8173ed");
				$("#imageLegendFavorite"+self.itemid).siblings().css("background-color", "#ffffff");
				//2020.11.10 syjin 이미지 범례 전체선택 폰트 색상 오류 수정 dogfoot
				$("#imageLegendAll"+self.itemid).find("span").css('color', '#000000');
			})
		}else{
			$("#imageCategory"+self.itemid).css("display","none");
		}
	}

	//2020.11.03 syjin 카카오맵 값에 따른 마커 표시 함수처리 dogfoot
	this.setMarkerValue = function(){
		if(self.markerEditOptions[self.Map.LocationType].valueMarkerCheck){
			if(self.clusterer!=undefined){
			    self.clusterer.clear();
			}
			$.each(self.markersInfo, function(mi_i, mi_v){							
				if(self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMin <= mi_v['value'] && self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMax >= mi_v['value']){
					self.markers[mi_i].setMap(self.map);
					if(self.clusterer!=undefined){
					    self.clusterer.addMarker(self.markers[mi_i]);		
					}				
				}else{
					self.markers[mi_i].setMap(null);
				}
			})
		}else{
			if(self.clusterer!=undefined){
			    self.clusterer.clear();
			}
			$.each(self.markersInfo, function(mi_i, mi_v){														
				self.markers[mi_i].setMap(self.map);
				if(self.clusterer!=undefined){
				    self.clusterer.addMarker(self.markers[mi_i]);			
				}
			})
		}
	}
    
    this.initClusterImage = function(){
    	var markerImage = 
			new kakao.maps.MarkerImage("https://t1.daumcdn.net/mapjsapi/images/marker.png", 
			new kakao.maps.Size(31, 35), 
			new kakao.maps.Point(13, 34)
		);

    	$.each(self.markers, function(m_i, m_v){
    	    m_v.setImage(markerImage);													
    	})
    }

	this.setBgColor = function(){
		$.each(self.polygons, function(_i, _v){
        	var fillColor;                  
        	//2020.11.02 syjin 카카오맵 selectBox 반응형 처리 dogfoot
            var stateAddressType = $("#"+self.ComponentName+"addressSelectLabel").dxSelectBox('instance').option('value')
            var length;
            var bgColor = [];

            switch(stateAddressType){
            	case '시도' :
            	stateAddressType = 'sidoDataSet';
            	break;

            	case '시도+시군구' :
            	stateAddressType = 'siGunGuDataSet';
            	break;

            	case '시도+시군구+읍면동' :
            	stateAddressType = 'eupMyeonDongDataSet';
            	break;
            }

        	switch(_i){
        		case 'Sido':
        		fillColor = '#CFE7FF';
        		length = Object.keys(self.dataSetGroupByAddressType.sidoDataSet).length;

        		if(stateAddressType != 'sidoDataSet'){
        			length -= 1;
        		}
        		break;

        		case 'SiGunGu':
        		fillColor = '#FF99FF';
        		length = Object.keys(self.dataSetGroupByAddressType.siGunGuDataSet).length;

        		if(stateAddressType == 'eupMyeonDongDataSet'){
        			length -= 1;
        		}
        		break;

        		case 'EupMyeonDong':
        		fillColor = '#A2FF99';
        		length = Object.keys(self.dataSetGroupByAddressType.eupMyeonDongDataSet).length;
        		break;
        	}
            
            if(_v.length != 0){
            	//2020.11.04 mksong 카카오맵 length 오류 수정 dogfoot
				for(var i=0; i < _v.length; i++){
				  	//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
					if(_v[i].fillColor != fillColor){
                        if((bgColor.indexOf(_v[i].fillColor)) < 0){
                        	bgColor.push(_v[i].fillColor);
                        }
					}
				}
            }
            $.each(bgColor, function(bc_i, bc_v){
            	var bgColorObject = {
					bgColor : '',
					listName : []
				};
				bgColorObject['bgColor'] = bc_v;

                $.each(self.polygons[_i], function(pl_i, pl_v){    
                	//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
            		if(bc_v == pl_v.fillColor){
            			bgColorObject['listName'].push(pl_v.locationFullName);
            		}
            		if(pl_i == length-1){
            			return false;
            		}
            	})
                
            	 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
            	if(self.polygonEditOptions.polygonBgColorOptions[_i].indexOf(bgColorObject) == -1){
                	self.polygonEditOptions.polygonBgColorOptions[_i].push(bgColorObject);
                }
            	
            })
        })
	}
	
	/* DOGFOOT syjin 카카오 지도 폴리곤 테두리 초기화 20201030 */
	this.polygonLineInit = function(){
		$.each(self.polygons, function(p_i, p_v){
			//마우스 오버 이벤트 제거 , 추가, 테두리 변경
			$.each(p_v, function(pv_i, pv_v){
				//pv_v['m']['mouseout'] = [];
				//pv_v['m']['mouseover'] = [];
				/* DOGFOOT syjin 카카오 지도 마우스 오버, 아웃 리스너 제거 20201111 */
				kakao.maps.event.removeListener(pv_v, 'mouseout', pv_v.mouseout);
				kakao.maps.event.removeListener(pv_v, 'mouseover', pv_v.mouseover);
                //2020.11.12 syjin 폴리곤 텍스트 이벤트 삭제 dogfoot
                $(pv_v.textCustom).off();
                
				self.mouseListner(pv_v, 'mouseover', pv_v['mouseover']);
				self.mouseListner(pv_v, 'mouseout', pv_v['mouseout']);
                //2020.11.12 syjin 폴리곤 텍스트 이벤트 추가 dogfoot
                $(pv_v.textCustom).on('mouseover', pv_v['mouseover']);
                $(pv_v.textCustom).on('mouseout', pv_v['mouseout']);
                 //2020.11.18 syjin 폴리곤 마스터 필터 시 텍스트 이벤트 사라지는 오류 수정 dogfoot
                $(pv_v.textCustom).on('click', pv_v['mouseclick']);
                                
				pv_v.setOptions({
					strokeWeight : 1,
					//2020.11.20 MKSONG 카카오맵 마스터필터 해제 오류 수정 DOGFOOT
					strokeStyle : 'solid',
					fillColor : pv_v.fillColor
				})
			})
		})
	}

	//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
	this.checkPolygonInArea = function(_coordinateArray){
		var stateBounds = self.map.getBounds();
		var east = stateBounds.getNorthEast()[_.keys(stateBounds.getNorthEast())[0]];
		var north = stateBounds.getNorthEast()[_.keys(stateBounds.getNorthEast())[1]];
		var west = stateBounds.getSouthWest()[_.keys(stateBounds.getSouthWest())[0]];
		var south = stateBounds.getSouthWest()[_.keys(stateBounds.getSouthWest())[1]];  
		
		var boundLimit = [north, east, south, west];
		
		var drawPolygonPossible = false;
		$.each(_coordinateArray, function(_i, _coordinate){
			if(_coordinate[1] < boundLimit[0] && _coordinate[1] > boundLimit[2] && _coordinate[0] < boundLimit[1] && _coordinate[0] > boundLimit[3]){
				drawPolygonPossible = true;
				return false;
			}
		});
		return drawPolygonPossible;
	};

	//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
	this.initializeCustomOverlay = function(){
		$.each(self.customOverlay, function(_i, _v){
			_v["customOverlay"].setMap(null);						
		})

		self.customOverlay = [];
	}
                
	this.initializePolygonList = function(){
		$.each(self.polygons,function(_key,_locationPolygonList){
			$.each(_locationPolygonList, function(_i,_polygon){
				_polygon.setMap(null);
			});
			
			//2020.10.28 mksong 폴리곤 리스트 초기화 dogfoot
			_locationPolygonList = [];
		});
		
		//2020.10.28 mksong customOverlay 제거 dogfoot
		$.each(self.customOverlayList,function(_i,_customOverlay){
			_customOverlay.setMap(null);
		});
		
		self.customOverlayList = [];
	}

	//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
	this.drawByChanged = function(){
		self.mapInfo.zoomLevel = self.map.getLevel();
		var drawChartOverlay = function(){
			$.each(self.customOverlayList, function(_i, _customOverlay){
				_customOverlay.setContent(_customOverlay.getContent());
				
				var lz_i = _customOverlay.chartInfo.locationName;
				var _v = _customOverlay.chartInfo.value;
				var chartWidth = _customOverlay.chartInfo.chartWidth;
				
				if(self.polygonEditOptions.polygonChartCheck){
					switch(self.chartEditOptions.chartType){
						case 'Pie':
							self.renderPie(lz_i, _v, chartWidth);
							break;
						case 'Bubble':
							self.renderBubble(lz_i, _v, chartWidth);
							break;
					}
				}
			});
		};
		
		//2020.12.07 MKSONG 카카오맵 마커일 경우 오류 수정  DOGFOOT
		//2020.12.9 SYJIN 시도,시군구,읍면동 변환하는 줌 레벨 재조정 DOGFOOT
		if(self.Map.LocationType == 'address'){
			switch(self.addresses[0]['addressType']){
				//2020.12.31 mksong 카카오맵 시도 dragend 폴리곤 오류 수정 dogfoot
				case 'Sido':
					if(self.map.getLevel() > 9){
						self.initializePolygonList();
						self.initializeCustomOverlay();
						self.setPolygonByDataset('Sido');
					}
					break;
				case 'SiGunGu':
					if(self.map.getLevel() > 9){
						self.initializePolygonList();
						self.initializeCustomOverlay();
						self.setPolygonByDataset('Sido');
					}else if(self.map.getLevel() < 10){
						self.initializePolygonList();
						self.initializeCustomOverlay();
						self.setPolygonByDataset('SiGunGu');
					}else{
						drawChartOverlay();
					}
					break;
				case 'EupMyeonDong':
					if(self.map.getLevel() > 9){
						self.initializePolygonList();	
						self.initializeCustomOverlay();
						self.setPolygonByDataset('Sido');
					}else if((self.map.getLevel() < 10 && self.map.getLevel() > 5)){
						self.initializePolygonList();
						self.initializeCustomOverlay();
						self.setPolygonByDataset('SiGunGu');
					}else if(self.map.getLevel() < 6){
						self.initializePolygonList();
						self.initializeCustomOverlay();
						self.setPolygonByDataset('EupMyeonDong');
					}else{
						drawChartOverlay();
					}
					break;
			}
		}
	};

	//2020.11.17 mksong 카카오맵 마스터필터 기능 수정 dogfoot
	this.masterFiltering = function(polygon){
		var locationType = polygon['locationType'];
		var locationFullName = polygon['locationFullName'];
        
		var markerMasterFilterCheck = false;
		
		$.each(self.polygonMfList, function(pm_i, pm_v){
            var name = pm_v['name'];

            if(name == locationFullName){
                markerMasterFilterCheck = true;
            	return false;
            }
		});
		
		if (self.IO && self.IO.MasterFilterMode !== 'Off') {
			switch(self.IO.MasterFilterMode){
				case 'Multiple':
					if(markerMasterFilterCheck){									
						var start;
						var length;
                        
                         //2020.12.10 SYJIN 폴리곤 마스터 필터 클릭 시 하위 섬 폴리곤 색상 변경이 안되는 오류 수정                      
                        $.each(self.polygons[polygon.locationType], function(p_i, p_v){
                        	if(polygon.locationFullName == p_v.locationFullName){
                        		self.mouseListner(p_v, 'mouseover', p_v['mouseover']);
                                self.mouseListner(p_v, 'mouseout', p_v['mouseout']);
                        	}
                        })

                        //폴리곤 이벤트 추가
                        //self.mouseListner(polygon, 'mouseover', polygon['mouseover']);
                        //self.mouseListner(polygon, 'mouseout', polygon['mouseout']);
                        
                         //2020.11.12 syjin 폴리곤 텍스트 이벤트 추가 dogfoot
						$(polygon.textCustom).on('mouseover', polygon['mouseover']);
						$(polygon.textCustom).on('mouseout', polygon['mouseout']);
						//2020.11.18 syjin 폴리곤 마스터 필터 시 텍스트 이벤트 사라지는 오류 수정 dogfoot
						$(polygon.textCustom).on('click', polygon['mouseclick']);
                        
                        $.each(self.polygons[polygon.locationType], function(p_i, p_v){
                        	if(polygon.locationFullName == p_v.locationFullName){
                        		p_v.setOptions({
									//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
									//strokeColor : polygon.Eb[0].strokeColor,
									strokeColor : p_v.strokeColor,
									strokeWeight : 1,
									strokeStyle : 'solid',
									fillColor : p_v.fillColor
								})
                        	}
                        })
                        
                        //폴리곤 테두리 변경
// 						polygon.setOptions({
// 							//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
// 							//strokeColor : polygon.Eb[0].strokeColor,
// 							strokeColor : polygon.strokeColor,
// 							strokeWeight : 1,
// 							strokeStyle : 'solid',
// 							fillColor : polygon.fillColor
// 						})
						
                        //trackingData 제거
                        $.each(self.polygonMfList, function(pm_i, pm_v){
                        	//2020.11.18 mksong 카카오맵 오타 오류 수정 dogfoot
                        	if(pm_v['name'] == locationFullName){
                        		
                        		start = pm_v['start'];
                        		end = pm_v['end'];
                                
                                //polygonMfList에서 삭제
                        		for(var i=start; i<end; i++){
                        		    delete self.trackingData[i];	
                        		}

                                self.polygonMfList.splice(pm_i, 1);                                             
                        		return false;
                        	}
                        })
					}else{
						polygonMfObject = {
							name : locationFullName,
							start : self.trackingData.length
						}
				                                   
                        //마우스 오버 이벤트 제거
                        //polygon['m']['mouseout'] = [];
                        //polygon['m']['mouseover'] = [];

                         //2020.12.10 SYJIN 폴리곤 마스터 필터 클릭 시 하위 섬 폴리곤 색상 변경이 안되는 오류 수정
                        $.each(self.polygons[polygon.locationType], function(p_i, p_v){
                        	if(p_v.locationFullName == polygon.locationFullName){
                        	    kakao.maps.event.removeListener(p_v, 'mouseout', p_v.mouseout);
                                kakao.maps.event.removeListener(p_v, 'mouseover', p_v.mouseover);	

                                //2020.11.12 syjin 폴리곤 텍스트 이벤트 삭제 dogfoot
                                $(p_v.textCustom).off();
                        	}
                        })

                         //2020.11.11 syjin 폴리곤 마스터 필터 시 마우스 오버, 아웃 이벤트 제거 수정 dogfoot
                        //kakao.maps.event.removeListener(polygon, 'mouseout', polygon.mouseout);
                        //kakao.maps.event.removeListener(polygon, 'mouseover', polygon.mouseover);
                        
                         //2020.11.12 syjin 폴리곤 텍스트 이벤트 삭제 dogfoot
                        $(polygon.textCustom).off();

                        //2020.12.10 SYJIN 폴리곤 마스터 필터 클릭 시 하위 섬 폴리곤 색상 변경이 안되는 오류 수정
                        $.each(self.polygons[polygon.locationType], function(p_i, p_v){
                        	if(p_v.locationFullName == polygon.locationFullName){
                        		p_v.setOptions({
									strokeWeight : 7,
									strokeStyle : 'solid',
									fillColor : '#e1e10f'
								})
                        	}
                        })

                        //폴리곤 테두리 변경
// 						polygon.setOptions({
// 							strokeWeight : 7,
//                             strokeStyle : 'solid',
// 							fillColor : '#e1e10f'
// 						});
                        
                        var key = [];
						
						//2020.11.12 MKSONG 카카오맵 마스터필터 타겟 옵션 DOGFOOT
						if(self.IO.TargetDimensions == 'Address'){
							var trackingKey;
							$.each(self.addresses, function(d_i, d_v){
								trackingKey = d_v['name'];
                        		key.push(d_v['name']);
                            });

							var trackingDataObject = {};
							trackingDataObject[trackingKey] = 'LIKEDATA:' + locationFullName.replace(':',' '); 
                        	self.trackingData.push(trackingDataObject);
						}else{
							$.each(self.dimensions, function(d_i, d_v){
                            	if(d_i != 0){
                            		key.push(d_v['name']);
                            	}
                            })

                            //polygonData 파싱
                            $.each(polygon.polygonData, function(pd_i, pd_v){                                                         
                                $.each(key, function(k_i, k_v){
                                    var trackingObject = {};
                                	trackingObject[k_v] = pd_v[k_v];
                                	self.trackingData.push(trackingObject);
                                })
                            })
						}

                        polygonMfObject['end'] = self.trackingData.length;
                        
                        //polygonMfList에 추가
                        self.polygonMfList.push(polygonMfObject);
					}
					break;

				case 'Single':
					/* DOGFOOT syjin 카카오 지도 마커 마스터 필터 선택 여부 분기 처리  20200925 */
					if(markerMasterFilterCheck){
						var start;
						var length;
                        
                        //폴리곤 이벤트 추가
                        $.each(self.polygons[polygon.locationType], function(p_i, p_v){
                        	if(polygon.locationFullName == p_v.locationFullName){
                        		self.mouseListner(p_v, 'mouseover', p_v['mouseover']);
                                self.mouseListner(p_v, 'mouseout', p_v['mouseout']);
                        	}
                        })
                        //self.mouseListner(polygon, 'mouseover', polygon['mouseover']);
                        //self.mouseListner(polygon, 'mouseout', polygon['mouseout']);
                        
                        //2020.11.12 syjin 폴리곤 텍스트 이벤트 추가 dogfoot
						$(polygon.textCustom).on('mouseover', polygon['mouseover']);
						$(polygon.textCustom).on('mouseout', polygon['mouseout']);
						//2020.11.18 syjin 폴리곤 마스터 필터 시 텍스트 이벤트 사라지는 오류 수정 dogfoot
						$(polygon.textCustom).on('click', polygon['mouseclick']);
						
                        //폴리곤 테두리 변경
                        $.each(self.polygons[polygon.locationType], function(p_i, p_v){
                        	if(polygon.locationFullName == p_v.locationFullName){
                        		p_v.setOptions({
									//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
									//strokeColor : polygon.Eb[0].strokeColor,
									strokeColor : p_v.strokeColor,
									strokeWeight : 1,
									strokeStyle : 'solid',
									fillColor : p_v.fillColor
								})
                        	}
                        })
// 						polygon.setOptions({
// 							//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
// 							//strokeColor : polygon.Eb[0].strokeColor,
// 							strokeColor : polygon.strokeColor,
// 							strokeWeight : 1,
// 							strokeStyle : 'solid',
// 							fillColor : polygon.fillColor
// 						})
						
                        //trackingData 제거
                        $.each(self.polygonMfList, function(pm_i, pm_v){
                        	//2020.11.18 mksong 카카오맵 폴리곤 단일마스터필터 선택 해제 오류 수정 dogfoot
                        	if(pm_v['name'] == locationFullName){
                        		
                        		start = pm_v['start'];
                        		end = pm_v['end'];
                                
                                //polygonMfList에서 삭제
                        		for(var i=start; i<end; i++){
                        		    delete self.trackingData[i];	
                        		}                                        
                                
                                self.polygonMfList.splice(pm_i, 1);
                        		return false;
                        	}
                        })
					}else{
						self.trackingData = [];
						self.polygonMfList = [];
						
						polygonMfObject = {
							name : locationFullName,
							start : 0
						}
				                   
				         //폴리곤 테두리 초기화
                        self.polygonLineInit();
                                        
                        //마우스 오버 이벤트 제거
                        //polygon['m']['mouseout'] = [];
                        //polygon['m']['mouseover'] = [];                         
                        
                        //2020.12.10 SYJIN 폴리곤 마스터 필터 클릭 시 하위 섬 폴리곤 색상 변경이 안되는 오류 수정
                        $.each(self.polygons[polygon.locationType], function(p_i, p_v){
                        	if(p_v.locationFullName == polygon.locationFullName){
                        	    kakao.maps.event.removeListener(p_v, 'mouseout', p_v.mouseout);
                                kakao.maps.event.removeListener(p_v, 'mouseover', p_v.mouseover);	

                                //2020.11.12 syjin 폴리곤 텍스트 이벤트 삭제 dogfoot
                                $(p_v.textCustom).off();
                        	}
                        })
                        // kakao.maps.event.removeListener(polygon, 'mouseout', polygon.mouseout);
                        //kakao.maps.event.removeListener(polygon, 'mouseover', polygon.mouseover);
                        //2020.11.12 syjin 폴리곤 텍스트 이벤트 삭제 dogfoot
                        //$(polygon.textCustom).off();
                        //폴리곤 테두리 변경
                        //2020.12.10 SYJIN 폴리곤 마스터 필터 클릭 시 하위 섬 폴리곤 색상 변경이 안되는 오류 수정
                        $.each(self.polygons[polygon.locationType], function(p_i, p_v){
                        	if(p_v.locationFullName == polygon.locationFullName){
                        		p_v.setOptions({
									strokeWeight : 7,
									strokeStyle : 'solid',
									fillColor : '#e1e10f'
								})
                        	}
                        })
// 						polygon.setOptions({
// 							strokeWeight : 7,
//                             strokeStyle : 'solid',
// 							fillColor : '#e1e10f'
// 						})
                        
                        var key = [];
						
						//2020.11.12 MKSONG 카카오맵 마스터필터 타겟 옵션 DOGFOOT
						if(self.IO.TargetDimensions == 'Address'){
							var trackingKey;
							$.each(self.addresses, function(d_i, d_v){
								trackingKey = d_v['name'];
                        		key.push(d_v['name']);
                            });

							var trackingDataObject = {};
							trackingDataObject[trackingKey] = 'LIKEDATA:' + locationFullName.replace(':',' '); 
                        	self.trackingData.push(trackingDataObject);
						}else{
							$.each(self.dimensions, function(d_i, d_v){
                            	if(d_i != 0){
                            		key.push(d_v['name']);
                            	}
                            });

                            //polygonData 파싱
                            $.each(polygon.polygonData, function(pd_i, pd_v){
                                $.each(key, function(k_i, k_v){
                                    var trackingObject = {};
                                	trackingObject[k_v] = pd_v[k_v];
                                	self.trackingData.push(trackingObject);
                                });
                            });
						}

                        polygonMfObject['end'] = polygon.polygonData.length;
                        
                        //polygonMfList에 추가
                        self.polygonMfList.push(polygonMfObject);
					}
					break;
			}
		}
		
		var trackingData = self.trackingData.filter(function(item) {
		  return item !== null && item !== undefined && item !== '';
		})
		
		//2020.11.18 syjin 카카오맵 마스터필터 조회 오류 수정 DOGFOOT
		var replaceAt = function(input, index, character){
			 return input.substr(0, index) + character + input.substr(index+character.length);
		}

		$.each(trackingData, function(td_i, td_v){
			$.each(td_v, function(_i, _v){
				var result = _v.match(/:/g);
				if(result != null){
					if(result.length > 1){
						trackingData[td_i][_i] = replaceAt(_v, _v.lastIndexOf(":"), ' ');
					}
				}			
			})
		})

		//최종적으로 filterData 호출
		if (self.IO && self.IO.MasterFilterMode !== 'Off') {
			if(self.trackingData != '' || self.trackingData.length==0 || trackingData.length==0){
				gDashboard.filterData(self.itemid, trackingData);
			}
		}		
	};

	/* DOGFOOT syjin 카카오 지도 마커 편집 설정 20201012 */
	this.markerEditOptions = {
		address:{
			'valueMarkerCheck' : false,
			/* DOGFOOT syjin 마커 편집 객체에 데이터에 따른 마커 표시 최소 최대값 추가 20201013 */
			'valueMarkerRangeMin' : 0,
			'valueMarkerRangeMax' : 9999,
			/* DOGFOOT syjin 마커 편집 객체에 툴팁 표시 추가 20201013 */
			//2020.11.24 syjin dogfoot 툴팁 비활성화
			'tooltipCheck' : false,
			/* DOGFOOT syjin 마커 편집 객체에 위도,경도 표시 추가 20201014 */
			'laloCheck' : false,
			/* DOGFOOT syjin 마커 편집 이미지 범례 추가 수정 20201023 */
			'imageLegendCheck' : false,
			/* DOGFOOT syjin 마커 즐겨찾기 여부 설정 20201015*/
			'favoriteCheck' : false	
		},
		coordinate:{
			'valueMarkerCheck' : false,
			'valueMarkerRangeMin' : 0,
			'valueMarkerRangeMax' : 9999,
			//2020.11.24 syjin dogfoot 툴팁 비활성화
			'tooltipCheck' : false,
			'laloCheck' : false,
			'imageLegendCheck' : false,
			'favoriteCheck' : false,
		}
	}
	
	//2020.11.06 MKSONG 카카오맵 주소타입 이름변환 DOGFOOT
	this.locationNameConverter = {
		'시도': 'sido',
		'시군구': 'sigungu',
		'읍면동': 'eupmyeondong'
	};
	
	this.polygonEditOptions = {
		/* DOGFOOT syjin 카카오 지도 폴리곤 차트 표시 설정 20201005 */
		"polygonChartCheck" : false,
		//2020.11.18 mksong 카카오맵 폴리곤 툴팁 default 변경 dogfoot
		'tooltipCheck' : false,
		//DOGFOOT syjin 2020-11-30 한반도만 보이도록 하고 확대 못하도록 옵션 설정해주기
		'hanbandoCheck' : false,
		//2020.10.08 MKSONG 카카오맵 투명도 조정 기능 옵션 추가 DOGFOOT
		polygonOpacityEnabled : false, 
		polygonOpacityOption : 'addressType',
		
		//2020.11.03 MKSONG 카카오맵 폴리곤 투명도 가중치 설정 DOGFOOT
		polygonOpacityWeight : 100,
		//2020.11.04 mksong 카카오맵 폴리곤 레이블 설정 기능 변경 dogfoot
		"polygonLabelOptions" : {
			'type' : '지역명 및 값'
		},
		/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 20201006 */
		"polygonTextOptions" : {
			'sido' : {
				"textColor" : "black",
				/* DOGFOOT syjin 카카오 지도 폴리곤 시도일 때, 텍스트 크기 초기 설정 변경 20201118 */
				"fontSize" : 230
			},
			'sigungu' : {
				"textColor" : "black",
				"fontSize" : 150
			},
			'eupmyeondong' : {
				"textColor" : "black",
				"fontSize" : 50
			}			
		},
		/* DOGFOOT syjin 카카오 지도 폴리곤 색상 설정 20201008 */
		"polygonBgColorOptions" : {
			Sido : [],
			SiGunGu : [],
			EupMyeonDong : []
		},
		"polygonMasterFilter" : {
			Sido : [],
			SiGunGu : [],
			EupMyeonDong : []
		},
		"polygonLineOptions" : {
			'sido' : {
				"lineColor" : "#fff"
			},
			'sigungu' : {
				"lineColor" : "#fff"
			},
			'eupmyeondong' : {
				"lineColor" : "#fff"
			}			
		},
		//2020.11.20 MKSONG 카카오맵 폴리곤 배경 팔레트 Default변경 DOGFOOT
		"polygonPaletteCheck" : true,
		"polygonPaletteOptions" : {
			'sido' : {
				"Palette" : userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette,
				CustomPalette : {
					Color: []
				}
			},
			'sigungu' : {
				"Palette" : userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette,
				CustomPalette : {
					Color: []
				}
			},
			'eupmyeondong' : {
				"Palette" : userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette,
				CustomPalette : {
					Color: []
				}
			}			
		}
	}
	
	/* DOGFOOT syjin 카카오 지도 지도 정보 추가 20201028 */
	/* DOGFOOT syjin 카카오 지도 처음 중심좌표 한반도 다 보이도록 수정 20201120 */
	this.mapInfo = {
		zoomLevel : 13,
		lat : 35.94522067302675,
		lng : 127.74940032415145
	};
	
	//2020.11.03 MKSONG 카카오맵 줌 위치, 레벨 초기화 DOGFOOT
	/* DOGFOOT syjin 카카오 지도 처음 중심좌표 한반도 다 보이도록 수정 20201120 */
	this.mapInitInfo = {
		zoomLevel : 13,
		lat : 35.94522067302675,
		lng : 127.74940032415145
	}

    /* DOGFOOT syjin 카카오 지도 마커 정보 추가 20201026 */
    this.mkInfo = {
		address:{
	    	image : [],
	    	favorite : []
		},
		coordinate:{
			//2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
			standardDimension : {},
			image: {},
			favorite : []
		}
    }
    
    //2020.11.25 syjin dogfoot 폴리곤 마커 이미지 변경 여부 체크 속도 개선
    this.imageChangeCheck = false;
    
	/* DOGFOOT syjin 카카오 지도 폴리곤 마우스 이벤트 설정 20201022 */
	/* DOGFOOT syjin 카카오 지도 마우스 오버, 아웃 리스너 수정 20201111 */
	this.mouseListner = function(polygon, event, handler){
		var option;

		switch(event){
			case 'mouseover':
				option = {
					strokeWeight : 7,
					strokeStyle : 'solid'
				}
			break;

			case 'mouseout':
				option = {
					//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
					//strokeColor : polygon.Eb[0].strokeColor,
					strokeColor : polygon.strokeColor,
					strokeWeight : 1,
					strokeStyle : 'solid'
				}
			break;
		}        
		
// 		$.each(self.polygons[polygon.locationType], function(p_i, p_v){
// 			if(p_v.locationFullName == polygon.locationFullName){
// 		        kakao.maps.event.addListener(p_v, event, handler);		
// 			}
// 		})
		kakao.maps.event.addListener(polygon, event, handler);	
    };
	//2020.10.19 mksong dogfoot 카카오지도 사용자팔레트 편집
	this.samplePalettePoint = [0,1,2,3,4,5,6,7,8];
	
	//2020.10.19 mksong dogfoot 카카오지도 차트편집
	this.chartEditOptions = {
		chartType : 'Pie',
		Palette : userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette,		
		CustomPalette : {
			Color: [],
		},
		chartWeightEnabled : false, 
		chartWeightOption : 'addressType',
		chartLabelOptions : {
			'type' : '인수 및 %'
		},
		getChartLabelCustomizeText : function(point){
			switch(self.chartEditOptions['chartLabelOptions']['type']){
				case "없음":
					return;
					break;
				case "인수":
					return point.argumentText;
					break;
				case "값":
					return point.valueText;
					break;
				case "%":
					return point.percentText;
					break;
				case "인수 및 값":
					return point.argumentText + ": " + point.valueText;
					break;
				case "값 및 %":
					return point.valueText + " (" + point.percentText + ")";
					break;
				case "인수 및 %":
					return point.argumentText + ": " + " (" + point.percentText + ")";
				case "인수,값 및 %":
					return point.argumentText + ": " + point.valueText + " (" + point.percentText + ")";
					break;
			}
		}
	}
	
	/**
	 * @param _map: meta object
	 */
	
    this.setCustomMarkerImage = function(){
    	for(var i=0; i<self.markersInfo.length; i++){
    		var markerImage = new kakao.maps.MarkerImage(self.markersInfo[i]['image'], new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));

    		self.markers[i].setImage(markerImage);
    	}
    }

    this.setMarkerImage = function(_markerImage){
    	for(var i=0; i<self.markers.length; i++){
    		self.markers[i].setImage(_markerImage);
    	}
    }

	this.setButton = function(_id, _text){
		$("#"+_id).dxButton({
	    	"text" : _text
	    })('instance');
	}
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
//			onClick: function(_e) {
//				if (selectionMode !== 'none') {
//					if(_e.target){
//						var imgSrc, overImgSrc, clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
//			        	imgSrc = 'cont_box_icon_filter';
//			        	overImgSrc = 'cont_box_icon_filter_';
//			           	
//			           	$(clearTrackingImg)
//			           		.attr('src', WISE.Constants.context + '/images/' + imgSrc + '.png')
//			           		.on('mouseover', function() {
//			           			$(this).attr('src', WISE.Constants.context + '/images/' + overImgSrc + '.png');
//			           		})
//			           		.on('mouseout', function() {
//			           			$(this).attr('src', WISE.Constants.context + '/images/' + imgSrc + '.png');
//			           		});
//			           
//		           		var trackedDataName = _e.target.attribute(self.attributeName);
//			           	
//		           		var selected = {};
//		           		if(self.selectedText.indexOf(trackedDataName) == -1){
//		           			selected[self.attributeDimension.name] = trackedDataName;
//		           			self.selectedValues.push(selected);
//		           			_e.target.selected(true);
//		           		}
//		           		else{
//		           			$.each(self.selectedValues,function(_i,_f){
//		           				if(_f[self.attributeDimension.name] == trackedDataName){
//		           					self.selectedValues.splice(_i,1);
//		           					return false;
//		           				}
//		           			});
//		           			_e.target.selected(false);
//		           		}
//		           		selected[self.attributeDimension.name] = trackedDataName;
//		           		self.selectedValues.push(selected);
//
//		           		self.selectedText = "";
//		           		$.each(self.selectedValues,function(_i,_e){
//		           			self.selectedText += _e[self.attributeDimension.name]+' ';
//		           		})
//		           		if(self.selectedText==""){
//		           			var clearImg = $("#" + self.trackingClearId).find('img')[0];
//		           			$(clearImg).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
//		           		}
//		           		$('#' + self.itemid + '_tracking_data_container').empty();
//		           		$('#' + self.itemid + '_tracking_data_container').html('[ ' + self.selectedText + ']');
//		           		
//		           		window[self.dashboardid].filterData(self.itemid, self.selectedValues,self.isMasterFilterCrossDataSource);
//		           	}
//				}
//			}
		};
		return dxConfigs;
	};
	
	this.setTile = function(map){
        /* DOGFOOT syjin 카카오 지도 타일셋 추가  20201116 */
		// Tileset을 생성하고 지도 오버레이로 추가합니다
		/* DOGFOOT syjin 카카오 지도 한반도 보이는 줌레벨에서만 타일셋 설정 20201118 */
		if(kakao.maps.MapTypeId.TILE_NUMBER != undefined){
			map.removeOverlayMapTypeId(kakao.maps.MapTypeId.TILE_NUMBER);
		}
		
	    if(map.getLevel() == 12 || map.getLevel() == 13 || map.getLevel() == 14){
			kakao.maps.Tileset.add('TILE_NUMBER', 
				new kakao.maps.Tileset({
					width: 256,
					height: 256,
					minZoom: 12,
					maxZoom: 14,
					getTile: function(x, y, z) {
						var div = document.createElement('div');
						 /* DOGFOOT syjin 카카오 지도 타일셋 색상 변경 20201118 */
						div.style.backgroundColor = '#FFF';
						return div;
					}
				}));
			
			// 지도 위에 TILE_NUMBER 오버레이 레이어를 추가합니다
 		    map.addOverlayMapTypeId(kakao.maps.MapTypeId.TILE_NUMBER);
	    }
		
 		
	}

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
		//2020.09.22 mksong dogfoot 카카오지도 포인트타입, 로케이션타입 추가
		//2020.10.08 MKSONG 카카오맵 ShowPointType 기본값 변경 DOGFOOT
		this.Map['ShowPointType'] = this.Map['ShowPointType'] == undefined ? 'polygon' : this.Map['ShowPointType'];
		this.Map['LocationType'] = this.Map['LocationType'] == undefined ? 'address' : this.Map['LocationType'];
//		this.Map['ShowCaption'] = true;
		this.Map['LockNavigation'] = self.LockNavigation;
		/*view.do 와 맞추기 위한 더미 Element 또는 모르는것*/
//		this.Map['MapLegend'] = "";
		/*dogfoot 지도 팔레트 첫 생성시 범례 못그리는 오류 수정 shlim 20200617*/
		this.Map['MapLegend'] = this.Map['MapLegend'] != undefined && this.Map['MapLegend'] !="" ? this.Map['MapLegend'] : {'Visible': false};
		this.Map['WeightedLegend'] = "";
		this.Map['InteractivityOptions'] = {
			MasterFilterMode: 'Off',
			//2020.11.12 MKSONG 카카오맵 마스터필터 타겟 옵션 DOGFOOT
			TargetDimensions: 'Address',
			IsDrillDownEnabled: false,
			IgnoreMasterFilters: false
		};
		/*dogfoot polygonEditOptions 추가 syjin 20201007*/
		this.Map['polygonEditOptions'] = self.polygonEditOptions;
		//2020.10.19 mksong dogfoot 카카오지도 차트편집
		this.Map['chartEditOptions'] = self.chartEditOptions;
		//2020.10.19 mksong dogfoot 카카오지도 마커편집
		this.Map['markerEditOptions'] = self.markerEditOptions;
		this.Map['mkInfo'] = self.mkInfo;
		
		//2020.12.07 MKSONG 카카오맵 저장 옵션 기능 추가  DOGFOOT
		this.Map['SaveOptions'] = {
			SaveAutoZoomLevel : true,
			SaveAutoLatLng : true
		};
		
		if (!(this.Map.Palette)) {
			this.Map.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		
		
		/*dogfoot 마스터필터 InteractiveityOptions 초기화 syjin 20200925*/
		if (this.Map.InteractivityOptions) {
			if (!(this.Map.InteractivityOptions.MasterFilterMode)) {
				this.Map.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Map.InteractivityOptions.TargetDimensions)) {
				//2020.12.07 MKSONG 카카오맵 마스터필터 타겟 주소차원지정  DOGFOOT
				this.Map.InteractivityOptions.TargetDimensions = 'Address';
			}
			if (!(this.Map.InteractivityOptions.IsDrillDownEnabled)) {
				this.Map.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.Map.InteractivityOptions.IgnoreMasterFilters)) {
				this.Map.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Map.InteractivityOptions = {
				MasterFilterMode: 'Off',
				//2020.12.07 MKSONG 카카오맵 마스터필터 타겟 주소차원지정  DOGFOOT
				TargetDimensions: 'Address',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		this.meta = this.Map;

	}
	
	/*dogfoot 카카오맵 뷰어 불러오기 추가 syjin 20201106*/
	this.setMapForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setKakaoMap();
		}
		else{
			this.Map = this.meta;
		}
	
		//2020.10.21 MKSONG 차트옵션 저장 및 불러오기 DOGFOOT
		var webKaKaoMapElement = {};
		if (typeof gDashboard.structure.MapOption.DASHBOARD_XML !== 'undefined') {
			tempWKE = gDashboard.structure.MapOption.DASHBOARD_XML.WEB ? WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP_ELEMENT) : [];
		} else {
			tempWKE = [];
		}
		
		//2020.11.03 MKSONG 카카오맵 줌 위치, 레벨 조회시 반영 DOGFOOT
		//DOGFOOT syjin 2020-12-03 불러오기 후 카카오 지도 아이템 추가해서 조회했을 때 오류 수정
		//2020.12.04 syjin 카카오맵 2개이상인 보고서 서로 다른 세팅을 하고 불러오는 경우 오류 수정(뷰어 포함) dogfoot
		var kakaoMapMeta = {};
		if (typeof gDashboard.structure.Items.KakaoMap !== 'undefined'){
            $.each(WISE.util.Object.toArray(gDashboard.structure.Items.KakaoMap), function(_i, _kakaoMapMeta){
            	//2020.12.17 syjin 저장 시 줌레벨을 기억하고 뷰어에서 불러오기
            	if(_kakaoMapMeta.ComponentName == self.Map.ComponentName){
                    kakaoMapMeta = _kakaoMapMeta;
                }
            });
        }        
		
		if(kakaoMapMeta['Lng'] != undefined){
			self.mapInfo['lng'] = kakaoMapMeta['Lng'];
			//gDashboard.structure.Items.KakaoMap['Lng'] = undefined;
		}

		if(kakaoMapMeta['Lat'] != undefined){
			self.mapInfo['lat'] = kakaoMapMeta['Lat'];
			//gDashboard.structure.Items.KakaoMap['Lat'] = undefined;
		}

		if(kakaoMapMeta['Level'] != undefined){
			self.mapInfo['zoomLevel'] = kakaoMapMeta['Level'];
			//gDashboard.structure.Items.KakaoMap['Level'] = undefined;
		}
		
		$.each(tempWKE,function(_i,_e){
			if(_e.CTRL_NM == self.meta.ComponentName){
				webKaKaoMapElement = _e;
				var getChartLabelCustomizeText = self.chartEditOptions.getChartLabelCustomizeText;
				var getPolygonLabelCustomizeText = self.polygonEditOptions.getPolygonLabelCustomizeText;
				
				if(webKaKaoMapElement.ChartEditOptions != undefined){
					self.chartEditOptions = webKaKaoMapElement.ChartEditOptions;
					self.chartEditOptions.getChartLabelCustomizeText = getChartLabelCustomizeText;
					//2020.10.28 mksong 차트 팔레트 편집 추가  dogfoot
					if(webKaKaoMapElement.ChartEditOptions.CustomPalette == ''){
						self.chartEditOptions.CustomPalette = {};
						self.chartEditOptions.CustomPalette.Color = [];
					}
				}

				if(webKaKaoMapElement.PolygonEditOptions != undefined){
					self.polygonEditOptions = webKaKaoMapElement.PolygonEditOptions;
					$.each(self.polygonEditOptions.polygonBgColorOptions, function(_i, _v){
						if(_v.length == undefined){
							var array = WISE.util.Object.toArray(_v);
							self.polygonEditOptions.polygonBgColorOptions[_i] = array;
						}
					})
                    
                    //2020.11.02 syjin 카카오맵 불러오기 시 빈값일 때 option 들 초기화 처리  dogfoot
                    var initOptions = function(option, type){
                    	var sido = type=="small"?"sido":"Sido";
                    	var sigungu = type=="small"?"sigungu":"SiGunGu";
                    	var eupmyeondong = type=="small"?"eupmyeondong":"EupMyeonDong";

                    	if(self.polygonEditOptions[option] == undefined || self.polygonEditOptions[option] ==""){
                    		self.polygonEditOptions[option] = {};
                    	}
                    	                   	
                    	if(self.polygonEditOptions[option][sido] == undefined) self.polygonEditOptions[option][sido] = [];                	
                    	if(self.polygonEditOptions[option][sigungu] == undefined) self.polygonEditOptions[option][sigungu] = [];
                    	if(self.polygonEditOptions[option][eupmyeondong] == undefined) self.polygonEditOptions[option][eupmyeondong] = [];
                    }
                    initOptions("polygonBgColorOptions");
                    initOptions("polygonLineOptions", "small");
                    initOptions("polygonTextOptions", "small");                   			
		            
					self.polygonEditOptions.getPolygonLabelCustomizeText = getPolygonLabelCustomizeText;
				}
                
				 /* DOGFOOT syjin 마커 불러오기 오류 수정  20201104 */
                if(webKaKaoMapElement.MkInfo != undefined){
                	//2020.12.04 syjin  마커 즐겨찾기 선택 후 다른 마커 클릭시 오류 - 해당보고서 저장 후 불러오기 오류 수정 dogfoot 
                	//2020.12.07 syjin decode 예외 처리
                	var mkInfo;
                	if(typeof webKaKaoMapElement.MkInfo != 'string'){
                        //2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
                        mkInfo = {
							address : {
								favorite : JSON.parse(Base64.decode(webKaKaoMapElement.MkInfo.address.favorite)),
								image : JSON.parse(Base64.decode(webKaKaoMapElement.MkInfo.address.image))
							},
							coordinate : {
								standardDimension : webKaKaoMapElement.MkInfo.coordinate.standardDimension,
								favorite : JSON.parse(Base64.decode(webKaKaoMapElement.MkInfo.coordinate.favorite)),
								image : webKaKaoMapElement.MkInfo.coordinate.image
							}
						}
                	}else{
                        mkInfo = JSON.parse(Base64.decode(webKaKaoMapElement.MkInfo));
                	} 
                	
					self.mkInfo = mkInfo;
//                	self.mkInfo[self.Map.LocationType] = mkInfo[self.Map.LocationType] == "" ? self.mkInfo[self.Map.LocationType] : mkInfo[self.Map.LocationType];
//                
//                    if(self.mkInfo[self.Map.LocationType]['image'] == undefined) self.mkInfo[self.Map.LocationType]['image'] = {};
//                    if(self.mkInfo[self.Map.LocationType]['favorite'] == undefined) self.mkInfo[self.Map.LocationType]['favorite'] = [];
//
//                    if(self.mkInfo[self.Map.LocationType]['image'] != undefined){
////						if(typeof self.mkInfo[self.Map.LocationType]['image'] != 'Object'){
////							var array = WISE.util.Object.toArray(self.mkInfo[self.Map.LocationType]['image']);
////							self.mkInfo[self.Map.LocationType]['image'] = array; 
////						}
//                    }
//                    if(self.mkInfo[self.Map.LocationType]['favorite'] != undefined){
//						if(!Array.isArray(self.mkInfo[self.Map.LocationType]['favorite'])){
//							var array = WISE.util.Object.toArray(self.mkInfo[self.Map.LocationType]['favorite']);
//							self.mkInfo[self.Map.LocationType]['favorite'] = array; 
//						}
//                    }

					webKaKaoMapElement.MkInfo = undefined;
                }
                
                 //2020.11.03 syjin 마커옵션 저장 및 불러오기 DOGFOOT
				if(webKaKaoMapElement.MarkerEditOptions[self.Map.LocationType] != undefined){
				    self.markerEditOptions[self.Map.LocationType] = webKaKaoMapElement.MarkerEditOptions[self.Map.LocationType];                                   
				}
				
				//2020.12.03 mksong 카카오맵 저장 옵션 기능 추가 DOGFOOT
				if(webKaKaoMapElement.SaveOptions != undefined){
				    self.meta.SaveOptions = webKaKaoMapElement.SaveOptions;                                   
				}
								
				return false;
			}
		});
		
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		this.Map['ComponentName'] = this.ComponentName;
		this.Map['DataSource'] = this.dataSourceId;
		this.Map['Name'] = this.Name;
		
		/*dogfoot polygonEditOptions 추가 syjin 20201007*/
		this.Map['polygonEditOptions'] = self.polygonEditOptions;
		
		//2020.10.21 MKSONG 차트옵션 저장 및 불러오기 DOGFOOT
		this.Map['chartEditOptions'] = self.chartEditOptions;

		//2020.10.26 syjin 마커옵션 저장 및 불러오기 DOGFOOT
		this.Map['mkInfo'] = self.mkInfo;
        
        //2020.11.03 syjin 마커옵션 저장 및 불러오기 DOGFOOT
		this.Map['markerEditOptions'] = self.markerEditOptions;

		if(this.fieldManager != undefined){
			this.Map['DataItems'] = this.fieldManager.DataItems;
			this.Map['AttributeDimension'] = this.fieldManager.attributeDimension;
			/*dogfoot 코로플레스 맵 안그려지는 오류 수정  shlim 20200612*/
			this.Map['Maps'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//2020.09.22 mksong dogfoot 카카오지도 포인트타입, 로케이션타입 추가
		if(this.meta['LocationType'] != undefined){
			this.Map['LocationType'] = self.LocationType = this.meta['LocationType'];
		}
		
		if(this.meta['ShowPointType'] != undefined){
			this.Map['ShowPointType'] = self.ShowPointType = this.meta['ShowPointType'];
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

		/*dogfoot 마스터필터 InteractiveityOptions 초기화 syjin 20200925*/
		if (this.Map.InteractivityOptions) {
			if (!(this.Map.InteractivityOptions.MasterFilterMode)) {
				this.Map.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Map.InteractivityOptions.TargetDimensions)) {
				//2020.12.07 MKSONG 카카오맵 마스터필터 타겟 주소차원지정  DOGFOOT
				this.Map.InteractivityOptions.TargetDimensions = 'Address';
			}
			if (!(this.Map.InteractivityOptions.IsDrillDownEnabled)) {
				this.Map.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.Map.InteractivityOptions.IgnoreMasterFilters)) {
				this.Map.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Map.InteractivityOptions = {
				MasterFilterMode: 'Off',
				//2020.12.07 MKSONG 카카오맵 마스터필터 타겟 주소차원지정  DOGFOOT
				TargetDimensions: 'Address',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
				
		//2020.12.07 MKSONG 카카오맵 저장 옵션 기능 추가  DOGFOOT
		if(this.meta['SaveOptions'] != undefined){
			this.Map['SaveOptions'] = this.meta['SaveOptions'];
		}else{
			this.Map['SaveOptions'] = this.meta['SaveOptions'] = {
				SaveAutoZoomLevel : true,
				SaveAutoLatLng : true
			};
		};
		
		this.meta = this.Map;
	
	}
	
	this.setKakaoMapForOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setKakaoMap();
		}
		else{
			this.Map = this.meta;
		}
	
		//2020.10.21 MKSONG 차트옵션 저장 및 불러오기 DOGFOOT
		var webKaKaoMapElement = {};
		if (typeof gDashboard.structure.MapOption.DASHBOARD_XML !== 'undefined') {
			tempWKE = gDashboard.structure.MapOption.DASHBOARD_XML.WEB ? WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP_ELEMENT) : [];
		} else {
			tempWKE = [];
		}
		
		//2020.11.03 MKSONG 카카오맵 줌 위치, 레벨 조회시 반영 DOGFOOT
		//DOGFOOT syjin 2020-12-03 불러오기 후 카카오 지도 아이템 추가해서 조회했을 때 오류 수정
		//2020.12.04 syjin 카카오맵 2개이상인 보고서 서로 다른 세팅을 하고 불러오는 경우 오류 수정(뷰어 포함) dogfoot
		var kakaoMapMeta = {};
        if (typeof gDashboard.structure.Items.KakaoMap !== 'undefined'){
            $.each(WISE.util.Object.toArray(gDashboard.structure.Items.KakaoMap), function(_i, _kakaoMapMeta){
                if(_kakaoMapMeta.ComponentName == self.ComponentName){
                    kakaoMapMeta = _kakaoMapMeta;
                }
            });
        }        
		
		if(kakaoMapMeta['Lng'] != undefined){
			self.mapInfo['lng'] = kakaoMapMeta['Lng'];
			//gDashboard.structure.Items.KakaoMap['Lng'] = undefined;
		}

		if(kakaoMapMeta['Lat'] != undefined){
			self.mapInfo['lat'] = kakaoMapMeta['Lat'];
			//gDashboard.structure.Items.KakaoMap['Lat'] = undefined;
		}

		if(kakaoMapMeta['Level'] != undefined){
			self.mapInfo['zoomLevel'] = kakaoMapMeta['Level'];
			//gDashboard.structure.Items.KakaoMap['Level'] = undefined;
		}
				
		$.each(tempWKE,function(_i,_e){
			if(_e.CTRL_NM == self.meta.ComponentName){
				webKaKaoMapElement = _e;
				var getChartLabelCustomizeText = self.chartEditOptions.getChartLabelCustomizeText;
				var getPolygonLabelCustomizeText = self.polygonEditOptions.getPolygonLabelCustomizeText;
				
				if(webKaKaoMapElement.ChartEditOptions != undefined){
					self.chartEditOptions = webKaKaoMapElement.ChartEditOptions;
					self.chartEditOptions.getChartLabelCustomizeText = getChartLabelCustomizeText;
					//2020.10.28 mksong 차트 팔레트 편집 추가  dogfoot
					if(webKaKaoMapElement.ChartEditOptions.CustomPalette == ''){
						self.chartEditOptions.CustomPalette = {};
						self.chartEditOptions.CustomPalette.Color = [];
					}
				}

				if(webKaKaoMapElement.PolygonEditOptions != undefined){
					self.polygonEditOptions = webKaKaoMapElement.PolygonEditOptions;
					$.each(self.polygonEditOptions.polygonBgColorOptions, function(_i, _v){
						if(_v.length == undefined){
							var array = WISE.util.Object.toArray(_v);
							self.polygonEditOptions.polygonBgColorOptions[_i] = array;
						}
					})
                    
                    //2020.11.02 syjin 카카오맵 불러오기 시 빈값일 때 option 들 초기화 처리  dogfoot
                    var initOptions = function(option, type){
                    	var sido = type=="small"?"sido":"Sido";
                    	var sigungu = type=="small"?"sigungu":"SiGunGu";
                    	var eupmyeondong = type=="small"?"eupmyeondong":"EupMyeonDong";

                    	if(self.polygonEditOptions[option] == undefined || self.polygonEditOptions[option] ==""){
                    		self.polygonEditOptions[option] = {};
                    	}
						//2020.11.12 mksong 카카오맵 폴리곤 편집 오류 수정 dogfoot
						if(option == 'polygonPaletteOptions'){
							if(self.polygonEditOptions[option][sido]['CustomPalette'] == "") self.polygonEditOptions[option][sido]['CustomPalette'] = {Color:[]};                	
	                    	if(self.polygonEditOptions[option][sigungu]['CustomPalette'] == "") self.polygonEditOptions[option][sigungu]['CustomPalette'] = {Color:[]};                	
    	                	if(self.polygonEditOptions[option][eupmyeondong]['CustomPalette'] == "") self.polygonEditOptions[option][eupmyeondong]['CustomPalette'] = {Color:[]};                	
						}else{
							if(self.polygonEditOptions[option][sido] == undefined) self.polygonEditOptions[option][sido] = [];                	
	                    	if(self.polygonEditOptions[option][sigungu] == undefined) self.polygonEditOptions[option][sigungu] = [];
    	                	if(self.polygonEditOptions[option][eupmyeondong] == undefined) self.polygonEditOptions[option][eupmyeondong] = [];
						}
                    }
                    initOptions("polygonBgColorOptions");
                    initOptions("polygonLineOptions", "small");
                    initOptions("polygonTextOptions", "small");
                    //2020.11.12 mksong 카카오맵 폴리곤 편집 오류 수정 dogfoot
					initOptions("polygonPaletteOptions", "small");
		            
					self.polygonEditOptions.getPolygonLabelCustomizeText = getPolygonLabelCustomizeText;
				}
                
				 /* DOGFOOT syjin 마커 불러오기 오류 수정  20201104 */
                if(webKaKaoMapElement.MkInfo != undefined){
                	//2020.12.04 syjin  마커 즐겨찾기 선택 후 다른 마커 클릭시 오류 - 해당보고서 저장 후 불러오기 오류 수정 dogfoot 
                	//2020.12.07 syjin decode 예외 처리
                	//2020.12.31 mksong 카카오맵 불러오기 오류 수정 dogfoot
                	var mkInfo = {
						address:{
					    	image : [],
					    	favorite : []
						},
						coordinate:{
							//2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
							standardDimension : {},
							image: {},
							favorite : []
						}
				    };

                	if(typeof webKaKaoMapElement.MkInfo != 'string'){
                        mkInfo = {
							address : {
								favorite : JSON.parse(Base64.decode(webKaKaoMapElement.MkInfo.address.favorite)),
								image : JSON.parse(Base64.decode(webKaKaoMapElement.MkInfo.address.image))
							},
							coordinate : {
								standardDimension : webKaKaoMapElement.MkInfo.coordinate.standardDimension,
								favorite : JSON.parse(Base64.decode(webKaKaoMapElement.MkInfo.coordinate.favorite)),
								image : webKaKaoMapElement.MkInfo.coordinate.image
							}
						}
                	}else{
                        mkInfo = JSON.parse(Base64.decode(webKaKaoMapElement.MkInfo));
                	} 
                	
					self.mkInfo = mkInfo;
//                	self.mkInfo[self.Map.LocationType] = mkInfo[self.Map.LocationType] == "" ? self.mkInfo[self.Map.LocationType] : mkInfo[self.Map.LocationType];
//                
//                    if(self.mkInfo[self.Map.LocationType]['image'] == undefined) self.mkInfo[self.Map.LocationType]['image'] = {};
//                    if(self.mkInfo[self.Map.LocationType]['favorite'] == undefined) self.mkInfo[self.Map.LocationType]['favorite'] = [];
//
//                    if(self.mkInfo[self.Map.LocationType]['image'] != undefined){
////						if(typeof self.mkInfo[self.Map.LocationType]['image'] != 'Object'){
////							var array = WISE.util.Object.toArray(self.mkInfo[self.Map.LocationType]['image']);
////							self.mkInfo[self.Map.LocationType]['image'] = array; 
////						}
//                    }
//                    if(self.mkInfo[self.Map.LocationType]['favorite'] != undefined){
//						if(!Array.isArray(self.mkInfo[self.Map.LocationType]['favorite'])){
//							var array = WISE.util.Object.toArray(self.mkInfo[self.Map.LocationType]['favorite']);
//							self.mkInfo[self.Map.LocationType]['favorite'] = array; 
//						}
//                    }

					webKaKaoMapElement.MkInfo = undefined;
                }
                
                 //2020.11.03 syjin 마커옵션 저장 및 불러오기 DOGFOOT
				if(webKaKaoMapElement.MarkerEditOptions[self.Map.LocationType] != undefined){
				    self.markerEditOptions[self.Map.LocationType] = webKaKaoMapElement.MarkerEditOptions[self.Map.LocationType];                                   
				}
								
				//2020.12.03 mksong 카카오맵 저장 옵션 기능 추가 DOGFOOT
				if(webKaKaoMapElement.SaveOptions != undefined){
				    self.meta.SaveOptions = webKaKaoMapElement.SaveOptions;                                   
				}
								
				return false;
			}
		});
		
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		this.Map['ComponentName'] = this.ComponentName;
		this.Map['DataSource'] = this.dataSourceId;
		this.Map['Name'] = this.Name;
		
		/*dogfoot polygonEditOptions 추가 syjin 20201007*/
		this.Map['polygonEditOptions'] = self.polygonEditOptions;
		
		//2020.10.21 MKSONG 차트옵션 저장 및 불러오기 DOGFOOT
		this.Map['chartEditOptions'] = self.chartEditOptions;

		//2020.10.26 syjin 마커옵션 저장 및 불러오기 DOGFOOT
		this.Map['mkInfo'] = self.mkInfo;
        
        //2020.11.03 syjin 마커옵션 저장 및 불러오기 DOGFOOT
		this.Map['markerEditOptions'] = self.markerEditOptions;

		if(this.fieldManager != undefined){
			this.Map['DataItems'] = this.fieldManager.DataItems;
			this.Map['AttributeDimension'] = this.fieldManager.attributeDimension;
			/*dogfoot 코로플레스 맵 안그려지는 오류 수정  shlim 20200612*/
			this.Map['Maps'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//2020.09.22 mksong dogfoot 카카오지도 포인트타입, 로케이션타입 추가
		if(this.meta['LocationType'] != undefined){
			this.Map['LocationType'] = self.LocationType = this.meta['LocationType'];
		}
		
		if(this.meta['ShowPointType'] != undefined){
			this.Map['ShowPointType'] = self.ShowPointType = this.meta['ShowPointType'];
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

		/*dogfoot 마스터필터 InteractiveityOptions 초기화 syjin 20200925*/
		if (this.Map.InteractivityOptions) {
			if (!(this.Map.InteractivityOptions.MasterFilterMode)) {
				this.Map.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Map.InteractivityOptions.TargetDimensions)) {
				//2020.12.07 MKSONG 카카오맵 마스터필터 타겟 주소차원지정  DOGFOOT
				this.Map.InteractivityOptions.TargetDimensions = 'Address';
			}
			if (!(this.Map.InteractivityOptions.IsDrillDownEnabled)) {
				this.Map.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.Map.InteractivityOptions.IgnoreMasterFilters)) {
				this.Map.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Map.InteractivityOptions = {
				MasterFilterMode: 'Off',
				//2020.12.07 MKSONG 카카오맵 마스터필터 타겟 주소차원지정  DOGFOOT
				TargetDimensions: 'Address',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		//2020.09.22 mksong dogfoot 카카오지도 포인트타입, 로케이션타입 추가
		if(this.meta['SaveOptions'] != undefined){
			this.Map['SaveOptions'] = this.meta['SaveOptions'];
		}else{
			this.Map['SaveOptions'] = this.meta['SaveOptions'] = {
				SaveAutoZoomLevel : true,
				SaveAutoLatLng : true
			};
		};
				
		this.meta = this.Map;
	};
	
	/** @Override */
	this.bindData = function(_data, _ativePanelId) {
		$("#" + this.itemid).empty();
		//2020.09.28 mksong 불필요한 코드 제거 dogfoot
		//2020.11.24 syjin dogfoot 카카오 지도 보고서 불러오기 시 로딩화면 추가
		gProgressbar.show();
		this.renderMap(_data, _ativePanelId);
		gProgressbar.hide();
	};
	
	this.renderMap = function(_data, _ativePanelId) {
		//2020.11.27 mksong 마스터필터 오류 수정 dogfoot
		self.trackingData = [];
		//2020.10.29 mksong 카카오맵 customOverList 초기화 dogfoot
		self.customOverlayList = [];
		//2020.11.23 syjin customOverlay 초기화  dogfoot
		self.customOverlay = [];
		//2020.10.19 mksong dogfoot 카카오지도 차트 List
		self.chartList = [];
		//2020.11.18 syjin dogfoot 카카오지도 폴리곤 마스터 필터 리스트 초기화
		if(!self.functionBinddata){
		    self.polygonMfList = [];
		}
		
		//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
		self.dataSetGroupByAddressType = {
			'sidoDataSet': {},
			'siGunGuDataSet': {},
			'eupMyeonDongDataSet': {}
		};
		
		//2020.12.16 syjin 마스터 필터 적용 후 폴리곤 편집 확인 클릭 시 sqlConfigWhere 초기화
        gDashboard.itemGenerateManager.sqlConfigWhere = [];
        
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

			//2020.10.28 mksong 불필요한 부분 제거  dogfoot
		}
		else if(this.fieldManager != null && gDashboard.isNewReport == false){ // 레포트 열기
		    //2020.11.04 syjin불필요한 부분 주석 처리 dogfoot
// 			if(WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale != undefined){
// 				this.fieldManager.CustomScale = {'RangeStop': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomScale.RangeStop};
// 				/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
// 				this.fieldManager.CustomPalette = {'Color': WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0].CustomPalette.Color};
// 				/*dogfoot 지도 생성,불러오기 오류 수정 shlim 20200617*/
// 				if(typeof WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] != 'undefined'){
// 				    this.fieldManager.CustomColorSet = {'CustomColorSetCheck' : WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet']['CustomColorSetCheck']};	
// 				}else{
// 					WISE.util.Object.toArray(self.meta.Maps.ValueMap)[0]['CustomColorSet'] = {'CustomColorSetCheck':'Y'};
// 					this.fieldManager.CustomColorSet = {'CustomColorSetCheck':'Y'};
// 				}
// 			}
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setKakaoMapForOpen();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}
		/*dogfoot 카카오맵 뷰어 불러오기 추가 syjin 20201106*/
		//카카오 지도 뷰어모드
		else if(self.meta && $.isEmptyObject(self.Map)) {
			this.setMapForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			gDashboard.itemGenerateManager.generateItem(self, self.Map);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setMapForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Map);
			gDashboard.itemGenerateManager.generateItem(self, self.Map);
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

		if(self.meta['AttributeDimension'] != undefined){
			this.attributeDimension = this.DU.getDataMember(self.meta['AttributeDimension']['UniqueName'], this.DI, this.dimensions);	
		}
		
		this.panelManager.makePanel(this.valueMaps, ['dummy_value']);
		
		var dataset, dimensions = self.dimensions, measures = self.measures;
			
		if ($.type(self.tooltipMeasures) === 'array' && self.tooltipMeasures.length > 0) {
			measures = measures.concat(self.tooltipMeasures);
		}
		
		//2020.02.07 mksong sqllike 적용 dogfoot
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
		if(self.Map.LocationType == 'coordinate'){
			//2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
			if(self.mkInfo.coordinate.standardDimension.name != undefined){
				dimensions = self.dimensions.concat(self.mkInfo.coordinate.standardDimension);	
			}
		}

		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		
		//2020.11.18 mksong 카카오맵 functionbinddata 수정 dogfoot
		var datasetConfig = self.SQLike.fromJson(dimensions, measures, []);
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		var dataset = SQLikeUtil.doSqlLike(dataSourceId, datasetConfig, self);
		
		//2020.10.08 MKSONG 카카오맵 renderButtons 추가 DOGFOOT
		gDashboard.itemGenerateManager.renderButtons(self);
		
		//2020.11.18 mksong 카카오맵 functionbinddata 수정 dogfoot
		if(!self.functionBinddata){
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
				if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
				}
				gProgressbar.hide();
			}
			
			
			self.functionBinddata = false;
			
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
			
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}

			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();	
				gDashboard.updateReportLog();
			}	
			
			if(this.measures.length == 0) {
				if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
				}
				if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
					gProgressbar.hide();
					gDashboard.updateReportLog();
				}
			}
		}else{
			if (!dataset || ($.type(dataset) === 'array' && dataset.length === 0)) {
				$('#'+self.itemid + ' .nodata-layer').remove();
				var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
				$("#" + self.itemid).children().css('display','none');
				$("#" + self.itemid).prepend(nodataHtml);
				$("#" + self.itemid).css('display', 'block');
				
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
				if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
				}
				
				$('#'+self.itemid + ' .nodata-layer').remove();
				$("#" + self.itemid).children().css('display','block');
			}
			
			self.functionBinddata = false;
			gProgressbar.hide();
		}
		
		self.filteredData = dataset; 
		self.csvData = self.filteredData;
				
		/*
		$.each(dimensions, function(d_i, d_v){
			console.log(d_v);
		});
		*/

		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		self.activePanel = _ativePanelId;
		self.panelManager.activeValuePanel(self.itemid,_ativePanelId);
		
		//2020.10.19 mksong dogfoot 카카오지도 팔레트 편집
		var currentTarget = {};
		$.each(WISE.util.Object.toArray(self.meta.Maps.ValueMap),function(_i,_Maparr){
			if(self.measures[0].uniqueName == _Maparr.Value.UniqueName){
				currentTarget = _Maparr;
			}
		});
		/*dogfoot 지도 사용자 지정범위 팔레트 기능 추가 shlim 20200616*/
		//2020.11.04 syjin 불필요한 부분 주석 처리 dogfoot
		//var colorGroupArray = self.gradientValue(dataset, currentTarget.CustomScale, currentTarget.GradientPalette, self.measures[0].nameBySummaryType,currentTarget.CustomColorSet);
		
		//2020.12.07 MKSONG 카카오맵 저장 옵션 기능 추가  DOGFOOT
		if(!self.Map.SaveOptions.SaveAutoLatLng){
			self.mapInfo['lat'] = self.mapInitInfo['lat'];
			self.mapInfo['lng'] = self.mapInitInfo['lng'];
			
			self.center = new kakao.maps.LatLng(self.mapInfo['lat'], self.mapInfo['lng']);
		}
		
		if(!self.Map.SaveOptions.SaveAutoZoomLevel){
			self.mapInfo['zoomLevel'] = self.mapInitInfo['zoomLevel'];
			self.zoomLevel = self.mapInfo['zoomLevel'];
		}
		
        /* DOGFOOT syjin 카카오 지도 그리기  20200824 */
       	var container = document.getElementById(self.itemid); //지도를 담을 영역의 DOM 레퍼런스
				var options = { //지도를 생성할 때 필요한 기본 옵션
				/* DOGFOOT syjin 카카오 지도 조회시 중심좌표 설정  20201120 */
					center: self.center==undefined?new kakao.maps.LatLng(self.mapInfo['lat'], self.mapInfo['lng']):self.center, //지도의 중심좌표.
					level: self.zoomLevel==undefined?self.mapInfo['zoomLevel']:self.zoomLevel, //지도의 레벨(확대, 축소 정도)
					/* DOGFOOT syjin 카카오 지도 더블클릭 이벤트 중지  20200925 */
					disableDoubleClickZoom: true
		};

		var map = new kakao.maps.Map(container, options); //지도 생성 및 객체 리턴
		
		//DOGFOOT syjin 2020-11-30 한반도만 보이도록 하고 확대 못하도록 옵션 설정해주기
		if(self.polygonEditOptions['hanbandoCheck']){
            map.setCenter(new kakao.maps.LatLng(35.94522067302675, 127.74940032415145));
            map.setLevel(14);
            map.setZoomable(false);
            map.setDraggable(false);
		}else{
            map.setZoomable(true);
            map.setDraggable(true);
		}

		/* DOGFOOT syjin 카카오 지도 타일셋 추가  20201116 */	
		if(self.Map.ShowPointType != 'marker'){
		    self.setTile(map);
		}
			
		self.map = map;
				
        /* DOGFOOT syjin 카카오 지도 Resize 20201119 */
        self.setMapCenter = function(){
        	self.center = self.map.getCenter();
        	self.zoomLevel = self.map.getLevel();
        }
        
        self.setMapCenter();
        	
        if(self.resizeCheck){       
	 		$("#"+self.itemid).on("resize", function(){
	 			self.map.relayout();
	 			self.map.setCenter(self.center); 			
	 		})
	 		
	 		self.resizeCheck = false;
        }
        //2020.12.04 syjin chartCategory 범례 추가 dogfoot
        //2020.12.8 SYJIN 지도 차트 범례 파이일때만 보이도록 DOGFOOT
        var chartCategoryDisplay = (self.polygonEditOptions.polygonChartCheck == true) && (self.Map.LocationType == "address") && (self.chartEditOptions.chartType != 'Bubble')?"block":"none";
        
		var imageCategory = 
		     //2020.11.23 syjin 일반 차트 추가 시 이미지 범례가 popover 창 가리는 오류 수정 dogfoot
			 //2020.12.04 syjin chartCategory 범례 추가 dogfoot
			 //2020.12.17 syjin 이미지 범례 아이템 별로 설정
			 '<div id="imageCategory'+ self.itemid +'" style="position:absolute; top:3%; z-index:98; display:none">' +
		        '<ul id="imageLegendContainer'+ self.itemid +'" style="border:solid 3px #8173ed; display:flex;">' +
		        '</ul>' +
		    '</div>' +
            '<div id="chartCategory'+ self.itemid +'" style="position:absolute; top:3%; z-index:98; display:'+chartCategoryDisplay+';">' +
		         '<div id="chartCategoryContainer'+ self.itemid +'" class="scrollbar" style="padding-bottom:10px; border:solid 3px #8173ed; display:flex; width:190px; max-height:220px; overflow:hidden; background-color:white">' +
		         	 //2020.12.8 SYJIN 차트 범례 스크롤 추가 DOGFOOT
		             '<div class="imageLegend" style="padding:10px; background-color:#ffffff; width:100%; max-height:208px;">' +
//		                 '<div style="width:29px; height:42px">' +
//		                 '</div>' + 
//		                 '<div style="width:29px; height:42px">' +
//		                 '</div>' + 
//		                 '<div style="width:29px; height:42px">' +
//		                 '</div>' + 
					  '</div>' +				  
		         '</div>' +	
		         
		         //2020.12.18 syjin 폴리곤 차트 범례 팔레트 설정
		         '<div style="display:none;" id="legendPieChart">' +
				  '</div>' +
		     '</div>';   
					
		$("#"+self.itemid).append($(imageCategory));
		
		//2020.12.07 syjin dogfoot 파이차트 범례 기능 추가
		
		if(self.chartEditOptions.chartType != 'Bubble'){
			var paletteName = self.chartEditOptions.Palette == 'Custom'? self.chartEditOptions.CustomPalette.Color : self.chartEditOptions.Palette,
				palette = [],
				paletteContainer = $("#chartCategoryContainer"+self.itemid+" .imageLegend"),
				pieChartLegend = [],
				SQLikeUtil = WISE.libs.Dashboard.Query.likeSql,
				dataSourceId = this.dataSourceId,
				dataSource = [],
				//2020.12.15 mksong 카카오맵 오타 수정 dogfoot
				piedataset = [];
				if(self.markerDimensions.length != 0){
					piedataset = SQLikeUtil.doSqlLike(dataSourceId, self.SQLike.fromJson(self.markerDimensions, [], []), self);
				}

				paletteContainer.html("");

				$.each(piedataset, function(_i, _v){
					var legend = "";
					var count = 0;

					$.each(_v, function(_vi, _vv){
						if(count != 0){
							legend += "-";
						}

						legend += _vv;
						count++;
					})

					pieChartLegend.push(legend);	
				})
				
				//2020.12.18 syjin 폴리곤 차트 범례 팔레트 설정
                $.each(pieChartLegend, function(_i, _v){
                	var legendObject = {
                		'legend' : _v,
                		'value' : 3
                	}

                	dataSource.push(legendObject);
                })

				$("#legendPieChart").dxPieChart({
                    dataSource : dataSource,
                    palette : paletteName,
                    series : [
                        {
                        	argumentField : "legend",
                        	valueField : "value"
                        }
                    ]
				})
                
				//2020.12.18 syjin 폴리곤 차트 범례 팔레트 설정
                palette = [];
                
                $.each($("#legendPieChart").dxPieChart('instance').series[0].pointsByArgument, function(_i, _v){
                	$.each(_v, function(_i2, _v2){                		
                		palette.push(_v2.getColor());
                	})
                })

				$.each(pieChartLegend, function(p_i, p_v){
					$("<div>").css({
						display : 'flex',
						'justify-content' : 'space-between',
						'margin-bottom' : '5px'
					})
					.append($("<div>").html(p_v))
					.append($("<div>").css({
						width: '20px',
						height: '20px',
						backgroundColor: palette[p_i]
					})).appendTo(paletteContainer);               
				})
                                
			//2020.12.8 SYJIN 차트 범례 스크롤 추가 DOGFOOT
			gDashboard.scrollbar();            
			gProgressbar.hide();
		}
		//2020.09.22 mksong dogfoot 카카오지도 dxItem에 담기
		self.dxItem = map;
		
		//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
	    //측정값 저장
		this.measureNames = {};

		self.measureNames['name'] = [];
        self.measureNames['nameBySummaryType'] = [];
        //2020.11.12 syjin 측정값 caption 추가 dogfoot
        self.measureNames['caption'] = [];

        $.each(measures, function(_mi, _mv){
            self.measureNames['name'].push(_mv['name']);
            self.measureNames['nameBySummaryType'].push(_mv['nameBySummaryType']);
             //2020.11.12 syjin 측정값 caption 추가 dogfoot
            self.measureNames['caption'].push(_mv['caption']);
        });
		
		var markerCount = 1;
		//2020.09.22 mksong dogfoot 카카오지도 포인트타입 옵션 추가
		if(self.Map.ShowPointType == 'marker'){	
				//marker 객체배열 생성
				var markers = [];
				var markersInfo = new Array();
				//위도 : _lat
				//경도 : _lon             
                
				//2020.09.29 syjin 카카오맵 기본 이미지 추가 dogfoot
				var createMarker = function(_map, _lat, _lon, _title, _info, _image){     //마커 객체 생성					
    				var valueMarkerCheck = self.markerEditOptions[self.Map.LocationType].valueMarkerCheck;
	
					//2020.12.16 syjin 카카오맵 값에 따른 마커 표시 최대 최소 값 수정
                    var marker = new kakao.maps.Marker({
							map : _map,
							position : new kakao.maps.LatLng(_lat, _lon),
							title : _title,
							image : _image
						});

					//2020.11.13 syjin 카카오맵 로딩 시 마커 생성 과정 가리도록 수정 dogfoot
					marker.setVisible(false); 
					
					gProgressbar.show();
					
					if(self.Map.LocationType == 'address'){
					    self.addressCount++;
					}					

                    if(marker != undefined){					
						var closeOverlay = 
						function(_overlay, id){
							_overlay.setMap(null);
							//2020.10.14 syjin customOverlay 객체 삭제 dogfoot	
							$.each(self.customOverlay, function(_i, _v){
								if(!(Object.keys(_v).length === 0 && _v.constructor === Object)){
									if(id == _v['id']){
										self.customOverlay.splice(_i, 1);
									}
								}							
							})
                            
                            //2020.11.24 syjin dogfoot 툴팁 사용 후, X버튼 눌러 툴팁 없앨때, 툴팁 누르기전 기본위치로 이동							
							self.map.panTo(self.beforClickTooltipCenter);
							
						};

						//2020.09.24 mksong 카카오맵 데이터 정보 수정  및 툴팁 수정 dogfoot
						marker.index = markerCount;
						//2020.09.28 mksong 주소타입 지정 dogfoot
						var locationType = self.Map.LocationType;

						//2020.10.08 MKSONG 카카오맵 마커 trigger 기능 변경 DOGFOOT
						//2020.10.12 syjin 카카오맵 마커 이벤트 click로 변경 주석처리 dogfoot
		//				kakao.maps.event.addListener(marker, 'mouseout', function() {
		//					$('#tooltipLink'+marker.index).hide();
		//				});	

		//				마커에 클릭 이벤트 추가
						//2020.10.12 syjin 카카오맵 마커 이벤트 click로 변경 dogfoot
						kakao.maps.event.addListener(marker, 'click', function(){
							//2020.11.23 syjin 마커 툴팁 하나만 나오도록 수정 dogfoot
							if(self.customOverlay.length != 0){
								$.each(self.customOverlay, function(co_i, co_v){
									co_v['customOverlay'].setMap(null);
								})

								self.customOverlay = [];
							}
							if(self.markerEditOptions[self.Map.LocationType].tooltipCheck){
								if($('#tooltipLink'+marker.index).length != 1){
									// 마커 위에 인포윈도우를 표시합니다
									var position = marker.getPosition();
									var title = marker.getTitle();
									var content = '';

									var name = _info['name'];
									var values = _info['values'];
									var latitude = _info['latitude'];
									var longitude = _info['longitude'];					
									/* DOGFOOT syjin 마커 즐겨찾기 여부 가져오기 20201015*/
									var favoriteCheck;
									//2020.11.09 syjin 마커 즐겨찾기 초기화 수정 dogfoot
									var locationType = self.Map.LocationType;

									if(self.markersInfo[marker.index-1]['favorite']){
										favoriteCheck = self.markersInfo[marker.index-1]['favorite'];
									}
									//2020.09.28 mksong 주소타입 변경했을 경우 차트 오류 수정 dogfoot
									var colspan = locationType == 'address' ?  _.keys(_info.groupByData[0]).length * 2 : 2;
									//2020.10.14 syjin 위도 경도 표시 여부에 따른 display 속성 체크 dogfoot
									var display = self.markerEditOptions[self.Map.LocationType]['laloCheck']?"":"none";
									//2020.11.09 syjin 마커 즐겨찾기 초기화 수정 dogfoot
									var favoriteSrc = "data:image/png;base64,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";
									
									if(self.Map.LocationType == "coordinate"){
										$.each(self.mkInfo[locationType].favorite, function(fv_i, fv_v){
											if(JSON.stringify(fv_v) === JSON.stringify(_info['position'])){
	                                            favoriteSrc = "data:image/png;base64,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";
												return false;
											}
										})
									}else{
										$.each(self.mkInfo[locationType].favorite, function(fv_i, fv_v){
											if(fv_v == _info['address'][0]){
	                                            favoriteSrc = "data:image/png;base64,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";
												return false;
											}
										})
									}

									//2020.09.24 mksong 데이터 정보 차트보기 dogfoot
									//line-height:30px; vertical-align:middle;
									//2020.11.05 syjin dogfoot 카카오지도 툴팁 그림자 추가
									content = '<div id="tooltipLink' + marker.index + '" class="wrap custom-wrap" style="box-shadow: 0 0 10px 1px #544d4d;">' + 
										'    <div class="info"'+(locationType == 'coordinate' ? 'style="width:300px;"' : '') + '>' + 
										//2020.10.23 syjin 타이틀 디스플레이 수정 dogfoot
										'        <div class="title" style="display:flex; justify-content:space-between; align-items:flex-start;">' +
										'			<div style="margin-right:24px;">' +
										'				<span style=" color:#ffffff; line-height:30px; vertical-align:middle;">데이터 정보</span>' +
										'			</div>' +
										//2020.09.25 syjin 카카오맵 툴팁 url연결 주석처리 dogfoot
										//'			<div id="urlLink' + marker.index + '" class="btn neutral urlLink" style="min-width:60px;font-size:12px;border-radius:5px;line-height:30px;vertical-align:middle;right: 100px;position: absolute;">URL 연결</div>' +
										//2020.10.16 syjin 카카오맵 툴팁 마스터 필터 아이콘 추가 dogfoot
										//markerMasterFilter에 marker.index 추가
										//2020.11.05 syjin dogfoot 카카오지도 툴팁 타이틀 ui 수정
										'			<div style="display:flex;">' +
											'			<div style="margin-right:24px;">' +			
											'				<div id="markerMasterFilter'+ marker.index + '" class="btn" style="min-width:30px;margin:0px;"><img style="width:30px;" src="'+WISE.Constants.context+'/resources/main/images/ico_singleMasterFilter.png"/></div>' +
											'				<div id="favorite' + marker.index + '" class="btn" style="min-width:30px;line-height:30px;vertical-align:middle;margin:0px;"><img style="width:30px;" src="'+ favoriteSrc +'"/></div>' +
											'				<div id="chartViewLink' + marker.index + '" class="btn neutral" style="min-width:30px; margin:0px; line-height:30px; vertical-align:middle;"><img style="width:30px;" src="'+WISE.Constants.context+'/resources/main/images/ico_pie.png"/></div>' +
											'			</div>' +
											'			<div>' +
											'           	<div class="close" id="close' + marker.index + '" style="position:static; margin-right:5px;" title="닫기">&times</div>' +
											'			</div>' +
										'			</div>' +
										'        </div>' +
										'        <div class="body">' +
										'        	<div id="description' + marker.index + '" class="desc">';
									 //2020.11.05 syjin dogfoot 카카오지도 툴팁 데이터 그리드로 수정
                                    content +=              '<div id="markerDataGrid'+marker.index+'"></div>' ;
									content +=              '<table class="tableInfo" style="border-collapse: collapse; text-align: left; line-height: 1.5; border: 1px solid #ccc; width:100%;">' +
															//2020.10.14 syjin 위도 경도 표시 여부에 따른 display 속성 체크 dogfoot
															'<thead class= "lalo" style= "border-right: 1px solid #ccc; border-left: 1px solid #ccc; background: #ffcd36; display:'+display+';">' +
																'<tr>'+
																	'<th scope="cols" colspan="' + colspan + '" style="padding: 5px; font-weight: bold; vertical-align: top; color: #000;">' +
																		'위도' +
																	'</th>' +
																'</tr>' +
															'</thead>' +
															'<tbody class= "lalo" style="display:'+display+';">' +
																'<tr>' +
																	'<th scope="row" colspan="' + colspan + '" style="padding: 5px; font-weight: bold; vertical-align: top; border-bottom: 1px solid #ccc; background: #fcf1f4;">' +
																		latitude +
																	'</th>' +
																'</tr>' +
															'</tbody>' +
															'<thead class= "lalo" style= " border-right: 1px solid #ccc; border-left: 1px solid #ccc; background: #ffcd36; display:'+display+';">' +
																'<tr>' +
																	'<th scope="cols" colspan="' + colspan + '" style="padding: 5px; font-weight: bold; vertical-align: top; color: #000;">' +
																		'경도' +
																	'</th>' +
																'</tr>' +
															'</thead>' +
															'<tbody class= "lalo" style="display:'+display+';">' +
																'<tr>' +
																	'<th scope="row" colspan="' + colspan + '" style="padding: 5px; font-weight: bold; vertical-align: top; border-bottom: 1px solid #ccc; background: #fcf1f4;">' +
																		longitude +
																	'</th>' +
																'</tr>' +
															'</tbody>' +
														'</table>';	
									content +=			
										'            </div>' +
										//2020.09.24 mksong 데이터 정보 차트보기 dogfoot
										'			 <div id="chartView'+marker.index+'" class="chartView" style="display:none;">' +
										'			 </div>' +		
										'        </div>' + 
										'    </div>' +    
										'</div>';

									//self.setButton("mapUrl", "새창으로 열기");

									var customOverlay =  createCustomOverlay(position, content);

									var customOverlayObject = {
											'id' : marker.index,
											'customOverlay' : customOverlay 
									}
									
									self.setCustomOverlay(customOverlay, map, self.markerEditOptions[self.Map.LocationType].tooltipCheck);
									self.customOverlay.push(customOverlayObject);
									
                                    //2020.11.05 syjin dogfoot 카카오지도 툴팁 데이터 그리드로 수정							
 									//self.renderPie(marker.index, _info);
 									//2020.11.23 syjin 마커 툴팁 데이터 그리드 안나오는 오류 수정  dogfoot
 									self.renderGrid(marker.index, _info);
 																				
									 
									 $(".custom-wrap").parent().css("z-index", 9999);

									 $("#close" + marker.index).click(function(){
										 //2020.10.14 syjin marker.index 매개변수 추가 dogfoot
										 closeOverlay(customOverlay, marker.index);
									 });

									 $("#urlLink" + marker.index).click(function(){
										 switch(self.selectValue){
											 case 'kakao' : 
												 window.open('https://map.kakao.com/link/map/Hello World!,' + latitude + ',' + longitude , '_blank');
												 break;
											 case 'naver' :
												 window.open('http://maps.naver.com/?menu=location&mapMode=0&lat=' + latitude + '&lng=' + longitude, '_blank');
												 break; 
										 }				
									 });

									//2020.10.15 클릭 시 중요 이미지 범례 설정(즐겨찾기) 설정 dogfoot
									$("#favorite" + marker.index).click(function(){
										var favoriteCheck = self.markersInfo[marker.index-1].favorite;

										if(favoriteCheck){
											favoriteCheck = false;
										}else{
											favoriteCheck = true;
										}

										if(favoriteCheck){
											$("#favorite" + marker.index).find('img').attr({
												src : "data:image/png;base64,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",
												style : "width:30px;"
											}) 			

											/* DOGFOOT syjin 카카오 지도 즐겨찾기로 저장된 마커 지역 이름 저장 20201026 */
											//2020.12.04 syjin  마커 즐겨찾기 선택 후 다른 마커 클릭시 오류 - 해당보고서 저장 후 불러오기 오류 수정 dogfoot 
											if(self.Map.LocationType == 'coordinate'){
												self.mkInfo[self.Map.LocationType]['favorite'].push(self.markersInfo[marker.index-1].position);
											}else{
												self.mkInfo[self.Map.LocationType]['favorite'].push(self.markersInfo[marker.index-1].address[0]);
											}
										}else{
											$("#favorite" + marker.index).find('img').attr({
												src : "data:image/png;base64,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",
												style : "width:30px;"
											}) 

											/* DOGFOOT syjin 카카오 지도 즐겨찾기로 저장된 마커 지역 이름 삭제 20201026 */
											//2020.12.04 syjin  마커 즐겨찾기 선택 후 다른 마커 클릭시 오류 - 해당보고서 저장 후 불러오기 오류 수정 dogfoot 
											if(self.Map.LocationType == 'coordinate'){
												$.each(self.mkInfo[self.Map.LocationType]['favorite'], function(_i, _v){
													if(JSON.stringify(_v) === JSON.stringify(self.markersInfo[marker.index-1].position)){
														self.mkInfo[self.Map.LocationType]['favorite'].splice(_i, 1);
													}
												})
											}else{
												$.each(self.mkInfo[self.Map.LocationType]['favorite'], function(_i, _v){
													if(_v == self.markersInfo[marker.index-1].address[0]){
														self.mkInfo[self.Map.LocationType]['favorite'].splice(_i, 1);
													}
												})
											}
										}

										self.markersInfo[marker.index-1].favorite = favoriteCheck;
									})

									/* DOGFOOT syjin 카카오 지도 마커 클릭 이벤트 추가(마스터 필터)  20200925 */
									/* DOGFOOT syjin 카카오 지도 마스터 필터 오른쪽 클릭 이벤트로 변경  20201013 */
									/* DOGFOOT syjin 카카오 지도 마스터 필터 툴팁 아이콘 클릭 시 적용되도록 변경  20201019 */
									$("#markerMasterFilter"+ marker.index).click(function(e){
										self.clickMarkerMasterFilter(marker, _info);
									});

									//2020.09.24 mksong 데이터 정보 차트보기 dogfoot
									$("#chartViewLink" + marker.index).click(function(){
										$('#description'+ marker.index).toggle();
										$('#chartView'+ marker.index).toggle();
										
										/* DOGFOOT syjin editds 수정 20201120 */
										if($('#chartViewLink'+ marker.index).find('img').attr('src') == WISE.Constants.context+"/resources/main/images/ico_pie.png"){
											$("#chartViewLink" + marker.index).find('img').attr({
												/* DOGFOOT syjin editds 수정 20201120 */
												src : WISE.Constants.context+"/resources/main/images/ico_basicGrid.png",
												style : "width:30px"
											})
											//2020.09.28 mksong 주소타입 변경했을 경우 차트 오류 수정 dogfoot
											if(locationType == 'coordinate'){
												$('#tooltipLink'+marker.index).find('.info').width('400px');
											}
										}else{
											//$('#chartViewLink'+ marker.index).text('차트');

											$("#chartViewLink" + marker.index).find('img').attr({
												//src : "WISE.Constants.context/resources/main/images/ico_basicGrid.png",
												src : WISE.Constants.context+"/resources/main/images/ico_pie.png",
												style : "width:30px"
											})
											//2020.09.28 mksong 주소타입 변경했을 경우 차트 오류 수정 dogfoot
											if(locationType == 'coordinate'){
												$('#tooltipLink'+marker.index).find('.info').width('300px');
											}
										}

										var CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
										if($('#chartView'+marker.index).children().length == 0){
											var dataBasket = [];
											//2020.09.28 mksong 주소타입 변경했을 경우 차트 오류 수정 dogfoot
											if(locationType == 'address'){
												$.each(_info.groupByData, function(_i0, _v0) {
													var captionBySummaryType = self.measureNames.nameBySummaryType[0];
													var caption = [];
													$.each(self.markerDimensions, function(_ii, _ao) {
														caption.push(_v0[_ao.name]);
													});
													var d = {};
													d[CTN.arguments.name.SINGLE_ARGUMENT] = caption.reverse().join(',');
													d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _v0[captionBySummaryType];
													d['caption'] = self.measureNames.name[0];
													dataBasket.push(d);
												});
											}else{
												var captionBySummaryType = self.measureNames.nameBySummaryType[0];
												var d = {};
												var caption = [];
												$.each(_info.markerDimensions, function(_i0, _v0) {
													//DOGFOOT syjin 2020-11-27 마커 위도 경도 일떄, 범례 object 로 나오는 오류 수정
													caption.push(_.values(_v0)[0]);
												});
												d[CTN.arguments.name.SINGLE_ARGUMENT] = caption.reverse().join(',');
												d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _info.values[0];
												d['caption'] = self.measureNames.name[0];
												dataBasket.push(d);
											}

											$('#chartView'+marker.index).dxPieChart({
												dataSource : dataBasket,
												size: {
													width: 380
												},
												palette: "bright",
												series: [
													{
														argumentField: CTN.arguments.name.SINGLE_ARGUMENT,
														valueField: CTN.arguments.name.SINGLE_ARGUMENT_VALUE,
														label: {
															visible: true,
															connector: {
																visible: true,
																width: 1
															}
														}
													}
												],
											}).dxPieChart('instance');
										}
									});
								}else{
									//2020.10.08 MKSONG 카카오맵 마커 trigger 기능 변경 DOGFOOT
									$('#tooltipLink'+marker.index).show();
								}
							}else{
								//2020.11.26 syjin dogfoot 마커 툴팁 없을 때 마스터 필터 적용
								self.clickMarkerMasterFilter(marker, _info);
							}				
						});

						markerCount++;
						//마커배열에 추가
						markers.push(marker);
						var ml = markers.length;
						
						markersInfo[ml-1] = {
							md : "",
							image : "",
							address : "",
							//2020.09.29 syjin 카카오맵 마스터 필터 선택 여부 설정 추가 dogfoot
							masterFilterSelected : false,
							//2020.10.15 syjin 카카오맵 마커 즐겨찾기 여부 설정 추가 dogfoot
							favorite : false,
							//2020.12.04 syjin  마커 즐겨찾기 선택 후 다른 마커 클릭시 오류 - 해당보고서 저장 후 불러오기 오류 수정 dogfoot
							position : _info['position']
						};
						
						//2020.12.11 syjin 카카오맵 블러오기 즐겨찾기 초기화 dogfoot
						$.each(self.mkInfo[self.Map.LocationType].favorite, function(_i, _v){
							if(JSON.stringify(_v) == JSON.stringify(_info['position'])){
								markersInfo[ml-1]['favorite'] = true;
							}
						})
						
						_info['position'] = markersInfo[ml-1]['position'];
						
						if(_info['markerDimensions']){
							markersInfo[ml-1].md = _info['markerDimensions'];
						}
						
						//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
						if(_info['standardDimension']){
							markersInfo[ml-1].standardDimension = Array.isArray(_info['standardDimension']) ? _info['standardDimension'] : WISE.util.Object.toArray(_info['standardDimension']);
						}
						
						if(_info['address']){
							markersInfo[ml-1].address = _info['address'];
						}

						var mkInfoAddress;
						$.each(self.mkInfo[self.Map.LocationType], function(_i, _v){
							if(_i == 'favorite'){
								mkInfoAddress = _v;
							}
						})

						$.each(mkInfoAddress, function(_i, _v){
							if(_v == markersInfo[ml-1].address){
								markersInfo[ml-1]['favorite'] = true;
							}
						})

						//2020.11.03 syjin 카카오맵 마커 이미지 초기화 dogfoot
						var mkInfoImage = "https://t1.daumcdn.net/mapjsapi/images/marker.png";

						//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
						$.each(WISE.util.Object.toArray(self.mkInfo[self.Map.LocationType]['image'][self.mkInfo[self.Map.LocationType].standardDimension.name]), function(mi_i, mi_v){
							$.each(WISE.util.Object.toArray(mi_v['listName']), function(_vi, _vv){
								if(self.Map.LocationType == 'address'){
									if(_vv == markersInfo[ml-1]['address'][0]){
										mkInfoImage = mi_v['source'];
	
										return false;
									}	
								}else{
									if(markersInfo[ml-1]['standardDimension'] != undefined){
										if(_vv == markersInfo[ml-1]['standardDimension'][0]){
											mkInfoImage = mi_v['source'];
											return false;
										}
									}
								}
							})
						})

						//2020.09.29 syjin 카카오맵 이미지 변경 dogfoot
						markersInfo[ml-1].image = mkInfoImage;

						//markersInfo[ml-1].image = "https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png";

						//2020.10.13 syjin markersInfo 객체에 value 추가 dogfoot
						markersInfo[ml-1].value = _info['values'][0];

						self.markers = markers;
						self.markersInfo = markersInfo;
						self.Map.markersInfo = self.markersInfo;			
					}
                    
                    if(self.Map.LocationType == 'address'){
						if(self.addressLength == self.addressCount){
							//2020.11.03 syjin 카카오맵 값에 따른 마커 표시 함수처리 dogfoot				
							createClusterer(map, markers);
							gProgressbar.hide();
						}
                    }
				}

				var createCustomOverlay = function(_position, _content){
					var customOverlay = new kakao.maps.CustomOverlay({
						position:_position,						
						content : _content
					});

					return customOverlay;
				}

				var createClusterer = function(_map, _markers, _gridSize, _averageCenter, _minLevel, _disableClickZoom, _styles){
					//2020.11.13 syjin 카카오맵 로딩 시 마커 생성 과정 가리도록 수정 dogfoot
					//2020.12.16 syjin 카카오맵 값에 따른 마커 표시 최대 최소 값 수정
					var valueMarkers = [];

					$.each(markers,function(m_i, m_v){
						if(self.markerEditOptions[self.Map.LocationType].valueMarkerCheck){
                            var min = self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMin;
                            var max = self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMax;                           

                            if((min <= self.markersInfo[m_i].value) && (self.markersInfo[m_i].value <= max)){
                            	m_v.setVisible(true);
                            	valueMarkers.push(m_v);
                            }
						}else{
						    m_v.setVisible(true);
						}
					})

					var clusterer = new kakao.maps.MarkerClusterer({
						map : _map,
						markers : self.markerEditOptions[self.Map.LocationType].valueMarkerCheck ? valueMarkers : markers,
						//gridSize : 80,
						gridSize : 110,
						//averageCenter : _averageCenter,
						minLevel : _minLevel,
						disableClickZoom : _disableClickZoom,
						styles : _styles,
						//2020.11.13 syjin 카카오맵 클러스터러 클릭시 숫자 만큼 마커가 보이도록 수정 dogfoot
						disableClickZoom: true,    //클러스터 마커를 클릭했을 때 지도가 확대되지 않도록 설정 
                        //2020.11.16 syjin 카카오맵 클러스터링 할 최소 마커수 설정 dogfoot
						minClusterSize : 5
					});
                    
                     //2020.11.16 syjin 카카오맵 줌인 아웃시 마커 이미지 초기화 dogfoot
                    kakao.maps.event.addListener(self.map, 'zoom_start', function() {
						self.clusterZoomLevel = self.map.getLevel();
						/* DOGFOOT syjin 카카오 지도 Resize 20201119 */ 
	                    self.setMapCenter();
					});

                    kakao.maps.event.addListener(self.map, 'zoom_changed', function() {                       
                        if(self.clusterZoomLevel < self.map.getLevel()){
                        	/* DOGFOOT syjin 카카오 지도 Resize 20201119 */ 
                        	self.setMapCenter();
                            //self.setCustomMarkerImage();                           
                        }

                        if(self.clustererMinLevel <= self.map.getLevel()){
                            //2020.11.23 syjin dogfoot 마커 투명도 초기화
                            self.initMarkerOpacity(); 
                        }
                        /* DOGFOOT syjin 카카오 지도 조회시 중심좌표 설정  20201120 */
    					self.zoomLevel = self.map.getLevel();	
                    })
                    
                    kakao.maps.event.addListener(map, 'dragend', function() {
                    	/* DOGFOOT syjin 카카오 지도 Resize 20201119 */ 
                        self.setMapCenter();
                    })

					//2020.11.13 syjin 카카오맵 클러스터러 클릭시 숫자 만큼 마커가 보이도록 수정 dogfoot
					kakao.maps.event.addListener(clusterer, 'clusterclick', function(cluster) {
					    var clusterMarkers = cluster.getMarkers();
                        
                        var points = [];
                        var bounds = new kakao.maps.LatLngBounds();

                        $.each(clusterMarkers, function(cm_i, cm_v){                       	
                        	//cm_v.setImage(clusterClickImage);
                        	points.push(cm_v.getPosition());
                        })
                                  
                        for (i = 0; i < clusterMarkers.length; i++) {
							// LatLngBounds 객체에 좌표를 추가합니다
							bounds.extend(points[i]);
						}
					    
					    //2020.11.23 syjin dogfoot 마커 클러스터 클릭시 투명도 조절
					    self.clustererMinLevel = self.map.getLevel();
					    self.map.setBounds(bounds);
					    
					    

					    $.each(self.markers, function(m_i, m_v){
                            var smPosition = m_v.getPosition();
                            var isFlag = true;
                            
                            m_v.setOpacity(1);
                            
                            $.each(points, function(p_i, p_v){
                            	if(p_v.equals(smPosition)){
                                    isFlag = false;        
                            		return false;
                            	}                                                          
                            })

						    if(isFlag){
						    	//DOGFOOT syjin 2020-11-27 마커 더 투명하게 수정
							    m_v.setOpacity(0.3);
						    }
                        })
					});

					self.clusterer = clusterer;
				}

				//2020.09.22 mksong dogfoot 카카오지도 로케이션타입에 따른 동기화
				if(self.Map.LocationType == 'address'){
					var geocoder = new kakao.maps.services.Geocoder();
					//2020.09.24 mksong 카카오맵 데이터 정보 수정  dogfoot
					var datasetGroupByAddress = {};

					$.each(self.filteredData, function(_i, _v){
						var addressData = '';

						$.each(self.addresses, function(_ii, _addressField){
							if(_ii == 0){
								addressData += _v[_addressField.caption];	
							}else{
								addressData += ' ' + _v[_addressField.caption];
							}
						});

						if(datasetGroupByAddress[addressData] == undefined){
							datasetGroupByAddress[addressData] = [];
						}

						var dataObject = {};
						//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
						var dataObjectMarkersDimensions = {};
						dataObject[self.measureNames.nameBySummaryType] = _v[self.measureNames.nameBySummaryType];					

						$.each(self.markerDimensions, function(_ii, _markerDimension){
							dataObject[_markerDimension.caption] = _v[_markerDimension.caption];					
						});

						datasetGroupByAddress[addressData].push(dataObject);
					});

					// 주소로 좌표를 검색합니다
					//2020.11.04 syjin 카카오맵 마커 표시 시 로딩화면 dogfoot
					//2020.11.06 syjin 카카오맵 마커 주소 정보 저장 dogfoot
					self.datasetGroupByAddress = datasetGroupByAddress;
					self.addressLength = _.keys(datasetGroupByAddress).length;
					self.addressCount = 0;
					//encodeURIComponent(
					/*$.each(_.keys(datasetGroupByAddress),function(_i,_address){
						$.ajax({
							url: 'https://dapi.kakao.com/v2/local/search/address.json?query=' + _address,
						    headers: { 'Authorization': 'KakaoAK 2ddb3c6cc4246d267030cb6c0c5f4849'}, 	
						    contentType : 'application/json',
						    type: 'GET'
						}).done(function(data) {
							var title = '';
							var text = '';

							var info = {};
							var coords = new kakao.maps.LatLng(result[0].y, result[0].x);				    
							info['name'] = [];
							info['values'] = [];
							//2020.11.04 syjin 카카오맵 마커 옵션 함수 처리 dogfoot
							//info['latitude'] = coords.Ha;
							info['latitude'] = coords.getLat();
							//info['longitude'] = coords.Ga;
							info['longitude'] = coords.getLng();
							info['groupByData'] = datasetGroupByAddress[_address];
							info['address'] = new Array();						
							info['markerDimensions'] = [];
							info['masterFilterSelected'] = false;
							 DOGFOOT syjin 마커 즐겨찾기 여부 초기화 20201015
							info['favoriteCheck'] = false;

							$.each(self.markersInfo, function(mi_i, mi_v){
								if(_address == mi_v['address'][0]){
									if(mi_v['masterFilterSelected']){
										info['masterFilterSelected'] = true;
									} 
								}
							})
							 DOGFOOT syjin 카카오 지도 markerDimension 추가 마스터 필터 관련  20200928 
							 DOGFOOT syjin 카카오 지도 markerDimension 수정  20200928 
							var key = [];

							$.each(self.markerDimensions, function(md_i, md_v){
                                key.push(md_v['name']);
							})
                                                         
							$.each(datasetGroupByAddress, function(dgb_i, dgb_v){
								if(dgb_i == _address){										
    								var addressInfo = dgb_v;

									$.each(dgb_v, function(dg_i, dg_v){
										$.each(key, function(k_i, k_v){
											var trackingObject = {};

											trackingObject[k_v] = dg_v[k_v];
										    info['markerDimensions'].push(trackingObject);
										})
									})									
								}
							})

							$.each(datasetGroupByAddress, function(dgb_i, dgb_v){
								if(_address == dgb_i)
									info['address'].push(dgb_i);
							});

							//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
							$.each(self.measureNames, function(mn_i, mn_v){
								//console.log(mn_v);
								if(mn_i == 'name'){
									title += mn_v + ' : ';
									$.each(mn_v, function(_a,_b){
										info['name'].push(_b);
									});
								}else if(mn_i == 'nameBySummaryType'){
									var sumValue = 0;
									$.each(datasetGroupByAddress[_address],function(_index,_data){
										sumValue += _data[mn_v];
									});
									title += sumValue + '\n';
									$.each(mn_v, function(_a, _b){
										info['values'].push(sumValue);
									});
								}
							});							                                                          

							//2020.09.29 syjin 카카오맵 기본 이미지 추가 dogfoot
							//var basicImage = "https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png";
							var basicImage = "https://t1.daumcdn.net/mapjsapi/images/marker.png";

							//2020.10.26 syjin 카카오맵 기본 이미지 초기화 dogfoot
							$.each(self.mkInfo[self.Map.LocationType], function(_mi, _mv){
								if(_mi == 'image'){
									$.each(_mv, function(mv_i, mv_v){
										$.each(mv_v['listName'], function(ln_i, ln_v){
											if(ln_v == info['address'][0]){
                                                basicImage = mv_v['source'];
												return false;
											}
										})
									})
								}
							})  
							var basicImageSize = new kakao.maps.Size(31, 35);
							var basicImageOption = new kakao.maps.Point(13, 34);

							var markerImage = new kakao.maps.MarkerImage(basicImage, basicImageSize, basicImageOption);
                            
                             //2020.11.04 syjin 카카오맵 마커 옵션 함수 처리 dogfoot
							createMarker(map, coords.getLat(), coords.getLng(), title, info, markerImage);    //마커 객체 생성 함수 호출

							//2020.11.03 syjin 카카오맵 조회 시 이미지 범례 표시 dogfoot
							self.displayImageLegend(self.markerEditOptions[self.Map.LocationType]['imageLegendCheck']);
						})
						.fail(function(data){
							//2020.11.04 syjin 카카오맵 마커 표시 시 로딩화면 dogfoot
							self.addressCount++;

							if(self.addressLength == self.addressCount){
								//2020.11.03 syjin 카카오맵 값에 따른 마커 표시 함수처리 dogfoot				
								createClusterer(map, markers);
								gProgressbar.hide();
							}
						});
					})*/
					
					//addressSearch 재귀함수 호출
//					var addressSearch = function(_address){
//					    geocoder.addressSearch(_address, function(result, status) {
//					    	if(result == 'ERROR'){
//					    		addressSearch(_address);
//					    	}
//							 // 정상적으로 검색이 완료됐으면 
//							 if (status === kakao.maps.services.Status.OK) {
//									var title = '';
//									var text = '';
//
//									var info = {};
//									var coords = new kakao.maps.LatLng(result[0].y, result[0].x);				    
//									info['name'] = [];
//									info['values'] = [];
//									
//									//2020.11.04 syjin 카카오맵 마커 옵션 함수 처리 dogfoot
//									//info['latitude'] = coords.Ha;
//									info['latitude'] = coords.getLat();
//									//info['longitude'] = coords.Ga;
//									info['longitude'] = coords.getLng();
//									info['groupByData'] = datasetGroupByAddress[_address];
//									info['address'] = new Array();						
//									info['markerDimensions'] = [];
//									info['masterFilterSelected'] = false;
//									// DOGFOOT syjin 마커 즐겨찾기 여부 초기화 20201015
//									info['favoriteCheck'] = false;
//
//									$.each(self.markersInfo, function(mi_i, mi_v){
//										if(_address == mi_v['address'][0]){
//											if(mi_v['masterFilterSelected']){
//												info['masterFilterSelected'] = true;
//											} 
//										}
//									})
//									 //DOGFOOT syjin 카카오 지도 markerDimension 추가 마스터 필터 관련  20200928 
//									 //DOGFOOT syjin 카카오 지도 markerDimension 수정  20200928 
//									var key = [];
//
//									$.each(self.markerDimensions, function(md_i, md_v){
//		                               key.push(md_v['name']);
//									})
//		                                                        
//									$.each(datasetGroupByAddress, function(dgb_i, dgb_v){
//										if(dgb_i == _address){										
//		   								var addressInfo = dgb_v;
//
//											$.each(dgb_v, function(dg_i, dg_v){
//												$.each(key, function(k_i, k_v){
//													var trackingObject = {};
//
//													trackingObject[k_v] = dg_v[k_v];
//												    info['markerDimensions'].push(trackingObject);
//												})
//											})									
//										}
//									})
//
//									$.each(datasetGroupByAddress, function(dgb_i, dgb_v){
//										if(_address == dgb_i)
//											info['address'].push(dgb_i);
//									});
//
//									//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
//									$.each(self.measureNames, function(mn_i, mn_v){
//										//console.log(mn_v);
//										if(mn_i == 'name'){
//											title += mn_v + ' : ';
//											$.each(mn_v, function(_a,_b){
//												info['name'].push(_b);
//											});
//										}else if(mn_i == 'nameBySummaryType'){
//											var sumValue = 0;
//											$.each(datasetGroupByAddress[_address],function(_index,_data){
//												sumValue += _data[mn_v];
//											});
//											title += sumValue + '\n';
//											$.each(mn_v, function(_a, _b){
//												info['values'].push(sumValue);
//											});
//										}
//									});							                                                          
//
//									//2020.09.29 syjin 카카오맵 기본 이미지 추가 dogfoot
//									//var basicImage = "https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png";
//									var basicImage = "https://t1.daumcdn.net/mapjsapi/images/marker.png";
//
//									//2020.10.26 syjin 카카오맵 기본 이미지 초기화 dogfoot
//									$.each(self.mkInfo[self.Map.LocationType], function(_mi, _mv){
//										if(_mi == 'image'){
//											$.each(_mv, function(mv_i, mv_v){
//												$.each(mv_v['listName'], function(ln_i, ln_v){
//													if(ln_v == info['address'][0]){
//		                                               basicImage = mv_v['source'];
//														return false;
//													}
//												})
//											})
//										}
//									})  
//									var basicImageSize = new kakao.maps.Size(31, 35);
//									var basicImageOption = new kakao.maps.Point(13, 34);
//
//									var markerImage = new kakao.maps.MarkerImage(basicImage, basicImageSize, basicImageOption);
//		                           
//		                            //2020.11.04 syjin 카카오맵 마커 옵션 함수 처리 dogfoot
//									createMarker(map, coords.getLat(), coords.getLng(), title, info, markerImage);    //마커 객체 생성 함수 호출
//
//									//2020.11.03 syjin 카카오맵 조회 시 이미지 범례 표시 dogfoot
//									self.displayImageLegend(self.markerEditOptions[self.Map.LocationType]['imageLegendCheck']);						
//								
//							 }else{								
//								//2020.11.04 syjin 카카오맵 마커 표시 시 로딩화면 dogfoot
//								self.addressCount++;
//
//								if(self.addressLength == self.addressCount){
//									//2020.11.03 syjin 카카오맵 값에 따른 마커 표시 함수처리 dogfoot				
//									createClusterer(map, markers);
//									gProgressbar.hide();
//								}
//							} 		
//							
//						});	
//					}					
//					$.each(_.keys(datasetGroupByAddress),function(_i,_address){
//					    addressSearch(_address);	 															
//					});			

					$.each(_.keys(datasetGroupByAddress),function(_i,_address){
						//2020.11.26 syjin dogfoot 마커 데이터가 많을 경우 재귀 함수 타서 다 그려줄 수 있도록 수정
						var addressSearch = function(){
							geocoder.addressSearch(_address, function(result, status) {
								 // 정상적으로 검색이 완료됐으면
								 if(result == 'ERROR'){
								 	setTimeout(addressSearch,500);
								 }else{
									 if (status === kakao.maps.services.Status.OK) {
											var title = '';
											var text = '';

											var info = {};
											var coords = new kakao.maps.LatLng(result[0].y, result[0].x);				    
											info['name'] = [];
											info['values'] = [];

											//2020.11.04 syjin 카카오맵 마커 옵션 함수 처리 dogfoot
											//info['latitude'] = coords.Ha;
											info['latitude'] = coords.getLat();
											//info['longitude'] = coords.Ga;
											info['longitude'] = coords.getLng();
											info['groupByData'] = datasetGroupByAddress[_address];
											info['address'] = new Array();						
											info['markerDimensions'] = [];
											info['masterFilterSelected'] = false;
											// DOGFOOT syjin 마커 즐겨찾기 여부 초기화 20201015
											info['favoriteCheck'] = false;

											$.each(self.markersInfo, function(mi_i, mi_v){
												if(_address == mi_v['address'][0]){
													if(mi_v['masterFilterSelected']){
														info['masterFilterSelected'] = true;
													} 
												}
											})
											 //DOGFOOT syjin 카카오 지도 markerDimension 추가 마스터 필터 관련  20200928 
											 //DOGFOOT syjin 카카오 지도 markerDimension 수정  20200928 
											var key = [];

											$.each(self.markerDimensions, function(md_i, md_v){
											   key.push(md_v['name']);
											})

											$.each(datasetGroupByAddress, function(dgb_i, dgb_v){
												if(dgb_i == _address){										
												var addressInfo = dgb_v;

													$.each(dgb_v, function(dg_i, dg_v){
														$.each(key, function(k_i, k_v){
															var trackingObject = {};

															trackingObject[k_v] = dg_v[k_v];
															info['markerDimensions'].push(trackingObject);
														})
													})									
												}
											})

											$.each(datasetGroupByAddress, function(dgb_i, dgb_v){
												if(_address == dgb_i)
													info['address'].push(dgb_i);
											});

											//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
											$.each(self.measureNames, function(mn_i, mn_v){
												//console.log(mn_v);
												if(mn_i == 'name'){
													title += mn_v + ' : ';
													$.each(mn_v, function(_a,_b){
														info['name'].push(_b);
													});
												}else if(mn_i == 'nameBySummaryType'){
													var sumValue = 0;
													$.each(datasetGroupByAddress[_address],function(_index,_data){
														sumValue += _data[mn_v];
													});
													title += sumValue + '\n';
													$.each(mn_v, function(_a, _b){
														info['values'].push(sumValue);
													});
												}
											});							                                                          

											//2020.09.29 syjin 카카오맵 기본 이미지 추가 dogfoot
											//var basicImage = "https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png";
											var basicImage = "https://t1.daumcdn.net/mapjsapi/images/marker.png";

											//2020.10.26 syjin 카카오맵 기본 이미지 초기화 dogfoot
											$.each(self.mkInfo[self.Map.LocationType], function(_mi, _mv){
												if(_mi == 'image'){
													$.each(_mv, function(mv_i, mv_v){
														$.each(mv_v['listName'], function(ln_i, ln_v){
															if(ln_v == info['address'][0]){
															   basicImage = mv_v['source'];
																return false;
															}
														})
													})
												}
											})
											
											var basicImageSize = new kakao.maps.Size(31, 35);
											var basicImageOption = new kakao.maps.Point(13, 34);

											var markerImage = new kakao.maps.MarkerImage(basicImage, basicImageSize, basicImageOption);

											//2020.11.04 syjin 카카오맵 마커 옵션 함수 처리 dogfoot
											createMarker(map, coords.getLat(), coords.getLng(), title, info, markerImage);    //마커 객체 생성 함수 호출

											//2020.11.03 syjin 카카오맵 조회 시 이미지 범례 표시 dogfoot
											self.displayImageLegend(self.markerEditOptions[self.Map.LocationType]['imageLegendCheck']);						

									 }else{								
										//2020.11.04 syjin 카카오맵 마커 표시 시 로딩화면 dogfoot
										self.addressCount++;

										if(self.addressLength == self.addressCount){
											//2020.11.03 syjin 카카오맵 값에 따른 마커 표시 함수처리 dogfoot				
											createClusterer(map, markers);
											gProgressbar.hide();
										}
									} 		
                                
							    }
							}); 	

					    }			
					    addressSearch(_address);											
					});										
				}else{
					//2020.09.24 mksong 카카오맵 데이터 정보 수정  dogfoot
					var latitudeColumn = self.latitudes[0];
					var longitudeColumn = self.longitudes[0];

					$.each(self.filteredData, function(_i, _v){
						var title = '';
						var text = '';

						var info = {};

						info['name'] = [];
						info['values'] = [];
						//2020.09.24 mksong 카카오맵 데이터 정보 수정  dogfoot
						info['latitude'] = _v[latitudeColumn.caption];
						info['longitude'] = _v[longitudeColumn.caption];
						info['markerDimensions'] = [];
						info['masterFilterSelected'] = false;    
						info['index'] = _i;  
						/* DOGFOOT syjin 마커 즐겨찾기 여부 초기화 20201015*/
						info['favoriteCheck'] = false;
						//2020.12.04 syjin  마커 즐겨찾기 선택 후 다른 마커 클릭시 오류 - 해당보고서 저장 후 불러오기 오류 수정 dogfoot 
						info['position'] = {
								latitude : info['latitude'].toString(),
								longitude : info['longitude'].toString()
						}
						
						$.each(self.markersInfo, function(mi_i, mi_v){
							if(info['index'] == mi_i){
								if(mi_v['masterFilterSelected']){
									info['masterFilterSelected'] = true;
								} 
							}
						})

						$.each(self.measureNames, function(mn_i, mn_v){
							//console.log(mn_v);
							if(mn_i == 'name'){
								title += mn_v + ' : ';
								$.each(mn_v, function(_a,_b){
									info['name'].push(_b);
								});
							}else if(mn_i == 'nameBySummaryType'){
								title += _v[mn_v] + '\n';
								$.each(mn_v, function(_a, _b){
									info['values'].push(_v[_b]);
								});
							}
						});		
                        
						$.each(self.markerDimensions, function(_ii, _markerDimension){
							var trackingObject = {};

							trackingObject[_markerDimension.caption] = _v[_markerDimension.caption];
							info['markerDimensions'].push(trackingObject);
						});
						
						//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
						if(_v['standardDimension'] != undefined){
							info['standardDimension'] = Array.isArray(_v['standardDimension']) ? _v['standardDimension'] : WISE.util.Object.toArray(_v['standardDimension']);	
						}

						//2020.09.29 syjin 카카오맵 기본 이미지 추가 dogfoot
						//var basicImage = "https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png";
						var basicImage = "https://t1.daumcdn.net/mapjsapi/images/marker.png";

						//2020.10.26 syjin 카카오맵 기본 이미지 초기화 dogfoot
						//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
						//2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
						if(self.Map.LocationType == 'address'){
							$.each(self.mkInfo[self.Map.LocationType]['image'], function(mi_i, mi_v){
								$.each(mi_v['listName'], function(_vi, _vv){
									if(_vv == info['address'][0]){
										basicImage = mi_v['source'];
	
										return false;
									}	
								})
							})	
						}else{
							$.each(WISE.util.Object.toArray(self.mkInfo[self.Map.LocationType]['image'][self.mkInfo[self.Map.LocationType].standardDimension.name]), function(mi_i, mi_v){
								$.each(WISE.util.Object.toArray(mi_v['listName']), function(_vi, _vv){
									if(self.Map.LocationType == 'address'){
										if(_vv == info['address'][0]){
											basicImage = mi_v['source'];
		
											return false;
										}	
									}else{
										if(info['standardDimension'] != undefined){
											if(_vv == info['standardDimension'][0]){
												basicImage = mi_v['source'];
												return false;
											}
										}
									}
								})
							})						
						}

						var basicImageSize = new kakao.maps.Size(31, 35);
						var basicImageOption = new kakao.maps.Point(13, 34); 

						var markerImage = new kakao.maps.MarkerImage(basicImage, basicImageSize, basicImageOption);				

						createMarker(map, _v[latitudeColumn.caption], _v[longitudeColumn.caption], title, info, markerImage);    //마커 객체 생성 함수 호출
					}); 

					createClusterer(map, markers);                  

                    //2020.11.03 syjin 카카오맵 조회 시 이미지 범례 표시 dogfoot
					self.displayImageLegend(self.markerEditOptions[self.Map.LocationType]['imageLegendCheck']);
				}
				
				//2020.11.26 syjin dogfoot 카카오 지도 relayout 설정
				map.relayout();
				self.map.relayout();
		}else{
			//2020.10.23 syjin dogfoot 카카오지도 조회 시 포인트 타입 오류 예외 처리
			if(self.meta.LocationType != 'coordinate'){
	//			09.02 polygon 시도, 시군구, 읍면동 출력
				var address = new Array();	//주소
				var array = [];
				var addressValues = {};	//주소에 대한 측정 값

				//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
				var datasetGroupByAddress = {};
				$.each(self.filteredData, function(index, value){
					var localAddress = '';

					$.each(self.addresses, function(_i, _v){
						localAddress += value[_v.caption]+' ';
						if(_i == self.addresses.length-1){
							address.push(localAddress);
						}
					});	
				})


				$.each(self.filteredData, function(_i, _v){
					var addressData = '';
					$.each(self.addresses, function(_ii, _addressField){
						if(_ii == 0){
							addressData += _v[_addressField.caption];	
						}else{
							addressData += ' ' + _v[_addressField.caption];
						}
					});

					if(datasetGroupByAddress[addressData] == undefined){
						datasetGroupByAddress[addressData] = [];
					}

					var dataObject = {};
					dataObject[self.measureNames.nameBySummaryType] = _v[self.measureNames.nameBySummaryType];					

					$.each(self.markerDimensions, function(_ii, _markerDimension){
						dataObject[_markerDimension.caption] = _v[_markerDimension.caption];
					});

					datasetGroupByAddress[addressData].push(dataObject);
				});

				// 2020.09.02 jsy 시도, 시군구, 읍면동 polygon 출력
				var locationCode;

				var setCity; //시도
				var setState; //시군구
				var setDong; //읍면동

				//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
				var dataSetGroupByAddressType = function(_addressType, _datasetGroupByAddress){
					switch(_addressType){
						case 'Sido':
							//2020.10.19 mksong dogfoot 카카오지도 지역별 합계 계산
							self.dataSetGroupByAddressType['total_' + self.measureNames.nameBySummaryType] = 0;
							self.dataSetGroupByAddressType['sidoDataSet'] = _datasetGroupByAddress;
							$.each(_datasetGroupByAddress,function(_key,_dataArray){
								//2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
								//if(!_key.includes('total')){
								if(_key.indexOf('total') == -1){								
									//2020.10.08 MKSONG 카카오맵 주소타입별 총계값 구하기 DOGFOOT
									$.each(_dataArray,function(_i,_data){
										self.dataSetGroupByAddressType['total_'+self.measureNames.nameBySummaryType] += _data[self.measureNames.nameBySummaryType];
									});
								}
							});
							break;
						case 'SiGunGu':
							//2020.10.19 mksong dogfoot 카카오지도 지역별 합계 계산
							self.dataSetGroupByAddressType['total_'+self.measureNames.nameBySummaryType] = 0;
							$.each(_datasetGroupByAddress,function(_key,_dataArray){
								//2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
								//if(!_key.includes('total')){
								if(_key.indexOf('total') == -1){	
									var sidoName = _key.split(' ')[0];
									var siGunGuName = _key.split(' ')[1];
									
									//2020.11.17 mksong 카카오맵 시군구 시 포함하는 구 영역 오류 수정 dogfoot
									var sidoName = _key.split(' ')[0];
									var siGunGuName = _key.split(' ')[1];
									
									if(_key.split(' ').length == 3){
										sidoName = _key.split(' ')[0];
										siGunGuName = _key.split(' ')[1] + ' ' + _key.split(' ')[2];
									}
									

									if(self.dataSetGroupByAddressType['sidoDataSet'][sidoName] == undefined){
										self.dataSetGroupByAddressType['sidoDataSet'][sidoName] = [];
										//2020.10.08 MKSONG 카카오맵 주소타입별 총계값 구하기 DOGFOOT
										self.dataSetGroupByAddressType['sidoDataSet'][sidoName+'_total_'+self.measureNames.nameBySummaryType] = 0;
									}

									//2020.10.08 MKSONG 카카오맵 주소타입별 총계값 구하기 DOGFOOT
									$.each(_dataArray,function(_i,_data){
										self.dataSetGroupByAddressType['total_'+self.measureNames.nameBySummaryType] += _data[self.measureNames.nameBySummaryType];
										self.dataSetGroupByAddressType['sidoDataSet'][sidoName+'_total_'+self.measureNames.nameBySummaryType] += _data[self.measureNames.nameBySummaryType];
									});

									self.dataSetGroupByAddressType['sidoDataSet'][sidoName] = self.dataSetGroupByAddressType['sidoDataSet'][sidoName].concat(_dataArray);
									//2020.11.20 mksong geojson 전역처리 dogfoot
									$.each(gDashboard.SidoJson.features, function(f_i, f_v){
										var jsonLocation = f_v.properties['CTP_KOR_NM'];
										
										 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
										//if(jsonLocation.includes(sidoName)){
										if(jsonLocation.indexOf(sidoName) != -1){
											//2020.10.08 MKSONG 카카오맵 데이터 키 코드->네임으로 변경 DOGFOOT
											if(self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName + ':' + siGunGuName] == undefined){
												self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName + ':' + siGunGuName] = [];
											}
											self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName + ':' + siGunGuName] = _dataArray;
										}
									});
								}
							});
							break;
						case 'EupMyeonDong':
							//2020.10.19 mksong dogfoot 카카오지도 지역별 합계 계산
							self.dataSetGroupByAddressType['total_'+self.measureNames.nameBySummaryType] = 0;
							$.each(_datasetGroupByAddress,function(_key,_dataArray){
								//if(!_key.includes('total')){
								//2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
								if(_key.indexOf('total') == -1){
									var sidoName = _key.split(' ')[0];
									var siGunGuName = _key.split(' ')[1];
									var eupMyeonDongName = _key.split(' ')[2];
									
									//2020.11.17 mksong 카카오맵 시군구 시 포함하는 구 영역 오류 수정 dogfoot
									if(_key.split(' ').length == 4){
										sidoName = _key.split(' ')[0];
										siGunGuName = _key.split(' ')[1] + ' ' + _key.split(' ')[2];
										eupMyeonDongName = _key.split(' ')[3];
									}

									if(self.dataSetGroupByAddressType['sidoDataSet'][sidoName] == undefined){
										self.dataSetGroupByAddressType['sidoDataSet'][sidoName] = [];
										self.dataSetGroupByAddressType['sidoDataSet'][sidoName+'_total_'+self.measureNames.nameBySummaryType] = 0;
									}

									self.dataSetGroupByAddressType['sidoDataSet'][sidoName] = self.dataSetGroupByAddressType['sidoDataSet'][sidoName].concat(_dataArray);
									//2020.11.20 mksong geojson 전역처리 dogfoot
									$.each(gDashboard.SidoJson.features, function(f_i, f_v){
										var jsonLocation = f_v.properties['CTP_KOR_NM'];
										
										//2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
										//if(jsonLocation.includes(sidoName)){
										if(jsonLocation.indexOf(sidoName) != -1){
											//2020.10.08 MKSONG 카카오맵 데이터 키 코드->네임으로 변경 DOGFOOT
											if(self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName+ ':' +siGunGuName]== undefined){
												self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName+ ':' +siGunGuName] = [];
												self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName+ ':' +siGunGuName +'_total_'+self.measureNames.nameBySummaryType] = 0;
											}
											self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName+ ':' +siGunGuName] = self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName+ ':' +siGunGuName].concat(_dataArray);
										}
									});

									$.each(_dataArray,function(_i,_data){
										self.dataSetGroupByAddressType['total_'+self.measureNames.nameBySummaryType] += _data[self.measureNames.nameBySummaryType];
										self.dataSetGroupByAddressType['sidoDataSet'][sidoName+'_total_'+self.measureNames.nameBySummaryType] += _data[self.measureNames.nameBySummaryType];
										self.dataSetGroupByAddressType['siGunGuDataSet'][sidoName+ ':' +siGunGuName +'_total_'+self.measureNames.nameBySummaryType] += _data[self.measureNames.nameBySummaryType];
									});
									
									//2020.11.20 mksong geojson 전역처리 dogfoot
									$.each(gDashboard.SiGunGuJson.features, function(f_i, f_v){
										var jsonLocation = f_v.properties['SIG_KOR_NM'];
										
										//2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
										//if(jsonLocation.includes(siGunGuName)){
										if(jsonLocation.indexOf(siGunGuName) != -1){
											//2020.10.08 MKSONG 카카오맵 데이터 키 코드->네임으로 변경 DOGFOOT
											if(self.dataSetGroupByAddressType['eupMyeonDongDataSet'][sidoName + ':' + siGunGuName + ':' +eupMyeonDongName] == undefined){
												self.dataSetGroupByAddressType['eupMyeonDongDataSet'][sidoName + ':' + siGunGuName + ':' +eupMyeonDongName] = [];
											}
											self.dataSetGroupByAddressType['eupMyeonDongDataSet'][sidoName + ':' + siGunGuName + ':' +eupMyeonDongName] = _dataArray;
										}
									});	
								}
							});
							break;
					}
                
	                //2020.10.28 syjin 줌 레벨에 따른 addressType 변화 dogfoot
	                //2020.12.9 SYJIN 시도,시군구,읍면동 변환하는 줌 레벨 재조정 DOGFOOT    
	                var drawingAddressType;
	
	  			    //if(self.mapInfo['zoomLevel'] > 9){
	  			    if(self.map.getLevel() > 9){
	  					drawingAddressType = 'Sido';
	  				//}else if(self.mapInfo['zoomLevel'] > 7){
	  				}else if(self.map.getLevel() > 5){
	  				    drawingAddressType = 'SiGunGu';
	  				}else{
	                    drawingAddressType = 'EupMyeonDong';
	  				}

					//2020.09.29 mksong 줌 레벨에 따른 addressType 동기화 dogfoot
					self.setPolygonByDataset(drawingAddressType);
				}		
				
				//2020.09.29 mksong 줌 레벨에 따른 addressType 동기화 dogfoot
				//dataSetGroupByAddressType(self.addresses[0]['addressType'],datasetGroupByAddress);
				
				//2020.11.24 syjin dogfoot 카카오 지도 보고서 불러오기 오류 수정
				function checkGeoJsonLoad(){
                    return gDashboard.SidoJson == undefined || gDashboard.SiGunGuJson == undefined || gDashboard.EupMyeonDongJson == undefined? true : false;
                }
                      
                function doDataSetGroupByAddressType(){                	
                    var checkGeoJsonLoaded = checkGeoJsonLoad();
                    if(checkGeoJsonLoaded){
                    	setTimeout(doDataSetGroupByAddressType, 2000);
                    	//DOGFOOT syjin 2020-12-02 지도 불러오기 로딩 표시 추가
                    	gProgressbar.show();
                    }else{
                        dataSetGroupByAddressType(self.addresses[0]['addressType'],datasetGroupByAddress);
                      //DOGFOOT syjin 2020-12-02 지도 불러오기 로딩 표시 추가
                        gProgressbar.hide();
                    }
                }
                             
                doDataSetGroupByAddressType();
                
				//2020.09.29 mksong 줌 레벨 최소값 설정 dogfoot
				var zoomMinLevel;
				//2020.10.29 mksong 카카오맵 줌 maxLevel 조정 dogfoot
				var zoomMaxLevel = 14;
				switch(self.addresses[0]['addressType']){
					case 'Sido':
						zoomMinLevel = 8;
						break;
					case 'SiGunGu':
						zoomMinLevel = 6;
						break;
					case 'EupMyeonDong':
						zoomMinLevel = 1;
						break;
				}
				
				if(zoomMinLevel != undefined){
					map.setMinLevel(zoomMinLevel);
				}
				
				//2020.10.29 mksong 카카오맵 줌 maxLevel 조정 dogfoot
				map.setMaxLevel(zoomMaxLevel);	

				//2020.09.29 mksong 줌 레벨에 따른 addressType 동기화 dogfoot
				kakao.maps.event.addListener(map, 'zoom_start', function(){
					self.startZoomLevel = map.getLevel();
					/* DOGFOOT syjin 카카오 지도 Resize 20201119 */ 
                    self.setMapCenter();
				});
				
				//2020.09.29 mksong 줌 레벨에 따른 addressType 동기화 dogfoot
				kakao.maps.event.addListener(map, 'zoom_changed', function(){
					/* DOGFOOT syjin 카카오 지도 Resize 20201119 */ 
                    self.setMapCenter();
                    
					//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
					/* DOGFOOT syjin 카카오 지도 한반도 보이는 줌레벨에서만 타일셋 설정 20201118 */
					if(self.map.getLevel() == 12 || self.map.getLevel() == 13 || self.map.getLevel() == 14){
						self.setTile(self.map);						
					}else{
					    self.map.removeOverlayMapTypeId(kakao.maps.MapTypeId.TILE_NUMBER);
					}
					self.drawByChanged();
                    
                     /* DOGFOOT syjin 카카오 지도 조회시 중심좌표 설정  20201120 */
					self.zoomLevel = self.map.getLevel();					
				});
				
				kakao.maps.event.addListener(map, 'dragend', function() {
					/* DOGFOOT syjin 카카오 지도 Resize 20201119 */ 
                    self.setMapCenter();
					//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
					self.drawByChanged();
//					//2020.11.03 MKSONG 카카오맵 줌 위치, 레벨 조회시 반영 DOGFOOT
//					self.mapInfo.lat = map.getCenter().getLat();
//					self.mapInfo.lng = map.getCenter().getLng();
//					
//					//2020.10.29 mksong 카카오맵 화면에 가려진 차트 안나오는 오류 수정 dogfoot
//					$.each(self.customOverlayList, function(_i, _customOverlay){
//						_customOverlay.setContent(_customOverlay.getContent());
//						//2020.11.12 syjin 카카오맵 드래그 해서 툴팁 안나오는 오류 수정 dogfoot
//						if(!_customOverlay['masterFilterCheck']){
//							$(_customOverlay.textCustom).on('mouseover', _customOverlay.mouseover);
//							$(_customOverlay.textCustom).on('mouseout', _customOverlay.mouseout);
//						}		    
//						$(_customOverlay.textCustom).on('click', _customOverlay.mouseclick);
//
//						var lz_i = _customOverlay.chartInfo.locationName;
//						var _v = _customOverlay.chartInfo.value;
//						var chartWidth = _customOverlay.chartInfo.chartWidth;
//						
//						if(self.polygonEditOptions.polygonChartCheck){
//							switch(self.chartEditOptions.chartType){
//								case 'Pie':
//									self.renderPie(lz_i, _v, chartWidth);
//									break;
//								case 'Bubble':
//									self.renderBubble(lz_i, _v, chartWidth);
//									break;
//							}
//						}
//					});
//					
//					/* DOGFOOT syjin 카카오 지도 텍스트 드래그 했을 때 변하지 않는 요류 수정 20201102 */
//					$.each(self.polygonEditOptions.polygonTextOptions, function(pe_i, pe_v){
//						var color = pe_v['textColor'];
//						var fontSize = pe_v['fontSize'];
//						var zoomLevel = self.map.getLevel();
//
//						$(".polygonText").css('color', pe_v['textColor']);
//						$(".polygonValueText").css('color', pe_v['textColor']);              	    
//                	    $(".polygonText").css('font-size', pe_v['fontSize']/self.map.getLevel());
//                	    $(".polygonValueText").css('font-size', pe_v['fontSize']/1.5/self.map.getLevel());
//
//                	    if(zoomLevel>8){
//                            if(pe_i == 'sido')
//                            return false;
//						}else if(zoomLevel>5){
//                            if(pe_i == 'sigungu')
//                            return false;
//						}else{
//							if(pe_i == 'eupmyeondong')
//                            return false;
//						}
//					})     						     
				});
				
				//2020.10.29 mksong 카카오맵 위치값 반환 이벤트 추가 dogfoot
				kakao.maps.event.addListener(map, 'dblclick', function(mouseEvent) {
					//2020.12.18 syjin 마스터 필터 일 때 dblClick 비활성화
					if(self.IO.MasterFilterMode == 'Off'){
						var latlng = mouseEvent.latLng;
						//WISE.alert('현재 좌표는 ' + latlng.toString() + '입니다.');
						//2020.11.24 syjin dogfoot 폴리곤 더블 클릭 시 시도-> 시군구, 시군구-> 읍면동 으로 확대 처리
						if(!self.polygonEditOptions.tooltipCheck){
							if(self.map.getLevel() > 8){
								self.map.setCenter(latlng);
								self.map.setLevel(8);
							}else if(self.map.getLevel() > 5){
								self.map.setCenter(latlng);
								self.map.setLevel(5);
							}
						}
					}
				});
			}
		}
		
		//2020.11.03 mksong 카카오맵 줌 컨트롤러 추가 dogfoot
		var zoom = new kakao.maps.ZoomControl();
		map.addControl(zoom, kakao.maps.ControlPosition.BOTTOMRIGHT);
		
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
	
	//2020.12.07 syjin dogfoot 파이차트 범례 기능 추가
	this.pieChartLegend;

	//2020.10.19 mksong dogfoot 카카오지도 차트 타입별 렌더
	//2020.11.20 MKSONG 카카오맵 파이차트 레전드 체크 DOGFOOT
	this.renderPie = function(lz_i, _v, chartWidth, _legendCheck){
		var CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
		var loactionId = typeof lz_i != 'number' ? lz_i.replace(/\ /g,"") : lz_i;
		//DOGFOOT syjin 2020-12-03 카카오 지도 여러개 있을 때 , 차트 표시 하나의 아이템에만 적용되는 오류 수정 
		if($("#"+self.Map.ComponentName).find('#chartView'+loactionId).children().length == 0){
			//2020.11.27 mksong 버블 차트 위치 수정 dogfoot
			//2020.12.8 SYJIN 버블 차트 위치 수정 DOGFOOT
			if(self.chartEditOptions.chartType == 'Bubble'){
				if(self.chartEditOptions.chartWeightEnabled){
					$('#chartView'+loactionId).css({
						//'margin-left' : '40%',
						//'position' : 'relative',
						//'top' : '-40px'
						'position' : 'relative',
						'top' : '-60px',
						//'left' : '-20%'
					});
				}else{
					$('#chartView'+loactionId).css({
						//'margin-left' : '40%',
						//'position' : 'relative',
						//'top' : '-40px'
						'position' : 'absolute',
						'top' : '-100%',
						'left' : '-200%'
					});
				}
			}else{
				$('#chartView'+loactionId).css({
					'margin-left' : '20%',
				});
			}
			var dataBasket = [];
			$.each(_v, function(_i0, _v0) {
				var captionBySummaryType = self.measureNames.nameBySummaryType[0];
				var caption = [];
				$.each(self.markerDimensions, function(_ii, _ao) {
					caption.push(_v0[_ao.name]);
				});
				var d = {};
				d[CTN.arguments.name.SINGLE_ARGUMENT] = caption.reverse().join(',');
				d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _v0[captionBySummaryType];
				d['caption'] = self.measureNames.name[0];

				//2020.10.08 MKSONG 카카오맵 중복 데이터 합게 처리 DOGFOOT
				var duplicatedCheck = false;
				$.each(dataBasket,function(_i,_data){
					if(_data[CTN.arguments.name.SINGLE_ARGUMENT] == d[CTN.arguments.name.SINGLE_ARGUMENT]){
						_data[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] += d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE];
						duplicatedCheck = true;
						return false;
					}
				});
				if(!duplicatedCheck){
					dataBasket.push(d);
				}
			});

			//2020.12.11 SYJIN 파이 차트 색상 범례와 동일하게 나오도록 수정
            let palette = [];
            
			$.each(dataBasket, function(db_i, db_v){
				let singleArgument = db_v.SINGLE_ARGUMENT;	

				$.each($("#chartCategory"+ self.itemid +" .imageLegend").children(), function(_i, _v){
					if(_v.innerText == singleArgument){
						palette.push($(_v).children().eq(1).css('background-color'));
					}
				})
			})              
                        	
			var dxChart = $('#chartView'+loactionId).dxPieChart({
				dataSource : dataBasket,
				size: {
					//2020.10.08 MKSONG 카카오맵 주소타입별 차트 크기 변경 DOGFOOT
					width: chartWidth,
					height: chartWidth
				},
				palette: palette,
				legend:{
					visible: _legendCheck == undefined ? false : true
				},
				resolveLabelOverlapping: 'shift',
				series: [
					{
						argumentField: CTN.arguments.name.SINGLE_ARGUMENT,
						valueField: CTN.arguments.name.SINGLE_ARGUMENT_VALUE,
						label: {
							'visible': true,
							'font': {
								size: 8
							},
							"backgroundColor": "1",
							"connector": {
								visible: true,
								width: 1
							},
							'position': "inside",
							'customizeText': function(point) {
								return self.chartEditOptions['getChartLabelCustomizeText'](point);									
							}
//							'radialAngle': -50,
//							'textOverflow': 'hide'
						}
					}
				],
			}).dxPieChart('instance');

			self.chartList.push(dxChart);
		}
	};
	
	//2020.11.20 MKSONG 카카오맵 렌더그리드 추가 DOGFOOT
	this.renderGrid = function(lz_i, _v){
		var markerDataValues = [];
		var markerColumns = [];
		var columnValue = {
			dataField : self.measures[0]['caption']
		}
		var columnDimensions = [];
        var type;
        var column = [];
		$.each(self.dimensions, function(d_i, d_v){
			var count = self.Map.LocationType == 'address' ? 0 : 1;

			if(d_i > count){
				var object = {
					dataField : d_v['name']
				}
				columnDimensions.push(object);
			}
		})

		markerColumns.push(columnValue);
		$.each(columnDimensions, function(cd_i, cd_v){
			markerColumns.push(cd_v);
		})	

		if(self.Map.ShowPointType == 'polygon'){    
		     type= 'polygon';     
		       
			 if(self.Map.LocationType == 'address'){
				$.each(_v,function(_i, _data){
					var markerDataObject = {};
					$.each(_.keys(_data), function(_ii,_key){
						//2020.11.12 syjin 측정값 caption 추가 dogfoot
						var key = self.measureNames.nameBySummaryType[0] == _key ? self.measureNames.caption[0] : _key;
								markerDataObject[key] = _data[_key];
					});
					markerDataValues.push(markerDataObject);
				});
			 }
		}else{
			//2020.11.05 syjin dogfoot 카카오지도 툴팁 데이터 그리드로 수정
			type = 'marker';

			if(self.Map.LocationType == 'address'){		    				
				$.each(_v.groupByData,function(_i, _data){
					var markerDataObject = {};
					$.each(_.keys(_v.groupByData[0]), function(_ii,_key){
						//2020.11.12 syjin 측정값 caption 추가 dogfoot
						var key = self.measureNames.nameBySummaryType[0] == _key ? self.measureNames.caption[0] : _key;

						markerDataObject[key] = _data[_key];											
					});

					markerDataValues.push(markerDataObject);
				});
			 }else{

				var markerDataObject = {};
				markerDataObject[[_v.name][0]] = _v.values[0];                

				$.each(_v.markerDimensions, function(md_i, md_v){
					$.each(md_v, function(mdv_i, mdv_v){
						markerDataObject[mdv_i] = mdv_v;                        
					})
				})

				markerDataValues.push(markerDataObject);
			 }			 
		}
		
		//2020.11.05 syjin dogfoot 카카오지도 툴팁 데이터 그리드 칼럼 순서 변경
		for(var i=markerColumns.length; i>=0; i--){
			column.push(markerColumns[i]);
		}
		
		$("#"+type+"DataGrid"+lz_i).dxDataGrid({
			 dataSource : markerDataValues,
			 paging : {
				pageSize : 5
			 },
			 columns : column,
			 summary : {
				totalItems:[{
					column : columnValue['dataField'],
					summaryType : "sum",
					customizeText : function(value){
						return "합계 : " + value.value;
					}
				}]		
			 },
			 width : 300
		});
	};
	
	this.renderBubble = function(lz_i, _v, chartWidth){
		var CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
		//2020.11.20 MKSONG 카카오맵 지역명 id 띄어쓰기 오류 수정 DOGFOOT
		var loactionId = lz_i.replace(/\ /g,"");
		if($('#chartView'+loactionId).children().length == 0){
			var dataBasket = [];
			var maxBubbleSize =  0.8;
			
			var d = {
				value : 0,
				caption : self.measureNames.name[0],
				arg : lz_i + '-' + self.measureNames.name[0],
				size : 3
			};
			$.each(_v, function(_i0, _v0) {
				var captionBySummaryType = self.measureNames.nameBySummaryType[0];
				d['value'] += _v0[captionBySummaryType];
				d['caption'] = self.measureNames.name[0];
			});
			
			dataBasket.push(d);
			
			//2020.11.27 mksong 버블 차트 위치 수정 dogfoot
			$('#chartView'+loactionId).css({
				//'margin-left' : '0px',  	
				//'position' : 'relative',
				//'top' : '-70px'
			});

			var diameter = 80;
			
			//2020.12.9 SYJIN 버블차트 d3로 변환
			var bubble = d3.pack(dataBasket)
			    .size([diameter, diameter])
			    .padding(1.5);
			
			var svg = d3.select('#chartView'+loactionId).append("svg")
			.attr("width", diameter)
			.attr("height", diameter)
			.attr("id",loactionId + "bubble")
			.attr("class", "bubble")
			//.attr("transform", "translate(" + diameter/2 + "," + diameter/2 + ")");

			svg.append("circle")
			.attr("r", function(d) {
				return chartWidth;
			})
			//2020.12.11 SYJIN 버블차트 투명도 추가
			.attr("opacity", 0.6)
			//2020.12.11 SYJIN 버블차트 색상 변경
			.style("fill", self.chartEditOptions.Palette == 'Custom' ? self.chartEditOptions.CustomPalette.Color[0] : DevExpress.viz.getPalette(self.chartEditOptions.Palette).simpleSet[0])
			.attr("transform", "translate(" + diameter/2 + "," + diameter/2 + ")");
		    
			//2020.11.20 MKSONG 카카오맵 지역명 id 띄어쓰기 오류 수정 DOGFOOT
// 			var dxChart = $('#chartView'+loactionId).dxChart({
// 				dataSource : dataBasket,
// 				argumentAxis : {					
// 					visible : false					
// 				},
// 				valueAxis : {			
// 					visible : false				
// 				},
// 				commonSeriesSettings: {
// 		            type: 'bubble'
// 		        },  
// 				size: {
// 					//2020.10.08 MKSONG 카카오맵 주소타입별 차트 크기 변경 DOGFOOT
// 		            width: chartWidth * 4,
// 					height: chartWidth * 4
// 		        },
// 				maxBubbleSize: maxBubbleSize,
// 		        palette: self.chartEditOptions.Palette == 'Custom'? self.chartEditOptions.CustomPalette.Color : self.chartEditOptions.Palette,
// 		        legend:{
// 		        	visible: false
// 		        },
// 		        series: [
// 		            {			            	
// 						sizeField: 'value',
// 		                valueField: 'size'
// //		                label: {
// //		                    'visible': false,
// //		                    'font': {
// //		                    	visible: false,
// //								size: 8
// //							},
// //		                    "connector": {
// //		                        visible: false,
// //		                        width: 1
// //		                    },
// //                            'position': "inside"
// //                            //2020.12.9 SYJIN 버블차트 가로축 생김현상 제거 DOGFOOT
// //							//'customizeText': function(point) {
// //							//	return self.chartEditOptions['getChartLabelCustomizeText'](point);									
// //							//}
// //		                }
// 		            }
// 		        ]
// 			}).dxChart('instance');
			
// 			//2020.12.9 SYJIN 버블차트 가로축 생김현상 제거 DOGFOOT
// 			$(".dxc-grids-group").css('display', 'none');
// 			self.chartList.push(dxChart);
		}
	};
	
	//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
	//2020.11.04 mksong 카카오맵 폴리곤 레이블 설정 기능 변경 dogfoot
	//2020.11.11 syjin 폴리곤 이벤트 커스텀오버레이에 위임 dogfoot
	const getPolygonCenterPath = function(_x, _y, lz_i, map, _v, _locationType, _rateOfTotal, polygon, _isLandCheck){
    	var maxX = Math.max.apply(null, _x);
		var minX = Math.min.apply(null, _x);

		var maxY = Math.max.apply(null, _y);
		var minY = Math.min.apply(null, _y);

		polygonCenter = new Array();

		polygonCenter.push((minX+maxX)/2);
		polygonCenter.push((minY+maxY)/2);
		
		//2020.10.28 mksong 시도 커스텀오버레이 위치값 변경 dogfoot
		if(_locationType == 'Sido'){
			polygonCenter = self.SidoCenterPath[lz_i];
		}
		
        var locationContent = _v;
        
		var totalValue = 0;
        $.each(locationContent, function(vc_i, vc_v){
			totalValue += vc_v[self.measureNames["nameBySummaryType"]];
        });

		var textcolor;
		var addressfontsize;
		var valuefontsize;
		var addressType;
		//2020.10.08 MKSONG 카카오맵 주소타입별 차트 크기 변경 DOGFOOT
		var chartWidth;
		//2020.12.8 SYJIN 파이 차트 크기 조정 DOGFOOT
		var sidoChartSize;
	    var sigunguChartSize;
	    var eupmyeondongChartSize;

		switch(_locationType){
			case 'Sido':
				//textcolor = 'red';
				/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 20201006 */
				textcolor = self.polygonEditOptions['polygonTextOptions']['sido']["textColor"];
				fontsize = self.polygonEditOptions['polygonTextOptions']['sido']["fontSize"];
				addressType = "시도";

                //2020.12.8 SYJIN 파이 차트 크기 조정 DOGFOOT
				chartWidth = self.chartEditOptions['chartWeightEnabled'] ? (_rateOfTotal == 1 ? 550 : _rateOfTotal * 1500) : 550;
				break;
			case 'SiGunGu':
				//textcolor = 'blue';
				/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 20201006 */
				textcolor = self.polygonEditOptions['polygonTextOptions']['sigungu']["textColor"];
				fontsize = self.polygonEditOptions['polygonTextOptions']['sigungu']["fontSize"];
				addressType = "시군구";

				//2020.11.20 mksong dogfoot 카카오지도 차트 크기 편집
				chartWidth = self.chartEditOptions['chartWeightEnabled'] ? (_rateOfTotal == 1 ? 350 : _rateOfTotal * 900) : 350;
				break;
			case 'EupMyeonDong':
				//textcolor = 'blue';
				/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 20201006 */
				textcolor = self.polygonEditOptions['polygonTextOptions']['eupmyeondong']["textColor"];
				fontsize = self.polygonEditOptions['polygonTextOptions']['eupmyeondong']["fontSize"];
				addressType = "읍면동";

				//2020.11.20 mksong dogfoot 카카오지도 차트 크기 편집
				chartWidth = self.chartEditOptions['chartWeightEnabled'] ? (_rateOfTotal == 1 ? 50 : _rateOfTotal * 150) : 50;
				break;
		}
		
		//2020.10.28 mksong 줌에 따른 사이즈 변경 dogfoot
		//2020.12.8 SYJIN 차트 크기 조정 DOGFOOT
		valuefontsize = fontsize / 1.5 / map.getLevel();
		fontsize = fontsize / map.getLevel();
		switch(_locationType){
			case 'Sido':
				if(self.chartEditOptions['chartWeightEnabled']){
					if(self.chartEditOptions.chartType == 'Bubble'){
						chartWidth = chartWidth / (map.getLevel()*0.7);
					}else{
						chartWidth = chartWidth / (map.getLevel()*0.2);
					}
				}else{
					chartWidth = chartWidth / (map.getLevel()*0.9);
				}                
				break;
			case 'SiGunGu':
				if(self.chartEditOptions['chartWeightEnabled']){
					if(self.chartEditOptions.chartType == 'Bubble'){
						chartWidth = chartWidth / (map.getLevel()*0.5);
					}else{
						chartWidth = chartWidth / (map.getLevel()*0.2);
					}
				}else{
					chartWidth = chartWidth / (map.getLevel()*0.7);
				}  
				break;
			case 'EupMyeonDong':
				if(self.chartEditOptions['chartWeightEnabled']){
					chartWidth = chartWidth / (map.getLevel()*0.05);
				}else{
					chartWidth = chartWidth / (map.getLevel()*0.3);
				}  
			    break;
		}
				
		//2020.10.28 mksong 줌에 따른 위치값 변경 dogfoot
		//2020.11.20 syjin 줌에 따른 위치값 변경 dogfoot
		if(map.getLevel() <= 14){
			if(map.getLevel() >= 9){
				switch(lz_i){
					case '세종특별자치시':
					    lz_i = '세종';
					    if(map.getLevel() == 9){
					    	lz_i = '세종특별자치시';
					    	polygonCenter = [127.25349079643084, 36.57711719373759];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '세종특별자치시';
					    	polygonCenter = [127.25597922675053, 36.57278638365103];
					    }
					    else if(map.getLevel() == 11){
							polygonCenter = [127.2557044514521, 36.59787478732297];
						}
						else if(map.getLevel() == 12){
							polygonCenter = [127.24993780618354, 36.584045478604914];
						}else{
							polygonCenter = [127.309195324698, 36.6090649113762];
						}
						
						break;
					case '인천광역시':
					    if(map.getLevel() == 9){
					    	lz_i = '인천광역시';
					    	polygonCenter = [126.46549243712526, 37.601808647495005];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '인천광역시';
					    	polygonCenter = [126.43291703962414, 37.59675528907219];
					    }
					    else if(map.getLevel() == 11){
					    	lz_i = '인천';
							polygonCenter = [126.41551587620765, 37.59782365029269];
						}
						else{
						    polygonCenter = [126.42148773974, 37.4473487903571];
						}
						break;
					case '대전광역시':
					    lz_i = '대전';
						if(map.getLevel() == 9){
					    	lz_i = '대전광역시';
					    	polygonCenter = [127.39044751649243, 36.36796740731156];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '대전광역시';
					    	polygonCenter = [127.39217391024224, 36.35671511647813];
					    }
					    else if(map.getLevel() == 11){
							polygonCenter = [127.40601056372498, 36.34369199393485];
						}
						else if(map.getLevel() == 12){
							polygonCenter = [127.383789715873, 36.3054987200544];
						}else{
							polygonCenter = [127.383789715873, 36.1554987200544];
						}
						break;
					case '울산광역시':
					    lz_i = '울산';
					    if(map.getLevel() == 9){
					    	lz_i = '울산광역시';
					    	polygonCenter = [129.25380414215698, 35.57232140748589];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '울산광역시';
					    	polygonCenter = [129.23206202208277, 35.57733964369162];
					    }
						else if(map.getLevel() == 11){
							polygonCenter = [129.2484468923755, 35.5574276459904];
						}
						else if(map.getLevel() == 12){
							polygonCenter = [129.24536818525885, 35.54825804021384];
						}else{
							polygonCenter = [129.330091790832, 35.5938097037164];
						}
						
						break;
					case '광주광역시':
					    lz_i = '광주';
						if(map.getLevel() == 9){
					    	lz_i = '광주광역시';
					    	polygonCenter = [126.83244747666886, 35.16929783838361];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '광주광역시';
					    	polygonCenter = [126.81701909940197, 35.157161270327165];
					    }
						else if(map.getLevel() == 11){
							polygonCenter = [126.85212128409184, 35.16759284607902];
						}
						else if(map.getLevel() == 12){
							polygonCenter = [126.82966023674268, 35.15833344132944];
						}else{
							polygonCenter = [126.890107526298, 35.2023722691304];
						}
						
						break;
					case '강원도':
						lz_i = '강원';
						if(map.getLevel() == 9){
							lz_i = '강원도';
						}
						else if(map.getLevel() == 10){
					    	 lz_i = '강원도';
					    	polygonCenter = [128.2807144151892, 37.75492031592439];
					    }else{
						    polygonCenter = [128.2756258054575, 37.71230823440496];
					    }
						break;
					case '경기도':
						lz_i = '경기';
						if(map.getLevel() == 9){
					    	lz_i = '경기도';
					    	polygonCenter = [127.34289883939215, 37.38368529840591];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '경기도';
					    	polygonCenter = [127.39014836920559, 37.437167228222016];
					    }
						else if(map.getLevel() == 11){
							polygonCenter = [127.31607637106694, 37.36357714151331];
						}
						else if(map.getLevel() == 12){
							polygonCenter = [127.34507997560975, 37.386562215891324];
						}else{
							polygonCenter = [127.38000092016145, 37.2772675901776];
						}
						
						break;
					case '충청북도':
						lz_i = '충북';
						if(map.getLevel() == 9){
					    	lz_i = '충청북도';
					    	polygonCenter = [127.74556446921406, 36.88532248391118];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '충청북도';
					    	polygonCenter = [127.78673131582228, 36.909277931258075];
					    }
						else if(map.getLevel() == 11){
							polygonCenter = [127.73851532286606, 36.82423701382696];
						}
						else if(map.getLevel() == 12){
							polygonCenter = [127.74423137398583, 36.821894588743746];
						}else{
							polygonCenter = [127.990480041094, 36.8303218849121];
						}
						
						break;
					case '충청남도':
						lz_i = '충남';
						if(map.getLevel() == 9){
					    	lz_i = '충청남도';
					    	polygonCenter = [126.7922885536952, 36.57143841949843];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '충청남도';
					    	polygonCenter = [126.85120335138282, 36.609879183070575];
					    }
					    else if(map.getLevel() == 11){
							polygonCenter = [126.81234510324275, 36.55647658744213];
						}
						else if(map.getLevel() == 12){
							polygonCenter = [126.80940626652156, 36.58876899275038];
						}else{
							polygonCenter = [126.65200021685, 36.5592146952303];
						}
						
						break;
					case '경상북도':
						lz_i = '경북';
						if(map.getLevel() == 9){
					    	lz_i = '경상북도';
					    	polygonCenter = [128.73901220043763, 36.4995388998297];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '경상북도';
					    	polygonCenter = [128.6899568412058, 36.51004738567386];
					    }else{
						    polygonCenter = [128.797077816076, 36.4527164442425];
					    }
						break;
					case '경상남도':
						lz_i = '경남';
						if(map.getLevel() == 9){
					    	lz_i = '경상남도';
					    	polygonCenter = [128.22667484491308, 35.43199751031871];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '경상남도';
					    	polygonCenter = [128.23265630445695, 35.408287744372096];
					    }
						break;
					case '전라북도':
						lz_i = '전북';
						if(map.getLevel() == 9){
					    	lz_i = '전라북도';
					    	polygonCenter = [127.11920403904979, 35.73292961418227];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '전라북도';
					    	polygonCenter = [127.09163761735573, 35.753719072896985];
					    }else{
						    polygonCenter = [127.16806103969762, 35.75363658067618];
					    }
						break;
					case '전라남도':
						lz_i = '전남';
						if(map.getLevel() == 9){
					    	lz_i = '전라남도';
					    	polygonCenter = [126.95200565662486, 34.94961304595975];
					    }
					    else if(map.getLevel() == 10){
					    	 lz_i = '전라남도';
					    	polygonCenter = [126.87496958548711, 34.92648254804025];
					    }
					    else if(map.getLevel() == 11){
							polygonCenter = [126.8582203143176, 34.89069676170707];
						}
						else if(map.getLevel() == 12){
							polygonCenter = [126.90864101300654, 34.881514774466005];
						}else{
							polygonCenter = [126.879977043574, 34.7654607621149];
						}
						
						break;
				}
				
			}
			
			if(map.getLevel() > 11){
				if(lz_i.indexOf('광역시') != -1 || lz_i.indexOf('특별자치') != -1 || lz_i.indexOf('특별시') != -1){
					lz_i = lz_i.substr(0,2);	
				}
			}
			
			//2020.11.04 mksong 카카오맵 폴리곤 레이블 설정 기능 변경 dogfoot
			 /* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 구분 id 설정 20201112 */
			var index = polygon.polygonTextCount;
			var chartPosition = self.chartEditOptions.chartType == 'Bubble' ? 'relative' : '';
			
			var content = '<div id="textCustom'+ index +'" class ="polygon-label label" address="'+ lz_i +'" style="text-align:center; position:'+chartPosition+'">';
			_rateOfTotal = Math.round(_rateOfTotal * 100);
			switch(self.polygonEditOptions['polygonLabelOptions']['type']){
				case "없음":
					break;
					case "지역명":
						content += '<span class="left"></span><span class="center" style="font-size:' + fontsize + 'px; color:' + textcolor + ';">' +lz_i + '</span><br>';
						break;
					case "값":
						content += '<span style="font-size:' + valuefontsize + 'px; color:' + textcolor + ';">'+totalValue+'</span>';
						break;
					case "%":
						content += '<span style="font-size:' + valuefontsize + 'px; color:' + textcolor + ';">'+_rateOfTotal+'%</span>';
					break;
					case "지역명 및 값":
						content += '<span class="left"></span><span class="center" style="font-size:' + fontsize + 'px; color:' + textcolor + ';">' +lz_i + '</span>';
						content += '<br>';
						content += '<span style="font-size:' + valuefontsize + 'px; color:' + textcolor + ';">'+totalValue+'</span>';
					break;
					case "값 및 %":
						content += '<span style="font-size:' + valuefontsize + 'px; color:' + textcolor + ';">'+totalValue+'</span>';
						content += '<br>'
						content += '<span style="font-size:' + valuefontsize + 'px; color:' + textcolor + ';">'+_rateOfTotal+'%</span>';
					break;
					case "지역명 및 %":
						content += '<span class="left"></span><span class="center" style="font-size:' + fontsize + 'px; color:' + textcolor + ';">' +lz_i + '</span>';
						content += '<br>';
						content += '<span style="font-size:' + valuefontsize + 'px; color:' + textcolor + ';">'+_rateOfTotal +'%</span>';
					case "지역명, 값 및 %":
						content += '<span class="left"></span><span class="center" style="font-size:' + fontsize + 'px; color:' + textcolor + ';">' +lz_i + '</span>';
						content += '<br>';
						content += '<span style="font-size:' + valuefontsize + 'px; color:' + textcolor + ';">'+totalValue+'</span>';
						content += '<br>';
						content += '<span style="font-size:' + valuefontsize + 'px; color:' + textcolor + ';">'+_rateOfTotal +'%</span>';
					break;
			}
			
			//2020.11.20 MKSONG 카카오맵 지역명 id 띄어쓰기 오류 수정 DOGFOOT
			var loactionId = lz_i.replace(/\ /g,"");
			
			//2020.12.8 SYJIN 버블 차트 위치 수정 DOGFOOT
			if(self.chartEditOptions.chartType == 'Bubble') {
				if(self.chartEditOptions.chartWeightEnabled){
				    content += '<div id="chartView' + loactionId + '" address="'+ lz_i + '" class="polygon-chart" style="position:relative; top:-60px;"></div></div>';	
				}else{
					content += '<div id="chartView' + loactionId + '" address="'+ lz_i + '" class="polygon-chart" style="position:absolute; top:-100%; left:-200%;"></div></div>';
				}				
			}else{
				content += '<div id="chartView' + loactionId + '" address="'+ lz_i + '" class="polygon-chart" style="margin-left: 20%;"></div></div>';
			}
			
			// 커스텀 오버레이가 표시될 위치입니다 
			var position = new kakao.maps.LatLng(polygonCenter[1], polygonCenter[0]);   
	
			// 커스텀 오버레이를 생성합니다
			var customOverlay = new kakao.maps.CustomOverlay({
				position: position,
				content: content   
			});
	
			// 커스텀 오버레이를 지도에 표시합니다
			//DOGFOOT syjin 2020-11-30 인천 텍스트 표시 수정
			if(!_isLandCheck){
				customOverlay.setMap(map);
			}			
			
			//2020.11.11 syjin 폴리곤 이벤트 커스텀오버레이에 위임 dogfoot
 			//$(customOverlay.a).on('mouseover', mouseOverHandler);
			//$(customOverlay.a).on('mouseout', mouseOutHandler);
			
			//$(customOverlay.a).on('mouseover', polygon['mouseover']);
			//$(customOverlay.a).on('mouseout', polygon['mouseout']);
			//$(customOverlay.a).on('click', polygonClickHandler);
			//2020.11.11 syjin 폴리곤 텍스트 이벤트 수정 dogfoot
			//2020.11.12 syjin 폴리곤 텍스트 마스터 필터 오류 수정 dogfoot
			if(!polygon['masterFilterCheck']){
				$("#textCustom" + index).on('mouseover', polygon['mouseover']);
			    $("#textCustom" + index).on('mouseout', polygon['mouseout']);
			}		    
			$("#textCustom" + index).on('click', polygon['mouseclick']);

			polygon['textCustom'] = "#textCustom" + index;
			//2020.11.12 syjin 카카오맵 드래그 해서 툴팁 안나오는 오류 수정 dogfoot
			customOverlay['textCustom'] = "#textCustom" + index;
			customOverlay['mouseout'] = polygon['mouseout'];
			customOverlay['mouseover'] = polygon['mouseover'];
			customOverlay['mouseclick'] = polygon['mouseclick'];
			customOverlay['masterFilterCheck'] = polygon['masterFilterCheck'];
			
			//2020.10.29 mksong 카카오맵 화면에 가려진 차트 안나오는 오류 수정 dogfoot
			customOverlay.chartInfo = {
				locationName : lz_i,
				value : _v,
				chartWidth : chartWidth 
			};
			
			//2020.09.29 mksong 줌 레벨에 따른 addressType 동기화 dogfoot
			self.customOverlayList.push(customOverlay);
		}
		
		//2020.10.29 syjin dogfoot 카카오지도 차트 표시 유무 수정	
		//2020.10.19 mksong dogfoot 카카오지도 차트 타입별 렌더
		switch(self.chartEditOptions.chartType){
			case 'Pie':
				self.renderPie(lz_i, _v, chartWidth);
				//DOGFOOT syjin 2020-12-03 카카오 지도 여러개 있을 때 , 차트 표시 하나의 아이템에만 적용되는 오류 수정 
				if(self.polygonEditOptions.polygonChartCheck){
				    $("#"+self.Map.ComponentName).find('.polygon-chart').css('visibility', 'inherit');
				}else{
				    //$("#"+self.Map.ComponentName).find('.polygon-chart').css('visibility', 'hidden');
					$("#"+self.Map.ComponentName).find('.polygon-chart').css('display', 'none');
				}
				break;
			case 'Bubble':
				self.renderBubble(lz_i, _v, chartWidth);
				if(self.polygonEditOptions.polygonChartCheck){
				    $("#"+self.Map.ComponentName).find('.polygon-chart').css('visibility', 'inherit');
				}else{
				    //$("#"+self.Map.ComponentName).find('.polygon-chart').css('visibility', 'hidden');
					$("#"+self.Map.ComponentName).find('.polygon-chart').css('display', 'none');
				}
				break;
		}
		
		return position;
    };

	//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
	const createPolygonPath = function(_x, _y){
    	return new kakao.maps.LatLng(_y, _x);
    };
    
    //2020.10.28 mksong 섬 체크  dogfoot
	const createPolygon = function(map, _locationObject, _locationType, _locationDataArray, _locationName, _locationFullName, _isLandCheck){
		var polygonPath = [];
        var pathX = new Array();
        var pathY = new Array();
        
        //2020.10.19 mksong dogfoot 카카오지도 차트 옵션 반영
        //2020.11.03 MKSONG 카카오맵 폴리곤 투명도 가중치 설정 DOGFOOT
		var fillOpacity = (self.polygonEditOptions.polygonOpacityWeight / 100);
		var totalLocationName = _locationFullName.substr(0, _locationFullName.lastIndexOf(':'));
		var totalValue = 0;
		//2020.11.04 mksong 카카오맵 폴리곤 레이블 설정 기능 변경 dogfoot
		var rateOfTotal;
		//2020.10.30 dogfoot 마스터 필터 체크 여부 확인
		var masterFilterCheck = false;
		
		//2020.10.29 syjin 카카오맵 폴리곤 index 추가 dogfoot
		var polygonLength = self.getPolygonLength();
		var index = (self.polygons[_locationType].length)%polygonLength[_locationType];
		
        $.each(self.polygonMfList, function(pm_i, pm_v){
			if(pm_v['name'] == _locationFullName){
				masterFilterCheck = true;
				return false;
			}
		})

        $.each(_locationDataArray,function(vc_i, vc_v){
			totalValue += vc_v[self.measureNames["nameBySummaryType"]];
        });
		
		$.each(_locationObject, function(lz_i, lz_v){
            for(var i=0; i<lz_v.length; i++){
            	polygonPath.push(createPolygonPath(lz_v[0], lz_v[1]));
            	pathX.push(lz_v[0]);
            	pathY.push(lz_v[1]);
            }
		});
		
		//2020.10.08 MKSONG 카카오맵 투명도 조정 기능 옵션 추가 DOGFOOT
//		if(self.polygonEditOptions['polygonOpacityEnabled'] || self.chartEditOptions['chartWeightEnabled']){
			var GrandTotalValue;
			switch(self.polygonEditOptions['polygonOpacityOption']){
				case 'addressType':
					switch(_locationType){
						case 'Sido' :
							GrandTotalValue = self.dataSetGroupByAddressType['total_'+self.measureNames.nameBySummaryType];
							break;
						case 'SiGunGu' :
							GrandTotalValue = self.dataSetGroupByAddressType['sidoDataSet'][totalLocationName+'_total_'+self.measureNames.nameBySummaryType];
							break;
						case 'EupMyeonDong' :
							GrandTotalValue = self.dataSetGroupByAddressType['siGunGuDataSet'][totalLocationName+'_total_'+self.measureNames.nameBySummaryType];
							break;
					}
					break;
				case 'rateType':
					GrandTotalValue = self.dataSetGroupByAddressType['total_'+self.measureNames.nameBySummaryType];
					break;
			}
			
			//2020.11.06 MKSONG 카카오맵 폴리곤 투명도 오류 수정 DOGFOOT
			if(self.polygonEditOptions['polygonOpacityEnabled']){
				//2020.11.03 MKSONG 카카오맵 폴리곤 투명도 가중치 설정 DOGFOOT
				fillOpacity = (self.polygonEditOptions.polygonOpacityWeight / 10) * (totalValue / GrandTotalValue) ;	
			}else{
				fillOpacity = 0.7;
			}
						
			rateOfTotal = totalValue / GrandTotalValue;
			
//		}
		
		//2020.10.12 syjin 폴리곤 채우기 색깔 초기화 설정
        var fillColor;
        
         //2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
        var setInitBgColor = function(_locationType, _index){
        	var fillColor;
        	
        	switch(_locationType){
				case 'Sido':
					fillColor = '#CFE7FF';
					break;
				case 'SiGunGu':
					//fillColor = '#FF8AEF';
					fillColor = '#FF99FF';
					break;
				case 'EupMyeonDong':
					//fillColor = '#A2FF99';
					fillColor = '#CCFFCC';
					break;
			} 
			
			//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
        	if(!self.polygonEditOptions.polygonPaletteCheck){
				$.each(self.polygonEditOptions.polygonBgColorOptions[_locationType], function(pl_i, pl_v){
					$.each(pl_v['listName'], function(ln_i, ln_v){
						if(ln_v == _locationFullName){
							fillColor = pl_v['bgColor'];
						}
					});
				});
			}else{
				var paletteType = self.polygonEditOptions.polygonPaletteOptions[_locationType.toLowerCase()].Palette;
				var palette = paletteType == 'Custom' ? self.polygonEditOptions.polygonPaletteOptions[_locationType.toLowerCase()].CustomPalette.Color : DevExpress.viz.getPalette(paletteType).simpleSet;
				
				fillColor = palette[_index % palette.length]; 
			}

			return fillColor;
        }

		//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
		
		//2020.11.20 mksong 카카오맵 colorindex 추가 dogfoot
		var colorIndex = self.getColorIndex(_locationFullName);
        fillColor = setInitBgColor(_locationType, colorIndex);
					
		//2020.10.30 dogfoot 마스터 필터 체크 여부에 따른 테두리 설정
		var polygon = new kakao.maps.Polygon({
			path:polygonPath, // 그려질 다각형의 좌표 배열입니다
			strokeWeight: masterFilterCheck?7:1, // 선의 두께입니다
//				strokeColor: '#75B8FA', // 선의 색깔입니다
			strokeOpacity: 0.8, // 선의 불투명도 입니다 1에서 0 사이의 값이며 0에 가까울수록 투명합니다
			strokeStyle: 'solid', // 선의 스타일입니다
			fillColor: masterFilterCheck ? '#e1e10f' : fillColor, // 채우기 색깔입니다
			fillOpacity: fillOpacity // 채우기 불투명도 입니다
		});
		
		//2020.11.12 syjin 폴리곤 텍스트 마스터 필터 오류 수정 dogfoot
		polygon['index'] = index;
		 /* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 구분 id 설정 20201112 */
		polygon['polygonTextCount'] = self.polygonTextCount++;
		polygon['masterFilterCheck'] = masterFilterCheck;
		 /* DOGFOOT syjin 카카오 지도 속성 오류 수정 20201112 */
		polygon['fillColor'] = fillColor;

		//2020.11.11 syjin 카카오맵 마우스오버, 아웃 이벤트 객체에 추가 dogfoot
		var mouseOverHandler = function(){
			var option = {
				strokeWeight : 7,
				strokeStyle : 'solid'
		    }
            
            //2020.12.10 SYJIN 폴리곤 하위 섬 마우스 오버 이벤트 적용
            $.each(self.polygons[_locationType], function(_i, _v){
            	if(_v.locationFullName == polygon.locationFullName){
                    _v.setOptions(option);		
            	}
            })
		    //polygon.setOptions(option);
		}
//		
        var mouseOutHandler = function(){
			var option = {
				//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
				//strokeColor : polygon.Eb[0].strokeColor,
				strokeColor : polygon.strokeColor,
				strokeWeight : 1,
				strokeStyle : 'solid'
			}

			//2020.12.10 SYJIN 폴리곤 하위 섬 마우스 오버 이벤트 적용
            $.each(self.polygons[_locationType], function(_i, _v){
            	if(_v.locationFullName == polygon.locationFullName){
                    _v.setOptions(option);		
            	}
            })
		    //polygon.setOptions(option);
		}	
        
        var mouseClickHandler = function(e){
			//2020.10.29 mksong 카카오맵 폴리곤 툴팁 추가 dogfoot
			if(self.polygonEditOptions.tooltipCheck){
				//2020.11.23 syjin 폴리곤 툴팁 하나만 나오도록 수정 dogfoot
				if(self.customOverlay.length != 0){
					$.each(self.customOverlay, function(co_i, co_v){
						co_v['customOverlay'].setMap(null);
					})

					self.customOverlay = [];
				}
				
				if($('#tooltipLink'+index).length != 1){
					// 마커 위에 인포윈도우를 표시합니다
					var position = polygon.tooltipLatLng;
					var title = polygon.locationFullName;
					var content = '';

					var values = polygon['polygonData'];
					
					var datasetConfig = self.SQLike.fromJson(self.markerDimensions, self.measures, values);
					var selectConfig = [];
					
					$.each(self.markerDimensions, function(_i, _markerDimension){
						selectConfig.push(_markerDimension.caption);
						selectConfig.push('|as|');
						selectConfig.push(_markerDimension.caption);
					});
					
					$.each(self.measures, function(_i, _measure){
						selectConfig.push('|sum|');
						selectConfig.push(_measure.nameBySummaryType);
						selectConfig.push('|as|');
						selectConfig.push(_measure.caption);
					});
					
					datasetConfig.Select = selectConfig;
					datasetConfig.Where = undefined;
					var sqlLikeData = SQLike.q(datasetConfig);
					
					var grandTotal = 0;
					$.each(sqlLikeData, function(_i,_value){
						grandTotal += _value[self.measureNames.nameBySummaryType[0]];
					});
					
					//2020.09.28 mksong 주소타입 변경했을 경우 차트 오류 수정 dogfoot
					var colspan = self.Map.LocationType == 'address' ?  _.keys(values[0]).length * 2 : 2;
					
					//2020.10.15 syjin 마커 즐겨찾기 이미지 추가 dogfoot
					var favoriteSrc = "data:image/png;base64,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";

					//2020.09.24 mksong 데이터 정보 차트보기 dogfoot
					//line-height:30px; vertical-align:middle;
					//2020.11.05 syjin dogfoot 카카오지도 툴팁 그림자 추가
					content = '<div id="tooltipLink' + index + '" class="wrap custom-wrap" style="box-shadow: 0 0 10px 1px #544d4d;">' + 
						'    <div class="info"'+(self.Map.LocationType == 'coordinate' ? 'style="width:300px;"' : '') + '>' + 
						//2020.10.23 syjin 타이틀 디스플레이 수정 dogfoot
						'        <div class="title" style="display:flex; justify-content:space-between; align-items:flex-start;">' +
						'			<div style="margin-right:24px;">' +
						'				<span style=" color:#ffffff; line-height:30px; vertical-align:middle;">데이터 정보</span>' +
						'			</div>' +
						//2020.09.25 syjin 카카오맵 툴팁 url연결 주석처리 dogfoot
						//'			<div id="urlLink' + marker.index + '" class="btn neutral urlLink" style="min-width:60px;font-size:12px;border-radius:5px;line-height:30px;vertical-align:middle;right: 100px;position: absolute;">URL 연결</div>' +
						//2020.10.16 syjin 카카오맵 툴팁 마스터 필터 아이콘 추가 dogfoot
						//markerMasterFilter에 marker.index 추가
						//2020.11.05 syjin dogfoot 카카오지도 툴팁 타이틀 ui 수정
						'			<div style="display:flex;">' +		
							'			<div style="margin-right:24px;">' +			
							/* DOGFOOT syjin editds 수정 20201120 */
							'				<div id="polygonMasterFilter'+ index + '" class="btn" style="min-width:30px;margin:0px;"><img style="width:30px;" src="' + WISE.Constants.context + '/resources/main/images/ico_singleMasterFilter.png"/></div>' +
							//2020.11.02 syjin 카카오맵 폴리곤 툴팁 즐겨찾기 아이콘 삭제 dogfoot
							//'				<div id="favorite' + index + '" class="btn" style="min-width:30px;line-height:30px;vertical-align:middle;margin:0px;"><img style="width:30px;" src="'+ favoriteSrc +'"/></div>' +
							//2020.11.20 MKSONG 카카오맵 툴팁 아이콘 수정 DOGFOOT
							'				<div id="chartViewLink' + index + '" class="btn" style="min-width:30px; margin:0px; line-height:0px; vertical-align:middle;"><img style="width:30px;" src="'+WISE.Constants.context+'/resources/main/images/ico_pie.png"/></div>' +
							'			</div>' +
							'			<div>' +
							'           	<div class="close" id="close' + index + '" style="position:static; margin-right:5px;" title="닫기">&times</div>' +
							'			</div>' +	
						'			</div>' +
						'        </div>' +
						'        <div class="body">' +
						'        	<div id="description' + index + '" class="desc">';
					 //2020.09.24 mksong 카카오맵 툴팁 로케이션에 따라 동기화  dogfoot
// 					 content += 		'<table class="tableInfo" style="border-collapse: collapse; text-align: left; line-height: 1.5; border: 1px solid #ccc; width:100%;">';
// 					 if(self.Map.LocationType == 'address'){
// 												//데이터 영역
// 						 content +=			'<thead style= "border-right: 1px solid #ccc; border-left: 1px solid #ccc; background: #ffcd36;">' +
// 												'<tr>' +
// 													'<th scope="cols" colspan="' + colspan + '" style="padding: 5px; font-weight: bold; vertical-align: top; color: #000;">' +
// 														'데이터' +
// 													'</th>' +
// 												'</tr>' +
// 											'</thead>' +
// 											'<tbody>';
// 						//2020.09.24 mksong 카카오맵 주소 데이터 툴팁 수정  dogfoot
// 						$.each(sqlLikeData,function(_i, _data){
// 							content +=			'<tr>';
// 							$.each(_.keys(_data), function(_ii,_key){
// 								//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
// 								var key = self.measureNames.nameBySummaryType[0] == _key ? self.measureNames.name[0] : _key;

// 								content +=			'<th scope="row" style="padding: 5px; font-weight: bold; vertical-align: top; border-bottom: 1px solid #ccc; background: #fcf1f4;">' +
// 														key +
// 													'</th>' +
// 													'<td style="padding: 5px; vertical-align: top; border-bottom: 1px solid #ccc;">' +
// 														_data[_key] +
// 													'</td>';
// 							});
// 							content +=			'</tr>';
// 						});
// 						content +=				'<tr>' +
// 													'<th scope="row" style="padding: 5px; font-weight: bold; vertical-align: top; border-bottom: 1px solid #ccc; background: #fcf1f4;">' +
// 														'합계' +
// 													'</th>' +
// 													'<td style="padding: 5px; vertical-align: top; border-bottom: 1px solid #ccc;">' +
// 														grandTotal +
// 													'</td>' +
// 												'</tr>';
// 						content +=			'</tbody>';
// 					 }

// 					content +=			'</table>';	
                    content +=       
                        '            <div id="polygonDataGrid'+index+'"></div>';
					content +=			
						'            </div>' +
						//2020.09.24 mksong 데이터 정보 차트보기 dogfoot
						'			 <div id="chartView'+index+'" class="chartView" style="display:none;">' +
						'			 </div>' +		
						'        </div>' + 
						'    </div>' +    
						'</div>';

					//self.setButton("mapUrl", "새창으로 열기");
					
					var createCustomOverlay = function(_position, _content){
						var customOverlay = new kakao.maps.CustomOverlay({
							position:_position,
							content : _content,
						});
	
						return customOverlay;
					};
					
					var customOverlay = createCustomOverlay(position, content);

					var customOverlayObject = {
						'id' : index,
						'customOverlay' : customOverlay 
					};
					
					self.setCustomOverlay(customOverlay, map, self.polygonEditOptions.tooltipCheck);
					self.customOverlay.push(customOverlayObject);
					
                    //2020.11.20 MKSONG 카카오맵 렌더그리드 추가 DOGFOOT				
 					self.renderGrid(index, sqlLikeData);

					$(".custom-wrap").parent().css("z-index", 9999);

					var closeOverlay = function(_overlay, id){
						_overlay.setMap(null);
						//2020.10.14 syjin customOverlay 객체 삭제 dogfoot	
						$.each(self.customOverlay, function(_i, _v){
							if(id == _v['id']){
								self.customOverlay.splice(_i, 1);
							}
						})

						//2020.11.24 syjin dogfoot 툴팁 사용 후, X버튼 눌러 툴팁 없앨때, 툴팁 누르기전 기본위치로 이동		
						//DOGFOOT syjin 2020-11-27 툴팁 표시 시 폴리곤 load 오류 수정
						//self.map.panTo(moveLatLon);	
						//DOGFOOT syjin 2020-11-30 한반도만 보이도록 체크된 상태로 커스텀오버레이 닫았을 때 줌레벨 조정
						if(self.polygonEditOptions['hanbandoCheck']){
                            self.map.setCenter(new kakao.maps.LatLng(35.94522067302675, 127.74940032415145));
                            self.map.setLevel(14);                           
						}else{
							self.map.setCenter(self.beforClickTooltipCenter);	
						}
						
						self.drawByChanged();
						//self.map.panTo(self.beforClickTooltipCenter);
					};

					$("#close" + index).click(function(){
						//2020.10.14 syjin polygon.index 매개변수 추가 dogfoot
						closeOverlay(customOverlay, "close"+index);
					});

					/* DOGFOOT syjin 카카오 지도 마커 클릭 이벤트 추가(마스터 필터)  20200925 */
					/* DOGFOOT syjin 카카오 지도 마스터 필터 오른쪽 클릭 이벤트로 변경  20201013 */
					/* DOGFOOT syjin 카카오 지도 마스터 필터 툴팁 아이콘 클릭 시 적용되도록 변경  20201019 */
					$("#polygonMasterFilter"+ index).click(function(){
						//2020.11.17 mksong 카카오맵 마스터필터 기능 수정 dogfoot
						self.masterFiltering(polygon);
					});

					//2020.09.24 mksong 데이터 정보 차트보기 dogfoot
					$("#chartViewLink" + index).click(function(){
						$('#description'+ index).toggle();
						$('#chartView'+ index).toggle();

						if($('#chartViewLink'+ index).find('img').attr('src') == WISE.Constants.context + "/resources/main/images/ico_pie.png"){
							$("#chartViewLink" + index).find('img').attr({
								src : WISE.Constants.context+"/resources/main/images/ico_basicGrid.png",
								style : "width:30px"
							})
							//2020.09.28 mksong 주소타입 변경했을 경우 차트 오류 수정 dogfoot
							if(self.Map.LocationType == 'coordinate'){
								$('#tooltipLink'+index).find('.info').width('400px');
							}
						}else{
							//$('#chartViewLink'+ polygon.index).text('차트');

							$("#chartViewLink" + index).find('img').attr({
								//src : "WISE.Constants.context/resources/main/images/ico_basicGrid.png",
								src : WISE.Constants.context+"/resources/main/images/ico_pie.png",
								style : "width:30px"
							})
							//2020.09.28 mksong 주소타입 변경했을 경우 차트 오류 수정 dogfoot
							if(self.Map.LocationType == 'coordinate'){
								$('#tooltipLink'+index).find('.info').width('300px');
							}
						}
						
						//2020.11.20 MKSONG 카카오맵 툴팁 파이 오류 수정 DOGFOOT
						self.renderPie(index, sqlLikeData, 380, true);
					});
				}else{
					//2020.10.08 MKSONG 카카오맵 마커 trigger 기능 변경 DOGFOOT
					$('#tooltipLink'+index).show();
				}
			}else{
				//2020.11.17 mksong 카카오맵 마스터필터 기능 수정 dogfoot
				self.masterFiltering(polygon);
			}						
        }
        
        polygon['mouseover'] = mouseOverHandler;
        polygon['mouseout'] = mouseOutHandler;
        polygon['mouseclick'] = mouseClickHandler;
        
		//2020.10.29 mksong 카카오맵 폴리곤 툴팁 추가 dogfoot
		var polygonTooltipLatLng;
        
		//2020.10.28 mksong 섬 체크  dogfoot
		//2020.11.23 syjin 인천광역시 텍스트 지도에 안나오는 오류 수정  dogfoot		
		//2020.11.11 syjin 폴리곤 이벤트 커스텀오버레이에 위임 dogfoot
		//2020.11.11 syjin mouseListner 매개변수 변경 dogfoot
		//DOGFOOT syjin 2020-11-30 인천 텍스트 표시 수정
		polygonTooltipLatLng = getPolygonCenterPath(pathX, pathY, _locationName, map, _locationDataArray, _locationType, rateOfTotal, polygon, _isLandCheck);	
		
		
		//2020.11.11 syjin 폴리곤 이벤트 커스텀오버레이에 위임 dogfoot
          
               
		/* DOGFOOT syjin 카카오 지도 폴리곤 색상 설정 20201008 */
		var polygonObject = {
			"locationName" : _locationFullName,
			/* DOGFOOT syjin 카카오 지도 속성 오류 수정 20201112 */
			"bgColor" : polygon.fillColor
		};

        //2020.10.20 syjin dogfoot 카카오지도 polygon 속성 추가
        polygon['locationFullName'] = _locationFullName;
        polygon['locationType'] = _locationType;
		
		//2020.10.29 mksong 카카오맵 폴리곤 툴팁 추가 dogfoot
		polygon['tooltipLatLng'] = polygonTooltipLatLng;
		polygon['polygonData'] = _locationDataArray;            
        
		self.polygons[_locationType].push(polygon);     

		switch(_locationType){
			case 'Sido':
				//polygon.Db[0].strokeColor = '#FFF';
				//polygon.Db[0].fillColor = '#CFE7FF';
				//2020.11.02 syjin 카카오맵 폴리곤 선 색상 초기화 설정dogfoot
				//polygon.Db[0].strokeColor = self.polygonEditOptions.polygonLineOptions.sido.lineColor;
				 /* DOGFOOT syjin 카카오 지도 속성 오류 수정 20201112 */
				polygon.setOptions({
					strokeColor : self.polygonEditOptions.polygonLineOptions.sido.lineColor
				})
				
				//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
				polygon['strokeColor'] = self.polygonEditOptions.polygonLineOptions.sido.lineColor;
				break;
			case 'SiGunGu':
				//polygon.Db[0].strokeColor = '#FFF';
				//polygon.Db[0].fillColor = '#FF8AEF';
				//2020.11.02 syjin 카카오맵 폴리곤 선 색상 초기화 설정dogfoot
				//polygon.Db[0].strokeColor = self.polygonEditOptions.polygonLineOptions.sigungu.lineColor;
				 /* DOGFOOT syjin 카카오 지도 속성 오류 수정 20201112 */
				polygon.setOptions({
					strokeColor : self.polygonEditOptions.polygonLineOptions.sigungu.lineColor
				})
				
				//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
				polygon['strokeColor'] = self.polygonEditOptions.polygonLineOptions.sigungu.lineColor;
				break;
			case 'EupMyeonDong':
				//polygon.Db[0].strokeColor = '#FFF';
				//polygon.Db[0].fillColor = '#A2FF99';
				//2020.11.02 syjin 카카오맵 폴리곤 선 색상 초기화 설정dogfoot
				//polygon.Db[0].strokeColor = self.polygonEditOptions.polygonLineOptions.eupmyeondong.lineColor;
				 /* DOGFOOT syjin 카카오 지도 속성 오류 수정 20201112 */
				polygon.setOptions({
					strokeColor : self.polygonEditOptions.polygonLineOptions.eupmyeondong.lineColor
				})
				
				//2020.11.13 syjin 카카오맵 속성 오류 수정 dogfoot
				polygon['strokeColor'] = self.polygonEditOptions.polygonLineOptions.eupmyeondong.lineColor;
				break;
		}
		
		//2020.12.10 SYJIN 폴리곤 하위 섬 마우스 오버 이벤트 적용	
		/* DOGFOOT syjin 카카오 지도 폴리곤 마우스 오버,아웃 이벤트 추가 20201029 */			
// 		if(!masterFilterCheck){
// 		    kakao.maps.event.addListener(polygon, 'mouseover', polygon.mouseover);
// 		    kakao.maps.event.addListener(polygon, 'mouseout', polygon.mouseout);
// 		}
		
 		kakao.maps.event.addListener(polygon, 'click', polygon.mouseclick);
        
	    polygon.setMap(map);
//		$(polygon.Bc).addClass('polygon-area');
//		$(polygon.Bc).attr('address', _locationFullName);
    };
	
	//2020.10.08 MKSONG 카카오맵 주소이름 -> 코드값 DOGFOOT
	this.getSidoCodeBySidoName = function(_sidoName){
		var sidoCode;
		//2020.11.20 mksong geojson 전역처리 dogfoot
		$.each(gDashboard.SidoJson.features, function(f_i, f_v){
			if(f_v.properties['CTP_KOR_NM'] == _sidoName){
				sidoCode = f_v.properties['CTPRVN_CD'];
				return false;
			}
		});
		return sidoCode;
	};
	
	//2020.11.20 MKSONG 카카오맵 시군구코드 조회 추가 DOGFOOT
	this.getSiGunGuCodeBySidoName = function(_sidoCode, _sigunguName){
		var siGunGuCode;
		if(_sigunguName != undefined && _sigunguName != ""){
			//2020.11.20 mksong geojson 전역처리 dogfoot
			$.each(gDashboard.SiGunGuJson.features, function(f_i, f_v){
				if(f_v.properties['SIG_KOR_NM'] == _sigunguName && _sidoCode == f_v.properties['SIG_CD'].substr(0, _sidoCode.length)){
					siGunGuCode = f_v.properties['SIG_CD'];
					return false;
				}
			});	
		}else{
			siGunGuCode = _sidoCode;
		}
		
		return siGunGuCode;
	};
	
	//2020.12.15 mksong 카카오맵 데이터집합 차원컬럼목록 조회 dogfoot
	this.getDimensionColumnList = function(){
		var columnList = [];
		var datasetInfo = gDashboard.dataSourceManager.datasetInformation[self.dataSourceId];
		switch(datasetInfo.DATASET_TYPE){
			case "DataSetSingleDs" :
				if(datasetInfo.DATA_META){
					$.each(datasetInfo.DATA_META, function(_i, _column){
						if(_column.TYPE == 'DIM'){
							columnList.push(_column.CAPTION);
						}
					});
				}else{
					$.each(datasetInfo.SelArea, function(_i, _column){
						if(_column.TYPE == 'DIM'){
							columnList.push(_column.CAPTION);
						}
					});	
				}
				break;
			case "DataSetSQL":
				$.each(datasetInfo.DATA_META, function(_i, _column){
					if(_column.TYPE == 'DIM'){
						columnList.push(_column.CAPTION);
					}
				});
				break;
		}
		return columnList;
	};
	
	//2020.09.28 mksong 폴리곤을 위한 데이터 처리방식 수정 dogfoot
	this.setPolygonByDataset = function(locationType){
		self.stateAddressType = locationType;
		switch(locationType){
			case 'Sido':    
				//시도 일때
				$.each(self.dataSetGroupByAddressType['sidoDataSet'], function(_key,_v){
					//2020.10.19 mksong dogfoot 카카오지도 지역별 합계 키 예외 처리
					 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
					//if(!_key.includes('total')){
					if(_key.indexOf('total') == -1){
						//2020.11.20 mksong geojson 전역처리 dogfoot
						$.each(gDashboard.SidoJson.features, function(f_i, f_v){
	                		var jsonLocation = f_v.properties['CTP_KOR_NM'];
	                		
	                		 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
	                		//if(jsonLocation.includes(_key)){
	                		if(jsonLocation.indexOf(_key) != -1){
								self.locationObject.locationSido[_key] = f_v.geometry.coordinates;
	                		}
	                	});

						//2020.10.28 mksong 메인 좌표그룹 체크 dogfoot
						var isTheLongestLength = 0;
						$.each(self.locationObject.locationSido[_key], function(_i, _coordinateArray){
							if(_i > 0){
								if(_coordinateArray.length > self.locationObject.locationSido[_key][_i-1].length){
									isTheLongestLength = _i;
								}	
							}else if(_i == 0){
								isTheLongestLength = _i;
							}
						});
						
						$.each(self.locationObject.locationSido[_key], function(_i, _coordinateArray){
							//2020.12.8 SYJIN 인천 텍스트 오류 수정 DOGFOOT
							if(_i == isTheLongestLength && _key != '전라남도' && _key != '인천광역시'){
								//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
								if(self.checkPolygonInArea(_coordinateArray)){
									createPolygon(self.map, _coordinateArray, locationType, self.dataSetGroupByAddressType['sidoDataSet'][_key],_key, _key, false);
								}
							}else{
								if((_key == '전라남도' && _i == 32) || (_key == '인천광역시' && _i == 0)){
									if(!self.exceptCoordinateCheck(locationType, _key, _i)){
										//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
										if(self.checkPolygonInArea(_coordinateArray)){
											createPolygon(self.map, _coordinateArray, locationType, self.dataSetGroupByAddressType['sidoDataSet'][_key],_key, _key, false);
										}
									}
								}else{
									if(!self.exceptCoordinateCheck(locationType, _key, _i)){
										//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
										if(self.checkPolygonInArea(_coordinateArray)){
											createPolygon(self.map, _coordinateArray, locationType, self.dataSetGroupByAddressType['sidoDataSet'][_key],_key, _key, true);
										}
									}
								}
							}								
						});
                        
                        //2020.12.10 SYJIN 폴리곤 하위 섬 마우스 오버 이벤트 적용
                        $.each(self.polygons[locationType], function(_i, _v){
                        	/* DOGFOOT syjin 카카오 지도 폴리곤 마우스 오버,아웃 이벤트 추가 20201029 */			
							if(!_v.masterFilterCheck){
								kakao.maps.event.addListener(_v, 'mouseover', _v.mouseover);
								kakao.maps.event.addListener(_v, 'mouseout', _v.mouseout);
							}

							//kakao.maps.event.addListener(_v, 'click', _v.mouseclick);
						})
						
					}
				});
				break;
			case 'SiGunGu':	
				//시군구 일때
				$.each(self.dataSetGroupByAddressType['siGunGuDataSet'], function(_key,_v){
					self.locationObject.locationSiGunGu[_key] = new Array();
					//2020.10.19 mksong dogfoot 카카오지도 지역별 합계 키 예외 처리
					 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
					//if(!_key.includes('total')){
					if(_key.indexOf('total') == -1){
						//2020.10.08 MKSONG 카카오맵 데이터 키 코드->네임으로 변경 DOGFOOT
						var sidoName = _key.split(':')[0];
						var siGunGuName = _key.split(':')[1];
						
						//2020.10.08 MKSONG 카카오맵 주소이름 -> 코드값 DOGFOOT
						var sidoCode = self.getSidoCodeBySidoName(sidoName);
						
						//2020.11.20 mksong geojson 전역처리 dogfoot
						$.each(gDashboard.SiGunGuJson.features, function(f_i, f_v){
                    		var jsonLocation = f_v.properties['SIG_KOR_NM'];
                    		//2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
                    		//if(jsonLocation.includes(siGunGuName) && sidoCode == f_v.properties['SIG_CD'].substr(0,sidoCode.length)){
                    		//2020.11.17 mksong 카카오맵 양주시 남양주시 include 오류 수정 dogfoot
                    		if(jsonLocation.indexOf(siGunGuName) == 0 && sidoCode == f_v.properties['SIG_CD'].substr(0,sidoCode.length)){
								//2020.10.08 MKSONG 카카오맵 주소값 가져오기 누락 부분 수정 DOGFOOT
								self.locationObject.locationSiGunGu[_key] = self.locationObject.locationSiGunGu[_key].concat(f_v.geometry.coordinates);									
                    		}
                    	});
					}
				});
				
				//2020.10.28 mksong 메인 좌표그룹 체크 dogfoot
				$.each(self.locationObject.locationSiGunGu, function(_key, _coordinateDataArray){
					//2020.10.29 mksong 카카오맵 토탈 오류 수정 dogfoot
					 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
					//if(!_key.includes('total')){
					if(_key.indexOf('total') == -1){
						var isTheLongestLength = 0;
						$.each(self.locationObject.locationSiGunGu[_key], function(_i, _coordinateArray){
							if(_i > 0){
								if(_coordinateArray.length > self.locationObject.locationSiGunGu[_key][_i-1].length){
									isTheLongestLength = _i;
								}	
							}else if(_i == 0){
								isTheLongestLength = _i;
							}
						});
						
						var sidoName = _key.split(':')[0];
						var siGunGuName = _key.split(':')[1];
						var sidoCode = self.getSidoCodeBySidoName(sidoName);
						
						//2020.11.17 mksong 카카오맵 시군구 세종특별자치시 오류 수정 dogfoot
						if(sidoCode == 36){
							siGunGuName = sidoName;
						}
						
						var isIntegratedGunGu = true;
						$.each(self.siGunGuIntegrationCodeList, function(_i, _code){
							if(sidoCode == _code){
								isIntegratedGunGu = false;
							}
						});
						
						if(isIntegratedGunGu){
							$.each(_coordinateDataArray, function(_i,_coordinateArray){
								if(_i == isTheLongestLength){
									//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
									if(self.checkPolygonInArea(_coordinateArray)){
										createPolygon(self.map, _coordinateArray, locationType, self.dataSetGroupByAddressType['siGunGuDataSet'][_key],siGunGuName, _key, false);
									}
								}else{
									if(!self.exceptCoordinateCheck(locationType, _key, _i)){
										//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
										if(self.checkPolygonInArea(_coordinateArray)){
											createPolygon(self.map, _coordinateArray, locationType, self.dataSetGroupByAddressType['siGunGuDataSet'][_key],siGunGuName, _key, true);
										}
									}
								}							
							});
						}else{
							var integratedCoordinateArray = [];
							$.each(_coordinateDataArray, function(_i,_coordinateArray){
								if(!self.exceptCoordinateCheck(locationType, _key, _i)){
									integratedCoordinateArray = integratedCoordinateArray.concat(_coordinateArray);
								}
							});
							//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
							if(self.checkPolygonInArea(_coordinateArray)){
								createPolygon(self.map, integratedCoordinateArray, locationType, self.dataSetGroupByAddressType['siGunGuDataSet'][_key],siGunGuName, _key, false);
							}
						}
					}
				});
				break;
				
			case 'EupMyeonDong':		    
				$.each(self.dataSetGroupByAddressType['eupMyeonDongDataSet'], function(_key,_v){
					self.locationObject.locationEupMyeonDong[_key] = new Array();
					//2020.10.19 mksong dogfoot 카카오지도 지역별 합계 키 예외 처리
					 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
					//if(!_key.includes('total')){
					if(_key.indexOf('total') == -1){
						//2020.10.08 MKSONG 카카오맵 데이터 키 코드->네임으로 변경 DOGFOOT
						var sidoName = _key.split(':')[0];
						var siGunGuName = _key.split(':')[1];
						var eupMyeonDongName = _key.split(':')[2];
						
						//2020.10.08 MKSONG 카카오맵 주소이름 -> 코드값 DOGFOOT
						var sidoCode = self.getSidoCodeBySidoName(sidoName);
						//2020.11.20 MKSONG 카카오맵 시군구코드 조회 추가 DOGFOOT
						var siGunGuCode = self.getSiGunGuCodeBySidoName(sidoCode, siGunGuName);
						//2020.11.20 mksong geojson 전역처리 dogfoot
						$.each(gDashboard.EupMyeonDongJson.features, function(f_i, f_v){
                    		var jsonLocation = f_v.properties['EMD_KOR_NM'];
                    		 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
                    		//if(jsonLocation.includes(eupMyeonDongName) && sidoCode == f_v.properties['EMD_CD'].substr(0,sidoCode.length)){
                    		//2020.11.20 MKSONG 카카오맵 같은 시군구에서 동명이 겹치는 오류 수정 DOGFOOT
                    		if(jsonLocation.indexOf(eupMyeonDongName) != -1 && siGunGuCode == f_v.properties['EMD_CD'].substr(0,siGunGuCode.length)){
								self.locationObject.locationEupMyeonDong[_key] = self.locationObject.locationEupMyeonDong[_key].concat(f_v.geometry.coordinates);
								//2020.10.08 MKSONG 카카오맵 주소값 가져오기 누락 부분 수정 DOGFOOT
//                    			$.each(f_v.geometry.coordinates,function(_i,_coordinateArray){
//                    				$.each(_coordinateArray, function(c_i, c_v){
//			    						self.locationObject.locationEupMyeonDong[_key].push(c_v);
//									});
//			    				});
                    		}
                    	});
				    }
				});	
				
				//2020.10.28 mksong 메인 좌표그룹 체크 dogfoot
				$.each(self.locationObject.locationEupMyeonDong, function(_key, _coordinateDataArray){
					//2020.10.29 mksong 카카오맵 토탈 오류 수정 dogfoot
					 //2020.11.13 syjin 카카오맵  IE 지원 수정 dogfoot
					//if(!_key.includes('total')){
					if(_key.indexOf('total') == -1){
						var sidoName = _key.split(':')[0];
						var siGunGuName = _key.split(':')[1];
						var eupMyeonDongName = _key.split(':')[2];
						var sidoCode = self.getSidoCodeBySidoName(sidoName);
						
						var isTheLongestLength = 0;
						$.each(self.locationObject.locationEupMyeonDong[_key], function(_i, _coordinateArray){
							if(_i > 0){
								if(_coordinateArray.length > self.locationObject.locationEupMyeonDong[_key][_i-1].length){
									isTheLongestLength = _i;
								}	
							}else if(_i == 0){
								isTheLongestLength = _i;
							}
						});
					
						$.each(_coordinateDataArray, function(_i,_coordinateArray){
							if(_i == isTheLongestLength){
								//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
								if(self.checkPolygonInArea(_coordinateArray)){
									createPolygon(self.map, _coordinateArray, locationType, self.dataSetGroupByAddressType['eupMyeonDongDataSet'][_key],eupMyeonDongName, _key, false);
								}
							}else{
								if(!self.exceptCoordinateCheck(locationType, _key, _i)){
									//2020.11.17 mksong 카카오맵 화면 영역 안에 포함되는 폴리곤만 그리도록 수정 dogfoot
									if(self.checkPolygonInArea(_coordinateArray)){
										createPolygon(self.map, _coordinateArray, locationType, self.dataSetGroupByAddressType['eupMyeonDongDataSet'][_key],eupMyeonDongName, _key, true);
									}
								}
							}		
						});
					}
				});
			break;
		}
		           
            //2020.12.07 syjin dogfoot 파이차트 범례 기능 추가
// 			if(self.pieChartLegend != undefined){
// 	            if(self.pieChartLegend.length == 0){            	 
// 	            	$.each(dataBasket, function(d_i, d_v){
// 	            		self.pieChartLegend.push(d_v.SINGLE_ARGUMENT);
// 	            	})
// 	            }
	            
// 	            $.each(self.pieChartLegend, function(_i, _data){
// 	            	var duplicatedCheck = false;
// 	            	$.each(dataBasket, function(d_i, d_v){
// 	            		if(d_v.SINGLE_ARGUMENT == _data){
// 	            		    duplicatedCheck = true;
// 	            		    if(!duplicatedCheck){
// 	            		    	self.pieChartLegend.push(d_v.SINGLE_ARGUMENT);
// 	            		    }	
// 	            		}
// 	            	})
// 	            })
// 			}	           
	};
	
	//2020.09.25 syjin clearTrackingConditions 주석 해제 dogfoot
	this.clearTrackingConditions = function() {
		//2020.09.29 mksong dxVectorMap 오류로 주석 dogfoot
        //2020.10.27 syjin clearTrackingConditions 추가 dogfoot
        if (self.IO && self.IO.MasterFilterMode) {
            if(gDashboard.reportType != 'AdHoc' || !(gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer')){
                if(self.dxItem){
                	//2020.10.05 syjin 카카오맵 마커 이미지 초기화 수정 dogfoot
                    var markerInfoImage;
                    
					for(var i=0; i<self.markersInfo.length; i++){
						markerInfoImage = self.markersInfo[i]['image'];
						var markerImage = new kakao.maps.MarkerImage(markerInfoImage, new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));
						
						self.markers[i].setImage(markerImage);
						self.markersInfo[i].masterFilterSelected = false;
					}

					//2020.10.30 syjin 카카오맵 폴리곤 테두리 초기화 dogfoot
					self.polygonLineInit();
                }
                
                //2020.10.30 syjin 카카오맵 폴리곤 마스터 필터 리스트 초기화 dogfoot
                self.polygonMfList = [];
                self.trackingData = [];
				self.tempTrackingData = [];
				self.selectedPoint = undefined;	
            }
        }
	};
	
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
		
		//2020.10.28 mksong 불필요한 부분 제거  dogfoot
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
			case 'singleMasterFilter': {
				if(!(self.dxItem)){
					break;
				}
                
				gProgressbar.show();
                
                self.functionBinddata = true;
				self.trackingClearId = self.itemid + '_topicon_tracking_clear';
				
				if (self.meta.InteractivityOptions.MasterFilterMode === 'Single') {
				    $('#' + self.trackingClearId).addClass('invisible');
				    self.meta.InteractivityOptions.MasterFilterMode = 'Off';
					self.clearTrackingConditions();

					var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
					if(reTrackItem){
						gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
					}else{
						gDashboard.filterData(self.itemid, self.trackingData);	
					}
				}else{
                    $('#' + self.trackingClearId).removeClass('invisible');
					self.meta.InteractivityOptions.MasterFilterMode = 'Single';
					self.meta.InteractivityOptions.MasterFilterMode = 'Single';

					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
						/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
						if(gDashboard.getLayoutType() == "Container"){
							var ContainerList = gDashboard.setContainerList(self);            	

							$.each(ContainerList,function(_l,_con){
								if (_con.DashboardItem == item.ComponentName) {
									if (item.ComponentName !== self.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
										$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
										item.meta.InteractivityOptions.MasterFilterMode = 'Off';
										item.meta.InteractivityOptions.MasterFilterMode = 'Off';
										/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
										gDashboard.filterData(item.itemid, []);
									}
								}
							})

						}else{
							if (item.ComponentName !== self.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
								$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
								item.meta.InteractivityOptions.MasterFilterMode = 'Off';
								item.meta.InteractivityOptions.MasterFilterMode = 'Off';
								/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
								gDashboard.filterData(item.itemid, []);
							}
						}
					});

					self.clearTrackingConditions();
					/* DOGFOOT syjin 2020-1030 마스터 필터 초기화*/
					gDashboard.filterData(self.itemid, []);
					gProgressbar.hide();
				}

                break;
			}
			// toggle multiple master filter mode
			/* DOGFOOT syjin 카카오 지도 마스터 필터 주석해제  20200928 */
			case 'multipleMasterFilter': {
				if (!(self.dxItem)) {
					break;
				}
				gProgressbar.show();
				/* DOGFOOT 20201021 ajkim setTimeout 제거*/
				self.functionBinddata = true;

				if (self.meta.InteractivityOptions.IsDrillDownEnabled) {
					self.terminateDrillDownOperation();
				}

				if (self.meta.InteractivityOptions.MasterFilterMode === 'Multiple') {
					$('#' + self.trackingClearId).addClass('invisible');
					self.meta.InteractivityOptions.MasterFilterMode = 'Off';
					self.clearTrackingConditions();

					var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
					if(reTrackItem){
						gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
					}else{
						gDashboard.filterData(self.itemid, self.trackingData);	
					}
				} else{
					$('#' + self.trackingClearId).removeClass('invisible');
					self.meta.InteractivityOptions.MasterFilterMode = 'Multiple';
					// Only one master filter can be on. Turn off master filters on other items.
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
						/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
						if(gDashboard.getLayoutType() == "Container"){
							var ContainerList = gDashboard.setContainerList(self);            	

							$.each(ContainerList,function(_l,_con){
								if (_con.DashboardItem == item.ComponentName) {
									if (item.ComponentName !== self.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
										$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
										item.meta.InteractivityOptions.MasterFilterMode = 'Off';
										/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
										gDashboard.filterData(item.itemid, []);
									}
								}
							})

						}else{
							if (item.ComponentName !== self.ComponentName && item.IO && item.meta.InteractivityOptions.MasterFilterMode !== 'Off') {
								$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
								item.meta.InteractivityOptions.MasterFilterMode = 'Off';
								/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
								gDashboard.filterData(item.itemid, []);
							}
						}
					});
					self.clearTrackingConditions();					
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
//						_d3Item.selectFirstPoint();
				}
				
				/* DOGFOOT syjin 2020-1030 마스터 필터 초기화*/
				self.clearTrackingConditions();	
				gDashboard.filterData(self.itemid, []);
				gProgressbar.hide();
				break;
			}
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
		
		/* DOGFOOT syjin 카카오 지도 폴리곤 편집 팝업창 설정 20201005 */
		case 'editPolygon':{
			var p = $("#editPopup").dxPopup('instance');
			
			/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 SelectBox 추가 20201007 */
			var sidoCheck = "시도";
			var sigunguCheck = "시군구";
			var eupmyeondongCheck = "읍면동";
			var addressSelectBoxValue = [];
			
			//2020.11.18 mksong 카카오맵 폴리곤 투명도 옵션 주석 dogfoot
//			var polygonOpacityOption = self.polygonEditOptions['polygonOpacityOption'];
			//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
			var originPaletteObject = {
				'sido' : {
					"Palette" : self.polygonEditOptions.polygonPaletteOptions.sido.Palette,
					CustomPalette : {
						Color: []
					}
				},
				'sigungu' : {
					"Palette" : self.polygonEditOptions.polygonPaletteOptions.sigungu.Palette,
					CustomPalette : {
						Color: []
					}
				},
				'eupmyeondong' : {
					"Palette" : self.polygonEditOptions.polygonPaletteOptions.eupmyeondong.Palette,
					CustomPalette : {
						Color: []
					}
				}
			}
			
			//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
			$.each(self.polygonEditOptions.polygonPaletteOptions,function(_key,_paletteObject){
				$.each(_paletteObject.CustomPalette.Color, function(_i,_color){
					originPaletteObject[_key].CustomPalette.Color.push(_color);
				});
			});
			
			var polygonPaletteObject = self.polygonEditOptions.polygonPaletteOptions;
			
			var emptyCheck = function(param){
				return Object.keys(param).length === 0 && param.constructor ===Object;
			}
			if(!emptyCheck(self.dataSetGroupByAddressType.sidoDataSet)){
				addressSelectBoxValue.push(sidoCheck);
			}
			if(!emptyCheck(self.dataSetGroupByAddressType.siGunGuDataSet)){
				addressSelectBoxValue.push(sigunguCheck);
			}
			if(!emptyCheck(self.dataSetGroupByAddressType.eupMyeonDongDataSet)){
				addressSelectBoxValue.push(eupmyeondongCheck);
			}
			
			p.option({
				title: '폴리곤 편집',
				contentTemplate : function(contentElement){
					                   			
					var html = 
						'<div class="tab-title focus">' +
							'<ul class="tab-m">' + 
								'<li id="tabP1-1" class="on">' +
									'<a href="#">' +
										'폴리곤 편집' +
									'</a>' +
								'</li>' +
								/* DOGFOOT syjin 카카오 지도 폴리곤 편집 레이블 설정 주석 처리 20201102 */
 								'<li id="tabP1-2" id="defaultSeriesOptions">' +
 									'<a href="#">' +
 										'레이블 설정' +
 									'</a>' +
 								'</li>' +
								'<li id="tabP1-3" id="defaultSeriesOptions">' +
									'<a href="#">' +
										'텍스트 설정' +
									'</a>' +
								'</li>' +
								'<li id="tabP1-4" id="defaultSeriesOptions">' +
									'<a href="#">' +
										'배경 편집' +
									'</a>' +
								'</li>' +
								'<li id="tabP1-5" id="defaultSeriesOptions">' +
								'<a href="#">' +
									'라인 편집' +
								'</a>' +
							'</li>' +
							'</ul>' +
						'</div>' +
						
						'<div id="tab-content1">' +
							'<div id="' + self.itemid + '_polygonOptions" style="padding:20px"></div>' +
						'</div>' +
						
						'<div id="tab-content2" style=display:none;">' +
							/* DOGFOOT syjin 카카오 지도 폴리곤 레이블 설정 20201006 */
							'<div id="' + self.itemid + '_polygonLabelOptions" style="padding:20px"></div>' +
						'</div>' +
						
						'<div id="tab-content3" style=display:none;">' +
							/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 SelectBox 추가 20201007 */
							'<div style="padding-top:20px; padding-left:20px; padding-right:20px;">' +
								'<div id="addressSelectBox"></div>' +
							'</div>' +
							/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 20201006 */
							'<div id="' + self.itemid + '_polygonTextOptions' + sidoCheck +'" style="padding:20px; display:none;"></div>' +
							'<div id="' + self.itemid + '_polygonTextOptions' + sigunguCheck +'" style="padding:20px; display:none;"></div>' +
							'<div id="' + self.itemid + '_polygonTextOptions' + eupmyeondongCheck +'" style="padding:20px; display:none;"></div>' +
						'</div>' +
						
						'<div id="tab-content4" style=display:none;">' +
							/* DOGFOOT syjin 카카오 지도 폴리곤 색상 설정 20201007 */
							'<div style="padding-top:20px; padding-left:20px; padding-right:20px;">' +
								'<div id="addressSelectBox2"></div>' +
							'</div>' +
							/* DOGFOOT syjin 카카오 지도 폴리곤 색상 설정 버튼 추가 20201008 */
							'<div id="colorBtnDiv" style="margin-left:20px; position:absolute; margin-top:20px; z-index:9;">' +									
									'<a class="btn positive" id="colorBtn">색상 설정</a>' +									     
							'</div>' +
							'<div id="colorBoxDiv" style="padding:20px; position:absolute; visibility:hidden;">' +
								'<div id="colorBox"">' +
								'</div>' +
							'</div>' +
							//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
							'<div id="' + self.itemid + '_polygonColorOptions" style="padding:20px"></div>' +
							'<div id="' + self.itemid + '_polygonPaletteOptions" style="padding:20px">' +
								'<div class="modal-article">' +
									'<div class="modal-tit" style="padding-top: 15px;">' +
										'<span>팔레트 선택</span>' +
									'</div>' +
									'<div id="' + self.itemid + '_polygonPalette"></div>' +
								'</div>' +
								'<div class="modal-article" style="margin-top:0px;padding-top:20px;">' +
									'<div class="modal-tit">' +
										'<span>사용자 정의 팔레트</span>' +
									'</div>' +
									'<div id="' + self.itemid + '_polygonCustomColor" style="padding: 0px 20px 10px 20px;"></div>' +
								'</div>'+
							'</div>' + 
						'</div>' +
						'<div id="tab-content5" style=display:none;">' +                           				
							/* DOGFOOT syjin 카카오 지도 폴리곤 선 서식 설정 SelectBox 추가 20201102 */
							'<div style="padding-top:20px; padding-left:20px; padding-right:20px;">' +
								'<div id="lineAddressSelectBox"></div>' +
							'</div>' +

							'<div id="' + self.itemid + '_polygonLineOptions' + sidoCheck +'" style="padding:20px; display:block;"></div>' +
							'<div id="' + self.itemid + '_polygonLineOptions' + sigunguCheck +'" style="padding:20px; display:none;"></div>' +
							'<div id="' + self.itemid + '_polygonLineOptions' + eupmyeondongCheck +'" style="padding:20px; display:none;"></div>' +							    							
						'</div>' +

						'<div class="modal-footer" style="padding-bottom:0px;">' +
							'<div class="row center">' +
								'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
								'<a id="close" href="#" class="btn neutral close">취소</a>' +
							'</div>' +
						'</div>';
					
					contentElement.append(html);
					
					/* DOGFOOT syjin 카카오 지도 폴리곤 차트 표시 유무 설정 20201005 */
					var optionsForm = $('#' + self.itemid + '_polygonOptions').dxForm({
						items : [
							{
								dataField : "차트 표시" ,
								editortType : 'dxCheckBox',
								editorOptions:{
									'value' : self.polygonEditOptions['polygonChartCheck'],
									'elementAttr' : {
										'id' : 'polygonChartCheck'
									},
									'onContentReady' : function(){
										self.polygonEditOptions['disPlayPolygonChart'] = function(_value){
											if(_value){
												//2020.10.29 syjin 카카오맵 텍스트 위치 조정 오류 수정 DOGFOOT
												//DOGFOOT syjin 2020-12-03 카카오 지도 여러개 있을 때 , 차트 표시 하나의 아이템에만 적용되는 오류 수정 
												$("#"+self.Map.ComponentName).find('.polygon-chart').css('visibility', 'inherit ');
												//$(".polygon-chart").removeClass('dx-state-invisible');
											}else{
												//2020.10.29 syjin 카카오맵 텍스트 위치 조정 오류 수정 DOGFOOT
												//DOGFOOT syjin 2020-12-03 카카오 지도 여러개 있을 때 , 차트 표시 하나의 아이템에만 적용되는 오류 수정 
												$("#"+self.Map.ComponentName).find('.polygon-chart').css('visibility', 'hidden');
												//$(".polygon-chart").addClass('dx-state-invisible');
											}
										}
									}
								}
							},
							//2020.10.29 mksong 카카오맵 폴리곤 툴팁 추가 dogfoot
							{
								dataField : "툴팁 표시",
								editorType : "dxCheckBox",
								editorOptions : {
									'value' : self.polygonEditOptions['tooltipCheck'],
									'elementAttr' : {
										'id' : 'polygonTooltipCheck'
									}
								}
							},
							{
								dataField : "한반도만 보이게 하기",
								editorType : "dxCheckBox",
								editorOptions : {
									'value' : self.polygonEditOptions['hanbandoCheck'],
									'elementAttr' : {
										'id' : 'polygonHanbandoCheck'
									}
								}
							},
							//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
							{
								dataField : "폴리곤 팔레트 적용 여부" ,
								editorType : 'dxCheckBox',
								editorOptions:{
									'value' : self.polygonEditOptions['polygonPaletteCheck'],
									'elementAttr' : {
										'id' : 'polygonPaletteCheck'
									},
									'onValueChanged' : function(e){
										if(e.value){
											$('#'+self.itemid + '_polygonColorOptions').hide();
											$('#colorBtnDiv').hide();
											$('#colorBoxDiv').hide();
											$('#'+self.itemid + '_polygonPaletteOptions').show();
											//2020.11.20 MKSONG 카카오맵 팔레트 적용시 투명도 해제 DOGFOOT
											$('#polygonOpacityEnabled').dxCheckBox('instance').option('value',false);
										}else{
											$('#'+self.itemid + '_polygonColorOptions').show();
											$('#colorBtnDiv').show();
											$('#colorBoxDiv').show();
											//2020.11.20 MKSONG 카카오맵 팔레트 적용시 투명도 해제 DOGFOOT
											$('#polygonOpacityEnabled').dxCheckBox('instance').option('value',self.polygonEditOptions['polygonOpacityEnabled']);
											$('#'+self.itemid + '_polygonColorOptions').show();
											$('#'+self.itemid + '_polygonPaletteOptions').hide();
										}
									}
								}
							},
							//2020.10.08 MKSONG 카카오맵 투명도 조정 기능 옵션 추가 DOGFOOT
							{
								dataField : "폴리곤 투명도 여부" ,
								editorType : 'dxCheckBox',
								editorOptions:{
									'value' : self.polygonEditOptions['polygonOpacityEnabled'],
									'elementAttr' : {
										'id' : 'polygonOpacityEnabled'
									},
									//2020.11.06 MKSONG 카카오맵 폴리곤 투명도 조절 슬라이더 활성화 구분  DOGFOOT
									'onValueChanged' : function(e){
										if(e.value){
											$('#polygonOpacityWeight').dxSlider('instance').option('disabled',false);
										}else{
											$('#polygonOpacityWeight').dxSlider('instance').option('disabled',true);
										}
									}
								}
							},
							//2020.11.03 MKSONG 카카오맵 폴리곤 투명도 가중치 설정 DOGFOOT
							{
								dataField : "폴리곤 투명도 가중치" ,
								editorType : 'dxSlider',
								editorOptions:{
									'value' : self.polygonEditOptions['polygonOpacityWeight'],
									'elementAttr' : {
										'id' : 'polygonOpacityWeight'
									},
									'min' : 40,
									'max' : 100,
									//2020.11.20 mksong 카카오맵 slider 툴팁 및 레이블 추가 dogfoot
									label: {
							            visible: true,
							            format: function(value) {
							                return value + "%";
							            },
							            position: "bottom"
							        },
									tooltip: {
							            enabled: true,
							            format: function (value) {
							                return value + "%";
							            },
							            showMode: "always", 
							            position: "bottom"
							        },
									//2020.11.06 MKSONG 카카오맵 폴리곤 투명도 조절 슬라이더 활성화 구분  DOGFOOT
									disabled : !self.polygonEditOptions['polygonOpacityEnabled']
								}
							}
							//2020.11.18 mksong 카카오맵 폴리곤 투명도 옵션 주석 dogfoot
//							{
//								dataField : "투명도 조정 기준" ,
//								editorType : "dxSelectBox",
//								editorOptions:{
//									value : polygonOpacityOption == 'addressType' ? '주소 영역별 기준' : '전체 비율 기준',
//									dataSource : ['주소 영역별 기준','전체 비율 기준'],
//									elementAttr : {
//										'id' : 'polygonOpacityOption'
//									},
//									onValueChanged : function(data){
//										polygonOpacityOption = data.value == '주소 영역별 기준' ? 'addressType' : 'rateType';
//									}
//								}
//							}
						]
					});
					
					/* DOGFOOT syjin 카카오 지도 폴리곤 레이블 설정 20201006 */
					var labelOptionsForm = $('#' + self.itemid + '_polygonLabelOptions').dxForm({
						items : [
							{
								dataField : "표기 형식",
								editorType : "dxSelectBox",
								editorOptions : {
									dataSource : ['없음', '지역명', '값', '%', '지역명 및 값', 
										 '값 및 %', '지역명 및 %', '지역명, 값 및 %'],
									elementAttr : {
										 'id' : 'polygonLabelOptions'
									},
									value : self.polygonEditOptions['polygonLabelOptions']['type'] 
								}
							}
						]
					});
									
					/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 SelectBox 추가 20201007 */
					var addressSelectBox = $("#addressSelectBox").dxSelectBox({
						items : addressSelectBoxValue,
						value : addressSelectBoxValue[0],
						onValueChanged : function(e){
							for(var i=0; i<addressSelectBoxValue.length; i++){
								if(e.value == addressSelectBoxValue[i]){
									$("#" + self.itemid + '_polygonTextOptions' + addressSelectBoxValue[i]).css('display',"block");
								}else{
									$("#" + self.itemid + '_polygonTextOptions' + addressSelectBoxValue[i]).css('display',"none");
								}
							}
						}
					}).dxSelectBox('instance');
					
					/* DOGFOOT syjin 카카오 지도 폴리곤 선 색상 서식 설정 SelectBox 추가 20201102 */
					var lineAddressSelectBox = $("#lineAddressSelectBox").dxSelectBox({
						items : addressSelectBoxValue,
						value : addressSelectBoxValue[0],
						onValueChanged : function(e){
							for(var i=0; i<addressSelectBoxValue.length; i++){
								if(e.value == addressSelectBoxValue[i]){
									$("#" + self.itemid + '_polygonLineOptions' + addressSelectBoxValue[i]).css('display',"block");
								}else{
									$("#" + self.itemid + '_polygonLineOptions' + addressSelectBoxValue[i]).css('display',"none");
								}
							}
						}
					}).dxSelectBox('instance');
					
					/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 20201006 */
					var textOptionsForm = $('#' + self.itemid + '_polygonTextOptions' + sidoCheck).dxForm({
						items : [
							{
								dataField : "텍스트 색상",
								editorType : "dxColorBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonTextOptions']['sido']['textColor'],
									elementAttr : {
										 'id' : 'polygonTextColor' + sidoCheck
									},
								}
							},
							{
								dataField : "폰트 사이즈(px)",
								editorType : "dxTextBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonTextOptions']['sido']['fontSize'],
									elementAttr : {
										 'id' : 'polygonTextFontSize' + sidoCheck
									},
								}
							}
						]
					});
					
					var textOptionsForm2 = $('#' + self.itemid + '_polygonTextOptions' + sigunguCheck).dxForm({
						items : [
							{
								dataField : "텍스트 색상",
								editorType : "dxColorBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonTextOptions']['sigungu']['textColor'],
									elementAttr : {
										 'id' : 'polygonTextColor' + sigunguCheck
									},
								}
							},
							{
								dataField : "폰트 사이즈(px)",
								editorType : "dxTextBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonTextOptions']['sigungu']['fontSize'],
									elementAttr : {
										 'id' : 'polygonTextFontSize' + sigunguCheck
									},
								}
							}
						]
					});
					
					var textOptionsForm3 = $('#' + self.itemid + '_polygonTextOptions' + eupmyeondongCheck).dxForm({
						items : [
							{
								dataField : "텍스트 색상",
								editorType : "dxColorBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonTextOptions']['eupmyeondong']['textColor'],
									elementAttr : {
										 'id' : 'polygonTextColor' + eupmyeondongCheck
									},
								}
							},
							{
								dataField : "폰트 사이즈(px)",
								editorType : "dxTextBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonTextOptions']['eupmyeondong']['fontSize'],
									elementAttr : {
										 'id' : 'polygonTextFontSize' + eupmyeondongCheck
									},
								}
							}
						]
					});
					
					/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 20201006 */
					var lineOptionsForm = $('#' + self.itemid + '_polygonLineOptions' + sidoCheck).dxForm({
						items : [
							{
								dataField : "선 색상",
								editorType : "dxColorBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonLineOptions']['sido']['lineColor'],
									elementAttr : {
										 'id' : 'polygonLineColor' + sidoCheck
									},
								}
							}
						]
					});
					
					var lineOptionsForm2 = $('#' + self.itemid + '_polygonLineOptions' + sigunguCheck).dxForm({
						items : [
							{
								dataField : "선 색상",
								editorType : "dxColorBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonLineOptions']['sigungu']['lineColor'],
									elementAttr : {
										 'id' : 'polygonLineColor' + sigunguCheck
									},
								}
							}
						]
					});
					
					var lineOptionsForm3 = $('#' + self.itemid + '_polygonLineOptions' + eupmyeondongCheck).dxForm({
						items : [
							{
								dataField : "선 색상",
								editorType : "dxColorBox",
								editorOptions : {
									value : self.polygonEditOptions['polygonLineOptions']['eupmyeondong']['lineColor'],
									elementAttr : {
										 'id' : 'polygonLineColor' + eupmyeondongCheck
									},
								}
							}
						]
					});
					
					/* DOGFOOT syjin 카카오 지도 폴리곤 색상 tab 셀렉트 박스 설정 20201008 */
					//selectBoxDataSource
					var addressSelectBoxData = [];
                    var dataSource = [];
					
					//2020.11.06 MKSONG 카카오맵 폴리곤 주소타입에 따른 목록 동기화 DOGFOOT
					switch(self.addresses[0].addressType){
						case 'Sido': 
							addressSelectBoxData = ['시도'];
							break;
						case 'SiGunGu':
							addressSelectBoxData = ['시도','시군구'];
							break;
						case 'EupMyeonDong':
							addressSelectBoxData = ['시도','시군구','읍면동'];
							break;
					}
					
// 					$.each(self.polygonEditOptions.polygonBgColorOptions, function(_i,_v){
// 						if(_v.length != 0){
// 							switch(_i){
// 								case "Sido":
// 								 addressSelectBoxData.push("시도");	
// 								break;
// 								case "SiGunGu":
// 								addressSelectBoxData.push("시군구");
// 								break;
// 								case "EupMyeonDong":
// 								addressSelectBoxData.push("읍면동");
// 								break;
// 							}														
// 						}
// 					})
                    
//                    $.each(self.polygons, function(p_i, p_v){
//                        if(p_v.length != 0){
// 							switch(p_i){
// 								case "Sido":
// 								 addressSelectBoxData.push("시도");	
// 								break;
// 								case "SiGunGu":
// 								addressSelectBoxData.push("시군구");
// 								break;
// 								case "EupMyeonDong":
// 								addressSelectBoxData.push("읍면동");
// 								break;
// 							}
// 						}
//                    })

                    //2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
					var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
						'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office', 'Custom'];
					var paletteCollection2 = ['밝음', '발광체', '바다', '파스텔', '부드러움', '연한 파스텔', '나무', '포도', 
						'단색', '우주', '진보라', '안개숲', '연파랑', '기본값', '사무실 테마','사용자 정의 테마'];
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
					
					var originalPalette = paletteCollection.indexOf(polygonPaletteObject[self.locationNameConverter[addressSelectBoxData[0]]].Palette) != -1
								? polygonPaletteObject[self.locationNameConverter[addressSelectBoxData[0]]].Palette
								: 'Custom';
					var colorContainer = $("#" + self.itemid + "_polygonCustomColor");
					var colorArray = [];
					
					var addressSelectBox2 = $("#addressSelectBox2").dxSelectBox({
                        dataSource : addressSelectBoxData,
                        value : addressSelectBoxData[0],
                        onValueChanged : function(data){
                        	var compareValue;
                        	var polygonLength = self.getPolygonLength();
                            var dataSet;
                        	dataSource = [];
                        	switch(data.value){
								case "시도":
								compareValue = "Sido";
								dataSet = 'sidoDataSet';	
								break;

								case "시군구":
								compareValue = "SiGunGu";
								dataSet = 'siGunGuDataSet';
								break;
								
								case "읍면동":
								compareValue = "EupMyeonDong";
								dataSet = 'eupMyeonDongDataSet';
								break;
							}

							switch(compareValue){
								case 'Sido':
									fillColor = '#CFE7FF';
									break;
								case 'SiGunGu':
									//fillColor = '#FF8AEF';
									fillColor = '#FF99FF';
									break;
								case 'EupMyeonDong':
									//fillColor = '#A2FF99';
									fillColor = '#CCFFCC';
									break;
							}
							
							$.each(self.dataSetGroupByAddressType, function(_i, _v){
							    if((!(Object.keys(_v).length === 0)) && _i==dataSet){
									$.each(_v, function(_vi, _vv){
										var dataSourceObject = {};

										if(Array.isArray(_vv)){

											var polygonBgColorOptions = self.polygonEditOptions.polygonBgColorOptions[compareValue];

											if(polygonBgColorOptions.length > 0){
												var flag = true;

												$.each(polygonBgColorOptions, function(bgc_i, bgc_v){
													$.each(bgc_v, function(_i, _v){
														if(_i == 'listName'){
															$.each(_v, function(ln_i, ln_v){
																if(ln_v == _vi){
																	dataSourceObject['주소'] = _vi;
																	dataSourceObject['색상'] = bgc_v['bgColor'];
																	flag = false;
																}
															})
														}
													})
												})

												if(flag){
													dataSourceObject['주소'] = _vi;
													dataSourceObject['색상'] = fillColor;
												}
											}else{
												dataSourceObject['주소'] = _vi;
												dataSourceObject['색상'] = fillColor;
											}

		// 									$.each(self.polygons, function(pl_i, pl_v){										
		// 										if(locationType == pl_i){
		// 											$.each(pl_v, function(j, k){
		// 												//if(j<length){
		// 													if(_vi == k['locationFullName']){
		// 														dataSourceObject['주소'] = _vi;
		// 														dataSourceObject['색상'] = k["Db"][0]['fillColor'];
		// 														return false;
		// 													}
		// 												//}
		// 											})
		// 										}																				  								
		// 									})

											if(!(Object.keys(dataSourceObject).length === 0 && dataSourceObject.constructor === Object)){
												dataSource.push(dataSourceObject);
											}
										}
									})
								}
							});
							
							//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
							$('#' + self.itemid + '_polygonPalette').dxSelectBox('instance').option('value', paletteObject[polygonPaletteObject[self.locationNameConverter[data.value]].Palette]);
							var parentColorContainer = colorContainer.parent();
							colorContainer.remove();
							parentColorContainer.append('<div id="' + self.itemid + '_polygonCustomColor" style="padding: 0px 20px 10px 20px;"></div>');
							colorContainer = $('#'+ self.itemid + '_polygonCustomColor');
							
							self.samplePalettePoint.forEach(function(index) {
								colorContainer.append('<p>Point ' + index
														+ '</p><div id="' + self.itemid + '_pointColor' + index + '">');
		                    });
		                    
							colorArray = [];
							self.samplePalettePoint.forEach(function(index) {
								var palette = polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color.length > 0 ? polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color : DevExpress.viz.getPalette(originalPalette).simpleSet;
								var paletteIndex = polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color.length > 0 ? index : index % 6;
								
								colorArray.push(palette[paletteIndex]);
								
								$('#' + self.itemid + '_pointColor' + index).dxColorBox({
									value: palette[paletteIndex],
									onValueChanged: function(e){
										colorArray[index] = e.value;
										polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color = colorArray;
									}
								});
		                    });

							polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color = colorArray;
							
							colorContainer.dxScrollView({
								height: 200,
								width: '100%'
							});  							
							
							//change dataGrid DataSource
							$('#' + self.itemid + '_polygonColorOptions').dxDataGrid('instance').option('dataSource', dataSource);
						}
					}).dxSelectBox('instance');
                    
                    /* DOGFOOT syjin 카카오 지도 폴리곤 색상 설정 버튼 클릭시 데이터 그리드 색상 변경 20201012 */
					$("#colorBox").dxColorBox({
						value : "black",
						applyValueMode : "useButtons",
						onValueChanged: function(e){
							var selectKeys = $('#' + self.itemid + '_polygonColorOptions').dxDataGrid('instance').option('selectedRowKeys');
							var gridDataSource = $('#' + self.itemid + '_polygonColorOptions').dxDataGrid('instance').option('dataSource');

							$.each(selectKeys, function(sk_i, sk_v){
								console.log(sk_v);
								$.each(gridDataSource, function(gds_i, gds_v){
									if(JSON.stringify(gds_v) === JSON.stringify(sk_v)){
										//gds_v['색상'] = sk_v['색상'];
										gds_v['색상'] = e.value;
									}
								})
							})

							$('#' + self.itemid + '_polygonColorOptions').dxDataGrid('instance').refresh();
						}
					}).dxColorBox('instance');
					                    
                    /* DOGFOOT syjin 카카오 지도 폴리곤 색상 설정 데이터 그리드 dataSource 수정 20201028 */
                    $.each(self.dataSetGroupByAddressType, function(_i, _v){
                        var selectBoxValue = $("#addressSelectBox2").dxSelectBox('instance').option('value');
                    	var locationType;
                    	var locationType2;
                        var polygonLength = self.getPolygonLength();
                        var length;
                        var fillColor;
                        
                     	switch(selectBoxValue){
							case "시도":
							    selectBoxValue = "sidoDataSet";
							    locationType = 'Sido';	
							break;
							case "시군구":
							    selectBoxValue = "siGunGuDataSet";
							    locationType = 'SiGunGu';
							break;
							case "읍면동":
							    selectBoxValue = "eupMyeonDongDataSet";
							    locationType = 'EupMyeonDong';
							break;
						}
                        
                        switch(_i){
                        	case 'sidoDataSet':
                        	    locationType2 = 'Sido';
                        	break;

                        	case 'siGunGuDataSet':
                        	    locationType2 = 'SiGunGu';
                        	break;

                        	case 'eupMyeonDongDataSet':
                        	    locationType2 = 'EupMyeonDong';
                        	break;
                        }
                        
                        length = polygonLength[locationType2];

						switch(locationType2){
							case 'Sido':
								fillColor = '#CFE7FF';
								break;
							case 'SiGunGu':
								//fillColor = '#FF8AEF';
								fillColor = '#FF99FF';
								break;
							case 'EupMyeonDong':
								//fillColor = '#A2FF99';
								fillColor = '#CCFFCC';
								break;
						} 

						if((!(Object.keys(_v).length === 0)) && _i==selectBoxValue){
							$.each(_v, function(_vi, _vv){
								var dataSourceObject = {};

								if(Array.isArray(_vv)){
									
									var polygonBgColorOptions = self.polygonEditOptions.polygonBgColorOptions[locationType];

									if(polygonBgColorOptions.length > 0){
										var flag = true;

                                        $.each(polygonBgColorOptions, function(bgc_i, bgc_v){
                                        	$.each(bgc_v, function(_i, _v){
                                        		if(_i == 'listName'){
                                        			$.each(_v, function(ln_i, ln_v){
                                        				if(ln_v == _vi){
                                        					dataSourceObject['주소'] = _vi;
										                    dataSourceObject['색상'] = bgc_v['bgColor'];
										                    flag = false;
                                        				}
                                        			})
                                        		}
                                        	})
                                        })

                                        if(flag){
                                        	dataSourceObject['주소'] = _vi;
										    dataSourceObject['색상'] = fillColor;
                                        }
									}else{
										dataSourceObject['주소'] = _vi;
										dataSourceObject['색상'] = fillColor;
									}
                                                       
// 									$.each(self.polygons, function(pl_i, pl_v){										
// 										if(locationType == pl_i){
// 											$.each(pl_v, function(j, k){
// 												//if(j<length){
// 													if(_vi == k['locationFullName']){
// 														dataSourceObject['주소'] = _vi;
// 														dataSourceObject['색상'] = k["Db"][0]['fillColor'];
// 														return false;
// 													}
// 												//}
// 											})
// 										}																				  								
// 									})
                                    
                                    if(!(Object.keys(dataSourceObject).length === 0 && dataSourceObject.constructor === Object)){
									    dataSource.push(dataSourceObject);
                                    }
								}
							})
						}
                    })
					/* DOGFOOT syjin 카카오 지도 폴리곤 색상 설정 20201007 */
					var colorOptionsForm = $('#' + self.itemid + '_polygonColorOptions').dxDataGrid({
						dataSource : dataSource,
						/* DOGFOOT syjin 카카오 지도 데이터 그리드 칼럼 설정 추가 20201008 */
						columns : [
                            "주소",
                            {
                            	dataField : "색상",
                            	width : 45,
                            	cellTemplate : function(container, options){
                            		var div = $("<div class='colorBox' style='text-align:center;'>");
                            		var colorBoxDiv = $("<div class='polygonBgColor'>").dxColorBox({
                            			value : options.value,
                            			readOnly : true
                            		});
                            		
                            		$(div).append($(colorBoxDiv));
                            		$(div).appendTo(container);
                            		
                            		$(".colorBox").parent().css('padding', "0px");
//                            		$("<div class='polygonBgColor'>").dxColorBox({
//                            			value : options.value,
//                            			readOnly : true
//                            		}).appendTo(container);
                            	}
                            }
						],
						paging: {
							pageSize: 5
						},
						selection: {
							mode: "multiple",
							showCheckBoxesMode : "always"
						},
						searchPanel: {
				            visible: true,
				            width:200,
				            highlightSearchText : false,	
				            searchVisibleColumnsOnly: true
				        },
					});
					
					//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
					$('#' + self.itemid + '_polygonPalette').dxSelectBox({
                        items: paletteCollection2,
                        itemTemplate: function(data) {
                            var html = $('<div />');
                            $('<p />').text(data).css({
                                display: 'inline-block',
                                float: 'left'
                            }).appendTo(html);
                            
                            colorArray = [];
                            if(data === '사용자 정의 테마'){
                            	$.each(polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color,function(_i,_color){
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
							polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].Palette = paletteObject2[e.value];
							if (e.value == '사용자 정의 테마') {
                                self.isCustomPalette = true;
                                colorArray = [];
                            	$.each(polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color,function(_i,_color){
 									if(typeof _color == 'string' && _color.indexOf('#') > -1){
 										colorArray.push(_color.toUpperCase());	
 									}else{
 										colorArray.push(self.getHexColor(_color).toUpperCase());
 									}	
 								});
							} else {
                                self.isCustomPalette = false;
							}
						}
                    });

					//색상 편집
					var customListCnt = [];
					var colorCustomList = [];
					
					self.samplePalettePoint.forEach(function(index) {
						colorContainer.append('<p>Point ' + index
												+ '</p><div id="' + self.itemid + '_pointColor' + index + '">');
                    });
                    colorContainer.dxScrollView({
                        height: 200,
                        width: '100%'
                    });
                    
					self.samplePalettePoint.forEach(function(index) {
						var palette = polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color.length > 0 ? polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color : DevExpress.viz.getPalette(originalPalette).simpleSet;
						var paletteIndex = polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color.length > 0 ? index : index % 6;
						
						colorArray.push(palette[paletteIndex]);
						
						$('#' + self.itemid + '_pointColor' + index).dxColorBox({
							value: palette[paletteIndex],
							onValueChanged: function(e){
								colorArray[index] = e.value;
								polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color = colorArray;
							}
						});
                    });
					
					polygonPaletteObject[self.locationNameConverter[addressSelectBox2.option('value')]].CustomPalette.Color = colorArray;
					
					if(self.polygonEditOptions['polygonPaletteCheck']){
						$('#'+self.itemid + '_polygonColorOptions').hide();
						$('#colorBtnDiv').hide();
						$('#colorBoxDiv').hide();
						$('#'+self.itemid + '_polygonPaletteOptions').show();
					}else{
						$('#'+self.itemid + '_polygonColorOptions').show();
						$('#colorBtnDiv').show();
						$('#colorBoxDiv').show();
						$('#'+self.itemid + '_polygonColorOptions').show();
						$('#'+self.itemid + '_polygonPaletteOptions').hide();
					}

				}
			});
			
			p.option('visible', !(p.option('visible')));
			p.option('position', 'center');
			
			//when click 색상설정
			/* DOGFOOT syjin 색상설정 버튼 클릭시 이벤트 구현 20201008 */
			$("#colorBtn").click(function(){
				var selectKeys = $('#' + self.itemid + '_polygonColorOptions').dxDataGrid('instance').option('selectedRowKeys');
				
				if(selectKeys.length>0){
					var color = selectKeys[0]['색상'];
					
					$("#colorBox").dxColorBox('instance').option('value', color);
					$("#colorBox").dxColorBox('instance').option('opened', true);
				}
                //selectKey, $(".polygonBgColor") 이용
                //$(".polygonBgColor") 접근할 때 현재 페이지에서 보이는 div만 선택됨(10개) 마커편집에서 참고해서 해결방안 검토
                //먼저 팝업창의 색상 바꿔주고 확인 버튼 눌렀을 때 polygonEditOptions 의 값 수정 해주면됨
                
			});

			//when click confirm
			$("#ok-hide").click(function(){
				/* DOGFOOT syjin 카카오 지도 폴리곤 차트 표시 유무 설정 20201005 */
				//display polygonChart
				self.polygonEditOptions['polygonChartCheck'] = $("#polygonChartCheck").dxCheckBox('instance').option('value');
				//2020.10.29 mksong 카카오맵 폴리곤 툴팁 추가 dogfoot
				self.polygonEditOptions['tooltipCheck'] = $("#polygonTooltipCheck").dxCheckBox('instance').option('value');
				//DOGFOOT syjin 2020-11-30 한반도만 보이도록 하고 확대 못하도록 옵션 설정해주기
				if(self.polygonEditOptions['hanbandoCheck'] != $("#polygonHanbandoCheck").dxCheckBox('instance').option('value')){
					self.polygonEditOptions['hanbandoCheck'] = $("#polygonHanbandoCheck").dxCheckBox('instance').option('value');				
				}
				//2020.10.08 MKSONG 카카오맵 투명도 조정 기능 옵션 추가 DOGFOOT
				self.polygonEditOptions['polygonOpacityEnabled'] = $("#polygonOpacityEnabled").dxCheckBox('instance').option('value');
				//2020.11.18 mksong 카카오맵 폴리곤 투명도 옵션 주석 dogfoot
//				self.polygonEditOptions['polygonOpacityOption'] = polygonOpacityOption;
				//2020.11.03 MKSONG 카카오맵 폴리곤 투명도 가중치 설정 DOGFOOT
				self.polygonEditOptions['polygonOpacityWeight'] = $('#polygonOpacityWeight').dxSlider('instance').option('value');
				self.polygonEditOptions['disPlayPolygonChart'](self.polygonEditOptions['polygonChartCheck']);
				
				/* DOGFOOT syjin 카카오 지도 폴리곤 레이블 설정 20201006 */
				//setting polygonLabel
				self.polygonEditOptions['polygonLabelOptions']['type'] = $("#polygonLabelOptions").dxSelectBox('instance').option('value');
                
                //2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
				self.polygonEditOptions['polygonPaletteCheck'] = $('#polygonPaletteCheck').dxCheckBox('instance').option('value');
				self.polygonEditOptions['polygonPaletteOptions'] = polygonPaletteObject;

                /* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 20201007 */
                //setting polygonText       
                for(var i=0; i<addressSelectBoxValue.length; i++){
                	var addressType;
                	var lineColor =  $("#polygonLineColor" + addressSelectBoxValue[i]).dxColorBox('instance').option('value');;

                	switch(addressSelectBoxValue[i]){
                	case '시도':
                		addressType = "sido";
                		break;
                	case '시군구':
                		addressType = "sigungu";
                		break;
                	case '읍면동':
                		addressType = "eupmyeondong";
                		break;
                	}

                	self.polygonEditOptions['polygonTextOptions'][addressType]['textColor'] = $("#polygonTextColor" + addressSelectBoxValue[i]).dxColorBox('instance').option('value');
                	self.polygonEditOptions['polygonTextOptions'][addressType]['fontSize'] = $("#polygonTextFontSize" + addressSelectBoxValue[i]).dxTextBox('instance').option('value');

                	$("." + addressSelectBoxValue[i]).find(".polygonText").css('color', self.polygonEditOptions['polygonTextOptions'][addressType]['textColor']);
                	$("." + addressSelectBoxValue[i]).find(".polygonValueText").css('color', self.polygonEditOptions['polygonTextOptions'][addressType]['textColor']);
                	
                	/* DOGFOOT syjin 카카오 지도 텍스트 크기 오류 수정 20201028 */
                	$("." + addressSelectBoxValue[i]).find(".polygonText").css('font-size', self.polygonEditOptions['polygonTextOptions'][addressType]['fontSize']/self.map.getLevel());
                	$("." + addressSelectBoxValue[i]).find(".polygonValueText").css('font-size', self.polygonEditOptions['polygonTextOptions'][addressType]['fontSize']/1.5/self.map.getLevel());
                
                    /* DOGFOOT syjin 카카오 지도 폴리곤 선 색상 설정 20201102 */
                    self.polygonEditOptions['polygonLineOptions'][addressType]['lineColor'] = lineColor;

                    $.each(self.polygons, function(pl_i, pl_v){
                    	var lowerType = pl_i.toLowerCase();
                    	if(lowerType == addressType){
                            $.each(pl_v, function(_i, _v){
                                _v.setOptions({
                                	strokeColor : lineColor
                                })
                            })
                            
                    		return false;
                    	}
                    })
                }
                
                /* DOGFOOT syjin 카카오 지도 폴리곤 색상 설정 버튼 클릭시 데이터 그리드 색상 변경 20201012 */
                var gridDataSource = $('#' + self.itemid + '_polygonColorOptions').dxDataGrid('instance').option('dataSource');
                var bgColorArray = self.polygonEditOptions.polygonBgColorOptions;
				
				//2020.11.17 mksong 카카오맵 팔레트 수정사항 바로 반영 dogfoot
				var selectBoxValue = $("#addressSelectBox2").dxSelectBox('instance').option('value');
				var fillColor;
                var type;

                switch(selectBoxValue){
					case '시도':
						fillColor = '#CFE7FF';
						type = "Sido";
						break;
					case '시군구':
						//fillColor = '#FF8AEF';
						fillColor = '#FF99FF';
						type = "SiGunGu";
						break;
					case '읍면동':
						//fillColor = '#A2FF99';
						fillColor = '#CCFFCC';
						type = "EupMyeonDong";
						break;
				}
                
                 //2020.11.05 syjin dogfoot 카카오지도 배경 색상 주소 불러오기 오류 수정
				$.each(gridDataSource, function(gd_i, gd_v){
					if(gd_v['색상'] != fillColor){
						var locationName = gd_v['주소'];
                        var bgColor = gd_v['색상'];
                        var flag = true;

						$.each(bgColorArray, function(bc_i, bc_v){
							if(bc_i == type){
								$.each(bc_v, function(_i, _v){									
									if(_v['bgColor'] == bgColor){
										 flag = false;
										 
										if(_v['listName'].indexOf(locationName)<0){
										    _v['listName'].push(locationName);										
										  
										    return false;
                                        }				
									}									  
								})							
							}
						})

						if(flag){
							var bgColorObject = {
								bgColor : "",
								listName : []
							};

							bgColorObject['bgColor'] = bgColor;
							bgColorObject['listName'].push(locationName);

							bgColorArray[type].push(bgColorObject);
						}					
					}
				});
				//2020.11.17 mksong 카카오맵 팔레트 수정사항 바로 반영 dogfoot
				//2020.11.18 mksong 카카오맵 functionbinddata 수정 dogfoot
				self.functionBinddata = true;
				self.bindData();
				//popup hide
				$("#editPopup").dxPopup('instance').hide();
			});
			
			//when click cancel
			$("#close").click(function(){
				//2020.11.06 MKSONG 카카오맵 폴리곤 배경 색상 편집 DOGFOOT
				self.polygonEditOptions.polygonPaletteOptions = originPaletteObject;
				$("#editPopup").dxPopup('instance').hide();
			});
			
			//when click tab
			$("#tabP1-1").click(function(){
				$("#tab-content1").css("display", "block");
				$("#tab-content2").css("display", "none");
				$("#tab-content3").css("display", "none");
				$("#tab-content4").css("display", "none");
				/* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
				$("#tab-content5").css("display", "none");
				
				$("#tabP1-1").addClass('on');
				/* DOGFOOT syjin 카카오 지도 폴리곤 편집 레이블 설정 주석 처리 20201102 */
				$("#tabP1-2").removeClass('on');
				$("#tabP1-3").removeClass('on');
				$("#tabP1-4").removeClass('on');
				/* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
				$("#tabP1-5").removeClass('on');

				//p.option('position', 'center');
			});
			
			/* DOGFOOT syjin 카카오 지도 폴리곤 편집 레이블 설정 주석 처리 20201102 */
 			$("#tabP1-2").click(function(){
 				$("#tab-content2").css("display", "block");
 				$("#tab-content1").css("display", "none");
 				$("#tab-content3").css("display", "none");
 				$("#tab-content4").css("display", "none");
 				/* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
 				$("#tab-content5").css("display", "none");

 				$("#tabP1-2").addClass('on');
 				$("#tabP1-1").removeClass('on');
 				$("#tabP1-3").removeClass('on');
 				$("#tabP1-4").removeClass('on');
 				/* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
 				$("#tabP1-5").removeClass('on');
 				//p.option('position', 'center');
 			});
			
			$("#tabP1-3").click(function(){
				$("#tab-content3").css("display", "block");
				$("#tab-content1").css("display", "none");
				$("#tab-content2").css("display", "none");
				$("#tab-content4").css("display", "none");
				/* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
				$("#tab-content5").css("display", "none");

				$("#tabP1-3").addClass('on');
				$("#tabP1-1").removeClass('on');
				/* DOGFOOT syjin 카카오 지도 폴리곤 편집 레이블 설정 주석 처리 20201102 */
				$("#tabP1-2").removeClass('on');
				$("#tabP1-4").removeClass('on');
				/* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
				$("#tabP1-5").removeClass('on');
				/* DOGFOOT syjin 카카오 지도 폴리곤 텍스트 서식 설정 SelectBox 추가 20201007 */
				for(var i=0; i<addressSelectBoxValue.length; i++){
					if(i==0){
						$("#" + self.itemid + '_polygonTextOptions' + addressSelectBoxValue[i]).css('display',"block");
					}else{
						$("#" + self.itemid + '_polygonTextOptions' + addressSelectBoxValue[i]).css('display',"none");
					}
				}
				//p.option('position', 'center');
			});
			
			$("#tabP1-4").click(function(){
				$("#tab-content4").css("display", "block");
				$("#tab-content1").css("display", "none");
				$("#tab-content2").css("display", "none");
				$("#tab-content3").css("display", "none");
				/* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
				$("#tab-content5").css("display", "none");

				$("#tabP1-4").addClass('on');
				$("#tabP1-1").removeClass('on');
				/* DOGFOOT syjin 카카오 지도 폴리곤 편집 레이블 설정 주석 처리 20201102 */
				$("#tabP1-2").removeClass('on');
				$("#tabP1-3").removeClass('on');
				/* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
				$("#tabP1-5").removeClass('on');
				//p.option('position', 'center');
			});
            
            /* DOGFOOT syjin 카카오 지도 선색상설정 탭 이벤트 추가 20201102 */
			$("#tabP1-5").click(function(){
				$("#tab-content5").css("display", "block");
				$("#tab-content1").css("display", "none");
				$("#tab-content2").css("display", "none");
				$("#tab-content3").css("display", "none");
				$("#tab-content4").css("display", "none");
				
				$("#tabP1-5").addClass('on');
				$("#tabP1-1").removeClass('on');
				/* DOGFOOT syjin 카카오 지도 폴리곤 편집 레이블 설정 주석 처리 20201102 */
				$("#tabP1-2").removeClass('on');
				$("#tabP1-3").removeClass('on');				
				$("#tabP1-4").removeClass('on');
				//p.option('position', 'center');
			});
			break;
		}
			
		case 'editMarker': {
			//if(!(self.dxItem)){
				//break;
			//}
			
			var p = $("#editPopup").dxPopup('instance');
            
			p.option({
				title: '마커 편집',
				//target : "#editMarker",
				contentTemplate : function(contentElement){
					/* DOGFOOT syjin 좌표일 때 이미지 설정 버튼 비활성화  20201104 */
					var locationType = self.Map.LocationType;
//					var imageSettingDisplay = locationType!='address'?'none':'';
					
					var html = 
						'<div class="tab-title focus">' +
							'<ul class="tab-m">' + 
								'<li id="tabP1-1" class="on">' +
									'<a href="#">' +
										'편집' +
									'</a>' +
								'</li>' +
								/* DOGFOOT syjin 좌표일 때 이미지 설정 버튼 비활성화  20201104 */
								'<li id="tabP1-2" id="defaultSeriesOptions">' +
									'<a href="#">' +
										'이미지 설정' +
									'</a>' +
								'</li>' +
							'</ul>' +
						'</div>' +
						'<div id="tab-content1">' +
							'<div id="' + self.itemid + '_markerOptions" style="padding:20px"></div>' +
						'</div>' +
						'<div id="tab-content2" style="display:none;">' +
							//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
							'<div style="margin-top:15px;">' +								
									'<div id="selectStandardDimension">' +								
									'</div>' +																
							'</div>' +
							/* DOGFOOT syjin 카카오 지도 되돌리기, 이미지 설정 버튼 위치 오류 수정  20200925 */
							//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
							'<div style="display:flex; flex-direction:row; margin-top:10px; position:absolute; z-index:9; top:173px">' +
								'<div hidden="hidden"> ' +
		                            '<form id="IMG_FORM" name="imgForm" method="post" enctype="multipart/form-data" accept-charset="UTF-8`">' +
		                                '<div id="IMG_BUTTON" class="image-ui">' +
		                                    '<input id="customImgInput" class="real-image" type="file" accept=".gif, .jpg, .png">' +
		                                '</div> ' +
		                                '<span id="imageText">파일 선택하세요.</span> ' +
		                            '</form>' +
		                        '</div>' +		                        
								'<div>' +
									'<a class="btn positive" id="init-image">되돌리기</a>' +
								'</div>' +
								'<div id="customImgBtn" style="margin-left:10px">' +									
									'<a class="btn positive" id="customMarkerImage">이미지 설정</a>' +									     
								'</div>' +
							'</div>' +
							'<div style="margin-top:15px;">' +								
									'<div id="imageDimensionGrid">' +								
									'</div>' +																
							'</div>' +
						'</div>' +
						'<div class="modal-footer" style="padding-bottom:0px;">' +
							'<div class="row center">' +
								'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
								'<a id="close" href="#" class="btn neutral close">취소</a>' +
							'</div>' +
						'</div>';
					
					contentElement.append(html);
							
					var optionsForm = $('#' + self.itemid + '_markerOptions').dxForm({
						items: [
//							{
//								dataField: "마커 표시",
//								editorType: 'dxCheckBox',
//								editorOptions:{
//									'value' : true,
//									'elementAttr' : {
//										'id' : "marker-check"
//									}
//								}
//							},
//							{
//								dataField: "클러스터러 표시",
//								editorType: 'dxCheckBox',
//								editorOptions:{
//									'value' : true,
//									'elementAttr' : {
//										'id' : "clusterer-check"
//									}
//								}
//							},
                            /* DOGFOOT syjin 데이터 크기에 따른 마커 표시 추가 20201012 */
							{
								/* DOGFOOT syjin 데이터 크기에 따른 마커 표시 오류 수정 20201120 */
								dataField : self.measures[0]['caption'] + "에 따른 마커 표시",
								editorType : 'dxCheckBox',
								editorOptions: {
									'value' : self.markerEditOptions[self.Map.LocationType]['valueMarkerCheck'], 
									'elementAttr' : {
										'id' : 'valueMarkerCheck'
									},
									'onValueChanged' : function(e){
										if(e.value){
										    $("#sliderMarker").dxRangeSlider('instance').option('disabled', false);
										}else{
											$("#sliderMarker").dxRangeSlider('instance').option('disabled', true);
										}

									}
								}
							},
							/* DOGFOOT syjin 데이터 크기에 따른 마커 표시 RangeSlider 추가 20201012 */
							{
								dataField : "",
								editorType : "dxRangeSlider",
								editorOptions : {						
									tooltip: {
										enabled: true,
										format: function (value) {
											return value;
										},
										showMode: "always", 
										position: "bottom"
									},
									disabled : !self.markerEditOptions[self.Map.LocationType].valueMarkerCheck,
									elementAttr : {
									    id : "sliderMarker", 
									 	style: 'margin-bottom: 30px;'
									},
									onContentReady : function(e){
										var measureArr = [];

										$.each(self.markersInfo, function(_i, _v){
											measureArr.push(_v.value);
										})
                                        
										//DOGFOOT syjin 2020-12-03 마커 편집 값에따른 마커 표시 null 값 들어가는 오류 수정
										if(!self.markerEditOptions[self.Map.LocationType].valueMarkerCheck){
										    self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMax = measureArr.length==0?9999:Math.max.apply(null, measureArr);
										    self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMin = measureArr.length==0?0:Math.min.apply(null, measureArr);
                                        }
                                        
                                        $("#sliderMarker").dxRangeSlider('instance').option('min', measureArr.length==0?0:Math.min.apply(null, measureArr));
										$("#sliderMarker").dxRangeSlider('instance').option('max', measureArr.length==0?9999:Math.max.apply(null, measureArr));
										$("#sliderMarker").dxRangeSlider('instance').option('start', measureArr.length==0?0:self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMin);
										$("#sliderMarker").dxRangeSlider('instance').option('end', measureArr.length==0?9999:self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMax);
									},		
								}		
							},
							{
								dataField : "툴팁 표시",
								editorType : "dxCheckBox",
								editorOptions : {
									'value' : self.markerEditOptions[self.Map.LocationType]['tooltipCheck'],
									'elementAttr' : {
										'id' : 'tooltipCheck'
									},
									/* DOGFOOT syjin 툴팁 체크 시 위도 경도 표시 활성화, 비활성화 20201014 */
									'onValueChanged' : function(e){
										if(e.value){
											/* DOGFOOT syjin 마커 위도 경도 표시 주석 처리 20201106 */
                                            //$("#laloCheck").dxCheckBox('instance').option('disabled', false);
										}else{
											//$("#laloCheck").dxCheckBox('instance').option('disabled', true);
										}
									}
								}
							},
							
							/* DOGFOOT syjin 마커 툴팁 체크 시 위도 경도 표시 비활성화 20201120 */
// 							{
// 								dataField : '위도, 경도 표시',
// 								editorType : 'dxCheckBox',
// 								editorOptions : {
// 									'value' : self.markerEditOptions[self.Map.LocationType]['laloCheck'],
// 									'elementAttr' : {
// 										'id' : 'laloCheck'
// 									},
// 									'disabled' : !self.markerEditOptions[self.Map.LocationType]['tooltipCheck']
// 								}
// 							},
							{
								dataField: "이미지 범례 표시",
								editorType: 'dxCheckBox',
								editorOptions:{
									/* DOGFOOT syjin 마커 편집 이미지 범례 추가 수정 20201023 */
									'value' : self.markerEditOptions[self.Map.LocationType]['imageLegendCheck'],
									'elementAttr' : {
										'id' : "imageLegend-check"
									}
								}
							}
							/*{
								dataField: "url 링크 연결",
								editorType : 'dxSelectBox',
								editorOptions:{
									'items': ['kakao', 'naver'],
									'value' : self.selectValue,
									'elementAttr' : {
										'id' : "urlSelectBox"
									}
								}
							}*/
						]
					});
					
                    //imageGrid
					var dataSourceArray = new Array();
					var dataSourceArrayCom = new Array();
					var columnsArray = new Array();
					var dataSourceImage = new Array();
					var dimensionDataObject = {};

					function clone(obj){
						var output = {};
						for(var i in obj){
							output[i] = obj[i];
						}

						return output;
					}
					
					//2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
					function dataSourceArraySetting(_standardDimensionObject){
						var dataSourceArray = [];	
					    var dimensionDataSet = WISE.libs.Dashboard.Query.likeSql.doSqlLike(self.dataSourceId, self.SQLike.fromJson([_standardDimensionObject], [], []), self);
					    $.each(dimensionDataSet, function(_i, _dimensionData){
						    var index = dataSourceArray.length;
	                        var imageCheck = true;
	
						   	dataSourceArray[index] = {
								dimensionData : "",
								image : ""
	                       	};

							dataSourceArray[index]['dimensionData'] = _dimensionData[_standardDimensionObject.caption];
							$.each(WISE.util.Object.toArray(self.mkInfo.coordinate.image[_standardDimensionObject.name]), function(ma_i, ma_v){
							   $.each(WISE.util.Object.toArray(ma_v['listName']), function(av_i, av_v){
					   	   	       if(av_v == _dimensionData.standardDimension){
									   dataSourceArray[index]['image'] = ma_v['source'];
									   imageCheck = false;

									   return false;
								   }
							   });                               
	                        });
	
	                        if(imageCheck){
	                           dataSourceArray[index]['image'] = "https://t1.daumcdn.net/mapjsapi/images/marker.png";
	                        }
					    });
						
						return dataSourceArray;
					}
					
					//dataSource
					/* DOGFOOT syjin 카카오 지도 마커 이미지 데이터그리드 dataSource 부분 수정  20201106 */
					
					//2020.12.31 mksong 카카오맵 데이터집합 차원컬럼목록 조회 오류 수정 dogfoot
					var dimensionColumnList = self.getDimensionColumnList();
					if(dimensionColumnList.length == 0){
						$.each(self.markerDimensions, function(_i, _markerDimension){
							dimensionColumnList.push(_markerDimension.caption);
						});
					}
					
					//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
					if(self.meta.LocationType == 'address'){
						$.each(_.keys(self.datasetGroupByAddress), function(kd_i, kd_v){
						    var index = dataSourceArray.length;
                            var imageCheck = true;

						    dataSourceArray[index] = {
								주소 : "",
								이미지 : ""
                           };

                           dataSourceArray[index]['주소'] = kd_v;
                           
                           $.each(self.mkInfo.coordinate.image, function(ma_i, ma_v){                             
							   $.each(ma_v, function(av_i, av_v){
							   	   if(av_i == 'listName'){
							   	   	    $.each(av_v, function(avv_i, avv_v){
							   	   	    	if(avv_v == kd_v){
											   dataSourceArray[index]['이미지'] = ma_v['source'];
											   imageCheck = false;

											   return false;
										   }
							   	   	    })								   
							   	   }
							   })                               
                           })

                           if(imageCheck){
                               dataSourceArray[index]['이미지'] = "https://t1.daumcdn.net/mapjsapi/images/marker.png";
                           }
						});
					}else{
						//2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
					    dimensionDataObject = self.mkInfo.coordinate.standardDimension.name != undefined ? self.mkInfo.coordinate.standardDimension : (self.markerDimensions.length != 0 ? {name : self.markerDimensions[0].name, caption : 'standardDimension'} : {name : dimensionColumnList[0], caption : 'standardDimension'});
					    dataSourceArray = dataSourceArraySetting(dimensionDataObject);
					}
					
					//columns
					/* DOGFOOT syjin 카카오 지도 마커 주소일때 분기 처리  20200925 */
					if(self.meta.LocationType=='address'){
                        columnsArray.push("주소");
					}else{
						//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
					    columnsArray.push({
							dataField: "dimensionData",
							caption : dimensionDataObject.name
						});
					}
					//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
					var imageColumn = {
						dataField:  self.Map.LocationType == 'address' ? '이미지' : 'image',
						caption : '이미지',
						width: 90,
						cellTemplate: function (container, options) {
						  $("<div style='text-align:center;'>")
							.append($("<img>", { 
								"src": self.Map.LocationType == 'address' ? options.data['이미지'] : options.data['image'] , 
								"style": "width:20px; height:20px;"
							}))
							.appendTo(container);
						}
					};

					columnsArray.push(imageColumn);

					//2020.12.11 mksong 마커 이미지 변경 차원기준으로 수정 dogfoot
					var standardDimensionDataset = []; 
					var valueDimension = self.Map.LocationType == 'coordinate' ? dimensionDataObject.name : (self.markerDimensions[0] != undefined ? self.markerDimensions[0].name : dimensionColumnList[0]) 
					var selectStandardDimensionButton = $('#selectStandardDimension').dxSelectBox({
						items : dimensionColumnList,
						value : valueDimension,
						onValueChanged : function(e){
							dimensionDataObject = {name : e.value, caption : 'standardDimension'};
							dataSourceArray = dataSourceArraySetting(dimensionDataObject);
							$("#imageDimensionGrid").dxDataGrid('instance').option('dataSource', dataSourceArray);
							gProgressbar.hide();
						}
					}).dxSelectBox('instance');

					//set imageGrid
					var setImageGrid = $("#imageDimensionGrid").dxDataGrid({
						dataSource : dataSourceArray,
						columns: columnsArray,
						paging: {
							pageSize: 5
						},
						selection: {
							mode: "multiple",
							showCheckBoxesMode : "always"
						},
						searchPanel: {
				            visible: true,
				            width:200,
				            highlightSearchText : false,	
				            searchVisibleColumnsOnly: true
				        },
						onContentReady: function(element){
							$("#customImgInput").change(function(){
								var fReader = new FileReader();
								var file = $("#customImgInput")[0].files[0];
								fReader.readAsDataURL(file);

								fReader.onloadend = function(event){														
									//change dataGridImage
									var selectKeys = $("#imageDimensionGrid").dxDataGrid('instance').option('selectedRowKeys');
									var keyType = self.Map.LocationType == 'address' ? '이미지' : 'image';
									$.each(selectKeys, function(sk_i, sk_v){
										sk_v[keyType] = event.target.result;
									});		                                                        	                                                       
                                    
                                    //2020.11.25 syjin dogfoot 폴리곤 마커 이미지 변경 여부 체크 속도 개선
                                    self.imageChangeCheck = true;

									self.changeMarkerInfoImage = function(){
										/* DOGFOOT syjin 카카오 지도 마커 주소일때 분기 처리  20200925 */
										if(self.meta.LocationType == "address"){
                                            var addressDataSource = $("#imageDimensionGrid").dxDataGrid('instance').option('dataSource');
                                            var imageArray = [];
                                            var mkInfoImageObject;

                                            $.each(addressDataSource, function(_i, _v){
                                                imageArray.push(_v['이미지']);
                                            })
                                            
                                            const imageSet = new Set(imageArray);
                                            imageArray = Array.from(imageSet);

                                            $.each(imageArray, function(_i, _v){
                                            	var listNM = [];

                                            	$.each(addressDataSource, function(_i2, _v2){
                                            		if(_v2['이미지'] == _v){
                                            		    listNM.push(_v2['주소']);
                                            		}
                                            	})

                                            	mkInfoImageObject = {
                                            		source : _v,
                                                    listName : listNM
                                            	}
                                                
                                                if(mkInfoImageObject['source'] != "https://t1.daumcdn.net/mapjsapi/images/marker.png")
                                            	    self.mkInfo[self.Map.LocationType]['image'].push(mkInfoImageObject);
                                            })

                                            for(var i=0; i<self.markersInfo.length; i++){
                                            	for(var j=0; j<addressDataSource.length; j++){
                                            		if(self.markersInfo[i]['address'][0] == addressDataSource[j]['주소']){
                                            			self.markersInfo[i]['image'] = addressDataSource[j]['이미지'];
                                            		}
                                            	}
                                            }
										}else{
											//change markersInfo Image														
											var customDataSource = $("#imageDimensionGrid").dxDataGrid('instance').option('dataSource');
											var imageArray = [];
                                            var mkInfoImageObject;

											$.each(customDataSource, function(_i, _v){
                                                imageArray.push(_v['image']);
                                            })
                                            
                                            const imageSet = new Set(imageArray);
                                            imageArray = Array.from(imageSet);

                                            $.each(imageArray, function(_i, _v){
                                            	var listNM = [];

                                            	$.each(customDataSource, function(_i2, _v2){
                                            		if(_v2['image'] == _v){
                                            		    listNM.push(_v2['dimensionData']);
                                            		}
                                            	})

                                            	mkInfoImageObject = {
                                            		source : _v,
                                                    listName : listNM
                                            	}
                                                
                                                if(mkInfoImageObject['source'] != "https://t1.daumcdn.net/mapjsapi/images/marker.png" && mkInfoImageObject['source'] != undefined){
													if(self.mkInfo[self.Map.LocationType]['image'][self.mkInfo.coordinate.standardDimension.name] == undefined){
														self.mkInfo[self.Map.LocationType]['image'][self.mkInfo.coordinate.standardDimension.name] = [];
													}
													self.mkInfo[self.Map.LocationType]['image'][self.mkInfo.coordinate.standardDimension.name].push(mkInfoImageObject);
												}                                            	    
                                            });

											//before change markersInfo
											self.beforeMarkersInfo = _.cloneDeep(self.markersInfo);

//											for(var i=0; i<self.markersInfo.length; i++){
//												var markersInfoMd = JSON.stringify(self.markersInfo[i]['md']);
//												for(var j=0; j < customDataSourceMd.length; j++){
//													var customMd = JSON.stringify(customDataSourceMd[j]);
//
//													if(markersInfoMd === customMd){
//														self.markersInfo[i]['image'] = customDataSourceImage[j]['이미지'];
//													}
//												}
//											}
										}
									}

									//dataGrid refresh    
									$("#imageDimensionGrid").dxDataGrid('instance').refresh();
									//init file input
									$("#customImgInput").replaceWith($("<input>").attr({
										"id" : "customImgInput",
										"class" : "real-image",
										"type" : "file",
										"accept" : ".gif, .jpg, .png"
									}));
								}															
							})
						}
					}).dxDataGrid('instance');			
					
					gProgressbar.hide();
					
					//tab-click event
					$("#tabP1-1").click(function(){
						$("#tab-content1").css("display", "block");
						$("#tab-content2").css("display", "none");
						
						$("#tabP1-1").addClass('on');
						$("#tabP1-2").removeClass('on');
						
						//p.option('position', 'center');
					});
					
					$("#tabP1-2").click(function(){
						$("#tab-content1").css("display", "none");
						$("#tab-content2").css("display", "block");
						
						$("#tabP1-1").removeClass('on');
						$("#tabP1-2").addClass('on');
						
						//p.option('position', 'top');
					});
					
					//btn-click event
					//url
					/*var changeUrlSelectBox = function(){				
						self.selectValue = $("#urlSelectBox").dxSelectBox('instance').option('value')					
					};*/
					
					$("#customMarkerImage").click(function(){
						$("#customImgInput").click();
					});
					
					var changeMarkerImage = function(_selfMarkerImage, _markerImage){
						self.markerImage = _selfMarkerImage;
						self.setMarkerImage(_markerImage);
					};
					
					$("#imgInput").change(function(){
						var fReader = new FileReader();
						var file = $("#imgInput")[0].files[0];
						fReader.readAsDataURL(file);
						fReader.onloadend = function(event){
							$("#markerImage").attr({
                    			"src" : event.target.result,
                    			"width" : 50,
                    			"height" : 50
                    		});
							
							$.each($("img"), function(_i, _v){
								if(_v.id == 'markerImage'){
									_v.style['height'] = "50px";
								}
							});
							
 							self.selfMarkerImage = event.target.result;
 							self.changedMarkerImage =  new kakao.maps.MarkerImage(self.selfMarkerImage, new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));
					
 							//before change markersInfo
 							self.beforeMarkersInfo = _.cloneDeep(self.markersInfo);
							
 							//change markersInfo
 							for(var i=0; i<self.markersInfo.length; i++){
 								self.markersInfo[i]['image'] = self.selfMarkerImage;
 							}
						}			
					})
					
					$("#init-image").click(function(){
						//init markersInfo                  	
                    	$.each(self.markersInfo, function(_i, _v){
                    		_v['image'] = "https://t1.daumcdn.net/mapjsapi/images/marker.png";
                    		//_v['image'] = "https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png";                  		
                    	})

                        //init gridImage
                    	var initImageGrid = $("#imageDimensionGrid").dxDataGrid('instance').option('dataSource');
                    	$.each(initImageGrid, function(_i, _v){
                            _v['이미지'] = "https://t1.daumcdn.net/mapjsapi/images/marker.png";
                            //_v['이미지'] = "https://www.iconfinder.com/data/icons/user-interface-outline-10/32/2-Location-128.png";  
                    	})
                    	$('#imageDimensionGrid').dxDataGrid('repaint');
                        
                        /* DOGFOOT syjin 이미지 되돌리기 클릭 시 mkInfo 초기화 20201109 */
                    	self.mkInfo['address']['image'] = [];
                    	self.mkInfo['coordinate']['image'][self.mkInfo.coordinate.standardDimension.name] = [];
	                });
					
					
					//when click confirm
					$("#ok-hide").click(function(){		
					    //2020.11.25 syjin dogfoot 마커 편집 확인 클릭 시 로딩창 활성화
					    gProgressbar.show();

					    //2020.11.25 syjin dogfoot 폴리곤 마커 이미지 변경 여부 체크 속도 개선
					    if(self.imageChangeCheck){
							changeMarkerImage(self.selfMarkerImage, self.changedMarkerImage);

							if(self.Map.LocationType == 'coordinate'){
								self.mkInfo[self.Map.LocationType].standardDimension = dimensionDataObject;
							}
							
							//change MarkersInfo
							if(self.changeMarkerInfoImage){
								self.changeMarkerInfoImage();
							}
							
							//change customMarkerImage
							self.setCustomMarkerImage();
					    }

						//2020.11.25 syjin dogfoot 폴리곤 마커 이미지 변경 여부 체크 속도 개선
						self.imageChangeCheck = false;

						//display imageLegend
						/* DOGFOOT syjin 마커 편집 이미지 범례 추가 수정 20201023 */
						self.markerEditOptions[self.Map.LocationType]['imageLegendCheck'] = $("#imageLegend-check").dxCheckBox('instance').option('value');
						self.displayImageLegend(self.markerEditOptions[self.Map.LocationType]['imageLegendCheck']);	

						/* DOGFOOT syjin 데이터 크기에 따른 마커 표시 확인 클릭 시 20201013 */
						self.markerEditOptions[self.Map.LocationType].valueMarkerCheck = $("#valueMarkerCheck").dxCheckBox('instance').option('value');
						valueMarkerRange = $("#sliderMarker").dxRangeSlider('instance').option('value');
                        
                        self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMin = valueMarkerRange[0];
						self.markerEditOptions[self.Map.LocationType].valueMarkerRangeMax = valueMarkerRange[1];
						
						 //2020.11.03 syjin 카카오맵 값에 따른 마커 표시 함수처리 dogfoot
						//2020.11.25 syjin dogfoot 값에 따른 마커 표시 체크 되어있을 때만 실행하도록, 속도 개선
						if(self.markerEditOptions[self.Map.LocationType].valueMarkerCheck){							
						    self.setMarkerValue();						   
						}

						/* DOGFOOT syjin 툴팁 표시 확인 클릭 시 20201014*/
						self.markerEditOptions[self.Map.LocationType].tooltipCheck = $("#tooltipCheck").dxCheckBox('instance').option('value');
						
						/* DOGFOOT syjin 툴팁 표시 확인 클릭 열려있는 툴팁창 닫기 20201014*/
						if(!self.markerEditOptions[self.Map.LocationType].tooltipCheck){
							$.each(self.customOverlay, function(_i, _v){
								_v['customOverlay'].setMap(null);
							})
						}else{
							$.each(self.customOverlay, function(_i, _v){
								_v['customOverlay'].setMap(self.map);
							})
						}
						
						/* DOGFOOT syjin 위도 경도 표시 확인 클릭 시 20201014*/
						/* DOGFOOT syjin 마커 툴팁 체크 시 위도 경도 표시 비활성화 20201120 */
//  						self.markerEditOptions[self.Map.LocationType].laloCheck = $("#laloCheck").dxCheckBox('instance').option('value');
//  						if(self.markerEditOptions[self.Map.LocationType].laloCheck){
//  							$(".lalo").css('display', "");
//  						}else{
//  							$(".lalo").css('display', "none");
//  						}
                        
                        //2020.11.25 syjin dogfoot 마커 편집 확인 클릭 시 로딩창 활성화
                        gProgressbar.hide();
						
						if(self.Map.LocationType == 'coordinate'){
							self.functionBinddata = true;
							self.bindData();
						}
						
                        /* DOGFOOT syjin 마커 편집 hide 위치 수정 20201103*/
						$("#editPopup").dxPopup('instance').hide();
					});
					
					//when click cancel
					$("#close").click(function(){
						//self.markersInfo = _.cloneDeep(self.beforeMarkersInfo);
						
						$("#editPopup").dxPopup('instance').hide();
					});
					/*var urlLink = 
						'<div id="urlLink">' +
							'<h4 class="tit-level3">url 링크 연결</h4>' +
							'<div id="urlSelectBox"></div>' +
						'</div>';
					
					var markerImage =
						'<div>' +
							'<h4 class="tit-level3">이미지 불러오기</h4>' +
							'<div class="panel-body">' +
                                '<div class="design-menu rowColumn">' +
                                    '<ul class="design-menu-list col-1">' +
                                         '<li>' +
                                         '<div style="display:flex; justify-content:space-between;">' +
                                             '<div style="text-align:center">' +
												 '<a href="#" id="loadImg" class="functiondo">' +
												     '<div>' +
														'<img id="markerImage" src="'+ self.markerImage +'" alt="" width=50 height=50>' +
														'<br>' +
														'<span>이미지 불러오기</span>' +
												     '</div>' +
												 '</a>' +
                                             '</div>' +

                                             '<div style="display:flex; align-items:center">' +
                                                 '<div id="initImageMarker"></div>' +
                                             '</div>' +
                                         '</div>' +
                                         '</li>' +
                                    '</ul>' +
                                '</div>' +

                                '<div hidden="hidden"> ' +
                                    '<form id="IMG_FORM" name="imgForm" method="post" enctype="multipart/form-data" accept-charset="UTF-8`">' +
                                        '<div id="IMG_BUTTON" class="image-ui">' +
                                            '<input id="imgInput" name="imgInput" class="real-image" type="file" accept=".gif, .jpg, .png">' +
                                        '</div> ' +
                                        '<span id="imageText">파일 선택하세요.</span> ' +
                                    '</form>' +
                                '</div>' +

                                '<a id="imageOkButton" hidden="hidden">확인</a>' +
							'</div>' +
						'</div>';				
                    

           
					$(contentElement).append($(urlLink));
					//dev component 추가
					var urlArray = ['naver', 'kakao'];    

					var urlSelectBox = $("#urlSelectBox").dxSelectBox({
						'dataSource' : urlArray,
						'value' : self.selectValue
					}).dxSelectBox('instance');
					

					$("#urlSelectBox").dxSelectBox('instance').option('onItemClick', function(element){
						self.selectValue = element['itemData'];	
					})

					
					$(contentElement).append($(markerImage));
                    
                    var initImageMarker = $("#initImageMarker").dxButton({
                    	'text' : "기본으로 설정"
                    })
                    
                    $("#initImageMarker").click(function(){
                    	$("#markerImage").attr("src", "WISE.Constants.context/resources/main/images/ico_loadImages.png");
                    	self.markerImage = "WISE.Constants.context/resources/main/images/ico_loadImages.png";
                    	self.setMarkerImage(null);
                    });
                    
					$("#loadImg").click(function(){
						$("#imgInput").click();
					});
					$("#imgInput").change(function(){
						var fReader = new FileReader();
						var file = $("#imgInput")[0].files[0];
						fReader.readAsDataURL(file);
						fReader.onloadend = function(event){
							$("#markerImage").attr("src", event.target.result);
							self.markerImage = event.target.result;

							var _markerImage =  new kakao.maps.MarkerImage(self.markerImage, new kakao.maps.Size(31, 35), new kakao.maps.Point(13, 34));

							self.setMarkerImage(_markerImage);
						}			
					});*/
					
				}	
			});
				p.option('visible', !(p.option('visible')));
				p.option('position', 'center');
				break;
			}
			case 'loadImg': {
		    	$('#imgInput').click();
		        break;
		    }
			// change dimension target to arguments
			case 'targetAddress': {
				if (!(self.dxItem)) {
					break;
				}
				self.IO.TargetDimensions = 'Address';
				self.Map.InteractivityOptions.TargetDimensions = 'Address';
				self.clearTrackingConditions();
				gDashboard.filterData(self.itemid, self.trackingData);
				break;
			}
			// change dimension target to series
			case 'targetArgument': {
				if (!(self.dxItem)) {
					break;
				}
				self.IO.TargetDimensions = 'Argument';
				self.Map.InteractivityOptions.TargetDimensions = 'Argument';
				self.clearTrackingConditions();
				gDashboard.filterData(self.itemid, self.trackingData);
				break;
			}
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
				//2020.10.08 MKSONG 카카오맵 이름편집 오류 수정 DOGFOOT
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '이름 편집',
					width:500,
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize title input box
						contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput">');
                        var html = '<div class="modal-footer" style="padding-bottom:0px;">';
						html += '<div class="row center">';
						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
						html += '</div>';
						html += '</div>';
						html += '</div>';
						contentElement.append(html);
                        
                        $('#' + self.itemid + '_titleInput').dxTextBox({
							text: $('#' + self.itemid + '_title').text()
                        });
                        
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
                            if(newName.trim() == '') {
                            	WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                            	$('#' + self.itemid + '_titleInput').dxTextBox('instance').option('value', self.Name);
                            } else {
                            	/* DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류 수정  20191223 */
//                            	var goldenLayout = gDashboard.goldenLayoutManager;
//                            	goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);
                            	var ele = $('#' + self.itemid + '_title');
                            	ele.attr( 'title', newName)
                                ele.find( '.lm_title' ).html(newName);
                                
                                if (self.meta) {
                                    self.meta['Name'] = newName;
                                }
                                self.Name = newName;
                                p.hide();
                            }
						});
						contentElement.find('#close').on('click', function() {
							p.hide();
						});
					}
				});
				// show popup
				p.show();
				break;
			}
			//2020.09.22 mksong dogfoot 카카오지도 포인트타입 옵션 추가
			case 'showPointType':{
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#showPointType',
					//2020.10.08 MKSONG 카카오맵 ShowPointType width 변경 DOGFOOT	
					width: 120,
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_showPointType">');
						$('#' + self.itemid + '_showPointType').dxRadioGroup({
							//2020.10.08 MKSONG 카카오맵 ShowPointType 기본값 변경 DOGFOOT	
							dataSource: ['다각형','마커'],
							value: self.Map.ShowPointType == 'marker' ? '마커' : '다각형',
							onValueChanged: function(e) {
                                //2020.11.20 syjin 포인트 타입 변경시 지도 레이아웃 재설정 dogfoot
								self.map.relayout();
								//2020.10.30 syjin 마스터 필터 관련 trackingData 초기화 dogfoot
								self.trackingData = [];
								self.clearTrackingConditions();							
                                /* DOGFOOT syjin 2020-10-30 마스터 필터 초기화*/
					            gDashboard.filterData(self.itemid, []);
					            
					            /* DOGFOOT syjin 2020-11-04 filterData 초기화*/
					            self.filteredData = [];
								self.Map.ShowPointType = e.value === '마커' ? 'marker' : 'polygon';
								self.meta = self.Map;
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData,true);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			}
			//2020.09.22 mksong dogfoot 카카오지도 포인트타입 옵션 추가
			case 'saveOption':{
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#saveOption',
					//2020.10.08 MKSONG 카카오맵 ShowPointType width 변경 DOGFOOT	
					width: 180,
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_saveAutoZoomLevel">');
						contentElement.append('<div id="' + self.itemid + '_saveAutoLatLng">');
						$('#' + self.itemid + '_saveAutoZoomLevel').dxCheckBox({
							width: 150,
							value: self.Map.SaveOptions['SaveAutoZoomLevel'] == undefined || self.Map.SaveOptions['SaveAutoZoomLevel'] == false ? false : true,
							text: '현재 줌 레벨 저장',
							onValueChanged: function(e) {
								self.Map.SaveOptions['SaveAutoZoomLevel'] = e.value == false ? false : true;
								self.meta = self.Map;
							}
						});
						
						$('#' + self.itemid + '_saveAutoLatLng').dxCheckBox({
							width: 150,
							value: self.Map.SaveOptions['SaveAutoLatLng'] == undefined || self.Map.SaveOptions['SaveAutoLatLng'] == false ? false : true,
							text: '현재 좌표 저장',
							onValueChanged: function(e) {
								self.Map.SaveOptions['SaveAutoLatLng'] = e.value == false ? false : true;
								self.meta = self.Map;
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			}
			//2020.10.19 mksong dogfoot 카카오지도 차트 편집
			case 'editChart': {
				if (!(self.dxItem)) {
					break;
				}
				
				var p = $("#editPopup").dxPopup('instance');
            	var changePalette = self.chartEditOptions.Palette;
				var chartWeightOption = self.chartEditOptions['chartWeightOption'];

//editPalette
				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office', 'Custom'];
				var paletteCollection2 = ['밝음', '발광체', '바다', '파스텔', '부드러움', '연한 파스텔', '나무', '포도', 
					'단색', '우주', '진보라', '안개숲', '연파랑', '기본값', '사무실 테마','사용자 정의 테마'];
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

				// palette select
                var originalPalette = paletteCollection.indexOf(self.chartEditOptions.Palette) != -1
								? self.chartEditOptions.Palette
								: 'Custom';

				p.option({
					title: '차트 편집',
					contentTemplate : function(contentElement){
						var html = 
							'<div class="tab-title focus">' +
								'<ul class="tab-m">' + 
									'<li id="tabP1-1" class="on">' +
										'<a href="#">' +
											'차트 유형' +
										'</a>' +
									'</li>' +
									'<li id="tabP1-2">' +
										'<a href="#">' +
											'차트 색상편집' +
										'</a>' +
									'</li>' +
									'<li id="tabP1-3">' +
										'<a href="#">' +
											'레이블 설정' +
										'</a>' +
									'</li>' +
								'</ul>' +
							'</div>' +
							
							'<div id="tab-content1">' +
								'<div id="' + self.itemid + '_chartEdit" style="padding:20px"></div>' +
							'</div>' +
							
							'<div id="tab-content2" style=display:none;">' +
								'<div class="modal-article">' +
									'<div class="modal-tit" style="padding-top: 15px;">' +
										'<span>팔레트 선택</span>' +
									'</div>' +
									'<div id="' + self.itemid + '_chartPalette"></div>' +
								'</div>' +
								'<div class="modal-article" style="margin-top:0px;padding-top:20px;">' +
									'<div class="modal-tit">' +
										'<span>사용자 정의 팔레트</span>' +
									'</div>' +
									'<div id="' + self.itemid + '_chartCustomColor" style="padding: 0px 20px 10px 20px;"></div>' +
								'</div>' +
							'</div>' +
							
							'<div id="tab-content3" style=display:none;">' +
								'<div id="' + self.itemid + '_chartLabelOptions" style="padding:20px"></div>' + 
							'</div>' +
							
							'<div class="modal-footer" style="padding-bottom:0px;">' +
								'<div class="row center">' +
									'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
									'<a id="close" href="#" class="btn neutral close">취소</a>' +
								'</div>' +
							'</div>';
						
						contentElement.append(html);
						
						//editChartType
						var chartTypeForm = $('#' + self.itemid + '_chartEdit').dxForm({
							items : [
								{
									dataField : "차트 유형",
									editorType : "dxSelectBox",
									editorOptions : {
										dataSource : ['파이', '버블'],
										elementAttr : {
											 'id' : 'chartType'
										},
										//2020.11.20 MKSONG 카카오맵 차트 타입 파이 크기 고정 DOGFOOT
										value : self.chartEditOptions['chartType'] == 'Pie' ? '파이' : '버블',
										onValueChanged : function(e){
											if(e.value == '파이'){
												$('#chartWeightEnabled').dxCheckBox('instance').option('value', false);
											}else{
												$('#chartWeightEnabled').dxCheckBox('instance').option('value', true);
//												$('#chartWeightEnabled').dxCheckBox('instance').option('value', self.chartEditOptions['chartWeightEnabled']);
											}
										}
									}
								},
								//2020.10.08 MKSONG 카카오맵 투명도 조정 기능 옵션 추가 DOGFOOT
								{
									dataField : "차트 측정값에 따른 비중 여부" ,
									editortType : 'dxCheckBox',
									editorOptions:{
										'value' : self.chartEditOptions['chartWeightEnabled'],
										'elementAttr' : {
											'id' : 'chartWeightEnabled'
										},
									}
								}
//								{
//									dataField : "차트 크기 조정 기준" ,
//									editorType : "dxSelectBox",
//									editorOptions:{
//										value : chartWeightOption == 'addressType' ? '주소 영역별 기준' : '전체 비율 기준',
//										dataSource : ['주소 영역별 기준','전체 비율 기준'],
//										elementAttr : {
//											'id' : 'chartWeightOption'
//										},
//										onValueChanged : function(data){
//											chartWeightOption = data.value == '주소 영역별 기준' ? 'addressType' : 'rateType';
//										}
//									}
//								}
							]
						});
						
						/* DOGFOOT syjin 카카오 지도 폴리곤 레이블 설정 20201006 */
						var chartLabelOptionsForm = $('#'+ self.itemid+'_chartLabelOptions').dxForm({
							items : [
								{
									dataField : "표기 형식",
									editorType : "dxSelectBox",
									editorOptions : {
										dataSource : ['없음', '인수', '값', '%', '인수 및 값', 
											 '값 및 %', '인수 및 %', '인수, 값 및 %'],
										elementAttr : {
											 'id' : 'chartLabelOptions'
										},
										value : self.chartEditOptions['chartLabelOptions']['type'] 
									}
								}
							]
						});
                        
						$('#' + self.itemid + '_chartPalette').dxSelectBox({
//                            width: 400,
	
                            items: paletteCollection2,
                            itemTemplate: function(data) {
                                var html = $('<div />');
                                $('<p />').text(data).css({
                                    display: 'inline-block',
                                    float: 'left'
                                }).appendTo(html);
                                
                                var colorArray = [];
                                if(data === '사용자 정의 테마'){
                                	$.each(self.chartEditOptions.CustomPalette.Color,function(_i,_color){
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
                                	$.each(self.chartEditOptions.CustomPalette.Color,function(_i,_color){
     									if(typeof _color == 'string' && _color.indexOf('#') > -1){
     										colorArray.push(_color.toUpperCase());	
     									}else{
     										colorArray.push(self.getHexColor(_color).toUpperCase());
     									}	
     								});
//                                    self.dxItem.option('layers[0].palette', colorArray);
								} else {
                                    self.isCustomPalette = false;
//                                    self.dxItem.option('layers[0].palette',paletteObject2[e.value]);
                                    //self.dxItem.option('palette', paletteObject2[e.value]);
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });

						//색상 편집
						var customListCnt = [];
						if (self.chartEditOptions.CustomPalette != undefined){  
							if(self.chartEditOptions.CustomPalette.Color.length > 0) {
								paletteCollection.push('Custom');
								paletteCollection2.push('사용자 정의 테마');	
							}
						}
						
						var colorContainer = $("#" + self.itemid + "_chartCustomColor");
						var colorCustomList = [];
						
						self.samplePalettePoint.forEach(function(index) {
							colorContainer.append('<p>Point ' + index
													+ '</p><div id="' + self.itemid + '_pointColor' + index + '">');
                        });
                        colorContainer.dxScrollView({
                            height: 200,
                            width: '100%'
                        });
                        
						self.samplePalettePoint.forEach(function(index) {
							var palette = self.chartEditOptions.CustomPalette.Color.length > 0 ? self.chartEditOptions.CustomPalette.Color : DevExpress.viz.getPalette(originalPalette).simpleSet;
							//2020.11.06 MKSONG 카카오맵 차트 팔레트 인덱스 오류 수정 DOGFOOT
							var paletteIndex = self.chartEditOptions.CustomPalette.Color.length > 0 ? index : index % 6;
							
							$('#' + self.itemid + '_pointColor' + index).dxColorBox({
								value: palette[paletteIndex]
							});
                        });
				// popup configs
				
	               }	
				});
				p.option('visible', !(p.option('visible')));
//				p.option('position', 'center');
				
				//when click confirm
				$("#ok-hide").click(function(){
					/* DOGFOOT syjin 카카오 지도 폴리곤 차트 표시 유무 설정 20201005 */
					//display polygonChart
					self.chartEditOptions['chartType'] = $('#chartType').dxSelectBox('instance').option('value') == '파이' ? 'Pie' : 'Bubble';
					//2020.10.08 MKSONG 카카오맵 투명도 조정 기능 옵션 추가 DOGFOOT
					self.chartEditOptions['chartWeightEnabled'] = $("#chartWeightEnabled").dxCheckBox('instance').option('value');
					self.chartEditOptions['chartWeightOption'] = chartWeightOption;
					
					/* DOGFOOT syjin 카카오 지도 폴리곤 레이블 설정 20201006 */
					self.chartEditOptions['chartLabelOptions']['type'] = $("#chartLabelOptions").dxSelectBox('instance').option('value');
	                
 					self.chartEditOptions.Palette = paletteObject2[$('#' + self.itemid + '_chartPalette').dxSelectBox('instance').option('value')];
                    changePalette = paletteObject2[$('#' + self.itemid + '_chartPalette').dxSelectBox('instance').option('value')];
					
					 var newPalette = [];

                    self.samplePalettePoint.forEach(function(item, index) {
                        newPalette[index] = $('#' + self.itemid + '_pointColor' + index).dxColorBox('instance').option('value');
                    });
                    self.chartEditOptions.CustomPalette.Color = newPalette;
                    self.customPalette = newPalette;
                    self.isCustomPalette = true;
					
					//2020.12.9 SYJIN 차트편집 확인 누를 시 조회되도록 수정 DOGFOOT
				    self.functionBinddata = true;
				    self.bindData();

					//popup hide
					$("#editPopup").dxPopup('instance').hide();
				});
				
				//when click cancel
				$("#close").click(function(){
					$("#editPopup").dxPopup('instance').hide();
				})
				
				//when click tab
				$("#tabP1-1").click(function(){
					$("#tab-content1").css("display", "block");
					$("#tab-content2").css("display", "none");
					$("#tab-content3").css("display", "none");
					
					$("#tabP1-1").addClass('on');
					$("#tabP1-2").removeClass('on');
					$("#tabP1-3").removeClass('on');
					
					p.option('position', 'center');
				});
				
				$("#tabP1-2").click(function(){
					$("#tab-content2").css("display", "block");
					$("#tab-content1").css("display", "none");
					$("#tab-content3").css("display", "none");
					
					$("#tabP1-2").addClass('on');
					$("#tabP1-1").removeClass('on');
					$("#tabP1-3").removeClass('on');
					
					p.option('position', 'center');
				});
				
				$("#tabP1-3").click(function(){
					$("#tab-content3").css("display", "block");
					$("#tab-content1").css("display", "none");
					$("#tab-content2").css("display", "none");
					
					$("#tabP1-3").addClass('on');
					$("#tabP1-1").removeClass('on');
					$("#tabP1-2").removeClass('on');
					
					p.option('position', 'center');
				});
				
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
WISE.libs.Dashboard.KakaoMapFieldManager = function() {
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
		self.DataItems['Latitude'] = [];
		self.DataItems['Longitude'] = [];
		self.DataItems['Address'] = [];
		//2020.09.24 mksong 카카오맵 데이터 정보 수정  dogfoot
		self.DataItems['MarkerDimension'] = [];
		
		var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
		
		for(var i = 0; i < _fieldlist.length; i++){
			var dataFieldType = $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1);
//			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
			//2020.09.22 mksong dogfoot 카카오지도 주소필드 추가
			//2020.09.24 mksong 카카오맵 데이터 정보 수정  dogfoot
			if(dataFieldType=='kakaoMapAddressList' || dataFieldType=='kakaoMapLatitudeList' || dataFieldType=='kakaoMapLongitudeList' || dataFieldType=='kakaoMapParameterList'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
//				dataItem['DataMember'] = $(_fieldlist[i]).children().get(0).innerText; 
//				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				//2020.09.28 mksong 주소타입 지정 dogfoot
				//2020.10.23 syjin 주소타입 지정 SelectBox로 변경 dogfoot
				if(dataFieldType=='kakaoMapAddressList'){
					//2020.11.02 syjin 카카오맵 selectBox 반응형 처리 dogfoot
					var componentName = $(self.stateFieldChooser).attr('id').substr(0,$(self.stateFieldChooser).attr('id').lastIndexOf('fieldM'));
                    var selectValue = $("#"+componentName+"addressSelectLabel").dxSelectBox('instance').option('value');
					switch(selectValue){
						case '시도':
							dataItem['AddressType'] = 'Sido';
						break;

						case '시도+시군구':
							dataItem['AddressType'] = 'SiGunGu';
						break;

						case '시도+시군구+읍면동':
							dataItem['AddressType'] = 'EupMyeonDong';
						break;
					}

					//dataItem['AddressType'] = $(_fieldlist[i]).find('.addressTypeList').find('.on').attr('addressType');
				}else{
					dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');	
				}
				
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
				
				//2020.09.24 mksong 카카오맵 데이터 정보 수정  dogfoot
				switch(dataFieldType){
					case 'kakaoMapAddressList':
						self.DataItems['Address'].push(dataItem);
						break;
					case 'kakaoMapLatitudeList':
						self.DataItems['Latitude'].push(dataItem);
						break;
					case 'kakaoMapLongitudeList':
						self.DataItems['Longitude'].push(dataItem);
						break;
					case 'kakaoMapParameterList':
						self.DataItems['MarkerDimension'].push(dataItem);
						break;
				}
//			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
			} else if(dataFieldType=='kakaoMapValueList') {
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
	
	this.setSeriesDimensionsByField = function(_series){
		this.SeriesDimensions = {'SeriesDimension' : []};
		_.each(_series,function(_s){
			var Value = {'UniqueName' : _s.uniqueName};
			self.SeriesDimensions['SeriesDimension'].push(Value);
		})
		return self.SeriesDimensions;
	};
	
	this.setArgumentsByField = function(_argument){
		this.attributeDimension = {};
//		_.each(_argument,function(_a){
			//dogfoot 코로플레스 맵 안그려지는 오류 수정  shlim 20200612
			if(_argument.length != 0){
				var Value = {'UniqueName' : _argument[0].uniqueName};
	//			self.Arguments['Argument'].push(Value);
				self.attributeDimension = Value;	
			}
			
//		})
		return self.attributeDimension;
	};

	this.setLatitudeByField = function(_latitude){
		this.Latitude = {'latitude' : []};

		_.each(_latitude, function(_s){
			var Value = {'UniqueName' : _s.uniqueName};
			self.Latitude = Value;
		})
		return self.Latitude;
	}

	this.setLongitudeByField = function(_longitude){
		this.Longitude = {'longitude' : []};

		_.each(_longitude, function(_s){
			var Value = {'UniqueName' : _s.uniqueName};
			self.Longitude = Value;
		})
		return self.Longitude;
	}

	//2020.09.22 mksong dogfoot 카카오지도 주소필드 추가
	this.setAddressByField = function(_address){
		this.Addresses = {'address' : []};

		_.each(_address, function(_s){
			var Value = {'UniqueName' : _s.uniqueName};
			self.addresses = Value;
		})
		return self.addresses;
	}

	this.setDimensionsByField = function(_dimensions){
		this.Dimensions = {'dimensions' : []};

		_.each(_dimensions, function(_s){
			var Value = {'UniqueName' : _s.uniqueName};
			self.Dimensions = Value;
		})
		
		return self.Dimensions;
	}

	this.setFieldsByField = function(_fields){
		this.Fields = {'fields' : []};

		_.each(_fields, function(_s){
			var Value = {'UniqueName' : _s.uniqueName};
			self.Fields = Value;
		})
		return self.Fields;
	}
	
	this.setMarkerDimensionsByField = function(_markerDimensions){
		this.MarkerDimension = {};

		_.each(_markerDimensions, function(_s){
			
			var Value = {'UniqueName' : _s.uniqueName};
			self.MarkerDimension = Value;
		})
		return self.MarkerDimension;
		;
	}
};
