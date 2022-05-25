WISE.libs.Dashboard.item.MapGenerator = {
	setLegendPostion: function(_legend, _position) {
		switch(_position) {
		case 'BottomLeft':
			_legend.verticalAlignment = 'bottom';
			_legend.horizontalAlignment = 'left';
			break;
		case 'BottomCenter':
			_legend.verticalAlignment = 'bottom';
			_legend.horizontalAlignment = 'center';
			break;
		case 'BottomRight':
			_legend.verticalAlignment = 'bottom';
			_legend.horizontalAlignment = 'right';
			break;
		case 'TopCenter':
			_legend.verticalAlignment = 'top';
			_legend.horizontalAlignment = 'center';
			break;
		case 'TopRight':
			_legend.verticalAlignment = 'top';
			_legend.horizontalAlignment = 'right';
			break;
		default:
			_legend.verticalAlignment = 'top';
			_legend.horizontalAlignment = 'left';
		}
		return _legend;
	}
};
WISE.libs.Dashboard.item.MapGenerator.PanelManager = function() {
	var self = this;
	
	this.dashboardid;
	this.itemid; // map chart item id
	this.valuePanel = {};
	
	this.empty = function() {
		$.each(this.valuePanel, function(_k, _vp) {
			_vp.panel.empty();
			_vp.panel.empty();
		});
	};
	
	this.makePanel = function(_values, _arguments) {
		var PP = $('#' + this.itemid);
		PP.empty();
		
		// reset value panel
		this.valuePanel = {};

		if ($.type(_arguments) === 'array' && _arguments.length > 0) {
			$.each(_values, function(_i, _v) {
				var id = self.itemid + '_' + _v.uniqueName;
				var activeCssClass = 'active'
				var valuePanel = $('<div id="' + id + '" class="dx-item-map-panel ' + activeCssClass + '"></div>');
				PP.append(valuePanel);
					
				self.valuePanel[id] = {panel: valuePanel, value: _v, title: _v.caption}; 
			});
		}
		else {
			var pid = new Date().valueOf();
			var id = self.itemid + '_' + pid;
			var activeCssClass = 'active'
			var valuePanel = $('<div id="' + id + '" class="dx-item-map-panel ' + activeCssClass + '"></div>');
			PP.append(valuePanel);
					
			self.valuePanel[id] = {panel: valuePanel}; 
		}
	};
	
	this.activeValuePanel = function(itemid,_activePanelId) {
		$.each(this.valuePanel, function(_k, _vp) {
			_vp.panel.removeClass('active');
			_vp.panel.addClass('in-active');
		});
		$.each(this.valuePanel, function(_k, _vp) {
			if (_k === _activePanelId) { 
				
				_vp.panel.removeClass('in-active');
				_vp.panel.addClass('active');
				
				if (!self.initTitleNm) {
					self.initTitleNm = $('#' + self.itemid + '_title').text().split('-');
				}
				
				if (_vp.title) {
					var title = self.initTitleNm[0] + ' - ' + _vp.title;
					if(gDashboard.goldenLayoutManager.canvasLayout != undefined){
						/* DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류 수정  20191223 */
                    	
//                    	var goldenLayout = gDashboard.goldenLayoutManager;
//                    	goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);
                    	
                    	var ele = $('#' + self.itemid + '_title');
                    	ele.attr( 'title', title)
                        ele.find( '.lm_title' ).html(title);
					}else{
						$('#' + self.itemid + '_title').text(title);
					}
				}
				
				self.ativePanelId = _activePanelId;
				var svg = $('#' + _activePanelId).children('svg').get(0);
				if (!svg) {
					var dxConfigs = _vp.dxConfigs;
					
					if (_vp.useShapeFile) {
						WISE.alert('can not use shaper file..');
						// DevExpress.viz.vectormaputils.parse(_vp.shapelocation, {precision: 2}, function (_mapData) {
							// dxConfigs.mapData = _mapData.features;
							// var item = $('#' + _activePanelId).dxVectorMap(dxConfigs).dxVectorMap('instance');
							
							// $.each(item.getAreas(), function(_i0, _area) {
								// $.each(self.mapData, function(_i1, _data0) {
									// if (_area.attribute('province') == _data0['영문지역명']) { //alert(_data0['sum_상담시간']);
										// _area.applySettings({
											// color: _data0['영문지역명']
										// });
									// }
								// });
							// });
						// });
					} else {
						var item = $('#' + _activePanelId).dxVectorMap(dxConfigs).dxVectorMap('instance');
						gProgressbar.hide();
					}
				}
				
				return false;
			}
		});
	};
};
