/**
 * 2020.05.12 MKSON DOGFOOT
 * 모든 아이템의 팔레트 부분은 이곳에서 관리
 */

WISE.libs.Dashboard.item.ItemColorManager = function() {
	var self = this;
	
	this.dashboardid;
	this.colorMeta;
	
	this.paletteColor = ['#5F8B95','#BA4D51','#AF8A53','#955F71','#859666','#7E688C','#5F6D95','#AC569C','#A6AF53','#95715F',
		'#5D9E81', '#A6779B','#4AA1AA','#7181C5','#C4853D','#BBC289','#9D5361','#9DA0AD','#5C577E','#E3A653'];
	
	this.init = function(){
		this.colorMeta = [];
		
		var colorList = WISE.util.Object.toArray(typeof window[this.dashboardid].structure.ColorSheme == 'undefined' ?  [] : window[this.dashboardid].structure.ColorSheme.Entry);
		$.each(colorList,function(_i,_e){
			var colorItem = {
					Color: typeof _e.Color == 'undefined' ? undefined : _e.Color,
					DataSource : _e.DataSource,
					DataMember : typeof  _e.DimensionKeys == 'undefined'? _e.MeasureKey.Definition.DataMember :  _e.DimensionKeys.DimensionKey.Definition.DataMember,
					Value : typeof  _e.DimensionKeys == 'undefined' ?  _e.MeasureKey.Definition.DataMember :_e.DimensionKeys.DimensionKey.Value.Value,
					PaletteIndex : _e.PaletteIndex,
					isMeasure :  typeof  _e.DimensionKeys == 'undefined' ? true : false
			}
			self.colorMeta.push(colorItem);
		});
	};
	
	this.generateColorMeta = function(_colorMeta){
		var returnColorList = [];
		var colorList = WISE.util.Object.toArray(_colorMeta || []);
		$.each(colorList,function(_i,_e){
			var colorItem = {
					Color: _e.Color,
					DataSource : _e.DataSource,
					DataMember : (typeof  _e.DimensionKeys == 'undefined' ?  _e.MeasureKey.Definition.DataMember: _e.DimensionKeys.DimensionKey.Definition.DataMember),
					Value : typeof  _e.DimensionKeys == 'undefined'? _e.MeasureKey.Definition.DataMember: _e.DimensionKeys.DimensionKey.Value.Value,
					PaletteIndex : _e.PaletteIndex,
					isMeasure :  typeof  _e.DimensionKeys == 'undefined' ? true : false
			}
			returnColorList.push(colorItem);
		});
		return returnColorList;
	};
	this.getHexColor = function(number){
	    return "#"+((number)>>>0).toString(16).slice(-6);
	};
	this.rgbToHex = function(rgbStr){
		if(rgbStr != undefined){
			rgbStr = "ff"+rgbStr.substring(1);
			var returnBinStr = (parseInt((rgbStr).toString(), 16)-0xFFFFFFFF-0x00000001).toString(2);
			return parseInt((returnBinStr).toString(), 2).toString(10);	
		}else{
			return '';
		}
	};
	this.hexToRgb = function(hex)
	{
		var result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
		return result ? {
			r : parseInt(result[1], 16),
			g : parseInt(result[2], 16),
			b : parseInt(result[3], 16)
		} : null;
	};
};