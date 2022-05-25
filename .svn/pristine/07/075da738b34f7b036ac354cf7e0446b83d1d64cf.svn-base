WISE.libs.Dashboard.item.LiquidFillGaugeGenerator = function() {
	var self = this;

	this.type = 'LIQUID_FILL_GAUGE';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	
	var dataMember;
	var Exprname;
	var FilterArray = [];
	
	this.LiquidFillGauge = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	this.customPalette = [];
	this.isCustomPalette = false;
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [""];
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	this.resizeData = [];
	this.trackingData = [];
	this.tempTrackingData = [];
	
	/**
	 * @param _item:
	 *            meta object
	 */
	var CheckCurrentFilter;
	this.getDxItemConfig = function(_item) {

		this.dataSourceConfig = {};
		this.dataSourceConfig.fields = [];

		var count = 0;
		
//		D = _item.FilterDimensions ? WISE.util.Object
//				.toArray(_item.DataItems.Dimension) : [];

		this.DU = WISE.libs.Dashboard.item.DataUtility;
		
		this.DI = _item.DataItems;
		this.V = WISE.util.Object.toArray((_item.Values && _item.Values.Value) || []);
		this.A = WISE.util.Object.toArray((_item.Arguments && _item.Arguments.Argument) || []);
		
		this.measures = [];
		$.each(this.V, function(_i0, _a0) {
			var uniqueName = _a0['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			self.measures.push(dataMember);
		});
		this.dimensions = [];
		$.each(this.A, function(_i0, _a0) {
			var uniqueName = _a0['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			self.dimensions.push(dataMember);
		});
		
		var dxConfigs = {
			dataSource : this.dataSourceConfig,
			dataStructure: 'plain',
			allowExpandAll: true,
			allowFiltering: true,
			allowSorting: true,
			allowSortingBySummary: true,
			size:{
				width : $('#'+self.itemid).width(),
				height : $('#'+self.itemid).height(),
			},
			tooltip: {
				enabled: true,
				zIndex: 21,
				customizeTooltip:function(_pointInfo){
					var text = '<b>' + _pointInfo.node.data.name + '</b>' + '<br/>' +"<b>" +self.currentMeasureName+"</b> : " +WISE.util.Number.unit(_pointInfo.value,'O',0);
					ret = {html: text};
					return ret;
				}
			}
		}

		// extend custom-configurations
		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
		var CustomConfigs = $.extend({}, Configurations);
		$.extend(CustomConfigs, dxConfigs);
		dxConfigs = CustomConfigs;
		return dxConfigs;
	};
	
	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	};
	
	var idGenerator = (function() {
        var count = 0;
        return function(prefix) {
            return prefix + "-" + count++;
        };
    })();

    var defaultConfig = {
        // Values
        minValue: 0, // The gauge minimum value.
        maxValue: 100, // The gauge maximum value.

        // Styles
        circleThickness: 0.05, // The outer circle thickness as a percentage of it's radius.
        circleFillGap: 0.05, // The size of the gap between the outer circle and wave circle as a percentage of the outer circles radius.
        circleColor: "#178BCA", // The color of the outer circle.
        backgroundColor: "#fff", // The color of the background
        waveColor: "#178BCA", // The color of the fill wave.
        width: 0, // You might want to set the width and height if it is not detected properly by the plugin
        height: 0,

        // Gradient
        fillWithGradient: false, // Controls if the wave should be filled with gradient
        gradientPoints: [0, 0, 1., 1.], //  [x1, y1, x2, y2], coordinates for gradient start point(x1,y1) and final point(x2,y2)
        gradientFromColor: "#FFF",
        gradientToColor: "#000",

        // Waves
        waveHeight: 0.05, // The wave height as a percentage of the radius of the wave circle.
        waveCount: 3, // The number of full waves per width of the wave circle.
        waveOffset: 0.25, // The amount to initially offset the wave. 0 = no offset. 1 = offset of one full wave.

        // Animations
        waveRise: true, // Control if the wave should rise from 0 to it's full height, or start at it's full height.
        waveRiseTime: 1000, // The amount of time in milliseconds for the wave to rise from 0 to it's final height.
        waveRiseAtStart: true, // If set to false and waveRise at true, will disable only the initial animation
        waveAnimate: true, // Controls if the wave scrolls or is static.
        waveAnimateTime: 2000, // The amount of time in milliseconds for a full wave to enter the wave circle.
        waveHeightScaling: true, // Controls wave size scaling at low and high fill percentages. When true, wave height reaches it's maximum at 50% fill, and minimum at 0% and 100% fill. This helps to prevent the wave from making the wave circle from appear totally full or empty when near it's minimum or maximum fill.
        valueCountUp: true, // If true, the displayed value counts up from 0 to it's final value upon loading and updating. If false, the final value is displayed.
        valueCountUpAtStart: true, // If set to false and valueCountUp at true, will disable only the initial animation

        // Text
        textVertPosition: 0.5, // The height at which to display the percentage text withing the wave circle. 0 = bottom, 1 = top.
        textSize: 1, // The relative height of the text to display in the wave circle. 1 = 50%
        displayPercent: true, // If true, a % symbol is displayed after the value.
        textColor: "#045681", // The color of the value text when the wave does not overlap it.
        waveTextColor: "#A4DBf8", // The color of the value text when the wave overlaps it.
        
        //Title
        titleVertPosition: 0.9,
        titleSize: 0.4,
        
        //value
        valueVertPosition: 0.3,
        valueSize: 0.4,
        	
        //margin
        margin : 10
    };

    var liquidfillgauge = function(g, pValue,value, title, settings) {
        // Handle configuration
        var config = d3.map(defaultConfig);
        d3.map(settings).each(function(val, key) {
            config.set(key, val);
        });

        g.each(function(d) {
            var gauge = d3.select(this);
            var margin = config.get("margin");
            var width = (config.get("width") !== 0 ? config.get("width") : parseInt(gauge.attr("width"))) - margin * 2;
            var height = (config.get("height") !== 0 ? config.get("height") : parseInt(gauge.attr("height"))) - margin * 2;
            var radius = Math.min(width, height) / 2;
            var locationX = width / 2 - radius;
            var locationY = height / 2 - radius;
            var fillPercent = Math.max(config.get("minValue"), Math.min(config.get("maxValue"), pValue)) / config.get("maxValue");

            var waveHeightScale;
            if (config.get("waveHeightScaling")) {
              waveHeightScale = d3.scaleLinear()
                  .range([0, config.get("waveHeight"), 0])
                  .domain([0, 50, 100]);
            } else {
                waveHeightScale = d3.scaleLinear()
                  .range([config.get("waveHeight"), config.get("waveHeight")])
                  .domain([0, 100]);
            }

            var textPixels = (config.get("textSize") * radius / 2);
            var textFinalValue = parseFloat(pValue).toFixed(2);
            var textStartValue = config.get("valueCountUp") ? config.get("minValue") : textFinalValue;
            var percentText = config.get("displayPercent") ? "%" : "";
            var titlePixels = (config.get("titleSize") * radius / 2);
            var valuePixels = (config.get("valueSize") * radius / 2);
            var circleThickness = config.get("circleThickness") * radius;
            var circleFillGap = config.get("circleFillGap") * radius;
            var fillCircleMargin = circleThickness + circleFillGap;
            var fillCircleRadius = radius - fillCircleMargin;
            var waveHeight = fillCircleRadius * waveHeightScale(fillPercent * 100);

            var waveLength = fillCircleRadius * 2 / config.get("waveCount");
            var waveClipCount = 1 + config.get("waveCount");
            var waveClipWidth = waveLength * waveClipCount;

            // Rounding functions so that the correct number of decimal places is always displayed as the value counts up.
            var textRounder = function(value) {
                return Math.round(value);
            };
            if (parseFloat(textFinalValue) != parseFloat(textRounder(textFinalValue))) {
                textRounder = function(value) {
                    return parseFloat(value).toFixed(1);
                };
            }
            if (parseFloat(textFinalValue) != parseFloat(textRounder(textFinalValue))) {
                textRounder = function(value) {
                    return parseFloat(value).toFixed(2);
                };
            }

            // Data for building the clip wave area.
            var data = [];
            for (var i = 0; i <= 40 * waveClipCount; i++) {
                data.push({
                    x: i / (40 * waveClipCount),
                    y: (i / (40))
                });
            }

            // Scales for drawing the outer circle.
            var gaugeCircleX = d3.scaleLinear().range([0, 2 * Math.PI]).domain([0, 1]);
            var gaugeCircleY = d3.scaleLinear().range([0, radius]).domain([0, radius]);

            // Scales for controlling the size of the clipping path.
            var waveScaleX = d3.scaleLinear().range([0, waveClipWidth]).domain([0, 1]);
            var waveScaleY = d3.scaleLinear().range([0, waveHeight]).domain([0, 1]);

            // Scales for controlling the position of the clipping path.
            var waveRiseScale = d3.scaleLinear()
            // The clipping area size is the height of the fill circle + the wave height, so we position the clip wave
            // such that the it will won't overlap the fill circle at all when at 0%, and will totally cover the fill
            // circle at 100%.
              .range([(fillCircleMargin + fillCircleRadius * 2 + waveHeight), (fillCircleMargin - waveHeight)])
              .domain([0, 1]);
            var waveAnimateScale = d3.scaleLinear()
              .range([0, waveClipWidth - fillCircleRadius * 2]) // Push the clip area one full wave then snap back.
              .domain([0, 1]);

            // Scale for controlling the position of the text within the gauge.
            var textRiseScaleY = d3.scaleLinear()
              .range([fillCircleMargin + fillCircleRadius * 2, (fillCircleMargin + textPixels * 0.7)])
              .domain([0, 1]);

            // Center the gauge within the parent
            var gaugeGroup = gauge.append("g").attr("cursor", "pointer").on("click", function(){
            	var selectCircle = function(d){
    				d3.select(d).select('circle').style("fill", config.get("circleColor")).style("opacity", 0.2);
    			}
    			
    			var unselectCircle = function(d){
    				d3.select(d).select('circle').style("fill", config.get("backgroundColor")).style("opacity", 1);
    			}
    			
    			var unselectAllCircle = function(){
    				d3.selectAll('#' + self.itemid + ' .bgCircle').style("fill", config.get("backgroundColor")).style("opacity", 1);
    			}
    			
            	switch(self.meta.InteractivityOptions.MasterFilterMode){
		    		case 'Single':
		    			var selectPath = d3.select(this).select('path');
		    			var selectAllPath = d3.selectAll('#' + self.itemid + ' path')
		    			self.trackingData = [];
		    			self.tempTrackingData = [];
		    			if(selectPath.attr("filter") === "true"){
		    				selectAllPath.style("opacity", 0.5).attr("filter", "false");
		    				unselectAllCircle();
				    	}else{
				    		//선택 모두 해제
				    		selectAllPath.style("opacity", 0.5).attr("filter", "false");
				    		unselectAllCircle();
							
				    		selectPath.style("opacity", 1).attr("filter", "true");
				    		selectCircle(this);
				    		
				    		var dimNames = title.split(' - ');
				    		var tempSelectedData = {};
			       			$.each(self.dimensions, function(i, dim){
			       				var selectedData = {};
				    			selectedData[dim.name] = dimNames[i]
				    			tempSelectedData[dim.name] = dimNames[i]
				    			self.trackingData.push(selectedData);
			       			});
			       			self.tempTrackingData.push(tempSelectedData);
			       			var dimNames = title.split(' - ');
				    		var selectedData = {};
				    	}
		    			/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
						if(WISE.Constants.editmode === "viewer"){
							gDashboard.itemGenerateManager.focusedItem = self;
						}
			       		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
		           		gDashboard.filterData(self.itemid, self.trackingData);
		    		break;
			    	case 'Multiple':
			    		var selectPath = d3.select(this).select('path');
		    			var selectAllPath = d3.selectAll('#' + self.itemid + ' path')
				    	if(selectPath.attr("filter") === "true"){
				    		selectPath.style("opacity", 0.5).attr("filter", "false");
				    		unselectCircle(this);
				    		var dimNames = title.split(' - ');
				    		for (var index = 0; index < self.tempTrackingData.length; index++) {
				    			var check = 0;
			       				$.each(self.dimensions, function(i, dim){
			       					if(self.tempTrackingData[index][dim.name] === dimNames[i])
			       						check++;
			       				})
			       				if(check === self.dimensions.length){
			       					self.tempTrackingData.splice(index, 1);
			       					index--;
			       				}
			       			}
				    	}else{
				    		selectPath.style("opacity", 1).attr("filter", "true");
				    		selectCircle(this);
				    		
				    		var dimNames = title.split(' - ');
				    		var selectedData = {};
			       			$.each(self.dimensions, function(i, dim){
				    			selectedData[dim.name] = dimNames[i]
			       			})
				    		self.tempTrackingData.push(selectedData);
				    	}
				    	
				    	self.trackingData = [];
				    	
				    	$.each(self.dimensions, function(i, dim){
				    		var unique = self.tempTrackingData.map(function(val, index){
				    			return val[dim.name];
				    		}).filter(function(val, index, arr){
				    			return arr.indexOf(val) === index;
				    		});
				    		
				    		for(var j = 0; j < unique.length; j++){
				    			var selectedData = {};
				    			selectedData[dim.caption] = unique[j]
				    			self.trackingData.push(selectedData);
				    		}
				    	})
				    	/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
						if(WISE.Constants.editmode === "viewer"){
							gDashboard.itemGenerateManager.focusedItem = self;
						}
			       		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
		           		gDashboard.filterData(self.itemid, self.trackingData);
			    	break;
		    	  }
            })
              .attr('transform', 'translate(' + locationX + ',' + locationY + ')');

            var inArray = false;
            var _dimNames = title.split(' - ');
    		for (var index = 0; index < self.tempTrackingData.length; index++) {
    			var check = 0;
   				$.each(self.dimensions, function(i, dim){
   					if(self.tempTrackingData[index][dim.name] === _dimNames[i])
   						check++;
   				})
   				if(check === self.dimensions.length){
   					inArray = true;
   					break;
   				}
   			}
    		
            // Draw the background circle
            if (config.get("backgroundColor")) {
                gaugeGroup.append("circle")
                  .attr("r", radius)
                  .attr("class", "bgCircle")
                  .style("fill", inArray?config.get("circleColor") : config.get("backgroundColor"))
                  .style("opacity", inArray? 0.2 : 1 )
                  .attr('transform', 'translate(' + radius + ',' + radius + ')');
            }

            // Draw the outer circle.
            var gaugeCircleArc = d3.arc()
              .startAngle(gaugeCircleX(0))
              .endAngle(gaugeCircleX(1))
              .outerRadius(gaugeCircleY(radius))
              .innerRadius(gaugeCircleY(radius - circleThickness));
            gaugeGroup.append("path")
              .attr("d", gaugeCircleArc)
              .style("fill", config.get("circleColor"))
              .style("opacity", inArray? 1 : 0.5)
              .attr("filter", inArray? "true": "false")
              .attr('transform', 'translate(' + radius + ',' + radius + ')')

            function wrap() {
            	var self = d3.select(this),
            	textLength = self.node().getComputedTextLength(),
            	text = self.text();
            	while (textLength > (width) && text.length > 0) {
            		text = text.slice(0, -1);
            		self.text(text + '...');
            		textLength = self.node().getComputedTextLength();
            	}
            } 
            
            // Text where the wave does not overlap.
            var text1 = gaugeGroup.append("text")
              .attr("class", "liquidFillGaugeText")
              .attr("text-anchor", "middle")
              .attr("font-size", textPixels + "px")
              .style("fill", config.get("textColor"))
              .attr('transform', 'translate(' + radius + ',' + textRiseScaleY(config.get("textVertPosition")) + ')');
            
            var title1 = gaugeGroup.append("text")
            .attr("class", "liquidFillGaugeText")
            .attr("text-anchor", "middle")
            .attr("font-size", titlePixels + "px")
            .style("fill", config.get("textColor"))
            .attr('transform', 'translate(' + radius + ',' + textRiseScaleY(config.get("titleVertPosition")) + ')');

            var value1 = gaugeGroup.append("text")
            .attr("class", "liquidFillGaugeText")
            .attr("text-anchor", "middle")
            .attr("font-size", valuePixels + "px")
            .style("fill", config.get("textColor"))
            .attr('transform', 'translate(' + radius + ',' + textRiseScaleY(config.get("valueVertPosition")) + ')');

            // The clipping wave area.
            var clipArea = d3.area()
              .x(function(d) {
                  return waveScaleX(d.x);
              })
              .y0(function(d) {
                  return waveScaleY(Math.sin(Math.PI * 2 * config.get("waveOffset") * -1 + Math.PI * 2 * (1 - config.get("waveCount")) + d.y * 2 * Math.PI));
              })
              .y1(function(d) {
                  return (fillCircleRadius * 2 + waveHeight);
              });

            var gaugeGroupDefs = gaugeGroup.append("defs");

            var clipId = idGenerator("clipWave");
            var waveGroup = gaugeGroupDefs
              .append("clipPath")
              .attr("id", clipId);
            var wave = waveGroup.append("path")
              .datum(data)
              .attr("d", clipArea);

            // The inner circle with the clipping wave attached.
            var fillCircleGroup = gaugeGroup.append("g")
              .attr("clip-path", "url(#" + clipId + ")");
            fillCircleGroup.append("circle")
              .attr("cx", radius)
              .attr("cy", radius)
              .attr("r", fillCircleRadius);

            if (config.get("fillWithGradient")) {
                var points = config.get("gradientPoints");
                var gradientId = idGenerator("linearGradient");
                var grad = gaugeGroupDefs.append("linearGradient")
                  .attr("id", gradientId)
                  .attr("x1", points[0])
                  .attr("y1", points[1])
                  .attr("x2", points[2])
                  .attr("y2", points[3]);
                grad.append("stop")
                  .attr("offset", "0")
                  .attr("stop-color", config.get("gradientFromColor"));
                grad.append("stop")
                  .attr("offset", "1")
                  .attr("stop-color", config.get("gradientToColor"));

                fillCircleGroup.style("fill", "url(#" + gradientId + ")");
            } else {
                fillCircleGroup.style("fill", config.get("waveColor"));
            }

            // Text where the wave does overlap.
            var text2 = fillCircleGroup.append("text")
              .attr("class", "liquidFillGaugeText")
              .attr("text-anchor", "middle")
              .attr("font-size", textPixels + "px")
              .style("fill", config.get("waveTextColor"))
              .attr('transform', 'translate(' + radius + ',' + textRiseScaleY(config.get("textVertPosition")) + ')');
            
         // Text where the wave does overlap.
            var title2 = fillCircleGroup.append("text")
              .attr("class", "liquidFillGaugeText")
              .attr("text-anchor", "middle")
              .attr("font-size", titlePixels + "px")
              .style("fill", config.get("waveTextColor"))
              .attr('transform', 'translate(' + radius + ',' + textRiseScaleY(config.get("titleVertPosition")) + ')');
            
            var value2 = fillCircleGroup.append("text")
            .attr("class", "liquidFillGaugeText")
            .attr("text-anchor", "middle")
            .attr("font-size", valuePixels + "px")
            .style("fill", config.get("waveTextColor"))
            .attr('transform', 'translate(' + radius + ',' + textRiseScaleY(config.get("valueVertPosition")) + ')');

            // Make the wave rise. wave and waveGroup are separate so that horizontal and vertical movement can be controlled independently.
            var waveGroupXPosition = fillCircleMargin + fillCircleRadius * 2 - waveClipWidth;

            if (config.get("waveAnimate")) {
                var animateWave = function() {
                    wave.transition()
                      .duration(config.get("waveAnimateTime"))
                      .ease(d3.easeLinear)
                      .attr('transform', 'translate(' + waveAnimateScale(1) + ',0)')
                      .on("end", function() {
                          wave.attr('transform', 'translate(' + waveAnimateScale(0) + ',0)');
                          animateWave();
                      });
                };
                animateWave();
            }

            var transition = function(from, to, riseWave, animateText) {
                // Update texts and animate
                if (animateText) {
                    var textTween = function() {
                        var that = d3.select(this);
                        var i = d3.interpolate(from, to);
                        return function(t) {
                        	switch(self.meta.TextFormat){
	                        	case 'none':
	                        		that.text("")
	                        		break;
	                        	case 'Argument':
	                        	case 'Argument, Value':
	                        		that.text(title).each(wrap).append('title').text(title);
	                        		break;
	                        	case 'Value':
	                        		that.text(value).each(wrap).append('title').text(value);
	                        		break;
	                        	case 'Percent':
	                        	case 'Argument, Percent':
	                        	case 'Value, Percent':
	                        	case 'Argument, Value, Percent':
	                        		that.text(textRounder(i(t)) + percentText)
	                        		break;
                        	}
//                            that.text(textRounder(i(t)) + percentText)
                        };
                    };
                    
                    var titleTween = function() {
                        var that = d3.select(this);
                        return function(t) {
                        	switch(self.meta.TextFormat){
	                        	case 'none':
	                        	case 'Argument':
	                        	case 'Argument, Value':
	                        	case 'Value':
	                        	case 'Percent':
	                        	case 'Value, Percent':
	                        		that.text("")
	                        		break;
	                        	case 'Argument, Percent':
	                        	case 'Argument, Value, Percent':
	                        		 that.text(title).each(wrap).append('title').text(title);
	                        		 break;
	                    	}
                        };
                    };
                    
                    var valueTween = function() {
                        var that = d3.select(this);
                        return function(t) {
                        	switch(self.meta.TextFormat){
	                        	case 'none':
	                        	case 'Argument':
	                        	case 'Value':
	                        	case 'Percent':
	                        	case 'Argument, Percent':
	                        		that.text("");
	                        		break;
	                        	case 'Argument, Value':
	                        	case 'Value, Percent':
	                        	case 'Argument, Value, Percent':
	                        		 that.text(value).each(wrap).append('title').text(title);
	                        		 break;
	                    	}
                        };
                    };
                    text1.transition()
                      .duration(config.get("waveRiseTime"))
                      .tween("text", textTween);
                    text2.transition()
                      .duration(config.get("waveRiseTime"))
                      .tween("text", textTween)
                    
                    title1.transition()
                    .duration(config.get("waveRiseTime"))
                    .tween("text", titleTween);
                  title2.transition()
                    .duration(config.get("waveRiseTime"))
                    .tween("text", titleTween);
                  
                  value1.transition()
                  .duration(config.get("waveRiseTime"))
                  .tween("text", valueTween);
                value2.transition()
                  .duration(config.get("waveRiseTime"))
                  .tween("text", valueTween);
                } else {
                    text1.text(textRounder(to) + percentText);
                    text2.text(textRounder(to) + percentText);
                    title1.text(title);
                    title2.text(title);
                    value1.text(value);
                    value2.text(value);
                }

                // Update the wave
                toPercent = Math.max(config.get("minValue"), Math.min(config.get("maxValue"), to)) / config.get("maxValue");
                fromPercent = Math.max(config.get("minValue"), Math.min(config.get("maxValue"), from)) / config.get("maxValue");

                if (riseWave) {
                    waveGroup.attr('transform', 'translate(' + waveGroupXPosition + ',' + waveRiseScale(fromPercent) + ')')
                      .transition()
                      .duration(config.get("waveRiseTime"))
                      .attr('transform', 'translate(' + waveGroupXPosition + ',' + waveRiseScale(toPercent) + ')');
                } else {
                    waveGroup.attr('transform', 'translate(' + waveGroupXPosition + ',' + waveRiseScale(toPercent) + ')');
                }
            };

            transition(
              textStartValue,
              textFinalValue,
              config.get("waveRise") && config.get("waveRiseAtStart"),
              config.get("valueCountUp") && config.get("valueCountUpAtStart")
            );

            // Event to update the value
            gauge.on("valueChanged", function(newValue) {
                transition(value, newValue, config.get("waveRise"), config.get("valueCountUp"));
                value = newValue;
            });

            gauge.on("destroy", function() {
                // Stop all the transitions
                text1.interrupt().transition();
                text2.interrupt().transition();
                waveGroup.interrupt().transition();
                wave.interrupt().transition();

                // Unattach events
                gauge.on("valueChanged", null);
                gauge.on("destroy", null);
            });
        });
    };
	
	this.setLiquidFillGauge = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.LiquidFillGauge['ComponentName'] = this.ComponentName;
		this.LiquidFillGauge['Name'] = this.Name;
		this.LiquidFillGauge['DataSource'] = this.dataSourceId;
		
		this.LiquidFillGauge['DataItems'] = this.fieldManager.DataItems;
		this.LiquidFillGauge['Arguments'] = this.fieldManager.Arguments;
		this.LiquidFillGauge['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.LiquidFillGauge;
		
		if (!(this.LiquidFillGauge['Palette'])) {
			this.LiquidFillGauge['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.LiquidFillGauge.InteractivityOptions) {
			if (!(this.LiquidFillGauge.InteractivityOptions.MasterFilterMode)) {
				this.LiquidFillGauge.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.LiquidFillGauge.InteractivityOptions.TargetDimensions)) {
				this.LiquidFillGauge.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.LiquidFillGauge.InteractivityOptions.IgnoreMasterFilters)) {
				this.LiquidFillGauge.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.LiquidFillGauge.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.LiquidFillGauge.AxisY)) {
			this.LiquidFillGauge.AxisY = {
				FormatType: 'Number',
				Unit: 'Ones',
				ShowZero: true,
				Visible: true,
				SuffixEnabled: false,
				MeasureFormat: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				Separator: true
			};
		}
		
		if (!(this.LiquidFillGauge['TextFormat'])) {
			this.LiquidFillGauge['TextFormat'] = 'Argument, Value, Percent'
		}
		
		if(!this.LiquidFillGauge.LayoutOption){
			this.LiquidFillGauge.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
					},
			}
		}
		
		if(!this.LiquidFillGauge['ZoomAble']){
			this.LiquidFillGauge.ZoomAble = 'none'
		}
		
		if(!this.LiquidFillGauge['ContentOption']){
			this.LiquidFillGauge.ContentOption = {
					ContentColumnCount : 5,
					ContentAutoColumn : true
			}
		}
		
	};
	
	this.setLiquidFillGaugeforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setLiquidFillGauge();
		}
		else{
			this.LiquidFillGauge = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.LiquidFillGauge['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.LiquidFillGauge['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.LiquidFillGauge['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.LiquidFillGauge['Palette'])) {
			this.LiquidFillGauge['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var LiquidFillGaugeOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.LIQUID_FILL_GAUGE_DATA_ELEMENT);
				
				$.each(LiquidFillGaugeOption,function(_i,_LiquidFillGaugeOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _LiquidFillGaugeOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _LiquidFillGaugeOption.CTRL_NM;
					}
					if(self.LiquidFillGauge.ComponentName == CtrlNM){
						self.LiquidFillGauge['Palette'] = _LiquidFillGaugeOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.LiquidFillGauge.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.LiquidFillGauge.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (!(this.LiquidFillGauge.AxisY)) {
			this.LiquidFillGauge.AxisY = {
				FormatType: 'Number',
				Unit: 'Ones',
				ShowZero: true,
				Visible: true,
				SuffixEnabled: false,
				MeasureFormat: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				Separator: true
			};
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.LiquidFillGauge.InteractivityOptions) {
			if (!(this.LiquidFillGauge.InteractivityOptions.MasterFilterMode)) {
				this.LiquidFillGauge.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.LiquidFillGauge.InteractivityOptions.TargetDimensions)) {
				this.LiquidFillGauge.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.LiquidFillGauge.InteractivityOptions.IgnoreMasterFilters)) {
				this.LiquidFillGauge.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.LiquidFillGauge.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.LiquidFillGauge['TextFormat'])) {
			this.LiquidFillGauge['TextFormat'] = 'Argument, Value, Percent'
		}
		
		if(!this.LiquidFillGauge.LayoutOption){
			this.LiquidFillGauge.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
					},
			}
		}
		if(!this.LiquidFillGauge['ZoomAble']){
			this.LiquidFillGauge.ZoomAble = 'none'
		}
		
		if(!this.LiquidFillGauge['ContentOption']){
			this.LiquidFillGauge.ContentOption = {
					ContentColumnCount : 5,
					ContentAutoColumn : true
			}
		}
	}
	
	this.setLiquidFillGaugeForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setLiquidFillGauge();
		}
		else{
			this.LiquidFillGauge = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.LiquidFillGauge['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.LiquidFillGauge['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.LiquidFillGauge['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.LiquidFillGauge['Palette'])) {
			this.LiquidFillGauge['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var LiquidFillGaugeOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.LIQUID_FILL_GAUGE_DATA_ELEMENT);
				
				$.each(LiquidFillGaugeOption,function(_i,_LiquidFillGaugeOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _LiquidFillGaugeOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _LiquidFillGaugeOption.CTRL_NM;
//					}
					if(self.LiquidFillGauge.ComponentName == CtrlNM){
						self.LiquidFillGauge['Palette'] = _LiquidFillGaugeOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.LiquidFillGauge.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.LiquidFillGauge.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		if (!(this.LiquidFillGauge.AxisY)) {
			this.LiquidFillGauge.AxisY = {
				FormatType: 'Number',
				Unit: 'Ones',
				ShowZero: true,
				Visible: true,
				SuffixEnabled: false,
				MeasureFormat: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				Separator: true
			};
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.LiquidFillGauge.InteractivityOptions) {
			if (!(this.LiquidFillGauge.InteractivityOptions.MasterFilterMode)) {
				this.LiquidFillGauge.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.LiquidFillGauge.InteractivityOptions.TargetDimensions)) {
				this.LiquidFillGauge.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.LiquidFillGauge.InteractivityOptions.IgnoreMasterFilters)) {
				this.LiquidFillGauge.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.LiquidFillGauge.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.LiquidFillGauge['TextFormat'])) {
			this.LiquidFillGauge['TextFormat'] = 'Argument, Value, Percent'
		}
		
		if(!this.LiquidFillGauge.LayoutOption){
			this.LiquidFillGauge.LayoutOption = {
					Label : {
						family: 'Noto Sans KR',
					},
			}
		}
		if(!this.LiquidFillGauge['ZoomAble']){
			this.LiquidFillGauge.ZoomAble = 'none'
		}
		
		if(!this.LiquidFillGauge['ContentOption']){
			this.LiquidFillGauge.ContentOption = {
					ContentColumnCount : 5,
					ContentAutoColumn : true
			}
		}
		
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setLiquidFillGauge();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.LiquidFillGauge);
			gDashboard.itemGenerateManager.generateItem(self, self.LiquidFillGauge);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setLiquidFillGaugeforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.LiquidFillGauge);
			gDashboard.itemGenerateManager.generateItem(self, self.LiquidFillGauge);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.LiquidFillGauge)) {
			this.setLiquidFillGaugeForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.LiquidFillGauge);
			gDashboard.itemGenerateManager.generateItem(self, self.LiquidFillGauge);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setLiquidFillGaugeForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.LiquidFillGauge);
			gDashboard.itemGenerateManager.generateItem(self, self.LiquidFillGauge);
		}

		
		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
			topIconPanel.append(trackingDataContainerHtml);
		}
		
		var dxConfig = this.getDxItemConfig(this.meta);
		
		this.calculatedFields = [];
		/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
		this.calculateCaption;
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[this.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(self.measures,function(_i,_measure){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_measure != undefined){
							if(field.Name == _measure.name){
								self.calculatedFields.push(_measure);
								self.calculateCaption = _measure.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.measures,function(_k, _measure){
											if(_tempDataField == _measure.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								self.measures.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
												captionBySummaryType: "sum_"+_tempDataField,
												currencyCulture: undefined,
												format: "fixedPoint",
												formatType: "Number",
												includeGroupSeparator: true,
												name: _tempDataField,
												nameBySummaryType: "sum("+_tempDataField+")",
												nameBySummaryType2: "sum_"+_tempDataField,
												precision: 0,
												rawCaption: _tempDataField,
												suffix: {
													B: "십억",
													K: "천",
													M: "백만",
													O: ""
												},
												suffixEnabled: false,
												summaryType: "sum",
												type: "measure",
												unit: "Ones",
												tempdata: true
										}
										self.measures.push(dataMember);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
					/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
					$.each(self.dimensions,function(_i,_dimension){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_dimension != undefined){
							if(field.Name == _dimension.name){
								self.calculatedFields.push(_dimension);
								self.calculateCaption = _dimension.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.dimensions,function(_k, _dimension2){
											if(_tempDataField == _dimension2.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								self.dimensions.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
												captionBySummaryType: _tempDataField,
												currencyCulture: undefined,
												includeGroupSeparator: true,
												name: _tempDataField,
												precision: 0,
												rawCaption: _tempDataField,
												suffixEnabled: false,
												type: "dimension",
												tempdata: true,
												nameBySummaryType: "min("+_tempDataField+")",
												nameBySummaryType2: "min_"+_tempDataField
										}
										self.dimensions.push(dataMember);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
				});
			}
		}
		
		var measureKey = this.measures[0];
    	var measureCheck = false;
    	$.each(this.measures, function(i, mea){
    		if(self.currentMeasureName === mea.caption){
    			measureKey = mea;
    			measureCheck = true;
    			return false;
    		}
    	})
		if(!self.currentMeasureName || self.currentMeasureName === "" || !measureCheck)
			self.currentMeasureName = measureKey.caption;
    	
    	
    	
		self.currentMeasureName = measureKey.caption;
		self.trackingData = [];
		self.tempTrackingData = [];
		
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fLiquidFillGauge(self.deleteDuplecateData(_data,measureKey));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
//		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
//				"instance");
		gDashboard.itemGenerateManager.renderButtons(self);
		

		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
		
//		gDashboard.itemGenerateManager.generateDxItem(self, _data);
	};
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
	}
	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if (self.dxItem){
				d3.selectAll('#' + self.itemid + ' path').style('opacity', '0.5').attr("filter", "false");
				d3.selectAll('.bgCircle').style("fill", "#fff").style("opacity", 1);
			}
			self.trackingData = [];
			self.tempTrackingData = [];
		}
	};
	
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
	};
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	
	this.resize = function() {
		if(typeof self.resizeData != 'undefined'){
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fLiquidFillGauge(self.resizeData);
			d3.selectAll('#' + self.itemid + ' .bubbles[filter="true"]').style('stroke', 'black').style('stroke-width', 2).style('stroke-opacity', 0.7).attr("filter", "true");
		}
		gProgressbar.hide();
	};
	
	this.fLiquidFillGauge = function(dupleData) {
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		self.resizeData = dupleData;
		
		labelFormat = 'Number',
		labelUnit = 'O',
		labelPrecision = 0,
		labelSeparator = true,
		labelSuffixEnabled = false,
		labelSuffix = {
			O: '',
			K: '천',
			M: '백만',
			B: '십억'
		};
    	
    	if (self.meta.DataItems.Measure.length == 1) {
			if(self.meta.DataItems.Measure[0].NumericFormat != undefined){
				labelFormat = typeof self.meta.DataItems.Measure[0].NumericFormat.FormatType == 'undefined' ? labelFormat : self.meta.DataItems.Measure[0].NumericFormat.FormatType;
				labelUnit = typeof self.meta.DataItems.Measure[0].NumericFormat.Unit == 'undefined'? labelUnit : self.meta.DataItems.Measure[0].NumericFormat.Unit;
				labelPrecision = typeof self.meta.DataItems.Measure[0].NumericFormat.Precision == 'undefined' ? labelPrecision : self.meta.DataItems.Measure[0].NumericFormat.Precision;
				labelSeparator = typeof self.meta.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator == 'undefined' ? labelSeparator : self.meta.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator;
				labelSuffixEnabled = typeof self.meta.DataItems.Measure[0].NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : self.meta.DataItems.Measure[0].NumericFormat.SuffixEnabled;
				labelSuffix = typeof self.meta.DataItems.Measure[0].NumericFormat.Suffix == 'undefined' ? labelSuffix : self.meta.DataItems.Measure[0].NumericFormat.Suffix;
			}
		} else {
			$.each(self.meta.DataItems.Measure, function(i,k) {
				if (self.currentMeasureName===k.Name) {
					labelFormat = typeof k.NumericFormat.FormatType == 'undefined' ? '' : k.NumericFormat.FormatType;
					labelUnit = typeof k.NumericFormat.Unit == 'undefined'? undefined : k.NumericFormat.Unit.substring(0,1);
					labelPrecision = typeof k.NumericFormat.Precision == 'undefined' ? 2 : k.NumericFormat.Precision;
					labelSeparator = typeof k.NumericFormat.IncludeGroupSeparator == 'undefined' ? true : k.NumericFormat.IncludeGroupSeparator;
					labelSuffixEnabled = typeof k.NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : k.NumericFormat.SuffixEnabled;
					labelSuffix = typeof k.NumericFormat.Suffix == 'undefined' ? labelSuffix : k.NumericFormat.Suffix;
					return false;
				}
			});
		}
    	
    	var getLabelText = function(value){
    		return WISE.util.Number.unit(value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
    	}
    	
		$("#"+self.itemid+" svg").remove();
		
		var size = self.__calcgaugePanelSize(dupleData.length);
		$("#"+self.itemid).css('overflow-y', 'auto').css('overflow-x', 'hidden').css("text-align", "center").css('font-family', self.meta.LayoutOption.Label.family);
		var palette = gDashboard.d3Manager.getPalette(self);
		var padding = 10;
		var xCount = Math.floor($('#'+self.itemid).width() / (size.w + padding));
		if((size.w + padding) * xCount - padding/2 + size.w < $('#'+self.itemid).width()) xCount++;
		var width = (size.w + padding) * xCount - padding/2;
		var yCount = Math.ceil(dupleData.length/xCount);
		var height = yCount * (padding + size.h) - padding;
		d3.select("#"+self.itemid).append("svg").attr("id", self.itemid+"_wrapper").style("text-align", "center").style("overflow-y", 'auto').attr("width", width).attr("height", height).append("g"); 
        
        var zoomCnt = 0;
		function zoomable(){
			 var zoom = d3.zoom().on("zoom", function (d,zz) {
				 if(pressKey['z'] || pressKey['Z'])
					 d3.select('#'+self.itemid).select('g').attr("transform", function(){ 
						 if(zoomCnt==0){
							 d3.event.transform.x = d3.event.sourceEvent.layerX
							 d3.event.transform.y = d3.event.sourceEvent.layerY
							 d3.event.transform.k =1;
						 }
						 if(d3.event.transform.k <= 1){
							 zoomCnt++;
							 d3.event.transform.x = 0
							 d3.event.transform.y = 0
							 d3.event.transform.k =1;
							 zoomable();
							 return false;
						 }
						 if(d3.event.transform.x ===0 && d3.event.transform.y ===0){
							 d3.event.transform.x = d3.event.sourceEvent.layerX
							 d3.event.transform.y = d3.event.sourceEvent.layerY
						 }
						 zoomCnt++
						 return d3.event.transform;
					 })
		        else{
		        	// Move scrollbars.
					  const wrapper = $('#'+self.itemid);
					  if(pressKey['Shift'] && wrapper.css('overflow-x') != 'hidden')
					      wrapper.scrollLeft(wrapper.scrollLeft() + d3.event.sourceEvent.deltaY);
					  else if(wrapper.css('overflow-y') != 'hidden')
                       wrapper.scrollTop(wrapper.scrollTop() + d3.event.sourceEvent.deltaY);
		        }
			 })

			  d3.select('#'+self.itemid).select('svg').call(zoom)
		}
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}
		$.each(dupleData, function(i, d){
			var pIndex = i%palette.length;
			var xPosition = padding + ( size.w + padding ) * (i%xCount);
			var yPosition = padding + (size.h + padding) * Math.floor(i/xCount);
			
			d3.select("#"+self.itemid+"_wrapper").select('g').append("svg")
			.attr('x', xPosition).attr('y', yPosition)
			.style("width", size.w).style("height", size.h)
			.attr("width", size.w).attr("height", size.h)
			.call(liquidfillgauge, d.pValue, getLabelText(d.value), d.name, {
				textColor: palette[pIndex],
				waveTextColor: d3.rgb(palette[pIndex].r + 100, palette[pIndex].g + 100, palette[pIndex].b + 100),
				circleColor: palette[pIndex],
				waveColor: palette[pIndex],
				textSize: self.meta.TextFormat === 'Argument'||  self.meta.TextFormat === 'Argument, Value'? 0.7 : self.meta.TextFormat === 'Value'? 0.5 : 1
			});
		});
	};

	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
	
	this.__calcgaugePanelSize = function(_gaugeCount) {
		var ww = $('#'+this.itemid).width();
		var hh = $('#'+this.itemid).height();
		var itemPanelMinSize = 150;
        var itemPanelHeightSize, itemPanelWidthSize;
        
        if(self.meta.ContentOption.ContentAutoColumn){
        	if (ww < itemPanelMinSize) {
                itemPanelWidthSize = ww - 4; // padding-height, bottom : 2px
            }
            else {
                var _i = 0, itemPanelWidthSizeCountTimes;
                for (_i = 0; _i < _gaugeCount; _i++) {
                	itemPanelWidthSizeCountTimes = itemPanelMinSize * (_i+1);
                	if (ww < itemPanelWidthSizeCountTimes) {
                		break;
                	}
                }
                
                var gaugeCountForRow = _gaugeCount < (_i+1) ? _gaugeCount : (_i+1);
                
                itemPanelWidthSize = parseInt(ww / gaugeCountForRow, 10);
                itemPanelWidthSize = itemPanelWidthSize - 15; // 15: scroll width
            }
            
            if (hh < itemPanelMinSize) {
            	itemPanelHeightSize = hh - 4;  // padding-right, left : 2px
            }
            else {
            	itemPanelHeightSize = itemPanelWidthSize;
            }
            
            if (itemPanelHeightSize > itemPanelMinSize) {
            	itemPanelHeightSize = hh - 4;  // padding-right, left : 2px
            }

            if(itemPanelWidthSize < itemPanelHeightSize){
            	if(itemPanelWidthSize < itemPanelMinSize)
            	    itemPanelWidthSize = itemPanelHeightSize;
            	else
            	    itemPanelHeightSize = itemPanelWidthSize;
            }else{
            	if(itemPanelHeightSize < itemPanelMinSize)
            	    itemPanelHeightSize = itemPanelWidthSize;
            	else
            	    itemPanelWidthSize = itemPanelHeightSize;
            }
        }else{
        	itemPanelWidthSize = parseInt(ww / self.meta.ContentOption.ContentColumnCount, 10);
        	itemPanelWidthSize = itemPanelWidthSize - 15;
        	
        	itemPanelHeightSize = itemPanelWidthSize;
        }
        return {w: itemPanelWidthSize, h: itemPanelHeightSize};
        
	};
};

WISE.libs.Dashboard.LiquidFillGaugeFieldManager = function() {
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
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText; 
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['NumericFormat'] = NumericFormat;
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

	this.setArgumentsByField = function(_argument){
		this.Arguments = {'Argument' : []};
		_.each(_argument,function(_a){
			var Value = {'UniqueName' : _a.uniqueName};
			self.Arguments['Argument'].push(Value);
		});
		return self.Arguments;
	};
};
