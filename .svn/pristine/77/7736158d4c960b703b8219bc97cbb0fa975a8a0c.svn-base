/* DOGFOOT hsshim 2020-01-22 카드 만드는 기능 정리 및 개선 (전체) */
/**
 * WISE Card widget jQuery plugin.
 */
(function(_$) {
	/**
	 * WISE card widget constructor. Create a single card widget.
	 */
	_$.fn.wiseCard = function(_options) {
		var self = this;
		var options = {};
		$.extend(options, _options);
		
		/**
		 * @Method: option getter, setter 
		 * */
		this.option = function() {
			if (arguments && arguments.length === 1) {
				return options[arguments[0]];
			}
			if (arguments && arguments.length === 2) {
				if (options[arguments[0]]) {
					options[arguments[0]] = arguments[1];
				}
			}
			this.init();
		};

		/**
		 * Resize sparkline widget in card instance.
		 */				
		this.resize = function() {
			if (typeof this.dxItem !== 'undefined' && self.sparklineContainer.data('dxSparkline')) {
				this.dxItem.render();
			}
		};

		/**
		 * Get value according to parameter name. Result is empty if "Visible" setting is false.
		 */
		this.getValue = function(_type, _values) {
			var value = options.layoutTemplate[_type];
			if (value && value.Visible) {
				return _values[value.ValueType];
			}
			return '';
		}
		
		//20200727 ajkim 카드 폰트 설정 추가 dogfoot
		this.getFontStyle = function(_type){
			var value = options.layoutTemplate[_type].Font;
			
			return "font-family: " + gDashboard.fontManager.getFontFamily('Item').replace(/"/gi, "") + (value?
					("; font-size: " + value.Size + "px" +
							(value.ColorVisible? "; color: " + value.Color : '')) : '');
		}
		
		this.getAlignElement = function(_type){
			var value = options.layoutTemplate[_type].Font? options.layoutTemplate[_type].Font.Align : "";
			var align = "";
			switch(value){
			case 'Left' :
				align = '<div class="' + _type + '" style="text-align : left"></div>';
				break;
			case 'Right' :
				align = '<div class="' + _type + '" style="text-align : right"></div>';
				break;
			case 'Center' :
				align = '<div class="' + _type + '" style="text-align : center"></div>';
				break;
			}
			
			return align;
		}

		/**
		 * Initialize card widget instance with options.
		 */
		this.init = function() {
			// initialize delta options
			var valueTextObject = WISE.libs.Dashboard.item.DataUtility.makeTextValueObjectOfDeltaOptions(options.value, options.subvalues, options.deltaOptions);
			var colorType;
			switch (valueTextObject.fc) {
				case 'green':
					colorType = 'positive';
					break;
				case 'red':
					colorType = 'negative';
					break;
				case 'orange':
					colorType = 'warning';
					break;
				/* DOGFOOT mksong 2020-08-05 폰트 컬러 그레이 추가 */
				case 'gray':
					colorType = 'gray';
					break;
				default:
					colorType = 'neutral';
					break;
			}
			// text value types
			var values = {
				ActualValue: '',
				Title: options.title.text,
				Subtitle: options.title.subtext,
				CardName: options.name,
				TargetValue: '',
				AbsoluteVariation: '',
				PercentOfTarget: '',
				PercentVariation: '',
				DimensionNames: []
			};
			// obtain values based on settings
			if (options.actual) {
				values.ActualValue = (options.actual.caption?options.actual.caption : "테스트") + ": " + WISE.util.Number.unit(options.value, options.actual.formatType, options.actual.unit, options.actual.precision, 
					options.actual.includeGroupSeparator, undefined, options.actual.suffix, options.actual.suffixEnabled);
			}
			if (options.target) {
				values.TargetValue =  (options.target.caption?options.target.caption : "테스트") + ": " + WISE.util.Number.unit(options.subvalues[0], options.target.formatType, options.target.unit, options.target.precision, 
					options.target.includeGroupSeparator, undefined, options.target.suffix, options.target.suffixEnabled);
			}
			// obtain bottom values based on settings
			if (!valueTextObject.sg) {
				if (valueTextObject.avv > 0) {
					values.AbsoluteVariation = (options.actual.caption?options.target.caption : "테스트") + ": " + WISE.util.Number.unit(valueTextObject.avv, options.absoluteVariation.FormatType, options.absoluteVariation.Unit, options.absoluteVariation.Precision, 
							options.absoluteVariation.IncludeGroupSeparator, '+', options.absoluteVariation.Suffix, options.absoluteVariation.SuffixEnabled);
				}else {
					values.AbsoluteVariation = (options.actual.caption?options.target.caption : "테스트") + ": " + WISE.util.Number.unit(valueTextObject.avv, options.absoluteVariation.FormatType, options.absoluteVariation.Unit, options.absoluteVariation.Precision, 
						options.absoluteVariation.IncludeGroupSeparator, undefined, options.absoluteVariation.Suffix, options.absoluteVariation.SuffixEnabled);
				}
				if (valueTextObject.u_pvv > 0) {
					values.PercentVariation = WISE.util.Number.unit(valueTextObject.u_pvv, options.percentVariation.FormatType, options.percentVariation.Unit, options.percentVariation.Precision, 
						options.percentVariation.IncludeGroupSeparator, '+', options.percentVariation.Suffix, options.percentVariation.SuffixEnabled);
				} else {
					values.PercentVariation = WISE.util.Number.unit(valueTextObject.u_pvv, options.percentVariation.FormatType, options.percentVariation.Unit, options.percentVariation.Precision, 
						options.percentVariation.IncludeGroupSeparator, undefined, options.percentVariation.Suffix, options.percentVariation.SuffixEnabled);
				}
				if (valueTextObject.u_pot > 0) {
					values.PercentOfTarget = WISE.util.Number.unit(valueTextObject.u_pot, options.percentOfTarget.FormatType, options.percentOfTarget.Unit, options.percentOfTarget.Precision, 
						options.percentOfTarget.IncludeGroupSeparator, '+', options.percentOfTarget.Suffix, options.percentOfTarget.SuffixEnabled);
				} else {
					values.PercentOfTarget = WISE.util.Number.unit(valueTextObject.u_pot, options.percentOfTarget.FormatType, options.percentOfTarget.Unit, options.percentOfTarget.Precision, 
						options.percentOfTarget.IncludeGroupSeparator, undefined, options.percentOfTarget.Suffix, options.percentOfTarget.SuffixEnabled);
				}
			}
			// set configured values
			var topValue = self.getValue('TopValue', values);
			var mainValue = self.getValue('MainValue', values);
			var subValue = self.getValue('SubValue', values);
			var bottomValueOne = self.getValue('BottomValue1', values);
			var bottomValueTwo = self.getValue('BottomValue2', values);
			var indicator = options.layoutTemplate.DeltaIndicator.Visible ? valueTextObject.ind : '';
			var separator = (bottomValueOne.length === 0 || bottomValueTwo.length === 0) ? '' : ' / ';

			// create HTML layout based on text and delta values
			self.itemContainer = $('<div class="item-container"></div>');
			/* DOGFOOT mksong 2020-08-05 레이아웃 폭 적용 */
			self.dataContainer = $('<div class="data-container" style="min-width:'+ options.layoutTemplate.MinWidth +'px; max-width:' + (options.layoutTemplate.MaxWidth == 'auto'? 'auto;' : options.layoutTemplate.MaxWidth + 'px;margin: auto;') +'"></div>'); 
			self.sparklineContainer = $('<div class="sparkline-container" style="min-width:'+ options.layoutTemplate.MinWidth +'px; max-width:' + (options.layoutTemplate.MaxWidth == 'auto'? 'auto;' : options.layoutTemplate.MaxWidth + 'px;margin: auto;') +'"></div>');
			$(this).append(self.itemContainer);
			//20200727 ajkim 카드 폰트 설정 추가 dogfoot
			switch(_options.layoutTemplate.Type) {
				case 'Centered': {
					self.itemContainer.addClass('centered');
					// containers
					var $middleContainer = $('<div class="middle-container"></div>');
					var $header = $('<div class="value-container"><p class="title"></p></div>');
					var $body = $('<div class="value-container"><p class="values"></p></div>');
					//  values
					var $actual = $('<span class="large-text"><b style = "' + self.getFontStyle("TopValue") + '">' + topValue + '</b></span>');
					var $main = $('<span class="large-text"><b style = "' + self.getFontStyle("MainValue") + '">' + mainValue + '</b></span>');
					var $sub = $('<br><span class="text" style = "' + self.getFontStyle("SubValue") + '">' + subValue + '</span>');
					var $bottomOne = $('<br><span class="text ' + colorType + '" style = "' + self.getFontStyle("BottomValue2") + '">' + bottomValueTwo + separator + '</span>');
					var $bottomTwo = $('<span class="text ' + colorType + '" style = "' + self.getFontStyle("BottomValue1") + '">' + bottomValueOne + '</span>');
					var $delta = $('<span class="text ' + colorType + '" style = "' + self.getFontStyle("DeltaIndicator") + '">' + indicator + '</span>');
					// create layout
					if(self.getAlignElement("MainValue") !== ""){
						$header.find('p').append($(self.getAlignElement("MainValue"))).find('.MainValue').append($main);
					}else{
						$header.find('p').append($main);
					}
					if(self.getAlignElement("SubValue") !== ""){
						$header.find('p').append($(self.getAlignElement("SubValue"))).find('.SubValue').append($sub);
					}else{
						$header.find('p').append($sub);
					}
					if(self.getAlignElement("MainValue") !== "" || self.getAlignElement("SubValue") !== ""){
						$header.find('br').remove();
					}
					if(self.getAlignElement("TopValue") !== ""){
						$body.find('p').append($(self.getAlignElement("TopValue"))).find('.TopValue').append($actual).append($delta);
					}else{
						$body.find('p').append($actual);
						$body.find('p').append($delta);
					}
					if (!valueTextObject.sg) {
						if(self.getAlignElement("BottomValue1") !== ""){
							$body.find('p').append($(self.getAlignElement("BottomValue1"))).find('.BottomValue1').append($bottomOne).append($bottomTwo);
						}else{
							$body.find('p').append($bottomOne);
							$body.find('p').append($bottomTwo);
						}
					}
					
					if(self.getAlignElement("TopValue") !== "" || self.getAlignElement("BottomValue1") !== ""){
						$body.find('br').remove();
					}
					self.dataContainer.append($header);
					self.dataContainer.append($body);
					$middleContainer.append(self.dataContainer);
					$middleContainer.append(self.sparklineContainer);
					self.itemContainer.append($middleContainer);
					break;
				}
				case 'Compact': {
					self.itemContainer.addClass('compact');
					// containers
					var $middleContainer = $('<div class="middle-container"></div>');
					var $body = $('<div class="value-container"><p class="values"></p></div>');
					//  values
					var $actual = $('<br><span class="text"><b style = "' + self.getFontStyle("TopValue") + '">' + topValue + '</b></span>');
					var $main = $('<span class="text"><b style = "' + self.getFontStyle("MainValue") + '">' + mainValue + '</b></span>');
					var $sub = $('<br><span class="text" style = "' + self.getFontStyle("SubValue") + '">' + subValue + '</span>');
					var $bottomOne = $('<br><span class="text ' + colorType + '" style = "' + self.getFontStyle("BottomValue2") + '">' + bottomValueTwo + separator + '</span>');
					var $bottomTwo = $('<span class="text ' + colorType + '" style = "' + self.getFontStyle("BottomValue1") + '">' + bottomValueOne + '</span>');
					var $delta = $('<span class="text ' + colorType + '" style = "' + self.getFontStyle("DeltaIndicator") + '">' + indicator + '</span>');
					// create layout
					if(self.getAlignElement("MainValue") !== ""){
						$body.find('p').append($(self.getAlignElement("MainValue"))).find('.MainValue').append($main);
					}else{
						$body.find('p').append($main);
					}
					if(self.getAlignElement("SubValue") !== ""){
						$body.find('p').append($(self.getAlignElement("SubValue"))).find('.SubValue').append($sub);
					}else{
						$body.find('p').append($sub);
					}
					if(self.getAlignElement("MainValue") !== "" || self.getAlignElement("SubValue") !== ""){
						$body.find('br').remove();
					}
					if(self.getAlignElement("TopValue") !== ""){
						$body.find('p').append($(self.getAlignElement("TopValue"))).find('.TopValue').append($actual).append($delta);
						if(self.getAlignElement("SubValue") === ""){
							$body.find('br').last().remove();
						}
					}else{
						$body.find('p').append($actual);
						$body.find('p').append($delta);
					}
					if(self.getAlignElement("SubValue") !== ""){
						$body.find('br').last().remove();
					}
					
					if (!valueTextObject.sg) {
						if(self.getAlignElement("BottomValue1") !== ""){
							$body.find('p').append($(self.getAlignElement("BottomValue1"))).find('.BottomValue1').append($bottomOne).append($bottomTwo);
							$body.find('br').last().remove();
						}else{
							$body.find('p').append($bottomOne);
							$body.find('p').append($bottomTwo);
						}
					}
					
					self.dataContainer.append($body);
					$middleContainer.append(self.dataContainer);
					$middleContainer.append(self.sparklineContainer);
					self.itemContainer.append($middleContainer);
					break;
				}
				case 'Lightweight': {
					self.itemContainer.addClass('lightweight');
					// containers
					var $middleContainer = $('<div class="middle-container"></div>');
					var $body = $('<div class="value-container"><p class="values"></p></div>');
					//  values
					var $actual = $('<span class="large-text" style = "' + self.getFontStyle("TopValue") + '"><b>' + topValue + '</b></span>');
					var $main = $('<br><span class="text" style = "' + self.getFontStyle("MainValue") + '">' + mainValue + '</span>');
					var $sub = $('<br><span class="text" style = "' + self.getFontStyle("SubValue") + '">' + subValue + '</span>');
					// create layout
					
					if(self.getAlignElement("TopValue") !== ""){
						$body.find('p').append($(self.getAlignElement("TopValue"))).find('.TopValue').append($actual);
					}else{
						$body.find('p').append($actual);
					}
					if(self.getAlignElement("MainValue") !== ""){
						$body.find('p').append($(self.getAlignElement("MainValue"))).find('.MainValue').append($main);
					}else{
						$body.find('p').append($main);
					}
					if(self.getAlignElement("TopValue") !== ""){
						$body.find('br').remove();
					}
					if(self.getAlignElement("SubValue") !== ""){
						$body.find('p').append($(self.getAlignElement("SubValue"))).find('.SubValue').append($sub);
					}else{
						$body.find('p').append($sub);
					}
					if(self.getAlignElement("MainValue") !== ""){
						$body.find('br').remove();
					}
					if(self.getAlignElement("SubValue") !== ""){
						$body.find('br').last().remove();
					}
					self.dataContainer.append($body);
					
					$middleContainer.append(self.dataContainer);
					$middleContainer.append(self.sparklineContainer);
					self.itemContainer.append($middleContainer);
					break;
				}
				default: { // Stretched
					self.itemContainer.addClass('stretched');
					// containers
					var $header = $('<div class="top-value"></div>');
					var $body = $('<div class="value-container"><p class="title"></p></div>');
					var $footer = $('<div class="value-container"><p class="values"></p></div>');
					var $indicator = $('<div class="indicator"></div>');
					//  values
					var $actual = $('<span class="text" style = "' + self.getFontStyle("TopValue") + '">' + topValue + '</span>');
					var $main = $('<span class="large-text" style = "' + self.getFontStyle("MainValue") + '"><b>' + mainValue + '</b></span>');
					var $sub = $('<br><span class="text" style = "' + self.getFontStyle("SubValue") + '">' + subValue + '</span>');
					var $bottomOne = $('<span class="text ' + colorType + '" style = "' + self.getFontStyle("BottomValue1") + '">' + bottomValueOne + '</span>');
					var $bottomTwo = $('<br><span class="large-text ' + colorType + '" style = "' + self.getFontStyle("BottomValue2") + '"><b>' + bottomValueTwo + '</b></span>');
					var $delta = $('<span class="text ' + colorType + '" style = "' + self.getFontStyle("DeltaIndicator") + '">' + indicator + '</span>');
					// create layout
					if(self.getAlignElement("TopValue") !== ""){
						$header.append($(self.getAlignElement("TopValue"))).find('.TopValue').append($actual);
					}else{
						$header.append($actual);
					}
					if(self.getAlignElement("DeltaIndicator") !== ""){
						$indicator.append($(self.getAlignElement("DeltaIndicator"))).find('.DeltaIndicator').append($delta);
					}else{
						$indicator.append($delta);
					}
					if(self.getAlignElement("MainValue") !== ""){
						$body.find('p').append($(self.getAlignElement("MainValue"))).find('.MainValue').append($main);
					}else{
						$body.find('p').append($main);
					}
					if(self.getAlignElement("SubValue") !== ""){
						$body.find('p').append($(self.getAlignElement("SubValue"))).find('.SubValue').append($sub);
					}else{
						$body.find('p').append($sub);
					}
					if(self.getAlignElement("MainValue") !== "" || self.getAlignElement("SubValue") !== ""){
						$body.find('br').remove();
					}
					
					self.dataContainer.append($header);
					self.dataContainer.append($indicator);
					self.dataContainer.append($body);
					if (!valueTextObject.sg) {
						if(self.getAlignElement("BottomValue1") !== ""){
							$footer.find('p').append($(self.getAlignElement("BottomValue1"))).find('.BottomValue1').append($bottomOne);
						}else{
							$footer.find('p').append($bottomOne);
						}
						
						if(self.getAlignElement("BottomValue2") !== ""){
							$footer.find('p').append($(self.getAlignElement("BottomValue2"))).find('.BottomValue2').append($bottomTwo);
						}else{
							$footer.find('p').append($bottomTwo);
						}
						
						if(self.getAlignElement("BottomValue1") !== "" || self.getAlignElement("BottomValue2") !== ""){
							$footer.find('br').remove();
						}
						self.dataContainer.append($footer);
					}
					self.itemContainer.append(self.dataContainer);
					self.itemContainer.append(self.sparklineContainer);
				}
			}

			// initialize sparkline widget
			if (options.layoutTemplate.Sparkline.Visible) {
				self.sparklineContainer.addClass('active');
				self.dataContainer.addClass('sparkline');

				var sparklineOpts = {
					'ViewType': 'Line',
					'HighlightStartEndPoints': true,
					'HighlightMinMaxPoints': true
				};
				$.extend(sparklineOpts, options.sparkline.options);
				
				// type: line, area, bar, winloss
				if(options.sparkline.data!=undefined) {
					var configs = {
						dataSource: options.sparkline.data.dataSource,
						argumentField: options.sparkline.data.argumentField,
						valueField: options.sparkline.data.valueField,
						type: sparklineOpts.ViewType.toLowerCase().replace('/', ''),
						lineColor: "#a6a6a6",
		//			    firstLastColor: '#4641d9',
						showMinMax: sparklineOpts.HighlightMinMaxPoints,
						showFirstLast: sparklineOpts.HighlightStartEndPoints
					};
						
					this.dxItem = self.sparklineContainer.dxSparkline(configs).dxSparkline('instance');
				}
			}
		}
		
		// return card widget instance
		this.init();
		return this;
	};
})(jQuery);