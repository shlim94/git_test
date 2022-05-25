/**
 * 
 */

WISE.libs.Dashboard.item.FunctionButton = function(_options) {
	var self = this;
	
	this.id;
	this.type;
	/* DOGFOOT ktkang 버튼에 Style 주기  20200228 */
	this.style;
	this.image = {
		path: WISE.Constants.context + '/images',
		standard: undefined,
		selected: undefined, 
		over: undefined,
		url: function(_type) {
			return self.image.path + '/' + self.image[_type];
		}
	};
	this.text;
	this.toggleState = false;
	
	this.$button;
	this.event = this.on = {
		click: function(_e, _component) {
			WISE.alert('Override click-event');
		}
	};
	
	this.render = function(_$container) {
		var html = '';
		//필드선택기
		/*if(this.id == 'GRID_CONTENT_PANEL_fieldchooser_pop')
			html += '<li id="' + this.id + '" style="cursor:pointer;display:none;">';
		else
			html += '<li id="' + this.id + '" style="cursor:pointer;">';*/
		// 2020.01.16 mksong 아이콘 타이틀 추가 dogfoot
		html += '<li id="' + this.id + '" style="cursor:pointer;" class="img" title="' + this.text + '">';
		html += '<img src="' + this.image.url('standard') + '"';
		if(WISE.Constants.browser.indexOf('MOBILE') === -1) html += ' onMouseOver="this.src=\'' + this.image.url('over') + '\'"';
		html += ' onMouseOut="this.src=\'' + this.image.url('standard') + '\'"';
		html += ' alt="' + this.text + '"';
		html += ' title="' + this.text + '"';
		/* DOGFOOT ktkang 버튼에 Style 주기  20200228 */
		html += ' style="display:' + (this.state !== 'selected' ? '' : 'none') + '; ' + this.style + '">';
//		html += '<img src="' + this.image.url('selected') + '"';
//		if(WISE.Constants.browser.indexOf('MOBILE') === -1) html += ' onMouseOver="this.src=\'' + this.image.url('selected') + '\'"';
//		html += ' onMouseOut="this.src=\'' + this.image.url('selected') + '\'"';
//		html += ' alt="' + this.text + '"';
//		html += ' title="' + this.text + '"';
//		html += ' style="display:' + (self.state === 'selected' ? '' : 'none') + ';">';
		html += '</li>';
		// 2020.01.07 mksong img 클래스 추가  및 중복 부분 제거 끝 dogfoot
		
		this.$button = $(html).on('click', function(_e) { 
			if (self.type === 'toggle') {
				$('#'+self.id).find('img').toggle();
				self.toggleState = !self.toggleState;
			}
			self.on.click(_e, self); 
		});
		_$container.append(this.$button);
		
		return this;
	};
	
	/**
	 *  constructor
	 *  @param _args 
	 *  			{ 
	 *  			  id:String = undefined
	 *  			  type:String = undefined || 'toggle',
	 *  			  state:String = undefined  || 'selected',
	 *  			  text:String = '',
	 *  			  image: {
	 *  				standard:String = undefined,
	 *  				selected:String = undefined,
	 *  				over:String =  undefined
	 *  			  }
	 *   			}
	 **/
	(function(_args) {
		if (_.isEmpty(_args)) { WISE.alert('FunctionButton options is not defined.'); return; }
		if (_.isEmpty(_args.id)) { WISE.alert('FunctionButton id is not defined.'); return; }
		if (_.isEmpty(_args.image)) { WISE.alert('FunctionButton image is not defined.'); return; }
		if (_.isEmpty(_args.image.standard)) { WISE.alert('FunctionButton image.standard is not defined.'); return; }
		if (_.isEmpty(_args.image.selected)) { WISE.alert('FunctionButton image.selected is not defined.'); return; }
		
		self.id = _args.id;
		self.type = _args.type;
		self.state = _args.state;
		self.text = _args.text || '';
		self.image = $.extend(self.image, _args.image);
		/* DOGFOOT ktkang 버튼에 Style 주기  20200228 */
		self.style = _args.style || '';
		
	})(_options);
};
