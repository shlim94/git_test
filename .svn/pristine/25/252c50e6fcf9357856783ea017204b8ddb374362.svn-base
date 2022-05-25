WISE.widget.Condition.Validator = function(_condition) {
	var self = this;

	this.condition; // parameterFilterBar#geValue에서 생성된 condition object
	
	this.valid = true;
	this.mandatoryFields = [];
	this.mandatory = false;
	this.hasEmptyValueOnListType = false; // manyData flag를 true로 설정 시 list 타입에 한해서 value을 설정하지 않았는지(_EMPTY_VALUE_) 체크
	
	this.getReport = function() {
		return {
			valid: this.valid,
			mandatory: this.mandatory,
			hasEmptyValueOnListType: this.hasEmptyValueOnListType
		};
	};
	
	(function() {
		if (_.isEmpty(_condition)) {
			WISE.alert('shoud be defined condition value object for validating');
			return;
		}
		self.condition = _condition;
		
		self.commonConfig = WISE.widget.getCustom('common', 'Config') || {};
		self.commonConditionConfig = WISE.widget.getCustom('common', 'CONDITION') || {};
		self.pageConditionConfig = WISE.widget.getCustom(WISE.Constants.pid, 'CONDITION') || {};
		
		var ConcatDistinct = WISE.util.Array.concatDistinct;
		self.mandatoryFields = [];
		ConcatDistinct(self.mandatoryFields, self.commonConditionConfig['mandatory']||[]);
		ConcatDistinct(self.mandatoryFields, self.pageConditionConfig['mandatory']||[]);
	})();
	
	this.validateMandatory = function() {
		var mandatoryFields = self.pageConditionConfig['mandatory'];
		if ($.type(self.mandatoryFields) === 'array' && self.mandatoryFields.length === 0) return;
		
		_.each(self.mandatoryFields, function(_el) {
			if (_el === (self.condition.orgParamName || self.condition.paramName)) {
				if (self.condition.value.length === 0 || _.indexOf(self.condition.value, '_EMPTY_VALUE_') > -1) {
					self.mandatory = true;
					self.valid = false;
					WISE.alert(gMessage.get('WISE.message.page.condition.mandatory',[self.condition.name])); // 은(는) 필수입력 항목 입니다.
					return false;
				}
			}
		});
	};
	
	this.validate = function() {
		self.validateMandatory();
		if (!self.valid) return;
		
		var clearCalendarValue = function(_val) {
			_val = (_val + '')
						.replace(/\-/,'')
						.replace(/년/,'')
						.replace(/월/,'')
						.replace(/일/,'');
			return _val;
		};
		
		switch(self.condition.parameterType) {
		case 'CAND':
		case 'BETWEEN_CAND':
			if (_.indexOf(self.condition.value, 'null') > -1) {
				self.valid = false;
				WISE.alert(gMessage.get('WISE.message.page.condition.date.invalid',[self.condition.name])); // 이(가) 날짜형식이 아닙니다.
				return false;
			}
			if (!self.valid) break;
			
			if (_.indexOf(self.condition.value, '_EMPTY_VALUE_') > -1) {
				self.valid = false;
				WISE.alert(gMessage.get('WISE.message.page.condition.date.invalid',[self.condition.name])); // 이(가) 날짜형식이 아닙니다.
				return false;
			}
			if (!self.valid) break;
			
			if ('BETWEEN_CAND' === self.condition.parameterType) {
				var valueArray = self.condition.value;
				
				var frVal = clearCalendarValue(valueArray[0]);
				var toVal = clearCalendarValue(valueArray[1]);
				
				if (parseInt(frVal,10) > parseInt(toVal,10)) {
					self.valid = false;
					WISE.alert(gMessage.get('WISE.message.page.condition.date.from.greater',[self.condition.name])); // 은(는) 시작일이 종료일보다 작을 수 없습니다.
				}
			}
			if (!self.valid) break;
			
			break;
		case 'LIST':
			if (self.commonConfig.message.search.manyData) {
				if (self.condition.value.length == 1 && _.indexOf(self.condition.value, "_EMPTY_VALUE_") > -1) {
					self.hasEmptyValueOnListType = true;
				}
			}
			break;
		}
		
	};
};
