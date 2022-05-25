WISE.widget = {
	_CUSTOM_INFO_: {},
	configured: function(_pageid, _customObject) {
		var page = this['_CUSTOM_INFO_'][_pageid] || {};
		this['_CUSTOM_INFO_'][_pageid] = _.extend(page, _customObject);
	},
	getCustom: function(_pageid, _widgetid) {
		if (_widgetid === undefined) {
			return this['_CUSTOM_INFO_'][_pageid];
		} else {
			return ($.type(this['_CUSTOM_INFO_'][_pageid]) === 'object') ? this['_CUSTOM_INFO_'][_pageid][_widgetid] : undefined;
		}
	},
	Condition: {} // condition class package
};