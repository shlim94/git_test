/**
 * 
 */

WISE.namespace('WISE.lang');
WISE.lang.Message = function() {
	this.get = function(_code, _args) {
		if (_args) {
			if ($.type(_args) !== 'array') {
				alert(this.getMessage('app.msg.001'));
			}
		} else {
			_args = [];
		}
		var msg = WISE.i18n.message[_code] || '';
		for (var i = 0; i < _args.length; i++) {
			msg = msg.replace('{' + i + '}', _args[i]);
		}
		return msg;
	};
};