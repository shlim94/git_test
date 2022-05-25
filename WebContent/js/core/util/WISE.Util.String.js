/**
 * 
 */

WISE.util.String = {
	lpad: function (_str, _len, _add) {
	    var result = _str + '';
	    var templen = _len - result.length;
	    for (var i = 0; i < templen; i++) {
	        result = _add + result;
	    }
	    return result;
	},
	rpad: function (_str, _len, _add) {
	    var result = _str + '';
	    var templen = _len - result.length;
	    for (var i = 0; i < templen; i++) {
	        result = result + _add;
	    }
	    return result;
	},
	trim: function(_str) {
		return (_str+'').replace( /(^\s*)|(\s*$)/g, "" );
	},
	allTrim: function compactTrim(_str) {
		return (_str+'').replace( /(\s*)/g, "" );
	},
	toLowerCase: function(_str) {
		return (_str+'').toLowerCase();
	},
	toUpperCase: function(_str) {
		return (_str+'').toUpperCase();
	},
	length: function(_str) {
		return (_str+'').length;
	},
	escapeHtml: function(_str) {
		var entityMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#x2F;', '`': '&#x60;', '=': '&#x3D;' };
		return String(_str).replace(/[&<>"'`=\/]/g, 
		function (s) { 
			return entityMap[s]; 
		}); 
	},
	replaceAll: function(_input, _str, _rep) {
		if(typeof _input == 'string' && typeof _str == 'string' && typeof _rep == 'string') {
			while(_input.indexOf(_str) != -1) {
				_input = _input.replace(_str, _rep)
			}
			return _input;
		} else {
			_input = _input + '';
			_str = _str + '';
			_rep = _rep + '';
			
			while(_input.indexOf(_str) != -1) {
				_input = _input.replace(_str, _rep)
			}
			return _input;
		}
	}
};