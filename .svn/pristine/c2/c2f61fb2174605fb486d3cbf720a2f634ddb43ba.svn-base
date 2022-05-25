/**
 * 
 */

WISE.util.Array = {
	pushDistinct: function(_target, _source, _key) {
		if ($.type(_source) === 'object') {
			if (!_.some(_target, function(e) { return e[_key] == _source[_key]; })) {
				_target.push(_source);
			}
		}
		else {
			if (_.indexOf(_target, _source) === -1) {
				_target.push(_source);
			}
		}
	},
	concatDistinct: function(_target, _source, _key) {
		$.each(_source, function(_i, _o) {
			if ($.type(_o) === 'object') {
				if (!_.some(_target, function(e) { return e[_key] == _o[_key]; })) {
					_target.push(_o);
				}
			}
			else {
				if (_.indexOf(_target, _o) === -1) {
					_target.push(_o);
				}
			}
		});
	},
	sortable: function(_target, _sort) {
		var fn = {
			'asc':  function(_a, _b) {
				if (_a < _b) return -1; 
				if (_a > _b) return 1;
				return 0;
			},
			'desc': function(_a, _b) {
				if (_a > _b) return -1; 
				if (_a < _b) return 1;
				return 0;
			}
		};
		return _target.sort(fn[_sort]);
	}
};