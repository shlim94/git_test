/**
 * 
 */

WISE.util.Number = {
	/**
	 * Format a number.
	 * @param {number} _value 			Number to be formatted.
	 * @param {string} _type 			Format type. One of ("Auto", "General", "Number", "Currency", "Scientific", "Percent").
	 * @param {string} _unit 			Truncate to specified unit. ("O", "K", "M" or "B"). 
	 * 									If undefined or equals "A", automatically truncate to shortest output. 
	 * 										(eg. _unit = "K": 123456 --> 123K)
	 * @param {number} _precision 		Amount of decimal places to be shown.
	 * 										(eg. _precision = 2: 123.456 --> 123.45)
	 * @param {boolean} _separator 		If true, add comma separators between every thousand.
	 * 										(eg. _separator = true: 123456 --> 123,456)
	 * @param {string} _prefix 			Custom text to add at the head of the number.
	 * 										(eg. _prefix = $: 123456 --> $123456)
	 * @param {Object} _suffix 			Custom text object to replace default ("O", "K", "M", "B") suffixes.
	 * @param {boolean} _suffixEnabled	If true, use default "OKMB" suffixes.
	 */
	unit: function(_value, _type, _unit, _precision, _separator, _prefix, _suffix, _suffixEnabled,_precisionOption) {
		var value = 0,
			type = 'Number',
			unit,
			precision = 0,
			separator = '',
			prefix = '',
			suffix = {
				O: '',
				K: 'K',
				M: 'M',
				B: 'B'
			},
			precisionOption = "반올림",
			currency = '₩',
			// TODO: custom currency input
			_currency = 'KRW';
		if (typeof _value !== 'undefined') {
			value = _value;
		} else {
			return userJsonObject.showNullValue ? userJsonObject.nullValueString : "";
		}
		if (typeof _type !== 'undefined' && ['Auto', 'General', 'Number', 'Currency', 'Scientific', 'Percent'].indexOf(_type) !== -1) {
			type = _type;
		}
		if(typeof _unit !== 'undefined') {
			switch(_unit.toUpperCase()){
				case 'T': 
					unit = 'K';
					break;
				case 'L': 
					unit = 'K';
					break;
				case 'F': 
					unit = 'O';
					break;
				case 'AUTO': 
					unit = 'A';
					break;
				case 'ONES': 
					unit = 'O';
					break;
				case 'THOUSANDS': 
					unit = 'K';
					break;
				case 'MILLIONS': 
					unit = 'M';
					break;
				case 'BILLIONS': 
					unit = 'B';
					break;
				default:
					unit = _unit.toUpperCase();
					break;
			}
		}
		if (typeof _precision !== 'undefined') {
			precision = _precision;
		}
		if (typeof _precisionOption !== 'undefined') {
			precisionOption = _precisionOption;
		}
		if (typeof _separator !== 'undefined') {
			separator = _separator ? ',' : '';
		}else if(typeof _separator === 'undefined' && gDashboard.reportType == 'AdHoc'){
			separator = ',';
		}
		if (typeof _prefix !== 'undefined') {
			prefix = _prefix;
		}
		if (_suffixEnabled && typeof _suffix !== 'undefined') {
			suffix = _suffix;
		}
		if (typeof _currency !== 'undefined') {
			switch(_currency) {
				case 'KRW':
					currency = '₩';
					break;
				case 'USD':
					currency = '$';
					break;
				default:
					currency = '$';
					break;
			}
		}
		if (type === 'Auto') {
			unit = 'A';
			suffix = {
				O: '',
				K: 'K',
				M: 'M',
				B: 'B'
			};
			currency = '₩';
		}
		// number formatter
		var fn = {
			unitNum: {
				O: 1,
				K: 1000,
				M: 1000000,
				B: 1000000000
			},
			Auto: function(_v, _u, _p, _po, _s, _r, _f, _c) {
				var numText = $.number(_v / this.unitNum[_u], 2, '.', ',').toString();
				var numDecimal = numText.split('.');
				if (numDecimal.length === 2 && numDecimal[1] === '00') {
					return _c + numDecimal[0] + ' ' + _f;
				}
				return _c + numText + ' ' + _f;
			},
			General: function(_v, _u, _p, _po, _s, _r, _f, _c) {
				return _v.toString();
			},
			Number: function(_v, _u, _p, _po, _s, _r, _f, _c) {
				return _r + $.number(_v / this.unitNum[_u], _p, _po, '.', _s).toString() + ' ' + _f;
			},
			Currency: function(_v, _u, _p, _po, _s, _r, _f, _c) {
				return _r + _c + $.number(_v / this.unitNum[_u], _p, _po, '.', _s).toString() + ' ' + _f;
			},
			Scientific: function(_v, _u, _p, _po, _s, _r, _f, _c) {
				return _r + _v.toExponential(_p).toUpperCase();
			},
			Percent: function(_v, _u, _p, _po, _s, _r, _f, _c) {
				var i = $.number(_v * 100, _p, _po, '.', _s).length-1;
				var rtnval;
				while($.number(_v * 100, _p, _po, '.', _s).length){
					if($.number(_v * 100, _p, _po, '.', _s)[i] == "0" && _p > 0){
                       rtnval =  $.number(_v * 100, _p, _po, '.', _s).slice(0,i);
                       i--;
					}else if($.number(_v * 100, _p, _po, '.', _s)[i] == "." && _p > 0){
                        rtnval =  $.number(_v * 100, _p, _po, '.', _s).slice(0,i);
                        break;
					}else{
						if(i == $.number(_v * 100, _p, _po, '.', _s).length-1){
							rtnval =  $.number(_v * 100, _p, _po, '.', _s)
						}
					    break;
					}
                     
				}	
				return _r + rtnval.toString() + '%';
			}
//			Percent: function(_v, _u, _p, _s, _r, _f, _c) {
//				return _r + $.number(_v * 100, _p, '.', _s).toString() + '%';
//			}
		};
		// auto unit
		if (typeof _unit === 'undefined' || unit === 'A') {
			var valueText = value.toString().replace('-', '');
			if (valueText.length >= 10) {
				unit = 'B';
			}
			else if (valueText.length < 10 && valueText.length >= 7) {
				unit = 'M';
			}
			else if (valueText.length < 7 && valueText.length >= 4) {
				unit = 'K';
			}
			else {
				unit = 'O';
			}
			
			if(_unit === undefined && gDashboard.reportType == 'AdHoc'){
				unit = 'O'
			}
		}
		return fn[type](value, unit, precision, precisionOption, separator, prefix, suffix[unit], currency).trim();
	}	
};