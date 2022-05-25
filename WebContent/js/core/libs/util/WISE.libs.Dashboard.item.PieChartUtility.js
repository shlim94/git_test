/** PieChartUtility */
WISE.libs.Dashboard.item.PieChartUtility = {
	Series: {
		Label: {
			// helper function for formatting label text
			getLabelFormat: function(_pointInfo, pieLabelFormat) {
				var type = pieLabelFormat.type,
					format = 'Number',
					unit = pieLabelFormat.format,
					prefixEnabled = pieLabelFormat.prefixEnabled,
					suffixEnabled = pieLabelFormat.suffixEnabled,
					precision = pieLabelFormat.precision,
					precisionOption = pieLabelFormat.precisionOption,
					separator = true,
					prefix = '',
					suffix = pieLabelFormat.suffix;
				if (prefixEnabled) {
					prefix = pieLabelFormat.prefixFormat;
				}

				switch(type) {
					case 'None':
						return '';
					case 'Argument':
						return _pointInfo.argumentText;
					case 'Value':
						return WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption);
					case 'Percent':
						return (_pointInfo.percent*100).toFixed(precision) + '%';
					case 'ArgumentAndValue':
						return _pointInfo.argumentText + ': '
							+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption);
					case 'ValueAndPercent':
						return WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption)
							+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
					case 'ArgumentAndPercent':
						return _pointInfo.argumentText + ': (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
					case 'ArgumentValueAndPercent':
						return _pointInfo.argumentText + ': '
							+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption)
							+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
					default:
						return _pointInfo.argumentText + ': (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
				}
			}
		}
	},
	Tooltip: {
		getTooltipFormat: function(_pointInfo, pieTooltipFormat) {
			var type = pieTooltipFormat.type,
				format = 'Number',
				unit = pieTooltipFormat.format,
				prefixEnabled = pieTooltipFormat.prefixEnabled,
				suffixEnabled = pieTooltipFormat.suffixEnabled,
				precision = pieTooltipFormat.precision,
				precisionOption = pieTooltipFormat.precisionOption,
				separator = true,
				prefix = '',
				suffix = pieTooltipFormat.suffix;
			if (prefixEnabled) {
				prefix = pieTooltipFormat.prefixFormat;
			}

			switch(type) {
				case 'None':
					return '';
				case 'Argument':
					return _pointInfo.argumentText;
				case 'Value': 
					return WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption);
				case 'Percent':
					return (_pointInfo.percent*100).toFixed(precision) + '%';
				case 'ArgumentAndValue': 
					return '<b>' + _pointInfo.argumentText + '</b>: '
						+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption);
				case 'ValueAndPercent': 
					return WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption)
						+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
				case 'ArgumentAndPercent':
					return  '<b>' + _pointInfo.argumentText + '</b>: (' 
						+ (_pointInfo.percent*100).toFixed(precision) + '%)';
				case 'ArgumentValueAndPercent':
					return '<b>' + _pointInfo.argumentText + '</b>: '
						+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption)
						+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
				default:
					return '<b>' + _pointInfo.argumentText + '</b>: '
						+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled,precisionOption)
						+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
			}
		}
	}
}; // end of WISE.libs.Dashboard.item.PieChartUtility
