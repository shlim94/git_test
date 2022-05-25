package com.wise.comp.pivotmatrix.schema.converters;

import java.math.BigDecimal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import com.wise.comp.model.SummaryType;
import com.wise.comp.model.SummaryValue;
import com.wise.comp.pivotmatrix.schema.AvroConverter;
import com.wise.comp.pivotmatrix.schema.avro.AvroSummaryValue;

public class SummaryValueConverter implements AvroConverter<SummaryValue, AvroSummaryValue> {

    private final EnumConverter<SummaryType> summaryTypeConverter = new EnumConverter<>(
            SummaryType.class);
    private final BigDecimalConverter bigDecimalConverter = new BigDecimalConverter();

    @Override
    public AvroSummaryValue convert(SummaryValue unconverted) {
        return new AvroSummaryValue(unconverted.getFieldName(),
                summaryTypeConverter.convert(unconverted.getSummaryType()), unconverted.getCount(),
                bigDecimalConverter.convert(unconverted.getSum()),
                bigDecimalConverter.convert(unconverted.getValue()), SummaryConverterUtils
                        .convertObjectList(bigDecimalConverter, unconverted.getDistinctValues()),
                unconverted.getTextValue());
    }

    @Override
    public SummaryValue unconvert(AvroSummaryValue converted) {
        final SummaryType summaryType = StringUtils.isNotEmpty(converted.getSummaryType())
                ? SummaryType.valueOf(converted.getSummaryType()) : null;
        final SummaryValue sv = new SummaryValue(converted.getFieldName(), summaryType);
        sv.setCount(converted.getCount());
        sv.setSum(StringUtils.isNotEmpty(converted.getSum()) ? new BigDecimal(converted.getSum())
                : null);
        sv.setValue(StringUtils.isNotEmpty(converted.getValue())
                ? new BigDecimal(converted.getValue()) : null);
        final List<String> dvList = converted.getDistinctValues();
        Set<BigDecimal> dvSet = null;
        if (dvList != null && !dvList.isEmpty()) {
            dvSet = new HashSet<>();
            for (String dv : dvList) {
                dvSet.add(new BigDecimal(dv));
            }
            sv.setDistinctValues(dvSet);
        }
        return sv;
    }
}
