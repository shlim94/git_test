package com.wise.comp.pivotmatrix.schema.converters;

import java.util.ArrayList;
import java.util.List;

import com.wise.comp.model.SummaryValue;
import com.wise.comp.pivotmatrix.SummaryCell;
import com.wise.comp.pivotmatrix.impl.SummaryCellImpl;
import com.wise.comp.pivotmatrix.schema.AvroConverter;
import com.wise.comp.pivotmatrix.schema.avro.AvroSummaryCell;
import com.wise.comp.pivotmatrix.schema.avro.AvroSummaryValue;

public class SummaryCellConverter implements AvroConverter<SummaryCell, AvroSummaryCell> {

    private SummaryValueConverter summaryValueConverter = new SummaryValueConverter();

    @Override
    public AvroSummaryCell convert(SummaryCell unconverted) {
        final List<SummaryValue> svs = unconverted.getSummaryValues();
        final int size = svs != null ? svs.size() : 0;
        List<AvroSummaryValue> asvs = new ArrayList<>(size);
        if (svs != null) {
            for (SummaryValue sv : svs) {
                asvs.add(summaryValueConverter.convert(sv));
            }
        }
        return new AvroSummaryCell(asvs);
    }

    @Override
    public SummaryCell unconvert(AvroSummaryCell converted) {
        final List<AvroSummaryValue> asvs = converted.getSummaryValues();
        List<SummaryValue> svs = null;

        if (asvs != null) {
        	svs = new ArrayList<>(asvs.size());

        	for (AvroSummaryValue asv : asvs) {
            	svs.add(summaryValueConverter.unconvert(asv));
            }
        }

        return new SummaryCellImpl(svs);
    }

}
