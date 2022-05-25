package com.wise.comp.pivotmatrix.schema.converters;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.wise.comp.pivotmatrix.SummaryCell;
import com.wise.comp.pivotmatrix.schema.AvroConverter;
import com.wise.comp.pivotmatrix.schema.avro.AvroSummaryCell;
import com.wise.comp.pivotmatrix.schema.avro.AvroSummaryCellRow;

public final class SummaryConverterUtils {

    private SummaryConverterUtils() {
    }

    public static <U, C> List<C> convertObjectList(final AvroConverter<U, C> converter,
            final Collection<U> objectList) {
        final int size = objectList != null ? objectList.size() : 0;

        if (size == 0) {
            return Collections.emptyList();
        }

        final List<C> convertedList = new ArrayList<>(size);

        if (size > 0) {
            for (U object : objectList) {
                convertedList.add(converter.convert(object));
            }
        }

        return convertedList;
    }

    public static <U, C> List<U> unconvertAvroObjectList(final AvroConverter<U, C> converter,
            final List<C> convertedList) {
        final int size = convertedList != null ? convertedList.size() : 0;
        final List<U> objectList = new ArrayList<>(size);

        if (size > 0) {
            for (C converted : convertedList) {
                objectList.add(converter.unconvert(converted));
            }
        }

        return objectList;
    }

    public static List<AvroSummaryCellRow> summaryCellsToAvroSummaryCells(
            final SummaryCellConverter summaryCellConverter, final SummaryCell[][] cells) {
        final int rows = cells.length;

        if (rows == 0) {
            return Collections.emptyList();
        }

        final List<AvroSummaryCellRow> avCells = new ArrayList<>(rows);

        for (int i = 0; i < rows; i++) {
            avCells.add(summaryCellArrayToAvroSummaryCellRow(summaryCellConverter, cells[i]));
        }

        return avCells;
    }

    public static SummaryCell[][] avroSummaryCellsToSummaryCells(
            final SummaryCellConverter summaryCellConverter,
            final List<AvroSummaryCellRow> avCells) {
        final int rows = avCells.size();
        final int cols = !avCells.isEmpty() ? avCells.get(0).getRow().size() : 0;

        final SummaryCell[][] cells = new SummaryCell[rows][cols];

        int r = 0;

        for (AvroSummaryCellRow avCellRow : avCells) {
            int c = 0;

            for (AvroSummaryCell avCell : avCellRow.getRow()) {
                cells[r][c] = summaryCellConverter.unconvert(avCell);
                c++;
            }

            r++;
        }

        return cells;
    }

    private static AvroSummaryCellRow summaryCellArrayToAvroSummaryCellRow(
            final SummaryCellConverter summaryCellConverter, final SummaryCell[] cellArray) {
        final List<AvroSummaryCell> asCellList = new ArrayList<>(cellArray.length);

        for (SummaryCell cell : cellArray) {
            asCellList.add(summaryCellConverter.convert(cell));
        }

        return new AvroSummaryCellRow(asCellList);
    }
}
