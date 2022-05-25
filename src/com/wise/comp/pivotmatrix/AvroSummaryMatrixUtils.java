package com.wise.comp.pivotmatrix;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedList;

import org.apache.avro.io.DatumReader;
import org.apache.avro.io.DatumWriter;
import org.apache.avro.io.Decoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.io.Encoder;
import org.apache.avro.io.EncoderFactory;
import org.apache.avro.specific.SpecificDatumReader;
import org.apache.avro.specific.SpecificDatumWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wise.comp.pivotmatrix.schema.avro.AvroSummaryCell;
import com.wise.comp.pivotmatrix.schema.avro.AvroSummaryCellRow;
import com.wise.comp.pivotmatrix.schema.avro.AvroSummaryCellRows;
import com.wise.comp.pivotmatrix.schema.converters.SummaryCellConverter;

public final class AvroSummaryMatrixUtils {

    private static Logger log = LoggerFactory.getLogger(AvroSummaryMatrixUtils.class);

    private static SummaryCellConverter cellConverter = new SummaryCellConverter();

    private AvroSummaryMatrixUtils() {
    }

	public static void serializeAvroSummaryCellRowsToAvroData(final OutputStream output, final SummaryCell[][] cells) throws IOException {
		serializeAvroSummaryCellRowsToAvroData(output, cells, 0);
	}

	public static void serializeAvroSummaryCellRowsToAvroData(final OutputStream output, final SummaryCell[][] cells,
			final int beginCellRowIndex) throws IOException {
		serializeAvroSummaryCellRowsToAvroData(output, cells, beginCellRowIndex, -1);
	}

    public static void serializeAvroSummaryCellRowsToAvroData(final OutputStream output,
            final SummaryCell[][] cells, final int beginCellRowIndex, final int maxCellRows) throws IOException {
		final int endIndex = Math.min(cells.length,
				beginCellRowIndex + (maxCellRows >= 0 ? maxCellRows : cells.length));

		final AvroSummaryCellRows avroCellRows = new AvroSummaryCellRows(new LinkedList<AvroSummaryCellRow>());
    	final int rows = endIndex - beginCellRowIndex;

		if (rows > 0) {
			for (int i = beginCellRowIndex; i < endIndex; i++) {
	    		final AvroSummaryCellRow avroCellRow = new AvroSummaryCellRow(new LinkedList<AvroSummaryCell>());
				
				final int cols = cells[i].length;
				for (int j = 0; j < cols; j++) {
    				final SummaryCell cell = cells[i][j];
    				final AvroSummaryCell avroCell = cellConverter.convert(cell);
    				avroCellRow.getRow().add(avroCell);
				}
				
	    		avroCellRows.getRows().add(avroCellRow);
			}
		}

    	final DatumWriter<AvroSummaryCellRows> writer = new SpecificDatumWriter<>(AvroSummaryCellRows.class);
    	final Encoder encoder = EncoderFactory.get().binaryEncoder(output, null);
        writer.write(avroCellRows, encoder);
        encoder.flush();
    }

    public static SummaryCell[][] deserializeSummaryCellRowsFromAvroData(final InputStream input)
            throws IOException {
        final DatumReader<AvroSummaryCellRows> reader = new SpecificDatumReader<>(AvroSummaryCellRows.class);
        final Decoder decoder = DecoderFactory.get().binaryDecoder(input, null);
        final AvroSummaryCellRows avroCellRows = reader.read(null, decoder);
        final int rows = avroCellRows.getRows().size();

        if (rows == 0) {
        	return new SummaryCell[0][];
        }

        final int cols = avroCellRows.getRows().get(0).getRow().size();

        final SummaryCell[][] cells = new SummaryCell[rows][cols];

        int r = 0;
        for (AvroSummaryCellRow row : avroCellRows.getRows()) {
        	int c = 0;
        	for (AvroSummaryCell avroCell : row.getRow()) {
        		cells[r][c] = cellConverter.unconvert(avroCell);
        		c++;
        	}
        	r++;
        }

        return cells;
    }
}
