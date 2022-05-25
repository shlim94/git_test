package com.wise.comp.impl.json;

import java.util.Iterator;
import java.util.List;

import com.wise.comp.model.DataFrame;
import com.wise.comp.model.DataRow;

import net.sf.json.JSONObject;

public class JSONArrayDataFrame implements DataFrame {
	// 고운산 - 조회 루틴 변경  20210913
	private final List<JSONObject> dataArray;
	private final String[] columnNames;

	public JSONArrayDataFrame(final List<JSONObject> dataArray, final String[] columnNames) {
		this.dataArray = dataArray;
		final int columnCount = columnNames.length;
		this.columnNames = new String[columnCount];
		System.arraycopy(columnNames, 0, this.columnNames, 0, columnCount);
	}

	public String[] getColumnNames() {
		return columnNames.clone();
	}

	public Iterator<DataRow> iterator() {
		return new DataRowIterator(dataArray.iterator());
	}

	private class DataRowIterator implements Iterator<DataRow> {
		private final Iterator<JSONObject> it;
		
		DataRowIterator(Iterator<JSONObject> it){
			this.it = it;
		}
		
		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public DataRow next() {
			return new JSONObjectDataRow(it.next());
		}
	}
}
