package com.wise.ds.repository.dataset;

import java.sql.ResultSetMetaData;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 *     수정일                 수정자             수정내용   
 *  ----------    --------    ---------------------------
 *  2015.06.08      DOGFOOT             최초 생성
 * </pre>
 */

public class DataField extends javaxt.sql.Field {
    public DataField(int index, ResultSetMetaData md, Object dataValue) {
        super(index, md);
        super.Value = new DataValue(dataValue);
    }
    
    @Override
    public String toString() {
        return "DataField [name = " + super.getName() + ", value = " + super.getValue() + ", type : " + super.getType() + "]";
    }
}
