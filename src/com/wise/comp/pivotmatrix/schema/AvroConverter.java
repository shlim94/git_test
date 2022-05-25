package com.wise.comp.pivotmatrix.schema;

public interface AvroConverter<U, C> {

    public C convert(U unconverted);

    public U unconvert(C converted);

}
