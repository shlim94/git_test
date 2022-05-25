package com.wise.comp.pivotmatrix.schema.converters;

import org.apache.commons.lang3.StringUtils;

import com.wise.comp.pivotmatrix.schema.AvroConverter;

public class EnumConverter<T extends Enum<T>> implements AvroConverter<T, String> {

    private final Class<T> enumClazz;

    public EnumConverter(final Class<T> enumClazz) {
        this.enumClazz = enumClazz;
    }

    @Override
    public String convert(T unconverted) {
        return unconverted != null ? unconverted.toString() : null;
    }

    @Override
    public T unconvert(String converted) {
        return StringUtils.isNotEmpty(converted) ? Enum.valueOf(enumClazz, converted) : null;
    }

}
