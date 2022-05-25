package com.wise.comp.model;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SummaryValue implements Cloneable {

    private static final BigDecimal ZERO = BigDecimal.valueOf(0);

    private String fieldName;
    private SummaryType summaryType;
    private long count;
    private BigDecimal sum;
    private BigDecimal value;
    private String textValue;
    private Set<BigDecimal> distinctValues;
    private String precision;
    private String precisionOption;

    public SummaryValue() {
        this(null, null, null, null, null);
    }

    public SummaryValue(final String fieldName, final SummaryType summaryType) {
        this(fieldName, summaryType, null, null, null);
    }

    public SummaryValue(final String fieldName, final SummaryType summaryType, final BigDecimal value, final String precision, final String precisionOption) {
        this.fieldName = fieldName;
        this.summaryType = summaryType;
        this.value = value;
        this.precision = precision;
        this.precisionOption = precisionOption;
    }

    @JsonInclude(Include.NON_NULL)
    @JsonProperty("f")
    public String getFieldName() {
        return fieldName;
    }

    public void setFieldName(final String fieldName) {
        this.fieldName = fieldName;
    }

    @JsonProperty("t")
    public SummaryType getSummaryType() {
        return summaryType;
    }

    public void setSummaryType(final SummaryType summaryType) {
        this.summaryType = summaryType;
    }

    @JsonProperty("c")
    public long getCount() {
        return count;
    }

    public void setCount(long count) {
        this.count = count;
    }

    public long incrementCount() {
        return ++count;
    }

    @JsonInclude(Include.NON_NULL)
    @JsonProperty("s")
    public BigDecimal getSum() {
        return sum;
    }

    public void setSum(BigDecimal sum) {
        this.sum = sum;
    }

    @JsonInclude(Include.NON_NULL)
    @JsonProperty("tv")
    public String getTextValue() {
        return textValue;
    }

    public void setTextValue(String textValue) {
        this.textValue = textValue;
    }

    public BigDecimal addSum(final BigDecimal augend) {
        if (sum != null) {
            sum = sum.add(augend);
        } else {
            sum = augend;
        }

        return sum;
    }

    public void addDistinctValue(final BigDecimal distinctValue) {
        if (distinctValues == null) {
            distinctValues = new HashSet<>();
        }

        distinctValues.add(distinctValue);
    }

    @JsonProperty("dv")
    @JsonInclude(Include.NON_NULL)
    public Set<BigDecimal> getDistinctValues() {
        return distinctValues;
    }

    public void setDistinctValues(Set<BigDecimal> distinctValues) {
        this.distinctValues = distinctValues;
    }

    @JsonInclude(Include.NON_NULL)
    @JsonProperty("v")
    public BigDecimal getValue() {
        return value;
    }

    public void setValue(BigDecimal value) {
        this.value = value;
    }

    @JsonIgnore
    public BigDecimal getRepresentingValue() {
        switch (summaryType) {
        case SUM:
        case CUSTOM:
           return sum;
        case COUNT:
            return BigDecimal.valueOf(count);
        case COUNTDISTINCT:
            return BigDecimal.valueOf(distinctValues != null ? distinctValues.size() : 0);
        case AVERAGE:
        case AVG:
            if (count == 0) {
                return ZERO;
            }
            if(precision == null) {
            	precision = "0";
            }
            
            if(precisionOption != null) {
        		if("올림".equalsIgnoreCase(precisionOption)) {
        			return sum.divide(BigDecimal.valueOf(count), Integer.parseInt(precision), RoundingMode.CEILING);
        		}else if("내림".equalsIgnoreCase(precisionOption)) {
        			return sum.divide(BigDecimal.valueOf(count), Integer.parseInt(precision), RoundingMode.DOWN);
        		} else {
        			return sum.divide(BigDecimal.valueOf(count), Integer.parseInt(precision), RoundingMode.HALF_UP);
        		}
            }else {
            	return sum.divide(BigDecimal.valueOf(count), Integer.parseInt(precision), RoundingMode.HALF_UP);
            }
            
        default:
            break;
        }

        if (value != null) {
            return value;
        }

        return sum;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SummaryValue)) {
            return false;
        }

        final SummaryValue that = (SummaryValue) o;

        if (!StringUtils.equals(fieldName, that.fieldName)) {
            return false;
        }

        if (!Objects.equals(summaryType, that.summaryType)) {
            return false;
        }

        if (count != that.count) {
            return false;
        }

        if (!Objects.equals(sum, that.sum)) {
            return false;
        }

        if (!Objects.equals(value, that.value)) {
            return false;
        }

        if (!Objects.equals(textValue, that.textValue)) {
            return false;
        }

        if (!Objects.equals(distinctValues, that.distinctValues)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(fieldName).append(summaryType).append(count).append(sum)
                .append(value).append(textValue).append(distinctValues).toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("fieldName", fieldName)
                .append("summaryType", summaryType).append("count", count).append("sum", sum)
                .append("value", value).append("textValue", textValue)
                .append("distinctValues", distinctValues).toString();
    }

    @Override
    public Object clone() {
        final SummaryValue clone = new SummaryValue();
        clone.fieldName = fieldName;
        clone.summaryType = summaryType;
        clone.count = count;
        clone.sum = sum != null ? new BigDecimal(sum.toString()) : null;
        clone.value = value != null ? new BigDecimal(value.toString()) : null;;
        clone.textValue = textValue;
        clone.distinctValues = distinctValues != null ? new HashSet<>(distinctValues) : null;
        return clone;
    }

	public String getPrecision() {
		return precision;
	}

	public void setPrecision(String precision) {
		this.precision = precision;
	}

	public String getPrecisionOption() {
		return precisionOption;
	}

	public void setPrecisionOption(String precisionOption) {
		this.precisionOption = precisionOption;
	}
}
