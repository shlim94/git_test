package com.wise.comp.pivotgrid.aggregator.util;

import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.math3.stat.StatUtils;

public final class PivotFunctions {

    public PivotFunctions() {
    }

    public BigDecimal Avg(final Object o) {
        return BigDecimal.valueOf(StatUtils.mean(extractNumberArray(o)));
    }

    public BigDecimal Count(final Object o) {
        return BigDecimal.valueOf(extractNumberArray(o).length);
    }

    public BigDecimal Max(final Object o) {
        return BigDecimal.valueOf(StatUtils.max(extractNumberArray(o)));
    }

    public BigDecimal Median(final Object o) {
        return BigDecimal.valueOf(StatUtils.percentile(extractNumberArray(o), 50.0));
    }

    public BigDecimal Min(final Object o) {
        return BigDecimal.valueOf(StatUtils.min(extractNumberArray(o)));
    }

    public BigDecimal[] Mode(final Object o) {
        double[] modeValues = StatUtils.mode(extractNumberArray(o));

        if (modeValues == null || modeValues.length == 0) {
            return new BigDecimal[0];
        }

        BigDecimal[] values = new BigDecimal[modeValues.length];

        for (int i = 0; i < values.length; i++) {
            values[i] = BigDecimal.valueOf(modeValues[i]);
        }

        return values;
    }

    public BigDecimal StdDev(final Object o) {
        final double variance = StatUtils.variance(extractNumberArray(o));
        return BigDecimal.valueOf(variance != Double.NaN ? Math.sqrt(variance) : Double.NaN);
    }

    public BigDecimal Sum(final Object o) {
        return BigDecimal.valueOf(StatUtils.sum(extractNumberArray(o)));
    }

    public BigDecimal Var(final Object o) {
        final double variance = StatUtils.variance(extractNumberArray(o));
        return BigDecimal.valueOf(variance);
    }

    public boolean IsNull(final Object o) {
        return o == null;
    }

    public boolean IsNullOrEmpty(final Object o) {
        return o != null && StringUtils.isEmpty(o.toString());
    }

    public boolean ToBoolean(final Object v) {
        return v != null && BooleanUtils.toBoolean(v.toString());
    }

    public BigDecimal Abs(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return num.abs();
    }

    public BigDecimal Acos(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.acos(num.doubleValue()));
    }

    public BigDecimal Asin(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.asin(num.doubleValue()));
    }

    public BigDecimal Atn(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.atan(num.doubleValue()));
    }

    public BigDecimal BigMul(final Object n1, final Object n2) {
        final BigDecimal num1 = n1 instanceof BigDecimal ? (BigDecimal) n1
                : new BigDecimal(n1.toString());
        final BigDecimal num2 = n2 instanceof BigDecimal ? (BigDecimal) n2
                : new BigDecimal(n2.toString());
        return num1.multiply(num2);
    }

    public BigDecimal Ceiling(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.ceil(num.doubleValue()));
    }

    public BigDecimal Cos(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.cos(num.doubleValue()));
    }

    public BigDecimal Cosh(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.cosh(num.doubleValue()));
    }

    public BigDecimal Exp(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.exp(num.doubleValue()));
    }

    public BigDecimal Floor(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.floor(num.doubleValue()));
    }

    public BigDecimal Log(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.log(num.doubleValue()));
    }

    public BigDecimal Log10(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.log10(num.doubleValue()));
    }

    public BigDecimal Power(final Object n, final Object p) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        final BigDecimal pw = n instanceof BigDecimal ? (BigDecimal) p
                : new BigDecimal(p.toString());
        return num.pow(pw.intValue());
    }

    public BigDecimal Rnd() {
        return BigDecimal.valueOf(Math.random());
    }

    public BigDecimal Round(final Object n) {
        return Round(n, BigDecimal.valueOf(0));
    }
    
    public BigDecimal Round(final Object n1, final Object n2) {
    	final BigDecimal num = n1 instanceof BigDecimal ? (BigDecimal) n1
                : new BigDecimal(n1.toString());
    	final int scale = n2 instanceof BigDecimal ? ((BigDecimal) n2).intValue()
                : new BigDecimal(n2.toString()).intValue();
    	return num.setScale(scale, RoundingMode.HALF_UP);
    }

    public BigDecimal Sign(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(num.signum());
    }

    public BigDecimal Sin(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.sin(num.doubleValue()));
    }

    public BigDecimal Sinh(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.sinh(num.doubleValue()));
    }

    public BigDecimal Sqr(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.sqrt(num.doubleValue()));
    }

    public BigDecimal Tan(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.tan(num.doubleValue()));
    }

    public BigDecimal Tanh(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return BigDecimal.valueOf(Math.tanh(num.doubleValue()));
    }

    public String Ascii(final Object s) {
        byte[] bytes = s.toString().getBytes();
        return bytes.length > 0 ? Character.toString((char) bytes[0]) : "";
    }

    public String Char(final Object n) {
        final BigDecimal num = n instanceof BigDecimal ? (BigDecimal) n
                : new BigDecimal(n.toString());
        return Character.toString((char) num.intValue());
    }

    public BigDecimal CharIndex(final Object s1, final Object s2) {
        return BigDecimal.valueOf(StringUtils.indexOf(s2.toString(), s1.toString()));
    }

    public String Concat(final Object... array) {
        return StringUtils.join(array, "");
    }

    public boolean Contains(final Object s1, final Object s2) {
        return StringUtils.contains(s1.toString(), s2.toString());
    }

    public boolean EndsWith(final Object s, final Object f) {
        return StringUtils.endsWith(s.toString(), f.toString());
    }

    public String Insert(final Object s1, final Object p, final Object s2) {
        final BigDecimal pos = p instanceof BigDecimal ? (BigDecimal) p
                : new BigDecimal(p.toString());
        final String left = StringUtils.substring(s1.toString(), 0, pos.intValue());
        final String right = StringUtils.substring(s1.toString(), pos.intValue());
        return left + s2.toString() + right;
    }

    public int Len(final Object s) {
        return StringUtils.length(s.toString());
    }

    public String Lower(final Object s) {
        return StringUtils.lowerCase(s.toString());
    }

    public String PadLeft(final Object s, final Object l) {
        return PadLeft(s, l, " ");
    }

    public String PadLeft(final Object s, final Object l, final Object c) {
        final BigDecimal len = l instanceof BigDecimal ? (BigDecimal) l
                : new BigDecimal(l.toString());
        return StringUtils.leftPad(s.toString(), len.intValue(), c.toString());
    }

    public String PadRight(final Object s, final Object l) {
        return PadRight(s, l, " ");
    }

    public String PadRight(final Object s, final Object l, final Object c) {
        final BigDecimal len = l instanceof BigDecimal ? (BigDecimal) l
                : new BigDecimal(l.toString());
        return StringUtils.rightPad(s.toString(), len.intValue(), c.toString());
    }

    public String Remove(final Object o, final int pos) {
        return StringUtils.substring(o.toString(), 0, pos);
    }

    public String Remove(final Object o, final Object p, final Object l) {
        final BigDecimal pos = p instanceof BigDecimal ? (BigDecimal) l
                : new BigDecimal(p.toString());
        final BigDecimal len = l instanceof BigDecimal ? (BigDecimal) l
                : new BigDecimal(l.toString());
        final String left = StringUtils.substring(o.toString(), pos.intValue());
        final String right = StringUtils.substring(o.toString(), pos.intValue() + len.intValue());
        return left + right;
    }

    public String Replace(final Object o, final Object f, final Object r) {
        return StringUtils.replace(o.toString(), f.toString(), r.toString());
    }

    public String Reverse(final Object o) {
        return StringUtils.reverse(o.toString());
    }

    public boolean StartsWith(final Object s, final Object f) {
        return StringUtils.startsWith(s.toString(), f.toString());
    }

    public String StringAdd(final Object... arr) {
        return StringUtils.join(arr, "");
    }

    public String Substring(final Object s, final Object p, final Object l) {
        final BigDecimal pos = p instanceof BigDecimal ? (BigDecimal) l
                : new BigDecimal(p.toString());
        final BigDecimal len = l instanceof BigDecimal ? (BigDecimal) l
                : new BigDecimal(l.toString());
        return StringUtils.substring(s.toString(), pos.intValue(), pos.intValue() + len.intValue());
    }

    public String ToStr(final Object s) {
        return s.toString();
    }

    public String Trim(final Object s) {
        return StringUtils.trim(s.toString());
    }

    public String Upper(final Object s) {
        return StringUtils.upperCase(s.toString());
    }

    private double[] extractNumberArray(final Object o) {
        if (o != null) {
            if (o.getClass().isArray()) {
                final int size = Array.getLength(o);
                double[] nums = new double[size];
                for (int i = 0; i < size; i++) {
                    final BigDecimal d = new BigDecimal(Array.get(o, i).toString());
                    nums[i] = d.doubleValue();
                }
                return nums;
            } else if (o instanceof Iterable) {
                final List<?> list = IterableUtils.toList((Iterable<?>) o);
                final int size = list.size();
                double[] nums = new double[size];
                for (int i = 0; i < size; i++) {
                    final BigDecimal d = new BigDecimal(list.get(i).toString());
                    nums[i] = d.doubleValue();
                }
                return nums;
            } else if (o instanceof Iterator) {
                final List<?> list = IteratorUtils.toList((Iterator<?>) o);
                final int size = list.size();
                double[] nums = new double[size];
                for (int i = 0; i < size; i++) {
                    final BigDecimal d = new BigDecimal(list.get(i).toString());
                    nums[i] = d.doubleValue();
                }
                return nums;
            }
        }

        return ArrayUtils.EMPTY_DOUBLE_ARRAY;
    }
}
