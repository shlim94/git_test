package com.wise.comp.pivotgrid.param;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public class UdfGroupParam {

    private String name;
    private List<String> selectors;
    private List<String> groupIntervals;
    private String expression;

    public UdfGroupParam() {
    }

    public UdfGroupParam(final String name, final List<String> selectors,
            final List<String> groupIntervals) {
        setName(name);
        setSelectors(selectors);
        setGroupIntervals(groupIntervals);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getSelectors() {
        return selectors != null ? Collections.unmodifiableList(selectors) : Collections.emptyList();
    }

    public void setSelectors(List<String> selectors) {
        this.selectors = selectors != null ? new ArrayList<>(selectors) : Collections.emptyList();
    }

    public List<String> getGroupIntervals() {
        return groupIntervals != null ? Collections.unmodifiableList(groupIntervals) : Collections.emptyList();
    }

    public void setGroupIntervals(List<String> groupIntervals) {
        this.groupIntervals = groupIntervals != null ? new ArrayList<>(groupIntervals)
                : Collections.emptyList();
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof UdfGroupParam)) {
            return false;
        }

        final UdfGroupParam that = (UdfGroupParam) o;

        if (!StringUtils.equals(name, that.name)) {
            return false;
        }

        if (!Objects.equals(selectors, that.selectors)) {
            return false;
        }

        if (!Objects.equals(groupIntervals, that.groupIntervals)) {
            return false;
        }

        if (!StringUtils.equals(expression, that.expression)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(name).append(selectors).append(groupIntervals)
                .append(expression).toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("name", name).append("selectors", selectors)
                .append("groupIntervals", groupIntervals).append("expression", expression)
                .toString();
    }
}
