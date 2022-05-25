package com.wise.comp.pivotmatrix;

import java.util.concurrent.atomic.AtomicInteger;

public final class SummaryDimensionUtils {

	private static final String DEFAULT_DESCENDANT_COUNT_ATTR_NAME = "descnt";

	private static final String DEFAULT_LEAF_DESCENDANT_COUNT_ATTR_NAME = "lfdescnt";

	private SummaryDimensionUtils() {
	}
	
	public static int getDescendantCount(final SummaryDimension dimension) {
		final Integer cachedCount = (Integer) dimension.getAttribute(DEFAULT_DESCENDANT_COUNT_ATTR_NAME);
		
		if(cachedCount != null) {
			return cachedCount.intValue();
		}
		
		final AtomicInteger counter = new AtomicInteger();
		countChildCount(counter, dimension);
		final int count = counter.intValue();
		
		dimension.setAttribute(DEFAULT_DESCENDANT_COUNT_ATTR_NAME, Integer.valueOf(count));
		
		return count;
	}

	public static int getLeafDescendantCount(final SummaryDimension dimension) {
		final Integer cachedCount = (Integer) dimension.getAttribute(DEFAULT_LEAF_DESCENDANT_COUNT_ATTR_NAME);
		
		if(cachedCount != null) {
			return cachedCount.intValue();
		}
		
		final AtomicInteger counter = new AtomicInteger();
		countLeafChildCount(counter, dimension);
		final int count = counter.intValue();
		
		dimension.setAttribute(DEFAULT_LEAF_DESCENDANT_COUNT_ATTR_NAME, Integer.valueOf(count));
		
		return count;
	}

	private static void countChildCount(final AtomicInteger counter, final SummaryDimension dimension) {
		final Integer cachedOwnCount = (Integer) dimension.getAttribute(DEFAULT_DESCENDANT_COUNT_ATTR_NAME);
		
		if(cachedOwnCount != null) {
			counter.addAndGet(cachedOwnCount.intValue());
		}
		else {
			final AtomicInteger ownCounter = new AtomicInteger();
			
			if(dimension.hasChild()) {
				for(SummaryDimension childDimension : dimension.getChildren()) {
					countChildCount(ownCounter, childDimension);
				}
			}
			
			ownCounter.addAndGet(dimension.getChildCount());
			final int ownCount = ownCounter.intValue();
			dimension.setAttribute(DEFAULT_DESCENDANT_COUNT_ATTR_NAME, Integer.valueOf(ownCount));
			counter.addAndGet(ownCount);
		}
	}

	private static void countLeafChildCount(final AtomicInteger counter, final SummaryDimension dimension) {
		final Integer cachedOwnCount = (Integer) dimension.getAttribute(DEFAULT_LEAF_DESCENDANT_COUNT_ATTR_NAME);
		
		if(cachedOwnCount != null) {
			counter.addAndGet(cachedOwnCount.intValue());
		}
		else {
			if (dimension.hasChild()) {
				final AtomicInteger ownCounter = new AtomicInteger();
				for(SummaryDimension childDimension : dimension.getChildren()) {
					countLeafChildCount(ownCounter, childDimension);
				}
				final int ownCount = ownCounter.intValue();
				dimension.setAttribute(DEFAULT_LEAF_DESCENDANT_COUNT_ATTR_NAME, Integer.valueOf(ownCount));
				counter.addAndGet(ownCount);
			}
			else {
				counter.incrementAndGet();
			}
		}
	}
}
