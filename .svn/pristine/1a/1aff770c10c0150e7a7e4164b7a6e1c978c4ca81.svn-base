package com.wise.common.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wise.common.web.filter.GenericDataResourceContext;

import net.sf.json.JSONObject;

public class FileBackedJSONObjectList extends LinkedList<JSONObject> implements CloseableList<JSONObject> {

	private static final long serialVersionUID = 1L;

	private static Logger log = LoggerFactory.getLogger(FileBackedJSONObjectList.class);

	private static final AtomicInteger hashCodeGen = new AtomicInteger();

	private static final int DEFAULT_MAX_SIZE_IN_MEMORY_ON_PROD = 100000;

	private static final int DEFAULT_MAX_SIZE_IN_MEMORY_ON_DEV = 10000;

	private static final String TEMP_FILE_PREFIX = FileBackedJSONObjectList.class.getSimpleName();
	
	private static final String TEMP_FILE_SUFFIX = ".tmp";
	
	private static final File DEFAULT_BASE_TEMP_FOLDER = new File(new File("UploadFiles"), "list_json_temp");

	private static final String activeSpringProfile;
	
	private static final int defaultMaxSizeInMemory;
	
	static {
		activeSpringProfile = System.getProperty("spring.profiles.active");
		defaultMaxSizeInMemory = "PROD".equals(activeSpringProfile) ? DEFAULT_MAX_SIZE_IN_MEMORY_ON_PROD
				: DEFAULT_MAX_SIZE_IN_MEMORY_ON_DEV;
		log.info("Setting defaultMaxSizeInMemory to {}. Active spring profile: {}", defaultMaxSizeInMemory,
				activeSpringProfile);
	}

	private int totalSize;
	private final int maxSizeInMemory;
	private File baseTempFolder = DEFAULT_BASE_TEMP_FOLDER;
	private final int bufferSize = 100000;
	private List<JSONObject> bufferedElems = new LinkedList<>();
	private File backingFile;
	private final int hash;

	private Map<String, Object> attributes;
	
	private PrintWriter dataAppender;
	
	private List<FileBackedJSONObjectIterator> iterators;

	public FileBackedJSONObjectList() {
		this(defaultMaxSizeInMemory);
	}

	public FileBackedJSONObjectList(final int maxSizeInMemory) {
		this(maxSizeInMemory, DEFAULT_BASE_TEMP_FOLDER);
	}

	public FileBackedJSONObjectList(final File baseTempFolder) {
		this(defaultMaxSizeInMemory, baseTempFolder);
	}
	
	public FileBackedJSONObjectList(final int maxSizeInMemory, final File baseTempFolder) {
		super();
		this.maxSizeInMemory = maxSizeInMemory;
		this.baseTempFolder = baseTempFolder;
		this.hash = hashCodeGen.incrementAndGet();
		
		GenericDataResourceContext.add(this);
	}
	
	@Override
	public int size() {
		return totalSize;
	}
	
	@Override
	public boolean add(JSONObject e) {
		final int size = super.size();
		
		if (size < maxSizeInMemory) {
			final boolean added = super.add(e);
			
			if (added) {
				++totalSize;
			}
			
			return added;
		}
		
		boolean added = bufferedElems.add(e);
		
		if (added) {
			++totalSize;
			
			if (bufferedElems.size() > bufferSize) {
				flushToBackingFile();
			}
			
			return added;
		} 
		
		return false;
	}
	
	@Override
	public void add(int index, JSONObject element) {
		throw new UnsupportedOperationException();
	}
	
	@Override
	public Iterator<JSONObject> iterator() {
		if (totalSize < maxSizeInMemory) {
			return super.iterator();
		}
		
		flushToBackingFile();
		
		final FileBackedJSONObjectIterator it = new FileBackedJSONObjectIterator(super.iterator(), maxSizeInMemory, totalSize, backingFile, bufferSize);
		
		if (iterators == null) {
			iterators = new LinkedList<>();
		}
		
		iterators.add(it);
		
		return it;
	}

	@Override
	public JSONObject get(int i) {
		if (i < maxSizeInMemory) {
			return super.get(i);
		}

	    throw new UnsupportedOperationException();
	}
	
	@Override
	public List<JSONObject> subList(int fromIndex, int toIndex) {
		throw new UnsupportedOperationException();
	}
	
	@Override
	public boolean addAll(Collection<? extends JSONObject> c) {
		boolean added = false;
		
		for (JSONObject elem : c) {
			added = add(elem);
			
			if (!added) {
				break;
			}
		}
		
		return added;
	} 
	
	@Override
	public boolean addAll(int index, Collection<? extends JSONObject> c) {
		throw new UnsupportedOperationException();
	}
	
	@Override
	public boolean remove(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public JSONObject remove(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		super.clear();
		
		if (iterators != null && !iterators.isEmpty()) {
			for (FileBackedJSONObjectIterator it : iterators) {
				IOUtils.closeQuietly(it);
			}
			iterators.clear();
		}

		if (dataAppender != null) {
			IOUtils.closeQuietly(dataAppender);
			dataAppender = null;
		}
		
		if (backingFile != null && backingFile.isFile()) {
			backingFile.delete();
			backingFile = null;
		}

		totalSize = 0;
		bufferedElems.clear();;
	}

	@Override
	public void close() {
		if (iterators != null && !iterators.isEmpty()) {
			for (FileBackedJSONObjectIterator it : iterators) {
				IOUtils.closeQuietly(it);
			}
			iterators.clear();
			iterators = null;
		}

		if (dataAppender != null) {
			IOUtils.closeQuietly(dataAppender);
			dataAppender = null;
		}

		bufferedElems.clear();;
	}
	
	@Override
	public int hashCode() {
		return hash;
	}
	
	@Override
	public void setAttribute(final String attrName, final Object attrValue) {
		if (attributes == null) {
			attributes = new HashMap<>();
		}
		attributes.put(attrName, attrValue);
	}
	
	@Override
	public Object getAttribute(final String attrName) {
		return attributes != null ? attributes.get(attrName) : null;
	}

	private void flushToBackingFile() {
		if (bufferedElems.isEmpty()) {
			return;
		}
		
		if (backingFile == null || !backingFile.isFile()) {
			try {
				if (baseTempFolder == null) {
					backingFile = File.createTempFile(TEMP_FILE_PREFIX, TEMP_FILE_SUFFIX);
				} else {
					final String dateFolderName = new SimpleDateFormat("yyyyMMdd").format(new Date());
					final File tempFolder = new File(baseTempFolder, dateFolderName);
					if (!tempFolder.isDirectory()) {
						tempFolder.mkdirs();
					}
					backingFile = File.createTempFile(TEMP_FILE_PREFIX, TEMP_FILE_SUFFIX, tempFolder);
				}
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		
		int writeCount = 0;
		
		if (dataAppender == null) {
			FileOutputStream fos = null;
			OutputStreamWriter osw = null;
			BufferedWriter bw = null;
			try {
			    fos = new FileOutputStream(backingFile, true);
				osw = new OutputStreamWriter(fos, "UTF-8");
				bw = new BufferedWriter(osw);
				dataAppender = new PrintWriter(bw);
			} catch (Exception ex) {
				IOUtils.closeQuietly(dataAppender, bw, osw, fos);
				throw new RuntimeException(ex);
			}
		}

		try {
			for (JSONObject elem : bufferedElems) {
				dataAppender.println(elem.toString());
				++writeCount;
			}
			dataAppender.flush();
		}
		catch (Exception ex) {
			IOUtils.closeQuietly(dataAppender);
			throw new RuntimeException(ex);
		}
		finally {
			if (writeCount > 0) {
				if (writeCount == bufferedElems.size()) {
					bufferedElems.clear();
				}
				else {
					bufferedElems = bufferedElems.subList(writeCount, bufferedElems.size() - writeCount);
				}
			}
		}
	}
	
	static class FileBackedJSONObjectIterator implements Iterator<JSONObject>, Closeable {
		
		private int index;
		private Iterator<JSONObject> it;
		private List<JSONObject> itBufferedElems = new LinkedList<>();
		private final int maxSizeInMemory;
		private final int totalSize;
		private final File backingFile;
		private final int bufferSize;
		private BufferedReader dataFetcher;

		FileBackedJSONObjectIterator(final Iterator<JSONObject> it, final int maxSizeInMemory, final int totalSize, final File backingFile, final int bufferSize) {
			this.it = it;
			this.maxSizeInMemory = maxSizeInMemory;
			this.totalSize = totalSize;
			this.backingFile = backingFile;
			this.bufferSize = bufferSize;
		}
		
		@Override
		public boolean hasNext() {
			if (index < maxSizeInMemory) {
				return it.hasNext();
			}
			
			return index < totalSize;
		}
		
		@Override
		public JSONObject next() {
			if (index < maxSizeInMemory) {
				final JSONObject elem = it.next();
				++index;
				return elem;
			}
			
			if (itBufferedElems.isEmpty()) {
				if (dataFetcher == null && backingFile != null && backingFile.isFile()) {
					FileInputStream fis = null;
					InputStreamReader isr = null;
					try {
						fis = new FileInputStream(backingFile);
						isr = new InputStreamReader(fis, "UTF-8");
						dataFetcher = new BufferedReader(isr);
					}
					catch (IOException e) {
						IOUtils.closeQuietly(dataFetcher, isr, fis);
						throw new RuntimeException(e);
					}
				}

				try {
					for (int i = 0; i < bufferSize; i++) {
						final String line = dataFetcher.readLine();
						
						if (StringUtils.isEmpty(line)) {
							break;
						}
						
						itBufferedElems.add(JSONObject.fromObject(line));
					}
				}
				catch (IOException e) {
					IOUtils.closeQuietly(dataFetcher);
					throw new RuntimeException(e);
				}
			}
			
			if (itBufferedElems.isEmpty()) {
				throw new NoSuchElementException();
			}
			
			final JSONObject elem = itBufferedElems.remove(0);
			++index;
			return elem;
		}
		
		@Override
		public void close() {
			if (dataFetcher != null) {
				IOUtils.closeQuietly(dataFetcher);
				dataFetcher = null;
			}
		}
	}
}
