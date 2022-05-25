package com.wise.ds.repository.controller;

import org.apache.poi.xssf.model.SharedStringsTable;
import org.apache.poi.xssf.usermodel.XSSFRichTextString;
import org.xml.sax.Attributes;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class SheetHandler extends DefaultHandler {
	private SharedStringsTable sst;
	private String lastContents;
	private boolean nextlsString;
	
	public SheetHandler(SharedStringsTable sst) {
		this.sst = sst;
	}
	
	public void startElement(String url, String localName, String name, Attributes attributes) throws SAXException{
		if(name.equals("c")) {
			//cell reference
//			System.out.println(attributes.getValue("r")+ " - ");
			// Figure out if the value is an index in the SST
			String cellType = attributes.getValue("t");
			
			if(cellType != null && cellType.equals("s")) {
				nextlsString = true;
			}else {
				nextlsString = false;
			}
		}
		lastContents  ="";
	}
	
	public void endElement(String url, String localName, String name) throws SAXException{
		// Process the last contents as required.
        // Do now, as characters() may be called more than once
		if(nextlsString) {
			int idx = Integer.parseInt(lastContents);
			lastContents = new XSSFRichTextString(sst.getEntryAt(idx)).toString();
			nextlsString = false;
		}
		// v => contents of a cell
        // Output after we've seen the string contents
		if(name.equals("v")) {
//			System.out.println(lastContents);
		}
	}
	
	public void characters(char[] ch, int start, int length)  throws SAXException{
		lastContents += new String(ch,start,length);
	}
}
