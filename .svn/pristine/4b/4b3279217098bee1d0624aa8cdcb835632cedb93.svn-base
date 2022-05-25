package com.wise.ds.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.ConnectException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import net.sf.json.JSONObject;
import net.sf.json.JSONArray;

import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.wise.common.util.CoreUtils;
import com.wise.context.config.Configurator;
import com.wise.ds.repository.DimensionSorter;
import com.wise.ds.repository.NotFoundReportXmlException;
import com.wise.ds.repository.ReportMasterVO;

@Service("Xml2Json")
public class Xml2Json {
    private static final Logger logger = LoggerFactory.getLogger(Xml2Json.class);
    
    private String xmlBodyText = "";
	private JSONObject mapJSON;
	
    public void arrange(int xmlReqId, String shapeFileLocation) {
        try {          
	        boolean isBom = Configurator.getInstance().getConfigBooleanValue("wise.ds.repository.olap.xml.isBom", true);
	        if (isBom) {
	            this.xmlBodyText = this.xmlBodyText.substring(1);
	        }
	        
	        /* document */
	        InputSource is = new InputSource(new StringReader(this.xmlBodyText));
	        logger.debug(this.xmlBodyText);
	        Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
	        XPath xpath0 = XPathFactory.newInstance().newXPath();
	        
	        /* removing title vlaue */
	        NodeList TitleList = (NodeList) xpath0.evaluate("//Title", document, XPathConstants.NODESET);
	        for( int idx = 0; idx < TitleList.getLength(); idx++ ) {
	            Node title = TitleList.item(idx);
	            if (title.getNodeType() == Node.ELEMENT_NODE) {
	                ((Element) title).setTextContent("");
	                break;
	            }
	        }
	        
	        /* removing shape data */
	//        ShapeFileCreator shapeFileCreator = new ShapeFileCreator();
	//        NodeList shapeDataList = (NodeList) xpath0.evaluate("//Data[@ShapeData]", document, XPathConstants.NODESET);
	//        for( int idx = 0; idx < shapeDataList.getLength(); idx++ ) {
	//            Node shapeData = shapeDataList.item(idx);
	//            
	//            // remove ShapeData attribute
	//            if (shapeData.getNodeType() == Node.ELEMENT_NODE) {
	//                Node mapNode = shapeData.getParentNode().getParentNode();
	//                shapeFileName = Integer.toString(xmlReqId) + "_" + ((Element) mapNode).getAttribute("ComponentName");
	//                
	//                Element elem = (Element) shapeData;
	//                shapeDataValue = elem.getAttribute("ShapeData");
	//                attributeDataValue = elem.getAttribute("AttributeData");
	//                
	//                elem.setAttribute("wiseShapeFileName", shapeFileName);
	//                elem.removeAttribute("ShapeData");
	//                elem.removeAttribute("AttributeData");
	//                
	//                // create .shp & .dbf file
	//                shapeFileCreator.create(shapeFileLocation, shapeFileName, shapeDataValue, attributeDataValue);
	//            }
	//        }
	        
	        /* grid column ordering */
	        int gridColumnOrder = 0;
	        NodeList gridList = (NodeList) xpath0.evaluate("//Grid", document, XPathConstants.NODESET);
	        
	        for( int idx = 0; idx < gridList.getLength(); idx++ ) {
	            Node grid = gridList.item(idx);
	            XPath xpath1 = XPathFactory.newInstance().newXPath();
	            
	            NodeList gridColumnList = (NodeList) xpath1.evaluate("//GridColumns", grid, XPathConstants.NODESET);
	            
	            for( int x0 = 0; x0 < gridColumnList.getLength(); x0++ ){
	                Node gridColumn = gridColumnList.item(x0);
	                NodeList gridColumnChild = gridColumn.getChildNodes();
	                
	                gridColumnOrder = 0;
	                
	                for (int x1 = 0; x1 < gridColumnChild.getLength(); x1++) {
	                    Node child = gridColumnChild.item(x1);
	                    
	                    if (child.getNodeType() == Node.ELEMENT_NODE) {
	                        Element elem = (Element) child;
	                        elem.setAttribute("wiseOrder", Integer.toString(gridColumnOrder));
	                        
	                        gridColumnOrder += 1;
	                    }
	                }
	            }
	        }
	        
	        TransformerFactory tf = TransformerFactory.newInstance();
	        Transformer transformer = tf.newTransformer();
	        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
	        StringWriter writer = new StringWriter();
	        transformer.transform(new DOMSource(document), new StreamResult(writer));
	        
	        this.xmlBodyText = writer.getBuffer().toString().replaceAll("\n|\r", "");
        } catch (IOException | SAXException | ParserConfigurationException | XPathExpressionException | TransformerException e) {
        	e.printStackTrace();
        }
    }
    
    public JSONObject parseJSON(int reportid) {
        
//        logger.debug("XML(document) : " + this.xmlBodyText);
        
        int PRETTY_PRINT_INDENT_FACTOR = 4;
        org.json.JSONObject xmlJSONObj = org.json.XML.toJSONObject(this.xmlBodyText);
        String jsonPrettyPrintString = xmlJSONObj.toString(PRETTY_PRINT_INDENT_FACTOR);
        JSONObject jsonObject = JSONObject.fromObject(jsonPrettyPrintString);
        JSONArray DataSources;
        if(jsonObject.getJSONObject("Dashboard").getJSONObject("DataSources").has("DataSource")) {
        	if (jsonObject.getJSONObject("Dashboard").getJSONObject("DataSources").get("DataSource").getClass() == JSONObject.class) {
        		DataSources = JSONArray.fromObject("["+jsonObject.getJSONObject("Dashboard").getJSONObject("DataSources").getJSONObject("DataSource").toString()+"]");
        		jsonObject.getJSONObject("Dashboard").getJSONObject("DataSources").put("DataSource", DataSources);
        	}
        }else if(jsonObject.getJSONObject("Dashboard").getJSONObject("DataSources").has("ObjectDataSource")) {
        	if (jsonObject.getJSONObject("Dashboard").getJSONObject("DataSources").get("ObjectDataSource").getClass() == JSONObject.class) {
        		DataSources = JSONArray.fromObject("["+jsonObject.getJSONObject("Dashboard").getJSONObject("DataSources").getJSONObject("ObjectDataSource").toString()+"]");
        		jsonObject.getJSONObject("Dashboard").getJSONObject("DataSources").put("DataSource", DataSources);
        	}
        }
       
        /* layout handling */
        int toIndex = this.xmlBodyText.indexOf("<LayoutTree>");
        int frIndex = this.xmlBodyText.indexOf("</LayoutTree>");
        
        if (toIndex > -1 && frIndex > -1) {
        	try {
	            String layoutTreeString = this.xmlBodyText.substring(toIndex, frIndex);
	            layoutTreeString += "</LayoutTree>";
	            org.json.JSONObject tempobj = org.json.XML.toJSONObject(layoutTreeString);
	            InputSource layoutIs = new InputSource(new StringReader(layoutTreeString));
	            Document layoutDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(layoutIs);
	            
	            XPath xpath = XPathFactory.newInstance().newXPath();
	            
	            /* when layout xml has only one item */
	            NodeList layoutItemList = (NodeList) xpath.evaluate("//*[@DashboardItem]", layoutDocument, XPathConstants.NODESET);
	            if (layoutItemList.getLength() == 1) {
	                for(int idx = 0; idx < layoutItemList.getLength(); idx++) {
	                    Node layoutItem = layoutItemList.item(idx);
	                    
	                    if (layoutItem.getNodeType() == Node.ELEMENT_NODE) {
	                        Element elem = (Element) layoutItem;
	                        elem.setAttribute("Orientation", "Vertical");
	                        elem.setAttribute("Weight", "100");
	                    }
	                }
	            }
	            
	            /* layout vertical, horizontal setting */
	            NodeList layoutGroup = (NodeList) xpath.evaluate("//*[@Orientation='Vertical']", layoutDocument, XPathConstants.NODESET);
	            for(int idx = 0; idx < layoutGroup.getLength(); idx++) {
	                Node layout = layoutGroup.item(idx);
	//                System.out.println(layout.getNodeName()+"\n"+layout.toString());
	                NodeList childLayoutList = layout.getChildNodes();
	                
	                // add Vertical css class to chilid layout
	                for (int x0 = 0; x0 < childLayoutList.getLength(); x0++) {
	                    Node child = childLayoutList.item(x0);
	                    
	                    if (child.getNodeType() == Node.ELEMENT_NODE) {
	                        Element elem = (Element) child;
	                        elem.setAttribute("class", "horizontal");
	                    }
	                }
	                
	                // remove Orientation attribute
	                if (layout.getNodeType() == Node.ELEMENT_NODE) {
	                    ((Element) layout).removeAttribute("Orientation");
	                }
	            }
	            
	            /* layout width or height setting */
	            double weight;
	            String weightStr;
	            String cssClass;
	            String style;
	            NodeList weightGroup = (NodeList) xpath.evaluate("//*[@Weight]", layoutDocument, XPathConstants.NODESET);
	            for(int idx = 0; idx < weightGroup.getLength(); idx++){
	                Node layout = weightGroup.item(idx);
	                
	                // remove Orientation attribute
	                if (layout.getNodeType() == Node.ELEMENT_NODE) {
	                    Element elem = (Element) layout;
	                    cssClass = elem.getAttribute("class");
	//                    System.out.println("nodeName : "+elem.getNodeName());
	                    if(elem.getNodeName().equals("LayoutGroup")) {
	                    	elem.setAttribute("itemType", "Groups");
	                    }else {
	                    	elem.setAttribute("itemType", "Items");
	                    }
	                    
	                    int howManyMyParentHasChildCount = 0;
	                    for (int z0 = 0; z0 < layout.getParentNode().getChildNodes().getLength(); z0++) {
	                        Node childLayout = layout.getParentNode().getChildNodes().item(z0);
	                        if (childLayout.getNodeType() == Node.ELEMENT_NODE) {
	                            howManyMyParentHasChildCount++;
	                        }
	                    }
	                    if (howManyMyParentHasChildCount == 1) {
	                        weightStr = "100";
	                    } else {
	                        weightStr = elem.getAttribute("Weight");
	                    }
	                    
	                    weight = Double.valueOf(weightStr).doubleValue();
	                    if (weightStr.indexOf("0.") == 0) {
	                        weight = weight * 100;
	                    }
	                    
	                    if ("horizontal".equals(cssClass)) {
	                        style = "height: ";
	                    } else {
	                        style = "width: ";
	                    }
	                    String anotherStyle = "";
	                    if(style.equals("width: ")) {
	//                    	anotherStyle = "height : 100%;float:left;";
	                    	anotherStyle = "height : calc(100%);float:left;";
	                    }else {
	                    	anotherStyle = "width : calc(100%);float:left;";
	                    }
	//                    elem.setAttribute("style", style + Double.toString(weight) + "%;"+anotherStyle);
	                    elem.setAttribute("style", style+"calc(" + Double.toString(weight) + "%);"+anotherStyle);
	                    
	                    elem.removeAttribute("Weight");
	                }
	            }
	            
	            /* dashboard item id setting */
	            String id;
	            JSONArray itemArr = new JSONArray();
	            NodeList dashboardItemGroup = (NodeList) xpath.evaluate("//*[@DashboardItem]", layoutDocument, XPathConstants.NODESET);
	            for(int idx = 0; idx < dashboardItemGroup.getLength(); idx++) {
	                Node layout = dashboardItemGroup.item(idx);
	                JSONObject itemObj = new JSONObject();
	                // remove Orientation attribute
	                if (layout.getNodeType() == Node.ELEMENT_NODE) {
	                    Element elem = (Element) layout;
	                    id = elem.getAttribute("DashboardItem");
	                    elem.setAttribute("id", id+"_"+reportid);
	                    elem.setAttribute("index", idx+"");
	                    elem.setAttribute("reportId", reportid+"");
	//                    System.out.println(layout.toString());
	                    itemObj.put("index", idx);
	                    itemObj.put("itemID", id);
	                    itemArr.add(itemObj);
	                    NamedNodeMap nodemap = elem.getAttributes();
	                    for(int nodeattr=0;nodeattr<nodemap.getLength();nodeattr++) {
	//                    	System.out.println(elem.toString()+"\t"+id+"\t"+nodemap.item(nodeattr).toString());
	                    }
	                    
	                    elem.removeAttribute("DashboardItem");
	                }
	            }
	            
	            DOMSource domSource = new DOMSource(layoutDocument);
	            StringWriter writer = new StringWriter();
	            StreamResult result = new StreamResult(writer);
	            TransformerFactory tf = TransformerFactory.newInstance();
	            Transformer transformer = tf.newTransformer();
	            transformer.transform(domSource, result);
	            
	            String layoutXmlString = writer.toString();
	            writer.close();
	            
	            layoutXmlString = layoutXmlString.replaceAll("<\\?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"\\?>", "");
	            layoutXmlString = layoutXmlString.replaceAll("<LayoutTree>", "");
	            layoutXmlString = layoutXmlString.replaceAll("</LayoutTree>", "");
	            layoutXmlString = layoutXmlString.replaceAll("LayoutGroup", "div");
	            layoutXmlString = layoutXmlString.replaceAll("LayoutItem", "div");
	            layoutXmlString = layoutXmlString.replaceAll("<div>", "<div class=\"no-bpm\">");
	            
	//            logger.debug("XML(layout) : " + layoutXmlString);
	            
	            layoutXmlString = layoutXmlString.replaceAll("\r", "");
	            layoutXmlString = layoutXmlString.replaceAll("\n", "");
	            
	            jsonObject.getJSONObject("Dashboard").put("LayoutTreeHtml", layoutXmlString);
	            jsonObject.getJSONObject("Dashboard").put("MapOption", mapJSON);
	            jsonObject.getJSONObject("Dashboard").put("sortedItemIdx", itemArr);
        	} catch (IOException | SAXException | ParserConfigurationException | XPathExpressionException | TransformerException e) {
        		e.printStackTrace();
        	}
        }
        
        return jsonObject;
    }
    
    public void setXmlBodyText(String xmlBodyText) {
        this.xmlBodyText = xmlBodyText;
    }
    public String getXmlBodyText() {
        return xmlBodyText;
    }
    
    public void setMapJSON(JSONObject mapJSON) {
		this.mapJSON = mapJSON;
	}
    public JSONObject getMapJSON() {
		return mapJSON;
	}

    public void readXml(int xmlReqId, String shapeFileLocation) {
        String encoding = Configurator.getInstance().getConfig("encoding");
        
        String dashboardRepositoryXmlUrl = Configurator.getInstance().getDashboardRepositoryXmlURL();
        String url = dashboardRepositoryXmlUrl + "/" + Integer.toString(xmlReqId) + ".xml";
        
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(url);
        method.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        
        logger.debug("call url : " + url);
        
        method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, new DefaultHttpMethodRetryHandler(3, false));

        BufferedReader br = null;
        
        try {
          int statusCode = client.executeMethod(method);
          switch (statusCode) {
              case HttpStatus.SC_OK:
                  logger.debug("call url success");
                  
                  String wasKind = CoreUtils.ifNull(Configurator.getInstance().getConfig("wise.was")).toUpperCase();
                  
                  if ("TOMCAT".equals(wasKind)) {
                      byte[] responseBody = method.getResponseBody();
                      this.xmlBodyText = new String(responseBody, encoding);
                  }
                  else {
                      br = new BufferedReader(new InputStreamReader(method.getResponseBodyAsStream()));
                      String readLine;
                      this.xmlBodyText = "";
                      while(((readLine = br.readLine()) != null)) {
                          this.xmlBodyText += readLine;
                      }
                  }
                  
                  boolean isBom = Configurator.getInstance().getConfigBooleanValue("wise.ds.repository.olap.xml.isBom", true);
                  if (isBom) {
                      this.xmlBodyText = this.xmlBodyText.substring(1);
                  }
                  
                  /* document */
                  String shapeDataValue;
                  String attributeDataValue;
                  String shapeFileName;
                  InputSource is = new InputSource(new StringReader(this.xmlBodyText));
                  Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
                  XPath xpath0 = XPathFactory.newInstance().newXPath();
                  
                  /* removing title vlaue */
                  NodeList TitleList = (NodeList) xpath0.evaluate("//Title", document, XPathConstants.NODESET);
                  for( int idx = 0; idx < TitleList.getLength(); idx++ ) {
                      Node title = TitleList.item(idx);
                      if (title.getNodeType() == Node.ELEMENT_NODE) {
                          ((Element) title).setTextContent("");
                          break;
                      }
                  }
                  
                  /* removing shape data */
                  ShapeFileCreator shapeFileCreator = new ShapeFileCreator();
                  NodeList shapeDataList = (NodeList) xpath0.evaluate("//Data[@ShapeData]", document, XPathConstants.NODESET);
                  for( int idx = 0; idx < shapeDataList.getLength(); idx++ ) {
                      Node shapeData = shapeDataList.item(idx);
                      
                      // remove ShapeData attribute
                      if (shapeData.getNodeType() == Node.ELEMENT_NODE) {
                          Node mapNode = shapeData.getParentNode().getParentNode();
                          shapeFileName = Integer.toString(xmlReqId) + "_" + ((Element) mapNode).getAttribute("ComponentName");
                          
                          Element elem = (Element) shapeData;
                          shapeDataValue = elem.getAttribute("ShapeData");
                          attributeDataValue = elem.getAttribute("AttributeData");
                          
                          elem.setAttribute("wiseShapeFileName", shapeFileName);
                          elem.removeAttribute("ShapeData");
                          elem.removeAttribute("AttributeData");
                          
                          // create .shp & .dbf file
                          shapeFileCreator.create(shapeFileLocation, shapeFileName, shapeDataValue, attributeDataValue);
                      }
                  }
                  
                  /* grid column ordering */
                  int gridColumnOrder = 0;
                  NodeList gridList = (NodeList) xpath0.evaluate("//Grid", document, XPathConstants.NODESET);
                  
                  for( int idx = 0; idx < gridList.getLength(); idx++ ) {
                      Node grid = gridList.item(idx);
                      XPath xpath1 = XPathFactory.newInstance().newXPath();
                      
                      NodeList gridColumnList = (NodeList) xpath1.evaluate("//GridColumns", grid, XPathConstants.NODESET);
                      
                      for( int x0 = 0; x0 < gridColumnList.getLength(); x0++ ){
                          Node gridColumn = gridColumnList.item(x0);
                          NodeList gridColumnChild = gridColumn.getChildNodes();
                          
                          gridColumnOrder = 0;
                          
                          for (int x1 = 0; x1 < gridColumnChild.getLength(); x1++) {
                              Node child = gridColumnChild.item(x1);
                              
                              if (child.getNodeType() == Node.ELEMENT_NODE) {
                                  Element elem = (Element) child;
                                  elem.setAttribute("wiseOrder", Integer.toString(gridColumnOrder));
                                  
                                  gridColumnOrder += 1;
                              }
                          }
                      }
                  }
                  
                  TransformerFactory tf = TransformerFactory.newInstance();
                  Transformer transformer = tf.newTransformer();
                  transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                  StringWriter writer = new StringWriter();
                  transformer.transform(new DOMSource(document), new StreamResult(writer));
                  
                  this.xmlBodyText = writer.getBuffer().toString().replaceAll("\n|\r", "");
                  
                  break;
              case HttpStatus.SC_NOT_FOUND:
                  throw new NotFoundReportXmlException("please check OLAP WebService URL. [called URL :: " + url + "]");
              default:
                  logger.error("call url failed");
                  String message = "xml parse error(" + statusCode + ") : " + url;
                  XmlParseException e = new XmlParseException(message);
                  e.setHttpStatusCode(statusCode);
                  throw e;
          }
        } 
//        catch (HttpException e) {
//            logger.error("", e);
//            throw e;
//        }
//        catch (IOException e) {
//            logger.error("", e);
//            throw e;
//        }
        catch(IOException | TransformerException | NotFoundReportXmlException | XmlParseException | XPathExpressionException | SAXException | ParserConfigurationException e) {
            e.printStackTrace();
//            throw new ConnectException("please check OLAP WebService Domain or Port. [called URL :: " + url + "]");
        }
        finally {
    		method.releaseConnection();
    		if (br != null) {
    			try { 
    				br.close(); 
    			} catch (IOException fe) {
    				fe.printStackTrace();
    				br = null;
    			}
    		}
    	}  
    }
}
