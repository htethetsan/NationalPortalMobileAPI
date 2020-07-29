package com.portal.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.TextNode;
import org.jsoup.parser.Parser;
import org.jsoup.select.Elements;
import org.springframework.stereotype.Service;

import ch.qos.logback.classic.Logger;

@Service
public class AbstractController {

	public String getMyanmarElement(String content, String element, String remover) {
		int begin = content.indexOf(element);
		content = content.substring(begin, content.length());
		int end = content.indexOf("</dynamic-content>");
		String remainString = content.substring(end, content.length());

		int mStart = remainString.indexOf(remover);
		if (mStart > 0) {
			int mEnd = remainString.indexOf("]]");
			if (!remainString.isEmpty() && mEnd > 0)
				return Jsoup.parse(remainString.substring(mStart, mEnd)).text();
		}
		return "";
	}

	public String getEngElement(String content, String element, String remover) {
		int begin = content.indexOf(element);
		String remainString = content.substring(begin, content.length());
		int mStart = remainString.indexOf(remover);
		if (mStart > 0) {
			int mEnd = remainString.indexOf("]]");
			if (!remainString.isEmpty() && mEnd > 0)
				return Jsoup.parse(remainString.substring(mStart, mEnd)).text();
		}
		return "";
	}

	public String ImageSourceChange(String htmlinput) {

		Document docimage = Jsoup.parse(htmlinput, "", Parser.htmlParser());
		Elements images = docimage.getElementsByTag("img");
		if (images.size() > 0) {
			for (Element img : images) {
				String imgsrc = img.attr("src");

				// System.out.println("source image...." + imgsrc);
				String imgreplace = "https://myanmar.gov.mm" + imgsrc;
				img.attr("src", imgreplace);
			}
		}
		return docimage.html();
	}
	
	public String ImageSourceChangeforanouncement(String htmlinput) {

		Document docimage = Jsoup.parse(htmlinput, "", Parser.htmlParser());
		Elements images = docimage.getElementsByTag("img");
		String imgreplace;
		if (images.size() > 0) {
			for (Element img : images) {
				String imgsrc = img.attr("src");
				if(img.attr("src").contains("data:image/jpeg;")) {
					imgreplace =imgsrc;
				}else if(img.attr("src").contains("https://")) {
					imgreplace =imgsrc;
				}else {
					imgreplace = "https://myanmar.gov.mm" + imgsrc;
				}
				// System.out.println("source image...." + imgsrc);
				img.attr("src", imgreplace);
			}
		}
		return docimage.html();
	}

	public void replaceTag(Elements els) {
		ListIterator<Element> iter = els.listIterator();
		while (iter.hasNext()) {
			Element el = iter.next();
			replaceTag(el.children());
			if (el.parentNode() != null)
				el.replaceWith(new TextNode("/" + el.text().trim() + "/"));
		}
	}

	public List<String> removeInvalidString(String[] titleArr) {
		List<String> titleList = new ArrayList<String>();
		for (String title : titleArr) {
			if (title != null && !title.isEmpty() && title.length() > 1)
				titleList.add(title);
		}
		return titleList;
	}

	public List<String> removeDelimeterFrom(String str) {
		Document doc = Jsoup.parse(str);
		replaceTag(doc.children());
		String[] infos = Jsoup.parse(doc.toString()).text().split("/");
		return removeInvalidString(infos);
	}

	public String getImage(String content) {
		int start = content.indexOf("/image/");
		if (start < 0)
			return "";
		String remainString = content.substring(start, content.length());
		int end = remainString.indexOf("<");
		return remainString.substring(0, end).startsWith("/") ? "https://myanmar.gov.mm" + remainString.substring(0, end) : remainString.substring(0, end);
	}

	public String getDocumentImage(String content) {
		int start = content.indexOf("/document");
		if (start < 0)
			return "";
		String remainString = content.substring(start, content.length());
		int end = remainString.indexOf("]]");
		return remainString.substring(0, end).startsWith("/") ? "https://myanmar.gov.mm" + remainString.substring(0, end) : remainString.substring(0, end);
	}
	
	public String getHttpImage(String content) {
		int start = content.indexOf("http");
		if (start < 0)
			return "";
		String remainString = content.substring(start, content.length());
		int end = remainString.indexOf("]]");
		return remainString.substring(0, end).startsWith("/") ? "https://myanmar.gov.mm" + remainString.substring(0, end) : remainString.substring(0, end);
	}
	
	public String getHttpImage2(String content) {
		int start = content.indexOf("http");
		if (start < 0)
			return "";
		String remainString = content.substring(start, content.length());
		int end = remainString.indexOf("\"");
		return remainString.substring(0, end).startsWith("/") ? "https://myanmar.gov.mm" + remainString.substring(0, end) : remainString.substring(0, end);
	}

	public String convertEntryListToString(List<String> entryList, String input) {
		int index = Integer.parseInt(input);
		int lastIndex = (entryList.size() - 1) - (index * 10 - 10);
		int substract = lastIndex < 9 ? lastIndex : 9;
		int startIndex = lastIndex - substract;

		String info = "";
		for (int i = startIndex; i <= lastIndex; i++)
			info += entryList.get(i) + ",";
		return info;
	}

	public String getMyanamrContent(String content) {
		int begin = content.indexOf("\"text_area\"");
		content = content.substring(begin, content.length());
		int end = content.indexOf("</dynamic-content>");
		String remainString = content.substring(end, content.length());

		int mStart = remainString.indexOf("<dynamic-content language-id=\"my_MM\">");
		if (mStart > 0) {
			int mEnd = remainString.lastIndexOf("</dynamic-content>");
			return Jsoup.parse(remainString.substring(mStart, mEnd)).text().replaceAll("value 1", "");
		}
		return "";
	}

	public String getEngContent(String content) {
		int begin = content.indexOf("\"text_area\"");
		if (begin < 0)
			return "";
		content = content.substring(begin, content.length());

		int start = content.indexOf("<dynamic-content language-id=\"en_US\">");
		int end = content.indexOf("</dynamic-content>");

		if (start < 0 || end < 0)
			return "";
		return Jsoup.parse(content.substring(start, end)).text().replaceAll("value 1", "");
	}

	public List<Object> bySize(List<Object> entryList, String input) {
		int index = Integer.parseInt(input);
		int lastIndex = (entryList.size() - 1) - (index * 10 - 10);
		int substract = lastIndex < 9 ? lastIndex : 9;
		int startIndex = lastIndex - substract;

		List<Object> objectList = new ArrayList<Object>();
		for (int i = startIndex; i <= lastIndex; i++)
			objectList.add(entryList.get(i));
		return objectList;
	}
}
