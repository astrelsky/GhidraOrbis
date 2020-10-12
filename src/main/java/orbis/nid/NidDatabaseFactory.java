package orbis.nid;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import ghidra.framework.Application;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

import org.xml.sax.helpers.DefaultHandler;

import generic.jar.ResourceFile;

public class NidDatabaseFactory {

    private NidDatabaseFactory() {
    }

    public static Map<String, String> getNidDatabase() throws Exception {
		ResourceFile file = Application.findDataFileInAnyModule("nid_db.xml");
		XmlPullParser parser = XmlPullParserFactory.create(file, new DefaultHandler(), true);
		try {
			XmlElement header = parser.next();
			if (header.getName().equals("DynlibDatabase")) {
				Map<String, String> result = new HashMap<>();
				while (parser.hasNext()) {
					XmlElement e = parser.next();
					result.put(e.getAttribute("obf"), e.getAttribute("sym"));
				}
				return result;
			}
			return Collections.emptyMap();
		} finally {
			parser.dispose();
		}
    }

}
