package orbis.bin.sflash;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.framework.Application;
import ghidra.util.exception.AssertException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import generic.jar.ResourceFile;
import orbis.bin.FileSystemHeader;

public final class SflashHeader implements FileSystemHeader<SflashEntry> {

	private final List<SflashEntry> entries;

	SflashHeader(ByteProvider provider) throws IOException {
		ResourceFile file = Application.findDataFileInAnyModule("sflash.xml");
		if (file == null) {
			throw new IOException("sflash.xml not found! Please check the plugin installation.");
		}
		XmlPullParser parser;
		try {
			parser = XmlPullParserFactory.create(file, new DefaultHandler(), true);
		} catch (SAXException e) {
			throw new AssertException(e);
		}
		this.entries = new ArrayList<>();
		try {
			XmlElement e = parser.start("entries");
			do {
				e = parser.next();
				entries.add(new SflashEntry(provider, e));
				e = parser.end(e);
			} while (parser.hasNext() && parser.peek().getName().equals("entry"));
		} finally {
			parser.dispose();
		}
	}

	@Override
	public Iterator<SflashEntry> iterator() {
		return entries.iterator();
	}

}
