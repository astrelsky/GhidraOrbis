package orbis.bin.sflash;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.util.NumericUtilities;
import ghidra.xml.XmlElement;

import orbis.bin.FileInfoProvider;

public class SflashEntry implements FileInfoProvider {

	private final ByteProvider provider;
	private final String name;
	private final long offset;
	private final long size;

	SflashEntry(ByteProvider provider, XmlElement e) {
		this.provider = provider;
		this.name = e.getAttribute("name");
		this.offset = NumericUtilities.parseHexLong(e.getAttribute("offset"));
		this.size = NumericUtilities.parseHexLong(e.getAttribute("size"));
	}

	@Override
	public String getFileName() {
		return name;
	}

	@Override
	public long getSize() {
		return size;
	}

	@Override
	public InputStream getInputStream() throws IOException {
		return provider.getInputStream(offset);
	}

	@Override
	public ByteProvider getByteProvider() {
		return new ByteProviderWrapper(provider, offset, getSize(), provider.getFSRL());
	}

}
