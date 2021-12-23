package orbis.bin;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.ByteProvider;

public interface FileInfoProvider {
	public String getFileName();
	public long getSize();
	public InputStream getInputStream() throws IOException;

	public ByteProvider getByteProvider();
}
