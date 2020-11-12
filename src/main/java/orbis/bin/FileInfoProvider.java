package orbis.bin;

import java.io.IOException;
import java.io.InputStream;

public interface FileInfoProvider {
	public String getFileName();
	public long getSize();
	public InputStream getInputStream() throws IOException;
}
