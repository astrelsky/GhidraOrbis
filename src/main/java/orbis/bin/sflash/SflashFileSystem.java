package orbis.bin.sflash;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;

import orbis.bin.AbstractFileSystem;
import orbis.bin.FileSystemHeader;

@FileSystemInfo(type = "sflash", description = "Orbis SFLASH", priority = FileSystemInfo.PRIORITY_LOW, factory = SflashFileSystemFactory.class)
public class SflashFileSystem extends AbstractFileSystem<SflashEntry> {

	public SflashFileSystem(FSRLRoot fsrl, ByteProvider provider) {
		super(fsrl, provider);
	}

	@Override
	protected FileSystemHeader<SflashEntry> getHeader() throws IOException {
		return new SflashHeader(getProvider());
	}

}
