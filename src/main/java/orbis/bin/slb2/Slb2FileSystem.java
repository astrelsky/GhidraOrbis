package orbis.bin.slb2;

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;

import orbis.bin.AbstractFileSystem;
import orbis.bin.FileSystemHeader;

@FileSystemInfo(type = "slb2", description = "SLB2 Container", priority = FileSystemInfo.PRIORITY_LOW, factory = Slb2FileSystemFactory.class)
public class Slb2FileSystem extends AbstractFileSystem<Slb2Entry> {

	Slb2FileSystem(File file, FSRLRoot fsrl, ByteProvider provider) {
		super(file, fsrl, provider);
	}

	@Override
	protected FileSystemHeader<Slb2Entry> getHeader() throws IOException {
		return new Slb2Header(new BinaryReader(getProvider(), true));
	}
	
}
