package orbis.bin.pup;

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;

import orbis.bin.AbstractFileSystem;
import orbis.bin.FileSystemHeader;

@FileSystemInfo(type = "pup", description = "Update Package", priority = FileSystemInfo.PRIORITY_LOW, factory = PupFileSystemFactory.class)
public class PupFileSystem extends AbstractFileSystem<PupBlob> {

	PupFileSystem(File file, FSRLRoot fsrl, ByteProvider provider) {
		super(file, fsrl, provider);
	}

	@Override
	protected FileSystemHeader<PupBlob> getHeader() throws IOException {
		return new PupHeader(getProvider());
	}
	
}
