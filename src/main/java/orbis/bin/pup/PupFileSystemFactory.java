package orbis.bin.pup;

import java.io.*;
import java.util.Arrays;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PupFileSystemFactory implements GFileSystemFactoryFull<PupFileSystem>,
		GFileSystemProbeBytesOnly {

	@Override
	public int getBytesRequired() {
		return PupHeader.MAGIC.length;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		byte[] data = Arrays.copyOf(startBytes, getBytesRequired());
		return Arrays.equals(data, PupHeader.MAGIC);
	}

	@Override
	public PupFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
			ByteProvider byteProvider, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		PupFileSystem fs = new PupFileSystem(containerFile, targetFSRL, byteProvider);
		fs.mount(monitor);
		return fs;
	}

}
