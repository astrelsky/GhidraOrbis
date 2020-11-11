package orbis.bin.slb2;

import java.io.*;
import java.util.Arrays;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeWithFile;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Slb2FileSystemFactory implements GFileSystemFactoryFull<Slb2FileSystem>,
		GFileSystemProbeBytesOnly, GFileSystemProbeWithFile {

	@Override
	public boolean probe(FSRL containerFSRL, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		try (InputStream is = new FileInputStream(containerFile)) {
			byte[] startBytes = new byte[getBytesRequired()];
			if (is.read(startBytes) == startBytes.length) {
				return probeStartBytes(null, startBytes);
			}
		}
		return false;
	}

	@Override
	public int getBytesRequired() {
		return Slb2Header.MAGIC.length();
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return Arrays.equals(startBytes, Slb2Header.MAGIC.getBytes());
	}

	@Override
	public Slb2FileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
			ByteProvider byteProvider, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		Slb2FileSystem fs = new Slb2FileSystem(containerFile, targetFSRL, byteProvider);
		fs.mount(monitor);
		return fs;
	}
}
