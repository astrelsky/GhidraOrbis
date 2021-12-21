package orbis.bin.sflash;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SflashFileSystemFactory implements GFileSystemFactoryFull<SflashFileSystem>,
		GFileSystemProbeBytesOnly {

	private static final byte[] MAGIC_DIGEST = new byte[] {
		(byte) 0x63, (byte) 0x0b, (byte) 0xd2, (byte) 0x7d,
		(byte) 0x13, (byte) 0xef, (byte) 0xf4, (byte) 0xa1,
		(byte) 0x59, (byte) 0x06, (byte) 0xeb, (byte) 0x52,
		(byte) 0xbf, (byte) 0x4e, (byte) 0xd0, (byte) 0x1f
	};

	@Override
	public int getBytesRequired() {
		return 0x20;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		MessageDigest md5;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new AssertException(e);
		}
		md5.update(Arrays.copyOf(startBytes, getBytesRequired()));
		return Arrays.equals(md5.digest(), MAGIC_DIGEST);
	}

	@Override
	public SflashFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
			ByteProvider byteProvider, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		SflashFileSystem fs = new SflashFileSystem(containerFile, targetFSRL, byteProvider);
		fs.mount(monitor);
		return fs;
	}

}
