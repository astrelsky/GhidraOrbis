package orbis.bin.sflash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.exception.AssertException;

import orbis.bin.AbstractFileSystemFactory;

public class SflashFileSystemFactory extends AbstractFileSystemFactory<SflashFileSystem> {

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

}
