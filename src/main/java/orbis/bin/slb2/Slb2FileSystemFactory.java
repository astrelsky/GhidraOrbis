package orbis.bin.slb2;

import java.util.Arrays;

import ghidra.formats.gfilesystem.FSRL;

import orbis.bin.AbstractFileSystemFactory;

public class Slb2FileSystemFactory extends AbstractFileSystemFactory<Slb2FileSystem> {

	@Override
	public int getBytesRequired() {
		return Slb2Header.MAGIC.length();
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		byte[] data = Arrays.copyOf(startBytes, getBytesRequired());
		return Arrays.equals(data, Slb2Header.MAGIC.getBytes());
	}

}
