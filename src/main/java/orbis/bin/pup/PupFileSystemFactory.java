package orbis.bin.pup;

import java.util.Arrays;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.formats.gfilesystem.FSRL;

import orbis.bin.AbstractFileSystemFactory;
import orbis.self.SelfHeader;

public class PupFileSystemFactory extends AbstractFileSystemFactory<PupFileSystem> {

	@Override
	public int getBytesRequired() {
		return PupHeader.MAGIC.length;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		byte[] data = Arrays.copyOf(startBytes, getBytesRequired());
		if (Arrays.equals(data, PupHeader.MAGIC)) {
			try (ByteArrayProvider provider = new ByteArrayProvider(startBytes)) {
				return !SelfHeader.isSelf(provider);
			} catch (Exception e) {
				// ignore
			}
		}
		return false;
	}

}
