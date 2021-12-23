package orbis.bin.pup;

import java.io.*;
import java.util.zip.InflaterInputStream;

import ghidra.app.util.bin.*;

import orbis.bin.FileInfoProvider;

final class PupBlob implements FileInfoProvider {

	private static final int COMPRESSED_MASK = 0x8;
	private static final int BLOCKED_MASK = 0x800;
	private static final int SPECIAL1_MASK = 0xE0000000;
	private static final int SPECIAL2_MASK = 0xF0000000;

	private final BinaryReader reader;
	private final long flags;
	private final long offset;
	private final long fileSize;
	private final long memorySize;

	PupBlob(BinaryReader reader) throws IOException {
		this.reader = reader;
		this.flags = reader.readNextLong();
		this.offset = reader.readNextLong();
		this.fileSize = reader.readNextLong();
		this.memorySize = reader.readNextLong();
	}

	long getID() {
		return flags >> 20;
	}

	long getOffset() {
		return offset;
	}

	long getFileSize() {
		return fileSize;
	}

	@Override
	public long getSize() {
		return memorySize;
	}

	boolean isCompressed() {
		return (flags & COMPRESSED_MASK) == COMPRESSED_MASK;
	}

	boolean isBlocked() {
		return (flags & BLOCKED_MASK) == BLOCKED_MASK;
	}

	boolean isSpecial() {
		long v = flags & SPECIAL2_MASK;
		return v == SPECIAL1_MASK || v == SPECIAL2_MASK;
	}

	byte[] getData() throws IOException {
		byte[] data = reader.readByteArray(offset, (int) fileSize);

		return data;
	}

	@Override
	public InputStream getInputStream() throws IOException {
		InputStream is = reader.getByteProvider().getInputStream(offset);
		if (isCompressed()) {
			is = new InflaterInputStream(is);
		}
		return is;
	}

	@Override
	public ByteProvider getByteProvider() {
		try {
			return new InputStreamByteProvider(getInputStream(), getSize());
		} catch (IOException e) {
			throw shh(e);
		}
	}

	private static <E extends Throwable> RuntimeException shh(E t) {
		return (RuntimeException)t;
	}

	@Override
	public String getFileName() {
		switch ((int) getID()) {
			case 0x1  :
				return "emc_ipl.slb";
            case 0x2  :
				return "eap_kbl.slb";
            case 0x3  :
				return "torus2_fw.slb";
            case 0x4  :
				return "sam_ipl.slb";
            case 0x5  :
				return "coreos.slb";
            case 0x6  :
				return "system_exfat.img";
            case 0x7  :
				return "eap_kernel.slb";
            case 0x8  :
				return "eap_vsh_fat16.img";
            case 0x9  :
				return "preinst_fat32.img";
            case 0xB  :
				return "preinst2_fat32.img";
            case 0xC  :
				return "system_ex_exfat.img";
            case 0xD  :
				return "emc_ipl.slb";
            case 0xE  :
				return "eap_kbl.slb";
            case 0x20 :
				return "emc_ipl.slb";
            case 0x21 :
				return "eap_kbl.slb";
            case 0x22 :
				return "torus2_fw.slb";
            case 0x23 :
				return "sam_ipl.slb";
            case 0x24 :
				return "emc_ipl.slb";
            case 0x25 :
				return "eap_kbl.slb";
            case 0x26 :
				return "sam_ipl.slb";
            case 0x27 :
				return "sam_ipl.slb";
            case 0x28 :
				return "emc_ipl.slb";
            case 0x2A :
				return "emc_ipl.slb";
            case 0x2B :
				return "eap_kbl.slb";
            case 0x2C :
				return "emc_ipl.slb";
            case 0x2D :
				return "sam_ipl.slb";
            case 0x2E :
				return "emc_ipl.slb";
            case 0x30 :
				return "torus2_fw.bin";
            case 0x31 :
				return "sam_ipl.slb";
            case 0x32 :
				return "sam_ipl.slb";
            case 0x101:
				return "eula.xml";
            case 0x200:
				return "orbis_swu.elf";
            case 0x202:
				return "orbis_swu.self";
            case 0xD01:
				return "bd_firm.slb";
            case 0xD02:
				return "sata_bridge_fw.slb";
            case 0xD09:
				return "cp_fw_kernel.slb";
			default:
				return "";
		}
	}
}
