package orbis.self;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;

public final class SelfHeader {

	private static final byte[] MAGIC = new byte[] {
		(byte) 0x4F, (byte) 0x15, (byte) 0x3D, (byte) 0x1D
	};

	private final int version;
	private final int mode;
	private final int endian;
	private final int attributes;
	private final SelfExtendedHeader extendedHeader;
	private final long elfHeaderOffset;

	public SelfHeader(ByteProvider provider) throws IOException, EncryptedSelfException {
		BinaryReader reader = new BinaryReader(provider, true);
		skipBytes(reader, MAGIC.length);
		this.version = reader.readNextUnsignedByte();
		this.mode = reader.readNextUnsignedByte();
		this.endian = reader.readNextUnsignedByte();
		this.attributes = reader.readNextUnsignedByte();
		this.extendedHeader = new SelfExtendedHeader(reader);
		this.elfHeaderOffset = reader.getPointerIndex();
	}

	private static void skipBytes(BinaryReader reader, int n) {
		reader.setPointerIndex(reader.getPointerIndex() + n);
	}

	public static boolean isSelf(ByteProvider provider) throws IOException {
		byte[] magic = provider.readBytes(0, MAGIC.length);
		return Arrays.equals(magic, MAGIC);
	}

	/**
	 * @return the version
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * @return the mode
	 */
	public int getMode() {
		return mode;
	}

	/**
	 * @return the endian
	 */
	public int getEndian() {
		return endian;
	}

	/**
	 * @return the attributes
	 */
	public int getAttributes() {
		return attributes;
	}

	/**
	 * @return the extendedHeader
	 */
	public SelfExtendedHeader getExtendedHeader() {
		return extendedHeader;
	}

	public ByteProvider getElfHeaderByteProvider() throws IOException {
		return extendedHeader.getEntry().getElfHeaderByteProvider();
	}

	public ElfHeader buildElfHeader() throws IOException, ElfException {
		return buildElfHeader(RethrowContinuesFactory.INSTANCE);
	}

	public ElfHeader buildElfHeader(MessageLog log) throws IOException, ElfException {
		GenericFactory factory = MessageLogContinuesFactory.create(log);
		return buildElfHeader(factory);
	}

	private ElfHeader buildElfHeader(GenericFactory factory) throws IOException, ElfException {
		BinaryReader reader = extendedHeader.getReader();
		ByteProvider provider = new ByteProviderWrapper(
			reader.getByteProvider(), elfHeaderOffset, extendedHeader.getFileSize());
		ElfHeader header = ElfHeader.createElfHeader(factory, provider);
		for (SelfEntry entry : extendedHeader) {
			FactoryBundledWithBinaryReader bundle = new FactoryBundledWithBinaryReader(
				factory, entry.getElfHeaderByteProvider(), true);
			ElfProgramHeader progHeader = SelfProgramHeader.createElfProgramHeader(bundle, header);
			header.addProgramHeader(progHeader);
		}
		return header;
	}

	private static class SelfProgramHeader extends ElfProgramHeader {

		@SuppressWarnings("unused")
		public SelfProgramHeader() {
		}

		static ElfProgramHeader createElfProgramHeader(FactoryBundledWithBinaryReader reader,
				ElfHeader header) throws IOException {
			SelfProgramHeader elfProgramHeader =
				(SelfProgramHeader) reader.getFactory().create(SelfProgramHeader.class);
			elfProgramHeader.initElfProgramHeader(reader, header);
			return elfProgramHeader;
		}
	}
}
