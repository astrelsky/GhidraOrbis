package orbis.self;

import java.io.*;
import java.nio.file.AccessMode;
import java.util.Arrays;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

import orbis.elf.OrbisElfHeader;

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
		BinaryReader reader = extendedHeader.getReader();
		return new ByteProviderWrapper(
			reader.getByteProvider(), elfHeaderOffset,
			extendedHeader.getFileSize() - elfHeaderOffset);
	}

	public OrbisElfHeader buildElfHeader() throws IOException, ElfException {
		return new OrbisElfHeader(getElfHeaderByteProvider(), msg -> Msg.info(this, msg));
	}

	public OrbisElfHeader buildElfHeader(MessageLog log) throws IOException, ElfException {
		return new OrbisElfHeader(getElfHeaderByteProvider(), log::appendMsg);
	}

	public ByteProvider getElfByteProvider() throws IOException {
		OrbisElfHeader elf = null;
		try {
			elf = buildElfHeader();
		} catch (ElfException e) {
			throw new AssertException(e);
		}
		BinaryReader elfReader = new BinaryReader(getElfHeaderByteProvider(), true);
		String name = getByteProvider().getName();
		File file = File.createTempFile(name, null);
		file.deleteOnExit();
		try (DataWriter writer = new DataWriter(file)) {

			// write the ehdr and phdr table
			writer.write(elfReader.readNextByteArray(elf.e_ehsize()));
			int size = elf.getProgramHeaderCount() * elf.e_phentsize();
			writer.seek(elf.e_phoff());
			writer.write(elfReader.readNextByteArray(size));

			// clear the section header table
			writer.seek(0x3c);
			writer.write(new byte[]{0, 0});

			// write the program headers
			for (ElfProgramHeader phdr : elf.getRawProgramHeaders()) {
				for (SelfSegment entry : extendedHeader) {
					if (phdr.getFileSize() == entry.getFileSize()) {
						writer.seek(phdr.getOffset());
						writer.write(entry.getInputStream());
					}
				}
			}
		}
		return new TempRandomAccessByteProvider(file);
	}

	private BinaryReader getReader() {
		return extendedHeader.getReader();
	}

	private ByteProvider getByteProvider() {
		return getReader().getByteProvider();
	}

	private static class DataWriter implements AutoCloseable {

		private final RandomAccessFile f;

		DataWriter(File f) throws FileNotFoundException {
			this.f = new RandomAccessFile(f, "rw");
		}

		void seek(long pos) throws IOException {
			f.seek(pos);
		}

		private void write(InputStream is) throws IOException {
			is.transferTo(new FileOutputStream(f.getFD()));
		}

		private void write(byte[] data) throws IOException {
			f.write(data);
		}

		@Override
		public void close() throws IOException {
			f.close();
		}

	}

	private static class TempRandomAccessByteProvider extends FileByteProvider {

		TempRandomAccessByteProvider(File f) throws IOException {
			super(f, null, AccessMode.READ);
		}

		@Override
		public void close() throws IOException {
			super.close();
			File f = getFile();
			f.delete();
		}
	}

}
