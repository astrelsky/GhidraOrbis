package orbis.bin.slb2;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.RefdByteProvider;
import ghidra.program.model.data.*;

import orbis.bin.FileInfoProvider;

public final class Slb2Entry extends Slb2Structure implements FileInfoProvider {

	private static final int MAX_FILENAME_LENGTH = 32;
	private static final int BLOCK_SIZE = 512;
	public static final Structure dataType = getDataType();

	private final RefdByteProvider provider;
	private final long blockIndex;
	private final long fileSize;
	private final String fileName;

	public Slb2Entry(BinaryReader reader) throws IOException {
		this.provider = (RefdByteProvider) reader.getByteProvider();
		this.blockIndex = reader.readNextUnsignedInt();
		this.fileSize = reader.readNextUnsignedInt();
		advanceReader(reader, Integer.BYTES * 2);
		this.fileName = reader.readNextAsciiString(MAX_FILENAME_LENGTH).replaceAll("\0", "");
	}

	private static Structure getDataType() {
		Structure struct = new StructureDataType(PATH, "slb2_entry", 0);
		DataType string = new ArrayDataType(CharDataType.dataType, 32, 1);
		struct.add(DWordDataType.dataType, "block_offset", null);
		struct.add(DWordDataType.dataType, "file_size", null);
		struct.add(string, "file_name", null);
		struct.setToMachineAligned();
		return struct;
	}

	/**
	 * @return the blockOffset
	 */
	public long getBlockIndex() {
		return blockIndex;
	}

	private long getStartIndex() {
		return BLOCK_SIZE * blockIndex;
	}

	@Override
	public long getSize() {
		return fileSize;
	}

	@Override
	public String getFileName() {
		return fileName;
	}

	@Override
	public ByteProvider getByteProvider() {
		return new ByteProviderWrapper(provider, getStartIndex(), getSize(), provider.getFSRL());
	}

	@Override
	public InputStream getInputStream() throws IOException {
		return provider.getInputStream(getStartIndex());
	}
}
