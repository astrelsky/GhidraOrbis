package orbis.bin.sflash;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;

public final class Partition extends SflashStructure {

	public static final Structure dataType = getDataType();

	private final long offset;
	private final long size;
	private final int flag1;
	private final int flag2;

	public Partition(BinaryReader reader) throws IOException {
		this.offset = reader.readNextUnsignedInt();
		this.size = reader.readNextUnsignedInt();
		this.flag1 = reader.readNextUnsignedByte();
		this.flag2 = reader.readNextUnsignedByte();
	}

	private static Structure getDataType() {
		Structure struct = new StructureDataType(PATH, "partition_t", 0);
		struct.add(DWordDataType.dataType, "offset", null);
		struct.add(DWordDataType.dataType, "size", null);
		struct.add(ByteDataType.dataType, "flag1", null);
		struct.add(ByteDataType.dataType, "flag2", null);
		struct.add(WordDataType.dataType, "unknown", null);
		struct.setToMachineAligned();
		return struct;
	}

	/**
	 * @return the offset
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * @return the size
	 */
	public long getSize() {
		return size;
	}

	/**
	 * @return the flag1
	 */
	public int getFlag1() {
		return flag1;
	}

	/**
	 * @return the flag2
	 */
	public int getFlag2() {
		return flag2;
	}
}
