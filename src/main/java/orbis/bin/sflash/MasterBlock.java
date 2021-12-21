package orbis.bin.sflash;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;

public final class MasterBlock extends SflashStructure {

	private static final int COPYRIGHT_LENGTH = 0x20;
	private static final int MAX_PARTITIONS = 16;
	public static final Structure dataType = getDataType();

	private final long version;
	private final long size;
	private final long flag1;
	private final long flag2;
	private final Partition[] partitions;

	public MasterBlock(BinaryReader reader) throws IOException {
		PartitionLimiter limiter = new PartitionLimiter(reader);
		advanceReader(reader, COPYRIGHT_LENGTH);
		this.version = reader.readNextUnsignedInt();
		this.size = reader.readNextUnsignedInt();
		advanceReader(reader, 0x8);
		this.flag1 = reader.readNextUnsignedInt();
		this.flag2 = reader.readNextUnsignedInt();
		advanceReader(reader, 0x8);
		this.partitions = new Partition[MAX_PARTITIONS];
		for (int i = 0; limiter.getSize() < size && i < MAX_PARTITIONS; i++) {
			this.partitions[i] = new Partition(reader);
		}
	}

	private static Structure getDataType() {
		Structure struct = new StructureDataType(PATH, "master_block_t", 0);
		DataType string = new ArrayDataType(CharDataType.dataType, COPYRIGHT_LENGTH, 1);
		struct.add(string, "copyright", null);
		struct.add(DWordDataType.dataType, "version", null);
		struct.add(DWordDataType.dataType, "total_size", null);
		struct.add(DWordDataType.dataType, "flag1", null);
		struct.add(DWordDataType.dataType, "flag2", null);
		DataType dt = Partition.dataType;
		DataType partitions = new ArrayDataType(dt, MAX_PARTITIONS, dt.getLength());
		struct.add(partitions, "partitions", null);
		struct.setToMachineAligned();
		return struct;
	}

	private static class PartitionLimiter {
		final BinaryReader reader;
		final long start;

		PartitionLimiter(BinaryReader reader) {
			this.reader = reader;
			this.start = reader.getPointerIndex();
		}

		long getSize() {
			return reader.getPointerIndex() - start;
		}
	}

	/**
	 * @return the version
	 */
	public long getVersion() {
		return version;
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
	public long getFlag1() {
		return flag1;
	}

	/**
	 * @return the flag2
	 */
	public long getFlag2() {
		return flag2;
	}

	/**
	 * @return the partitions
	 */
	public Partition[] getPartitions() {
		return partitions;
	}
}
