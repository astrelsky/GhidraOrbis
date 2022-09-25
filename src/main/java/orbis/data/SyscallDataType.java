package orbis.data;

import ghidra.program.model.data.*;

public final class SyscallDataType {

	public static final DataType dataType = buildDataType();

	private static DataType buildDataType() {
		StructureDataType struct = new StructureDataType(OrbisDataUtils.PATH, "Syscall", 0);
		struct.add(DWordDataType.dataType, "narg", null);
		struct.add(PointerDataType.dataType, "function", null);
		struct.add(WordDataType.dataType, "auevent", null);
		struct.add(PointerDataType.dataType, "trace_args_func", null);
		struct.add(DWordDataType.dataType, "entry", null);
		struct.add(DWordDataType.dataType, "return", null);
		struct.add(DWordDataType.dataType, "flags", null);
		struct.add(DWordDataType.dataType, "thrcnt", null);
		struct.setToMachineAligned();
		struct.setToDefaultPacking();
		return struct;
	}
}
