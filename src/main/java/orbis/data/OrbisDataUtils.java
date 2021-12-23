package orbis.data;

import ghidra.program.model.data.*;

public final class OrbisDataUtils {

	public static final CategoryPath PATH = new CategoryPath(CategoryPath.ROOT, "orbis");
	public static final Structure procParamDataType = buildProcParamDataType();
	public static final Structure moduleParamDataType = buildModuleParamDataType();

	private OrbisDataUtils() {
	}

	private static Structure buildProcParamDataType() {
		StructureDataType struct = new StructureDataType(OrbisDataUtils.PATH, "Sce_Proc_Param", 0);
		struct.add(QWordDataType.dataType, "p_size", null);
		ArrayDataType array = new ArrayDataType(CharDataType.dataType, 4, 1);
		struct.add(array, "p_magic", null);
		struct.add(DWordDataType.dataType, "p_ent_count", null);
		struct.add(DWordDataType.dataType, "p_sdk_ver", null);
		array = new ArrayDataType(QWordDataType.dataType, 4, QWordDataType.dataType.getLength());
		struct.add(array, "p_unknown", null);
		array = new ArrayDataType(PointerDataType.dataType, 0, PointerDataType.dataType.getLength());
		struct.add(array, "entries", null);
		struct.setToMachineAligned();
		return struct;
	}

	private static Structure buildModuleParamDataType() {
		StructureDataType struct =
			new StructureDataType(OrbisDataUtils.PATH, "Sce_Module_Param", 0);
		struct.add(QWordDataType.dataType, "p_size", null);
		struct.add(QWordDataType.dataType, "p_magic", null);
		struct.add(DWordDataType.dataType, "p_sdk_ver", null);
		struct.setToMachineAligned();
		return struct;
	}
}
