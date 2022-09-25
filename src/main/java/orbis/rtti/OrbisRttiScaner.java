package orbis.rtti;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;

import cppclassanalyzer.scanner.ItaniumAbiRttiScanner;
import orbis.nid.OrbisNidGenerator;

public final class OrbisRttiScaner extends ItaniumAbiRttiScanner {

	private static final Map<String, TypeInfoConstructor> COPY_MAP = getCopyMap();

	private final OrbisNidGenerator obfuscator;

	public OrbisRttiScaner(Program program) {
		super(program);
		this.obfuscator = new OrbisNidGenerator();
	}

	@Override
	protected String getDynamicSymbol(String symbol) {
		return obfuscator.obfuscate(symbol);
	}

	@Override
	protected String getDynamicSymbol(Relocation relocation) {
		return obfuscator.trimObfuscatedSymbol(relocation.getSymbolName());
	}

	@Override
	public TypeInfo getTypeInfo(Address address) {
		Program program = getProgram();
		Relocation reloc = getRelocation(address);
		if (reloc == null) {
			return super.getTypeInfo(address);
		}
		String symbol = getDynamicSymbol(reloc);
		if (symbol == null || !COPY_MAP.containsKey(symbol)) {
			return super.getTypeInfo(address);
		}
		return COPY_MAP.get(symbol).getType(program, address);
	}

	@Override
	public boolean isTypeInfo(Address address) {
		Relocation reloc = getRelocation(address);
		if (reloc == null) {
			return super.isTypeInfo(address);
		}
		String symbol = getDynamicSymbol(reloc);
		if (symbol == null || !COPY_MAP.containsKey(symbol)) {
			return super.isTypeInfo(address);
		}
		return true;
	}
	
	private Relocation getRelocation(Address address) {
		List<Relocation> relocs = getProgram().getRelocationTable().getRelocations(address);
		if (relocs.isEmpty()) {
			return null;
		}
		return relocs.get(0);
	}

	private static Map<String, TypeInfoConstructor> getCopyMap() {
		Map<String, TypeInfoConstructor> copyMap = new HashMap<>();
		copyMap.put("byV+FWlAnB4", ClassTypeInfoModel::new);
		copyMap.put("749AEdSd4Go", TypeInfoModel::new);
		copyMap.put("pZ9WXcClPO8", SiClassTypeInfoModel::new);
		copyMap.put("9ByRMdo7ywg", VmiClassTypeInfoModel::new);
		copyMap.put("aMQhMoYipk4", ArrayTypeInfoModel::new);
		copyMap.put("fjni7nkqJ4M", EnumTypeInfoModel::new);
		copyMap.put("CSEjkTYt5dw", FunctionTypeInfoModel::new);
		copyMap.put("G4XM-SS1wxE", FundamentalTypeInfoModel::new);
		copyMap.put("7EirbE7st4E", PBaseTypeInfoModel::new);
		copyMap.put("2H51caHZU0Y", PointerToMemberTypeInfoModel::new);
		copyMap.put("aeHxLWwq0gQ", PointerTypeInfoModel::new);
		copyMap.put("+49o3lmIdBo", IosFailTypeInfoModel::new);
		return copyMap;
	}

	@FunctionalInterface
	private static interface TypeInfoConstructor {

		public TypeInfo getType(Program program, Address address);
	}

}
