package orbis.elf.fragment;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

import orbis.elf.OrbisElfHeader;

import static ghidra.app.util.bin.format.elf.ElfDynamicType.*;

public final class DynamicFragmentBuilder extends FragmentBuilder {

	private static final int DT_INIT_ARRAY_VALUE = 25;
	private static final int DT_FINI_ARRAY_VALUE = 26;
	private static final int DT_SCE_PLTGOT_VALUE = 0x61000027;
	private static final int DT_PREINIT_ARRAY_VALUE = 32;

	private final ElfDynamic dynamic;

	public DynamicFragmentBuilder(ElfLoadHelper helper, ElfDynamic dynamic) {
		super(helper);
		this.dynamic = dynamic;
	}

	@Override
	protected Address getStart() {
		ElfLoadHelper helper = getHelper();
		OrbisElfHeader elf = (OrbisElfHeader) helper.getElfHeader();
		long offset = elf.getDynamicAddrOffset(dynamic.getValue());
		return helper.getDefaultAddress(offset);
	}

	@Override
	protected long getSize() {
		switch((int) dynamic.getTag()) {
			case DT_INIT_ARRAY_VALUE:
				return getArraySize(DT_INIT_ARRAYSZ);
			case DT_FINI_ARRAY_VALUE:
				return getArraySize(DT_FINI_ARRAYSZ);
			case DT_PREINIT_ARRAY_VALUE:
				return getArraySize(DT_PREINIT_ARRAYSZ);
			case DT_SCE_PLTGOT_VALUE:
				return getGotPltSize();
			default:
				return -1;
		}
	}

	@Override
	protected String getName() {
		switch((int) dynamic.getTag()) {
			case DT_INIT_ARRAY_VALUE:
				return ".init_array";
			case DT_FINI_ARRAY_VALUE:
				return ".fini_array";
			case DT_PREINIT_ARRAY_VALUE:
				return ".preinit_array";
			case DT_SCE_PLTGOT_VALUE:
				return ".got.plt";
			default:
				return "";
		}
	}

	private long getGotPltSize() {
		Memory mem = getHelper().getProgram().getMemory();
		Address start = getStart();
		MemoryBufferImpl buf = new MemoryBufferImpl(mem, start);
		try {
			while (buf.getLong(0) == 0) {
				buf.advance(Long.BYTES);
			}
			while (buf.getLong(0) != 0) {
				buf.advance(Long.BYTES);
			}
			return buf.getAddress().subtract(start) - Long.BYTES;
		} catch (Exception e) {
			return -1;
		}
	}

	private long getArraySize(ElfDynamicType type) {
		try {
			ElfDynamicTable table = getHelper().getElfHeader().getDynamicTable();
			return table.getDynamicValue(type);
		} catch (NotFoundException e) {
			// impossible situation
			getHelper().getLog().appendException(e);
			throw new AssertException(e);
		}
	}

	public static boolean canHandle(ElfDynamicType type) {
		switch (type.value) {
			case DT_INIT_ARRAY_VALUE:
			case DT_FINI_ARRAY_VALUE:
			case DT_PREINIT_ARRAY_VALUE:
			case DT_SCE_PLTGOT_VALUE:
				return true;
			default:
				return false;
		}
	}
}
