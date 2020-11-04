package orbis.elf.fragment;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants;
import ghidra.program.model.address.Address;

import orbis.util.OrbisUtil;

import static ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants.*;
import static orbis.elf.OrbisElfConstants.*;

public final class ProgramHeaderFragmentBuilder extends FragmentBuilder {

	private final ElfProgramHeader phdr;
	private final String name;

	public ProgramHeaderFragmentBuilder(ElfLoadHelper helper, ElfProgramHeader phdr, int i) {
		super(helper);
		this.phdr = phdr;
		this.name = getProgramHeaderName(phdr, i);
	}

	@Override
	protected Address getStart() {
		return getHelper().getDefaultAddress(phdr.getVirtualAddress());
	}

	@Override
	protected long getSize() {
		return phdr.getMemorySize();
	}

	@Override
	protected String getName() {
		return name;
	}

	public static boolean canHandle(ElfProgramHeader phdr) {
		switch (phdr.getType()) {
			case ElfProgramHeaderConstants.PT_GNU_EH_FRAME:
			case ElfProgramHeaderConstants.PT_DYNAMIC:
				return false;
			default:
				return true;
		}
	}

	private static String getProgramHeaderName(ElfProgramHeader phdr, int i) {
		switch(phdr.getType()) {
			case PT_LOAD:
				if (phdr.isExecute()) {
					return ".text";
				}
				if (phdr.isWrite()) {
					return ".data";
				}
				return ".rodata";
			case PT_SCE_RELRO_VALUE:
				return ".data.rel.ro";
			case PT_DYNAMIC:
				return ".dynamic";
			case PT_TLS:
				return ".tdata";
			case PT_GNU_EH_FRAME:
				return ".eh_frame_hdr";
			case PT_SCE_DYNLIBDATA_VALUE:
				return OrbisUtil.SCE_SPECIAL_SECTION;
			case PT_SCE_LIBVERSION_VALUE:
				return ".libversion";
			case PT_SCE_COMMENT_VALUE:
				return ".comment";
			case PT_SCE_PROCPARAM_VALUE:
				return ".sce_process_param";
			case PT_SCE_MODULEPARAM_VALUE:
				return ".sce_module_param";
			case PT_INTERP:
				return ".interp";
			case PT_PHDR:
				return "_elfProgramHeaders";
			default:
				return "segment_"+Integer.toString(i);
		}
	}

}
