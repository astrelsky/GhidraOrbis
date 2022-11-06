package orbis.elf.fragment;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

import orbis.elf.OrbisElfExtension;
import orbis.elf.OrbisElfHeader;

import static ghidra.app.util.bin.format.elf.ElfDynamicType.*;

public final class DynamicFragmentBuilder extends FragmentBuilder {

	private static final int DT_PLTGOT = 3;
	private static final int DT_HASH = 4;
	private static final int DT_STRTAB = 5;
	private static final int DT_SYMTAB = 6;
	private static final int DT_RELA = 7;
	private static final int DT_STRSZ = 10;
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
			case DT_PLTGOT:
				return getGotPltSize();
			case DT_STRTAB:
				return getTableSize(DT_STRSZ);
			case DT_SYMTAB:
				return getTableSize(OrbisElfExtension.DT_SCE_SYMTABSZ);
			case DT_RELA:
				return getTableSize(DT_RELASZ);
			case DT_HASH:
				return getHashSize();
			default:
				return -1;
		}
	}
	
	private long getHashSize() {
		ElfDynamicTable dt = getHelper().getElfHeader().getDynamicTable();
		if (dt.containsDynamicValue(OrbisElfExtension.DT_SCE_HASHSZ)) {
			try {
				return dt.getDynamicValue(OrbisElfExtension.DT_SCE_HASHSZ);
			} catch (NotFoundException e) {
				// impossible
				throw new AssertException(e);
			}
		}
		// just split the block
		// easy to calculate the size but I'm lazy
		Memory mem = getHelper().getProgram().getMemory();
		Address start = getStart();
		MemoryBlock block = mem.getBlock(start);
		if (block == null) {
			return -1;
		}
		return (block.getEnd().getOffset() - start.getOffset()) + 1;
	}
	
	private long getTableSize(ElfDynamicType type) {
		return getTableSize(type.value);
	}
	
	private long getTableSize(long type) {
		ElfDynamicTable dt = getHelper().getElfHeader().getDynamicTable();
		if (!dt.containsDynamicValue(type)) {
			return -1;
		}
		try {
			return dt.getDynamicValue(type);
		} catch (NotFoundException e) {
			// impossible since we confirmed it contains it
			throw new AssertException(e);
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
			case DT_PLTGOT:
				return ".got";
			case DT_RELA:
				return ".rela.dyn";
			case DT_STRTAB:
				return ".dynstr";
			case DT_SYMTAB:
				return ".dynsym";
			case DT_HASH:
				return ".hash";
			default:
				return "";
		}
	}

	private long getGotPltSize() {
		Memory mem = getHelper().getProgram().getMemory();
		Address start = getStart();
		/*
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
		*/
		// just split the block
		MemoryBlock block = mem.getBlock(start);
		if (block == null) {
			return -1;
		}
		return (block.getEnd().getOffset() - start.getOffset()) + 1;
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
			case DT_PLTGOT:
			case DT_STRTAB:
			case DT_SYMTAB:
			case DT_RELA:
			case DT_HASH:
				return true;
			default:
				return false;
		}
	}
	
	@Override
	public void move() throws Exception {
		ElfLoadHelper helper = getHelper();
		Program program = helper.getProgram();
		Address start = getStart();
		if (start == null) {
			return;
		}
		long size = getSize();
		if (size <= 0) {
			return;
		}
		String name = getName();
		if (name.isBlank()) {
			return;
		}
		Listing listing = program.getListing();
		ProgramModule root = listing.getDefaultRootModule();
		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(start);
		if (!block.getStart().equals(start)) {
			mem.split(block, start);
			block = mem.getBlock(start);
		}
		block.setName(name);
		ProgramFragment frag = listing.getFragment(root.getTreeName(), name);
		if (frag != null) {
			return;
		}
		frag = root.createFragment(name);
		frag.move(block.getStart(), block.getEnd().subtract(1));
	}
}
