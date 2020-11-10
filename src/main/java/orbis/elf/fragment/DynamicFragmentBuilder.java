package orbis.elf.fragment;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

import orbis.elf.OrbisElfHeader;

import static ghidra.app.util.bin.format.elf.ElfDynamicType.*;

public final class DynamicFragmentBuilder extends FragmentBuilder {

	private static final int DT_INIT_VALUE = 12;
	private static final int DT_FINI_VALUE = 13;
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
			case DT_INIT_VALUE:
			case DT_FINI_VALUE:
				return getFunctionSize();
			case DT_INIT_ARRAY_VALUE:
				return getArraySize(DT_INIT_ARRAYSZ);
			case DT_FINI_ARRAY_VALUE:
				return getArraySize(DT_FINI_ARRAYSZ);
			case DT_PREINIT_ARRAY_VALUE:
				return getArraySize(DT_PREINIT_ARRAYSZ);
			case DT_SCE_PLTGOT_VALUE:
				Address start = getStart();
				MemoryBlock block = getHelper().getProgram().getMemory().getBlock(start);
				return block.getEnd().subtract(start);
			default:
				return -1;
		}
	}

	@Override
	protected String getName() {
		switch((int) dynamic.getTag()) {
			case DT_INIT_VALUE:
				return ".init";
			case DT_FINI_VALUE:
				return ".fini";
			case DT_INIT_ARRAY_VALUE:
				return ".init_array";
			case DT_FINI_ARRAY_VALUE:
				return ".fini_array";
			case DT_PREINIT_ARRAY_VALUE:
				return ".preinit_array";
			case DT_SCE_PLTGOT_VALUE:
				return ".plt.got";
			default:
				return "";
		}
	}

	private Function getFunction() {
		Address start = getStart();
		Program program = getHelper().getProgram();
		Listing listing = program.getListing();
		Function fun = listing.getFunctionAt(start);
		if (fun != null) {
			listing.removeFunction(start);
		}
		DisassembleCommand dCmd = new DisassembleCommand(start, null, true);
		dCmd.applyTo(program);
		CreateFunctionCmd cmd = new CreateFunctionCmd(start);
		cmd.applyTo(program);
		return cmd.getFunction();
	}

	private long getFunctionSize() {
		Address start = getStart();
		Function fun = getFunction();
		if (fun != null) {
			try {
				fun.setName(getName().replace(".", "_"), SourceType.IMPORTED);
			} catch (Exception e) {
				getHelper().getLog().appendException(e);
				throw new AssertException(e);
			}
			return fun.getBody().getMaxAddress().subtract(start);
		}
		return -1;
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

	@Override
	public void move() throws Exception {
		switch (dynamic.getTagType().value) {
			case DT_FINI_VALUE:
			case DT_INIT_VALUE:
				break;
			default:
				super.move();
		}
		Memory mem = getHelper().getProgram().getMemory();
		Address start = getStart();
		if (start == null) {
			return;
		}
		switch (dynamic.getTagType().value) {
			case DT_FINI_VALUE: {
				Function fun = getFunction();
				Address roAddress = fun.getBody().getMaxAddress().next();
				MemoryBlock block = mem.getBlock(roAddress);
				mem.split(block, roAddress);
				block = mem.getBlock(roAddress);
				block.setName(".rodata");
				block.setExecute(false);
				block.setWrite(false);
				long roLength = block.getEnd().subtract(roAddress);
				FragmentBuilder builder =
					new ReadOnlyDataFragmentBuilder(getHelper(), roAddress, roLength);
				builder.move();
			}
			case DT_INIT_VALUE:
				MemoryBlock block = mem.getBlock(start);
				block.setExecute(true);
				break;
			default:
				break;
		}
	}

	public static boolean canHandle(ElfDynamicType type) {
		switch (type.value) {
			case DT_INIT_VALUE:
			case DT_FINI_VALUE:
			case DT_INIT_ARRAY_VALUE:
			case DT_FINI_ARRAY_VALUE:
			case DT_PREINIT_ARRAY_VALUE:
			case DT_SCE_PLTGOT_VALUE:
				return true;
			default:
				return false;
		}
	}

	private static class ReadOnlyDataFragmentBuilder extends FragmentBuilder {

		private final Address start;
		private final long size;

		ReadOnlyDataFragmentBuilder(ElfLoadHelper helper, Address start, long size) {
			super(helper);
			this.start = start;
			this.size = size;
		}

		@Override
		protected Address getStart() {
			return start;
		}

		@Override
		protected long getSize() {
			return size;
		}

		@Override
		protected String getName() {
			return ".rodata";
		}

	}

}
