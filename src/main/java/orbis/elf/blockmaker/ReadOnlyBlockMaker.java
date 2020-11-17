package orbis.elf.blockmaker;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public abstract class ReadOnlyBlockMaker {

	private static final String RO_DATA_BLOCK_NAME = ".rodata";

	protected final ElfLoadHelper helper;
	protected final TaskMonitor monitor;

	protected ReadOnlyBlockMaker(ElfLoadHelper helper, TaskMonitor monitor) {
		this.helper = helper;
		this.monitor = monitor;
	}

	public abstract void makeBlock() throws Exception;

	protected Program getProgram() {
		return helper.getProgram();
	}

	protected ProgramFragment getFragment(String name) throws Exception {
		Listing listing = getProgram().getListing();
		ProgramModule root = listing.getDefaultRootModule();
		ProgramFragment frag = listing.getFragment(root.getTreeName(), name);
		if (frag == null) {
			frag = root.createFragment(name);
		}
		return frag;
	}

	protected void createReadOnlyBlock(Address addr) throws Exception {
		Program program = getProgram();
		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(addr);
		mem.split(block, addr);
		block = mem.getBlock(addr);
		block.setName(RO_DATA_BLOCK_NAME);
		block.setExecute(false);
		block.setWrite(false);
		ProgramFragment frag = getFragment(RO_DATA_BLOCK_NAME);
		frag.move(block.getStart(), block.getEnd());
	}
}
