package orbis.elf.blockmaker;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
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
		if (root == null) {
			Msg.warn(this, "ReadOnlyBlockMaker: root module is null while looking for fragment " + name);
			return null;
		}
		
		// 1. Search in all trees first
		ProgramFragment frag = null;
		for (String treeName : listing.getTreeNames()) {
			frag = listing.getFragment(treeName, name);
			if (frag != null) {
				return frag;
			}
		}
		
		// 2. Try creating it in the root module
		try {
			frag = root.createFragment(name);
		} catch (Exception e) {
			Msg.error(this, "ReadOnlyBlockMaker: failed to create fragment " + name + ": " + e.getMessage(), e);
		}
		
		return frag;
	}

	protected void createReadOnlyBlock(Address addr) throws Exception {
		Program program = getProgram();
		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(addr);
		if (block != null) {
			if (addr.compareTo(block.getStart()) > 0 && addr.compareTo(block.getEnd()) < 0) {
				try {
					mem.split(block, addr);
					block = mem.getBlock(addr);
				} catch (Exception e) {
					Msg.error(this, "ReadOnlyBlockMaker: failed to split memory block: " + e.getMessage(), e);
				}
			}
			block.setName(RO_DATA_BLOCK_NAME);
			block.setExecute(false);
			block.setWrite(false);
			ProgramFragment frag = getFragment(RO_DATA_BLOCK_NAME);
			if (frag != null) {
				frag.move(block.getStart(), block.getEnd());
			}
		}
	}
}
