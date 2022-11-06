package orbis.elf.fragment;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public abstract class FragmentBuilder {

	private final ElfLoadHelper helper;

	protected FragmentBuilder(ElfLoadHelper helper) {
		this.helper = helper;
	}

	protected ElfLoadHelper getHelper() {
		return helper;
	}

	protected abstract Address getStart();

	protected abstract long getSize();

	protected abstract String getName();

	public void move() throws Exception {
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
		
		Address end = start.add(size);
		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(start);
		if (block == null) {
			return;
		}
		if (!start.equals(block.getStart())) {
			mem.split(block, start);
			block = mem.getBlock(start);
		}
		if (!end.equals(block.getEnd()) && block.contains(end)) {
			if (end.equals(start)) {
				return;
			}
			mem.split(block, end);
			block = mem.getBlock(start);
		}
		MemoryBlock conflictBlock = mem.getBlock(name);
		if (conflictBlock != null && !conflictBlock.equals(block)) {
			conflictBlock.setName(name+"_old");
		}
		block.setName(name);
		if (name.equals(".text")) {
			return;
		}
		Listing listing = program.getListing();
		ProgramModule root = listing.getDefaultRootModule();
		ProgramFragment frag = listing.getFragment(root.getTreeName(), name);
		if (frag != null) {
			return;
		}
			frag = root.createFragment(name);
			frag.move(block.getStart(), block.getEnd().subtract(1));
	}
}
