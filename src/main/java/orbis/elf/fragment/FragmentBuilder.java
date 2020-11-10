package orbis.elf.fragment;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

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
		Listing listing = program.getListing();
		ProgramModule root = listing.getDefaultRootModule();
		Address end = start.add(size);
		ProgramFragment frag = listing.getFragment(root.getTreeName(), name);
		if (frag != null) {
			return;
		}
		frag = root.createFragment(name);
		frag.move(start, end);
	}
}
