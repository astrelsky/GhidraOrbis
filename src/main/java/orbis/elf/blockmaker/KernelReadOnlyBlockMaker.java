package orbis.elf.blockmaker;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.util.task.TaskMonitor;

public final class KernelReadOnlyBlockMaker extends ReadOnlyBlockMaker {

	public KernelReadOnlyBlockMaker(ElfLoadHelper helper, TaskMonitor monitor) {
		super(helper, monitor);
	}

	@Override
	public void makeBlock() throws Exception {
		// TODO need a way to do this that works for every dump
	}
}
