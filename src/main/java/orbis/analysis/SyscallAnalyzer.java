package orbis.analysis;

import java.util.Collection;
import java.util.List;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import orbis.kernel.syscall.Syscall;
import orbis.kernel.syscall.SyscallNameTable;
import orbis.kernel.syscall.SyscallTable;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

// Znullptr's syscalls
public final class SyscallAnalyzer extends AbstractKernelAnalyzer {

	private static final String NAME = "ORBIS Syscall Analyzer";
	private static final String DESCRIPTION =
		"Znullptr's syscalls\nLocates and marks up the syscall table";
	private static final String MAGIC_STRING = "ORBIS kernel SELF";

	public SyscallAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		SymbolTable table = program.getSymbolTable();
		List<MemoryBlock> blocks = List.of(program.getMemory().getBlocks());
		Collection<Address> magicAddresses =
			ProgramMemoryUtil.findString(MAGIC_STRING, program, blocks, set, monitor);
		if (magicAddresses.size() != 1) {
			return false;
		}
		int ptrSize = program.getDefaultPointerSize();
		magicAddresses = ProgramMemoryUtil.findDirectReferences(
			program, blocks, ptrSize, magicAddresses.iterator().next(), monitor);
		if (magicAddresses.size() != 1) {
			return false;
		}
		try {
			Address sysvec  = magicAddresses.iterator().next().subtract(0x60);
			Address sysent = getAbsoluteAddress(program, sysvec.add(ptrSize));
			Address sysnames = getAbsoluteAddress(program, sysvec.add(0xD0));
			table.createLabel(sysvec, "sysentvec", null, SourceType.ANALYSIS);
			table.createLabel(sysent, "sv_table", null, SourceType.ANALYSIS);
			table.createLabel(sysnames, "sv_syscallnames", null, SourceType.ANALYSIS);
			SyscallNameTable syscallNames = new SyscallNameTable(program, sysnames);
			syscallNames.parse();
			int length = syscallNames.getLength();
			SyscallTable syscallTable = new SyscallTable(program, sysent, length);
			for (int i = 0; i < length; i++) {
				Syscall syscall = syscallTable.getSyscall(i);
				Function fun = syscall.getFunction();
				if (fun != null) {
					fun.setName(syscallNames.getName(i), SourceType.ANALYSIS);
				} else {
					log.appendMsg(
						"Failed to create syscall function "+syscallNames.getName(i)
						+" at "+syscall.getFunctionAddress().toString());
				}
			}
			return true;
		} catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

}
