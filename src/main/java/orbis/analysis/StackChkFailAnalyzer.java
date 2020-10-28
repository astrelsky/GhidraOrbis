package orbis.analysis;

import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

public class StackChkFailAnalyzer extends AbstractKernelAnalyzer {

	private static final String NAME = "__stack_chk_fail locator";
	private static final String DESCRIPTION =
		"Kiwidog's __stack_chk_fail\nLocates and defined the __stack_chk_fail function";
	private static final String FUNCTION_NAME = "__stack_chk_fail";
	private static final String MAGIC_STRING = "stack overflow detected;";

	public StackChkFailAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());
	}
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// first check if we already have the function defined
		SymbolTable table = program.getSymbolTable();
		List<Symbol> symbols = table.getSymbols(FUNCTION_NAME, program.getGlobalNamespace());
		if (!symbols.isEmpty()) {
			Symbol symbol = symbols.get(0);
			return defineFunction(program, symbol.getAddress(), log);
		}
		int pointerSize = program.getDefaultPointerSize();
		List<MemoryBlock> blocks = List.of(ProgramMemoryUtil.getMemBlocks(program, true));
		Collection<Address> addresses =
			ProgramMemoryUtil.findString(MAGIC_STRING, program, blocks, set, monitor);
		if (addresses.isEmpty()) {
			return true;
		}
		Address address = addresses.iterator().next();
		addresses = ProgramMemoryUtil.findDirectReferences(
			program, blocks, pointerSize, address, monitor);
		if (addresses.isEmpty()) {
			return true;
		}
		address = addresses.iterator().next().subtract(pointerSize);
		address = getAbsoluteAddress(program, address);
		return defineFunction(program, address, log);
	}

	private static boolean defineFunction(Program program, Address address, MessageLog log) {
		try {
			FunctionManager man = program.getFunctionManager();
			Function function = man.getFunctionAt(address);
			if (function == null) {
				AddressSet entries = new AddressSet(address);
				CreateFunctionCmd cmd = new CreateFunctionCmd(entries, SourceType.IMPORTED);
				cmd.applyTo(program);
				function = cmd.getFunction();
			}
			function.setName(FUNCTION_NAME, SourceType.IMPORTED);
			function.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
			function.setCallingConvention(GenericCallingConvention.stdcall.getDeclarationName());
			function.setNoReturn(true);
			return true;
		} catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

}
