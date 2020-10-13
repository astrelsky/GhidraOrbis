//Dumps the syscall table to an output file for use in OrbisSyscallsScript
//@category Orbis
import java.io.File;
import java.io.FileWriter;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;

import orbis.data.SyscallDataType;
import orbis.kernel.syscall.Syscall;
import orbis.util.OrbisUtil;

public final class OrbisSyscallDumperScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (!OrbisUtil.isOrbisKernel(currentProgram)) {
			popup("This script is intended for the Orbis Kernel");
			return;
		}
		List<Symbol> symbols = getSymbols("sv_table", null);
		if (symbols.size() != 1) {
			popup("Only expected 1 sv_table to be defined");
			return;
		}
		Symbol table = symbols.get(0);
		Data data = getDataAt(table.getAddress());
		if (!isTableCorrectlyDefined(data)) {
			popup("sv_table is not properly defined");
			return;
		}

		File file = askFile("Select output file", "ok");
		try (FileWriter writer = new FileWriter(file)) {
			monitor.initialize(data.getNumComponents());
			monitor.setMessage("Dumping sv_table");
			Function dummy = getFunction(data.getComponent(0));
			for (int i = 1; i < data.getNumComponents(); i++) {
				monitor.checkCanceled();
				Function syscall = getFunction(data.getComponent(i));
				if (syscall != null && !syscall.equals(dummy)) {
					writer.write(String.format("%d sys_%s\n", i, syscall.getName()));
				}
				monitor.incrementProgress(1);
			}
		}
	}

	private boolean isTableCorrectlyDefined(Data data) {
		if (data == null || !data.isArray()) {
			return false;
		}
		DataType dt = ((Array) data.getDataType()).getDataType();
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		DataType syscallDt =
			dtm.resolve(SyscallDataType.dataType, DataTypeConflictHandler.KEEP_HANDLER);
		if (!dt.isEquivalent(syscallDt)) {
			return false;
		}
		return true;
	}

	private Function getFunction(Data data) {
		return getFunctionAt((Address) data.getComponent(Syscall.FUNCTION_ORDINAL).getValue());
	}

}
