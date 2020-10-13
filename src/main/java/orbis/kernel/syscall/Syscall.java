package orbis.kernel.syscall;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

public final class Syscall {

	public static final int FUNCTION_ORDINAL = 1;

	private final Data data;

	Syscall(Data data) {
		this.data = data;
	}

	public Address getFunctionAddress() {
		return (Address) data.getComponent(FUNCTION_ORDINAL).getValue();
	}

	public Function getFunction() throws Exception {
		Listing listing = data.getProgram().getListing();
		Address addr = getFunctionAddress();
		Function fun = listing.getFunctionAt(addr);
		if (fun == null) {
			CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
			if (cmd.applyTo(data.getProgram())) {
				fun = cmd.getFunction();
			}
		}
		return fun;
	}
}
