package orbis.kernel.syscall;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;

import static orbis.data.SyscallDataType.dataType;

public final class SyscallTable {

	private final Data data;

	public SyscallTable(Program program, Address address, int length) throws CodeUnitInsertionException {
		ArrayDataType dt = new ArrayDataType(dataType, length, -1);
		this.data = DataUtilities.createData(
			program, address, dt, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
	}

	public Syscall getSyscall(int index) {
		return new Syscall(data.getComponent(index));
	}
}
