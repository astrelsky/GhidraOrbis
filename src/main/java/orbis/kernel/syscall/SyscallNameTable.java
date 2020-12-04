package orbis.kernel.syscall;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

public final class SyscallNameTable {

	private static final String NAME_PREFIX = "sys_";

	private final Program program;
	private final Address start;
	private Data data;

	public SyscallNameTable(Program program, Address start) {
		this.program = program;
		this.start = start;
	}

	public void parse() throws Exception {
		Listing listing = program.getListing();
		Memory mem = program.getMemory();
		DataTypeManager dtm = program.getDataTypeManager();
		Address currentAddress = getAbsoluteAddress(program, start);
		MemoryBlock block = mem.getBlock(currentAddress);
		int ptrSize = program.getDefaultPointerSize();
		currentAddress = start;
		while (block.contains(getAbsoluteAddress(program, currentAddress))) {
			currentAddress = currentAddress.add(ptrSize);
		}
		int count = (int) (currentAddress.subtract(start) / ptrSize);
		DataType str = TerminatedStringDataType.dataType;
		DataType dt = dtm.getPointer(str);
		ArrayDataType array = new ArrayDataType(dt, count, -1);
		Address end = start.add(program.getDefaultPointerSize() * count);
		listing.clearCodeUnits(start, end, false);
		data = listing.createData(start, array);
		for (int i = 0; i < data.getNumComponents(); i++) {
			currentAddress = (Address) data.getComponent(i).getValue();
			DataUtilities.createData(
				program, currentAddress, str, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
	}

	public String getName(int index) {
		Listing listing = program.getListing();
		Address addr = (Address) data.getComponent(index).getValue();
		Data str = listing.getDataAt(addr);
		String name = (String) str.getValue();
		return name.startsWith(NAME_PREFIX) ? name : NAME_PREFIX + name;
	}

	public int getLength() {
		return data.getNumComponents();
	}
}
