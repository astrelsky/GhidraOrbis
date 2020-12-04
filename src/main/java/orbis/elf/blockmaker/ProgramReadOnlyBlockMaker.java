package orbis.elf.blockmaker;

import java.util.LinkedList;
import java.util.List;

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.task.TaskMonitor;

public class ProgramReadOnlyBlockMaker extends ReadOnlyBlockMaker {

	private static final byte[] JMP_BYTES = new byte[]{
		(byte) 0xff, (byte) 0x25,
		(byte) 0, (byte) 0, (byte) 0, (byte) 0,
		(byte) 0x68
	};

	private static final byte[] JMP_MASK = new byte[]{
		(byte) 0xff, (byte) 0xff,
		(byte) 0, (byte) 0, (byte) 0, (byte) 0,
		(byte) 0xff
	};

	public ProgramReadOnlyBlockMaker(ElfLoadHelper helper, TaskMonitor monitor) {
		super(helper, monitor);
	}

	@Override
	public void makeBlock() throws Exception {
		ProgramFragment frag = getPltGotFragment();
		Address addr = frag.getMinAddress();
		if (addr == null) {
			monitor.setMessage("Locating .got.plt");
			Program program = getProgram();
			AddressSet addrs = new AddressSet();
			SymbolTable st = program.getSymbolTable();
			for (Symbol s : st.getExternalSymbols()) {
				monitor.checkCanceled();
				if (s.getReferenceCount() == 1) {
					addrs.add(s.getReferences()[0].getFromAddress());
				}
			}
			List<ReferenceAddressPair> refs = new LinkedList<>();
			ProgramMemoryUtil.loadDirectReferenceList(
				program, 8, addrs.getMinAddress(), addrs, refs, monitor);
			addrs.clear();
			refs.forEach(r -> addrs.add(r.getSource()));
			frag.move(addrs.getMinAddress(), addrs.getMaxAddress());
			addr = frag.getMinAddress();
		}
		monitor.setMessage("Scanning .got.plt");
		while (frag.contains(addr)) {
			monitor.checkCanceled();
			helper.createData(addr, PointerDataType.dataType);
			addr = addr.add(Long.BYTES);
		}
		addr = createTrampolines();
		createReadOnlyBlock(addr);
	}

	private Address createTrampolines() throws Exception {
		Program program = getProgram();
		Listing listing = program.getListing();
		monitor.setMessage("Finding trampolines");
		JumpSearcher searcher = new JumpSearcher(program, monitor);
		ProgramFragment frag = getPltGotFragment();
		while (searcher.getNextAddress() != null) {
			monitor.checkCanceled();
			Address addr = searcher.getTarget();
			if (frag.contains(addr)) {
				break;
			}
		}
		Address start = searcher.getAddress();
		monitor.setMessage("Creating tampolines");
		while (searcher.isJump() && frag.contains(searcher.getTarget())) {
			Function fun =
				helper.createOneByteFunction(null, searcher.getAddress(), true);
			Data data = listing.getDataAt(searcher.getTarget());
			Address thunkAddr = (Address) data.getValue();
			if (thunkAddr.getOffset() != 0) {
				Function thunked = listing.getFunctionAt(thunkAddr);
				fun.setThunkedFunction(thunked);
			}
			searcher.setAddress(searcher.getAddress().add(0x10));
		}
		frag = getFragment(".plt");
		Address end = searcher.getAddress();
		frag.move(start, end.previous());
		return end;
	}

	private ProgramFragment getPltGotFragment() throws Exception {
		return getFragment(".got.plt");
	}

	private static class JumpSearcher {

		private final Memory mem;
		private final Address end;
		private final TaskMonitor monitor;
		private Address address;

		JumpSearcher(Program program, TaskMonitor monitor) {
			this.mem = program.getMemory();
			this.monitor = monitor;
			MemoryBlock block = mem.getBlock(".text");
			this.address = block.getStart();
			this.end = block.getEnd();
		}

		boolean isJump() throws Exception {
			return mem.getShort(address) == 0x25ff;
		}

		void setAddress(Address address) {
			this.address = address;
		}

		Address getAddress() {
			return address;
		}

		Address getTarget() throws Exception {
			int offset = (mem.getInt(address.add(2)) & ~3) + 8;
			try {
				return address.add(offset);
			} catch (AddressOutOfBoundsException e) {
				return Address.NO_ADDRESS;
			}
		}

		Address getNextAddress() {
			if (address == null) {
				return null;
			}
			do {
				address = mem.findBytes(
					address.next(), end, JMP_BYTES, JMP_MASK, true, monitor);
			} while (address != null && address.getOffset() % 8 != 0);
			return address;
		}
	}

}
