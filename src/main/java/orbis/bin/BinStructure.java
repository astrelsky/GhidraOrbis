package orbis.bin;

import ghidra.app.util.bin.BinaryReader;

public abstract class BinStructure {
	
	protected BinStructure() {
	}

	protected static final void advanceReader(BinaryReader reader, int n) {
		reader.setPointerIndex(reader.getPointerIndex() + n);
	}
}
