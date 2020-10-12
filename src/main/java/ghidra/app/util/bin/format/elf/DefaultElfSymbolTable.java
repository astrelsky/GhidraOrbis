package ghidra.app.util.bin.format.elf;

import java.io.IOException;
import java.lang.reflect.Method;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.exception.AssertException;

public class DefaultElfSymbolTable extends ElfSymbolTable {

	protected DefaultElfSymbolTable() {
	}

	public static ElfSymbolTable createElfSymbolTable(FactoryBundledWithBinaryReader reader,
			ElfHeader header, ElfSectionHeader symbolTableSection, long fileOffset, long addrOffset,
			long length, long entrySize, ElfStringTable stringTable, boolean isDynamic)
			throws IOException {
		return ElfSymbolTable.createElfSymbolTable(
			reader, header, symbolTableSection, fileOffset, addrOffset,
			length, entrySize, stringTable, isDynamic);
	}

	protected void initElfSymbolTable(FactoryBundledWithBinaryReader reader, ElfHeader header,
			ElfSectionHeader symbolTableSection, long fileOffset, long addrOffset, long length,
			long entrySize, ElfStringTable stringTable, boolean isDynamic) {
		try {
			Method m = ElfSymbolTable.class.getDeclaredMethod(
				"initElfSymbolTable", FactoryBundledWithBinaryReader.class, ElfHeader.class,
				ElfSectionHeader.class, long.class, long.class, long.class, long.class,
				ElfStringTable.class, boolean.class);
			m.setAccessible(true);
			m.invoke(this, reader, header, symbolTableSection, fileOffset, addrOffset,
				length, entrySize, stringTable, isDynamic);
			m.setAccessible(false);
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}
}
