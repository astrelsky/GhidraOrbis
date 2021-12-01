package ghidra.app.util.bin.format.elf;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat;
import ghidra.util.exception.AssertException;

import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.reflect.MethodUtils;

import utility.function.ExceptionalCallback;

public class DefaultElfHeader extends ElfHeader {

	public DefaultElfHeader() {
		super();
	}

	//////////////////////////////////////////////////////////////////////////////////////////
	//							PRIVATE METHOD DELEGATES									//
	//////////////////////////////////////////////////////////////////////////////////////////

	protected void initElfLoadAdapter() {
		invoke("initElfLoadAdapter");
	}

	protected void parseProgramHeaders() throws IOException {
		invoke("parseProgramHeaders");
	}

	protected void parseSectionHeaders() throws IOException {
		invoke("parseSectionHeaders");
	}

	protected void parseDynamicTable() throws IOException {
		invoke("parseDynamicTable");
	}

	protected void parseStringTables() throws IOException {
		invoke("parseStringTables");
	}

	protected void parseDynamicLibraryNames() throws IOException {
		invoke("parseDynamicLibraryNames");
	}

	protected void parseSymbolTables() throws IOException {
		invoke("parseSymbolTables");
	}

	protected void parseRelocationTables() throws IOException {
		invoke("parseRelocationTables");
	}

	protected void parseGNU_d() {
		invoke("parseGNU_d");
	}

	protected void parseGNU_r() {
		invoke("parseGNU_r");
	}

	//////////////////////////////////////////////////////////////////////////////////////////
	//							PRIVATE FIELD DELEGATES										//
	//////////////////////////////////////////////////////////////////////////////////////////

	protected void setRelocationTables(ElfRelocationTable[] tables) {
		setField("relocationTables", tables);
	}

	protected boolean isParsed() {
		return getField("parsed");
	}

	protected void setParsed() {
		setField("parsed", true);
	}

	protected void setDynamicTable(ElfDynamicTable table) {
		setField("dynamicTable", table);
	}

	protected void setDynamicStringTable(ElfStringTable table) {
		setField("dynamicStringTable", table);
	}

	protected void setStringTables(ElfStringTable[] tables) {
		setField("stringTables", tables);
	}

	protected void setDynamicSymbolTable(ElfSymbolTable table) {
		setField("dynamicSymbolTable", table);
	}

	protected void setSymbolTables(ElfSymbolTable[] tables) {
		setField("symbolTables", tables);
	}

	protected static ElfRelocationTable createElfRelocationTable(
		FactoryBundledWithBinaryReader reader, ElfHeader header,
		ElfSectionHeader relocTableSection, long fileOffset, long addrOffset, long length,
		long entrySize, boolean addendTypeReloc, ElfSymbolTable symbolTable,
		ElfSectionHeader sectionToBeRelocated, TableFormat format) throws IOException {
			return invokeStatic(ElfRelocationTable.class, "createElfRelocationTable",
				reader, header, relocTableSection, fileOffset, addrOffset, length, entrySize,
				addendTypeReloc, symbolTable, sectionToBeRelocated, format);
	}

	@SuppressWarnings("unchecked")
	private <R> R getField(String field) {
		return invoke(() -> {
			Field f = ElfHeader.class.getDeclaredField(field);
			f.setAccessible(true);
			R result = (R) f.get(this);
			f.setAccessible(false);
			return result;
		});
	}

	private <T> void setField(String field, T value) {
		invoke(() -> {
			Field f = ElfHeader.class.getDeclaredField(field);
			f.setAccessible(true);
			f.set(this, value);
			f.setAccessible(false);
		});
	}

	private static <R, E extends Exception> R invoke(ExceptionalSupplier<R, E> s) {
		try {
			return s.get();
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	@SuppressWarnings("unchecked")
	private <R> R invoke(String method) {
		try {
			Method m = ElfHeader.class.getDeclaredMethod(method);
			m.setAccessible(true);
			R result = (R) m.invoke(this);
			m.setAccessible(false);
			return result;
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	@SuppressWarnings("unchecked")
	private static <R> R invokeStatic(Class<R> clazz, String method, Object... args) {
		return invoke(() -> {
			Class<?>[] types = ClassUtils.toClass(args);
			Method m = MethodUtils.getMatchingMethod(clazz, method, types);
			m.setAccessible(true);
			return (R) m.invoke(null, args);
		});
	}

	private static <E extends Exception> void invoke(ExceptionalCallback<E> c) {
		try {
			c.call();
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	@FunctionalInterface
	private static interface ExceptionalSupplier<R, E extends Exception> {
		public R get() throws E;
	}

}
