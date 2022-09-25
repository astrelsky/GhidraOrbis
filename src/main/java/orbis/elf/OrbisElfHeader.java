package orbis.elf;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.function.Consumer;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

import utility.function.ExceptionalCallback;

import static orbis.elf.OrbisElfExtension.*;

public class OrbisElfHeader extends ElfHeader {

	private static final long KERNEL_BASE = 0xFFFFFFFF82200000L;

    public static final short ET_SCE_EXEC = (short) 0xFE00;
    public static final short ET_SCE_REPLAY_EXEC = (short) 0xFE01;
    public static final short ET_SCE_RELEXEC = (short) 0xFE04;
    public static final short ET_SCE_STUBLIB = (short) 0xFE0C;
    public static final short ET_SCE_DYNEXEC = (short) 0xFE10;
    public static final short ET_SCE_DYNAMIC = (short) 0xFE18;
	public static final short ET_SCE_KERNEL = 2;

	public OrbisElfHeader(ByteProvider provider, Consumer<String> errorConsumer) throws ElfException {
		super(provider, errorConsumer);
	}

	@Override
	public void parse() throws IOException {

		if (getReader() == null) {
			throw new IOException("ELF binary reader is null!");
		}
		if (isParsed()) {
			return;
		}

		invoke("initElfLoadAdapter");

		setParsed();

		parseProgramHeaders();

		parseSectionHeaders();

		if (isKernel()) {
			invoke("parseDynamicTable");
			invoke("parseStringTables");
			invoke("parseDynamicLibraryNames");
			invoke("parseSymbolTables");
			invoke("parseRelocationTables");
			invoke("parseGNU_d");
			invoke("parseGNU_r");
		} else {
			parseDynamicTable();
		}
	}

	public boolean isKernel() {
		return e_type() == ET_SCE_KERNEL;
	}

	public long getDynamicAddrOffset(long offset) {
		offset = adjustAddressForPrelink(offset);
		if (isKernel()) {
			ElfProgramHeader text = getTextSegment();
			return offset + (text.getVirtualAddress() - KERNEL_BASE);
		}
		return offset;
	}

	private long getDynamicFileOffset(long offset) {
		ElfProgramHeader phdr;
		if (isKernel()) {
			phdr = getDynamicSegment();
			//offset = getDynamicAddrOffset(offset);
		} else {
			phdr = getDynlibData();
		}
		return offset + phdr.getOffset();
	}

	public ElfProgramHeader[] getRawProgramHeaders() throws IOException {
		BinaryReader reader = getReader();
		ElfProgramHeader[] programHeaders = new ElfProgramHeader[getProgramHeaderCount()];
		for (int i = 0; i < getProgramHeaderCount(); ++i) {
			long index = e_phoff() + (i * e_phentsize());
			reader.setPointerIndex(index);
			programHeaders[i] = new ElfProgramHeader(reader, this);
		}
		return programHeaders;
	}

	@Override
	public ElfProgramHeader[] getProgramHeaders() {
		if (super.getProgramHeaders() == null) {
			try {
				parseProgramHeaders();
			} catch (Exception e) {
				// already logged
			}
		}
		return super.getProgramHeaders();
	}

	private void parseProgramHeaders() throws IOException {
		BinaryReader reader = getReader();
		long fileLength = reader.length();
		ElfProgramHeader[] programHeaders = new ElfProgramHeader[getProgramHeaderCount()];
		setProgramHeaders(programHeaders);
		for (int i = 0; i < getProgramHeaderCount(); ++i) {
			long index = e_phoff() + (i * e_phentsize());
			reader.setPointerIndex(index);
			programHeaders[i] = new ElfProgramHeader(reader, this);
		}

		long size = 0;
		for (ElfProgramHeader phdr : programHeaders) {
			if (isKernel()) {
				long memSize = phdr.getMemorySize();
				phdr.setSize(memSize, memSize);
				if (!phdr.isExecute()) {
					fixupProgramHeader(phdr);
				}
			}
			size += phdr.getFileSize();
		}
		if (size == fileLength) {
			// adjust program section file offset to be based on relative read offset
			long relOffset = 0;
			for (ElfProgramHeader pheader : programHeaders) {
				pheader.setOffset(relOffset);
				relOffset += pheader.getFileSize();
			}
		}
	}

	private ElfProgramHeader getTextSegment() {
		for (ElfProgramHeader phdr : getProgramHeaders(ElfProgramHeaderConstants.PT_LOAD)) {
			if (phdr.isExecute()) {
				return phdr;
			}
		}
		return null;
	}

	private ElfProgramHeader getDynamicSegment() {
		for (ElfProgramHeader phdr : getProgramHeaders(ElfProgramHeaderConstants.PT_DYNAMIC)) {
			return phdr;
		}
		return null;
	}

	private void fixupProgramHeader(ElfProgramHeader phdr) {
		long vaddr = phdr.getVirtualAddress();
		switch (phdr.getType()) {
			case ElfProgramHeaderConstants.PT_LOAD:
			case OrbisElfProgramBuilder.PT_SCE_RELRO_VALUE:
			case ElfProgramHeaderConstants.PT_DYNAMIC:
				ElfProgramHeader text = getTextSegment();
				if (text.getVirtualAddress() != KERNEL_BASE) {
					phdr.setOffset(vaddr - text.getVirtualAddress());
				}
			default:
				break;
		}
	}

	@Override
	public String[] getDynamicLibraryNames() {
		String[] names = super.getDynamicLibraryNames();
		return names != null ? names : new String[0];
	}

	public void parseDynamicLibraryNames() {
		invoke("parseDynamicLibraryNames");
	}

	public void parseRelocationTables() throws IOException {
		ArrayList<ElfRelocationTable> relocationTableList = new ArrayList<>();

		// Order of parsing and processing dynamic relocation tables can be important to ensure that
		// GOT/PLT relocations are applied late.

		parseDynamicRelocTable(
			relocationTableList, DT_SCE_RELA, DT_SCE_RELAENT, DT_SCE_RELASZ, true);

		parseJMPRelocTable(relocationTableList);

		setRelocationTables(relocationTableList.toArray(ElfRelocationTable[]::new));
	}

	public ElfProgramHeader getDynlibData() {
		ElfProgramHeader[] phdrs = getProgramHeaders(PT_SCE_DYNLIBDATA.value);
		if (phdrs.length != 1) {
			return null;
		}
		return phdrs[0];
	}

	private void parseDynamicRelocTable(ArrayList<ElfRelocationTable> relocationTableList,
			ElfDynamicType relocTableAddrType, ElfDynamicType relocEntrySizeType,
			ElfDynamicType relocTableSizeType, boolean addendTypeReloc) throws IOException {
		ElfDynamicTable dynamicTable = getDynamicTable();
		ElfSymbolTable dynamicSymbolTable = getDynamicSymbolTable();
		if (dynamicTable == null) {
			return;
		}

		try {

			// NOTE: Dynamic and Relocation tables are loaded into memory, however,
			// we construct them without loading so we must map memory addresses
			// back to file offsets.

			long value = dynamicTable.getDynamicValue(relocTableAddrType);

			long addrOffset = getDynamicAddrOffset(value);

			ElfProgramHeader phdr = getDynlibData();

			if ((phdr == null || phdr.getOffset() < 0) && !isKernel()) {
				return;
			}

			if (dynamicSymbolTable == null) {
				Msg.warn(this, "Failed to process " + relocTableAddrType.name +
					", missing dynamic symbol table");
				return;
			}

			long fileOffset = getDynamicFileOffset(value);
			if (fileOffset < 0) {
				return;
			}
			long tableEntrySize =
				relocEntrySizeType != null ? dynamicTable.getDynamicValue(relocEntrySizeType) : -1;
			long tableSize = dynamicTable.getDynamicValue(relocTableSizeType);

			ElfRelocationTable relocTable = createElfRelocationTable(getReader(),
				this, null, fileOffset, addrOffset, tableSize, tableEntrySize,
				addendTypeReloc, dynamicSymbolTable, null, TableFormat.DEFAULT);
			relocationTableList.add(relocTable);
		}
		catch (NotFoundException e) {
			// ignore - skip (required dynamic table value is missing)
		}
	}

	private static ElfRelocationTable createElfRelocationTable(BinaryReader reader,
		ElfHeader header, ElfSectionHeader relocTableSection, long fileOffset, long addrOffset,
		long length, long entrySize, boolean addendTypeReloc, ElfSymbolTable symbolTable,
		ElfSectionHeader sectionToBeRelocated, TableFormat format) throws IOException {
			return new ElfRelocationTable(
				reader, header, relocTableSection, fileOffset, addrOffset, length, entrySize,
				addendTypeReloc, symbolTable, sectionToBeRelocated, format);
	}

	private void parseJMPRelocTable(ArrayList<ElfRelocationTable> relocationTableList)
			throws IOException {

		ElfDynamicTable dynamicTable = getDynamicTable();
		if (dynamicTable == null) {
			return;
		}

		parseDynamicRelocTable(
			relocationTableList, DT_SCE_JMPREL, DT_SCE_RELAENT, DT_SCE_PLTRELSZ, true);
	}

	private void parseDynamicTable() throws IOException {
		ElfProgramHeader[] dynamicHeaders = getProgramHeaders(ElfProgramHeaderConstants.PT_DYNAMIC);
		if (dynamicHeaders.length == 1) { // no more than one expected
			ElfProgramHeader prog = dynamicHeaders[0];
			if (prog != null) {
				ElfDynamicTable table =
					new ElfDynamicTable(getReader(), this, prog.getOffset(), prog.getVirtualAddress());
				for (ElfDynamic dynamic : table.getDynamics()) {
					ElfDynamicType tagType = dynamic.getTagType();
					if (tagType == null) {
						continue;
					}
					if (tagType.valueType == ElfDynamicValueType.ADDRESS) {
						long value = getDynamicAddrOffset(dynamic.getValue());
						dynamic.setValue(value);
					}
				}
				setDynamicTable(table);
			}
		}
	}

	public void parseDynamicStringTable() throws IOException {
		List<ElfStringTable> tables = new ArrayList<>(List.of(getStringTables()));
		ElfProgramHeader phdr = getDynlibData();
		ElfDynamicTable dynamicTable = getDynamicTable();
		if (dynamicTable == null) {
			return;
		}
		if (!dynamicTable.containsDynamicValue(DT_SCE_STRSZ)) {
			Msg.warn(this, "Failed to parse DT_SCE_STRSZ, missing dynamic dependency");
			return;
		}

		try {
			long value = dynamicTable.getDynamicValue(DT_SCE_STRTAB);
			long addrOffset = getDynamicAddrOffset(value);
			long stringTableSize = dynamicTable.getDynamicValue(DT_SCE_STRSZ);

			if (addrOffset == 0) {
				Msg.warn(this, "ELF Dynamic String Table of size " + stringTableSize +
					" appears to have been stripped from binary");
				return;
			}

			if (phdr == null && !isKernel()) {
				Msg.warn(this, "Failed to locate DT_STRTAB in memory at 0x" +
					Long.toHexString(addrOffset));
				return;
			}
			long fileOffset = getDynamicFileOffset(value);
			if (fileOffset < 0) {
				return;
			}
			ElfStringTable tbl = new ElfStringTable(this, null, fileOffset, addrOffset, stringTableSize);
			setDynamicStringTable(tbl);
			tables.add(tbl);
			setStringTables(tables.toArray(ElfStringTable[]::new));
		} catch (NotFoundException e) {
			throw new AssertException(e);
		}
	}

	public void parseDynamicSymbolTable() throws IOException {
		List<ElfSymbolTable> tables = new ArrayList<>(List.of(getSymbolTables()));
		ElfDynamicTable dynamicTable = getDynamicTable();
		ElfStringTable dynamicStringTable = getDynamicStringTable();
		if (dynamicTable == null) {
			return;
		}
		BinaryReader reader = getReader();
		if (!dynamicTable.containsDynamicValue(DT_SCE_SYMTAB) ||
			!dynamicTable.containsDynamicValue(DT_SCE_SYMENT) ||
			!(dynamicTable.containsDynamicValue(DT_SCE_HASH))) {
			if (dynamicStringTable != null) {
				Msg.warn(this, "Failed to parse DT_SYMTAB, missing dynamic dependency");
			}
			return;
		}

		try {

			// Create dynamic symbol table if not defined as a section
			long value = dynamicTable.getDynamicValue(DT_SCE_SYMTAB);
			long addrOffset = getDynamicAddrOffset(value);
			if (addrOffset == 0) {
				Msg.warn(this,
					"ELF Dynamic String Table of size appears to have been stripped from binary");
			}

			if (dynamicStringTable == null) {
				Msg.warn(this, "Failed to process DT_SYMTAB, missing dynamic string table");
				return;
			}

			if (addrOffset == 0) {
				return;
			}

			long fileOffset = getDynamicFileOffset(value);
			if (fileOffset < 0) {
				return;
			}
			long tableEntrySize = dynamicTable.getDynamicValue(DT_SCE_SYMENT);
			long tableSize = dynamicTable.getDynamicValue(DT_SCE_SYMTABSZ);

			ElfSymbolTable tbl = new ElfSymbolTable(
				reader, this, null, fileOffset, addrOffset,
				tableSize, tableEntrySize, dynamicStringTable, null, true);
			setDynamicSymbolTable(tbl);
			tables.add(tbl);
			setSymbolTables(tables.toArray(ElfSymbolTable[]::new));
		}
		catch (NotFoundException e) {
			throw new AssertException(e);
		}
	}

	private void setDynamicTable(ElfDynamicTable table) {
		setField("dynamicTable", table);
	}

	private void setDynamicStringTable(ElfStringTable table) {
		setField("dynamicStringTable", table);
	}

	private void setStringTables(ElfStringTable[] tables) {
		setField("stringTables", tables);
	}

	private void setDynamicSymbolTable(ElfSymbolTable table) {
		setField("dynamicSymbolTable", table);
	}

	private void setSymbolTables(ElfSymbolTable[] tables) {
		setField("symbolTables", tables);
	}

	@Override
	public ElfSymbolTable[] getSymbolTables() {
		ElfSymbolTable[] tables = super.getSymbolTables();
		return tables != null ? tables : new ElfSymbolTable[0];
	}

	@Override
	public ElfStringTable[] getStringTables() {
		ElfStringTable[] tables = super.getStringTables();
		return tables != null ? tables : new ElfStringTable[0];
	}

	@Override
	public ElfSectionHeader[] getSections() {
		ElfSectionHeader[] headers = super.getSections();
		return headers != null ? headers : new ElfSectionHeader[0];
	}

	@Override
	public boolean isRelocatable() {
		short e_type = e_type();
		return e_type == ET_SCE_RELEXEC || e_type == ElfConstants.ET_REL;
	}

	@Override
	public boolean isSharedObject() {
		short e_type = e_type();
		return e_type == ET_SCE_DYNAMIC || e_type == ET_SCE_STUBLIB || e_type == ElfConstants.ET_DYN;
	}

	@Override
	public boolean isExecutable() {
		short e_type = e_type();
		return e_type == ET_SCE_DYNEXEC || e_type == ET_SCE_EXEC
			|| e_type == ET_SCE_RELEXEC || e_type == ET_SCE_REPLAY_EXEC
			|| e_type == ElfConstants.ET_EXEC;
	}

	public void setSections(ElfSectionHeader[] sections) {
		setField("sectionHeaders", sections);
		setField("e_shnum", (short) sections.length);
	}

	private void setRelocationTables(ElfRelocationTable[] tables) {
		setField("relocationTables", tables);
	}

	private boolean isParsed() {
		return getField("parsed");
	}

	private void setParsed() {
		setField("parsed", true);
	}

	private void setProgramHeaders(ElfProgramHeader[] phdrs) {
		setField("programHeaders", phdrs);
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
