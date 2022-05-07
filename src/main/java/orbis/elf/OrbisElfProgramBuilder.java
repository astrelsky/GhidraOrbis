package orbis.elf;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.DefaultElfProgramBuilder;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import orbis.util.OrbisUtil;

import static orbis.elf.OrbisElfExtension.*;

public class OrbisElfProgramBuilder extends DefaultElfProgramBuilder {

	public static final int DT_SCE_PLTGOT_TAG = 0x61000027;
	public static final int PT_SCE_RELRO_VALUE = 0x61000010;
	public static final int PT_SCE_DYNLIBDATA_VALUE = 0x61000000;
	public static final int PT_SCE_LIBVERSION_VALUE = 0x6FFFFF01;
	public static final int PT_SCE_COMMENT_VALUE = 0x6FFFFF00;
	public static final int PT_SCE_PROCPARAM_VALUE = 0x61000001;
	public static final int PT_SCE_MODULEPARAM_VALUE = 0x61000002;

	private List<ElfProgramHeader> conflicts = new ArrayList<>();

	private OrbisElfProgramBuilder(OrbisElfHeader elf, Program program, List<Option> options,
			MessageLog log) {
		super(elf, program, options, log);
	}

	public static void loadElf(OrbisElfHeader elf, Program program, List<Option> options, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		OrbisElfProgramBuilder elfProgramBuilder =
			new OrbisElfProgramBuilder(elf, program, options, log);
		elfProgramBuilder.load(monitor);
	}

	@Override
	public OrbisElfHeader getElfHeader() {
		return (OrbisElfHeader) super.getElfHeader();
	}

	@Override
	protected void load(TaskMonitor monitor) throws IOException, CancelledException {
		OrbisElfHeader elf = getElfHeader();
		Memory memory = getMemory();
		monitor.setMessage("Completing ELF header parsing...");
		monitor.setCancelEnabled(false);
		elf.parse();
		monitor.setCancelEnabled(true);

		int id = program.startTransaction("Load ELF program");
		boolean success = false;
		try {

			addProgramProperties(monitor);

			setImageBase();
			program.setExecutableFormat(ElfLoader.ELF_NAME);

			// resolve segment/sections and create program memory blocks
			ByteProvider byteProvider = elf.getReader().getByteProvider();
			try (InputStream fileIn = byteProvider.getInputStream(0)) {
				FileBytes fileBytes = program.getMemory().createFileBytes(
					byteProvider.getName(), 0, byteProvider.length(), fileIn, monitor);
				setFileBytes(fileBytes);
			}

			// process headers and define "section" within memory elfProgramBuilder
			processProgramHeaders(monitor);
			processSectionHeaders(monitor);
			if (!elf.isKernel()) {
				processDynlibData();
			}

			resolve(monitor);

			if (elf.getSectionHeaderCount() == 0) {
				// create/expand segments to their fullsize if not sections are defined
				try {
					expandProgramHeaderBlocks(monitor);
				} catch (Exception e) {
					getLog().appendException(e);
				}
			}

			if (memory.isEmpty()) {
				// TODO: Does this really happen?
				success = true;
				return;
			}

			markupElfHeader(monitor);
			markupProgramHeaders(monitor);
			markupSectionHeaders(monitor);
			markupDynamicTable(monitor);
			markupInterpreter(monitor);

			processStringTables(monitor);

			processSymbolTables(monitor);

			elf.getLoadAdapter().processElf(this, monitor);

			processRelocations(monitor);
			processEntryPoints(monitor);
			processImports(monitor);

			monitor.setMessage("Processing PLT/GOT ...");
			elf.getLoadAdapter().processGotPlt(this, monitor);

			markupHashTable(monitor);
			markupGnuHashTable(monitor);
			markupPltGot(monitor);
			markupSceHashTable(monitor);

			processGNU(monitor);
			processGNU_readOnly(monitor);

			success = true;
		} finally {
			program.endTransaction(id, success);
		}
	}

	private void markupPltGot(TaskMonitor monitor) {
		MemoryBlock block = getMemory().getBlock(".plt.got");
		if (block == null) {
			block = getMemory().getBlock(".got.plt");
			if (block == null) {
				return;
			}
		}
		Address addr = block.getStart();
		int size = getProgram().getDefaultPointerSize();
		while (block.contains(addr)) {
			createData(addr, PointerDataType.dataType);
			addr = addr.add(size);
		}
	}

	protected void markupSceHashTable(TaskMonitor monitor) {
		OrbisElfHeader elf = getElfHeader();
		Listing listing = getProgram().getListing();
		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(DT_SCE_HASH)) {
			return;
		}
		DataType dt = DWordDataType.dataType;
		Address hashTableAddr = null;
		try {
			long value = dynamicTable.getDynamicValue(DT_SCE_HASH);
			if (value == 0) {
				return; // table has been stripped
			}

			MemoryBlock block = getMemory().getBlock(".sce_special");
			if (block == null) {
				return;
			}

			Address addr = block.getStart().add(value);
			Data d = listing.createData(addr, dt);
			d.setComment(CodeUnit.EOL_COMMENT, "Hash Table - nbucket");
			long nbucket = d.getScalar(0).getUnsignedValue();

			addr = addr.add(d.getLength());
			d = listing.createData(addr, dt);
			d.setComment(CodeUnit.EOL_COMMENT, "Hash Table - nchain");
			long nchain = d.getScalar(0).getUnsignedValue();

			addr = addr.add(d.getLength());
			d = listing.createData(addr, new ArrayDataType(dt, (int) nbucket, dt.getLength()));
			d.setComment(CodeUnit.EOL_COMMENT, "Hash Table - buckets");

			addr = addr.add(d.getLength());
			d = listing.createData(addr, new ArrayDataType(dt, (int) nchain, dt.getLength()));
			d.setComment(CodeUnit.EOL_COMMENT, "Hash Table - chains");
		}
		catch (Exception e) {
			log("Failed to properly markup Hash table at " + hashTableAddr + ": " + getMessage(e));
			return;
		}

	}

	@Override
	protected void processProgramHeaders(TaskMonitor monitor) throws CancelledException {

		ElfHeader elf = getElfHeader();
		FileBytes fileBytes = getFileBytes();
		if (elf.isRelocatable() && elf.getProgramHeaderCount() != 0) {
			log("Ignoring unexpected program headers for relocatable ELF (e_phnum=" +
				elf.getProgramHeaderCount() + ")");
			return;
		}

		monitor.setMessage("Processing program headers...");

		boolean includeOtherBlocks = shouldIncludeOtherBlocks();

		ElfProgramHeader[] elfProgramHeaders = elf.getProgramHeaders();
		for (int i = 0; i < elfProgramHeaders.length; ++i) {
			monitor.checkCanceled();
			ElfProgramHeader elfProgramHeader = elfProgramHeaders[i];
			if (elfProgramHeader.getType() == ElfProgramHeaderConstants.PT_NULL) {
				continue;
			}
			long fileOffset = elfProgramHeader.getOffset();
			if (elfProgramHeader.getType() != ElfProgramHeaderConstants.PT_LOAD) {
				if (!includeOtherBlocks) {
					continue;
				}
				if (fileOffset < 0 || fileOffset >= fileBytes.getSize()) {
					log("Skipping segment[" + i + ", " + elfProgramHeader.getDescription() +
						"] with invalid file offset");
					continue;
				}
				if (elf.getProgramLoadHeaderContainingFileOffset(fileOffset) != null) {
					conflicts.add(elfProgramHeader);
					continue;
				}
				ElfSectionHeader section = elf.getSectionHeaderContainingFileRange(fileOffset,
					elfProgramHeader.getFileSize());
				if (section != null) {
					log("Skipping segment[" + i + ", " + elfProgramHeader.getDescription() +
						"] included by section " + section.getNameAsString());
					continue;
				}
			}
			if (fileOffset < 0 || fileOffset >= fileBytes.getSize()) {
				log("Skipping PT_LOAD segment[" + i + ", " + elfProgramHeader.getDescription() +
					"] with invalid file offset");
				continue;
			}
			String name = getProgramHeaderName(elfProgramHeader, i);
			processProgramHeader(elfProgramHeader, name);
		}
	}

	public void splitConflictFragments(TaskMonitor monitor) throws CancelledException {
		try {
			for (ElfProgramHeader phdr : conflicts) {
				monitor.checkCanceled();
				String name = getProgramHeaderName(phdr, 0);
				Address start = getSegmentLoadAddress(phdr);
				createInitializedBlock(
					phdr, false, name, start, phdr.getOffset(),
					phdr.getAdjustedLoadSize(), getComment(phdr),
					phdr.isRead(), phdr.isWrite(), phdr.isExecute(),
					monitor);
			}
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			log(e);
			e.printStackTrace();
		}
	}

	private String getComment(ElfProgramHeader phdr) {
		Address address = getSegmentLoadAddress(phdr);
		AddressSpace space = address.getAddressSpace();
		long addr = phdr.getVirtualAddress();
		long fullSizeBytes =
			phdr.getAdjustedMemorySize() * space.getAddressableUnitSize();
		return getSectionComment(addr, fullSizeBytes, space.getAddressableUnitSize(),
				phdr.getDescription(), address.isLoadedMemoryAddress());
	}

	protected void processProgramHeader(ElfProgramHeader phdr, String name)
			throws AddressOutOfBoundsException {
		ElfHeader elf = getElfHeader();
		Address address = getSegmentLoadAddress(phdr);
		AddressSpace space = address.getAddressSpace();

		long addr = phdr.getVirtualAddress();
		long loadSizeBytes = phdr.getAdjustedLoadSize();
		long fullSizeBytes =
			phdr.getAdjustedMemorySize() * space.getAddressableUnitSize();

		boolean maintainExecuteBit = elf.getSectionHeaderCount() == 0;

		if (phdr.getType() == PT_SCE_DYNLIBDATA_VALUE) {
			fullSizeBytes = loadSizeBytes;
		}

		if (fullSizeBytes <= 0) {
			log("Skipping zero-length segment [" + name + "," +
				phdr.getDescription() + "] at address " + address.toString(true));
			return;
		}

		if (!space.isValidRange(address.getOffset(), fullSizeBytes)) {
			log("Skipping unloadable segment [" + name + "] at address " +
				address.toString(true) + " (size=" + fullSizeBytes + ")");
			return;
		}

		try {

			String comment = getSectionComment(addr, fullSizeBytes, space.getAddressableUnitSize(),
				phdr.getDescription(), address.isLoadedMemoryAddress());
			if (!maintainExecuteBit && phdr.isExecute()) {
				comment += " (disabled execute bit)";
			}

			if (loadSizeBytes != 0) {
				addInitializedMemorySection(phdr, phdr.getOffset(),
					loadSizeBytes, address, name, phdr.isRead(),
					phdr.isWrite(),
					maintainExecuteBit ? phdr.isExecute() : false, comment,
					true, phdr.getType() == ElfProgramHeaderConstants.PT_LOAD);
			}
		} catch (AddressOverflowException e) {
			log("Failed to load segment [" + name + "]: " + getMessage(e));
		}
	}

	private static String getProgramHeaderName(ElfProgramHeader phdr, int i) {
		if (phdr.getElfHeader().getSectionHeaderCount() != 0) {
			return "segment_"+Integer.toString(i);
		}
		switch(phdr.getType()) {
			case ElfProgramHeaderConstants.PT_LOAD:
				if (phdr.isExecute()) {
					return ".text";
				}
				if (phdr.isWrite()) {
					return ".data";
				}
				return ".rodata";
			case PT_SCE_RELRO_VALUE:
				return ".data.rel.ro";
			case ElfProgramHeaderConstants.PT_DYNAMIC:
				return ".dynamic";
			case ElfProgramHeaderConstants.PT_TLS:
				return ".tdata";
			case ElfProgramHeaderConstants.PT_GNU_EH_FRAME:
				return ".eh_frame_hdr";
			case PT_SCE_DYNLIBDATA_VALUE:
				return OrbisUtil.SCE_SPECIAL_SECTION;
			case PT_SCE_LIBVERSION_VALUE:
				return ".libversion";
			case PT_SCE_COMMENT_VALUE:
				return ".comment";
			case PT_SCE_PROCPARAM_VALUE:
				return ".sce_process_param";
			case PT_SCE_MODULEPARAM_VALUE:
				return ".sce_module_param";
			case ElfProgramHeaderConstants.PT_INTERP:
				return ".interp";
			case ElfProgramHeaderConstants.PT_PHDR:
				return "_elfProgramHeaders";
			default:
				return "segment_"+Integer.toString(i);
		}
	}

	private void processDynlibData() {
		try {
			OrbisElfHeader elf = getElfHeader();
			elf.parseDynamicStringTable();
			elf.parseDynamicSymbolTable();
			elf.parseDynamicLibraryNames();
			elf.parseRelocationTables();
		} catch (Exception e) {
			log(e);
		}
	}
}
