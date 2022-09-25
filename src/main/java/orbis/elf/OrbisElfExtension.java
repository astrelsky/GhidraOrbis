package orbis.elf;

import java.lang.reflect.Field;
import java.util.List;

import ghidra.app.plugin.exceptionhandlers.gcc.sections.EhFrameHeaderSection;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.extend.ElfExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import orbis.data.OrbisDataUtils;
import orbis.db.ImportManager;
import orbis.elf.blockmaker.KernelReadOnlyBlockMaker;
import orbis.elf.blockmaker.ProgramReadOnlyBlockMaker;
import orbis.elf.blockmaker.ReadOnlyBlockMaker;
import orbis.elf.fragment.DynamicFragmentBuilder;
import orbis.elf.fragment.FragmentBuilder;
import orbis.elf.fragment.ProgramHeaderFragmentBuilder;
import orbis.util.OrbisUtil;

public class OrbisElfExtension extends ElfExtension {

	private static final String EH_FRAME = ".eh_frame";
	private static final String EH_FRAME_HDR = EH_FRAME + "_hdr";
	private static final String PRX_LIB_EXTENSION = ".prx";
	private static final int PARAM_SIZE_ORDINAL = 2;
	public static final int DT_SCE_STRTAB_TAG = 0x61000035;
	public static final int DT_SCE_STRSZ_TAG = 0x61000037;
	public static final int DT_SCE_SYMTAB_TAG = 0x61000039;
	public static final int DT_INIT_TAG = 12;
	public static final int DT_FINI_TAG = 13;
	public static final int DT_SCE_PLTGOT_TAG = 0x61000027;
	public static final int DT_JMPREL_TAG = 23;
	public static final int PT_SCE_DYNLIBDATA_VALUE = 0x61000000;

	public static final ElfProgramHeaderType PT_SCE_RELA = new ElfProgramHeaderType(
		0x60000000, "SCE_RELA", "");
	public static final ElfProgramHeaderType PT_SCE_DYNLIBDATA = new ElfProgramHeaderType(
		0x61000000, "SCE_DYNLIBDATA", "");
	public static final ElfProgramHeaderType PT_SCE_PROCPARAM = new ElfProgramHeaderType(
		0x61000001, "SCE_PROCPARAM", "");
	public static final ElfProgramHeaderType PT_SCE_MODULEPARAM = new ElfProgramHeaderType(
		0x61000002, "SCE_MODULEPARAM", "");
	public static final ElfProgramHeaderType PT_SCE_RELRO = new ElfProgramHeaderType(
		0x61000010, "SCE_RELRO", "");
	public static final ElfProgramHeaderType PT_SCE_COMMENT = new ElfProgramHeaderType(
		0x6FFFFF00, "SCE_COMMENT", "");
	public static final ElfProgramHeaderType PT_SCE_LIBVERSION = new ElfProgramHeaderType(
		0x6FFFFF01, "SCE_LIBVERSION", "");
	public static final ElfProgramHeaderType PT_SCE_SEGSYM = new ElfProgramHeaderType(
		0x700000A8, "SCE_SEGSYM", "");

	// dynamic types
	public static final ElfDynamicType DT_SCE_IDTABENTSZ = new ElfDynamicType(
		0x61000005, "SCE_IDTABENTSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_FINGERPRINT = new ElfDynamicType(
		0x61000007, "SCE_FINGERPRINT", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_ORIGINAL_FILENAME = new ElfDynamicType(
		0x61000009, "SCE_ORIGINAL_FILENAME", "", ElfDynamicValueType.STRING);
	public static final ElfDynamicType DT_SCE_MODULE_INFO = new ElfDynamicType(
		0x6100000D, "SCE_MODULE_INFO", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_NEEDED_MODULE = new ElfDynamicType(
		0x6100000F, "SCE_NEEDED_MODULE", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_MODULE_ATTR = new ElfDynamicType(
		0x61000011, "SCE_MODULE_ATTR", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_EXPORT_LIB = new ElfDynamicType(
		0x61000013, "SCE_EXPORT_LIB", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_IMPORT_LIB = new ElfDynamicType(
		0x61000015, "SCE_IMPORT_LIB", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_EXPORT_LIB_ATTR = new ElfDynamicType(
		0x61000017, "SCE_EXPORT_LIB_ATTR", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_IMPORT_LIB_ATTR = new ElfDynamicType(
		0x61000019, "SCE_IMPORT_LIB_ATTR", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_STUB_MODULE_NAME = new ElfDynamicType(
		0x6100001D, "SCE_STUB_MODULE_NAME", "", ElfDynamicValueType.STRING);
	public static final ElfDynamicType DT_SCE_STUB_MODULE_VERSION = new ElfDynamicType(
		0x6100001F, "SCE_STUB_MODULE_VERSION", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_STUB_LIBRARY_NAME = new ElfDynamicType(
		0x61000021, "SCE_STUB_LIBRARY_NAME", "", ElfDynamicValueType.STRING);
	public static final ElfDynamicType DT_SCE_STUB_LIBRARY_VERSION = new ElfDynamicType(
		0x61000023, "SCE_STUB_LIBRARY_VERSION", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_HASH = new ElfDynamicType(
		0x61000025, "SCE_HASH", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_PLTGOT = new ElfDynamicType(
		0x61000027, "SCE_PLTGOT", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_JMPREL = new ElfDynamicType(
		0x61000029, "SCE_JMPREL", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_PLTREL = new ElfDynamicType(
		0x6100002B, "SCE_PLTREL", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_PLTRELSZ = new ElfDynamicType(
		0x6100002D, "SCE_PLTRELSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_RELA = new ElfDynamicType(
		0x6100002F, "SCE_RELA", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_RELASZ = new ElfDynamicType(
		0x61000031, "SCE_RELASZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_RELAENT = new ElfDynamicType(
		0x61000033, "SCE_RELAENT", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_STRTAB = new ElfDynamicType(
		0x61000035, "SCE_STRTAB", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_STRSZ = new ElfDynamicType(
		0x61000037, "SCE_STRSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_SYMTAB = new ElfDynamicType(
		0x61000039, "SCE_SYMTAB", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_SYMENT = new ElfDynamicType(
		0x6100003B, "SCE_SYMENT", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_HASHSZ = new ElfDynamicType(
		0x6100003D, "SCE_HASHSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_SYMTABSZ = new ElfDynamicType(
		0x6100003F, "SCE_SYMTABSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_HIOS = new ElfDynamicType(
		0x6FFFF000, "SCE_HIOS", "", ElfDynamicValueType.VALUE);

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf instanceof OrbisElfHeader;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return canHandle(elfLoadHelper.getElfHeader());
	}

	@Override
	public String getDataTypeSuffix() {
		return null;
	}

	@Override
	public void processElf(ElfLoadHelper helper, TaskMonitor monitor) throws CancelledException {
		OrbisElfHeader elf = (OrbisElfHeader) helper.getElfHeader();
		ElfDynamicTable table = elf.getDynamicTable();
		if (table != null) {
			try {
				for (ElfDynamic dynamic : table.getDynamics()) {
					monitor.checkCanceled();
					ElfDynamicType tagType = dynamic.getTagType();
					if (tagType == null) {
						continue;
					}
					if (DynamicFragmentBuilder.canHandle(dynamic.getTagType())) {
						FragmentBuilder builder = new DynamicFragmentBuilder(helper, dynamic);
						builder.move();
					}
				}
				fixDynamicLabels(helper, monitor);
				setupLibraryMap(helper, monitor);
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				helper.getLog().appendException(e);
			}
			markupFingerprint(helper);
		}
		try {
			if (elf.getSections().length == 0) {
				int i = 0;
				for (ElfProgramHeader phdr : elf.getProgramHeaders()) {
					monitor.checkCanceled();
					if (ProgramHeaderFragmentBuilder.canHandle(phdr)) {
						FragmentBuilder builder =
							new ProgramHeaderFragmentBuilder(helper, phdr, i++);
						builder.move();
					}
				}
				fixEhFrame(helper, monitor);
				splitElfHeader(helper, monitor);
				fixDynamicSection(helper);
			}
			markupParamSection(helper);
			fixBlockNames(helper);
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			helper.getLog().appendException(e);
		}
	}

	@Override
	public void processGotPlt(ElfLoadHelper helper, TaskMonitor monitor)
			throws CancelledException {
		OrbisElfHeader elf = (OrbisElfHeader) helper.getElfHeader();
		if (elf.getSections().length != 0) {
			return;
		}
		ReadOnlyBlockMaker maker;
		if (elf.isKernel()) {
			maker = new KernelReadOnlyBlockMaker(helper, monitor);
		} else {
			maker = new ProgramReadOnlyBlockMaker(helper, monitor);
		}
		try {
			maker.makeBlock();
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			helper.log(e);
		}
	}

	private void fixBlockNames(ElfLoadHelper helper) throws Exception {
		Program program = helper.getProgram();
		Listing listing = program.getListing();
		Memory mem = program.getMemory();
		ProgramModule root = listing.getDefaultRootModule();
		ProgramFragment frag = listing.getFragment(root.getTreeName(), ".text");
		if (frag != null) {
			MemoryBlock block = mem.getBlock(frag.getMinAddress());
			block.setName(".text");
		}
		frag = listing.getFragment(root.getTreeName(), ".data");
		if (frag != null) {
			MemoryBlock block = mem.getBlock(frag.getMinAddress());
			block.setName(".data");
		}
	}

	private void fixDynamicLabels(ElfLoadHelper helper, TaskMonitor monitor) throws Exception {
		OrbisElfHeader elf = (OrbisElfHeader) helper.getElfHeader();
		ElfDynamicTable table = elf.getDynamicTable();
		Program program = helper.getProgram();
		SymbolTable symTable = program.getSymbolTable();
		for (ElfDynamic dynamic : table.getDynamics()) {
			monitor.checkCanceled();
			String symbolName = "__"+dynamic.getTagAsString();
			List<Symbol> symbols = symTable.getGlobalSymbols(symbolName);
			if (symbols.size() == 1) {
				Symbol symbol = symbols.get(0);
				Address symbolAddress = getSceSpecialAddress(symbol);
				if (symbolAddress == null) {
					return;
				}
				symbol.delete();
				symTable.createLabel(symbolAddress, symbolName, SourceType.IMPORTED);
			}
		}
	}

	private static Address getSceSpecialAddress(Symbol symbol) {
		Memory mem = symbol.getProgram().getMemory();
		MemoryBlock block = mem.getBlock(".sce_special");
		if (block == null) {
			return null;
		}
		AddressSpace space = block.getStart().getAddressSpace();
		return space.getAddress(symbol.getAddress().getOffset());
	}

	private void fixDynamicSection(ElfLoadHelper helper) throws Exception {
		Listing listing = helper.getProgram().getListing();
		ProgramModule root = listing.getDefaultRootModule();
		if (listing.getFragment(root.getTreeName(), ".sce_special") != null) {
			ProgramFragment frag = listing.getFragment(root.getTreeName(), ".dynamic");
			Field f = frag.getClass().getDeclaredField("addrSet");
			f.setAccessible(true);
			AddressSet set = (AddressSet) f.get(frag);
			f.setAccessible(false);
			set.clear();
			root.removeChild(".dynamic");
		}
	}

	private void splitElfHeader(ElfLoadHelper helper, TaskMonitor monitor) throws Exception {
		Program program = helper.getProgram();
		Listing listing = program.getListing();
		ProgramModule root = listing.getDefaultRootModule();
		if (listing.getFragment(root.getTreeName(), "_elfHeader") != null) {
			return;
		}
		for (Data data : listing.getDefinedData(true)) {
			monitor.checkCanceled();
			if (data.getDataType().getName().equals("Elf64_Ehdr")) {
				Memory mem = program.getMemory();
				MemoryBlock block = mem.getBlock(data.getAddress());
				String blockName = block.getName();
				block.setExecute(false);
				block.setName("_elfHeader");
				block = mem.getBlock(data.getAddress());
				ProgramFragment frag = root.createFragment("_elfHeader");
				frag.move(block.getStart(), block.getEnd());
				frag = listing.getFragment(root.getTreeName(), blockName);
				if (frag.getMinAddress() != null) {
					block = mem.getBlock(frag.getMinAddress());
					block.setName(frag.getName());
				}
				return;
			}
		}
	}

	private void setupLibraryMap(ElfLoadHelper helper, TaskMonitor monitor) throws Exception {
		ImportManager man = new ImportManager(helper.getProgram());
		OrbisElfHeader elf = (OrbisElfHeader) helper.getElfHeader();
		ElfDynamicTable table = elf.getDynamicTable();
		ElfStringTable stringTable = elf.getDynamicStringTable();
		BinaryReader reader = elf.getReader();
		for (ElfDynamic dynamic : table.getDynamics(DT_SCE_IMPORT_LIB)) {
			monitor.checkCanceled();
			long value = dynamic.getValue();
			long offset =  value & 0xffffffffL;
			long id = value >> 48;
			String libName = stringTable.readString(reader, offset) + PRX_LIB_EXTENSION;
			man.addLibrary(libName, id);
		}
	}

	private void markupParamSection(ElfLoadHelper helper) throws Exception {
		Program program = helper.getProgram();
		Listing listing = program.getListing();
		Memory mem = program.getMemory();
		Structure struct = null;
		MemoryBlock block = mem.getBlock(".sce_process_param");
		if (block != null) {
			struct = OrbisDataUtils.procParamDataType;
		} else {
			block = mem.getBlock(".sce_module_param");
			if (block != null) {
				struct = OrbisDataUtils.moduleParamDataType;
			}
		}
		if (struct == null) {
			return;
		}
		Data data = listing.createData(block.getStart(), struct);
		DataTypeComponent[] comps = struct.getComponents();
		if (comps.length == 0) {
			return;
		}
		DataTypeComponent flexComp = comps[comps.length - 1];
		if (!(flexComp.getDataType() instanceof Array)) {
			return;
		}
		if (((Array) flexComp.getDataType()).getNumElements() != 0) {
			return;
		}
		DataType dt = PointerDataType.dataType;
		Scalar count = (Scalar) data.getComponent(PARAM_SIZE_ORDINAL).getValue();
		ArrayDataType array = new ArrayDataType(dt, (int) count.getValue(), dt.getLength());
		listing.createData(data.getAddress().add(flexComp.getOffset()), array);
	}

	private void markupFingerprint(ElfLoadHelper helper) {
		Program program = helper.getProgram();
		MemoryBlock block = OrbisUtil.getSpecialBlock(program);
		if (block != null) {
			try {
				Address address = block.getStart();
				ArrayDataType dt = new ArrayDataType(ByteDataType.dataType, 0x14, 1);
				helper.createData(address, dt);
				helper.createSymbol(address, "SCE_FINGERPRINT", true, false, null);
			} catch (InvalidInputException e) {
				throw new AssertException(e);
			}
		}
	}

	private void fixEhFrame(ElfLoadHelper helper, TaskMonitor monitor) {
		OrbisElfHeader elf = (OrbisElfHeader) helper.getElfHeader();
		Program program = helper.getProgram();
		ElfProgramHeader[] phdrs = elf.getProgramHeaders(ElfProgramHeaderConstants.PT_GNU_EH_FRAME);
		if (phdrs != null && phdrs.length == 1) {
			try {
				ElfProgramHeader phdr = phdrs[0];
				Address addr = helper.getDefaultAddress(phdr.getVirtualAddress());
				Memory mem = program.getMemory();
				MemoryBlock block = mem.getBlock(addr);
				mem.split(block, addr);
				block = mem.getBlock(addr);
				block.setName(EH_FRAME_HDR);
				Listing listing = program.getListing();
				ProgramModule root = listing.getDefaultRootModule();
				ProgramFragment fragment = root.createFragment(EH_FRAME_HDR);
				fragment.move(block.getStart(), block.getEnd());
				EhFrameHeaderSection section = new EhFrameHeaderSection(program);
				section.analyze(monitor);
				Reference[] refs = listing.getDataAfter(addr).getReferencesFrom();
				if (refs != null && refs.length == 1) {
					addr = refs[0].getToAddress();
					block = mem.getBlock(addr);
					mem.split(block, addr);
					block = mem.getBlock(addr);
					block.setName(EH_FRAME);
					fragment = root.createFragment(EH_FRAME);
					fragment.move(block.getStart(), block.getEnd());
				}
			} catch (Exception e) {
				helper.log(e);
			}
		}
	}

}
