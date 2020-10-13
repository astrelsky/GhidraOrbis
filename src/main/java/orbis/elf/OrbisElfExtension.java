package orbis.elf;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.sections.EhFrameHeaderSection;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.extend.ElfExtension;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import orbis.data.OrbisDataUtils;
import orbis.db.ImportManager;
import orbis.util.OrbisUtil;

import static ghidra.app.util.bin.format.elf.ElfDynamicType.*;

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

	private static final SegmentSection[] SEGMENT_SECTIONS = new SegmentSection[]{
		new SegmentSection(ElfProgramHeaderConstants.PT_INTERP, ".interp"),
	};

	// dynamic types
	public static final ElfDynamicType DT_SCE_IDTABENTSZ = new ElfDynamicType(
		0x61000005, "SCE_IDTABENTSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_FINGERPRINT = new ElfDynamicType(
		0x61000007, "SCE_FINGERPRINT", "", ElfDynamicValueType.VALUE);
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

	private static final DynamicSegmentSection[] DYNAMIC_SECTIONS = new DynamicSegmentSection[]{
		new DynamicSegmentSection(DT_INIT.value, ".init", -2),
		new DynamicSegmentSection(DT_FINI.value, ".fini", -2),
		new DynamicSegmentSection(DT_INIT_ARRAY.value, ".init_array", DT_INIT_ARRAYSZ.value),
		new DynamicSegmentSection(DT_FINI_ARRAY.value, ".fini_array", DT_FINI_ARRAYSZ.value),
		new DynamicSegmentSection(DT_SCE_PLTGOT.value, ".plt.got", -1),
	};

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
				splitDynamicSegment(helper, monitor);
				setupLibraryMap(helper, monitor);
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				helper.getLog().appendException(e);
			}
			markupFingerprint(helper);
		}
		try {
			splitSegments(helper, monitor);
			fixEhFrame(helper, monitor);
			markupParamSection(helper);
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			helper.getLog().appendException(e);
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
		if (struct.hasFlexibleArrayComponent()) {
			DataTypeComponent flexComp = struct.getFlexibleArrayComponent();
			DataType dt = flexComp.getDataType();
			Scalar count = (Scalar) data.getComponent(PARAM_SIZE_ORDINAL).getValue();
			ArrayDataType array = new ArrayDataType(dt, (int) count.getValue(), dt.getLength());
			listing.createData(data.getAddress().add(flexComp.getOffset()), array);
		}
	}

	private void splitSegments(ElfLoadHelper helper, TaskMonitor monitor) throws Exception {
		OrbisElfHeader elf = (OrbisElfHeader) helper.getElfHeader();
		Program program = helper.getProgram();
		for (SegmentSection seg : SEGMENT_SECTIONS) {
			monitor.checkCanceled();
			for (ElfProgramHeader phdr : elf.getProgramHeaders(seg.type)) {
				monitor.checkCanceled();
				Address start = helper.getDefaultAddress(phdr.getVirtualAddress());
				seg.move(program, start, phdr.getMemorySize());
				break;
			}
		}
	}

	private void splitDynamicSegment(ElfLoadHelper helper, TaskMonitor monitor)
			throws Exception {
		OrbisElfHeader elf = (OrbisElfHeader) helper.getElfHeader();
		ElfDynamicTable table = elf.getDynamicTable();
		Program program = helper.getProgram();
		Memory mem = program.getMemory();
		for (DynamicSegmentSection seg : DYNAMIC_SECTIONS) {
			monitor.checkCanceled();
			for (ElfDynamic dynamic : table.getDynamics(seg.type)) {
				monitor.checkCanceled();
				Address start = helper.getDefaultAddress(dynamic.getValue());
				long size = -1;
				if (seg.sizeType == -1) {
					MemoryBlock block = mem.getBlock(start);
					size = block.getEnd().subtract(start);
				} else if (seg.sizeType == -2) {
					BackgroundCommand cmd = new DisassembleCommand(start, null, true);
					if (cmd.applyTo(program, monitor)) {
						cmd = new CreateFunctionCmd(start);
						cmd.applyTo(program, monitor);
						Function fun = ((CreateFunctionCmd) cmd).getFunction();
						fun.setName(seg.name.replace(".", "_"), SourceType.IMPORTED);
						size = fun.getBody().getMaxAddress().subtract(start);
						if (seg.type == DT_FINI.value) {
							Address roAddress = fun.getBody().getMaxAddress().next();
							MemoryBlock block = mem.getBlock(roAddress);
							long roLength = block.getEnd().subtract(roAddress);
							SegmentSection roSeg = new SegmentSection(-1, ".rodata");
							roSeg.move(program, roAddress, roLength);
						}
					}
				} else {
					for (ElfDynamic sizeDynamic : table.getDynamics(seg.sizeType)) {
						monitor.checkCanceled();
						size = sizeDynamic.getValue();
						break;
					}
				}
				if (size <= 0) {
					continue;
				}
				seg.move(program, start, size);
				if (seg.sizeType == -2) {
					MemoryBlock block = mem.getBlock(start);
					block.setExecute(true);
				}
				break;
			}
		}
	}

	private void markupFingerprint(ElfLoadHelper helper) {
		Program program = helper.getProgram();
		MemoryBlock block = OrbisUtil.getSpecialBlock(program);
		if (block != null) {
			try {
				Address address = block.getStart();
				ArrayDataType dt = new ArrayDataType(Undefined1DataType.dataType, 0x14, 1);
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

	private static class SegmentSection {
		protected final int type;
		protected final String name;

		SegmentSection(int type, String name) {
			this.type = type;
			this.name = name;
		}

		void move(Program program, Address start, long size) throws Exception {
			Memory mem = program.getMemory();
			Listing listing = program.getListing();
			ProgramModule root = listing.getDefaultRootModule();
			MemoryBlock block = mem.getBlock(start);
			if (start.equals(block.getStart())) {
				String name = block.getName();
				Address end = start.add(size).next();
				mem.split(block, end);
				block = mem.getBlock(start);
				block.setName(this.name);
				ProgramFragment frag = root.createFragment(this.name);
				frag.move(start, block.getEnd());
				block = mem.getBlock(end);
				block.setName(name);
				frag = program.getListing().getFragment(root.getTreeName(), name);
				frag.move(block.getStart(), block.getEnd());
			} else {
				mem.split(block, start);
				ProgramFragment frag =
					program.getListing().getFragment(root.getTreeName(), block.getName());
				frag.move(block.getStart(), block.getEnd());
				block = mem.getBlock(start);
				block.setName(this.name);
				frag = root.createFragment(this.name);
				frag.move(start, block.getEnd());
			}
			block = mem.getBlock(start);
			block.setExecute(false);
			block.setWrite(false);
		}
	}

	private static class DynamicSegmentSection extends SegmentSection {
		private final int sizeType;

		DynamicSegmentSection(int type, String name, int sizeType) {
			super(type, name);
			this.sizeType = sizeType;
		}
	}

}
