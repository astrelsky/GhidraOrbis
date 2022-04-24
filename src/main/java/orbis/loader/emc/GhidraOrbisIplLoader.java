package orbis.loader.emc;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.DefaultElfProgramBuilder;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import orbis.bin.ipl.EncryptedDataException;
import orbis.bin.ipl.IplHeader;
import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;

public class GhidraOrbisIplLoader extends AbstractProgramLoader {

	private static final LanguageCompilerSpecPair SPEC =
		new LanguageCompilerSpecPair("ARM:LE:32:v7", "default");
	public static final String MAP_NAME = "Encryption Keys";
	private static final String CIPHER_KEY = "Cipher Key";
	private static final String HASHER_KEY = "Hasher Key";
	private static final String HEADER_BLOCK_NAME = "_header";
	public static final String IPL_PROPERTY_NAME = "IPL Format";

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		IplHeader header = new IplHeader(provider);
		if (header.isValid()) {
			LoadSpec spec = new LoadSpec(this, 0, SPEC, true);
			return Set.of(spec);
		}
		return Collections.emptySet();
	}

	@Override
	public String getName() {
		return getClass().getSimpleName();
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	@Override
	protected List<Program> loadProgram(ByteProvider provider, String programName,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, TaskMonitor monitor) throws IOException, CancelledException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec importerCompilerSpec =
			importerLanguage.getCompilerSpecByID(pair.compilerSpecID);
		AddressSpace defaultSpace = importerLanguage.getAddressFactory().getDefaultAddressSpace();
		Address baseAddr = defaultSpace.getAddress(0);
		Program prog = createProgram(provider, programName, baseAddr, getName(), importerLanguage,
			importerCompilerSpec, consumer);
		boolean success = false;
		try {
			success = loadInto(provider, loadSpec, options, log, prog, monitor);
			if (success) {
				createDefaultMemoryBlocks(prog, importerLanguage, log);
			}
		} catch (Exception e) {
			throw new AssertException(e);
		} finally {
			if (!success) {
				prog.release(consumer);
				prog = null;
			}
		}
		return prog != null ? List.of(prog) : Collections.emptyList();
	}

	@Override
	protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		boolean success = false;
		IplHeader header = new IplHeader(provider);
		try {
			header.decrypt(getKey(options, CIPHER_KEY), getKey(options, HASHER_KEY));
		} catch (EncryptedDataException e) {
			Msg.showInfo(this, null, "Import Failed", e.getMessage());
			return false;
		} catch (Exception e) {
			log.appendException(e);
			return false;
		}
		InputStream headerStream = null;
		InputStream bodyStream = null;
		try {
			headerStream = header.getHeaderInputStream();
			bodyStream = header.getBodyInputStream();
			Memory mem = program.getMemory();
			AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
			Address base = defaultSpace.getAddress(0);
			FileBytes bytes = mem.createFileBytes(
				program.getName(), 0, header.getHeaderLength(), headerStream, monitor);
			if (header.isEAP()) {
				ByteProvider bp = header.getBodyProvider(provider.getFSRL());
				ElfHeader elf = new ElfHeader(bp, log::appendMsg);
				DefaultElfProgramBuilder.loadElf(elf, program, options, log, monitor);
			} else {
				base = defaultSpace.getAddress(header.getLoadAddress0());
				bytes = mem.createFileBytes(
					program.getName(), 0, header.getBodyLength(), bodyStream, monitor);
				MemoryBlock block = mem.createInitializedBlock(
					"body", base, bytes, 0, header.getBodyLength(), true);
				block.setRead(true);
				block.setWrite(false);
				block.setExecute(true);
			}
			MemoryBlock block = mem.createInitializedBlock(
				HEADER_BLOCK_NAME, base, bytes, 0, header.getHeaderLength(), true);
			block.setRead(false);
			block.setWrite(false);
			block.setExecute(false);
			program.getDataTypeManager().resolve(header.toDataType(), KEEP_HANDLER);
			program.getUsrPropertyManager().createVoidPropertyMap(IPL_PROPERTY_NAME);
			success = true;
		} catch (Exception e) {
			log.appendException(e);
			e.printStackTrace();
		} finally {
			if (headerStream != null) {
				headerStream.close();
			}
			if (bodyStream != null) {
				bodyStream.close();
			}
		}
		return success;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list = new ArrayList<Option>();
		list.add(new Option(CIPHER_KEY, String.class));
		list.add(new Option(HASHER_KEY, String.class));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram));
		return list;
	}

	private String getKey(List<Option> options, String name) {
		return options.stream()
			.filter(o -> o.getName().equals(name))
			.map(Option::getValue)
			.map(String.class::cast)
			.findFirst()
			.orElse(null);
	}

	@Override
	protected void postLoadProgramFixups(List<Program> loadedPrograms, DomainFolder folder,
			List<Option> options, MessageLog log, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (loadedPrograms.isEmpty()) {
			return;
		}
		DataType dt = IplHeader.dataType;
		Program program = loadedPrograms.get(0);
		int id = program.startTransaction("Creating Header");
		boolean success = false;
		try {
			String cipherKey = getKey(options, CIPHER_KEY);
			String hasherKey = cipherKey != null ? getKey(options, HASHER_KEY) : null;
			if (cipherKey != null) {
				AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
				StringPropertyMap map = program.getUsrPropertyManager().createStringPropertyMap(MAP_NAME);
				map.add(defaultSpace.getAddress(0), cipherKey);
				map.add(defaultSpace.getAddress(1), hasherKey);
			}
			Listing listing = program.getListing();
			Address base = program.getMemory().getBlock(HEADER_BLOCK_NAME).getStart();
			listing.createData(base, dt);
			success = true;
		} catch (Exception e) {
			log.appendException(e);
		} finally {
			program.endTransaction(id, success);
		}
	}

}
