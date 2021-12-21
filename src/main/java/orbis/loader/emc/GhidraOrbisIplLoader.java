package orbis.loader.emc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
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
import ghidra.util.NumericUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import orbis.bin.ipl.IplHeader;
import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;

public class GhidraOrbisIplLoader extends AbstractProgramLoader {

	private static final LanguageCompilerSpecPair SPEC =
		new LanguageCompilerSpecPair("ARM:LE:32:v7", "default");
	private static final String OPTION_KEY = "Key";
	private static final String HEADER_BLOCK_NAME = "_header";

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
			List<Option> options, MessageLog messageLog, Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		byte[] data;
		boolean success = false;
		IplHeader header = new IplHeader(provider);
		try {
			data = header.getData(getKeyBytes(options));
		} catch (Exception e) {
			messageLog.appendException(e);
			return false;
		}
		ByteProvider decProvider = new ByteArrayProvider(data);
		ByteProvider bodyProvider = null;
		ByteProvider headerProvider = null;
		try {
			bodyProvider = new ByteProviderWrapper(
				decProvider, header.getHeaderLength(), header.getBodyLength());
			Memory mem = program.getMemory();
			AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
			headerProvider = new ByteProviderWrapper(
				decProvider, 0, header.getHeaderLength());
			Address base = defaultSpace.getAddress(0);
			FileBytes bytes = mem.createFileBytes(
				program.getName(), 0, header.getHeaderLength(),
				headerProvider.getInputStream(0), monitor);
			MemoryBlock block = mem.createInitializedBlock(
				HEADER_BLOCK_NAME, base, bytes, 0, header.getHeaderLength(), true);
			block.setRead(false);
			block.setWrite(false);
			block.setExecute(false);
			program.getDataTypeManager().resolve(header.toDataType(), KEEP_HANDLER);
			base = defaultSpace.getAddress(header.getLoadAddress0());
			block = mem.createInitializedBlock(
				"body", base, bodyProvider.getInputStream(0),
				header.getBodyLength(), monitor, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			success = true;
		} catch (Exception e) {
			messageLog.appendException(e);
		} finally {
			if (bodyProvider != null) {
				bodyProvider.close();
			}
			if (headerProvider != null) {
				headerProvider.close();
			}
		}
		return success;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list = new ArrayList<Option>();
		list.add(new Option(OPTION_KEY, String.class));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		try {
			IplHeader header = new IplHeader(provider);
			if (header.isEncrypted()) {
				String key = getKey(options);
				if (key.isBlank()) {
					return "Invalid decryption key";
				}
			}
		} catch (Exception e) {
			return e.getMessage();
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	private String getKey(List<Option> options) {
		String key = "";
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_KEY)) {
					key = (String) option.getValue();
				}
			}
		}
		return key;
	}

	private byte[] getKeyBytes(List<Option> options) {
		String key = getKey(options);
		return NumericUtilities.convertStringToBytes(key);
	}

	@Override
	protected void postLoadProgramFixups(List<Program> loadedPrograms, DomainFolder folder,
			List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		DataType dt = IplHeader.dataType;
		Program program = loadedPrograms.get(0);
		int id = program.startTransaction("Creating Header");
		boolean success = false;
		try {
			Listing listing = program.getListing();
			Address base = program.getMemory().getBlock(HEADER_BLOCK_NAME).getStart();
			listing.createData(base, dt);
			success = true;
		} catch (Exception e) {
			messageLog.appendException(e);
		} finally {
			program.endTransaction(id, success);
		}
	}

}
