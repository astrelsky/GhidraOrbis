package orbis.loader;

import java.io.IOException;
import java.util.*;
import java.math.BigInteger;


import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import orbis.elf.OrbisElfHeader;
import orbis.elf.OrbisElfProgramBuilder;

public class GhidraOrbisElfLoader extends ElfLoader {

	protected static final short ORBIS_MACHINE_TYPE = 0x3e;
	private static final LanguageCompilerSpecPair LANGUAGE =
		new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");

	@Override
	public String getName() {
		return "Orbis ELF";
	}

	protected final Collection<LoadSpec> findSupportedLoadSpecs(ElfHeader header) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		short type = header.e_type();
		short machine = header.e_machine();

		if(machine != ORBIS_MACHINE_TYPE) {
			return loadSpecs;
		}
		switch(type) {
			case OrbisElfHeader.ET_SCE_KERNEL:
				if (header.findImageBase() >= 0) {
					return loadSpecs;
				}
			case OrbisElfHeader.ET_SCE_EXEC:
			case OrbisElfHeader.ET_SCE_REPLAY_EXEC:
			case OrbisElfHeader.ET_SCE_RELEXEC:
			case OrbisElfHeader.ET_SCE_STUBLIB:
			case OrbisElfHeader.ET_SCE_DYNEXEC:
			case OrbisElfHeader.ET_SCE_DYNAMIC:
				break;
			default:
				return loadSpecs;
		}

		loadSpecs.add(new LoadSpec(this, header.findImageBase(), LANGUAGE, true));

		return loadSpecs;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		try {
			return findSupportedLoadSpecs(getElfHeader(provider));
		} catch (ElfException e) {
			return Collections.emptyList();
		}
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		try {
			GenericFactory factory = MessageLogContinuesFactory.create(log);
			OrbisElfHeader elf = OrbisElfHeader.createElfHeader(factory, provider);
			OrbisElfProgramBuilder.loadElf(elf, program, options, log, monitor);
			program.getUsrPropertyManager().createVoidPropertyMap("orbis");
		} catch (DuplicateNameException e) {
			log.appendException(e);
		} catch (ElfException e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return super.getTierPriority() - 1;
	}

	private static OrbisElfHeader getElfHeader(ByteProvider provider)
			throws ElfException, IOException {
		OrbisElfHeader elfHeader =
			OrbisElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
		return elfHeader;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> options =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		Option baseOption = options.stream()
			.filter(o -> o.getName().equals("Image Base"))
			.findFirst()
			.orElseThrow();
		BigInteger zero = new BigInteger("0");
		BigInteger base = NumericUtilities.parseHexBigInteger((String) baseOption.getValue());
		if (base == zero) {
			baseOption.setValue("1000000");
		}
		return options;
	}
}
