package orbis.loader;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import orbis.self.EncryptedSelfException;
import orbis.self.SelfHeader;

public class GhidraOrbisSelfLoader extends GhidraOrbisElfLoader {

	@Override
	public String getName() {
		return "Orbis SELF";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!SelfHeader.isSelf(provider)) {
			return Collections.emptyList();
		}
		try {
			SelfHeader header = new SelfHeader(provider);
			return findSupportedLoadSpecs(header.buildElfHeader());
		} catch (ElfException e) {
			// do nothing
		} catch (EncryptedSelfException e) {
			Msg.showInfo(this, null, "Encrypted SELF detected", "Encrypted SELF files cannot be loaded");
		}
		return Collections.emptyList();
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {
		try {
			SelfHeader header = new SelfHeader(provider);
			ByteProvider elfByteProvider = header.getElfHeaderByteProvider();
			super.load(elfByteProvider, loadSpec, options, program, monitor, log);
			elfByteProvider.close();
		} catch (EncryptedSelfException e) {
			Msg.showInfo(this, null, "Import Failed", "SELF is encrypted and cannot be loaded");
			throw new CancelledException();
		}
	}
}
