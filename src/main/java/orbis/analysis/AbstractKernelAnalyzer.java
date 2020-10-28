package orbis.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.program.model.listing.Program;

import orbis.util.OrbisUtil;

abstract class AbstractKernelAnalyzer extends AbstractAnalyzer {

	protected AbstractKernelAnalyzer(String name, String description, AnalyzerType type) {
		super(name, description, type);
	}

	@Override
	public final boolean canAnalyze(Program program) {
		return OrbisUtil.isOrbisKernel(program);
	}
}
