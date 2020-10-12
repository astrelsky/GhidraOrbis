package orbis.rtti;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPointProperties;

import cppclassanalyzer.scanner.RttiScanner;
import cppclassanalyzer.scanner.RttiScannerProvider;
import orbis.util.OrbisUtil;

@ExtensionPointProperties(priority = 2)
public final class OrbisRttiScannerProvider implements RttiScannerProvider {

	@Override
	public boolean canScan(Program program) {
		return OrbisUtil.isOrbisProgram(program);
	}

	@Override
	public RttiScanner getScanner(Program program) {
		return new OrbisRttiScaner(program);
	}

}
