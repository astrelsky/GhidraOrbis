package orbis.analysis;

import java.util.Collections;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import orbis.util.OrbisUtil;
import orbis.nid.NidDatabaseFactory;

public class NIDAnalyzer extends AbstractAnalyzer {

	public NIDAnalyzer() {
		super(NIDAnalyzer.class.getSimpleName(), "NID Resolver", AnalyzerType.BYTE_ANALYZER);
		// run first for non-returning functions
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());
		setSupportsOneTimeAnalysis();
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return OrbisUtil.isOrbisProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		try {
			NIDResolver resolver = new NIDResolver(program, log);
			SymbolTable table = program.getSymbolTable();
			monitor.initialize(table.getNumSymbols());
			monitor.setMessage("Resolving NIDs");
			for (Symbol s : table.getAllSymbols(false)) {
				// remaining symbols are data but the library namespace
				// cannot be added for some reason
				monitor.checkCanceled();
				if (s.isPrimary() && s.getName().contains("#")) {
					resolver.resolve(s);
				}
				monitor.incrementProgress(1);
			}
			return true;
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

	private static class NIDResolver {

		private final Map<String, String> db;
		private final MessageLog log;
		private final ExternalManager man;
		private final String[] libraries;
		NIDResolver(Program program, MessageLog log) {
			Map<String, String> db = Collections.emptyMap();
			try {
				db = NidDatabaseFactory.getNidDatabase();
			} catch (Exception e) {
				log.appendException(e);
			}
			this.db = db;
			this.log = log;
			this.man = program.getExternalManager();
			this.libraries = man.getExternalLibraryNames();
		}

		void resolve(Symbol s) {
			Namespace ns = s.getParentNamespace();
			String name = s.getName();
			if (name.length() != 15) {
				return;
			}
			if (name.charAt(13) == '#') {
				int i = getIndex(name.charAt(12))+1;
				if (i < libraries.length) {
					ns = man.getExternalLibrary(libraries[i]);
				}
			} else if (name.charAt(14) == '#') {
				int i = getIndex(name.charAt(12)) + getIndex(name.charAt(13))+1;
				if (i < libraries.length) {
					ns = man.getExternalLibrary(libraries[i]);
				}
			} else {
				return;
			}
			name = name.substring(0, 11);
			if (db.containsKey(name)) {
				String entry = db.get(name);
				try {
					s.setNameAndNamespace(entry, ns, SourceType.IMPORTED);
				} catch (InvalidInputException e) {
					try {
						s.setName(entry, SourceType.IMPORTED);
					} catch (Exception ex) {
						log.appendException(ex);
					}
				} catch (Exception e) {
					log.appendException(e);
				}
				if (entry.equals("__stack_chk_fail")) {
					Function fun = (Function) s.getObject();
					fun.setNoReturn(true);
				}
			}
		}

		private static int getIndex(char c) {
			if (c >= 'A' && c <= 'z') {
				return c - 'A';
			}
			if (c >= '0' && c <= '9') {
				return c - '0' + 52;
			}
			if (c == '+') {
				return 63;
			}
			if (c == '-') {
				return 64;
			}
			return -1;
		}
	}
}
