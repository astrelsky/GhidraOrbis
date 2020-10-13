package orbis.util;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class OrbisUtil {

	public static final String SCE_SPECIAL_SECTION = ".sce_special";

    private OrbisUtil() {
    }

	public static boolean isOrbisProgram(Program program) {
		if (getSpecialBlock(program) != null) {
			return true;
		}
		return program.getUsrPropertyManager().getVoidPropertyMap("orbis") != null;
	}

	public static boolean isOrbisKernel(Program program) {
		if (isOrbisProgram(program)) {
			// this is lazy but will do for now
			return program.getMinAddress().getOffset() < 0;
		}
		return false;
	}

	public static MemoryBlock getSpecialBlock(Program program) {
		return program.getMemory().getBlock(SCE_SPECIAL_SECTION);
	}
}
