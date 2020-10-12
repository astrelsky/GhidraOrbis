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

	public static MemoryBlock getSpecialBlock(Program program) {
		return program.getMemory().getBlock(SCE_SPECIAL_SECTION);
	}
}
