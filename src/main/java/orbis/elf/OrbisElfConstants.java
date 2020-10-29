package orbis.elf;

public class OrbisElfConstants {

	public static final int DT_SCE_PLTGOT_TAG = 0x61000027;
	public static final int PT_SCE_RELRO_VALUE = 0x61000010;
	public static final int PT_SCE_DYNLIBDATA_VALUE = 0x61000000;
	public static final int PT_SCE_LIBVERSION_VALUE = 0x6FFFFF01;
	public static final int PT_SCE_COMMENT_VALUE = 0x6FFFFF00;
	public static final int PT_SCE_PROCPARAM_VALUE = 0x61000001;
	public static final int PT_SCE_MODULEPARAM_VALUE = 0x61000002;

	private OrbisElfConstants() {
	}
}
