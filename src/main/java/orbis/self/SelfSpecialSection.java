package orbis.self;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public final class SelfSpecialSection {

	private static final int ARRAY_SIZE = 0x20;

	private final long authorityId;
	private final long type;
	private final long version1;
	private final long version2;
	/** Only exists if the SELF is NPDRM */
	private final byte[] contentId;
	/** SHA-256 digest */
	private final byte[] digest;
	
	SelfSpecialSection(BinaryReader reader) throws IOException {
		this.authorityId = reader.readNextLong();
		this.type = reader.readNextLong();
		this.version1 = reader.readNextLong();
		this.version2 = reader.readNextLong();
		this.contentId = reader.readNextByteArray(ARRAY_SIZE);
		this.digest = reader.readNextByteArray(ARRAY_SIZE);
	}

	/**
	 * @return the authorityId
	 */
	public long getAuthorityId() {
		return authorityId;
	}

	/**
	 * @return the type
	 */
	public ProgramType getType() {
		return ProgramType.getType(type);
	}

	/**
	 * @return the version1
	 */
	public long getVersion1() {
		return version1;
	}

	/**
	 * @return the version2
	 */
	public long getVersion2() {
		return version2;
	}

	/**
	 * @return the contentId
	 */
	public byte[] getContentId() {
		return contentId;
	}

	/**
	 * @return the SHA-256 digest
	 */
	public byte[] getDigest() {
		return digest;
	}

	public String getModule() {
		int upper = (int) (authorityId >> 32) & 0xffffffff;
		int lower = (int) (authorityId & 0xffffffff);
		switch(upper) {
			case 0x38000000:
				switch(lower) {
					case 0x00000003:
						return "SceVdecProxy.elf";
					case 0x00000004:
						return "SceVencProxy.elf";
					case 0x00000005:
						return "orbis_audiod.elf";
					case 0x00000006:
						return "coredump.elf";
					case 0x00000007:
						return "SceSysCore.elf";
					case 0x00000008:
						return "orbis_setip.elf";
					case 0x00000009:
						return "GnmCompositor.elf";
					case 0x0000000f:
						return "NPXS20001";
					case 0x00000010:
						return "SceShellCore.elf";
					case 0x00000011:
						return "NPXS20103";
					case 0x00000012:
						return "NPXS21000";
					case 0x00000013:
						return "NPXS21001";
					case 0x00000014:
						return "NPXS21002";
					case 0x00000015:
						return "NPXS21003";
					case 0x00000016:
						return "NPXS21004";
					case 0x00000017:
						return "becore.elf";
					case 0x00000018:
						return "avbase.elf";
					case 0x00000019:
						return "NPXS21006";
					case 0x0000001c:
						return "NPXS22010";
					case 0x0000001d:
						return "fs_cleaner.elf";
					case 0x0000001e:
						return "FirstImageWriter";
					case 0x00000022:
						return "Minisyscore";
					case 0x00000023:
						return "sce_video_service";
					case 0x00000024:
						return "ScePlayReady.self";
					case 0x00000026:
						return "swagner.self";
					case 0x00000029:
						return "swreset.self";
					case 0x00000031:
						return "webapp.self";
					case 0x00000033:
						return "SecureUIProcess.self";
					case 0x00000034:
						return "UIProcess.self";
					case 0x00000035:
						return "WebBrowserUIProcess.self";
					case 0x00000036:
						return "gpudump.elf";
					case 0x00010001:
						return "set_upper.self";
					case 0x00010002:
						return "mount_fusefs.elf";
					case 0x00010003:
						return "decid.elf";
					case 0x00010004:
						return "newfs.elf";
					case 0x00010005:
						return "fsck_ufs.elf";
					case 0x00010006:
						return "NPXS21008";
					case 0x10000003:
						return "SecureWebProcess.self";
					case 0x10000004:
						return "WebProcess.self";
					case 0x10000005:
						return "Bdjava";
					case 0x10000006:
						return "orbis-jsc-compiler.self";
					case 0x10000008:
						return "MonoCompiler.elf";
					case 0x10000009:
						return "Diskplayerui";
					case 0x1000000b:
						return "custom_video_core.elf";
					case 0x1000000f:
						return "WebProcessWebApp.self";
				}
				break;
			case 0x38001000:
				if (lower == 1) {
					return "orbis_swu.self";
				}
				break;
			case 0x38008000:
				if (lower == 2) {
					return "Vtrmadmin";
				}
				break;
			case 0x38010000:
				if (lower == 0x00000024) {
					return "DiagOSUpdater";
				}
				break;
			case 0x39000000:
				if (lower == 2) {
					return "sprx/prx";
				}
				break;
			case 0x39010000:
				if (lower == 1) {
					return "sdll/sexe";
				}
				break;
			case 0x3c000000:
				if (lower == 1) {
					return "x86 Kernel";
				}
				break;
			case 0x3e000000:
				switch (lower) {
					case 0x00000003:
						return "acmgr";
					case 0x00000005:
						return "authmgr";
					case 0x00000006:
						return "individual data mgr";
					case 0x00000008:
						return "manu_mode mgr";
					case 0x00000007:
						return "keymgr";
					case 0x00000009:
						return "sm_service";
					default:
						break;
				}
			case 0x3f000000:
				if (lower == 1) {
					return "Secure Kernel";
				}
				break;
			default:
				break;
		}
		return "";
	}

	private static enum ProgramType {
		PUP,
		NPDRM,
		PLUGIN,
		SECURE_KERNEL,
		SECURITY_MODULE,
		SECOND_LOADER;

		private static ProgramType getType(long type) {
			switch((int) type) {
				case 0:
					return PUP;
				case 8:
					return NPDRM;
				case 9:
					return PLUGIN;
				case 0xC:
					return SECURE_KERNEL;
				case 0xE:
					return SECURITY_MODULE;
				case 0xF:
					return SECOND_LOADER;
				default:
					throw new IllegalArgumentException();
			}
		}
	}
}
