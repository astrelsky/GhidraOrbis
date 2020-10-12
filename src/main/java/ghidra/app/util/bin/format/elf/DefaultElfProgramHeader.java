package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;

public class DefaultElfProgramHeader extends ElfProgramHeader {

	protected DefaultElfProgramHeader() {
	}

	public static ElfProgramHeader createElfProgramHeader(FactoryBundledWithBinaryReader reader,
			ElfHeader header) throws IOException {
		ElfProgramHeader elfProgramHeader =
			(ElfProgramHeader) reader.getFactory().create(DefaultElfProgramHeader.class);
		elfProgramHeader.initElfProgramHeader(reader, header);
		return elfProgramHeader;
	}
}
