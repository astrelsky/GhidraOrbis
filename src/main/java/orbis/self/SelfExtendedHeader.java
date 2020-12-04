package orbis.self;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;

public final class SelfExtendedHeader implements Iterable<SelfSegment> {

	private final BinaryReader reader;
	private final long keyType;
	private final int headerSize;
	private final int metaSize;
	private final long fileSize;
	private final int entryCount;
	private final int flag;
	private final List<SelfSegment> entries;

	SelfExtendedHeader(BinaryReader reader) throws IOException, EncryptedSelfException {
		this.reader = reader;
		this.keyType = reader.readNextUnsignedInt();
		this.headerSize = reader.readNextUnsignedShort();
		this.metaSize = reader.readNextUnsignedShort();
		this.fileSize = reader.readNextLong();
		this.entryCount = reader.readNextUnsignedShort();
		this.flag = reader.readNextUnsignedShort();
		// skip padding
		skipBytes(4);
		this.entries = new ArrayList<>(entryCount);
		for (int i = 0; i < entryCount; i++) {
			entries.add(new SelfSegment(reader));
		}
		entries.sort(null);
	}

	private void skipBytes(int n) {
		reader.setPointerIndex(reader.getPointerIndex() + n);
	}

	/**
	 * @return the reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * @return the keyType
	 */
	public long getKeyType() {
		return keyType;
	}

	/**
	 * @return the headerSize
	 */
	public int getHeaderSize() {
		return headerSize;
	}

	/**
	 * @return the metaSize
	 */
	public int getMetaSize() {
		return metaSize;
	}

	/**
	 * @return the fileSize
	 */
	public long getFileSize() {
		return fileSize;
	}

	/**
	 * @return the entryCount
	 */
	public int getEntryCount() {
		return entryCount;
	}

	/**
	 * @return the flag
	 */
	public int getFlag() {
		return flag;
	}

	SelfSegment getEntry() {
		return entries.get(0);
	}

	@Override
	public Iterator<SelfSegment> iterator() {
		return entries.iterator();
	}

	public List<SelfSegment> getEntries() {
		return Collections.unmodifiableList(entries);
	}
}
