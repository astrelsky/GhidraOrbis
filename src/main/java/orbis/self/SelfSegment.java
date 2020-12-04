package orbis.self;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.InflaterInputStream;

import ghidra.app.util.bin.*;

public final class SelfSegment implements Comparable<SelfSegment> {

	private static final Property ORDER = new Property(0, 0x1);
    private static final Property ENCRYPTED = new Property(1, 0x1);
    private static final Property SIGNED = new Property(2, 0x1);
    private static final Property COMPRESSED = new Property(3, 0x1);
    private static final Property WINDOW_BITS = new Property(8, 0x7);
    private static final Property HAS_BLOCK = new Property(11, 0x1);
    private static final Property BLOCK_SIZE = new Property(12, 0xF);
    private static final Property HAS_DIGEST = new Property(16, 0x1);
    private static final Property HAS_EXTENT = new Property(17, 0x1);
    private static final Property HAS_META = new Property(20, 0x1);
    private static final Property SEGMENT_INDEX = new Property(20, 0xFFFF);

	private final BinaryReader reader;
	private final long properties;
	private final long fileOffset;
	private final long fileSize;
	private final long memorySize;

	SelfSegment(BinaryReader reader) throws IOException, EncryptedSelfException {
		this.reader = reader;
		long[] values = reader.readNextLongArray(4);
		this.properties = values[0];
		this.fileOffset = values[1];
		this.fileSize = values[2];
		this.memorySize = values[3];
		if (isEncrypted()) {
			throw new EncryptedSelfException();
		}
	}

	@Override
	public int compareTo(SelfSegment o) {
		int i = Integer.compare(getSegmentIndex(), o.getSegmentIndex());
		if (i == 0) {
			return Long.compare(fileOffset, o.fileOffset);
		}
		return i;
	}

	public boolean hasOrder() {
		return getBooleanProperty(ORDER);
	}

	public boolean isEncrypted() {
		return getBooleanProperty(ENCRYPTED);
	}

	public boolean isSigned() {
		return getBooleanProperty(SIGNED);
	}

	public boolean isCompressed() {
		return getBooleanProperty(COMPRESSED);
	}

	public int getWindowBits() {
		return getIntProperty(WINDOW_BITS);
	}

	public boolean hasBlock() {
		return getBooleanProperty(HAS_BLOCK);
	}

	public int getBlockSize() {
		return getIntProperty(BLOCK_SIZE);
	}

	public boolean hasDigest() {
		return getBooleanProperty(HAS_DIGEST);
	}

	public boolean hasExtent() {
		return getBooleanProperty(HAS_EXTENT);
	}

	public boolean hasMeta() {
		return getBooleanProperty(HAS_META);
	}

	public int getSegmentIndex() {
		return getIntProperty(SEGMENT_INDEX);
	}

	public long getFileSize() {
		return fileSize;
	}

	public long getMemorySize() {
		return memorySize;
	}

	public ByteProvider getElfHeaderByteProvider() throws IOException {
		return new InputStreamByteProvider(getInputStream(), memorySize);
	}

	private boolean getBooleanProperty(Property property) {
		return ((properties >> property.shift) & property.mask) == property.mask;
	}

	private int getIntProperty(Property property) {
		return (int) ((properties >> property.shift) & property.mask);
	}

	InputStream getInputStream() throws IOException {
		InputStream is = reader.getByteProvider().getInputStream(fileOffset);
		if (isCompressed()) {
			is = new InflaterInputStream(is);
		}
		return is;
	}

	private static class Property {
		final int shift;
		final int mask;

		Property(int shift, int mask) {
			this.shift = shift;
			this.mask = mask;
		}
	}
}
