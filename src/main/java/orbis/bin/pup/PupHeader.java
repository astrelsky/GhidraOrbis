package orbis.bin.pup;

import java.io.IOException;
import java.util.Iterator;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.util.Msg;

import orbis.bin.BinStructure;
import orbis.bin.FileSystemHeader;

final class PupHeader extends BinStructure implements FileSystemHeader<PupBlob> {

	static final byte[] MAGIC = new byte[] {
		(byte) 0x4F, (byte) 0x15, (byte) 0x3D, (byte) 0x1D
	};

	private final BinaryReader reader;
	private final int version;
	private final int mode;
	private final int endian;
	private final int flags;
	private final int content;
	private final int product;
	private final int headerSize;
	private final int metaSize;
	private final long fileSize;
	private final int blobCount;
	private final int flags2;
	private final long blobStart;

	PupHeader(ByteProvider provider) throws IOException {
		this.reader = new BinaryReader(provider, true);
		// skip magic
		skipBytes(MAGIC.length);
		this.version = reader.readNextUnsignedByte();
		this.mode = reader.readNextUnsignedByte();
		this.endian = reader.readNextUnsignedByte();
		this.flags = reader.readNextUnsignedByte();
		this.content = reader.readNextUnsignedByte();
		this.product = reader.readNextUnsignedByte();
		// skip padding
		skipBytes(2);
		this.headerSize = reader.readNextUnsignedShort();
		this.metaSize = reader.readNextUnsignedShort();
		this.fileSize = reader.readNextUnsignedInt();
		// skip padding
		skipBytes(4);
		this.blobCount = reader.readNextUnsignedShort();
		this.flags2 = reader.readNextUnsignedShort();
		// skip padding
		skipBytes(4);
		this.blobStart = reader.getPointerIndex();
	}

	private void skipBytes(int n) {
		advanceReader(reader, n);
	}

	int getBlobCount() {
		return blobCount;
	}

	@Override
	public Iterator<PupBlob> iterator() {
		reader.setPointerIndex(blobStart);
		return new PupBlobIterator();
	}

	private class PupBlobIterator implements Iterator<PupBlob> {

		private int index = 0;

		@Override
		public boolean hasNext() {
			return index < blobCount;
		}

		@Override
		public PupBlob next() {
			index++;
			try {
				return new PupBlob(reader);
			} catch (IOException e) {
				Msg.error(this, e);
			}
			return null;
		}

	}

	/**
	 * @return the reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * @return the version
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * @return the mode
	 */
	public int getMode() {
		return mode;
	}

	/**
	 * @return the endian
	 */
	public int getEndian() {
		return endian;
	}

	/**
	 * @return the flags
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * @return the content
	 */
	public int getContent() {
		return content;
	}

	/**
	 * @return the product
	 */
	public int getProduct() {
		return product;
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
	 * @return the flags2
	 */
	public int getFlags2() {
		return flags2;
	}

	/**
	 * @return the blobStart
	 */
	public long getBlobStart() {
		return blobStart;
	}
}
