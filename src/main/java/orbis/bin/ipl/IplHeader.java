package orbis.bin.ipl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.AssertException;

/**
 * IPL Header build from information from fail0verflow and Znullptr
 */
public class IplHeader implements StructConverter {

	private static final int MAGIC = 0xd48ff9aa;
	private static final byte[] FILL_PATTERN = new byte[]{
		(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
		(byte) 0xCA, (byte) 0xFE, (byte) 0xBE, (byte) 0xBE,
		(byte) 0xDE, (byte) 0xAF, (byte) 0xBE, (byte) 0xEF,
		(byte) 0xCA, (byte) 0xFE, (byte) 0xBE, (byte) 0xBE
	};
	private static final byte[] KEY_SEED = new byte[]{
		(byte) 0xF1, (byte) 0xF2, (byte) 0xF3, (byte) 0xF4,
		(byte) 0xF5, (byte) 0xF6, (byte) 0xF7, (byte) 0xF8
	};
	private static final int ENCRYPTED_LENGTH = 0x50;
	private static final int KEY_LENGTH = 0x10;
	private static final int DIGEST_LENGTH = 0x14;
	public static final DataType dataType = getDataType();

	private final int magic;
	private final byte field_4;
	private final byte field_5;
	private final byte field_6;
	private final ProcessorType proc_type;
	private final int hdr_len;
	private final int body_len;
	private final int load_addr_0;
	private final int load_addr_1;
	private final byte[] fill_pattern;
	private final byte[] key_seed;
	private byte[] body_aes_key;
	private byte[] body_hmac_key;
	private byte[] body_hmac_digest;
	private int field_7;
	private byte[] header_hmac_digest;
	private int field_8;
	private final byte[] _body;

	public IplHeader(ByteProvider provider) throws IOException {
		this(new BinaryReader(provider, true));
	}

	public IplHeader(BinaryReader reader) throws IOException {
		this.magic = reader.readNextInt();
		this.field_4 = reader.readNextByte();
		this.field_5 = reader.readNextByte();
		this.field_6 = reader.readNextByte();
		this.proc_type = new ProcessorType(reader);
		this.hdr_len = reader.readNextInt();
		this.body_len = reader.readNextInt();
		this.load_addr_0 = reader.readNextInt();
		this.load_addr_1 = reader.readNextInt();
		this.fill_pattern = reader.readNextByteArray(FILL_PATTERN.length);
		this.key_seed = reader.readNextByteArray(KEY_SEED.length);
		this.body_aes_key = reader.readNextByteArray(KEY_LENGTH);
		this.body_hmac_key = reader.readNextByteArray(KEY_LENGTH);
		this.body_hmac_digest = reader.readNextByteArray(DIGEST_LENGTH);
		this.field_7 = reader.readNextInt();
		this.header_hmac_digest = reader.readNextByteArray(DIGEST_LENGTH);
		this.field_8 = reader.readNextInt();
		this._body = reader.readNextByteArray(body_len);
	}

	@Override
	public DataType toDataType() {
		return dataType;
	}

/**
	 * @return the magic
	 */
	public int getMagic() {
		return magic;
	}

	/**
	 * @return the field_4
	 */
	public byte getField_4() {
		return field_4;
	}

	/**
	 * @return the field_5
	 */
	public byte getField_5() {
		return field_5;
	}

	/**
	 * @return the field_6
	 */
	public byte getField_6() {
		return field_6;
	}

	/**
	 * @return the proc_type
	 */
	public ProcessorType getProc_type() {
		return proc_type;
	}

	/**
	 * @return the hdr_len
	 */
	public int getHeaderLength() {
		return hdr_len;
	}

	/**
	 * @return the body_len
	 */
	public int getBodyLength() {
		return body_len;
	}

	/**
	 * @return the load_addr_0
	 */
	public int getLoadAddress0() {
		return load_addr_0;
	}

	/**
	 * @return the load_addr_1
	 */
	public int getLoadAddress1() {
		return load_addr_1;
	}

	/**
	 * @return the fill_pattern
	 */
	public byte[] getFill_pattern() {
		return fill_pattern;
	}

	/**
	 * @return the key_seed
	 */
	public byte[] getKey_seed() {
		return key_seed;
	}

	public boolean isValid() {
		if (magic != MAGIC) {
			return false;
		}
		if (!Arrays.equals(FILL_PATTERN, fill_pattern)) {
			return false;
		}
		if (!Arrays.equals(KEY_SEED, key_seed)) {
			return false;
		}
		return true;
	}

	public boolean isEncrypted() {
		return (proc_type._value & 8) == 8;
	}

	public byte[] getData(byte[] key) throws IllegalBlockSizeException, BadPaddingException {
		ByteBuffer buf = ByteBuffer.allocate(getTotalLength())
			.order(ByteOrder.LITTLE_ENDIAN)
			.putInt(magic)
			.put(field_4)
			.put(field_5)
			.put(field_6)
			.put(proc_type._value)
			.putInt(hdr_len)
			.putInt(body_len)
			.putInt(load_addr_0)
			.putInt(load_addr_1)
			.put(fill_pattern)
			.put(key_seed);
		if (isEncrypted()) {
			Cipher cipher = getCipher(key);
			ByteBuffer encBuf = ByteBuffer.allocate(ENCRYPTED_LENGTH)
				.order(ByteOrder.LITTLE_ENDIAN)
				.put(body_aes_key)
				.put(body_hmac_key)
				.put(body_hmac_digest)
				.putInt(field_7)
				.put(header_hmac_digest)
				.putInt(field_8);
			byte[] decrypted = cipher.doFinal(encBuf.array());
			ByteBuffer decBuf = ByteBuffer.wrap(decrypted)
				.order(ByteOrder.LITTLE_ENDIAN)
				.get(body_aes_key)
				.get(body_hmac_key)
				.get(body_hmac_digest);
			field_7 = decBuf.getInt();
			decBuf.get(header_hmac_digest);
			field_8 = decBuf.getInt();
		}
		buf = buf.put(body_aes_key)
			.put(body_hmac_key)
			.put(body_hmac_digest)
			.putInt(field_7)
			.put(header_hmac_digest)
			.putInt(field_8);
		byte[] body = _body;
		if (isEncrypted()) {
			Cipher cipher = getCipher(body_aes_key);
			body = cipher.doFinal(_body);
		}
		buf.put(body);
		return buf.array();
	}

	private int getTotalLength() {
		return body_len + hdr_len;
	}

	private static Cipher getCipher(byte[] key) {
		try {
			IvParameterSpec iv = new IvParameterSpec(new byte[16]);
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec spec = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.DECRYPT_MODE, spec, iv);
			return cipher;
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	public static DataType getDataType() {
		CategoryPath path = new CategoryPath("/ipl");
		StructureDataType struct = new StructureDataType(path, "IplHeader", 0);
		struct.add(DWORD, "magic", null);
		struct.add(BYTE, "field_4", null);
		struct.add(BYTE, "field_5", null);
		struct.add(BYTE, "field_6", null);
		struct.add(ProcessorType.getDataType(), "proc_type", null);
		struct.add(DWORD, "hdr_len", null);
		struct.add(DWORD, "body_len", null);
		struct.add(POINTER, "load_addr_0", null);
		struct.add(POINTER, "load_addr_1", null);
		addArray(struct, KEY_LENGTH, "fill_pattern");
		addArray(struct, KEY_SEED.length, "key_seed");
		addArray(struct, KEY_LENGTH, "body_aes_key");
		addArray(struct, KEY_LENGTH, "body_hmac_key");
		addArray(struct, DIGEST_LENGTH, "body_hmac_digest");
		struct.add(DWORD, "field_7", null);
		addArray(struct, DIGEST_LENGTH, "header_hmac_digest");
		struct.add(DWORD, "field_8", null);
		return struct;
	}

	private static void addArray(StructureDataType struct, int numElements, String name) {
		ArrayDataType array = new ArrayDataType(BYTE, numElements, 1);
		struct.add(array, name, null);
	}

	private static class ProcessorType {

		private final byte _value;

		private ProcessorType(BinaryReader reader) throws IOException {
			_value = reader.readNextByte();
		}

		private static final CategoryPath PATH = new CategoryPath(CategoryPath.ROOT, "ipl");

		public static DataType getDataType() {
			EnumDataType dt = new EnumDataType(PATH, "proc_t", 1);
			dt.add("EMC", 0x40);
			dt.add("EMC_ENCRYPTED", 0x48);
			dt.add("EAP", 0x60);
			dt.add("EAP_ENCRYPTED", 0x68);
			return dt;
		}

		@Override
		public String toString() {
			switch (_value) {
				case 0x40:
				case 0x48:
					return "EMC";
				case 0x60:
				case 0x68:
					return "EAP";
				default:
					return "Unknown Processor Type";
			}
		}

	}

}
