package orbis.bin.ipl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
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
import ghidra.util.NumericUtilities;
import ghidra.util.exception.AssertException;

import static java.nio.ByteOrder.LITTLE_ENDIAN;

/**
 * IPL Header build from information from fail0verflow and Znullptr
 */
public class IplHeader implements StructConverter {

	private static final int MAGIC = 0xd48ff9aa;
	private static final String HMAC_ALGO = "HmacSHA1";
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

	private static final int KEY_LENGTH = 0x10;
	private static final int DIGEST_LENGTH = 0x14;
	public static final DataType dataType = getDataType();

	private final HeaderImpl header;
	private final ByteBuffer body;

	public IplHeader(ByteProvider provider) throws IOException {
		this(new BinaryReader(provider, true));
	}

	public IplHeader(BinaryReader reader) throws IOException {
		this.header = new HeaderImpl(reader);
		this.body = ByteBuffer.wrap(reader.readNextByteArray(header.getBodyLength()));
	}

	public IplHeader(ByteBuffer header, ByteBuffer body) {
		this.header = new HeaderImpl(header);
		this.body = body;
		this.header.setBodyLength(body.limit());
	}

	@Override
	public DataType toDataType() {
		return dataType;
	}

	public ByteBuffer getHeader() {
		return header.getBuffer();
	}

	public ByteBuffer getBody() {
		return body.position(0).asReadOnlyBuffer();
	}

	public InputStream getHeaderInputStream() {
		return new ByteArrayInputStream(header.buf.array());
	}

	public InputStream getBodyInputStream() {
		return new ByteArrayInputStream(body.array());
	}

	/**
	 * @return the magic
	 */
	public int getMagic() {
		return header.getMagic();
	}

	/**
	 * @return the proc_type
	 */
	public ProcessorType getProc_type() {
		return header.getProcessorType();
	}

	/**
	 * @return the hdr_len
	 */
	public int getHeaderLength() {
		return HeaderImpl.LENGTH;
	}

	/**
	 * @return the body_len
	 */
	public int getBodyLength() {
		return header.getBodyLength();
	}

	/**
	 * @return the load_addr_0
	 */
	public int getLoadAddress0() {
		return header.getLoadAddress0();
	}

	/**
	 * @return the load_addr_1
	 */
	public int getLoadAddress1() {
		return header.getLoadAddress1();
	}

	/**
	 * @return the fill_pattern
	 */
	public byte[] getFill_pattern() {
		return header.getFillPattern();
	}

	/**
	 * @return the key_seed
	 */
	public byte[] getKeySeed() {
		return header.getSeed();
	}

	public boolean isValid() {
		if (getMagic() != MAGIC) {
			return false;
		}
		if (!Arrays.equals(FILL_PATTERN, getFill_pattern())) {
			return false;
		}
		if (!Arrays.equals(KEY_SEED, getKeySeed())) {
			return false;
		}
		return true;
	}

	public boolean isEncrypted() {
		return header.isEncrypted();
	}

	public void decrypt(String cKey, String hKey)
			throws IllegalBlockSizeException, BadPaddingException, EncryptedDataException {
		if (!isEncrypted()) {
			return;
		}
		byte[] cipherKey = null;
		byte[] hasherKey = null;
		if (cKey != null && cKey.length() == KEY_LENGTH * 2) {
			cipherKey = NumericUtilities.convertStringToBytes(cKey);
		}
		if (hKey != null && hKey.length() == KEY_LENGTH * 2) {
			hasherKey = NumericUtilities.convertStringToBytes(hKey);
		}
		if (cipherKey == null || hasherKey == null) {
			throw new EncryptedDataException("Data is encrypted but no keys were provided");
		}
		header.decrypt(cipherKey);
		checkHeader(hasherKey);
		checkBody();
		try {
			body.position(0);
			Cipher cipher = getCipher(header.getAesKey());
			cipher.doFinal(body.slice(), body);
		} catch (ShortBufferException e) {
			throw new AssertException(e);
		}
	}

	public void encrypt(String cKey, String hKey)
			throws IllegalBlockSizeException, BadPaddingException {
		byte[] cipherKey = null;
		byte[] hasherKey = null;
		if (cKey != null && cKey.length() == KEY_LENGTH * 2) {
			cipherKey = NumericUtilities.convertStringToBytes(cKey);
		}
		if (hKey != null && hKey.length() == KEY_LENGTH * 2) {
			hasherKey = NumericUtilities.convertStringToBytes(hKey);
		}
		if (cipherKey == null || hasherKey == null) {
			return;
		}

		try {
			body.position(0);
			Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, header.getAesKey());
			cipher.doFinal(body.slice(), body);
			header.setBodyDigest(hashBody());
			header.setHeaderDigest(hashHeader(hasherKey));
			header.encrypt(cipherKey);
		} catch (ShortBufferException e) {
			throw new AssertException(e);
		}
	}

	private byte[] hashHeader(byte[] hasherKey) {
		try {
			byte[] data = new byte[0x6c];
			getHeader().get(data);
			SecretKeySpec secretKeySpec = new SecretKeySpec(hasherKey, HMAC_ALGO);
		    Mac mac = Mac.getInstance(HMAC_ALGO);
		    mac.init(secretKeySpec);
		    return mac.doFinal(data);
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	private void checkHeader(byte[] hasherKey) throws EncryptedDataException {
		if (!Arrays.equals(header.getHeaderDigest(), hashHeader(hasherKey))) {
			throw new EncryptedDataException("Header validation failed. Hasher key is incorrect.");
		}
	}

	private byte[] hashBody() {
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(header.getHmacKey(), HMAC_ALGO);
		    Mac mac = Mac.getInstance(HMAC_ALGO);
		    mac.init(secretKeySpec);
		    return mac.doFinal(body.array());
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	private void checkBody() throws EncryptedDataException {
		if (!Arrays.equals(header.getBodyDigest(), hashBody())) {
			throw new EncryptedDataException("Body validation failed. Cipher key is incorrect.");
		}
	}

	private static Cipher getCipher(byte[] key) {
		return getCipher(Cipher.DECRYPT_MODE, key);
	}

	private static Cipher getCipher(int mode, byte[] key) {
		try {
			IvParameterSpec iv = new IvParameterSpec(new byte[16]);
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec spec = new SecretKeySpec(key, "AES");
			cipher.init(mode, spec, iv);
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

		private ProcessorType(byte b) {
			_value = b;
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

	private static class HeaderImpl {
		private static final int LENGTH = 0x80;
		private final ByteBuffer buf;

		HeaderImpl(BinaryReader reader) throws IOException {
			buf = ByteBuffer.wrap(reader.readNextByteArray(LENGTH));
			buf.order(LITTLE_ENDIAN);
		}

		HeaderImpl(ByteBuffer buf) {
			this.buf = buf.order(LITTLE_ENDIAN);
		}

		ByteBuffer getBuffer() {
			return buf.position(0).asReadOnlyBuffer().order(LITTLE_ENDIAN);
		}

		int getMagic() {
			return buf.position(0)
				.asIntBuffer()
				.get();
		}

		ProcessorType getProcessorType() {
			return new ProcessorType(buf.position(7).get());
		}

		boolean isEncrypted() {
			int v = buf.position(0x6)
				.asShortBuffer()
				.get();
			return (v & 0x800) != 0;
		}

		byte[] getSeed() {
			byte[] res = new byte[0x8];
			buf.position(0x28);
			buf.get(res);
			return res;
		}

		int getBodyLength() {
			return buf.position(0xc)
				.asIntBuffer()
				.get();
		}

		void setBodyLength(int length) {
			buf.position(0xc)
				.asIntBuffer()
				.put(length);
		}

		int getLoadAddress0() {
			return buf.position(0x10)
				.asIntBuffer()
				.get();
		}

		int getLoadAddress1() {
			return buf.position(0x14)
				.asIntBuffer()
				.get();
		}

		byte[] getFillPattern() {
			byte[] res = new byte[FILL_PATTERN.length];
			buf.position(0x18).get(res);
			return res;
		}

		byte[] getAesKey() {
			byte[] res = new byte[KEY_LENGTH];
			buf.position(0x30);
			buf.get(res);
			return res;
		}

		byte[] getHmacKey() {
			byte[] res = new byte[KEY_LENGTH];
			buf.position(0x40);
			buf.get(res);
			return res;
		}

		byte[] getBodyDigest() {
			byte[] res = new byte[DIGEST_LENGTH];
			buf.position(0x50);
			buf.get(res);
			return res;
		}

		void setBodyDigest(byte[] digest) {
			buf.position(0x50);
			buf.put(digest);
		}

		byte[] getHeaderDigest() {
			byte[] res = new byte[DIGEST_LENGTH];
			buf.position(0x6c);
			buf.get(res);
			return res;
		}

		void setHeaderDigest(byte[] digest) {
			buf.position(0x6c);
			buf.put(digest);
		}

		void decrypt(byte[] key) throws IllegalBlockSizeException, BadPaddingException {
			try {
				Cipher cipher = getCipher(key);
				buf.position(0x30);
				cipher.doFinal(buf.slice(), buf);
			} catch (ShortBufferException e) {
				throw new AssertException(e);
			}
		}

		void encrypt(byte[] key) throws IllegalBlockSizeException, BadPaddingException {
			try {
				Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key);
				buf.position(0x30);
				cipher.doFinal(buf.slice(), buf);
			} catch (ShortBufferException e) {
				throw new AssertException(e);
			}
		}
	}

}
