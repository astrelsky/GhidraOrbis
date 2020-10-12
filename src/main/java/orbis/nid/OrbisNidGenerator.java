package orbis.nid;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

import ghidra.util.exception.AssertException;

public final class OrbisNidGenerator {

	private static final Base64.Encoder ENCODER = Base64.getEncoder();
	private static final int DIGEST_LENGTH = 8;
	private static final int NID_LENGTH = 11;
	private static final byte[] NID_KEY = new byte[] {
		(byte) 0x51, (byte) 0x8D, (byte) 0x64, (byte) 0xA6,
		(byte) 0x35, (byte) 0xDE, (byte) 0xD8, (byte) 0xC1,
		(byte) 0xE6, (byte) 0xB0, (byte) 0x39, (byte) 0xB1,
		(byte) 0xC3, (byte) 0xE5, (byte) 0x52, (byte) 0x30
	};

	public String obfuscate(String symbol) {
		Objects.requireNonNull(symbol);
		try {
			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
			sha1.update(symbol.getBytes(StandardCharsets.US_ASCII));
			sha1.update(NID_KEY);
			byte[] digest = sha1.digest();
			byte[] encodedDigest = new byte[DIGEST_LENGTH];
			for (int i = 0; i < DIGEST_LENGTH; i++) {
				encodedDigest[i] = digest[DIGEST_LENGTH - 1 - i];
			}
			String nid = ENCODER.encodeToString(encodedDigest).substring(0, NID_LENGTH);
			return nid.replaceAll("/", "-");
		} catch (NoSuchAlgorithmException e) {
			throw new AssertException(e);
		}
	}

	public String trimObfuscatedSymbol(String symbol) {
		if (symbol != null && symbol.length() > NID_LENGTH) {
			return symbol.substring(0, NID_LENGTH);
		}
		return symbol;
	}

}
