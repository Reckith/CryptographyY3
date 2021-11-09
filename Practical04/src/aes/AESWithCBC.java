
	package aes;

	import java.security.InvalidAlgorithmParameterException;
	import java.security.InvalidKeyException;
	import java.security.Key;
	import java.security.NoSuchAlgorithmException;
	import java.security.NoSuchProviderException;
	import java.security.Security;

	import javax.crypto.BadPaddingException;
	import javax.crypto.Cipher;
	import javax.crypto.IllegalBlockSizeException;
	import javax.crypto.NoSuchPaddingException;
	import javax.crypto.spec.IvParameterSpec;
	import javax.crypto.spec.SecretKeySpec;

	import org.bouncycastle.jce.provider.BouncyCastleProvider;
	import org.bouncycastle.util.encoders.Hex;

	public class AESWithCBC {

		static {
			Security.addProvider(new BouncyCastleProvider());
		}

		private static byte[] encrypt(final Cipher cipher, final Key key,
				final byte[] initialisationVector, final byte[] data)
				throws InvalidKeyException, InvalidAlgorithmParameterException,
				IllegalBlockSizeException, BadPaddingException {
			cipher.init(Cipher.ENCRYPT_MODE, key,
					new IvParameterSpec(initialisationVector));
			return cipher.doFinal(data);
		}

		private static byte[] decrypt(final Cipher cipher, final Key key,
				final byte[] initialisationVector, final byte[] data)
				throws InvalidKeyException, InvalidAlgorithmParameterException,
				IllegalBlockSizeException, BadPaddingException {
			cipher.init(Cipher.DECRYPT_MODE, key,
					new IvParameterSpec(initialisationVector));
			return cipher.doFinal(data);
		}

		public static void main(final String[] args)
				throws NoSuchAlgorithmException, NoSuchProviderException,
				NoSuchPaddingException, InvalidKeyException,
				InvalidAlgorithmParameterException, IllegalBlockSizeException,
				BadPaddingException {
			final String keytext = "thebestsecretkey";

			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
			final Key key = new SecretKeySpec(keytext.getBytes(), "AES");

			final byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");

			final String plaintext = "alphanumerically";
			System.out.println("Plaintext: " + plaintext);

			final byte[] ciphertext = encrypt(cipher, key, iv,
					plaintext.getBytes());
			System.out.println("Ciphertext: " + Hex.toHexString(ciphertext));

			final String plaintext2 = new String(
					decrypt(cipher, key, iv, ciphertext));
			System.out.println("Plaintext (decrypted): " + plaintext2);

			assert (plaintext.equals(plaintext2));
		}
	}


