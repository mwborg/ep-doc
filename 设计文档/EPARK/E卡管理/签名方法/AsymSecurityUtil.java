package key;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author gao_lei
 * 
 */
public class AsymSecurityUtil {

	public static final String PROVIDER = "BC";
	public static final String ENCRYPT_ALGORITHM = "DSA";
	private static final String SIGN_ALGORITHM = "SHA3-512WITHDSA";
	private static final String SECURE_RANDOM = "DEFAULT";

	private static final String CHARSET_UTF_8 = "UTF-8";
	private static final String CHARSET_ASCII = "ASCII";
	public static final String PRIVATE_KEY_FILENAME = "private.key";
	public static final String PUBLIC_KEY_FILENAME = "public.key";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static KeyPair generatorKeyPair() throws GeneralSecurityException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ENCRYPT_ALGORITHM, PROVIDER);
		SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM, PROVIDER);
		keyPairGenerator.initialize(1024, random);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * @param directoryPath
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static void genKeyPairAndSave(String directoryPath) throws GeneralSecurityException, IOException {
		if (directoryPath.charAt(directoryPath.length() - 1) != '/') {
			throw new IOException("please input correct directory path, the last char must be '/'");
		}
		File file = new File(directoryPath);
		if (!file.exists()) {
			file.mkdirs();
		}
		KeyPair keyPair = generatorKeyPair();
		savePriKeyToFile(directoryPath, keyPair.getPrivate());
		savePubKeyToFile(directoryPath, keyPair.getPublic());
	}

	/**
	 * @param path
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static PublicKey readPubKeyFromFile(String path) throws IOException, GeneralSecurityException {
		File file = new File(path);
		FileInputStream in = new FileInputStream(file);
		byte[] bytes = new byte[(int) file.length()];
		in.read(bytes);
		return loadPublicKey(bytes);
	}

	/**
	 * @param path
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static PrivateKey readPriKeyFromFile(String path) throws IOException, GeneralSecurityException {
		File file = new File(path);
		FileInputStream in = new FileInputStream(file);
		byte[] bytes = new byte[(int) file.length()];
		in.read(bytes);
		return loadPrivateKey(bytes);
	}

	/**
	 * @param directoryPath
	 * @param publicKey
	 * @throws IOException
	 */
	private static void savePubKeyToFile(String directoryPath, PublicKey publicKey) throws IOException {
		File file = new File(directoryPath + PUBLIC_KEY_FILENAME);
		FileOutputStream out = new FileOutputStream(file);
		out.write(publicKey.getEncoded());
		out.close();
	}

	/**
	 * @param directoryPath
	 * @param privateKey
	 * @throws IOException
	 */
	private static void savePriKeyToFile(String directoryPath, PrivateKey privateKey) throws IOException {
		File file = new File(directoryPath + PRIVATE_KEY_FILENAME);
		FileOutputStream out = new FileOutputStream(file);
		out.write(privateKey.getEncoded());
		out.close();
	}

	/**
	 * @param bytes
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static PublicKey loadPublicKey(byte[] bytes) throws GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance(ENCRYPT_ALGORITHM, PROVIDER);
		return keyFactory.generatePublic(new X509EncodedKeySpec(bytes));
	}

	/**
	 * @param bytes
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static PrivateKey loadPrivateKey(byte[] bytes) throws GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance(ENCRYPT_ALGORITHM, PROVIDER);
		return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(bytes));
	}

	/**
	 * 调用jdk中的Signature类进行签名，签名的结果为byte数组
	 * 为了便于网络传输，对byte数组先进行base64编码，然后按照ASCII格式转换成String
	 */
	public static String sign(String data, PrivateKey privateKey) throws GeneralSecurityException {
		try {
			Signature dsa = Signature.getInstance(SIGN_ALGORITHM, AsymSecurityUtil.PROVIDER);
			dsa.initSign(privateKey);
			dsa.update(data.getBytes(CHARSET_UTF_8));
			byte[] sign = dsa.sign();
			byte[] base64Code = base64EncodeUrlSafe(sign);
			return new String(base64Code, CHARSET_ASCII);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param data
	 * @param sign
	 * @param publicKey
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static boolean vertifySign(String data, String sign, PublicKey publicKey) throws GeneralSecurityException {
		try {
			Signature dsa = Signature.getInstance(SIGN_ALGORITHM, AsymSecurityUtil.PROVIDER);
			dsa.initVerify(publicKey);
			dsa.update(data.getBytes(CHARSET_UTF_8));
			byte[] signToVertify = base64DecodeUrlSafe(sign.getBytes(CHARSET_ASCII));
			return dsa.verify(signToVertify);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * 调用了apache的base64转码函数 为了便于网络传输，将编码后的'+'和'/'替换成其他字符
	 * 
	 * @param data
	 * @return
	 */
	private static byte[] base64EncodeUrlSafe(byte[] data) {
		byte[] encode = Base64.encodeBase64(data);
		for (int i = 0; i < encode.length; i++) {
			if (encode[i] == '+') {
				encode[i] = '-';
			} else if (encode[i] == '/') {
				encode[i] = '_';
			}
		}
		return encode;
	}

	/**
	 * @param data
	 * @return
	 */
	private static byte[] base64DecodeUrlSafe(byte[] data) {
		for (int i = 0; i < data.length; i++) {
			if (data[i] == '-') {
				data[i] = '+';
			} else if (data[i] == '_') {
				data[i] = '/';
			}
		}
		return Base64.decodeBase64(data);
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		try {
			String path = "d:/DSAKey/";
			// String path = "/DSAKey/";

			AsymSecurityUtil.genKeyPairAndSave(path);
			// //只在第一次执行的时候用到，之后执行的时候可以注释掉
			PublicKey publicKey = AsymSecurityUtil.readPubKeyFromFile(path + "public.key");
			PrivateKey privateKey = AsymSecurityUtil.readPriKeyFromFile(path + "private.key");
			String data = "Hello world, this is sign test!";
			String signStr = AsymSecurityUtil.sign(data, privateKey);
			System.out.println(signStr);
			System.out.println(signStr.length());
			System.out.println(AsymSecurityUtil.vertifySign(data, signStr, publicKey));
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
