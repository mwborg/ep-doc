
package com.im.epark.utils.alipay;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import com.im.epark.utils.Base64;

public class RSA{
	
	public static final String  SIGN_ALGORITHMS = "SHA1WithRSA";
	
	/**
	* RSA签名
	* @param content 待签名数据
	* @param privateKey 商户私钥
	* @param input_charset 编码格式
	* @return 签名值
	*/
	public static String sign(String content, String privateKey, String input_charset)
	{
        try 
        {
        	PKCS8EncodedKeySpec priPKCS8 	= new PKCS8EncodedKeySpec( Base64.decode(privateKey) ); 
        	KeyFactory keyf 				= KeyFactory.getInstance("RSA");
        	PrivateKey priKey 				= keyf.generatePrivate(priPKCS8);

            java.security.Signature signature = java.security.Signature
                .getInstance(SIGN_ALGORITHMS);

            signature.initSign(priKey);
            signature.update( content.getBytes(input_charset) );

            byte[] signed = signature.sign();
            
            return Base64.encode(signed);
        }
        catch (Exception e) 
        {
        	e.printStackTrace();
        }
        
        return null;
    }
	
	/**
	* RSA验签名检查
	* @param content 待签名数据
	* @param sign 签名值
	* @param ali_public_key 支付宝公钥
	* @param input_charset 编码格式
	* @return 布尔值
	*/
	public static boolean verify(String content, String sign, String ali_public_key, String input_charset)
	{
		try 
		{
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        byte[] encodedKey = Base64.decode(ali_public_key);
	        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));

		
			java.security.Signature signature = java.security.Signature
			.getInstance(SIGN_ALGORITHMS);
		
			signature.initVerify(pubKey);
			signature.update( content.getBytes(input_charset) );
		
			boolean bverify = signature.verify( Base64.decode(sign) );
			return bverify;
			
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	* 解密
	* @param content 密文
	* @param private_key 商户私钥
	* @param input_charset 编码格式
	* @return 解密后的字符串
	*/
	public static String decrypt(String content, String private_key, String input_charset) throws Exception {
        PrivateKey prikey = getPrivateKey(private_key);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, prikey);

        InputStream ins = new ByteArrayInputStream(Base64.decode(content));
        ByteArrayOutputStream writer = new ByteArrayOutputStream();
        //rsa解密的字节大小最多是128，将需要解密的内容，按128位拆开解密
        byte[] buf = new byte[128];
        int bufl;

        while ((bufl = ins.read(buf)) != -1) {
            byte[] block = null;

            if (buf.length == bufl) {
                block = buf;
            } else {
                block = new byte[bufl];
                for (int i = 0; i < bufl; i++) {
                    block[i] = buf[i];
                }
            }

            writer.write(cipher.doFinal(block));
        }

        return new String(writer.toByteArray(), input_charset);
    }

	
	/**
	* 得到私钥
	* @param key 密钥字符串（经过base64编码）
	* @throws Exception
	*/
	public static PrivateKey getPrivateKey(String key) throws Exception {

		byte[] keyBytes;
		
		keyBytes = Base64.decode(key);
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		
		return privateKey;
	}
	
	public static void main(String[] args) {
		
		String pri_key = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKer8ndt5AhhtcN2a6eSXlMkOZi1R16EOIxRbK0laoqGwF49eKKcRH6xx+1x8Ximufi6VbmtwYx+0VNH"
				+ "1irY/uGeRcj53WU/Lhj/JEdY6ZkChZ16rZbmYF8KhU5v/dgXy1vBcCF+LZLykheUk3kXWdHKoz7oyMpLWvsRYKMgX08LAgMBAAECgYBsqqnH8TZ6oCjW9yaqQdhT9gRG"
				+ "DialAPhNKHBQfxFfmhmOejR23uQdYEb8gn5G/XdF1i282vm3fnFXkhUhS+VTc0LjAgtaimMdW2jdJtdD3RjN13WH2/K6xOAGQCZfx+fCZlkI/NvCh/9WpRsKab3Gy5qi"
				+ "Uz339uFald+lcKA8cQJBANUNZEBtHRzQObb9LZrkhBLiq2GVrxBtXu2yErTwbMhDHoV5RBAuONQ0uIhKulHP7V/UfPyQL3U5IgU367zZfZ8CQQDJeK2ZkIMFjwUIfe/z"
				+ "if1eE0BOO6zbRhNE/FgeKQMfXY13yCVfBXehG59eJdB5kgmuY2OcDq8t4WuMt9rW1l8VAkAlV76NqFJk/X5QO5olvw4DPWWqqhDQQUtVQFQVENsQUutjm7i5WVCuqTr6"
				+ "8JYtxtMla9oobqFS25vB7GZOaJSjAkA5BpVsoADV8/NiwfLHJkm29RAAlNeKgT03C44Ni2I84IgIXXhmeu+vhFgJl/54SqO+3pb1NxrSi7mbbPbeVHM5AkEAy2kQ9/+C"
				+ "7YBVrzo0c8Io8OaRUVDFen41lRgmz9TB3yFQHcaR7e9qWpl1pPH9g5xjTza9S28I+q5aCpvI4XUnLw==";
		
		String content = "Hello world, this is sign test!";
		
		String si = sign(content, pri_key, "utf-8");
		
		System.out.println(si);
		
		String public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnq/J3beQIYbXDdmunkl5TJDmYtUdehDiMUWytJWqKhsBePXiinER+scftcfF4prn4ulW5rcGMftFTR9Yq2P7hnkXI+d1lPy4Y/yRHWOmZAoWdeq2W5mBfCoVOb/3YF8tbwXAhfi2S8pIXlJN5F1nRyqM+6MjKS1r7EWCjIF9PCwIDAQAB";
		
		boolean bool = verify("Hello world, this is sign test!", "QN0s2o7qC4czTesOvL7UlPzmv1YfgrBYsH2PqvHhq8LugEH4uICcr8INtn46gYAhMcxEo5/gR3X+yyjJcsCEhbRZaSOvJ0zcoNaatZv5P+R04oJkRBq3Hbp618nIvGcWw2PKjIC1TLYsB0xKI17s45rUFuCvP5mbqCkzCqZ1V1o=", public_key, "utf-8");
		
		System.out.println(bool);
		
	}
	
}
