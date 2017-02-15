package cn.core.net.secure;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import cn.core.net.Lg;

/**
 * 3DES加密工具类
 * 
 * @author liufeng 
 * @date 2012-10-11
 */
public class Des3 {
    // 密钥
    public final static String key = "pawifi1234567890123456789";
    // 向量
    private final static String iv = "01234567";
    // 加解密统一使用的编码方式
    private final static String encoding = "utf-8";

    /**
     * 3DES加密
     * 
     * @param plainText 普通文本
     * @return
     * @throws Exception
     */
    public static String encode(String plainText, String key) {
        byte[] encryptData = null;
		try {
			Key deskey = null;
			DESedeKeySpec spec = new DESedeKeySpec(key.getBytes());
			SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
			deskey = keyfactory.generateSecret(spec);

			Cipher cipher = Cipher.getInstance("desede/CBC/PKCS5Padding");
			IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
			cipher.init(Cipher.ENCRYPT_MODE, deskey, ips);
			encryptData = cipher.doFinal(plainText.getBytes(encoding));
		} catch (InvalidKeyException e) {
			Lg.w(e);
		} catch (NoSuchAlgorithmException e) {
			Lg.w(e);
		} catch (InvalidKeySpecException e) {
			Lg.w(e);
		} catch (NoSuchPaddingException e) {
			Lg.w(e);
		} catch (InvalidAlgorithmParameterException e) {
			Lg.w(e);
		} catch (IllegalBlockSizeException e) {
			Lg.w(e);
		} catch (BadPaddingException e) {
			Lg.w(e);
		} catch (UnsupportedEncodingException e) {
			Lg.w(e);
		}
        return Base64.encode(encryptData);
    }

    /**
     * 3DES解密
     * 
     * @param encryptText 加密文本
     * @return
     * @throws Exception
     */
    public static String decode(String encryptText, String key)  {
        byte[] decryptData=null;
        String result=null;
		try {
			Key deskey = null;
			DESedeKeySpec spec = new DESedeKeySpec(key.getBytes());
			SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
			deskey = keyfactory.generateSecret(spec);
			Cipher cipher = Cipher.getInstance("desede/CBC/PKCS5Padding");
			IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, deskey, ips);
			decryptData = cipher.doFinal(Base64.decode(encryptText));
			result=new String(decryptData, encoding);
		} catch (InvalidKeyException e) {
			Lg.w(e);
		} catch (NoSuchAlgorithmException e) {
			Lg.w(e);
		} catch (InvalidKeySpecException e) {
			Lg.w(e);
		} catch (NoSuchPaddingException e) {
			Lg.w(e);
		} catch (InvalidAlgorithmParameterException e) {
			Lg.w(e);
		} catch (IllegalBlockSizeException e) {
			Lg.w(e);
		} catch (BadPaddingException e) {
			Lg.w(e);
		} catch (UnsupportedEncodingException e) {
			Lg.w(e);
		}

        return result;
    }
}