package cn.core.net.secure;

import android.util.Base64;

import java.io.IOException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import cn.core.net.Lg;
//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;

public class Des {
 
    private final static String DES = "DES";
    public  static String key = "pawifi123456";
    public static void main(String[] args) throws Exception {
        String data = "12345678";
        String key = "pawifi123456";
        System.err.println(encrypt(data, key));
        System.err.println(decrypt(encrypt(data, key), key));
    }
    /**
     * Description 根据键值进行加密
     * @param data 
     * @param key  加密键byte数组
     * @return
     * @throws Exception
     */
    public static String encrypt(String data, String key) {
        //        String strs = new BASE64Encoder().encode(bt);
		String strs = null;
		try {
			byte[] bt = encrypt(data.getBytes(), key.getBytes());
			strs = Base64.encodeToString(bt, Base64.DEFAULT);
		} catch (Exception e) {
            Lg.w(e);
		}
        return strs;
    }
 
    /**
     * Description 根据键值进行解密
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws IOException
     * @throws Exception
     */
    public static String decrypt(String data, String key){
        byte[] bt = null;
		try {
			if (data == null)
			    return null;
//        BASE64Decoder decoder = new BASE64Decoder();
//        byte[] buf = decoder.decodeBuffer(data);
			byte[] buf= Base64.decode(data, Base64.DEFAULT);
			bt = decrypt(buf,key.getBytes());
		} catch (Exception e) {
            Lg.w(e);
		}
        return new String(bt);
    }
 
    /**
     * Description 根据键值进行加密
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws Exception
     */
    private static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();
 
        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key);
 
        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);
 
        // Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(DES);
 
        // 用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);
 
        return cipher.doFinal(data);
    }
     
     
    /**
     * Description 根据键值进行解密
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws Exception
     */
    private static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();
 
        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key);
 
        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);
 
        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(DES);
 
        // 用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);
 
        return cipher.doFinal(data);
    }
}