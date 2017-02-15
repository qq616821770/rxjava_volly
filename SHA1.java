package cn.core.net.secure;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import cn.core.net.Lg;

/**
 * @Description SHA加密算法
 * @author zhuheng397
 * @date 2015-1-15 下午2:32:24
 */
public class SHA1 {

    public static final String SHA1 = "sha1";
    public static final String SHA256 = "sha256";

    public static String encryptSHA(String data, String key) {
        MessageDigest md;
        String result = "";
        try {
            md = MessageDigest.getInstance(key);
            md.update(data.getBytes("utf-8"));
            result = bytes2Hex(md.digest()); // to HexString

        } catch (NoSuchAlgorithmException e) {
            Lg.w(e);
        } catch (UnsupportedEncodingException e) {
            Lg.w(e);
        }
        return result;
    }

    public static String bytes2Hex(byte[] bts) {
        String des = "";
        String tmp = null;
        for (int i = 0; i < bts.length; i++) {
            tmp = (Integer.toHexString(bts[i] & 0xFF));
            if (tmp.length() == 1) {
                des += "0";
            }
            des += tmp;
        }
        return des;
    }
}
