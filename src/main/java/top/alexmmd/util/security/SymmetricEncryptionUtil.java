package top.alexmmd.util.security;

import cn.hutool.core.lang.Assert;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * 对称加密、解密
 *
 * @author 汪永晖
 * @date 2021/12/23 10:59
 */
public class SymmetricEncryptionUtil {

    /**
     * 对称加密字符串
     *
     * @param content 内容
     * @param key     秘钥
     * @return 加密后
     */
    public static String symmetricCrypto(String content, String key) {

        return symmetricCrypto(content, key, true);
    }

    /**
     * 对称加密字符串解密
     *
     * @param encryptContent 加密内容
     * @param key            秘钥
     * @return 解密后字段
     */
    public static String symmetricDecrypt(String encryptContent, String key) {
        return symmetricCrypto(encryptContent, key, false);
    }

    public static String symmetricCrypto(String content, String key, boolean isEncrypt) {

        Assert.notEmpty(key, "秘钥不能为空!");

        String algorithm = SymmetricAlgorithm.AES.getValue();
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        //构建
        SecretKey secretKey = SecureUtil.generateKey(algorithm, keyBytes);
        AES aes = SecureUtil.aes(secretKey.getEncoded());
        if (isEncrypt) {
            return aes.encryptHex(aes.encrypt(content));
        } else {
            //解密为字符串
            return aes.decryptStr(aes.decrypt(content), CharsetUtil.CHARSET_UTF_8);
        }
    }
}
