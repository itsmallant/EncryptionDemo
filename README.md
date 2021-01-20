# Android网络请求加密总结

公司最近需要对App进行安全认证，检查发现在数据请求过程中有明文传输的问题，这就需要在数据传输中进行加密了。

## 加密方案

在查找了相关资料后，决定使用RSA结合AES，实现双向验证的方案。

以客户端给服务端传输数据为例，大概流程如下：

1. 客户端和服务端均生成一对RSA秘钥，私钥各自保管，公钥给对方；
2. 客户端使用随机函数生成AES加密要用的秘钥key1；
3. 客户端使用key1对要传输的数据进行AES加密，生成data1；
4. 客户端使用服务端给的公钥对key1进行RSA加密，生成key2
5. 客户端将data1和key2一起发给服务端；
6. 服务端拿到数据后，先使用自己的私钥对key2进行RSA解密，得到客户端生成的随机秘钥key1，再使用key1对data1进行AES解密就得到真实的数据了。

服务端给客户端传输数据和上面流程一样，因为第一步是重叠的，直接从第二步开始：

1. 服务端使用随机函数生成AES加密要用的秘钥key1；
2. 服务端使用key1对要传输的数据进行AES加密，生成data1；
3. 服务端使用客户端给的公钥对key1进行RSA加密，生成key2；
4. 服务端将data1和key2一起发给客户端；
5. 客户端拿到数据后，先使用自己的私钥对key2进行RSA解密，得到服务端生成的随机秘钥key1，再使用key1对data1进行AES解密就得到真实的数据了。

总结起来就是：

1. 两端均生成一对RSA秘钥，各自保管好私钥，公钥给对方；
2. 两端各自使用随机key对数据进行AES加密，再使用对方的公钥对随机key进行RSA加密，将加密后的数据和随机key发给对方；
3. 收到数据后，首先通过各自RSA私钥解密出随机key，在使用随机key通过AES得到真实数据

## 代码实现

### AES加解密工具类：

```java
package com.znq.encryption.utils;


import android.util.Log;


import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import androidx.annotation.NonNull;


/**
 * @author : yzq
 * @description: AES工具类
 * @date : 2019/3/18
 * @time : 9:54
 */

public class AESUtils {
    private static final String TAG = "AESUtils";

    private static String cipherMode = "AES/ECB/PKCS5Padding";//算法/模式/补码方式


    /**
     * @param length 需要生成的字符串长度
     * @return 随机生成的字符串
     */
    public static String getRandomKey(int length) {

        if (length != 16 && length != 24 && length != 32) {
            System.out.println("长度必须为16/24/32");
            return null;
        }

        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(62);
            stringBuilder.append(str.charAt(number));
        }
        return stringBuilder.toString();

    }


    /**
     * @param data 需要加密的数据
     * @param key  加密使用的key
     * @return 加密后的数据(Base64编码)
     * @throws Exception
     */
    public static String encrypt(String data, @NonNull String key) throws Exception {

        int length = key.length();
        if (length != 16 && length != 24 && length != 32) {
            Log.e(TAG, "长度必须为16/24/32");
            return null;
        }

        byte[] raw = key.getBytes("utf-8");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance(cipherMode);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes("utf-8"));

        return Base64.encodeToString(encrypted);
    }


    /**
     * @param data 需要解密的数据
     * @param key  解密用的key
     * @return 解密后的数据
     * @throws Exception
     */
    public static String decrypt(String data, @NonNull String key) throws Exception {
        try {
            int length = key.length();
            if (length != 16 && length != 24 && length != 32) {
                System.out.println("长度必须为16/24/32");
                return null;
            }

            byte[] raw = key.getBytes("utf-8");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance(cipherMode);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] encrypted = Base64.decode(data);//先用base64解密
            try {
                byte[] original = cipher.doFinal(encrypted);
                return new String(original, "utf-8");
            } catch (Exception e) {
                System.out.println(e.toString());
                return null;
            }
        } catch (Exception ex) {
            System.out.println(ex.toString());
            return null;
        }
    }

}
```

### RSA加解密工具类：

```java
package com.znq.encryption.utils;


import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;


/**
 * @author : yzq
 * @Description: RSA工具类，支持长度为2048的秘钥
 * @date : 2019/3/18
 * @time : 16:29
 */
public class RSAUtils {

    private static final String CIPHER_MODE = "RSA/ECB/OAEPwithSHA-256andMGF1Padding";
    /**
     * 加密算法RSA
     */
    private static final String KEY_ALGORITHM = "RSA";

    /**
     * 签名算法
     */
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    /**
     * 获取公钥的key
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";


    /**
     * 获取私钥的key
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";


    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;


    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 256;


    /**
     * @param keySize 生成的秘钥长度  一般为1024或2048
     * @return
     * @throws Exception
     */
    public static Map<String, Object> genKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(keySize);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);

        System.out.println("publicKey：" + Base64.encodeToString(publicKey.getEncoded()));
        System.out.println("privateKey：" + Base64.encodeToString(privateKey.getEncoded()));

        return keyMap;
    }


    /**
     * 对已加密数据进行签名
     *
     * @param data       已加密的数据
     * @param privateKey 私钥
     * @return 对已加密数据生成的签名
     * @throws Exception
     */

    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64.encodeToString(signature.sign());
    }


    /**
     * 验签
     *
     * @param data      签名之前的数据
     * @param publicKey 公钥
     * @param sign      签名之后的数据
     * @return 验签是否成功
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = Base64.decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.decode(sign));
    }


    /**
     * 用私钥对数据进行解密
     *
     * @param encryptedData 使用公钥加密过的数据
     * @param privateKey    私钥
     * @return 解密后的数据
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeNoWrap(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        //Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.DECRYPT_MODE, privateK);

        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();


        return decryptedData;
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 使用私钥加密过的数据
     * @param publicKey     公钥
     * @return 解密后的数据
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decodeNoWrap(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }


    /**
     * 公钥加密
     *
     * @param data      需要加密的数据
     * @param publicKey 公钥
     * @return 使用公钥加密后的数据
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decodeNoWrap(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }


    /**
     * 私钥加密
     *
     * @param data       待加密的数据
     * @param privateKey 私钥
     * @return 使用私钥加密后的数据
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }


    /**
     * 获取私钥
     *
     * @param keyMap 生成的秘钥对
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return Base64.encodeToString(key.getEncoded());
    }


    /**
     * 获取公钥
     *
     * @param keyMap 生成的秘钥对
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return Base64.encodeToString(key.getEncoded());
    }
}
```

在使用AES和RSA进行加解密的时候，指定`Cipher`的算法、模式和填充要与服务端的保持一致，不然会报异常。关于安卓支持的算法、模式和填充请查看[官方文档](https://developer.android.com/guide/topics/security/cryptography?hl=zh-cn#SupportedCipher)说明。

### Base64工具类：

```java
package com.znq.encryption.utils;

/**
 * @desc:
 * @author: ningqiang.zhao
 * @time: 1/14/21 2:25 PM
 **/
public class Base64 {
    public static String encodeToString(byte[] input) {
        return android.util.Base64.encodeToString(input, android.util.Base64.NO_WRAP | android.util.Base64.URL_SAFE);
    }

    public static byte[] decode(String str) {
        return android.util.Base64.decode(str, android.util.Base64.URL_SAFE);
    }

    public static byte[] decodeNoWrap(String str) {
        return android.util.Base64.decode(str, android.util.Base64.NO_WRAP);
    }
}

```

### 使用Demo

```java
package com.znq.encryption;

import android.os.Bundle;
import android.util.Log;
import android.view.View;

import com.znq.encryption.utils.AESUtils;
import com.znq.encryption.utils.Base64;
import com.znq.encryption.utils.RSAUtils;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    //客户端RSA公钥
    public static final String client_pub_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA80l61jM4RxV9gbpoNMew" +
            "REpNHbqsMxpIaHNUE2Y1SWu8LTmwEbitanF/UXAraYHu4scVhyWWBEDdcCDDL6iD" +
            "OIoZ8TGXOKSVZZdHGy0lsK8/nMnmi3KWhmcWcpUZnQIGcgh9NanT8bLWrrz/eOJA" +
            "Mgoi/Nucyq8lAeB0986A7QKOL9CIB6bC5WMfP+NYRuWv1s46HBszDQ5SXK9l8qZF" +
            "5kFzg+m/L/mfbD0qH31P33E3o1zXdaSdl5nJ194gslb6W7bUMHMmLUeTsXV9aYeI" +
            "1q+cDHD51FhoPtkcz3sWO4A6itLJ6k2mtV63QcSysm4quIOKnugKyDf+7ieiF6Ru" +
            "3QIDAQAB";
    //客户端RSA私钥
    private static final String client_pri_key = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDzSXrWMzhHFX2B" +
            "umg0x7BESk0duqwzGkhoc1QTZjVJa7wtObARuK1qcX9RcCtpge7ixxWHJZYEQN1w" +
            "IMMvqIM4ihnxMZc4pJVll0cbLSWwrz+cyeaLcpaGZxZylRmdAgZyCH01qdPxstau" +
            "vP944kAyCiL825zKryUB4HT3zoDtAo4v0IgHpsLlYx8/41hG5a/WzjocGzMNDlJc" +
            "r2XypkXmQXOD6b8v+Z9sPSoffU/fcTejXNd1pJ2XmcnX3iCyVvpbttQwcyYtR5Ox" +
            "dX1ph4jWr5wMcPnUWGg+2RzPexY7gDqK0snqTaa1XrdBxLKybiq4g4qe6ArIN/7u" +
            "J6IXpG7dAgMBAAECggEBALvcK5wnZPeO4qE//aNz5up0rWOdd8bmLq9pDq0EKXWO" +
            "WXpap1in0FD3XybVhNAt4vb+X+NB5LtYEyW4RsAQUXNhQHL8pha5EBuoWuHjVM1A" +
            "JdC+HuXjD9Ss2aqU83hHzg5T+8tqXhyuyhOYIXWIz6VUKnwyYLop0FvIpMmNjgR0" +
            "iS8twjx9vyP9qZe48r2lOnZ4peES3UyDTBp8K/kydvmebev4LVqx8d6EhmZ/8SWA" +
            "m+CLHBPMNZ3uQGy1jCHQMLecJkvXOHqn3J2jJ0RxJeWww0rpJqmgQqCcx0Alyows" +
            "g7B8DpQuYIE0hgY/CaKUMel9f2skwqFetmI+dH2F8cECgYEA/zkkYVGs4zdQHx/c" +
            "cMYJGrvS3RfIGsiAhMeA6/JY/VEi8wp+kWRdf0LZXcEBQLSy1GAFKZWSFJBzK0uo" +
            "IQna4067jfrATyFrkrB/WjB2lskCN0bI2rYNZII5wPh47LH22AWHWYGvLiUD296a" +
            "RWuKx6K2eFw2KZV9dzzWoBrssFUCgYEA9AcJoO1witZEOUA86yxH0OP31KLUbGBv" +
            "NHpCADOGIde2+RoNQKjrwbQY2rCqlKsnmftsVfNf+gSh3g9KtGXw7D6+mc9IZ1Ic" +
            "3CinMn35OopKKuRpS3gPUh8wYcYq+OSgzqkH0byUC+z0PYWj7+oXrmke4s6JTM5R" +
            "JhCy5li7rGkCgYEAkIXUEwPECdpNlYJeOsH5b9kB+862smvtUsMCPxm5yKBEUSoV" +
            "J9GUnDbHja54PiLUzSweYEDhOqHdhZvO9f51o5f23twqP+Tl3GfzhafBz3q9tX1w" +
            "yWCjztFrUNmi6C2SYRsoXMfx4gh12fCAnWTbbla2Swu0Y/HR3U5nHryAYQ0CgYA5" +
            "Kczfnb9XRooEvz+F94F7NWvAq8QG/zANovYDBg7NrrJ199xS4T8YyQ9paykKWm2U" +
            "bIkcOT6qWptwYTSmvZqKPMh5T00uptWL3RoNgeT4CZ0GHytrOlycaCH1RW6bjzL8" +
            "NixWvU4Q3Rj5sGyOrs+NU6KgjrErBMmNmSvPOcn8wQKBgQDyNbI5WL7RbsCdFjh4" +
            "sznz9SfhaYuRELXFbcHWxNXVwm+x1Og7skZ6qIAdlLHPlGraxw2LTyUSzE92FCFI" +
            "0N7ClsV1xRFXHNncnXbdmKWjy0GXmR7RpkD+1GQvQl9BDjztOCjafvTyPJL6OHSG" +
            "uiF1UjwrnrT62J8l8rIITypiww==";

    //服务端RSA公钥
    private static final String server_pub_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1yFKjpQNVAHrY3IyXZW2" +
            "jj0y3tx6EYdPAf3EB15xwU10SoOCwQUvtPA2tR0xDUGcizavEEOUv8Hf91UPBokE" +
            "xNUGI4MeWt3sFTWDcCrPm8NgQfHjQ71YEd2Xgzlf1cGPawTIB4omMdKxSWzOneKr" +
            "5bBKoFGEUXBsxVRjUFhT7KzyE7ubLOjoqQRqr7wcObYWo8EALPfV8ELCcRbcexl7" +
            "uMw6FIBhVzvOBlFOYEBbrgs5nEtK9o1CLKasV6bPhGdgMtwQ3CFPfbbyNQXkdq5S" +
            "8R18GqlG1y/vWL/pLdHJBMf3XjJF0brpD/oZ8/5hCBk+sYvNT8FEharJXYpPb9xW" +
            "QwIDAQAB";
    //服务端RSA私钥
    private static final String server_pri_key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDXIUqOlA1UAetj" +
            "cjJdlbaOPTLe3HoRh08B/cQHXnHBTXRKg4LBBS+08Da1HTENQZyLNq8QQ5S/wd/3" +
            "VQ8GiQTE1QYjgx5a3ewVNYNwKs+bw2BB8eNDvVgR3ZeDOV/VwY9rBMgHiiYx0rFJ" +
            "bM6d4qvlsEqgUYRRcGzFVGNQWFPsrPITu5ss6OipBGqvvBw5thajwQAs99XwQsJx" +
            "Ftx7GXu4zDoUgGFXO84GUU5gQFuuCzmcS0r2jUIspqxXps+EZ2Ay3BDcIU99tvI1" +
            "BeR2rlLxHXwaqUbXL+9Yv+kt0ckEx/deMkXRuukP+hnz/mEIGT6xi81PwUSFqsld" +
            "ik9v3FZDAgMBAAECggEBAL56WJRTXFW0eWGM3DFmfMQGRcNzvZVFk9v0f5vysI/x" +
            "73SGasBSwkHXqujD1wmgvWW53lltLQh4NcC9jFdB/Hn3D79juf3EnuLMhftLvJRy" +
            "8giRjqMMxCzVYfCrXUJbZovgKOgcFuNoZNbZQzwiVgdCB2FZq+mbvIMfy+t4uZ5E" +
            "h2MSrn5EWfiShHagUdCOiods5pu+4Nvc02OPGCKTBjb5S6EQjLZf6A5UivUCXymo" +
            "Nidj73kIADU/Xt+RF0yV7vMOVS9eLDe51Y0wpD5xUv13h10kyPBGvS8QiHh5hFyO" +
            "2+FoKGIYsLJhOLe2d5SX3l8WLW/A6iBvI5oG11ekBJkCgYEA6r0X8l2b1+PLvOFS" +
            "MUOsIeOfYhfIyD7EWEhIi8eGkDK1IvMQ6zyrEd0+oEjQm4rXGBBE67VES+uyRjOo" +
            "gHVURDxdzvqlgjqzOLzABKQ7f30fBKiqomiNcFmGnCdgBLl/5wKlu4sN/RPCVKTE" +
            "X6rXlw5XHhMI89qLnMRfe+9Iwd0CgYEA6p2H/syY6l3VpOBVzqJEaCTkv6PW8+qr" +
            "3QIt04q4cnu6q6r5mSoI3EAZf9PeiZGOpuXg3lXXdKUBhx09OsnSkmsJcBYVS/+N" +
            "7gkcCA1mbVXi0adQd2s+WPo7IkDZ+ik8McMbBupYpTCSg+/F++7j8frdWPCAUCIR" +
            "5i1pu0Z3xp8CgYBPwHL0Wy1pifFceMkuB6nh0a4C68XBkuGuhNBw/RcQwsmb2C01" +
            "XuVYKmzulA6b6e3uNQjVdD6B9NAa3c4v5qz8ie3tNmco+byOWEJ80TeNtvrk4FEo" +
            "4JC9TQ1Y3F/Y+xUjbVjVgQb9psrtaxV001xv6+VZSGpQPz4TwvwV5VQ42QKBgQC6" +
            "3PmCQabRlCcjiOIPEEL3x9rBoFcGMzTrdF7XjDdYR5/oNudRzJ79/bfRjghC/cHm" +
            "wFUYALr4Vqwe13T7K+Ahaks8EPqpa0O6AVtoNnQMRUnAvkhitPIVoEgVAh4bF1iw" +
            "MbuHCIPOHh+0IfdIr36yLqK5weQQ7vHeqPD7jia79QKBgEJO0CAULxe9c3HGOVBm" +
            "mYCno4T3uBsxFwKBeE+eU9SaQAkX54LXPqebFe33Q/jdnzJSNgwpST5/ZXsam6I0" +
            "YxmLCiDJJaaB30EH51fSG3SiGXOandYJBw1OlKgMWrDZnVWL9l8vVu/ZOFRL0Ogg" +
            "dXdEYNRIWSyoC7bYVJEM4qHd";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

    }

    public void test(View view) throws Exception {
        String body = "hello world";
        //客户端生成随机key
        String key = AESUtils.getRandomKey(16);
        //客户端使用随机key对数据进行AES加密
        String encryptedBody = AESUtils.encrypt(body, key);
        //客户端使用服务端公钥对随机key进行RSA加密
        String encryptedKey = Base64.encodeToString(RSAUtils.encryptByPublicKey(key.getBytes(), server_pub_key));

        Log.e(TAG, "客户端原始数据 key = " + key + " body = " + body);
        //服务端使用服务端私钥RSA解密加密后的key，得到客户端随机生成的key
        String originKey = new String(RSAUtils.decryptByPrivateKey(Base64.decode(encryptedKey), server_pri_key));
        //服务端使用随机key，通过AES解密数据
        String originBody = AESUtils.decrypt(encryptedBody, originKey);

        Log.e(TAG, "服务端解密得到的数据 originKey = " + originKey + " originBody = " + originBody);
    }
}
```

### 遇到的坑

刚开始生成的秘钥格式选择的是PKCS#1，在安卓10的设备上测试没问题，换了个安卓7的设备就报错：

```
java.lang.RuntimeException: error:0c0890ba:ASN.1 encoding routines:asn1_check_tlen:WRONG_TAG
```

这是因为安卓的低版本不支持PKCS#1导致的，当生成的pem文件头部是`-----BEGIN RSA PRIVATE KEY-----`意味着私钥的格式是PKCS#1。可以使用openssl工具将其转为PKSC#8：

```
# openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs1.key -out pkcs8.key
```

## 总结

* 秘钥一定要妥善保管；
* 加解密算法的模式、填充要两端保持一致；
* 在Android上使用秘钥一定要选择PKCS#8格式，防止出现兼容问题
* 在提交数据的时候，对加密数据进行Base64时建议选择URL安全模式`URL_SAFE`，防止GET请求参数加密时出问题。



参考文章：

[网络传输数据加解密方案选择（RSA+AES）](https://yuzhiqiang.blog.csdn.net/article/details/88641265)

[Android/Java完美使用RSA2结合AES对数据进行加解密（兼容RSA2 SHA256WithRSA，可使用2048长度的秘钥，AES Android各版本通用）](https://yuzhiqiang.blog.csdn.net/article/details/88657793)

[Google官方加密文档](https://developer.android.com/guide/topics/security/cryptography?hl=zh-cn)

[在线生成RSA秘钥](http://web.chacuo.net/netrsakeypair)

[PKCS#1报错的问题](https://www.hellojava.com/a/54196.html)





