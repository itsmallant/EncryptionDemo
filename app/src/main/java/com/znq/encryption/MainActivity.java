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
        String encryptedKey = Base64.encodeToString(RSAUtils.encryptByPrivateKey(key.getBytes(), server_pri_key));

        Log.e(TAG, "客户端原始数据 key = " + key + " body = " + body+" encryptedKey = "+encryptedKey);
        //服务端使用服务端私钥RSA解密加密后的key，得到客户端随机生成的key
        String originKey = new String(RSAUtils.decryptByPublicKey(Base64.decode(encryptedKey), server_pub_key));
        //服务端使用随机key，通过AES解密数据
        String originBody = AESUtils.decrypt(encryptedBody, originKey);

        Log.e(TAG, "服务端解密得到的数据 originKey = " + originKey + " originBody = " + originBody);
    }
}