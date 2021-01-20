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
