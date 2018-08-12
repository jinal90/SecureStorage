package com.keystore.securestorage;

public class Constants {

    public static final String KEY_ALIAS = "SecureStorage";

    public static final String TYPE_RSA = "RSA";
    public static final String AES_MODE_GCM = "AES/GCM/NoPadding";
    public static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    public static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    public static final String TAG = "ENCRYPTION_DECRYPTION";
    public static final String AES_MODE_CBC = "AES/CBC/PKCS7Padding";
    public static final String SHARED_PREFERENCE_NAME = "KeyStoragePref";
    public static final String ENCRYPTED_KEY = "ENCRYPTED_AES_KEY";
    public static final String ENCRYPTED_IV = "ENCRYPTED_AES_IV";
}
