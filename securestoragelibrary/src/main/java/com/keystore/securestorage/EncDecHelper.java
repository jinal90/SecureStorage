package com.keystore.securestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static android.content.ContentValues.TAG;
import static com.keystore.securestorage.Constants.AES_MODE_CBC;
import static com.keystore.securestorage.Constants.AES_MODE_GCM;
import static com.keystore.securestorage.Constants.ANDROID_KEYSTORE;
import static com.keystore.securestorage.Constants.ENCRYPTED_IV;
import static com.keystore.securestorage.Constants.ENCRYPTED_KEY;
import static com.keystore.securestorage.Constants.KEY_ALIAS;
import static com.keystore.securestorage.Constants.RSA_MODE;
import static com.keystore.securestorage.Constants.SHARED_PREFERENCE_NAME;

public class EncDecHelper {



    /**
     * Method to encrpt data using public key obtained from keystore and RSA algorithm.
     *
     * @param plainText
     * @return
     */
    public static String encryptRSA(byte[] plainText) {
        try {

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);

            // Load the key pair from the Android Key Store
            KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
            if (entry == null) {
                Log.w(TAG,"No key found under alias: " + KEY_ALIAS);
                Log.w(TAG,"Exiting signData()...");
                return null;
            }

            Cipher cipher = Cipher.getInstance(RSA_MODE);
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, ks.getCertificate(KEY_ALIAS).getPublicKey());
            String encText = new String(Base64.encode(cipher.doFinal(plainText), Base64.DEFAULT), "UTF-8");
            Log.d(TAG,"keystore Implementation rsa encrypted -- " + encText);
            return encText;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Method to decrypt cipher text using private key obtained from keystore and RSA algorithm
     *
     * @param cipherText
     * @return
     */
    public static byte[] decryptRSA(String cipherText) {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);

            // Load the key pair from the Android Key Store
            KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
            if (entry == null) {
                Log.w(TAG,"No key found under alias: " + KEY_ALIAS);
                Log.w(TAG,"Exiting signData()...");
                return null;
            }

            Key key = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] bytes = cipher.doFinal(Base64.decode(cipherText.getBytes(), Base64.DEFAULT));
            Log.d(TAG,"keystore Implementation rsa decrypted -- " + new String(bytes));
            return bytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void generateAndStoreAesSecretKey(Context mContext) {
        SharedPreferences pref = mContext.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        String encryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null);
        String encryptedIVB64 = pref.getString(ENCRYPTED_IV, null);
        if (TextUtils.isEmpty(encryptedKeyB64) || TextUtils.isEmpty(encryptedIVB64)) {

            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){
                byte[] randomIV = new byte[12];
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(randomIV);
                String randomIVString = Arrays.toString(randomIV);
            }else{
                Cipher eCipher = null;
                try {
                    eCipher = Cipher.getInstance(AES_MODE_CBC);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                }
                byte[] key, realIV;
                if (eCipher != null) {
                    key = new byte[eCipher.getBlockSize()];
                    realIV = new byte[eCipher.getBlockSize()];
                } else {
                    key = new byte[16];
                    realIV = new byte[16];
                }
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(key);
                secureRandom.nextBytes(realIV);

                encryptedKeyB64 = encryptRSA(key);
                encryptedIVB64 = encryptRSA(realIV);
            }


            Log.d(TAG,"keystore Implementation generated key encrypted  -- " + encryptedKeyB64);
            Log.d(TAG,"keystore Implementation generated iv encrypted  -- " + encryptedIVB64);
            SharedPreferences.Editor edit = pref.edit();
            edit.putString(ENCRYPTED_KEY, encryptedKeyB64);
            edit.putString(ENCRYPTED_IV, encryptedIVB64);
            edit.apply();
        }
    }

    public static byte[] getAESSecretKey(Context ctx){
        SharedPreferences pref = ctx.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        String encryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null);

        byte[] key = decryptRSA(encryptedKeyB64);
        return key;
    }

    public static byte[] getAESSecretIV(Context ctx){
        SharedPreferences pref = ctx.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        String encryptedIVB64 = pref.getString(ENCRYPTED_IV, null);

        byte[] key = decryptRSA(encryptedIVB64);
        return key;
    }

    /**
     * Method to encrpt data using symmetric key obtained from keystore and AES algorithm.
     *
     * @param plainText
     * @return
     */
    public static String encryptAES(String plainText, Context ctx) {
        try {
            Log.d(TAG,"keystore Implementation aes plainText  -- " + plainText);
            Cipher c;
            byte[] key, realIV;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                c = Cipher.getInstance(AES_MODE_GCM);
                KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);

                ks.load(null);

                KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
                if (entry == null) {
                    Log.w(TAG,"No key found under alias: " + KEY_ALIAS);
                    Log.w(TAG,"Exiting signData()...");
                    return null;
                }

                byte[] randomIV = new byte[12];
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(randomIV);
                String randomIVString = Arrays.toString(randomIV);
                SharedPreferences pref = ctx.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
                SharedPreferences.Editor edit = pref.edit();
                edit.putString("randomIV", randomIVString).commit();


                c.init(Cipher.ENCRYPT_MODE, ((KeyStore.SecretKeyEntry) entry).getSecretKey(), new GCMParameterSpec(128, randomIV));
            } else {
                c = Cipher.getInstance(AES_MODE_CBC);
                key = getAESSecretKey(ctx);
                realIV = getAESSecretIV(ctx);

                SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(realIV);

                c.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            }

            byte[] encodedBytes = c.doFinal(plainText.getBytes());
            String encryptedBase64Encoded = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
            Log.d(TAG,"keystore Implementation aes encrypted -- " + encryptedBase64Encoded);
            return encryptedBase64Encoded;
        } catch (Exception e) {
            Log.e(TAG," Exception" + " " + "Message:" + e.getMessage() + " -- " + e.getLocalizedMessage());
        }

        return null;
    }

    /**
     * Method to decrypt cipher text using symmetric key obtained from keystore and AES algorithm
     *
     * @param cipherText
     * @return
     */
    public static String decryptAES(String cipherText, Context ctx) {
        try {
            Cipher c;
            byte[] key, realIV;


            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                c = Cipher.getInstance(AES_MODE_CBC);
                KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
                ks.load(null);

                KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
                if (entry == null) {
                    Log.w(TAG,"No key found under alias: " + KEY_ALIAS);
                    Log.w(TAG,"Exiting signData()...");
                    return null;
                }

                SharedPreferences pref = ctx.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
                String randomIVString = pref.getString("randomIV", "");

                byte[] randomIV = new byte[12];
                if (randomIVString != null) {
                    String[] split = randomIVString.substring(1, randomIVString.length()-1).split(", ");
                    randomIV = new byte[split.length];
                    for (int i = 0; i < split.length; i++) {
                        randomIV[i] = Byte.parseByte(split[i]);
                    }
                }

                c.init(Cipher.DECRYPT_MODE, ((KeyStore.SecretKeyEntry) entry).getSecretKey(), new GCMParameterSpec(128, randomIV));

            } else {
                c = Cipher.getInstance(AES_MODE_CBC);
                key = getAESSecretKey(ctx);
                realIV = getAESSecretIV(ctx);

                SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(realIV);

                c.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            }

            byte[] decodedBytes = c.doFinal(Base64.decode(cipherText, Base64.DEFAULT));
            String decryptedText = new String(decodedBytes, 0, decodedBytes.length, "UTF-8");
            Log.d(TAG,"keystore Implementation aes decrypted -- " + decryptedText);
            return decryptedText;
        } catch (Exception e) {
            Log.e(TAG," Exception" + " " + "Message:" + e.getMessage() + " -- " + e.getLocalizedMessage());
        }
        return null;
    }
}
