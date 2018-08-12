package com.keystore.securestorage;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import javax.crypto.KeyGenerator;
import javax.security.auth.x500.X500Principal;

import static com.keystore.securestorage.Constants.ANDROID_KEYSTORE;
import static com.keystore.securestorage.Constants.KEY_ALIAS;
import static com.keystore.securestorage.Constants.TYPE_RSA;

public class KeyStoreManager {

    /**
     * Creates a public and private key and stores it using the Android Key Store, so that only
     * this application will be able to access the keys.
     */
    public void createAndStoreKeys(Context context) throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        boolean hasAlias = false;
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            Enumeration<String> aliases = ks.aliases();

            if (aliases != null)
                while (aliases.hasMoreElements()) {
                    String param = aliases.nextElement();
                    if (KEY_ALIAS.equalsIgnoreCase(param)) {
                        hasAlias = true;
                        break;
                    }
                }
        } catch (Exception e) {
            e.printStackTrace();
        }


        if (!hasAlias) {

            Calendar start = new GregorianCalendar();
            Calendar end = new GregorianCalendar();
            end.add(Calendar.YEAR, 30);

            KeyPairGenerator kpGenerator;

            KeyPairGeneratorSpec spec =
                    new KeyPairGeneratorSpec.Builder(context)
                            .setAlias(KEY_ALIAS)
                            .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                            .setSerialNumber(BigInteger.valueOf(1337))
                            .setStartDate(start.getTime())
                            .setEndDate(end.getTime())
                            .build();
            kpGenerator = KeyPairGenerator
                    .getInstance(TYPE_RSA, ANDROID_KEYSTORE);
            kpGenerator.initialize(spec);



            kpGenerator.generateKeyPair();
        }

    }

    public void createKeysForAES() throws KeyStoreException, NoSuchAlgorithmException,
            IOException, CertificateException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        if (!keyStore.containsAlias(KEY_ALIAS)) {

            KeyGenerator keyGenerator;
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    ANDROID_KEYSTORE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenerator.init(
                        new KeyGenParameterSpec.Builder(KEY_ALIAS,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setRandomizedEncryptionRequired(false)
                                .build());
            }
            keyGenerator.generateKey();
        }
    }

//    public void setAlias(String alias) {
//        mAlias = alias;
//    }
//
//    public String getmAlias() {
//        return mAlias;
//    }
}

