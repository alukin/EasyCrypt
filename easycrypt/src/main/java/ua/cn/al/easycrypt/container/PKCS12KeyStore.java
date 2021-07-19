/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation, version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * LICENSE
 */
package ua.cn.al.easycrypt.container;

import ua.cn.al.easycrypt.CryptoConfig;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Java key store is actually PKCS12 key store. So this class supports p12 and
 * jks files
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class PKCS12KeyStore {

    public static final String KEYSTORE_TYPE = "pkcs12";
    private KeyStore keystore;
    List<String> aliases = new ArrayList<>();
    List<Certificate> certificates = new ArrayList<>();

    private static final Logger log = LoggerFactory.getLogger(PKCS12KeyStore.class);

    public boolean openKeyStore(String path, String password) {
        boolean res = true;
        InputStream is = null;
        try {
            File file = new File(path);
            is = new FileInputStream(file);
            keystore = KeyStore.getInstance(KEYSTORE_TYPE, CryptoConfig.getProvider());
            keystore.load(is, password.toCharArray());
            Enumeration<String> enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                aliases.add(alias);
                Certificate certificate = keystore.getCertificate(alias);
                certificates.add(certificate);
            }
        } catch (FileNotFoundException ex) {
            log.error("File" + path + " does not exists", ex);
            res = false;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
            log.error("File" + path + " is not loadable", ex);
            res = false;
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (IOException ex) {
                log.error("File" + path + " is not loadable", ex);
                res = false;
            }
        }
        return res;
    }

    public boolean createOrOpenKeyStore(String path, String password) {
        boolean res = true;
        try {
            File file = new File(path);
            keystore = KeyStore.getInstance(KEYSTORE_TYPE,CryptoConfig.getProvider());
            if (file.exists()) {
                // if exists, load
                res = openKeyStore(path, password);
            } else {
                // if not exists, create
                keystore.load(null, null);
                keystore.store(new FileOutputStream(file), password.toCharArray());
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            log.error("Can not create file" + path, ex);
            res = false;
        }
        return res;
    }

    public List<String> getAliases() {
        return aliases;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }
    
    public Key getKey(String alias, String password){
        Key key = null;
        try {
            key = keystore.getKey(alias, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            log.error("Can not read key with alias:" + alias, ex);
        }
        return key;
    }
    
    public PrivateKey getPrivateKey(String alias, String password){
        PrivateKey key = null;
        Key k = getKey(alias, password);
        if(k instanceof PrivateKey){
            key=(PrivateKey) k;
        }
        return key;
    }
    
    public boolean addSymmetricKey(byte[] key, String algo, String alias, String password){
        boolean res = true;
        try {
            SecretKey secretKey = new SecretKeySpec(key,algo);
            KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.ProtectionParameter pwd  = new KeyStore.PasswordProtection(password.toCharArray());
            keystore.setEntry(alias, secret, pwd);
            return res;
        } catch (KeyStoreException ex) {
           log.error("Can not set key entry with alias: "+alias,ex);
           res=false;
        }
        return res;
    }
    
    public boolean addCertificate(String alias, X509Certificate cert){
        boolean res = true;
        try {
            keystore.setCertificateEntry(alias, cert);
        } catch (KeyStoreException ex) {
           log.error("Can not set certificate entry with alias: "+alias,ex);
           res=false;
        }
        return res;       
    }
    
    public boolean addPrivateKey(PrivateKey pvtKey, String alias, String password, X509Certificate cert, X509Certificate caCert){
        boolean res = true;
        if(password==null){
            password="";
        }
        try {
            X509Certificate[] chain = new X509Certificate[2];
            chain[0] = cert;
            chain[1] = caCert;
            keystore.setKeyEntry(alias, pvtKey, password.toCharArray(), chain);       
            return res;
        } catch (KeyStoreException ex) {
            log.error("Can not set private key entry with alias: "+alias,ex);
            res=false;
        }
        return res;
    }

    public boolean save(String path, String password){
        boolean res = false;
        File file = new File(path);
        try(FileOutputStream fos = new FileOutputStream(file)) {
            keystore.store(fos, password.toCharArray());
        } catch ( KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
             log.error("Can not dave keystore to file:" + file.getAbsolutePath(), ex);
        }
        return res;
    }
}
