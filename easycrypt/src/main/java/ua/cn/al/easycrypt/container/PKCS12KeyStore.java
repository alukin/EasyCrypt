/*
 * Copyright (C) 2018-2024 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
import java.util.Collections;
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
        aliases.clear();
        certificates.clear();
        keystore = null;
        if (path == null) {
            return false;
        }
        try (InputStream is = new FileInputStream(new File(path))) {
            KeyStore loaded = KeyStore.getInstance(KEYSTORE_TYPE, CryptoConfig.getProvider());
            loaded.load(is, passwordChars(password));
            List<String> loadedAliases = new ArrayList<>();
            List<Certificate> loadedCertificates = new ArrayList<>();
            Enumeration<String> enumeration = loaded.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                loadedAliases.add(alias);
                Certificate certificate = loaded.getCertificate(alias);
                if (certificate != null) {
                    loadedCertificates.add(certificate);
                }
            }
            keystore = loaded;
            aliases.addAll(loadedAliases);
            certificates.addAll(loadedCertificates);
        } catch (FileNotFoundException ex) {
            log.error("File" + path + " does not exists", ex);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
            log.error("File" + path + " is not loadable", ex);
            return false;
        }
        return keystore != null;
    }

    public boolean createOrOpenKeyStore(String path, String password) {
        if (path == null) {
            return false;
        }
        File file = new File(path);
        if (file.exists()) {
            return openKeyStore(path, password);
        }
        aliases.clear();
        certificates.clear();
        keystore = null;
        try {
            KeyStore created = KeyStore.getInstance(KEYSTORE_TYPE, CryptoConfig.getProvider());
            created.load(null, passwordChars(password));
            try (FileOutputStream fos = new FileOutputStream(file)) {
                created.store(fos, passwordChars(password));
            }
            keystore = created;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            log.error("Can not create file" + path, ex);
            return false;
        }
        return true;
    }

    public List<String> getAliases() {
        return Collections.unmodifiableList(new ArrayList<>(aliases));
    }

    public List<Certificate> getCertificates() {
        return Collections.unmodifiableList(new ArrayList<>(certificates));
    }
    
    public Key getKey(String alias, String password){
        Key key = null;
        if (keystore == null || alias == null) {
            return null;
        }
        try {
            key = keystore.getKey(alias, passwordChars(password));
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
        if (keystore == null || key == null || algo == null || alias == null) {
            return false;
        }
        try {
            SecretKey secretKey = new SecretKeySpec(key,algo);
            KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.ProtectionParameter pwd  = new KeyStore.PasswordProtection(passwordChars(password));
            keystore.setEntry(alias, secret, pwd);
            return true;
        } catch (KeyStoreException ex) {
           log.error("Can not set key entry with alias: "+alias,ex);
           return false;
        }
    }
    
    public boolean addCertificate(String alias, X509Certificate cert){
        if (keystore == null || alias == null || cert == null) {
            return false;
        }
        try {
            keystore.setCertificateEntry(alias, cert);
        } catch (KeyStoreException ex) {
           log.error("Can not set certificate entry with alias: "+alias,ex);
           return false;
        }
        return true;
    }
    
    public boolean addPrivateKey(PrivateKey pvtKey, String alias, String password, X509Certificate cert, X509Certificate caCert){
        if (keystore == null || pvtKey == null || alias == null || cert == null || caCert == null) {
            return false;
        }
        try {
            X509Certificate[] chain = new X509Certificate[2];
            chain[0] = cert;
            chain[1] = caCert;
            keystore.setKeyEntry(alias, pvtKey, passwordChars(password), chain);
            return true;
        } catch (KeyStoreException ex) {
            log.error("Can not set private key entry with alias: "+alias,ex);
            return false;
        }
    }

    public boolean save(String path, String password){
        if (keystore == null || path == null) {
            return false;
        }
        File file = new File(path);
        try(FileOutputStream fos = new FileOutputStream(file)) {
            keystore.store(fos, passwordChars(password));
            return true;
        } catch ( KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
             log.error("Can not dave keystore to file:" + file.getAbsolutePath(), ex);
             return false;
        }
    }

    /** Null passwords are treated as empty passwords consistently by this wrapper. */
    private static char[] passwordChars(String password) {
        return password == null ? new char[0] : password.toCharArray();
    }
}
