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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.Digester;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * JSON-based encrypted general purpose wallet
 *
 * @param <T> Model ow wallet
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class GenericWallet<T> {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private final ObjectMapper mapper = new ObjectMapper();
    protected T wallet;
    private byte[] openData;
    private byte[] container_iv;
    private Class<T> walletModelClass;

    public GenericWallet(T wallet) {
        this.wallet = Objects.requireNonNull(wallet);
        this.walletModelClass = (Class<T>) wallet.getClass();
    }

    /**
     * Gets open data of wallet even if key is wrong
     *
     * @return
     */
    public byte[] getOpenData() {
        return openData;
    }

    /**
     * Sets open data for wallet
     *
     * @param openData
     */
    public void setOpenData(byte[] openData) {
        this.openData = openData;
    }

    public byte[] getContainerIV() {
        return container_iv;
    }

    public void openFile(String path, byte[] key) throws FileNotFoundException, IOException, CryptoNotValidException {
        try (FileInputStream fis = new FileInputStream(path)) {
            openStream(fis, key);
        }
    }

    /**
     * Get only open data.
     *
     * @param path
     * @throws FileNotFoundException
     * @throws IOException
     * @throws CryptoNotValidException
     */
    public void readOpenData(String path) throws FileNotFoundException, IOException, CryptoNotValidException {
        try (FileInputStream fis = new FileInputStream(path)) {
            CryptedContainer c = new CryptedContainer();
            this.openData = c.readOpenDataOnly(fis);
            this.container_iv = c.getFullIV();
        }
    }

    /**
     * Get only open data.
     *
     * @throws FileNotFoundException
     * @throws IOException
     * @throws CryptoNotValidException
     */
    public void readOpenData(InputStream is) throws FileNotFoundException, IOException, CryptoNotValidException {
        try {
            CryptedContainer c = new CryptedContainer();
            this.openData = c.readOpenDataOnly(is);
            this.container_iv = c.getFullIV();
        } catch (Exception ex) {
            throw ex;
        } finally {
            is.close();
        }
    }

    public void openStream(InputStream is, byte[] key) throws IOException, CryptoNotValidException {
        CryptedContainer c = new CryptedContainer();
        try {
            byte[] data = c.read(is, key);
            openData = c.getOpenData();
            container_iv = c.getFullIV();
            wallet = mapper.readValue(data, walletModelClass);
        } catch (IOException | CryptoNotValidException e) {
            //try to read open data anyway and re-throw
            openData = c.getOpenData();
            throw e;
        }
    }

    public void saveFile(String path, byte[] key, byte[] IV) throws FileNotFoundException, IOException, JsonProcessingException, CryptoNotValidException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            saveStream(fos, key, IV);
        }
    }

    public void saveStream(OutputStream os, byte[] key, byte[] IV) throws JsonProcessingException, IOException, CryptoNotValidException {
        CryptedContainer c = new CryptedContainer();
        c.setOpenData(openData);
        c.save(os, mapper.writeValueAsBytes(wallet), key, IV);
    }

    /**
     * Derives a key using EasyCrypt's historical 16-iteration settings.
     * Existing ciphertext may depend on this behavior.
     *
     * @deprecated Use {@link #deriveKeyFromPassPhrase(String, byte[])} for new data.
     */
    @Deprecated
    public byte[] keyFromPassPhrase(String passPhrase, byte[] salt) throws CryptoNotValidException {
        CryptoFactory f = CryptoFactory.newInstance(CryptoConfig.createDefaultParams());
        Digester d = f.getDigesters();
        return d.PBKDF2(passPhrase, salt);
    }

    /**
     * Derives a key for new data using PBKDF2-HMAC-SHA256 with the configured
     * work factor. Callers must store the salt and iteration count with the
     * encrypted data; the encrypted container's AES-GCM IV does not encode KDF
     * parameters.
     *
     * @param passPhrase passphrase to derive from
     * @param salt unique random salt of at least 16 bytes
     * @return derived AES key
     */
    public byte[] deriveKeyFromPassPhrase(String passPhrase, byte[] salt) throws CryptoNotValidException {
        CryptoFactory f = CryptoFactory.newInstance(CryptoConfig.createDefaultParams());
        return f.getDigesters().deriveKeyFromPassPhrase(passPhrase, salt);
    }

    /**
     * Derives a key with an explicit PBKDF2 iteration count. Persist the count
     * and salt with ciphertext so the same key can be derived later.
     */
    public byte[] deriveKeyFromPassPhrase(String passPhrase, byte[] salt, int iterations)
            throws CryptoNotValidException {
        CryptoFactory f = CryptoFactory.newInstance(CryptoConfig.createDefaultParams());
        return f.getDigesters().deriveKeyFromPassPhrase(passPhrase, salt, iterations);
    }

    /** Creates a random salt of the recommended length for new passphrase keys. */
    public byte[] generatePassPhraseSalt() {
        byte[] salt = new byte[CryptoParams.PBKDF2_SALT_LEN_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public T getWallet() {
        return wallet;
    }

    public void setWallet(T wallet) {
        this.wallet = wallet;
    }

}
