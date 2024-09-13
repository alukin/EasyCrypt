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
import ua.cn.al.easycrypt.Digester;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * JSON-based encrypted general purpose wallet
 *
 * @param <T> Model ow wallet
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class GenericWallet<T> {

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

    public byte[] keyFromPassPhrase(String passPhrase, byte[] salt) throws CryptoNotValidException {
        CryptoFactory f = CryptoFactory.newInstance(CryptoConfig.createDefaultParams());
        Digester d = f.getDigesters();
        return d.PBKDF2(passPhrase, salt);
    }

    public T getWallet() {
        return wallet;
    }

    public void setWallet(T wallet) {
        this.wallet = wallet;
    }

}
