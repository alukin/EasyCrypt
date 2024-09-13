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
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.dataformat.AEADCiphered;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import ua.cn.al.easycrypt.SymCryptor;

/**
 * Binary encrypted container for arbitrary data. It contains open data as AAD
 * and open data could be extracted without proper encryption key. Protected
 * data are gziped and then encrypted with AES256. So it makes extremely
 * difficult or impossible to extract protected data without proper key.
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CryptedContainer {

    public static final byte[] FILE_MAGIC = {0x0F, 0x0B, 0x0C, 0x69};
    public static final int MAGIC_SIZE = 4;
    public static final int SALT_SIZE = 4; //IV=salt+nonce
    public static final int IV_SIZE = 12; // 4 bytes of salt and 8 bytes of explicit nonce in AEADMEssage
    public static final int BUF_SIZE = 4096;
    public static final int MAX_SIZE = BUF_SIZE * 1024 * 8; //32M
    private byte[] openData;
    private byte[] IV;
    
    private final CryptoParams params = CryptoConfig.createSecp521r1();
    private final CryptoFactory cryptoFactory =  CryptoFactory.newInstance(params);

    /**
     * Sets open data for container
     *
     * @param od
     */
    public void setOpenData(byte[] od) {
        openData = od;
    }

    /**
     * gets open data from container. It is enough to just call read() and ignore
     * exceptions.
     *
     * @return open data of container
     */
    public byte[] getOpenData() {
        return openData;
    }
    
    /**
     * All 12 bytes of IV. Note that is is ready only after read() or readOpenDataOnly()
     * @return 12 bytes of IV
     */
    public byte[] getFullIV(){
        return IV;
    }
    
    private void composeIV(byte[] salt, byte[] nonce){
        IV=new byte[IV_SIZE];
        System.arraycopy(salt, 0, IV, 0, 4);
        System.arraycopy(nonce, 0, IV, 4, 8);
    }

    /**
     * Reads open and protected data from container. If key is null or wrong,
     * open data is set anyway, just ignore exceptions. If key is correct,
     * protected data are extracted and open data are verified.
     *
     * @param is input stream
     * @param key 256 bit key
     * @return array of protected data stored in container
     * @throws IOException
     * @throws CryptoNotValidException
     */
    public byte[] read(InputStream is, byte[] key) throws IOException, CryptoNotValidException {
        byte[] magic = new byte[MAGIC_SIZE];
        is.read(magic);
        byte[] salt = new byte[SALT_SIZE];
        is.read(salt);
        if (Arrays.equals(magic, FILE_MAGIC)) {
            byte[] data = new byte[MAX_SIZE];
            int r;
            int sz = 0;
            while ((r = is.read(data, sz, MAX_SIZE - sz)) >= 0) {
                sz = sz + r;
                if (sz > MAX_SIZE) {
                    throw new CryptoNotValidException("Maximum size of container exceeded");
                }
            }
            return decrypt(Arrays.copyOf(data, sz), key, salt);
        } else {
            throw new CryptoNotValidException("Format error, magic at beginning does not  match");
        }
    }

    /**
     * Reads open data only from container
     *
     * @param is input stream
     * @return open data as byte array
     * @throws IOException
     * @throws CryptoNotValidException
     */
    public byte[] readOpenDataOnly(InputStream is) throws IOException, CryptoNotValidException {
        byte[] magic = new byte[MAGIC_SIZE];
        is.read(magic);
        byte[] salt = new byte[SALT_SIZE];
        is.read(salt);
        if (Arrays.equals(magic, FILE_MAGIC)) {
            byte[] data = new byte[MAX_SIZE];
            int r;
            int sz = 0;
            while ((r = is.read(data, sz, MAX_SIZE - sz)) >= 0) {
                sz = sz + r;
                if (sz > MAX_SIZE) {
                    throw new CryptoNotValidException("Maximum size of container exceeded");
                }
            }
            AEADCiphered msg = AEADCiphered.fromBytes(Arrays.copyOf(data, sz), params);
            composeIV(salt,msg.getExplicitNonce());            
            openData = msg.aatext;
            return openData;
        } else {
            throw new CryptoNotValidException("Format error, magic at beginning does not  match");
        }
    }

    private byte[] decrypt(byte[] input, byte[] key, byte[] salt) throws CryptoNotValidException, IOException {
        AEADCiphered msg = AEADCiphered.fromBytes(input, params);
        openData = msg.aatext;
        composeIV(salt,msg.getExplicitNonce());
        SymCryptor symCryptor = cryptoFactory.getSymCryptor();
        symCryptor.setSalt(salt);
        symCryptor.setKey(key);
        AEADPlain a = symCryptor.decryptWithAEAData(input);
        byte[] uncomp = gzipUncompress(a.decrypted);
        openData = Arrays.copyOf(a.plain, a.plain.length);
        return uncomp;
    }

    private byte[] encrypt(byte[] input, byte[] key, byte[] IV) throws IOException, CryptoNotValidException {
        byte[] comp = gzipCompress(input);
        SymCryptor symCryptor = cryptoFactory.getSymCryptor();
        symCryptor.setIV(IV);
        symCryptor.setKey(key);
        AEADCiphered am = symCryptor.encryptWithAEAData(comp, openData);
        return am.toBytes();
    }

    /**
     * Saves open data (if set) and protected data in encrypted container.
     *
     * @param os output stream
     * @param plain protected data
     * @param key 256 bit (32 bytes) key
     * @param IV 12 bytes of initialization vector;
     * @throws IOException
     * @throws CryptoNotValidException
     */
    public void save(OutputStream os, byte[] plain, byte[] key, byte[] IV) throws IOException, CryptoNotValidException {
        os.write(FILE_MAGIC);
        os.write(IV, 0, 4); //first 4 bytes is salt, last 8 is nonce
        byte[] res = encrypt(plain, key, IV);
        os.write(res);
    }

    /**
     * Compresses data with GZIP
     *
     * @param uncompressedData plain data
     * @return compressed data
     * @throws IOException
     */
    public byte[] gzipCompress(byte[] uncompressedData) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(uncompressedData.length);
        GZIPOutputStream gzipOS = new GZIPOutputStream(bos);
        gzipOS.write(uncompressedData);
        gzipOS.close();
        byte[] result = bos.toByteArray();
        return result;
    }

    /**
     * Un-compresses GZIP data
     *
     * @param compressedData gzip compressed data
     * @return plain uncompressed data
     * @throws IOException
     */
    public byte[] gzipUncompress(byte[] compressedData) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(compressedData);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        GZIPInputStream gzipIS = new GZIPInputStream(bis);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = gzipIS.read(buffer)) != -1) {
            bos.write(buffer, 0, len);
        }
        byte[] result = bos.toByteArray();
        return result;
    }
}
