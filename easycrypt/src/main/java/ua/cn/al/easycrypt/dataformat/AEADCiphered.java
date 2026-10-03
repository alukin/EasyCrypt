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

package ua.cn.al.easycrypt.dataformat;

import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.CryptoNotValidException;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Defines message format for AEAD with IV, plain authenticated
 * data and encrypted data.
 * specially formated data that includes: 
 *    IV  (12 bytes), (salt+explicit nounce)
 *    unencryped data lenght (4 bytes),
 *    ecnrypted data lenght (4 bytes)
 *    unencrypted data (variable len), 
 *    encrypted data in the rest of message including
 *    last 16 bytes (128 bits) of hmac 
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class AEADCiphered {
    /**
     * Maximal size of plain and encrypted parts in sum to prevent DoS attacks
     */
    public static final int MAX_MSG_SIZE = 65536;

    public byte[] aatext = new byte[0];
    public byte[] encrypted;

    private final int hmacSize;
    private final byte[] iv; //12 bytes = 4 of salt + 8 of nonce

    private final CryptoParams cryptoParams;

    public AEADCiphered(CryptoParams cryptoParams) {
        this.cryptoParams = cryptoParams;
        this.hmacSize = cryptoParams.getGcmAuthTagLenBits() / 8; //128 bits
        this.iv = new byte[cryptoParams.getAesIvLen()]; //12 bytes, RFC 5288;  salt and explicit nounce
    }

    /**
     * Sets 8 bytes of implicit part on nounce that goes with message
     * @param en 8 bytes of explicit part of IV
     */
    public void setExplicitNonce(byte[] en){
        if(en == null || en.length != cryptoParams.getAesGcmNonceLen()){
            throw new IllegalArgumentException("Nonce size must be exactly " + cryptoParams.getAesGcmNonceLen() + " bytes");
        }
        Arrays.fill(iv, (byte)0);
        System.arraycopy(en, 0, iv, cryptoParams.getAesGcmSaltLen(), en.length);
    }

    
    public byte[] getExplicitNonce(){
        return Arrays.copyOfRange(iv, cryptoParams.getAesGcmSaltLen(), iv.length);
    }

    public byte[] getIV(){
        return Arrays.copyOf(iv, iv.length);
    }
    
    public void setIV(byte[] ivv){
       if(ivv == null || ivv.length != cryptoParams.getAesIvLen()){
            throw new IllegalArgumentException("IV size must be exactly " + cryptoParams.getAesIvLen() + " bytes");
        }
       System.arraycopy(ivv, 0, iv, 0, cryptoParams.getAesIvLen());
    }
    
    public byte[] getHMAC(){
      if (encrypted == null || encrypted.length < hmacSize) {
          throw new IllegalStateException("Encrypted payload does not contain a complete authentication tag");
      }
      return Arrays.copyOfRange(encrypted, encrypted.length - hmacSize, encrypted.length);
    }
    
    public static AEADCiphered fromBytes(byte[] message, CryptoParams cryptoParams) throws CryptoNotValidException {
        if (message == null || cryptoParams == null) {
            throw new CryptoNotValidException("Message and crypto parameters must not be null");
        }
        int headerSize = cryptoParams.getAesIvLen() + 2 * Integer.BYTES;
        if (message.length < headerSize) {
            throw new CryptoNotValidException("Truncated AEAD message header");
        }
        AEADCiphered res = new AEADCiphered(cryptoParams);
        ByteBuffer bb = ByteBuffer.wrap(message);
        bb.get(res.iv);
        int txtlen = bb.getInt();
        int enclen = bb.getInt();
        long payloadSize = (long) txtlen + enclen;
        if (txtlen < 0 || enclen < 0) {
            throw new CryptoNotValidException("AEAD message lengths must not be negative");
        }
        if (payloadSize > MAX_MSG_SIZE) {
            throw new CryptoNotValidException("Declared AEAD payload is too large: " + payloadSize);
        }
        if (payloadSize != bb.remaining()) {
            throw new CryptoNotValidException("AEAD message lengths do not match the remaining input");
        }
        if (enclen < res.hmacSize) {
            throw new CryptoNotValidException("Encrypted AEAD payload is shorter than the authentication tag");
        }
        res.aatext = new byte[txtlen];
        res.encrypted = new byte[enclen];
        bb.get(res.aatext);
        bb.get(res.encrypted);
        return res;
    }
    
    public byte[] toBytes(){
        if (encrypted == null || aatext == null) {
            throw new IllegalStateException("AEAD plaintext and encrypted payload must be set before serialization");
        }
        if ((long) aatext.length + encrypted.length > MAX_MSG_SIZE || encrypted.length < hmacSize) {
            throw new IllegalArgumentException("AEAD payload is too large or shorter than its authentication tag");
        }
        int capacity = calcBytesSize();
        ByteBuffer bb = ByteBuffer.allocate(capacity);
        bb.put(iv);
        bb.putInt(aatext.length);
        bb.putInt(encrypted.length);
        bb.put(aatext);
        bb.put(encrypted); //hmac is 16 bytes tail of encrypted
        return bb.array();
    }

    public int calcBytesSize() {
        return iv.length + 4 + 4 + aatext.length + encrypted.length;
    }

}
