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

package ua.cn.al.easycrypt;


import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Interface to digesters
 * @author Oleksiy Lukin alukin@gmail.com
 */
public interface Digester {
    
   /**
    * Default digest algorithm defined by CryptoParams 
    * @param message
    * @return
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
    */  
   byte[] digest(byte[] message) throws CryptoNotValidException;

   /**
    * Create and return MessageDigest for specified digester parameter
    * @return MessageDigest object for algorithm specified by CryptoParams
    * @throws CryptoNotValidException when implementation for algorithm does not exist
    */
   MessageDigest digest() throws CryptoNotValidException;
   /**
    * Hash algorithms defined in FIPS PUB 180-4. SHA-256
    * @param message
    * @return
    * @throws CryptoNotValidException 
    */
   byte[] sha256 (byte[] message)throws CryptoNotValidException;
   /**
    * Hash algorithms defined in FIPS PUB 180-4. SHA-512
    * @param message
    * @return
    * @throws CryptoNotValidException 
    */
   byte[] sha512 (byte[] message)throws CryptoNotValidException;
   /**
    * Permutation-based hash and extendable-output functions as defined in FIPS PUB 202. 
    * SHA-3 256 bit
    * @param message
    * @return
    * @throws CryptoNotValidException 
    */
   byte[] sha3_256 (byte[] message)throws CryptoNotValidException;
   /**
    * Permutation-based hash and extendable-output functions as defined in FIPS PUB 202. 
    * SHA-3 384 bit
    * @param message
    * @return
    * @throws CryptoNotValidException 
    */
   byte[] sha3_384 (byte[] message)throws CryptoNotValidException;
   /**
    * Permutation-based hash and extendable-output functions as defined in FIPS PUB 202. 
    * SHA-3 512 bit 
    * @param message
    * @return
    * @throws CryptoNotValidException 
    */
   byte[] sha3_512 (byte[] message)throws CryptoNotValidException;
   
   /**
    * Derives a key using the historical EasyCrypt settings. Retained for
    * compatibility with existing data; use {@link #deriveKeyFromPassPhrase}
    * for new data.
    *
    * @deprecated This uses only 16 iterations and must not be used for new keys.
    */
   @Deprecated
   byte[] PBKDF2(String passPhrase, byte[] salt) throws CryptoNotValidException;

   /**
    * Derives a new key using this instance's configured PBKDF2 work factor.
    * The caller must retain the salt and iteration count with the ciphertext.
    *
    * @param passPhrase passphrase to derive from
    * @param salt unique random salt of at least 16 bytes
    * @return derived AES key
    */
   default byte[] deriveKeyFromPassPhrase(String passPhrase, byte[] salt) throws CryptoNotValidException {
      return deriveKeyFromPassPhrase(passPhrase, salt, CryptoParams.PBKDF2_ITERATIONS);
   }

   /**
    * Derives a new key with an explicit work factor. Store the iteration count
    * with the salt so the same key can be derived later.
    */
   default byte[] deriveKeyFromPassPhrase(String passPhrase, byte[] salt, int iterations) throws CryptoNotValidException {
      if (passPhrase == null || passPhrase.isEmpty()) {
         throw new CryptoNotValidException("Passphrase must not be null or empty");
      }
      if (salt == null || salt.length < CryptoParams.PBKDF2_SALT_LEN_BYTES) {
         throw new CryptoNotValidException("PBKDF2 salt must be at least "
                 + CryptoParams.PBKDF2_SALT_LEN_BYTES + " bytes");
      }
      if (iterations < CryptoParams.PBKDF2_ITERATIONS) {
         throw new CryptoNotValidException("PBKDF2 iteration count must be at least "
                 + CryptoParams.PBKDF2_ITERATIONS);
      }
      char[] password = passPhrase.toCharArray();
      PBEKeySpec spec = null;
      try {
         spec = new PBEKeySpec(password, salt, iterations, CryptoParams.PBKDF2_KEYELEN);
         SecretKeyFactory factory = SecretKeyFactory.getInstance(CryptoParams.PBKDF2_KEY_DERIVATION_FN);
         return factory.generateSecret(spec).getEncoded();
      } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
         throw new CryptoNotValidException("Unable to derive PBKDF2 key", ex);
      } finally {
         if (spec != null) {
            spec.clearPassword();
         }
         Arrays.fill(password, '\0');
      }
   }
}
