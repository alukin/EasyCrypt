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
   
   byte[] PBKDF2(String passPhrase, byte[] salt) throws CryptoNotValidException;
}
