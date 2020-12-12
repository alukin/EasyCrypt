/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

package ua.cn.al.easycrypt;


import java.security.MessageDigest;

/**
 * Interface to digesters
 * @author Oleksiy Lukin alukin@gmail.com
 */
public interface Digester {
    
   /**
    * Default digest algorithm defined by FBCryptoParams 
    * @param message
    * @return
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
    */  
   byte[] digest(byte[] message) throws CryptoNotValidException;

   /**
    * Create and return MessageDigest for specified digester parameter
    * @return MessageDigest object for algorithm specified by FBCryptoParams
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
