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

/**
 * Integrated encryption scheme (IES) encryption routines. For ECC: ECIES is
 * used that calculates shared key using some variant of ECDH. Rot RSA: simple
 * encryption with limitation of length
 *
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com
 */
public interface AsymCryptor extends Cryptor {

    /**
     * Set all required keys
     *
     * @param keys our public and private keys, their public key
     */
    void setKeys(AsymKeysHolder keys);

}
