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
