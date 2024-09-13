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
