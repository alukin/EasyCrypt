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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Key holder class for asymmetric crypto operations
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class AsymKeysHolder {
    private PrivateKey privateKey;
    private PublicKey ourPublicKey;
    private PublicKey theirPublicKey;
    
    /**
     * Sets asymmetric keys
     *
     * @param ourPubkey public key from our key pair
     * @param privKey private key from out key pair
     * @param theirPubKey public key of remote party
     */
    public AsymKeysHolder(PublicKey ourPubkey, PrivateKey privKey, PublicKey theirPubKey){
        this.privateKey=privKey;
        this.ourPublicKey=ourPubkey;
        this.theirPublicKey=theirPubKey;
    }

    /**
     * Key pair with our (PublicKey, PrivateKey)
     * @param keyPair public and private keys of "our side"
     */
    public void setOurKeyPair(KeyPair keyPair){
        this.privateKey=keyPair.getPrivate();
        this.ourPublicKey=keyPair.getPublic();
    }

    /**
     * set their public key
     * @param theirPublicKey public key of "other side"
     */
    public void setTheirPublicKey(PublicKey theirPublicKey){
        this.theirPublicKey=theirPublicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getOurPublicKey() {
        return ourPublicKey;
    }

    public PublicKey getTheirPublicKey() {
        return theirPublicKey;
    }
}
