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
