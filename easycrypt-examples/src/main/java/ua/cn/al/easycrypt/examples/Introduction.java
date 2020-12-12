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
package ua.cn.al.easycrypt.examples;

import ua.cn.al.easycrypt.AsymCryptor;
import ua.cn.al.easycrypt.AsymKeysHolder;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoSignature;
import ua.cn.al.easycrypt.KeyGenerator;
import java.security.KeyPair;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Introduction to FBCrypto: Simple asymmetric encryption
 * with default crypto parameters and integrated encryption schema.
 * It should work for all supported cypto systems
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class Introduction {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //Create factory with default crypto settings
        CryptoFactory factory = CryptoFactory.newInstance();

        System.out.println("Using crypto settings: ");
        System.out.println(factory.getCryptoParams().toString());

        // Generatee good random key apirs for Alice and Bob
        KeyGenerator kg = factory.getKeyGenerator();
        KeyPair alice = kg.generateKeys();
        KeyPair bob = kg.generateKeys();

        // Put keys (own key pair and other's public key) in holders for each side of communication
        AsymKeysHolder keysAlice = new AsymKeysHolder(alice.getPublic(), alice.getPrivate(), bob.getPublic());
// Now Alice has own key pair and Bob's public kay in her keys holder        

        AsymKeysHolder keysBob = new AsymKeysHolder(bob.getPublic(), bob.getPrivate(), alice.getPublic());
// Now Bob has own key pair and Alice's public kay in his keys holder        

        String plainA = "Hello, Bob! Howdy?";
        try {
            
//Prepare Alice's side
            AsymCryptor cryptorA = factory.getAsymCryptor();
            cryptorA.setKeys(keysAlice);
            CryptoSignature signerA = factory.getCryptoSiganture();
            signerA.setKeys(keysAlice);

//Prepare Bob's side
            AsymCryptor cryptorB = factory.getAsymCryptor();
            cryptorB.setKeys(keysBob);
            CryptoSignature signerB = factory.getCryptoSiganture();
            signerB.setKeys(keysBob);
            
// Encrypt for Bob and sign Alice's message
            byte[] msgA = cryptorA.encrypt(plainA.getBytes());
            byte[] sinatureA = signerA.sign(msgA);
// Decrypt and verify signature on Bob's side
            byte[] pa = cryptorB.decrypt(msgA);
            boolean sigOK = signerB.verify(msgA, sinatureA);
// Is everything OK?
            String planAdecrypted = new String(pa);
            if(sigOK){
                System.out.println("Bob verified Alice's signature sucessfuly.");
            }else{
                System.out.println("ERROR in signature check!");
            }
            if(plainA.equals(planAdecrypted)){
                System.out.println("Bob decryped Alices message and she says:");
                System.out.println(planAdecrypted);        
            }else{
                System.out.println("ERROR in message decyprion!");                
            }

        } catch (CryptoNotValidException ex) {
            Logger.getLogger(Introduction.class.getName()).log(Level.SEVERE, "Something is wrong with keys or other settings!", ex);
        }

    }

}
