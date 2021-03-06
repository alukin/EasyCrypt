/*
 * Copyright (C) 2018-2021 Oleksiy Lukin alukin@gmail.com
 *
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

import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.KeyGenerator;
import ua.cn.al.easycrypt.SymCryptor;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Introduction to EasyCrypt: Simple symmetric encryption with default crypto
 * parameters It should work for all supported cypto systems
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class Symmeric {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //Create factory with default crypto settings
        CryptoFactory factory = CryptoFactory.newInstance();

        System.out.println("Using crypto settings: ");
        System.out.println(factory.getCryptoParams().toString());
        KeyGenerator kg = factory.getKeyGenerator();
        byte[] symKey = kg.generateSymKey();
        byte[] iv = kg.generateIV();
        try {
//Prepare side A        
            SymCryptor cryptorA = factory.getSymCryptor();
            cryptorA.setKey(symKey);
//Same key is OK for each new message but IV must be changed at least partially        
            cryptorA.setIV(iv);
//encrypt        
            String plainA = "Hello, Bob!";
            byte[] msgA = cryptorA.encrypt(plainA.getBytes());
//Prepare side B        
            SymCryptor cryptorB = factory.getSymCryptor();
            cryptorB.setKey(symKey);
// We  not set entire IV here but nounce is a part of message
//so it is enoug just to jet salt
//            cryptorB.setIV(iv);
// Seo we set salt only
              cryptorB.setSalt(cryptorA.getSalt());
//decypt, side B should know the same key and IV        
            byte[] decr = cryptorB.decrypt(msgA);
            String stringDecr = new String(decr);
            if (plainA.equals(stringDecr)) {
                System.out.println("Bob received message: \n");
                System.out.println(stringDecr);
            } else {
                System.out.println("Bob did not receive message: \n");
            }
        } catch (CryptoNotValidException ex) {
            Logger.getLogger(Symmeric.class.getName()).log(Level.SEVERE, "Something is wron with keys", ex);
        }

    }

}
