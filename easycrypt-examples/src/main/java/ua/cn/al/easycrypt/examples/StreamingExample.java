/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.cn.al.easycrypt.examples;

import java.io.IOException;
import ua.cn.al.easycrypt.DigestingOutputStream;

/**
 *
 * @author al
 */
public class StreamingExample {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //TODO: write appropriate constructor
        
        String plain = "Hello, crypto world!";
        byte[] hash = null;
        try(DigestingOutputStream digestingOutputStream = new DigestingOutputStream()){
            digestingOutputStream.write(plain.getBytes());
            hash=digestingOutputStream.getHash();
        } catch (IOException ex) {
            
        }
    }
    
}
