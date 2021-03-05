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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import org.bouncycastle.util.encoders.Hex;
import ua.cn.al.easycrypt.CryptoFactory;


/**
 *
 * @author  Oleksiy Lukin alukin@gmail.com
 */
public class StreamingExample {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
      
        CryptoFactory factory = CryptoFactory.newInstance();
        System.out.println("Using crypto settings: ");
        System.out.println(factory.getCryptoParams().toString());
        
        String plain = "Hello, crypto world!";
        byte[] hash = null;
        
        System.out.println("Digesting plain sting: "+plain);
        
        OutputStream nullSink = OutputStream.nullOutputStream();
        
        try(DigestOutputStream  digestingOutputStream = factory.getDigestOutputStream(nullSink)){
            digestingOutputStream.write(plain.getBytes());
            hash=digestingOutputStream.getMessageDigest().digest();
            System.out.println("HASH algorithm: "+factory.getCryptoParams().getDigester()+" HASH: "+Hex.toHexString(hash));
        } catch (IOException ex) {
            System.out.println("Something is wrong: "+ex.getMessage());
        }
        
        System.out.println("Ecryption plain sting: "+plain);
        
        ByteArrayOutputStream sink = new ByteArrayOutputStream(200);
        
        try(CipherOutputStream es = factory.getCipherOutputStream(sink)){
            es.write(plain.getBytes());
        } catch (IOException ex) {
            System.out.println("Something is wrong: "+ex.getMessage());
        }
        
        ByteArrayInputStream source = new ByteArrayInputStream(sink.toByteArray());
        try(CipherInputStream ds = factory.getCipherInputStream(source)){
            byte[] b = ds.readAllBytes();
            System.out.println("Text after encryption/decryption round");
            System.out.println(new String(b));
        } catch (IOException ex) {
            System.out.println("Something is wrong: "+ex.getMessage());
        }
    }
    
}
