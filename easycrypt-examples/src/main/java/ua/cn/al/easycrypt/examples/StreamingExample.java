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
package ua.cn.al.easycrypt.examples;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import org.bouncycastle.util.encoders.Hex;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.KeyGenerator;


/**
 * Example of streaming interface
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
        KeyGenerator kg = factory.getKeyGenerator();
        byte[] iv = kg.generateIV();
        byte[] key =  kg.generateSymKey();
        
        ByteArrayOutputStream sink = new ByteArrayOutputStream(200);
        
        try(CipherOutputStream es = factory.getCipherOutputStream(sink,iv,key)){
            es.write(plain.getBytes());
        } catch (IOException ex) {
            System.out.println("Something is wrong: "+ex.getMessage());
        } catch (CryptoNotValidException ex) {
            System.out.println("Something is wrong: "+ex.getMessage());
        }
        
        ByteArrayInputStream source = new ByteArrayInputStream(sink.toByteArray());
        try(CipherInputStream ds = factory.getCipherInputStream(source,iv,key)){
            byte[] b = ds.readAllBytes();
            System.out.println("Text after encryption/decryption round");
            System.out.println(new String(b));
        } catch (IOException ex) {
            System.out.println("Something is wrong: "+ex.getMessage());
        } catch (CryptoNotValidException ex) {
            System.out.println("Something is wrong: "+ex.getMessage());
        }
    }
    
}
