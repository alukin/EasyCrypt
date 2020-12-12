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
 *
 */

package ua.cn.al.easycrypt.impl;

import ua.cn.al.easycrypt.KeyWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Write different keys in standard formats
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class KeyWriterImpl implements KeyWriter {
    private static Logger log = LoggerFactory.getLogger(KeyWriterImpl.class);
    
    @Override
    public boolean writePvtKeyPEM(String path, PrivateKey key) throws IOException {
        boolean res = false;
        try (PemWriter writer = new PemWriter(new FileWriter(path))) {
            writer.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
            res=true;
        }
        return res;
    }

    @Override
    public boolean writePvtKeyPKCS12(String path)  throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public boolean writeCertificateRequestPEM(String path, PKCS10CertificationRequest cr) throws IOException {
        boolean res = false;
        try (PemWriter writer = new PemWriter(new FileWriter(path))) {
            byte[] enc = cr.getEncoded();
            writer.writeObject(new PemObject("CERTIFICATE REQUEST", enc));
            res=true;
        }
        return res;
    }

    @Override
    public boolean writeX509CertificatePEM(String path, X509Certificate certificate) throws IOException {
        boolean res = false;
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must be defined.");
        }
        try (PemWriter writer = new PemWriter(new FileWriter(path))) {
                writer.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
                res=true;
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Problem with a certificate", e);
        }
        return res;
    }

    @Override
    public boolean addX509CertToPKCS12(X509Certificate certificate, String pathToJKS, String alias, String jksPassword) {
        throw new UnsupportedOperationException("Not supported yet."); 
    }
    
    @Override
    public byte[] serializePublicKey(PublicKey publicKey){
        return publicKey.getEncoded();
    }
    
    @Override
    public byte[] serializePrivateKey(PrivateKey privateKey){
       return privateKey.getEncoded();
    }

    @Override
    public String getCertificateRequestPEM(PKCS10CertificationRequest cr) throws IOException {
         StringWriter sw = new StringWriter(2048);
         PemWriter writer = new PemWriter(sw);
         byte[] enc = cr.getEncoded();
         writer.writeObject(new PemObject("CERTIFICATE REQUEST", enc));
         writer.flush();
         return sw.toString();
    }

    @Override
    public String getPvtKeyPEM(PrivateKey key) throws IOException {
        StringWriter sw = new StringWriter(2048);
        PemWriter writer = new PemWriter(sw);
        writer.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
        writer.flush();
        return sw.toString();
    }

    @Override
    public String getX509CertificatePEM(X509Certificate certificate) throws IOException {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must be defined.");
        }
        StringWriter sw = new StringWriter();
        try (PemWriter writer = new PemWriter(sw)) {
            writer.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
            writer.flush();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Problem wirh a certificate", e);
        }
        return sw.toString();
    }

    @Override
    public boolean writePvtKeyPKSC8(String path, PrivateKey key, String password) throws IOException {
        boolean res = false;
        try {
            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC);
            encryptorBuilder.setRandom(new SecureRandom());
            encryptorBuilder.setPasssword(password.toCharArray());
            OutputEncryptor encryptor = encryptorBuilder.build();  
            JcaPKCS8Generator generator = new JcaPKCS8Generator(key, encryptor);
            PemObject obj = generator.generate();
            try( FileWriter fwr = new FileWriter(path)) {
               JcaPEMWriter pw = new JcaPEMWriter(fwr); 
               pw.writeObject(obj);
               pw.flush();
            }
            res=true;
        } catch (OperatorCreationException | PemGenerationException ex) {
            log.warn("Can not create password encryptor", ex);
        }
        return res;
    }
}
