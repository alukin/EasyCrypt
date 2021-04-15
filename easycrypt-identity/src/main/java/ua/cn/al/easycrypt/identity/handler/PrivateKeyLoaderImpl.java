/*
 * Copyright (C) 2021 Oleksiy Lukin 
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
package ua.cn.al.easycrypt.identity.handler;

import ua.cn.al.easycrypt.identity.cert.CertKeyPersistence;
import ua.cn.al.easycrypt.identity.cert.ExtCert;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.PrivateKey;
import lombok.extern.slf4j.Slf4j;

/**
 *
 * @author alukin@gmail.com
 */
@Slf4j
public class PrivateKeyLoaderImpl implements PrivateKeyLoader {

    @Override
    public PrivateKey loadAndCheckPrivateKey(InputStream is, ExtCert cert, String password) {
        PrivateKey key = CertKeyPersistence.loadPvtKey(is,password);
        if (key == null) {
            log.warn("Can not load private key from stream");
        } else {
            boolean keyOK = cert.checkKeys(key);
            if (!keyOK) {
                log.warn("Private key does not corresponds to certificate's public key");
                key = null;
            }
        }
        return key;
    }

    @Override    
    public PrivateKey loadAndCheckPrivateKey(Path p, ExtCert cert, String password) {
        PrivateKey key = null;
        try(FileInputStream fis = new java.io.FileInputStream(p.toFile())){
            key = loadAndCheckPrivateKey(fis, cert, password);
        } catch (FileNotFoundException ex) {
            log.warn("Key file not found: {}",p.toAbsolutePath().toString());
        } catch (IOException ex) {
            log.warn("Key file not found: {}",p.toAbsolutePath().toString());
        }
        return key;
    }

}
