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
