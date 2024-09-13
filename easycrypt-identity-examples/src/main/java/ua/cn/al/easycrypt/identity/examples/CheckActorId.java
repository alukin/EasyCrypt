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
package ua.cn.al.easycrypt.identity.examples;

import ua.cn.al.easycrypt.identity.cert.CertException;
import ua.cn.al.easycrypt.identity.cert.CertKeyPersistence;
import ua.cn.al.easycrypt.identity.cert.ExtCert;
import ua.cn.al.easycrypt.identity.utils.Hex;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import lombok.extern.slf4j.Slf4j;

/**
 *
 * @author alukin@gmail.com
 */
@Slf4j
public class CheckActorId {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        System.out.println("Checking actor ID in certificate");

        String path = "test_cert.pem";
        if(args.length>1){
            path=args[1];
        }
        ExtCert xcert = null;
        System.out.println("Reading test certificate: "+path);
        try (InputStream is = new FileInputStream(path)) {
            xcert = CertKeyPersistence.loadCertPEMFromStream(is);
        } catch (IOException ex) {
            log.error("Can not load test certificate: "+path, ex);
            System.exit(1);
        } catch (CertException ex) {
            log.error("can not parse test certificate: " + path, ex);
            System.exit(1);
        }
        System.out.println(xcert.toString());
        System.out.println("Actor ID:" + Hex.encode(xcert.getActorId()));
                
    }
}