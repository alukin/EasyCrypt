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