/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation, version 3
 * of the License.
 */

package ua.cn.al.easycrypt.identity.handler;

import ua.cn.al.easycrypt.identity.cert.CertAndKey;
import ua.cn.al.easycrypt.identity.cert.ExtCSR;
import ua.cn.al.easycrypt.identity.cert.ExtCert;


/**
 * Handles operations with X509 certificate and private key of this node 
 * @author alukin@gmail.com
 */
public interface ThisActorIdHandler {
    byte[] getActorId();
    ExtCert getExtCert();
    byte[] sign(byte[] message);
    CertAndKey generateSelfSignedCert(ExtCSR csr);    
}
