/*

 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation, version 3
 * of the License.
 *
 */

package ua.cn.al.easycrypt.identity.handler;
import ua.cn.al.easycrypt.identity.cert.ExtCert;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoFactoryHelper;
import ua.cn.al.easycrypt.CryptoSignature;

/**
 *
 * @author alukin@gmail.com
 */
@Slf4j
public class IdValidatorImpl implements IdValidator {

    private final List<X509Certificate> trustedSigners = new ArrayList<>();

    public IdValidatorImpl() {
    }

    @Override
    public boolean isSelfSigned(X509Certificate cert) {
        ExtCert ecert = new ExtCert(cert);
        return ecert.isSelfSigned();
    }

    @Override
    public boolean isTrusted(X509Certificate cert) {
        boolean res = false;
        ExtCert ac = new ExtCert(cert);
        for (X509Certificate signerCert : trustedSigners) {
            res = ac.isSignedBy(signerCert);
            if (res) {
                break;
            }
        }
        return res;
    }

    @Override
    public void addTrustedSignerCert(X509Certificate cert) {
        trustedSigners.add(cert);
    }
    
    @Override
    public boolean verifySignedData(X509Certificate certificate, byte[] data, byte[] signature) {
        boolean res;
        CryptoFactory cf = CryptoFactoryHelper.createFactory(certificate.getPublicKey());
        CryptoSignature cs = cf.getCryptoSiganture();
        cs.setTheirPublicKey(certificate.getPublicKey());
        res = cs.verify(data, signature);
        return res;
    }


}
