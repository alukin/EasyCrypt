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
