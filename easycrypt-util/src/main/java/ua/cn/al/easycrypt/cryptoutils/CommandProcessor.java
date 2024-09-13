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
package ua.cn.al.easycrypt.cryptoutils;

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.KeyReader;
import ua.cn.al.easycrypt.KeyWriter;
import ua.cn.al.easycrypt.csr.CertificateRequestData;
import ua.cn.al.easycrypt.KeyGenerator;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.container.PKCS12KeyStore;
import ua.cn.al.easycrypt.csr.X509CertOperations;
import ua.cn.al.easycrypt.impl.KeyReaderImpl;
import ua.cn.al.easycrypt.impl.KeyWriterImpl;
import ua.cn.al.easycrypt.impl.csr.X509CertOperationsImpl;
import ua.cn.al.easycrypt.impl.ecc.KeyGeneratorEC;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Properties;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Processing of commands in Main
 *
 * @author alukin@gmail.com
 */
public class CommandProcessor {

    private static final Logger log = LoggerFactory.getLogger(CommandProcessor.class);

    private final String pathToKeyStore;
    private final String ksAlias;
    private final String ksPassword;
    private final String pvtKeyPassword;
    private final boolean useKeyStore;
    private final static String LS=System.lineSeparator();
    
    PKCS12KeyStore ks;
    private final CryptoParams params = CryptoConfig.createDefaultParams();

    TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
    }
    };

    public CommandProcessor(String pathToKeyStore, String ksAlias, String ksPassword, String pvtKeyPassword) {
        this.pathToKeyStore = pathToKeyStore;
        this.ksAlias = ksAlias;
        this.ksPassword = ksPassword;
        this.pvtKeyPassword = pvtKeyPassword;
        useKeyStore = isKeystoreOK();
    }

    private boolean isKeystoreOK() {
        boolean res = false;
        if (pathToKeyStore != null && !pathToKeyStore.isEmpty()) {
            ks = new PKCS12KeyStore();
            res = ks.createOrOpenKeyStore(pathToKeyStore, ksPassword);
        }
        return res;
    }

    public void createCSR(CertificateRequestData cd, String path, String challlengePassword) throws Exception {
        if (path == null || path.isEmpty()) {
            path = "newreq.pem";
        }
        cd.processCertData(false);
        KeyGenerator kg = new KeyGeneratorEC(params);
        KeyPair kp = kg.generateKeys();
        X509CertOperations certOps = new X509CertOperationsImpl(params);
        PKCS10CertificationRequest cr = certOps.createX509CertificateRequest(kp, cd, false, challlengePassword);
        KeyWriter kw = new KeyWriterImpl();
        kw.writeCertificateRequestPEM(path, cr);
        int idx = path.indexOf('.');
        if (idx < 0) {
            idx = path.length();
        }
        String key_path = path.substring(0, idx) + "_pvtkey.pem";
        kw.writePvtKeyPEM(key_path, kp.getPrivate());
        log.info("Certificate request written to file: " + path + ", private key is in file: " + key_path + "\n\n\t"
                + "Please keep your private key safe and in secret!");
    }

    public void createSelfSignedPair(CertificateRequestData cd, String path) throws IOException, CryptoNotValidException, CertificateEncodingException {
        if (path == null || path.isEmpty()) {
            path = "newcert.pem";
        }
        cd.processCertData(true);
        KeyGenerator kg = new KeyGeneratorEC(CryptoConfig.createDefaultParams());
        KeyPair kp = kg.generateKeys();
        X509CertOperations certOps = new X509CertOperationsImpl(params);
        X509Certificate cert = certOps.createSelfSignedX509v3(kp, cd);
        KeyWriter kw = new KeyWriterImpl();
        if (useKeyStore) {
            ks.addPrivateKey(kp.getPrivate(), ksAlias, pvtKeyPassword, cert, cert);
            ks.save(pathToKeyStore, ksPassword);
        }
        kw.writeX509CertificatePEM(path, cert);
        int idx = path.indexOf('.');
        if (idx < 0) {
            idx = path.length();
        }
        String key_path = path.substring(0, idx) + "_pvtkey.pem";
        kw.writePvtKeyPEM(key_path, kp.getPrivate());
        log.info("Certificate written to file: " + path + ", private key is in file: " + key_path + "\n\n\t"
                + "Please keep your private key safe and in secret!");
    }
    
//TODO: more parameters, tests     
    public void signCSRbyCA(String infile, String cAname){
        KeyReader kr = new KeyReaderImpl();
        X509Certificate caCert=null;
        PrivateKey caKey=null;
        PKCS10CertificationRequest req = null;
        try(InputStream is = new FileInputStream(infile)) {
          caCert = kr.readX509CertPEMorDER(is);
          X509CertOperations certOps = new X509CertOperationsImpl(params);
          GregorianCalendar certEnd = new GregorianCalendar();
          certEnd.add(GregorianCalendar.YEAR, 2);
          X509Certificate userCert = certOps.signCert(req,caCert,caKey, new Date(), certEnd.getTime());
          KeyWriter kw = new KeyWriterImpl();
          kw.writeX509CertificatePEM("newcert.pem", userCert);
        }catch (IOException ex) {
          log.error("Can not read CSR file: {}", infile, ex);
        }

    }
    
    public Properties readProperties(String path) throws FileNotFoundException, IOException {
        Properties prop = new Properties();
        InputStream input;
        input = new FileInputStream(path);
        prop.load(input);
        return prop;
    }

    public Properties addDefined(Properties p, CmdCertReq certreq) {
        certreq.params.keySet().forEach((key) -> {
            p.put(key, certreq.params.get(key));
        });
        return p;
    }

    public String readStdIn(String prompt) {
        String res = "";
        BufferedReader br = null;

        try {
            System.out.println(prompt);
            br = new BufferedReader(new InputStreamReader(System.in));
            res = br.readLine();
        } catch (IOException ex) {
            log.error("Can not read stdin", ex);
        }
        return res;
    }

    public boolean checkRequiredProperties(CertificateRequestData cd, boolean interactive) {
        boolean res = false;
        List<String> undefined = cd.checkNotSetParameters();
        if (interactive) {
            for (String param : undefined) {
                cd.addProperty(param, readStdIn("Please enter value of: " + param));
            }
            res = true;
        } else {
            res = undefined.isEmpty();
        }
        return res;
    }

    public void displayX509(String infile) {

        System.out.println("PEM OK");
        try(InputStream is = new FileInputStream(infile)) {
            KeyReader kr = new KeyReaderImpl();
            X509Certificate cert = kr.readX509CertPEMorDER(is);

            System.out.println("==================================================");
            System.out.println("=          X.509 CERTIFICATE AS STRING           =");
            System.out.println("==================================================");
            System.out.println();
            System.out.println(cert.toString());
            System.out.println();
            // log.error("X509 functionality  is not implemented yet");
        } catch (IOException ex) {
            log.error("Can not read file: {}", infile, ex);
        }
    }

    void displayPKCS10(String infile) {
 
         try (FileReader fr = new FileReader(infile)) {
             PEMParser parser = new PEMParser(fr);
            PKCS10CertificationRequest cr = (PKCS10CertificationRequest) parser.readObject();           
            System.out.println("==================================================");
            System.out.println("=              PKCS#10 CSR AS STRING             =");
            System.out.println("==================================================");    
            System.out.println();
            System.out.println(CertDisplayUtils.csrToString(cr));
            System.out.println();            
        } catch (IOException ex) {
            log.error("Can not read file: {}", infile, ex);
        }
    }

    
}
