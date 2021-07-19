/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation, version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * LICENSE
 */

package ua.cn.al.easycrypt.identity.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.KeyReader;
import ua.cn.al.easycrypt.KeyWriter;
import ua.cn.al.easycrypt.impl.KeyReaderImpl;

/**
 * Handler of certificate, ExtCSR and key names and directories placed in map with ID as a key
 *
 * @author alukin@gmail.com
 */
public class CertKeyPersistence {
    public static final String PVT_SEARCH_PATH = "private/";
    private static final Logger log = LoggerFactory.getLogger(CertKeyPersistence.class);

    
    private final Map<BigInteger, List<ExtCert>> certMap = new TreeMap<>();
    public static final String[] sfxes = {"_pvtkey",  "_cert", "_selfcert", "_csr"}; 
    
    public static String rmSuffixes(String fn) {
        String name = new String(fn);
        String ext = "";
        int last_dot = fn.lastIndexOf(".");
        if (last_dot >= 0) {
            ext = fn.substring(last_dot + 1);
            name = fn.substring(0, last_dot);
        }

        for (String s : sfxes) {
            int idx = name.indexOf(s);
            if (idx >= 0) {
                name = name.substring(0, idx);
            }
        }
        return name;
    }

    public static String pvtKeyFileName(String fn) {
        String suffix = "_pvtkey";
        String name = rmSuffixes(fn);
        return name + suffix + ".pem";
    }

    public static String selfSignedFileName(String fn) {
        String suffix = "_selfcert";
        String name = rmSuffixes(fn);
        return name + suffix + ".pem";
    }

    public static String certFileName(String fn) {
        String suffix = "_cert";
        String name = rmSuffixes(fn);
        return name + suffix + ".pem";
    }

    public static String csrFileName(String fn) {
        String suffix = "_csr";
        String name = rmSuffixes(fn);
        return name + suffix + ".pem";
    }

    public List<ExtCert> getCert(BigInteger id) {
        return certMap.get(id);
    }

    public void put(BigInteger id, ExtCert cert) {
        List<ExtCert> cl = certMap.get(id);
        if (cl == null) {
            cl = new ArrayList<>();
        }
        cl.add(cert);
        certMap.put(id, cl);
    }

    public int size() {
        return certMap.size();
    }

    public void readCertDirectory(String path) {
        File dir = new File(path);
        if (dir.exists() && dir.isDirectory()) {
            File[] filesList = dir.listFiles();
            for (File f : filesList) {
                if (f.isFile() && f.canRead()) {
                    ExtCert ac = null;
                    try {
                        ac = loadCertPEMFromPath(f.toPath());
                    } catch (IOException ex) {
                        //impossible here
                    } catch (CertException ex) {
                        log.error("Certificate load exception wilr loading " + f.getAbsolutePath(), ex);
                    }
                    if (ac != null) {
                        put(new BigInteger(ac.getActorId()), ac);
                    }
                }
            }
        } else {
            log.error("Can not read certificates.Directory: {} does not exist!", path);
        }
    }

    public static PrivateKey readPvtKey(Path filePath, String pvtKeyPassword) {
        PrivateKey res=null;
        try (FileInputStream fis = new FileInputStream(filePath.toAbsolutePath().toString())) {
            res = loadPvtKey(fis, pvtKeyPassword);
        } catch (IOException ex) {
            log.trace("Can not read private key: {}", filePath);
        }
        return res;
    }
    
    public static PrivateKey loadPvtKey(InputStream is, String pvtKeyPassword){
        PrivateKey res=null;
        KeyReader kr = new KeyReaderImpl();
        try  {
            res = kr.readPrivateKeyPEM(is, pvtKeyPassword);
        } catch (IOException ex) {
            log.warn("Can not read private key from input stream");
        }
        return res;
    }
          
    public static ExtCert loadCertPEMFromPath(Path path) throws CertException, IOException {
        ExtCert res = null;
        try (FileInputStream fis = new FileInputStream(path.toString())) {
            res = loadCertPEMFromStream(fis);
        }
        return res;
    }

    public static ExtCert loadCertPEMFromStream(InputStream is) throws IOException, CertException {
        CryptoFactory cf = CryptoFactory.newInstance();
        KeyReader kr = cf.getKeyReader();
        X509Certificate cert = kr.readX509CertPEMorDER(is);
        ExtCert ac = new ExtCert(cert);
        return ac;
    } 

    public static ExtCSR loadCSR(String csrPath, String pvtKeyPath, String pvtKeyPassword) {
        PKCS10CertificationRequest cr;
        ExtCSR res = null;
        try (FileReader fr = new FileReader(csrPath)) {
            PEMParser parser = new PEMParser(fr);
            cr = (PKCS10CertificationRequest) parser.readObject();
            //TODO: we need to load private key also
            PrivateKey key = CertKeyPersistence.readPvtKey(Path.of(pvtKeyPath), pvtKeyPassword);
            res = ExtCSR.fromPKCS10(cr,key);
        } catch (IOException ex) {
            log.error("Can not read PKCS#10 file: " + csrPath, ex);
        }
        return res;
    } 

    public static boolean saveCert(Path path, X509Certificate certificate) {
        boolean res = false;
        CryptoFactory cf = CryptoFactory.newInstance();
        KeyWriter kw =  cf.getKeyWriter();
        try{
          kw.writeX509CertificatePEM(path.toAbsolutePath().toString(), certificate);
          res=true;
        }catch(IOException ex){
            log.warn("Can not save certificate to path: {}");
        }  
        return res;
    }

    public static boolean saveKey(Path path, PrivateKey privateKey, String pvtKeyPassword) {
        boolean res = false;
        CryptoFactory cf = CryptoFactory.newInstance();
        KeyWriter kw =  cf.getKeyWriter();
        try{
          kw.writePvtKeyPEM(path.toAbsolutePath().toString(), privateKey);
          res=true;
        }catch(IOException ex){
            log.warn("Can not save certificate to path: {}");
        }         
        return res;
    }
    
}
