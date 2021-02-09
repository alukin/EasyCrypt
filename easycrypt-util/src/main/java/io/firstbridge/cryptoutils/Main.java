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
 */
package io.firstbridge.cryptoutils;

import com.beust.jcommander.JCommander;
import ua.cn.al.easycrypt.csr.CertificateRequestData;
import java.io.File;
import java.util.Properties;
import java.util.Map;
import org.apache.log4j.LogManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author alukin@gmail.com
 */
public class Main {
    private final static String version="1.2.8";
    
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    /**
     * @param argv the command line arguments
     */
    public static void main(String[] argv) {
        CmdLineArgs args = new CmdLineArgs();
        CmdKeyStore keystore = new CmdKeyStore();
        CmdCertReq certreq = new CmdCertReq();
        CmdX509Cert x509 = new CmdX509Cert();
        CommandProcessor cp;
        
        JCommander jc = JCommander.newBuilder()
                .addObject(args)
                .addCommand("keystore", keystore)
                .addCommand("x509", x509)
                .addCommand("certreq", certreq)
                .build();
        jc.setProgramName("cryptoutils");
        try {
            jc.parse(argv);
        } catch (RuntimeException ex) {
            System.err.println("Error parsing command line arguments.");
            System.err.println(ex.getMessage());
            jc.usage();
            System.exit(PosixExitCodes.EX_USAGE.exitCode());
        }
        if(args.show_version){
            System.out.println("cryptoutils version: "+version);
            System.exit(PosixExitCodes.OK.exitCode());          
        }
        if (args.help) {
            System.out.println("This is \"swiss army knife\" for CSR, certificates, keys \n and other cryptography related tasks");
            System.out.println("with full ECC upport nbased on BouncyCastle crypto libary.");
            System.out.println(" ");
            jc.usage();
            System.out.println("Supported properties. Some are quite idiotic, thanks to X.people. Please google for OID for more info.\n");
            Map<String, String> sa = CertificateRequestData.getSupportedAttributesHelp();
            for (String key : sa.keySet()) {
                System.out.println(key + "  " + sa.get(key));
            }
            System.exit(PosixExitCodes.OK.exitCode());
        }
        
        if (args.debug) {
            LogManager.getLogger("ua.cn.al").setLevel(org.apache.log4j.Level.DEBUG);
            log.debug("Current disrectory: " + System.getProperty("user.dir"));
        } else {
            LogManager.getLogger("ua.cn.al").setLevel(org.apache.log4j.Level.ERROR);
        }
        
        cp = new CommandProcessor(args.storefile, args.storealias, args.storepass, args.keypass);
        
        if (jc.getParsedCommand() == null) {
            jc.usage();
        } else if (jc.getParsedCommand().equalsIgnoreCase("keystore")) {
            log.error("keystore functionality  is not implemented yet");
        } else if (jc.getParsedCommand().equalsIgnoreCase("x509")) {
            cp.displayX509(args.infile);
        } else if (jc.getParsedCommand().equalsIgnoreCase("certreq")) {
            if(certreq.show){
                cp.displayPKCS10(args.infile);
                System.exit(PosixExitCodes.OK.exitCode());
            }
            Properties p=new Properties();
            if (certreq.template.isEmpty()) {
                log.debug("No template file specified!");
            } else {
                log.debug("Using certificate request template from file: " + certreq.template);
                try{
                  p = cp.readProperties(certreq.template);
                }catch(Exception ex){
                    File f = new File(certreq.template);
                    log.error("Can not read templte properies file: "+f.getAbsolutePath());
                    System.exit(PosixExitCodes.EX_OSFILE.exitCode());
                }
            }
            p = cp.addDefined(p, certreq);
            CertificateRequestData cd = null;
            if (certreq.rqtype.equalsIgnoreCase("personal")) {
                cd = CertificateRequestData.fromProperty(p, CertificateRequestData.CSRType.PERSON);
            } else if (certreq.rqtype.equalsIgnoreCase("host")) {
                cd = CertificateRequestData.fromProperty(p, CertificateRequestData.CSRType.HOST);
            } else if (certreq.rqtype.equalsIgnoreCase("softsign")) {
                cd = CertificateRequestData.fromProperty(p, CertificateRequestData.CSRType.SOFTSIGN);
            }
            try {
                if (!cp.checkRequiredProperties(cd, certreq.interactive)) {
                    log.error("Undefined mandatory properties found: " + cd.checkNotSetParameters());
                    System.exit(PosixExitCodes.EX_CONFIG.exitCode());
                }
                if (certreq.selfsigned) {
                    cp.createSelfSignedPair(cd, args.outfile);
                } else {
                    cp.createCSR(cd, args.outfile,certreq.challengePassword);
                }
            } catch (Exception ex) {
                log.error("Can not write certificate", ex);
            }
        }
    }

}
