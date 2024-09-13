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

import ua.cn.al.easycrypt.csr.CertificateRequestData;
import java.io.File;
import java.util.Properties;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.ParseResult;

/**
 *
 * @author alukin@gmail.com
 */
public class Main {
    private final static String version="1.2.8";
    
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void usage(CommandLine cmdParser){
       cmdParser.usage(System.out);
    }
    
    public static void main(String[] argv) {
        CmdLineArgs args = new CmdLineArgs();
        CmdKeyStore keystore = new CmdKeyStore();
        CmdCertReq certreq = new CmdCertReq();
        CmdX509Cert x509 = new CmdX509Cert();
        CommandProcessor cp;

        CommandLine cmdParser = new CommandLine(args);
        cmdParser.addSubcommand(keystore);
        cmdParser.addSubcommand(certreq);
        cmdParser.addSubcommand(x509);
        
        cmdParser.setCommandName("easycryptutil");
        
        try {
            cmdParser.parseArgs(argv);
        } catch (RuntimeException ex) {
            System.err.println("Error parsing command line arguments.");
            System.err.println(ex.getMessage());
            usage(cmdParser);
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
            usage(cmdParser);
            System.out.println("\nSupported properties. Some are quite frustratying, thanks to X guys. Please google for OID for more info.\n");
            Map<String, String> sa = CertificateRequestData.getSupportedAttributesHelp();
            sa.keySet().forEach(key -> {
                System.out.println(key + "  " + sa.get(key));
            });
            System.exit(PosixExitCodes.OK.exitCode());
        }
//TODO: log level setting        
//        if (args.debug) {
//            LogManager.getLogger("ua.cn.al").setLevel(org.apache.log4j.Level.DEBUG);
//            log.debug("Current disrectory: " + System.getProperty("user.dir"));
//        } else {
//            LogManager.getLogger("ua.cn.al").setLevel(org.apache.log4j.Level.ERROR);
//        }
        
        cp = new CommandProcessor(args.storefile, args.storealias, args.storepass, args.keypass);
        ParseResult sc = cmdParser.getParseResult().subcommand();
        
        String commandName ="";
        if(sc!=null){
          commandName = sc.commandSpec().name();
        }
        
        if (commandName.isEmpty()) {
             usage(cmdParser);
        } else if (commandName.equals("keystore")) {
            log.error("keystore functionality  is not implemented yet");
        } else if (commandName.equals("x509")) {
            cp.displayX509(args.infile);
        } else if (commandName.equals("certreq")) {
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
