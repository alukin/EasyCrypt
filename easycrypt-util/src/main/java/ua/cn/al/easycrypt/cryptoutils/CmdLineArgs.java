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

import picocli.CommandLine.Option;


/**
 * Command line arguments for cryptoutils
 * @author alukin@gmail.com
 * @see http://jcommander.org/
 */
public class CmdLineArgs {
    
    //Main parameter
//    @Option(description = "Command to run: keystore, x509, certreq")    
    public String command;
    @Option(names = {"--version", "-V"}, description = "Show version and exit")
    public boolean show_version = false;  
    @Option(names = {"--debug", "-d"}, description = "Debug mode")
    public boolean debug = false;
    @Option(names = {"--verbose", "-v"}, description = "Verbosity level 0-9")
    public Integer verbose = 1;
    @Option(names = {"--help", "-h"}, help = true, description = "Print help message")
    public boolean help;
    @Option(names = {"--keypass", "-p"}, description = "Passphrase for private key encryption") //password = true)
    public String keypass;
    @Option(names = {"--storefile", "-f"}, description = "Path to PKCS#12 key store file. If not set, PEM output is default")
    public String storefile;
    @Option(names = {"--storealias", "-a"}, description = "Alias in PKCS#12 key store")
    public String storealias;
    @Option(names = {"--storepass", "-s"}, description = "Passphrase for key store") //password = true)
    public String storepass;
    @Option(names = {"--out", "-o"}, description = "Output path. Defaults: newcert.pem, newreq.pem, newcert_pvtkey.pem")
    public String outfile="";
    @Option(names = {"--input", "-i"}, description = "Input path")
    public String infile="newcert.pem";    

}
