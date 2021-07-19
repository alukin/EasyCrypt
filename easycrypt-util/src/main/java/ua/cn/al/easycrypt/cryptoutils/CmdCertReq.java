/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
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
 *
 */

package ua.cn.al.easycrypt.cryptoutils;


import java.util.HashMap;
import java.util.Map;
import picocli.CommandLine.Command;

import picocli.CommandLine.Option;

/**
 *
 * @author alukin@gmail.com
 */

@Command(name="certreq", description = "Create, display, check certificate request")
public class CmdCertReq {

    @Option(names = {"--template", "-t"}, description = "Path to  file with default parameters")
    public String template="";
    @Option(names = {"--interactive", "-i"}, description = "Interactive mode")
    public Boolean interactive=false;
    @Option(names = {"--selfsigned", "-s"}, description = "Create self-signed X.509 certificate")
    public Boolean selfsigned=false;
    @Option(names = {"--rqtype", "-r"}, description = "Type of certificate request: personal, host, softsign") // validateWith = RqTypeValidator.class)
    public String rqtype="host";   
    @Option(names = {"--define","-D"}, description =  "Define property, e.g. certificate parameter. Format: name=value; May be used multiple times. Overwrites template")
    public Map<String, String> params = new HashMap<>();     
    @Option(names = {"--password", "-p"}, description = "Set challenge password in CSR")
    public String challengePassword="";
    @Option(names = {"--show", "-S"}, description = "Parse and show CSR")
    public boolean show;
}
