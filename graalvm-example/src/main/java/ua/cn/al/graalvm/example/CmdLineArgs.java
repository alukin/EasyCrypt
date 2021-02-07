/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details
 * Copyright (c 2021) Oleksiy Lukin .
 */
package ua.cn.al.graalvm.example;

import picocli.CommandLine;
import picocli.CommandLine.Option;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CmdLineArgs implements Runnable{

    @Option(names = {"-n", "--name"}, description = "Who will we greet?", defaultValue = "World")
    String name;
    @Option(names = {"--help", "-h"}, help = true, description = "Print help message")
    public boolean help;

    public boolean exit = false;

    @Override
    public void run() {
        System.out.println("==== Doing something after command line paring ====");
        System.out.println("==== Name: "+name);
        if(help){
           System.out.println("==== HELP ====");
           CommandLine.usage(this, System.out);
           exit = true;
        }
    }
    
}
