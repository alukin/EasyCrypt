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
import ua.cn.al.easycrypt.CryptoFactory;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class Main {

    /**
     * @param args the command line arguments
     * 
     */
    public static void main(String[] args) {
       CmdLineArgs cmdLine = new CmdLineArgs();
       int result = new CommandLine(cmdLine).execute(args);

      System.out.println("Hello!");
        //Create factory with default crypto settings
      CryptoFactory factory = CryptoFactory.newInstance();
    }
    
}
