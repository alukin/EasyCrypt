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
package ua.cn.al.easycrypt;

import java.io.IOException;
import java.io.OutputStream;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com
 */
public class DigestingOutputStream extends OutputStream{
    byte[] hash;
    
    @Override
    public void write(int b) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    public byte[] getHash(){
        return hash;
    }

    @Override
    public void close() throws IOException {
        //finalize hash calculation
        super.close();         
    }
    
}
