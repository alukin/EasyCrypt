/*
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
package ua.cn.al.easycrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;

/**
 * Base utility class for tests
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class TestBase {
    
    public static void mkdirs(String filename){
        Path p = Path.of(filename);
        File dir = p.getParent().toFile();
        if(!dir.exists()){
            dir.mkdirs();
        }
    }
    
    public static void writeToFile(ByteBuffer data, String fileName) throws IOException {
        mkdirs(fileName);
        try (FileChannel out = new FileOutputStream(fileName).getChannel()) {
            data.rewind();
            out.write(data);
        }
    }

    public static ByteBuffer readFromFile(String fileName) throws IOException {
        FileChannel fChan;
        Long fSize;
        ByteBuffer mBuf;
        fChan = new FileInputStream(fileName).getChannel();
        fSize = fChan.size();
        mBuf = ByteBuffer.allocate(fSize.intValue());
        fChan.read(mBuf);
        fChan.close();
        mBuf.rewind();
        return mBuf;
    }    
}
