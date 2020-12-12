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

/**
 * Universal exception that indicates problems with keys or data
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public final class CryptoNotValidException extends Exception {

    public CryptoNotValidException(String message) {
        super(message);
    }

    public CryptoNotValidException(String message, Throwable cause) {
        super(message, cause);
    }

}
