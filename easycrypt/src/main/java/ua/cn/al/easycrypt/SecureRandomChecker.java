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
 * Check secure random generation speed. It should be fast enough
 * to generate keys quickly. On Linux systems haveged package
 * should be installed to update /dev/random with enough entropy
 * @author Oleksiy Lukin alukin@gmail.com
 */
public interface SecureRandomChecker {
    Long SECURE_RANDOM_ACCEPTABLE_TIME_MS=100L;
    boolean check();
    
}
