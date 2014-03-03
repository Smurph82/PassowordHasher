/**
 * Copyright (c) 2013 Ben Murphy (Smurph)
 * Created - Nov 20, 2013
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.smurph.passwordhasher;

public class HexCoder {

	/**
	 * @param txt The {@link String} to convert to a HEX String
	 * @return The converted HEX String 
	 */
    public static String toHex(String txt) {
            return toHex(txt.getBytes());
    }

    /**
     * @param hex The HEX String to convert
     * @return The String
     */
    public static String fromHex(String hex) {
            return new String(toByte(hex));
    }

    /**
     * @param hexString The HEX {@link String} to convert
     * @return The <code>byte[]</code> of the {@link String}
     */
    public static byte[] toByte(String hexString) {
            int len = hexString.length() / 2;
            byte[] result = new byte[len];
            for (int i = 0; i < len; i++)
                    result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2), 16).byteValue();
            return result;
    }

    /**
     * @param buf The <code>byte[]</code> to convert
     * @return The {@link String} of the <code>byte[]</code>
     */
    public static String toHex(byte[] buf) {
            if (buf == null)
                    return "";
            StringBuffer result = new StringBuffer(2 * buf.length);
            for (int i = 0; i < buf.length; i++) {
                    appendHex(result, buf[i]);
            }
            return result.toString();
    }

    /** Append the <code>byte</code> to the {@link StringBuffer}*/
    private static void appendHex(StringBuffer sb, byte b) {
            sb.append(HEX.charAt((b >> 4) & 0x0f)).append(HEX.charAt(b & 0x0f));
    }

    /** HEX characters */
    private final static String HEX = "0123456789ABCDEF";
}