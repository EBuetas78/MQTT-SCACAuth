/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uned.ebs;

import java.math.BigInteger;

/**
 *
 * @author eduar
 */
public class FuncAuxiliares {
        public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
        }
        return data;
        }
        public static String byteArrayToHexString(byte[] b) {
        int len = b.length;
        String data = new String();

        for (int i = 0; i < len; i++){
            data += Integer.toHexString((b[i] >> 4) & 0xf);
            data += Integer.toHexString(b[i] & 0xf);
        }
        return data;
        }
        public static BigInteger ArrayBytetoBigInteger(byte[] bytes,int longitud){
            BigInteger respuesta = BigInteger.ZERO;
            BigInteger base = BigInteger.valueOf(256);
            for (int i = 0; i < longitud; i++) {
                respuesta = respuesta.add(BigInteger.valueOf(bytes[i] & 0xFF).multiply(base.pow(i)));
            }
            return respuesta;
        }
}
