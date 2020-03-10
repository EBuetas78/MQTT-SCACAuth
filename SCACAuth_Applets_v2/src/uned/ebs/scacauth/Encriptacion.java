package uned.ebs.scacauth;

import javacard.framework.ISOException;

import javacard.security.*;
import javacardx.crypto.Cipher;

public class Encriptacion {

		private Cipher cipher_encrypt;
		private Cipher cipher_decrypt;

		byte salida[];
		public Encriptacion(Cipher _cipher_encrypt, Cipher _cipher_decrypt,byte _salida[]) {

			cipher_encrypt=_cipher_encrypt;
			cipher_decrypt=_cipher_decrypt;
			//salida=new byte[258];
			salida=_salida;
		}
		public byte[] crypt(byte[] msg,short longitud_enc) throws CryptoException {
			short longitud=0;
			//byte salida[];
			//try {

		        longitud=cipher_encrypt.doFinal(msg, (short) 0,
		               longitud_enc, salida, (short)2);
		        salida[0]=(byte)(longitud>>8);
		        salida[1]=(byte)(longitud & 0xFF);

			//}catch(CryptoException ex) {
	    		//ISOException.throwIt(ex.getReason());
			//}
	        return salida;
	    }
		public byte[] decrypt(byte[] msg,short longitudmsg) throws CryptoException {
			short longitud=0;			
			//try {
		        longitud=cipher_decrypt.doFinal(msg, (short) 0,
		               (short) longitudmsg, salida, (short) 2);
		        salida[0]=(byte)(longitud>>8);
		        salida[1]=(byte)(longitud & 0xFF);

		//	}catch(CryptoException ex) {
	    	//	ISOException.throwIt(ex.getReason());
		///	}
	        return salida;
	    }

}
