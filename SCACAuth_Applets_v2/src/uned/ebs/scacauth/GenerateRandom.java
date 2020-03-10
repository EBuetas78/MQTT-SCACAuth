
package uned.ebs.scacauth;
import javacard.security.RandomData;
import javacard.framework.ISOException;
import javacard.security.CryptoException;

public class GenerateRandom {
	private byte RN[];
	RandomData randomdata=null;
	byte long_rn;
	public GenerateRandom(byte _long_rn,byte []_RN) {
		try {
			RN=_RN;
			long_rn=_long_rn;
			
		}catch(CryptoException ex) {
			ISOException.throwIt(ex.getReason());
		}
	}
	public byte[] get_RN() {
		randomdata=RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);//CON LA TARJETA DE VERDAD PONER ALG_SECURE_RANDOM
		randomdata.generateData(RN, (short)0, (short)long_rn); 
		return RN; 
	} 
}
