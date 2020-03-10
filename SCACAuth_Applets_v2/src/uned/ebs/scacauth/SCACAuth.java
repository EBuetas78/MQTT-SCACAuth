package uned.ebs.scacauth;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PublicKey;
import javacard.security.AESKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
//import javacardx.annotations.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
import javacard.framework.CardRuntimeException;
import javacard.framework.CardException;

//import static uned.ebs.scacauth.SCACAuthStrings.*;

/**
 * Applet class
 * 
 * @author <user>
 */
/*@StringPool(value = {
	    @StringDef(name = "Package", value = "uned.ebs.scacauth"),
	    @StringDef(name = "AppletName", value = "SCACAuth")},
	    // Insert your strings here 
	name = "SCACAuthStrings")*/
public class SCACAuth extends Applet  implements ExtendedLength{
	/*Constants*/
	final static byte LONG_UID=(byte) 0x08;
	final static byte LONG_RN=(byte) 0x10;
	//final static byte LONG_KEY_AES=(byte)0x10;
	final static short TIPO_CLAVE=KeyBuilder.LENGTH_RSA_2048;
	final static short TIPO_CLAVE_AES=KeyBuilder.LENGTH_AES_128;
	final static short LONG_BLOCK_AES=0x10;
	final static short LONG_CLAVE_RSA=0x100;

	final static byte TIPO_PUBLIC_KEY=KeyBuilder.TYPE_RSA_PUBLIC;
	final static byte TIPO_PRIVATE_KEY=KeyBuilder.TYPE_RSA_PRIVATE;
	final static byte TIPO_SIMETRIC_KEY=KeyBuilder.TYPE_AES_TRANSIENT_DESELECT;
	
	final static byte TIPO_ALGORITMO=Cipher.ALG_RSA_PKCS1;
	final static byte TIPO_ALGORITMO_AES=Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
	final static short MAX_APDU_1ENVIO=261;
	/*Instructions*/
    final static byte SCACAuth_CLA = (byte) 0x80;
    final static byte CREATE_PAIR=(byte) 0x20;
    final static byte GET_PUBLIC_KEY=(byte) 0x21;
    final static byte PUT_PUBLIC_KEY_BROKER=(byte)0x22;  
    final static byte PUT_UID=(byte)0x23;
    final static byte GET_UID=(byte)0x24; 
    final static byte CREATE_AUTH_STEP1=(byte)0x25;
    final static byte CHECK_AUTH_STEP2=(byte)0x26;
    final static byte CREATE_AUTH_STEP3=(byte)0x27; 
    final static byte CREATE_MSG_PUBLISH=(byte)0x28;
    final static byte CHECK_PUBREL=(byte)0x29;
    final static byte READ_PAYLOAD=(byte)0x30;
    final static byte CREATE_PUBREL=(byte)0x31;
    final static byte INICIALICE_CIPHER=(byte)0x2A;
    final static byte DAME_MEMORIA=(byte)0x2B;
    final static byte DAME_RN1=(byte)0x2C;

    /*Results*/
    final static byte RETURN_SUCCESS=(byte)0x00; 
    final static byte RETURN_ERROR_AUTH=(byte)0x80; 
    final static byte RETURN_ERROR_CRYPT=(byte)0x81;
    final static byte RETURN_ERROR_GENERATED_KEYPAIR=(byte)0x82;
    final static byte RETURN_ERROR_CHECK=(byte)0x82;
    final static byte RETURN_ERROR_UNKNOWN=(byte)0x99; 
	
	/**/
    
    
    /*Global Variables*/
    
    PublicKey clavepublica;
    RSAPrivateKey thePrivateKey; //=new RSAPrivateKey();// (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, true);
    RSAPublicKey thePublicKey;// = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, true);    
    KeyPair theKeyPair;// = new KeyPair(thePublickKey, thePrivateKey);
    byte RN1[];//=new byte[LONG_RN];
    byte RNpn[];//=new byte[LONG_RN]; //RNp mensaje actual
    byte RNsn[];//=new byte[LONG_RN];//RNs mensaje actual   
    byte UID[];//=new byte[LONG_UID]; //UID
    byte RN[];
    AESKey claveAES;
    byte par_crypt[];
    byte sal_crypt[];
   // byte par_crypt[];
    byte RNsn2[];
  //  byte sal_crypt[];
    byte salida_desencriptacion[];
    short memoriapersistente[];
    byte memoriabyte[];
    RandomData randomdata;
    byte[] buffer;
	//GenerateRandom random;
    byte exponente[];  
	byte modulos[];
	//byte[] buffer_pair=new byte[2048];
    RSAPublicKey theBrokerPublicKey;
    Cipher cipher_encrypt_prc;
	Cipher cipher_encrypt_pub;
	Cipher cipher_decrypt_prc;
	Cipher cipher_decrypt_pub;
	Cipher cipher_aes;	
	private Encriptacion encrypt_cliente;
	private Encriptacion encrypt_broker;
	private Encriptacion encrypt_aes;
	/**/
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SCACAuth();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected SCACAuth() {
    	RN1=JCSystem.makeTransientByteArray(LONG_RN,JCSystem.CLEAR_ON_DESELECT);
        RNpn=JCSystem.makeTransientByteArray(LONG_RN,JCSystem.CLEAR_ON_DESELECT);
        RNsn=JCSystem.makeTransientByteArray(LONG_RN,JCSystem.CLEAR_ON_DESELECT);
        RNsn2=JCSystem.makeTransientByteArray(LONG_RN,JCSystem.CLEAR_ON_DESELECT);
        RN=JCSystem.makeTransientByteArray(LONG_RN,JCSystem.CLEAR_ON_DESELECT);
        //claveAES=JCSystem.makeTransientByteArray(LONG_KEY_AES,JCSystem.CLEAR_ON_DESELECT);
        UID=JCSystem.makeTransientByteArray(LONG_UID,JCSystem.CLEAR_ON_DESELECT);            
        sal_crypt=JCSystem.makeTransientByteArray((short)300,JCSystem.CLEAR_ON_DESELECT);
        par_crypt=JCSystem.makeTransientByteArray((short)300,JCSystem.CLEAR_ON_DESELECT);
        exponente=JCSystem.makeTransientByteArray((short)3, JCSystem.CLEAR_ON_DESELECT);
        modulos=JCSystem.makeTransientByteArray((short)LONG_CLAVE_RSA, JCSystem.CLEAR_ON_DESELECT);
        memoriabyte=JCSystem.makeTransientByteArray((short)8,JCSystem.CLEAR_ON_DESELECT);
        salida_desencriptacion=JCSystem.makeTransientByteArray((short)258,JCSystem.CLEAR_ON_DESELECT);        
        memoriapersistente=JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        buffer=JCSystem.makeTransientByteArray((short)523, JCSystem.CLEAR_ON_DESELECT);
        cipher_encrypt_prc= Cipher.getInstance(TIPO_ALGORITMO, false);
		cipher_encrypt_pub= Cipher.getInstance(TIPO_ALGORITMO, false); 		
		cipher_decrypt_prc= Cipher.getInstance(TIPO_ALGORITMO, false); 
		cipher_decrypt_pub= Cipher.getInstance(TIPO_ALGORITMO, false);
		cipher_aes=Cipher.getInstance(TIPO_ALGORITMO_AES,false);
		randomdata=RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
    }
    
    
    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        
        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if (buffer[ISO7816.OFFSET_CLA] != SCACAuth_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        switch (buffer[ISO7816.OFFSET_INS]) {
            case CREATE_PAIR:
                create_pair(apdu);
                return;
            case GET_PUBLIC_KEY:
            	get_public_key(apdu);
            	return;
            case PUT_PUBLIC_KEY_BROKER:
                put_public_key_broker(apdu); 
                return;
            case PUT_UID: 
                put_UID(apdu);
                return;
            case GET_UID: 
                get_UID(apdu);
                return;
            case CREATE_AUTH_STEP1:
                create_auth_step1(apdu);
                return;
            case CHECK_AUTH_STEP2:
                check_auth_step2(apdu);
                return;
            case CREATE_AUTH_STEP3:
            	create_auth_step3(apdu);
            	return;
            case CREATE_MSG_PUBLISH:
            	create_msg_publish(apdu);
            	return;
            case CHECK_PUBREL:
            	check_pubrel(apdu);
            	return;
            case READ_PAYLOAD:
            	read_payload(apdu);
            	return;
            case CREATE_PUBREL:
            	create_pubrel(apdu);
            	return;
            case INICIALICE_CIPHER:
            	inicialice_cipher(apdu);
            	return;
            case DAME_MEMORIA:
            	dame_memoria(apdu);
            	return;
            case DAME_RN1:
            	dame_rn1(apdu);
            	return;
          //  case ENCRIPTAR_AES(apdu):
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return;
        }
    }
    private void create_pair(APDU apdu) {
    	//Genera el par de calves, si no pasa nada devuelve SW=90 00 
    	//Si no las genera por algo devuelve la INT correspondiete
    	//el APDU para ejecutarlo es 0x80 0x20 0x00 0x00 0x00 0x00;
    	
    	short longitudEx=0;
    	short longitudMod=0;
    	

        try {
        	thePrivateKey= (RSAPrivateKey) KeyBuilder.buildKey(TIPO_PRIVATE_KEY, TIPO_CLAVE, false);
        	thePublicKey=(RSAPublicKey) KeyBuilder.buildKey(TIPO_PUBLIC_KEY,TIPO_CLAVE, false);
        	claveAES=(AESKey)KeyBuilder.buildKey(TIPO_SIMETRIC_KEY, TIPO_CLAVE_AES, false);
        	theKeyPair=new KeyPair(thePublicKey, thePrivateKey);        	
        	theKeyPair.genKeyPair();
        	thePublicKey=(RSAPublicKey)theKeyPair.getPublic();
        	thePrivateKey=(RSAPrivateKey)theKeyPair.getPrivate();        	
        	longitudEx=((RSAPublicKey)thePublicKey).getExponent(exponente, (short) 0);
        	longitudMod=((RSAPublicKey)thePublicKey).getModulus(modulos,(short)0);
            
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)(4+longitudEx+longitudMod));
            buffer[0] = (byte) (longitudEx >> 8);           
            buffer[1] = (byte) (longitudEx & 0xFF);
            buffer[2] = (byte) (longitudMod >> 8); 
            buffer[3] = (byte) (longitudMod & 0xFF);
            apdu.sendBytesLong(buffer, (short)0, (short)4);
            apdu.sendBytesLong(exponente, (short)0, longitudEx);
            apdu.sendBytesLong(modulos, (short)0, longitudMod);
           
        }catch(CryptoException ex) {   
        	if (ex.getReason()==CryptoException.ILLEGAL_USE) {
        		ISOException.throwIt((short)1);
        	}else if(ex.getReason()==CryptoException.ILLEGAL_VALUE) {
        		ISOException.throwIt((short)2);
        	}else if(ex.getReason()==CryptoException.INVALID_INIT) {
        		ISOException.throwIt((short)3);
        	}else if(ex.getReason()==CryptoException.NO_SUCH_ALGORITHM) {
        		ISOException.throwIt((short)4);
        	}else if(ex.getReason()==CryptoException.UNINITIALIZED_KEY) {
        		ISOException.throwIt((short)5);
        	}
        	
        }
     
    } 
    private void get_public_key(APDU apdu) {
    	
    	short longitudEx=0;
    	short longitudMod=0;

    	
        try {
       /* 	
        	longitudEx=((RSAPublicKey)thePublicKey).getExponent(exponente, (short) 0);
        	longitudMod=((RSAPublicKey)thePublicKey).getModulus(modulos,(short)0);
        	
           
            short toSend = (short) (4+longitudEx+longitudMod);

            apdu.setOutgoing();
            apdu.setOutgoingLength(toSend);
            buffer_pair[0] = (byte) (longitudEx >> 8);
            buffer_pair[1] = (byte) (longitudEx & 0xFF);
            buffer_pair[2] = (byte) (longitudMod >> 8);
            buffer_pair[3] = (byte) (longitudMod & 0xFF); 

            Util.arrayCopyNonAtomic(exponente, (short) 0, buffer_pair, (short)4,longitudEx );
            Util.arrayCopyNonAtomic(modulos, (short) 0, buffer_pair, (short)(longitudEx+4),longitudMod );
            byte counter = 0;
            while (toSend > 0) {
            	short enviar=0;
            	if (toSend>32) {
            		enviar=32;
            	}else {
            		enviar=toSend;
            	}
                apdu.sendBytesLong(buffer_pair, (short) (32 * counter), enviar);
                toSend = (short) (toSend - 32);
                counter = (byte) (counter + 1);
            }
*/
        	
        }catch(CryptoException ex) {   
        	if (ex.getReason()==CryptoException.ILLEGAL_USE) {
        		ISOException.throwIt((short)1);
        	}else if(ex.getReason()==CryptoException.ILLEGAL_VALUE) {
        		ISOException.throwIt((short)2);
        	}else if(ex.getReason()==CryptoException.INVALID_INIT) {
        		ISOException.throwIt((short)3);
        	}else if(ex.getReason()==CryptoException.NO_SUCH_ALGORITHM) {
        		ISOException.throwIt((short)4);
        	}else if(ex.getReason()==CryptoException.UNINITIALIZED_KEY) {
        		ISOException.throwIt((short)5);
        	}
        	
        }
     
    } 
    private void put_public_key_broker (APDU apdu) {
    	// access authentication
      //  byte[] buffer;


        short posicion=0; 
        short longitudEx=0;
        short longitudMod=0;
        
        try {

			short read = apdu.setIncomingAndReceive();
			read += apdu.getOffsetCdata();
			short total = apdu.getIncomingLength();
			//buffer=new byte[(short)(total+7)];//+CLA+P1+P2+LC+LCex1+LCex2
			//byte[] apduBuffer = apdu.getBuffer();
			
			short sum = 0;
			
			do {
			    Util.arrayCopyNonAtomic(apdu.getBuffer(), (short) 0, buffer, sum, read);
			    sum += read;
			    read = apdu.receiveBytes((short) 0);
			} while (sum < total);
			if (buffer[ISO7816.OFFSET_LC]==0x00) {
				posicion=ISO7816.OFFSET_CDATA+2;
			}else {
				posicion=ISO7816.OFFSET_CDATA;
			}

		
	        longitudEx=(short)((buffer[posicion]*0x100)+buffer[(short)(posicion+1)]);
	        posicion=(short)(posicion+2);
	        longitudMod=(short)((buffer[posicion]*0x100)+buffer[(short)(posicion+1)]);
	        posicion=(short)(posicion+2);
	        Util.arrayCopyNonAtomic(buffer, posicion, exponente, (short)0,longitudEx );
	        posicion=(short)(posicion+longitudEx);
	        Util.arrayCopyNonAtomic(buffer,  posicion, modulos, (short)0,longitudMod );
	        posicion=(short)(posicion+longitudMod);
	        theBrokerPublicKey= (RSAPublicKey) KeyBuilder.buildKey(TIPO_PUBLIC_KEY, TIPO_CLAVE, false);
	        theBrokerPublicKey.setExponent(exponente,(short) 0, longitudEx);
	        theBrokerPublicKey.setModulus(modulos,(short)0, longitudMod);
	        
        }catch(CryptoException ex) {
        	ISOException.throwIt(ex.getReason());
        }catch(APDUException ex) {
        	ISOException.throwIt(ex.getReason());
        }catch(CardRuntimeException ex) {
        	ISOException.throwIt(ex.getReason());
        }catch(Exception ex) {        	
        	ISOException.throwIt(RETURN_ERROR_UNKNOWN);
        }
    }
    private void put_UID(APDU apdu) {
    	// access authentication
        byte[] buffer = apdu.getBuffer();

        byte numBytes = buffer[ISO7816.OFFSET_LC];

        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        if ((numBytes != LONG_UID) || (byteRead != LONG_UID)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        for (short i=ISO7816.OFFSET_CDATA;i<(short)(ISO7816.OFFSET_CDATA+LONG_UID);i++) {
        	UID[(short)(i-ISO7816.OFFSET_CDATA)]=buffer[i];
        }
    }
    private void get_UID(APDU apdu) {
    	 byte[] buffer = apdu.getBuffer();
         short le = apdu.setOutgoing();
         if (le < LONG_UID) {
             ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
         }
         apdu.setOutgoingLength((byte) LONG_UID);
         for (short i=0;i<LONG_UID;i++) {
        	 buffer[i]=UID[i];
         }
         apdu.sendBytes((short) 0, (short) LONG_UID);      
    }
 
    private void create_auth_step1(APDU apdu) {
    	short posicionpar_crypt=0;
    	short posicionSalida=0;
    	try {
	    	//RN1=random.get_RN();
    		randomdata.generateData(RN1, (short)0, LONG_RN);
	    	Util.arrayCopyNonAtomic(UID,  (short)0, par_crypt, posicionpar_crypt,LONG_UID );
	    	posicionpar_crypt=(short)(posicionpar_crypt+LONG_UID);
	    	Util.arrayCopyNonAtomic(RN1,  (short)0, par_crypt, posicionpar_crypt,LONG_RN );
	    	posicionpar_crypt=(short)(posicionpar_crypt+LONG_RN);
	    	sal_crypt=encrypt_cliente.crypt(par_crypt,(short)(LONG_UID+LONG_RN));
	    	short toSend = (short) ((sal_crypt[0]*0x100)+sal_crypt[1]+10); //el mensaje mas su longitud (en dos bytes) mas los 8 del UID sin encriptar
	    	Util.arrayCopyNonAtomic(UID,  (short)0,buffer , posicionSalida,LONG_UID );
	    	posicionSalida=(short)(posicionSalida+LONG_UID);
	    	Util.arrayCopyNonAtomic(sal_crypt,  (short)0, buffer,posicionSalida ,(short)(toSend-LONG_UID) );
	    	posicionSalida=(short)(posicionSalida+(toSend-LONG_UID));
	    	apdu.setOutgoing();
	        apdu.setOutgoingLength(toSend);
	    	byte counter = 0;
	        while (toSend > 0) {
	         	short enviar=0;
	           	if (toSend>32) {
	           		enviar=32;
	           	}else {
	           		enviar=toSend;
	           	}
	            apdu.sendBytesLong(buffer, (short) (32 * counter), enviar);
	            toSend = (short) (toSend - 32);
	            counter = (byte) (counter + 1);
	        }
    	}catch(CryptoException ex) {
    		ISOException.throwIt(ex.getReason());
    	}catch(Exception ex) {
		//	ISOException.throwIt((short)contador);//RETURN_ERROR_UNKNOWN);
			ISOException.throwIt(RETURN_ERROR_UNKNOWN); 
    	}
   } 
    private void check_auth_step2(APDU apdu) {
    	// access authentication
    //    byte[] buffer;// = apdu.getBuffer();
        short longitudP1=0;
        short longitudP2=0;
        short longitudDecP1=0;
        short longitudDecP2=0;
        short posicion=0;
        short posicionDecP1=0;
        short posicionDecP2=0;
 		try {
			short read = apdu.setIncomingAndReceive();
			read += apdu.getOffsetCdata();
			short total = apdu.getIncomingLength();
		//	buffer=new byte[(short)(total+7)];//+CLA+P1+P2+LC+LCex1+LCex2+Data+Le
			//byte[] apduBuffer = apdu.getBuffer();
			
			short sum = 0;
			
			do {	
			    Util.arrayCopyNonAtomic(apdu.getBuffer(), (short) 0, buffer, sum, read);
			    sum += read;
			    read = apdu.receiveBytes((short) 0);
			} while (sum < total);
			Util.arrayCopyNonAtomic(apdu.getBuffer(), (short) 0, buffer, sum, read);
			if (buffer[ISO7816.OFFSET_LC]==0x00) {
				posicion=ISO7816.OFFSET_CDATA+2;
			}else {
				posicion=ISO7816.OFFSET_CDATA;
			}
		     longitudP1=(short)((buffer[posicion]*0x100)+buffer[(short)(posicion+1)]);
		     posicion=(short)(posicion+2);
		     Util.arrayCopyNonAtomic(buffer,  posicion, sal_crypt,(short)0x00 ,longitudP1 );
		     posicion=(short)(posicion+longitudP1);
		     sal_crypt=encrypt_broker.decrypt(sal_crypt, longitudP1);
		     longitudDecP1=(short)((sal_crypt[0]*0x100)+sal_crypt[1]);
		     posicionDecP1=(short)(posicionDecP1+2);
		     if (Util.arrayCompare(sal_crypt,posicionDecP1,UID,(short)0,LONG_UID)!=0) {
		    	 ISOException.throwIt(RETURN_ERROR_AUTH);
		     }
		     posicionDecP1=(short)(posicionDecP1+LONG_UID);
		     //comprobamos que el RN1 del mensaje 1 es el que corresponde
		     if (Util.arrayCompare(sal_crypt,posicionDecP1,RN1,(short)0,LONG_RN)!=0) {
		    	 ISOException.throwIt(RETURN_ERROR_AUTH);
		     }		     
		     longitudP2=(short)((buffer[posicion]*0x100)+buffer[(short)(posicion+1)]);
		     posicion=(short)(posicion+2);
		     Util.arrayCopyNonAtomic(buffer,  posicion, sal_crypt,(short)0x00 ,longitudP2 );
		     posicion=(short)(posicion+longitudP2);
			 sal_crypt=encrypt_cliente.decrypt(sal_crypt, longitudP2);
		     longitudDecP2=(short)((sal_crypt[0]*0x100)+sal_crypt[1]);
		     posicionDecP2=(short)(posicionDecP2+2);
			//comprobamos uid en la segunda parte
		     if (Util.arrayCompare(sal_crypt,posicionDecP2,UID,(short)0,LONG_UID)!=0) {
		    	 ISOException.throwIt(RETURN_ERROR_AUTH);
		     }
		     posicionDecP2=(short)(posicionDecP2+LONG_UID);
		     //comprobamos que la longitud de los mensajes es la correcta
		     if (longitudDecP1!=LONG_UID+LONG_RN) {
		    	 ISOException.throwIt(RETURN_ERROR_AUTH);
		     }
		     if (longitudDecP2!=LONG_UID+2*LONG_RN) {
		    	 ISOException.throwIt(RETURN_ERROR_AUTH);
		     }
		     //todo las comprobaciones han sido correctas por lo que ahora guardamos RNpn y RNsn
		     Util.arrayCopyNonAtomic(sal_crypt,  posicionDecP2, RNpn,(short)0x00 ,LONG_RN );
		     posicionDecP2=(short)(posicionDecP2+LONG_RN);
		     Util.arrayCopyNonAtomic(sal_crypt,  posicionDecP2, RNsn,(short)0x00 ,LONG_RN );
		}catch(CryptoException ex) {
			ISOException.throwIt(ex.getReason());
		}catch(Exception ex) {
//			ISOException.throwIt((short)contador);//RETURN_ERROR_UNKNOWN);
			ISOException.throwIt(RETURN_ERROR_UNKNOWN);
		}
   }
    private void create_auth_step3(APDU apdu) { 
    	short posicionpar_crypt=0;
    	try {
	    	//GenerateRandom random=new GenerateRandom(LONG_RN,RN);
	    	//RN1=random.get_RN();	    	
	    	Util.arrayCopyNonAtomic(UID,  (short)0x00, par_crypt,posicionpar_crypt ,LONG_UID );
	    	posicionpar_crypt=(short)(posicionpar_crypt+LONG_UID);	    	
	    	Util.arrayCopyNonAtomic(RNpn,  (short)0x00, par_crypt,posicionpar_crypt ,LONG_RN );
	    	posicionpar_crypt=(short)(posicionpar_crypt+LONG_RN);	    	
	    	Util.arrayCopyNonAtomic(RNsn,  (short)0x00, par_crypt,posicionpar_crypt ,LONG_RN );
	    	posicionpar_crypt=(short)(posicionpar_crypt+LONG_RN);
	    	sal_crypt=encrypt_broker.crypt(par_crypt,(short)(LONG_UID+2*LONG_RN));
	    	short toSend = (short) ((sal_crypt[0]*0x100)+sal_crypt[1]+2); //el mensaje mas su longitud (en dos bytes) mas los 8 del UID sin encriptar
	    	//Util.arrayCopyNonAtomic(sal_crypt,  (short)0x00, sal_crypt, (short)0x00 ,toSend );
	    	apdu.setOutgoing();
	        apdu.setOutgoingLength(toSend);
	    	byte counter = 0;
	        while (toSend > 0) {
	         	short enviar=0;
	           	if (toSend>32) {
	           		enviar=32;
	           	}else {
	           		enviar=toSend;
	           	}
	            apdu.sendBytesLong(sal_crypt, (short) (32 * counter), enviar);
	            toSend = (short) (toSend - 32);
	            counter = (byte) (counter + 1);
	        }
	      //  JCSystem.requestObjectDeletion();
    	}catch(CryptoException ex) {
    		ISOException.throwIt(ex.getReason());
        }
   }
    private void create_msg_publish(APDU apdu) {
        byte[] buffer = apdu.getBuffer(); 
        short longitudPayload=0;
        short posicion_payload=0;
        short longitudpar_crypt=0;
        short posicion_par_crypt=0;
        short resto=0;
		try {
		     byte numBytes = buffer[ISO7816.OFFSET_LC];
		     try {
		    	 if (numBytes==0) {	  
		    		 longitudPayload=(short)((buffer[ISO7816.OFFSET_CDATA]*0x100)+buffer[(short)(ISO7816.OFFSET_CDATA+1)]);		    		 
		    		 posicion_payload=(short)(ISO7816.OFFSET_CDATA+2);
		    	 }else {	
		    		 longitudPayload=(short)numBytes;
		    		 posicion_payload=ISO7816.OFFSET_CDATA;
		    	 }
		    	 longitudpar_crypt=(short)(LONG_UID+LONG_RN+longitudPayload+2);
		    	 Util.arrayCopyNonAtomic(UID,  (short)0x00, par_crypt, posicion_par_crypt ,LONG_UID );
		    	 posicion_par_crypt=(short)(posicion_par_crypt+LONG_UID);
		    	 par_crypt[posicion_par_crypt]=(byte)(longitudPayload>>8);
		    	 posicion_par_crypt++;
		    	 par_crypt[posicion_par_crypt]=(byte)(longitudPayload & 0xff);
		    	 posicion_par_crypt++;
		    	 
			
		    	 Util.arrayCopyNonAtomic(buffer,  posicion_payload, par_crypt, posicion_par_crypt ,longitudPayload );
		    	 posicion_par_crypt=(short)(posicion_par_crypt+longitudPayload);
		    	 Util.arrayCopyNonAtomic(RNpn,  (short)0x00, par_crypt,posicion_par_crypt ,LONG_RN );
		    	 posicion_par_crypt=(short)(posicion_par_crypt+LONG_RN);
		    	 resto=(short)(longitudpar_crypt % LONG_BLOCK_AES);
		    	 if (resto !=0) {
		    		 for (short i=longitudpar_crypt;i<longitudpar_crypt+(LONG_BLOCK_AES-resto);i++) {
		    			 par_crypt[i]=0x00;
		    		 }
		    		 longitudpar_crypt=(short)(longitudpar_crypt+(LONG_BLOCK_AES-resto));
		    	 }
		    	 claveAES.setKey(RNpn, (short)0);
		    	 cipher_aes.init(claveAES, Cipher.MODE_ENCRYPT);
		    	 sal_crypt=encrypt_aes.crypt(par_crypt,(short)longitudpar_crypt);
		    	 short toSend = (short) ((sal_crypt[0]*0x100)+sal_crypt[1]+2); //el mensaje mas su longitud (en dos bytes) r
		    	 apdu.setOutgoing();
		    	 apdu.setOutgoingLength(toSend);
		    	 byte counter = 0;
		    	 while (toSend > 0) {
		    		 short enviar=0;
		    		 if (toSend>32) {
		    			 enviar=32;
		    		 }else {
		    			 enviar=toSend;
		    		 } 
		    		 apdu.sendBytesLong(sal_crypt, (short) (32 * counter), enviar);
		    		 toSend = (short) (toSend - 32);
		    		 counter = (byte) (counter + 1);
		    	 }
		    	 
		     }catch(CryptoException ex) {
		    	 ISOException.throwIt(ex.getReason());
		     }
		}catch(CryptoException ex) {
			ISOException.throwIt(RETURN_ERROR_CRYPT);
		}catch(Exception ex) {
			ISOException.throwIt(RETURN_ERROR_UNKNOWN);
		}
    }
    private void check_pubrel(APDU apdu) {
        short longitud_par_crypt=0; 
        short posicion_par_crypt=0;
        short posicion_sal_crypt=0;
 		try {
			short read = apdu.setIncomingAndReceive();
			read += apdu.getOffsetCdata();
			short total = apdu.getIncomingLength();
			//byte[] apduBuffer = apdu.getBuffer();
			//apduBuffer = apdu.getBuffer();
			short sum = 0;
			do {	
			    Util.arrayCopyNonAtomic(apdu.getBuffer(), (short) 0, par_crypt, sum, read);
			    sum += read;
			    read = apdu.receiveBytes((short) 0);
			} while (sum < total);
			Util.arrayCopyNonAtomic(apdu.getBuffer(), (short) 0, par_crypt, sum, read);
			if (par_crypt[ISO7816.OFFSET_LC]==0x00) {
				posicion_par_crypt=ISO7816.OFFSET_CDATA+2;
			}else {
				posicion_par_crypt=ISO7816.OFFSET_CDATA;
			}
	    	 longitud_par_crypt=(short)((par_crypt[posicion_par_crypt]*0x100)+par_crypt[(short)(posicion_par_crypt+1)]);
	    	 posicion_par_crypt=(short)(posicion_par_crypt+2);
	    	 Util.arrayCopyNonAtomic(par_crypt,  posicion_par_crypt, par_crypt, (short)0x00 ,longitud_par_crypt );
	    	 posicion_par_crypt=(short)(posicion_par_crypt+longitud_par_crypt);
	    	 
	    	 claveAES.setKey(RNpn, (short)0);
	    	 cipher_aes.init(claveAES, Cipher.MODE_DECRYPT);
	    	 sal_crypt=encrypt_aes.decrypt(par_crypt, longitud_par_crypt);
	    	 posicion_sal_crypt=(short)(posicion_sal_crypt+2);
	    	 //comprobamos la longitud
	    	/* if (longitud_sal_crypt!=LONG_UID+2*LONG_RN) {
	    		 ISOException.throwIt(RETURN_ERROR_CHECK);
	    	 }*/
	    	 //comprobamos el UID
	    	 if (Util.arrayCompare(sal_crypt,posicion_sal_crypt,UID,(short)0,LONG_UID)!=0) {
		    	 ISOException.throwIt(RETURN_ERROR_AUTH);
		     }
	    	 posicion_sal_crypt=(short)(posicion_sal_crypt+LONG_UID);
	    	 //comprobamos el RNpn
	    	 if (Util.arrayCompare(sal_crypt,posicion_sal_crypt,RNpn,(short)0,LONG_RN)!=0) {
		    	 ISOException.throwIt(RETURN_ERROR_AUTH);
		     }
	    	 posicion_sal_crypt=(short)(posicion_sal_crypt+LONG_RN);
	    	 //si todo esta bien pasamos RNp(n+1) a RNpn
	    	 Util.arrayCopyNonAtomic(sal_crypt,  posicion_sal_crypt, RNpn, (short)0x00 ,LONG_RN );
		}catch(CryptoException ex) {
			ISOException.throwIt(RETURN_ERROR_CRYPT);
		}catch(Exception ex) {
			ISOException.throwIt(RETURN_ERROR_UNKNOWN);
		}
    }
    private void read_payload(APDU apdu) {
         short longitud_par_crypt=0;
         short posicion_par_crypt=0;
         short posicion_sal_crypt=0;
         short longitud_payload=0;
 		try {

			short read = apdu.setIncomingAndReceive();
			read += apdu.getOffsetCdata();
			short total = apdu.getIncomingLength();	
			short sum = 0;
			do {					
			    Util.arrayCopyNonAtomic(apdu.getBuffer(), (short) 0, par_crypt, sum, read);
			    sum += read;
			    read = apdu.receiveBytes((short) 0);
			} while (sum < total);
			Util.arrayCopyNonAtomic(apdu.getBuffer(), (short) 0, par_crypt, sum, read);
			if (par_crypt[ISO7816.OFFSET_LC]==0x00) {
				posicion_par_crypt=ISO7816.OFFSET_CDATA+2;

			}else {
				posicion_par_crypt=ISO7816.OFFSET_CDATA;
			}
			 //longitud_par_crypt=(short)(par_crypt[posicion_par_crypt]*0x100);
			//si el byte 1 empieza por 1xxx xxxx el java, al transformarlo a short lo interpretara como un entero corto con signo y rellenara con FF,
			//asi que si este es el caso, le quito el primer 1 y luego le sumo 128 al entero
			if ((par_crypt[(short)(posicion_par_crypt+1)] & 0x80)!=0) {
				par_crypt[(short)(posicion_par_crypt+1)]=(byte)(par_crypt[(short)(posicion_par_crypt+1)] & 0x7F);
				longitud_par_crypt=(short)(par_crypt[(short)(posicion_par_crypt+1)]);
				longitud_par_crypt=(short)(longitud_par_crypt+0x80);
			}else {
				longitud_par_crypt=(short)((par_crypt[posicion_par_crypt]*0x100)+par_crypt[(short)(posicion_par_crypt+1)]);
			}
	    	 

	    	 
	    	 posicion_par_crypt=(short)(posicion_par_crypt+2);
	    	 Util.arrayCopyNonAtomic(par_crypt, posicion_par_crypt, par_crypt, (short)0x00, longitud_par_crypt);
	    	 claveAES.setKey(RNsn, (short)0);
	    	 cipher_aes.init(claveAES, Cipher.MODE_DECRYPT);
	    	 sal_crypt=encrypt_aes.decrypt(par_crypt, longitud_par_crypt);
	    	 posicion_sal_crypt=(short)(posicion_sal_crypt+2);
	    	 //comprobamos el UID
			if (Util.arrayCompare(sal_crypt,posicion_sal_crypt,UID,(short)0,LONG_UID)!=0) {
				ISOException.throwIt(RETURN_ERROR_CHECK);
			}
			posicion_sal_crypt=(short)(posicion_sal_crypt+LONG_UID);
	    	 //comprobamos el RNsn
			if ((sal_crypt[(short)(posicion_sal_crypt+1)] & 0x80)!=0) {
				sal_crypt[(short)(posicion_sal_crypt+1)]=(byte)(sal_crypt[(short)(posicion_sal_crypt+1)] & 0x7F);
				longitud_payload=(short)(sal_crypt[posicion_sal_crypt]*0x100+sal_crypt[(short)(posicion_sal_crypt+1)]);;
				longitud_payload=(short)(longitud_payload+0x80);
			}else {
				longitud_payload=(short)(sal_crypt[posicion_sal_crypt]*0x100+sal_crypt[(short)(posicion_sal_crypt+1)]);//(short)(longitud_sal_crypt-LONG_UID-LONG_RN);
			}
			posicion_sal_crypt=(short)(posicion_sal_crypt+2);
			//payload=new byte[longitud_payload];
			
			/*if (Util.arrayCompare(sal_crypt,(short)(posicion_sal_crypt+longitud_payload),RNsn,(short)0,LONG_RN)!=0) {
				ISOException.throwIt(RETURN_ERROR_CHECK);
			}*/
			short toSend = (short) (longitud_payload);
			//contador=0x18;
			apdu.setOutgoing(); 
	       apdu.setOutgoingLength(toSend);
	       byte counter = 0;
	       while (toSend > 0) { 		       
	    	   short enviar=0;
	           if (toSend>32) {
	           		enviar=32;
	           }else {
	        	   enviar=toSend;
	           }
	           apdu.sendBytesLong(sal_crypt, (short) ((32 * counter)+posicion_sal_crypt), enviar);
	           toSend = (short) (toSend - 32);
	           counter = (byte) (counter + 1);
	       }
 		}catch(CryptoException ex) {
 			ISOException.throwIt(RETURN_ERROR_CRYPT);
 		}catch(CardRuntimeException ex) {
 			ISOException.throwIt(ex.getReason());
 		}catch(Exception ex) {
 			ISOException.throwIt(RETURN_ERROR_UNKNOWN);
 		}
    }
    private void create_pubrel(APDU apdu) {
    	short posicionpar_crypt=0;
    	short posicionSalida=0;
    	short longitudpar_crypt=0;
    	short resto=0;
    	try {
	    	//GenerateRandom random=new GenerateRandom(LONG_RN,RN);
	    	//RNsn2=random.get_RN();
    		randomdata.generateData(RNsn2, (short)0, LONG_RN);
	    	Util.arrayCopyNonAtomic(UID, (short)0x00, par_crypt,posicionpar_crypt, LONG_UID);
	    	posicionpar_crypt=(short)(posicionpar_crypt+LONG_UID); 
	    	//Util.arrayCopyNonAtomic(RNsn, (short)0x00, par_crypt,posicionpar_crypt, LONG_RN);
	    	//posicionpar_crypt=(short)(posicionpar_crypt+LONG_RN); 
	    	Util.arrayCopyNonAtomic(RNsn2, (short)0x00, par_crypt,posicionpar_crypt, LONG_RN);
	    	posicionpar_crypt=(short)(posicionpar_crypt+LONG_RN); 
	    	//Encriptacion encriptacion=new Encriptacion(theBrokerPublicKey,TIPO_ALGORITMO);
	    	longitudpar_crypt=(short)(LONG_UID+2*LONG_RN);
	    	resto=(short)(longitudpar_crypt % LONG_BLOCK_AES);
	    	 if (resto !=0) {
	    		 /*for (short i=longitudpar_crypt;i<longitudpar_crypt+(LONG_BLOCK_AES-resto);i++) {
	    			 par_crypt[i]=0x00;
	    		 }*/
	    		 longitudpar_crypt=(short)(longitudpar_crypt+(LONG_BLOCK_AES-resto));
	    	 }
         	claveAES.setKey(RNpn, (short)0);
	    	cipher_aes.init(claveAES, Cipher.MODE_ENCRYPT);
	    	sal_crypt=encrypt_broker.crypt(par_crypt,longitudpar_crypt);//(short)(LONG_UID+2*LONG_RN));
	    	short toSend = (short) ((sal_crypt[0]*0x100)+sal_crypt[1]+2); //el mensaje mas su longitud (en dos bytes) 
	    	posicionSalida=0;
	    	Util.arrayCopyNonAtomic(sal_crypt, (short)0x00, par_crypt,posicionSalida, toSend);
	    	posicionSalida=(short)(posicionSalida+toSend); 
	    	//una vez hecho el mensaje cambiamos el RNsn por RNsn2
	    	Util.arrayCopyNonAtomic(RNsn2, (short)0x00, RNsn,(short)0x00, LONG_RN);
	    	apdu.setOutgoing();
	        apdu.setOutgoingLength(toSend); 
	    	byte counter = 0;
	        while (toSend > 0) {  
	         	short enviar=0;  
	           	if (toSend>32) {
	           		enviar=32;
	           	}else {
	           		enviar=toSend;
	           	}
	            apdu.sendBytesLong(par_crypt, (short) (32 * counter), enviar);
	            toSend = (short) (toSend - 32); 
	            counter = (byte) (counter + 1); 
	        }
    	}catch(CryptoException ex) {
    		ISOException.throwIt(ex.getReason());
    	}  	
    }
    private void inicialice_cipher(APDU apdu) {
    	try {
    		//aqui
    		cipher_encrypt_prc.init(thePrivateKey, Cipher.MODE_ENCRYPT); 
    		cipher_encrypt_pub.init(theBrokerPublicKey, Cipher.MODE_ENCRYPT);
    		cipher_decrypt_prc.init(thePrivateKey, Cipher.MODE_DECRYPT);
    		cipher_decrypt_pub.init(theBrokerPublicKey, Cipher.MODE_DECRYPT);
    		encrypt_cliente=new Encriptacion(cipher_encrypt_prc,cipher_decrypt_prc,salida_desencriptacion);
    		encrypt_broker=new Encriptacion(cipher_encrypt_pub,cipher_decrypt_pub,salida_desencriptacion);
    		encrypt_aes=new Encriptacion(cipher_aes,cipher_aes,salida_desencriptacion);
	    	//random=new GenerateRandom(LONG_RN,RN);

    	}catch(CryptoException ex) { 
    		ISOException.throwIt(ex.getReason());
    	}catch(Exception ex) { 
    		ISOException.throwIt(RETURN_ERROR_UNKNOWN); 
    	}
    }
    private void dame_memoria(APDU apdu) {
    	short memoria=JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
    	
   	 	memoriabyte[0]=(byte)(memoria>>8);
   	 	memoriabyte[1]=(byte)(memoria & 0xff);
   	 	memoria=JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
   	 	memoriabyte[2]=(byte)(memoria>>8); 
   	 	memoriabyte[3]=(byte)(memoria & 0xff);
   	 	
   	 	JCSystem.getAvailableMemory(memoriapersistente,(short)0,JCSystem.MEMORY_TYPE_PERSISTENT);
	 	memoriabyte[4]=(byte)(memoriapersistente[0]>>8);
	 	memoriabyte[5]=(byte)(memoriapersistente[0] & 0xff);
	 	memoriabyte[6]=(byte)(memoriapersistente[1]>>8);
	 	memoriabyte[7]=(byte)(memoriapersistente[1] & 0xff);

	 	byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();
        if (le < 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
        }
        for (short i=0;i<(short)8;i++) {
       	 buffer[i]=memoriabyte[i];
        }
        apdu.setOutgoingLength((byte) 8);

        apdu.sendBytes((short) 0, (short) 8);      
   	  
    }
    private void dame_rn1(APDU apdu) {
    	

	 	byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();
        if (le < LONG_RN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
        }
        for (short i=0;i<(short)LONG_RN;i++) {
       	 buffer[i]=RN1[i];
        }
        apdu.setOutgoingLength((byte) LONG_RN);

        apdu.sendBytes((short) 0, (short) LONG_RN);      
   	  
    }
}
