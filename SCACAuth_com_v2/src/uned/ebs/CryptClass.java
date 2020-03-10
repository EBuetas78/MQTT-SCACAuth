/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uned.ebs;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Key;
import javax.crypto.Cipher;
import java.util.Random; 
import java.security.Provider;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
/**
 *
 * @author eduar
 */
public class CryptClass {
    private KeyPairGenerator kpg;
    private KeyPair kp;
    private Key Public;
    private Key Private;
    private String tipo_clave;
    private String tipo_clave_aes;
    
    public CryptClass(int tamanoKey,String _tipo_clave,String _tipo_clave_aes) throws Exception{
        tipo_clave=_tipo_clave;
        tipo_clave_aes=_tipo_clave_aes;
        kpg = KeyPairGenerator.getInstance(tipo_clave);
        kpg.initialize(tamanoKey);
        KeyPair kp = kpg.generateKeyPair();
        Public = kp.getPublic();
        Private = kp.getPrivate();
    }
    public Key get_Public(){
        return Public;
    }
    public byte[] encriptar(byte[] aEncriptar) throws Exception{
            byte[]respuesta;
            Cipher cipher = Cipher.getInstance(tipo_clave);
	    cipher.init(Cipher.ENCRYPT_MODE, Private);
	    respuesta= cipher.doFinal(aEncriptar);
            return respuesta;
    }
    public byte[] encriptar(byte[] aEncriptar,Key clave) throws Exception{
            byte[]respuesta;
            Cipher cipher = Cipher.getInstance(tipo_clave);
	    cipher.init(Cipher.ENCRYPT_MODE, clave);
	    respuesta= cipher.doFinal(aEncriptar);
            return respuesta;
    }
    public byte[] encriptar_aes(byte[] aEncriptar,byte[] clave) throws Exception{
            byte[]respuesta;
            SecretKeySpec skeySpec = new SecretKeySpec(clave, "AES");
             byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(tipo_clave_aes);
	    cipher.init(Cipher.ENCRYPT_MODE, skeySpec,ivspec);

	    respuesta= cipher.doFinal(aEncriptar);
            return respuesta;
    }
    public byte[] desencriptar(byte[] aDesEncriptar) throws Exception{
            byte[]respuesta;            
            Cipher cipher = Cipher.getInstance(tipo_clave);                     
	    cipher.init(Cipher.DECRYPT_MODE, Private);
	    respuesta= cipher.doFinal(aDesEncriptar,0,aDesEncriptar.length);
            return respuesta;
    }
    public byte[] desencriptar(byte[] aDesEncriptar,Key clave) throws Exception{
            byte[]respuesta;
         //   Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");//tipo_clave);
            Cipher cipher = Cipher.getInstance(tipo_clave);
            //Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
	    cipher.init(Cipher.DECRYPT_MODE, clave);
	    respuesta= cipher.doFinal(aDesEncriptar,0,aDesEncriptar.length);
            return respuesta;
    }
    public byte[] desencriptar_aes(byte[] aDesEncriptar,byte[] clave) throws Exception{
            byte[]respuesta;
            SecretKeySpec skeySpec = new SecretKeySpec(clave, "AES");
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);
         //   Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");//tipo_clave);
            Cipher cipher = Cipher.getInstance(tipo_clave_aes);
            //Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
	    cipher.init(Cipher.DECRYPT_MODE, skeySpec,ivspec);
	    respuesta= cipher.doFinal(aDesEncriptar,0,aDesEncriptar.length);
            return respuesta;
    }
    public byte[] generateRN(int n_bytes) throws Exception{
        byte randomBytes[];
        randomBytes = new byte[n_bytes];
        Random rand = new Random(); 
        rand.nextBytes(randomBytes);
        return randomBytes;
    }

}
