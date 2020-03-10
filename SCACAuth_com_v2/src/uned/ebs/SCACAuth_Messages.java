/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uned.ebs;

import javax.smartcardio.*;
import java.security.spec.RSAPublicKeySpec;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.math.BigInteger;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.Byte;
/**
 *
 * @author eduar
 */
public class SCACAuth_Messages {
        final static short LONG_UID=8;
        final static short LONG_RN=0x10;
        final static byte CLA=(byte)0x80;
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
        final static byte INIT_CIPHERS=(byte)0x2A;
        final static byte DAME_MEMORIA=(byte)0x2B; 
        final static byte DAME_RN1=(byte)0x2C;
        
        final static int FAULT_LONG_UID=0x7001;
        private final CardChannel channel;
        private PublicKey PublicKeyClient;
        private String UID;
        private long inicio=0;
        private long fin=0;
        private double tiempo=0;
        private FileWriter writer;
        public SCACAuth_Messages(CardChannel _channel){
            channel=_channel;  
            try{
                writer = new FileWriter("Registros"+Long.toString(System.currentTimeMillis())+".csv");
            }catch(IOException ex){
                System.out.println(ex.getMessage());
            }
        }
        public PublicKey getPublicKey(){
            return PublicKeyClient;
        }
        
        public String getUID(){
            return UID;
        }
        public int create_pair() throws Exception{
           int respuesta=0;
           byte modulo[];
           byte exponente[];
           int longitudMod=0;
           int longitudEx=0;
           int data_pos=0;
           byte comando[]=new byte[4];
            
            comando[0]=CLA;
            comando[1]=CREATE_PAIR;
            comando[2]=0x00;
            comando[3]=0x00;
            //comando[4]=0x00;
            //comando[5]=0x00;
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(new CommandAPDU(comando));
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"create_pair");
            
            if (r.getSW()==0x9000){
                longitudEx=r.getData()[data_pos]*0x100+r.getData()[data_pos+1];
                data_pos=data_pos+2;
                longitudMod=r.getData()[data_pos]*0x100+r.getData()[data_pos+1];
                data_pos=data_pos+2;
                exponente=new byte[longitudEx];
                modulo=new byte[longitudMod+1];
                for (int i=0;i<longitudEx;i++){
                    exponente[i]=r.getData()[data_pos];
                    data_pos++;
                }
                modulo[0]=0x00;
                for (int i=1;i<longitudMod+1;i++){
                    modulo[i]=r.getData()[data_pos];
                    data_pos++;
                }
                RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(modulo),new BigInteger(exponente));
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PublicKeyClient = factory.generatePublic(spec);
              
            }
            respuesta=r.getSW();
            return respuesta;
        }
        public int get_public_key() throws Exception{
            int respuesta=0;
            byte modulo[];
            byte exponente[];
            int longitudMod=0;
            int longitudEx=0;
            int data_pos=0;
            byte comando[]=new byte[6];
            
            comando[0]=CLA;
            comando[1]=GET_PUBLIC_KEY;
            comando[2]=0x00;
            comando[3]=0x00;
            comando[4]=0x00;
            comando[5]=0x00;
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(new CommandAPDU(comando));
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"get_public_key");
            if (r.getSW()==0x9000){
                longitudEx=r.getData()[data_pos]*0xff+r.getData()[data_pos+1];
                data_pos=data_pos+2;
                longitudMod=r.getData()[data_pos]*0xff+r.getData()[data_pos+1];
                data_pos=data_pos+2;
                exponente=new byte[longitudEx];
                modulo=new byte[longitudMod];
                for (int i=0;i<longitudEx;i++){
                    exponente[i]=r.getData()[data_pos];
                    data_pos++;
                }
                for (int i=0;i<longitudMod;i++){
                    modulo[i]=r.getData()[data_pos];
                    data_pos++;
                }
                RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(modulo),new BigInteger(exponente));
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PublicKeyClient = factory.generatePublic(spec);
            }
            respuesta=r.getSW();
            return respuesta;
        }
        public int put_broker_public_key(RSAPublicKey brokerPublicKey) throws Exception{
            int respuesta;
            byte exponente[];
            byte modulo[];
            byte datos[];
            int longitud_modulo=0;
            int posicion_datos;
            exponente=brokerPublicKey.getPublicExponent().toByteArray();
            modulo=brokerPublicKey.getModulus().toByteArray();
            //a veces al sacar el modulo sale un byte de mas con un 0 por la conversion de BigInteger a byte[], asi que si el  primer byte es 0 lo quitamos. 
            if (modulo[0]==0x00){
                for (int i=0;i<modulo.length-1;i++){
                    modulo[i]=modulo[i+1];
                }
                datos=new byte[exponente.length+modulo.length+3];
                modulo[modulo.length-1]=0x00;
                longitud_modulo=modulo.length-1;
            }else{
                datos=new byte[exponente.length+modulo.length+4];
                longitud_modulo=modulo.length;
            }
            datos[0] = (byte) (exponente.length >> 8);
            datos[1] = (byte) (exponente.length & 0xFF);
            datos[2] = (byte) (longitud_modulo >> 8);
            datos[3] = (byte) (longitud_modulo & 0xFF);
            posicion_datos=4;
            for (int i=0;i<exponente.length;i++){
                datos[posicion_datos]=exponente[i];
                posicion_datos++;
            }
            for (int i=0;i<longitud_modulo;i++){
                datos[posicion_datos]=modulo[i];
                posicion_datos++;
            }
            CommandAPDU comandoapdu=new CommandAPDU(CLA,PUT_PUBLIC_KEY_BROKER,0x00,0x00,datos);
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(comandoapdu);
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"put_broker_public_key");
            
            respuesta=r.getSW();
            return respuesta;
        }
        public int put_uid(String _UID) throws Exception{
            int respuesta=0;
            if (_UID.length()!=LONG_UID){
                respuesta=FAULT_LONG_UID;
            }else{
                byte UIDByte[];
                UIDByte=_UID.getBytes();
               
                inicio=System.currentTimeMillis();
                ResponseAPDU r = channel.transmit(new CommandAPDU(CLA,PUT_UID,0x00,0x00,UIDByte));
                fin=System.currentTimeMillis();
                tiempo = (double) ((fin - inicio));
                escribe_tiempo(tiempo,"put_uid");
                respuesta=r.getSW();
            }
            return respuesta;
        }
        public int get_UID() throws Exception{
            int respuesta=0;
            
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(new CommandAPDU(CLA,GET_UID,0x00,0x00,0x08));
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"get_UID");
            if (r.getSW()==0x9000){
                byte UIDBytes[]=new byte[8];
                System.arraycopy(r.getData(), 0, UIDBytes, 0, 8);
                UID=new String(UIDBytes);
            }
            respuesta=r.getSW();
            return respuesta;
        }
        public byte[] create_auth_step1() throws Exception{
            byte comando[]=new byte[4];            
            comando[0]=CLA;
            comando[1]=CREATE_AUTH_STEP1;
            comando[2]=0x00;
            comando[3]=0x00;
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(new CommandAPDU(comando));  
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"create_auth_step1");
                    byte[] quitame=new byte[4];
                    quitame=Dame_RN1();
                    System.out.println(String.format("RN1: 0x%08X 0x%08X 0x%08X 0x%08X", quitame[0],quitame[1],quitame[2],quitame[3]));
            return r.getBytes();
        }
        public int check_auth_step2(byte[] datos) throws Exception{
            int respuesta=0;
            CommandAPDU commandapdu=new CommandAPDU(CLA,CHECK_AUTH_STEP2,0x00,0x00,datos);
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(commandapdu);
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"check_auth_step2");

            respuesta=r.getSW();
            return respuesta;
        }
        public byte[] create_auth_step3() throws Exception{
            byte comando[]=new byte[4];            
            comando[0]=CLA;
            comando[1]=CREATE_AUTH_STEP3;
            comando[2]=0x00;
            comando[3]=0x00;
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(new CommandAPDU(comando));   
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"create_auth_step3");
                     
            return r.getData();
        }
        public byte[] create_msg_publish(byte[] datos) throws Exception{
            //int respuestaint;
            
            
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(new CommandAPDU(CLA,CREATE_MSG_PUBLISH,0x00,0x00,datos));
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"create_msg_publish");

            return r.getData();
            
        }   
        public int check_pubrel(byte[] datos) throws Exception{            
            int respuesta;
            ResponseAPDU r;
            inicio=System.currentTimeMillis();
            r = channel.transmit(new CommandAPDU(CLA,CHECK_PUBREL,0x00,0x00,datos));
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"check_pubrel");            
            respuesta=r.getSW();
            return respuesta;
        }
        public byte[] read_payload(byte[] datos) throws Exception{
            //int respuestaint;
            byte[] respuesta;
             inicio=System.currentTimeMillis();
            CommandAPDU commandapdu=new CommandAPDU(CLA,READ_PAYLOAD,0x00,0x00,datos);
            ResponseAPDU r = channel.transmit(commandapdu);
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"read_payload");              
            if (r.getSW()!=0x9000){
                respuesta=String.format("Fallo 0x%08X", r.getSW()).getBytes();
            }else{
                respuesta=r.getData();
            }
            return respuesta;
        }   
        public byte[] create_pubrel() throws Exception{
            byte comando[]=new byte[4];            
            comando[0]=CLA;
            comando[1]=CREATE_PUBREL;
            comando[2]=0x00;
            comando[3]=0x00;
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(new CommandAPDU(comando));        
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"create_pubrel");     
                
            return r.getData(); 
        }
        public int InitCiphers() throws Exception{
            int respuesta=0;
            byte comando[]=new byte[4];            
            comando[0]=CLA;
            comando[1]=INIT_CIPHERS;
            comando[2]=0x00;
            comando[3]=0x00;
            inicio=System.currentTimeMillis();
            ResponseAPDU r = channel.transmit(new CommandAPDU(comando));    
            fin=System.currentTimeMillis();
            tiempo = (double) ((fin - inicio));
            escribe_tiempo(tiempo,"InitCiphers");    
            
            respuesta=r.getSW();
            return respuesta;
        }
        public byte[] Dame_Memoria() throws Exception{
            ResponseAPDU r = channel.transmit(new CommandAPDU(CLA,DAME_MEMORIA,0x00,0x00,0x08));
            return r.getData();
        }
         public byte[] Dame_RN1() throws Exception{
            ResponseAPDU r = channel.transmit(new CommandAPDU(CLA,DAME_RN1,0x00,0x00,0x20));
            return r.getData();
        }
        private void escribe_tiempo(double tiempo, String funcion){
             System.out.println(funcion + " " + tiempo + " milisegundos");
             try{                
                writer.write(funcion + ";" + tiempo +";\r\n");
                byte[] memoriabyte=new byte[8];                
                memoriabyte=Dame_Memoria();
                long memoria=0;
                memoria=java.lang.Byte.toUnsignedInt(memoriabyte[0])*0x100+java.lang.Byte.toUnsignedInt(memoriabyte[1]);
                System.out.print("M Reset: "+memoria);
                memoria=java.lang.Byte.toUnsignedInt(memoriabyte[2])*0x100+java.lang.Byte.toUnsignedInt(memoriabyte[3]);
                System.out.print(" M Deselect: "+memoria);
                memoria=java.lang.Byte.toUnsignedInt(memoriabyte[4])*0x1000000+java.lang.Byte.toUnsignedInt(memoriabyte[5])*0x10000+
                        java.lang.Byte.toUnsignedInt(memoriabyte[6])*0x100+java.lang.Byte.toUnsignedInt(memoriabyte[7]);
                System.out.println(" M Persistent: "+memoria);

             }catch(IOException ex){
                 System.out.println(ex.getMessage());
             }catch(Exception ex){
                 System.out.println(ex.getMessage());
             }
         }
        public void close(){
            try{
                writer.close();
             }catch(IOException ex){
                 System.out.println(ex.getMessage());
             }
         }
           
}
