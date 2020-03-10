/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/******************
 * argumentos:
 *  -init xxx  iteraciones de inicializaciones
 *  -auth xxx  iteraciones de autentificaciones
 *  -pub xxx iteraciones de publicaciones
 *  -sub xxx iteraciones de subscripciones
 */
package uned.ebs;
import javax.smartcardio.*;
import java.util.List;
import uned.ebs.FuncAuxiliares;
import uned.ebs.CryptClass;
import uned.ebs.SCACAuth_Messages;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
/**
 *
 * @author eduar
 */
public class SCACAuth_com {
    static int inicializaciones=0;
    static int publicaciones=0;
    static int subscripciones=0;
    static int autentificaciones=0;
    
    static String INIT="-init";
    static String AUTH="-auth";
    static String PUB="-pub";
    static String SUB="-sub";
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // show the list of available terminals
        Card card=null;
        SCACAuth_Messages scacauth_messages=null;
        
  
        
        
        //<editor-fold desc="leemos argumentos">
        for (int i=0;i<args.length;i++){
            if (args[i].equals(INIT)){
                i++;
                inicializaciones=Integer.parseInt(args[i]);    
            }
            if (args[i].equals(AUTH)){
                i++;
                autentificaciones=Integer.parseInt(args[i]);                
            }
            if (args[i].equals(PUB)){
                i++;
                publicaciones=Integer.parseInt(args[i]);                
            }
            if (args[i].equals(SUB)){
                i++;
                subscripciones=Integer.parseInt(args[i]);                
            }

        }
        //</editor-fold>
        try{
            //<editor-fold desc="variables">
            CryptClass cryptclass=new CryptClass(2048,"RSA","AES/CBC/NoPadding");
            
            Key PublicBrokerKey;
            Key PublicClientKey;
            PublicBrokerKey=cryptclass.get_Public();
            byte RNpn[]=new byte[SCACAuth_Messages.LONG_RN];
            byte RNsn[]=new byte[SCACAuth_Messages.LONG_RN];
            byte RN1[]=new byte[SCACAuth_Messages.LONG_RN];
            int respuesta=0;
            byte salida[];
            int posicion_salida=0;
            int longitud_encriptada=0;
            byte UIDBytes[]=new byte[SCACAuth_Messages.LONG_UID];
            byte salida_encriptada[];
            byte salida_desencriptada[];
            String UIDComp="";
            byte aEncriptar[];
            byte Encriptado1[];
            byte Encriptado2[];
            byte payload_bytes[];
            byte Datos[];
            byte payload[];
            int longitud_payload=0;
            int posicion_datos=0;
            int posicion_aEncriptar=0;
            int longitud_aEncriptar=0;
            int longitud_salida=0;

            //</editor-fold>
            RNpn=cryptclass.generateRN(RNpn.length);
            RNsn=cryptclass.generateRN(RNsn.length);
            String UIDCliente="CLIENTE1";
            //<editor-fold desc="Creamos la conexion con el lector y creamos el canal con la tarjeta">
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            System.out.println("Terminals: " + terminals);
            // get the first terminal
            CardTerminal terminal = terminals.get(0);
            // establish a connection with the card
            card = terminal.connect("T=1");
            System.out.println("card: " + card);
            CardChannel channel = card.getBasicChannel();
            scacauth_messages=new SCACAuth_Messages(channel);

            for (int j=0;j<inicializaciones;j++){
                //<editor-fold desc="Creamos las claves del broker y del cliente">
                respuesta=scacauth_messages.put_broker_public_key((RSAPublicKey)PublicBrokerKey);                
                if (respuesta!=0x9000){
                    card.disconnect(false);
                    System.out.println(String.format("Put Broker Key Respuesta = 0x%08X",respuesta));
                    System.exit(-1);
                }                
                respuesta=scacauth_messages.create_pair();                
                if (respuesta!=0x9000){
                    card.disconnect(false);
                    System.out.println(String.format("Create Pair Respuesta = 0x%08X",respuesta));
                    System.exit(-1);
                }
                //</editor-fold>
               //<editor-fold desc="inicializamo los ciphers">               
                respuesta=scacauth_messages.InitCiphers();               
                if (respuesta!=0x9000){
                    card.disconnect(false);
                    System.out.println(String.format("Init Ciphers fallo = 0x%08X",respuesta));
                    System.exit(-1);
                }
          
            //</editor-fold>
                //<editor-fold desc="Metemos el UID en la tarjeta">           
                scacauth_messages.put_uid(UIDCliente);           
                if (respuesta!=0x9000){                
                    card.disconnect(false);
                    System.out.println(String.format("Put UID Respuesta = 0x%08X",respuesta));
                    System.exit(-1);
                }           
                //</editor-fold>
            }
            PublicClientKey=scacauth_messages.getPublicKey();    
            for (int j=0;j<autentificaciones;j++){
                //<editor-fold desc="Primer paso de la autentificacion">                
                salida=scacauth_messages.create_auth_step1();                
                //primero sacamos el UID
                posicion_salida=0;
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                    UIDBytes[i]=salida[posicion_salida];
                    posicion_salida++;
                }
                UIDComp=new String(UIDBytes);
                //comparamos el UID
                if (!UIDCliente.equals(UIDComp)){
                    card.disconnect(false);
                    System.out.println("Fallo comparacion UID en paso 1");
                     System.exit(-1);
                }
                longitud_encriptada=salida[posicion_salida]*0x100+salida[posicion_salida+1];
                posicion_salida=posicion_salida+2;
                salida_encriptada=new byte[longitud_encriptada];
                for (int i=0;i<longitud_encriptada;i++){
                    salida_encriptada[i]=salida[posicion_salida];
                    posicion_salida++;
                }
                posicion_salida=0;
                salida_desencriptada=cryptclass.desencriptar(salida_encriptada, PublicClientKey);
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                    UIDBytes[i]=salida_desencriptada[posicion_salida];
                    posicion_salida++;
                }
                UIDComp=new String(UIDBytes);
                //comparamos el UID
                if (!UIDCliente.equals(UIDComp)){
                    card.disconnect(false);
                    System.out.println("Fallo comparacion UID en paso 1 zona encritpada");
                     System.exit(-1);
                }
                //guardamos el RN1
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    RN1[i]=salida_desencriptada[posicion_salida];
                    posicion_salida++;
                }
                //</editor-fold>
                //<editor-fold desc="Segundo paso de la autentificacion">
                //Creamos le primera parte de la encriptacion del paso dos de la autentificacion
                posicion_aEncriptar=0;
                longitud_aEncriptar=SCACAuth_Messages.LONG_UID+SCACAuth_Messages.LONG_RN;
                aEncriptar=new byte[longitud_aEncriptar];
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                    aEncriptar[posicion_aEncriptar]=UIDCliente.getBytes()[i];
                    posicion_aEncriptar++;
                }
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    aEncriptar[posicion_aEncriptar]=RN1[i];
                    posicion_aEncriptar++;
                }
                Encriptado1=cryptclass.encriptar(aEncriptar);
                longitud_aEncriptar=SCACAuth_Messages.LONG_UID+SCACAuth_Messages.LONG_RN*2;
                aEncriptar=new byte[longitud_aEncriptar];
                posicion_aEncriptar=0;
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                    aEncriptar[posicion_aEncriptar]=UIDCliente.getBytes()[i];
                    posicion_aEncriptar++;
                }
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    aEncriptar[posicion_aEncriptar]=RNpn[i];
                    posicion_aEncriptar++;
                }
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    aEncriptar[posicion_aEncriptar]=RNsn[i];
                    posicion_aEncriptar++;
                }
                posicion_datos=0;
                Encriptado2=cryptclass.encriptar(aEncriptar,PublicClientKey);
                Datos=new byte[Encriptado1.length+Encriptado2.length+4];
                Datos[posicion_datos]=(byte)(Encriptado1.length>>8);
                posicion_datos++;
                Datos[posicion_datos]=(byte)(Encriptado1.length & 0xff);
                posicion_datos++;
                for (int i=0;i<Encriptado1.length;i++){
                    Datos[posicion_datos]=Encriptado1[i];
                    posicion_datos++;
                }
                Datos[posicion_datos]=(byte)(Encriptado2.length>>8);
                posicion_datos++;
                Datos[posicion_datos]=(byte)(Encriptado2.length & 0xff);
                posicion_datos++;
                for (int i=0;i<Encriptado2.length;i++){
                    Datos[posicion_datos]=Encriptado2[i];
                    posicion_datos++;
                }
                respuesta=scacauth_messages.check_auth_step2(Datos);
                //byte []prueba;
                //prueba=scacauth_messages.check_auth_step2(Datos);
                if (respuesta!=0x9000){
                    card.disconnect(false);
                    System.out.println(String.format("Fallo check paso 2 authentificacion Respuesta = 0x%08X",respuesta));
                     System.exit(-1);
                }
                //</editor-fold>
                //<editor-fold desc="Tercer paso de la autentificacion">
                salida=scacauth_messages.create_auth_step3();
                //primero sacamos el UID
                posicion_salida=0;
                longitud_encriptada=salida[posicion_salida]*0x100+salida[posicion_salida+1];
                posicion_salida=posicion_salida+2;
                salida_encriptada=new byte[longitud_encriptada];
                for (int i=0;i<longitud_encriptada;i++){
                    salida_encriptada[i]=salida[posicion_salida];
                    posicion_salida++;
                }
                posicion_salida=0;
                salida_desencriptada=cryptclass.desencriptar(salida_encriptada);
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                    UIDBytes[i]=salida_desencriptada[posicion_salida];
                    posicion_salida++;
                }
                UIDComp=new String(UIDBytes);
                //comparamos el UID
                if (!UIDCliente.equals(UIDComp)){
                    card.disconnect(false);
                    System.out.println("Fallo comparacion UID en paso 3 zona encritpada");
                     System.exit(-1);
                }
                //comparamos el RNp
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    if (RNpn[i]!=salida_desencriptada[posicion_salida]){
                        card.disconnect(false);
                        System.out.println("Fallo comparacion RNp en paso 3 zona encritpada");
                        System.exit(-1);
                    }
                    posicion_salida++;
                }
                //comparamos el RNs
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    if (RNsn[i]!=salida_desencriptada[posicion_salida]){
                        System.out.println("Fallo comparacion RNs en paso 3 zona encritpada");
                        System.exit(-1);
                    }
                    posicion_salida++;
                }
                System.out.println("Authentificacion finalizada correctamente");
                //</editor-fold>
            }
            for (int j=0;j<publicaciones;j++){
                //<editor-fold desc="Comunicacion Pub-Broker">            
                salida=scacauth_messages.create_msg_publish("01234567890123456789012345678901234567890123456789".getBytes());
                posicion_salida=0;
                longitud_encriptada=salida[posicion_salida]*0x100+salida[posicion_salida+1];
                posicion_salida=posicion_salida+2;
                salida_encriptada=new byte[longitud_encriptada];
                for (int i=0;i<longitud_encriptada;i++){
                    salida_encriptada[i]=salida[posicion_salida];
                    posicion_salida++;
                }
                posicion_salida=0;
                
                salida_desencriptada=cryptclass.desencriptar_aes(salida_encriptada,RNpn);
                //comparamos UID
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                     if (UIDCliente.getBytes()[i]!=salida_desencriptada[posicion_salida]){
                        System.out.println("Fallo comparacion UID en publish");
                        System.exit(-1);
                    }
                    posicion_salida++;
                }
                //sacamos payload
                longitud_payload=salida_desencriptada[posicion_salida]*0x100+salida_desencriptada[posicion_salida+1];//salida_desencriptada.length-SCACAuth_Messages.LONG_RN-SCACAuth_Messages.LONG_UID;
                posicion_salida=posicion_salida+2;
                payload=new byte[longitud_payload];
                for (int i=0;i<longitud_payload;i++){
                    payload[i]=salida_desencriptada[posicion_salida];
                    posicion_salida++;
                }
                //comparamos el RNpn
                //int j=longitud_salida-SCACAuth_Messages.LONG_RN;
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    if (RNpn[i]!=salida_desencriptada[posicion_salida]){
                        card.disconnect(false);
                        System.out.println("Fallo comparacion RNp en publish");
                        System.exit(-1);
                    }
                    posicion_salida++;
                }
                System.out.println(new String(payload));

/*memoriabyte=scacauth_messages.Dame_Memoria();
memoria=0;
memoria=memoriabyte[0]*0x100+memoriabyte[1];
System.out.print("M Reset: "+memoria);
memoria=memoriabyte[2]*0x100+memoriabyte[3];
System.out.print(" M Deselect: "+memoria);
memoria=memoriabyte[4]*0x100+memoriabyte[5];
System.out.println(" M Persistent: "+memoria);
*/
                //creamos el PUBREL (auth data)
                int longitud=SCACAuth_Messages.LONG_RN*2+SCACAuth_Messages.LONG_UID;
                int resto=longitud %16;
                if (resto!=0){
                    longitud=longitud+(16-resto);
                }
                aEncriptar=new byte[longitud];
                posicion_aEncriptar=0;
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                    aEncriptar[posicion_aEncriptar]=UIDCliente.getBytes()[i];
                    posicion_aEncriptar++;
                }
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    aEncriptar[posicion_aEncriptar]=RNpn[i];
                    posicion_aEncriptar++;
                }
                //generamos el nuevo RNpn
                byte clave_aes[]=new byte[SCACAuth_Messages.LONG_RN];
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    clave_aes[i]=RNpn[i];
                }
                
                RNpn=cryptclass.generateRN(RNpn.length);
                //ponemos en luevo RNpn+1
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    aEncriptar[posicion_aEncriptar]=RNpn[i];
                    posicion_aEncriptar++;
                }
                //lo encriptamos todo en la clave publica del cliente
                Encriptado1=cryptclass.encriptar_aes(aEncriptar, clave_aes);
                //metemos la salida en datos con su longitud
                posicion_datos=0;
                Datos=new byte[Encriptado1.length+2];
                Datos[posicion_datos]=(byte)(Encriptado1.length>>8);
                posicion_datos++;
                Datos[posicion_datos]=(byte)(Encriptado1.length & 0xFF);
                posicion_datos++;
                for (int i=0;i<Encriptado1.length;i++){
                    Datos[posicion_datos]=Encriptado1[i];
                    posicion_datos++;
                }
                //ahora checkeamos el pubrel
                respuesta=scacauth_messages.check_pubrel(Datos);

/*memoriabyte=scacauth_messages.Dame_Memoria();
memoria=0;
memoria=memoriabyte[0]*0x100+memoriabyte[1];
System.out.print("M Reset: "+memoria);
memoria=memoriabyte[2]*0x100+memoriabyte[3];
System.out.print(" M Deselect: "+memoria);
memoria=memoriabyte[4]*0x100+memoriabyte[5];
System.out.println(" M Persistent: "+memoria);*/

                if (respuesta!=0x9000){
                    card.disconnect(false);
                    System.out.println(String.format("Fallo check pubrel = 0x%08X",respuesta));
                     System.exit(-1);
                }
                //</editor-fold>
            }
            for (int j=0;j<subscripciones;j++){
                //<editor-fold desc="Comunicacion Broker-Sub">
                //Creamos el mensaje a enviar
        short longitud_prueba=0xa0;
                String payloadEnviar="01234567890123456789012345678901234567890123456789";
                longitud_aEncriptar=SCACAuth_Messages.LONG_UID+payloadEnviar.length()+2;
                int resto=longitud_aEncriptar %16;
                if (resto!=0){
                    longitud_aEncriptar=longitud_aEncriptar+(16-resto);
                }
                aEncriptar=new byte[longitud_aEncriptar];
                posicion_aEncriptar=0;
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                    aEncriptar[posicion_aEncriptar]=UIDCliente.getBytes()[i];
                    posicion_aEncriptar++;
                }
                aEncriptar[posicion_aEncriptar]=(byte)(payloadEnviar.length()>>8);
                posicion_aEncriptar++;
                aEncriptar[posicion_aEncriptar]=(byte)(payloadEnviar.length() & 0xff);
                posicion_aEncriptar++;
                for (int i=0;i<payloadEnviar.length();i++){
                    aEncriptar[posicion_aEncriptar]=payloadEnviar.getBytes()[i];
                    posicion_aEncriptar++;
                }
                /*for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    aEncriptar[posicion_aEncriptar]=RNsn[i];
                    posicion_aEncriptar++;
                }*/
                Encriptado1=cryptclass.encriptar_aes(aEncriptar, RNsn);
                //comprobamos el mensaje enviado por el broker
                Datos=new byte[(Encriptado1.length)+2];
                posicion_datos=0;
                Datos[posicion_datos]=(byte)(Encriptado1.length>>8);
                posicion_datos++;
                Datos[posicion_datos]=(byte)(Encriptado1.length & 0xFF);
                posicion_datos++;
                for (int i=0;i<Encriptado1.length;i++){
                    Datos[posicion_datos]=Encriptado1[i];
                    posicion_datos++;
                }
                //payload_bytes=new byte[Encriptado1.length+2];            
                payload_bytes=scacauth_messages.read_payload(Datos);
                String payload2=new String(payload_bytes,"UTF-8");
                if (respuesta!=0x9000){
                    card.disconnect(false);
                    System.out.println(String.format("Fallo Read Payload= 0x%08X",respuesta));
                     System.exit(-1);
                }
                System.out.print("El payload enviado es ");
                System.out.println(payload2);
                //creamos el PUBREL desde la javacard
                salida=scacauth_messages.create_pubrel();
                //lo desencriptamos
                posicion_salida=0;
                longitud_salida=salida[posicion_salida]*0x100+salida[posicion_salida+1];
                salida_encriptada=new byte[longitud_salida];
                posicion_salida=posicion_salida+2;
                for (int i=0;i<longitud_salida;i++){
                    salida_encriptada[i]=salida[posicion_salida];
                    posicion_salida++;
                }
                salida_desencriptada=cryptclass.desencriptar(salida_encriptada);
                posicion_salida=0;
                //comparamos el UID
                for (int i=0;i<SCACAuth_Messages.LONG_UID;i++){
                    UIDBytes[i]=salida_desencriptada[posicion_salida];
                    posicion_salida++;
                }
                UIDComp=new String(UIDBytes);
                //comparamos el UID
                if (!UIDCliente.equals(UIDComp)){
                    card.disconnect(false);
                    System.out.println("Fallo comparacion UID en comprobacion pubrel desde el broker");
                    System.exit(-1);
                }
                //comparamos el RNsn
              /*  for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    if (RNsn[i]!=salida_desencriptada[posicion_salida]){

                    card.disconnect(false);
                        System.out.println("Fallo comparacion RNsn en comprobacion pubrel desde el broker");
                        System.exit(-1);
                    }
                    posicion_salida++;
                }*/
                //si todo va bien sustituimos el RNsn por el RNsn+1
                for (int i=0;i<SCACAuth_Messages.LONG_RN;i++){
                    RNsn[i]=salida_desencriptada[posicion_salida];
                    posicion_salida++;
                }
                System.out.println("fin todo ok");

                //</editor-fold>
            }

        }catch(CardException ex){
            System.out.println(ex.getMessage());
        }catch(Exception ex){
            System.out.println(ex.getMessage());
        }finally{
            try{
                card.disconnect(false);
                scacauth_messages.close();
            }catch(Exception ex){
                
            }
        }
    }
    
}



 /* ResponseAPDU r = channel.transmit(new CommandAPDU(FuncAuxiliares.hexStringToByteArray("0084000008")));
            System.out.println("response: " + FuncAuxiliares.byteArrayToHexString(r.getBytes()));
            r = channel.transmit(new CommandAPDU(FuncAuxiliares.hexStringToByteArray("90B8000007")));
            System.out.println("response: " + FuncAuxiliares.byteArrayToHexString(r.getBytes()));*/
            