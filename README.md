# MQTT-SCACAuth
 Security Method for MQTT with Smart Card
 
The Message Queuing Telemetry Transport (MQTT) protocol is one of the most extended protocols on the Internet of Things (IoT). However, this protocol does not implement a strong security scheme by default, 
In this repository, we propose making a security schema for MQTT protocol by using Cryptographic Smart Cards, for both challenges, the authentication schema and being able to trust in the confidentiality and integrity of data. We carry out this security schema without modifying some of the standard messages of the protocol. 

SCACAuth_Applets_v2 folder contains the eclipse project for create the applet for JavaCard 3.0.4 used for executing all cryptographic functions necessary to achieve the authentication and encryption method proposed. Is necessary install javacard pluging to complile this project in eclipse. [(plugin eclipse javacard)](https://docs.oracle.com/javacard/3.0.5/guide/eclipse-java-card-plug.htm#JCUGC126).

SCACAuth_com_v2 folder contains the netbeans 8.2 project for test all functions created in the JavaCard with the SCACAuth Applet. 


