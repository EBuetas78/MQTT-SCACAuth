# MQTT-SCACAuth
 Security Method for MQTT with Smart Card
 
The Message Queuing Telemetry Transport (MQTT) protocol is one of the most extended protocols on the Internet of Things (IoT). However, this protocol does not implement a security scheme by default, which does not allow a secure authentication mechanism between participants in the communication. Furthermore, we cannot trust the confidentiality and integrity of data.  
More and more sensible data are sent through lightweight IoT devices, in areas of Smart Building, Smart City, Smart House, Smart Car, Connected Car, Health Care, Smart Retail, Industrial IoT (IIoT), etc. This makes the security challenge in the protocols used in IoT are increasingly important. 
The standard of MQTT protocol strongly recommends implement it over Transport Layer Security (TLS) instead of plain TCP. Nonetheless, this option is not possible in most lightweight devices that make up the IoT ecosystem. 
Very often, the constrained resources of IoT devices prevent the use of secure asymmetric cryptography algorithms by themselves. 
In this repository, we propose making a security schema for MQTT protocol by using Cryptographic Smart Cards, for both challenges, the authentication schema and being able to trust in the confidentiality and integrity of data. We carry out this security schema without modifying some of the standard messages of the protocol. We present a time study with an implementation model using JavaCard.  


