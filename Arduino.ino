#include <Curve25519.h>
#include <SPI.h>                // needed for Arduino versions later than 0018
#include <Ethernet.h>
#include <EthernetUdp.h>        // UDP library from: bjoern@cs.stanford.edu 12/30/2008
#include <AES.h>
#include <Crypto.h>
#include <SHA3.h>

AES256 myAES256;

SHA3_256 mySHA3;

// Enter a MAC address for your controller below.
// The IP address will be dependent on your local network:
byte mac[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};

unsigned int localPort = 8888;      // local port to listen on

// buffers for receiving and sending data
char  packetBuffer[200];  //buffer to hold incoming packet

// An EthernetUDP instance to let us send and receive packets over UDP
EthernetUDP Udp;

void clear_udp_buffer()
{
  for(int i=0;i<200;i++) packetBuffer[i] = 0;
}

uint8_t private_key[32] = { 0 }
,       public_key[32]  = { 0 }
,       shared_key[32]  = { 0 } //this will also hold the server public key
;

char char_key[64] = { 0 }
,    char_public[64] = { 0 }
;

void setup() {
  Serial.begin(9600);

  //Perform the first half of ECDH, creating the public and private keys
  Curve25519::dh1(public_key, private_key);
 
  // start the Ethernet connection:
  if (Ethernet.begin(mac) == 0) 
  {
    Serial.println("Failed to configure Ethernet using DHCP");
    // no point in carrying on, so do nothing forevermore:
    for (;;)
      ;
  }
  Udp.begin(localPort);
  IPAddress gateway(192 , 168, 100, 93 );

  //Send the JoinReq via UDP
  Udp.beginPacket(gateway, 40001);
  Udp.write("Join");
  Udp.endPacket();
   
}

bool joined = false;

void loop() {
  uint8_t block[16] = "1234567890123456"
  ,       blockOutput[16] = "0000000000000000"
  ,       blockDecryptOutput[16] = "0000000000000000"
  ;

  
  // if there's data available, read a packet
  int packetSize = Udp.parsePacket();
  if (packetSize) {
    Serial.print("Received packet of size ");
    Serial.println(packetSize);
    Serial.print("From ");
    IPAddress remote = Udp.remoteIP();

    Serial.print(", port ");
    Serial.println(Udp.remotePort());

    // read the packet into packetBufffer
    Udp.read(packetBuffer, 200);
    Serial.println("Contents:");
    Serial.println(packetBuffer);
    String msg, string_msg;
    msg[0] = '\0';    
    msg = String(packetBuffer);
    char aux[2];
    
    if(msg[0] == 'P' && msg[1] == 'K'){
       //Message received is the public key of gateway
       clear_udp_buffer();
       msg.remove(0,2);
       msg.toCharArray(char_public, 65);
       Serial.println(char_public);
      
       for(int i = 0; i < 64; i+=2)
       {
         aux[0] = char_public[i];
         aux[1] = char_public[i+1];
         sscanf(aux, "%02x", &shared_key[i/2]);    
       }

       //Perform the second half of ECDH, generating the shared key
       Curve25519::dh2(shared_key, private_key);

       //Calculates hash of shared key
       mySHA3.reset();
       mySHA3.update(shared_key, 32);
       mySHA3.finalize(shared_key, 32);

       if (!myAES256.setKey(shared_key , 32))
         Serial.println("Falha no setKey");
       
       char_key[64] = '\0';

       //Send our public key to gateway
       Udp.beginPacket(Udp.remoteIP(), Udp.remotePort());
       Udp.write(char_key);
       Udp.endPacket();
    }else if (msg == "send")
    {
      //Received "send" in UDP, send 10 messages encrypted using AES256 for testing
      char outputMessage[32];
      for (int i = 0; i < 10; i++)
      {
        myAES256.encryptBlock(blockOutput, block);
        Udp.beginPacket(Udp.remoteIP(), Udp.remotePort());
        for (int j = 0; j < 16; j++){
          sprintf(&outputMessage[j*2], "%02x", blockOutput[j]);
        }
        outputMessage[32] = '\0';
        Serial.println(outputMessage);
        Udp.write(outputMessage);
        Udp.endPacket();
      }
      
    }
    else{
       Serial.println("Nothing to do");
    }


      // clear buffer
    clear_udp_buffer();
  }

  Ethernet.maintain();

}