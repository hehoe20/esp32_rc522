/*
 * RC522 Interfacing with NodeMCU
 * 
 * OBS compile error med Board Manager version 2.6.0 og 2.6.1
 * 
 * Typical pin layout used:
 * ----------------------------------
 *             MFRC522      Node     
 *             Reader/PCD   MCU      
 * Signal      Pin          Pin      
 * ----------------------------------
 * RST/Reset   RST          D1 (GPIO5)       fix RST to GPIO02
 * SPI SS      SDA(SS)      D2 (GPIO4)       fix SS pin to GPIO15
 * SPI MOSI    MOSI         D7 (GPIO13)
 * SPI MISO    MISO         D6 (GPIO12)
 * SPI SCK     SCK          D5 (GPIO14)
 * 3.3V        3.3V         3.3V
 * GND         GND          GND
 */
  
#include <stdint.h>
#include <ESP8266WiFi.h>
#include <WiFiClient.h>
#include <ESP8266mDNS.h>
#include <SPI.h>
#include <Hash.h>
#include <WebSocketsServer.h>
#include <MFRC522.h>
#include <FS.h>
#include <ESPAsyncTCP.h>
#include <ESPAsyncWebServer.h>

#define RST_PIN 5 // RST-PIN für RC522 - RFID - SPI
#define SS_PIN 4  // SDA-PIN für RC522 - RFID - SPI

AsyncWebServer server(80); //Initialize the AsyncWebServer on Port 80
WebSocketsServer webSocket = WebSocketsServer(81); //Initialize the webscoket-server on Port 80

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance
MFRC522::StatusCode status;
MFRC522::MIFARE_Key key;

// Number of known default keys (hard-coded)
// NOTE: Synchronize the NR_KNOWN_KEYS define with the defaultKeys[] array
#define NR_KNOWN_KEYS   8
// Known keys, see: https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys
byte knownKeys[NR_KNOWN_KEYS][MFRC522::MF_KEY_SIZE] =  {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF = factory default
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // 00 00 00 00 00 00
};

MDNSResponder mdns;

IPAddress local_IP(192,168,4,1);
IPAddress gateway(192,168,4,9);
IPAddress subnet(255,255,255,0);

// global variables used

static const char PROGMEM INDEX_HTML[] = R"rawliteral( 
<!DOCTYPE html>
<html>
<head>
<title>ESP12f/MRC522 RFID reader/writer by HFH</title>
<style>input[type="text"]{width: 90%; height: 3vh;}input[type="button"]{width: 9%; height: 3.6vh;}.rxd{height: 90vh;}textarea{width: 99%; height: 100%; resize: none;}</style>
<script>
  var Socket;
  function start(){
    Socket=new WebSocket("ws://" + window.location.hostname + ":81/");
    Socket.onmessage=function(evt){
      document.getElementById("rxConsole").value +=evt.data;
      document.getElementById("rxConsole").scrollTop=document.getElementById("rxConsole").scrollHeight;
    }
  }
  function enterpressed(){
    Socket.send(document.getElementById("txbuff").value);
    document.getElementById("txbuff").value="";}
</script>
</head>
<body onload="javascript:start();"> 
<div>
<input class="txd" type="text" id="txbuff" onkeydown="if(event.keyCode==13) enterpressed();" autofocus>
<input class="txd" type="button" onclick="enterpressed();" value="Execute"> 
</div>
<br />
<div class="rxd">
<textarea id="rxConsole" readonly></textarea>
</div>
</body>
</html>)rawliteral";

//String webPage = "<!DOCTYPE html><html><head><title>ESP12f/MRC522 RFID reader/writer by HFH</title><style>input[type=\"text\"]{width: 90%; height: 3vh;}input[type=\"button\"]{width: 9%; height: 3.6vh;}.rxd{height: 90vh;}textarea{width: 99%; height: 100%; resize: none;}</style><script>var Socket;function start(){Socket=new WebSocket('ws://' + window.location.hostname + ':81/'); Socket.onmessage=function(evt){document.getElementById(\"rxConsole\").value +=evt.data;document.getElementById(\"rxConsole\").scrollTop=document.getElementById(\"rxConsole\").scrollHeight;}}function enterpressed(){Socket.send(document.getElementById(\"txbuff\").value); document.getElementById(\"txbuff\").value=\"\";}</script></head><body onload=\"javascript:start();\"> <div><input class=\"txd\" type=\"text\" id=\"txbuff\" onkeydown=\"if(event.keyCode==13) enterpressed();\"><input class=\"txd\" type=\"button\" onclick=\"enterpressed();\" value=\"Execute\" > </div><br><div class=\"rxd\"> <textarea id=\"rxConsole\" readonly></textarea> </div></body></html>";
byte buff[18];
byte block;
byte card[64][16];
byte rwmode = 0;
const byte MaxByteArraySize = 4;
byte newUid[MaxByteArraySize] = {0}; 
//--------------------------------------------------------- 
void dump_byte_array(byte *buff, byte buffSize) {
  for (byte i = 0; i < buffSize; i++) {
    Serial.print(buff[i] < 0x10 ? " 0" : " ");
    Serial.print(buff[i], HEX);
  }
}
//---------------------------------------------------------
void dump_byte_array1(byte *buff, byte buffSize) {
  for (byte i = 0; i < buffSize; i++) {
    Serial.print(buff[i] < 0x10 ? " 0" : " ");
    Serial.write(buff[i]);
  }
}
//---------------------------------------------------------
bool writeentirecard(MFRC522::MIFARE_Key *key)
{
    bool result = false;
    byte errors = 0;

     mfrc522.PCD_Init();       
     mfrc522.PICC_IsNewCardPresent();
     mfrc522.PICC_ReadCardSerial();
    
     for(int i = 4; i <= 62; i++){ // Write block 4 to 62
       if(i == 7 || i == 11 || i == 15 || i == 19 || i == 23 || i == 27 || i == 31 || i == 35 || i == 39 || i == 43 || i == 47 || i == 51 || i == 55 || i == 59){
         i++;
       }

       if (errors>15 ) {
         mfrc522.PICC_HaltA();       // Halt PICC
         mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
         webSocket.broadcastTXT("Too many erros, halting... 5 sec. delay...\n");
         delay(5000);
         return false;
       }
       Serial.print(F("Trying with key:"));
       dump_byte_array((*key).keyByte, MFRC522::MF_KEY_SIZE);
       Serial.println();

       // Authenticate using key A
       Serial.println(F("Authenticating using key A..."));
       status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, i, key, &(mfrc522.uid));
       if (status != MFRC522::STATUS_OK) {
         Serial.print(F("PCD_Authenticate() failed: "));
         Serial.println(mfrc522.GetStatusCodeName(status));
         errors++;
       }

       // Authenticate using key B
       //Serial.println(F("Authenticating again using key B..."));
       //status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, i, key, &(mfrc522.uid));

       //if (status != MFRC522::STATUS_OK) {
       //  Serial.print(F("PCD_Authenticate() failed: "));
       //  Serial.println(mfrc522.GetStatusCodeName(status));
       //  errors++;
       //}

       // Write data to the block
       Serial.print(F("Writing data into block ")); 
       Serial.println(i);

       status = (MFRC522::StatusCode)mfrc522.MIFARE_Write(i, card[i], 16);
       if (status != MFRC522::STATUS_OK) {
         Serial.print(F("MIFARE_Write() failed: "));
         Serial.println(mfrc522.GetStatusCodeName(status));
         errors++;
         mfrc522.PCD_Init();       
         mfrc522.PICC_IsNewCardPresent();
         mfrc522.PICC_ReadCardSerial();
       } else {
         // Successful write
         result = true;
       }
     }
     result = true;
     return result;
}
//---------------------------------------------------------
bool readentirecard(MFRC522::MIFARE_Key *key)
{
    bool result = false;
    
    for(byte block = 0; block < 64; block++){
    // Serial.println(F("Authenticating using key A..."));
    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
    }

    // Read block
    byte byteCount = sizeof(buff);
    status = (MFRC522::StatusCode)mfrc522.MIFARE_Read(block, buff, &byteCount);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
    }
    else {
        // Successful read
        result = true;
        Serial.print(F("Success with key:"));
        dump_byte_array((*key).keyByte, MFRC522::MF_KEY_SIZE);
        Serial.println();
        
        // Dump block data
        Serial.print(F("Block ")); Serial.print(block); Serial.print(F(":"));
//        dump_byte_array1(buff, 16); // convert HEX to ASCII
        dump_byte_array(buff, 16); // convert HEX to ASCII
        Serial.println();
        
        for (int p = 0; p < 16; p++) // Store the 16 bits each block into card array
        {
          card[block][p] = buff[p];
          //Serial.print(card[block][p]);
          //Serial.print(" ");
        }
      }
      //Serial.println();
    }
    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
    return result;
}
//---------------------------------------------------------
byte nibble(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';

  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;

  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;

  return 0;  // Not a valid hexadecimal character
}
//---------------------------------------------------------
void hexCharacterStringToBytes(byte *byteArray, const char *hexString)
{
  bool oddLength = strlen(hexString) & 1;

  byte currentByte = 0;
  byte byteIndex = 0;

  for (byte charIndex = 0; charIndex < strlen(hexString); charIndex++)
  {
    bool oddCharIndex = charIndex & 1;

    if (oddLength)
    {
      // If the length is odd
      if (oddCharIndex)
      {
        // odd characters go in high nibble
        currentByte = nibble(hexString[charIndex]) << 4;
      }
      else
      {
        // Even characters go into low nibble
        currentByte |= nibble(hexString[charIndex]);
        byteArray[byteIndex++] = currentByte;
        currentByte = 0;
      }
    }
    else
    {
      // If the length is even
      if (!oddCharIndex)
      {
        // Odd characters go into the high nibble
        currentByte = nibble(hexString[charIndex]) << 4;
      }
      else
      {
        // Odd characters go into low nibble
        currentByte |= nibble(hexString[charIndex]);
        byteArray[byteIndex++] = currentByte;
        currentByte = 0;
      }
    }
  }
}
//---------------------------------------------------------
String split(String data, char separator, int index)
{
  int found = 0;
  int strIndex[] = {0, -1};
  int maxIndex = data.length()-1;

  for(int i=0; i<=maxIndex && found<=index; i++){
    if(data.charAt(i)==separator || i==maxIndex){
        found++;
        strIndex[0] = strIndex[1]+1;
        strIndex[1] = (i == maxIndex) ? i+1 : i;
    }
  }
  if ( found >0 )
    return found>index ? data.substring(strIndex[0], strIndex[1]) : "";
  else
    return "";
}
//---------------------------------------------------------
void webSocketEvent(uint8_t num, WStype_t type, uint8_t * payload, size_t length){ 
  String cmd = "";
  switch(type) {
    case WStype_DISCONNECTED:
      Serial.printf("[WSc] Disconnected!\n");
    break;
    case WStype_CONNECTED:
      Serial.printf("[WSc] Connected to url: %s\n", payload);
      webSocket.broadcastTXT("Connected via webSocket... Ready...\n");
    break;
    case WStype_TEXT:  
      for(int i = 0; i < length; i++) cmd += ((char) payload[i]); 
      Serial.println("Cmd: "+cmd);     
      if ( split(cmd, ' ',0) == "write" && split(cmd, ' ',1).length()>0 ) {
        digitalWrite(16, LOW);  // Turn the LED on 
        String param = split(cmd, ' ',1);
        char charBuf[param.length()+1];
        param.toCharArray(charBuf, param.length()+1);
        Serial.println(param);  
        hexCharacterStringToBytes(newUid, charBuf);
        dump_byte_array(newUid, MaxByteArraySize);
        Serial.println();
        webSocket.broadcastTXT("Ready to write tag with UID:"+param+"\n");
        rwmode = 1;
      } else if ( split(cmd, ' ',0) == "read" || cmd == "read" ) {
        digitalWrite(16, HIGH);  // Turn the LED off 
        webSocket.broadcastTXT("Ready to read tag\n");
        rwmode = 0;
      } else if ( cmd == "dumpcard" ) {
        digitalWrite(16, HIGH);  // Turn the LED off 
        webSocket.broadcastTXT("DumpCard - read entire card into memory\n");
        rwmode = 2;
      } else if ( cmd == "put2new" ) {
        digitalWrite(16, LOW);  // Turn the LED on
        webSocket.broadcastTXT("Write saved memory to new card\n");
        rwmode = 3;
      } else if ( cmd == "unbrick" ) {
        digitalWrite(16, LOW);  // Turn the LED on
        webSocket.broadcastTXT("Ready to unbrick card\n");
        rwmode = 4;
      } else if ( cmd == "write" ) {
        digitalWrite(16, HIGH);  // Turn the LED off
        rwmode = 0;
        webSocket.broadcastTXT("What to write? - read mode activated\n");
      } else if ( cmd == "help" ) {
        webSocket.broadcastTXT("COMMANDS: read, write [UID], dumpcard {to memory}, put2new {put memory to new card}, reset, unbrick\n");
      } else if ( cmd == "reset" ) {
        rwmode = 0;
        digitalWrite(16, HIGH);  // Turn the LED off
        mfrc522.PCD_Reset();
        mfrc522.PCD_Init();
        webSocket.broadcastTXT("Reader was reset\n");
      } else {
        webSocket.broadcastTXT("Unknown command\n");
      }
    break;
  } 
} 
//--------------------------------------------------------- 
void handleNotFound(AsyncWebServerRequest *request) {
    request->send(404, "text/plain", "Not found");
}
//---------------------------------------------------------
void handleRoot(AsyncWebServerRequest *request) {
  //server.send(200, "text/html", INDEX_HTML);
  //server.send(200, "text/html", webPage);
  request->send_P(200, "text/html", INDEX_HTML);
}
//---------------------------------------------------------
void setup()
{
  ESP.eraseConfig();
  
  digitalWrite(2, LOW);    // Turn the ESP LED on
  digitalWrite(16, HIGH);  // Turn the LED off 
  
  Serial.begin(115200);
  delay(250);

  Serial.println();
  Serial.println(F("Booting...."));

  pinMode(2, OUTPUT);               // Initialize the LED_BUILTIN pin as an output
  pinMode(16, OUTPUT);              // Initialize GPIO2 pin as an output

  Serial.print("Setting soft-AP configuration ... ");
  WiFi.mode(WIFI_AP_STA);
  Serial.println(WiFi.softAPConfig(local_IP, gateway, subnet) ? "Ready" : "Failed!");

  Serial.print("Setting soft-AP ... ");
  Serial.println(WiFi.softAP("CardRW") ? "Ready" : "Failed!");

  Serial.print("Soft-AP IP address = ");
  Serial.println(WiFi.softAPIP());

  server.on("/", handleRoot);
  server.onNotFound(handleNotFound);
  
  Serial.println(F("HTTP server started"));
  server.begin(); // Start the HTTP Server

  Serial.println("Init SPI bus");
  SPI.begin(); // Init SPI bus
  mfrc522.PCD_Init(); // Init MFRC522
  mfrc522.PCD_SetAntennaGain(0x07<<4);
  mfrc522.PCD_DumpVersionToSerial();  // Show details of PCD - MFRC522 Card Reader details

  IPAddress HTTPS_ServerIP= WiFi.softAPIP(); // Obtain the IP of the Server
  Serial.print("Server IP is: "); // Print the IP to the monitor window
  Serial.println(HTTPS_ServerIP);

  if (mdns.begin("cardrw")) 
    Serial.println(F("MDNS responder started"));
  // Add service to MDNS-SD
  mdns.addService("http", "tcp", 80);
  
  Serial.println("Starting websocket");
  webSocket.begin();
  webSocket.onEvent(webSocketEvent);

  Serial.println(F("Ready!"));
  Serial.println(F("======================================================"));
}
//---------------------------------------------------------
void loop() {
 //loop mDNS
 //mdns.update();
 //loop websocket
 webSocket.loop();
 //broadCast serial to websocket
 if (Serial.available() > 0){
   char c[] = {(char)Serial.read()};
   webSocket.broadcastTXT(c, sizeof(c));
 }
 // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle. And if present, select one.
 if ( ! mfrc522.PICC_IsNewCardPresent() || ! mfrc522.PICC_ReadCardSerial() ) {
    delay(5);
 } else {
   if ( rwmode == 0 ) {

     // read UID
     
     webSocket.broadcastTXT("Reading tag\n");
     // Dump debug info about the card; PICC_HaltA() is automatically called
     // mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
     String uid = "";
     for (int i = 0; i < mfrc522.uid.size; i++) {
       // String partial_id_HEX = String(mfrc522.uid.uidByte[i], HEX);
       // Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
       // Serial.print(mfrc522.uid.uidByte[i], HEX);
       uid.concat(String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : ""));
       uid.concat(String(mfrc522.uid.uidByte[i], HEX));
     }
     Serial.print(F("Card UID: "));
     Serial.println(uid);
     webSocket.broadcastTXT("Card UID read: "+uid+"\n");
     mfrc522.PICC_HaltA();
     mfrc522.PCD_StopCrypto1();
   } else if ( rwmode == 1 ) {

     // write UID
    
     webSocket.broadcastTXT("Writing to tag\n");
     // Set new UID
     // byte newUid[] = {0xDA, 0xAA, 0xAA, 0xAAF};

//     if (status != MFRC522::STATUS_OK) {
//       Serial.print(F("PCD_Authenticate() failed: "));
//       Serial.println(mfrc522.GetStatusCodeName(status));
//     }

     byte var = 0;
     while ( ! mfrc522.MIFARE_SetUid(newUid, (byte)4, true) && var < 20) {
        var++;
     }
     //if ( mfrc522.MIFARE_SetUid(newUid, (byte)4, true) ) {
     if( var < 20 ) {
       Serial.println(F("Wrote new UID to card."));
       webSocket.broadcastTXT("Wrote new UID to card.\n");
     } else {
       webSocket.broadcastTXT("Could not write UID to Card\n");
     }
  
     // Halt PICC and re-select it so DumpToSerial doesn't get confused
     mfrc522.PICC_HaltA();
     if ( ! mfrc522.PICC_IsNewCardPresent() || ! mfrc522.PICC_ReadCardSerial() ) {
       return;
     }
  
     // Dump the new memory contents
     //Serial.println(F("New UID and contents:"));
     //mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
  
     // delay(2000);     
     mfrc522.PICC_HaltA();
     mfrc522.PCD_StopCrypto1();
   } else if ( rwmode == 2 ) {

     //Dumpcard - read entire card into memory   
  
     // Show some details of the PICC (that is: the tag/card)
     Serial.print(F("Card UID:"));
     dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
     Serial.println();
     Serial.print(F("PICC type: "));
     MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
     Serial.println(mfrc522.PICC_GetTypeName(piccType));

     for(byte i=0; i<mfrc522.uid.size; i++)
     {
        newUid[i] = mfrc522.uid.uidByte[i];
     }
     // show the Uid saved in memory
     // dump_byte_array(newUid, MaxByteArraySize);
     // Serial.println();
     
     // Try the known default keys
     MFRC522::MIFARE_Key key;
     for (byte k = 0; k < NR_KNOWN_KEYS; k++) {
       // Copy the known key into the MIFARE_Key structure
       for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
         key.keyByte[i] = knownKeys[k][i];
       }
       // Try the key
       if (readentirecard(&key)) {
         // Found and reported on the key and block,
         // no need to try other keys for this PICC
         webSocket.broadcastTXT("Card was read into to memory\n");
         break;
       }
     }
     mfrc522.PICC_HaltA();
     mfrc522.PCD_StopCrypto1();
   } else if ( rwmode == 3 ) {

     //put2new - put memory to new card
    
     // Show some details of the PICC (that is: the tag/card)
     Serial.print(F("Card UID:"));
     dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
     Serial.println();
     Serial.print(F("PICC type: "));
     MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
     Serial.println(mfrc522.PICC_GetTypeName(piccType));

     MFRC522::MIFARE_Key key;
     // Try the known default keys
     //for (byte i = 0; i < 6; i++) {
     //   key.keyByte[i] = 0xFF;
     //}

     for (byte k = 0; k < NR_KNOWN_KEYS; k++) {
       // Copy the known key into the MIFARE_Key structure
       for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
          key.keyByte[i] = knownKeys[k][i];
       }

       // Try the key
       if (writeentirecard(&key)) {
         // Found and reported on the key and block,
         // no need to try other keys for this PICC
         webSocket.broadcastTXT("Card sectors block 4-63 was written\n");
         break;
       }
     }
     
     //byte newUid[] = {0xDE, 0xAD, 0xBE, 0xEF};
     if ( mfrc522.MIFARE_SetUid(newUid, (byte)4, true) ) {
       Serial.println(F("Wrote new UID to card."));
       webSocket.broadcastTXT("Success writing UID...\n");
     } else{
       Serial.println(F("Could not write new UID to card."));
       webSocket.broadcastTXT("Could not write UID/sector 0...\n");
     }
     mfrc522.PICC_HaltA();       // Halt PICC
     mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
     webSocket.broadcastTXT("Finished...\n");
     delay(5000);
   } else if ( rwmode == 4 ) {
     MFRC522::MIFARE_Key key;
     // Prepare key - all keys are set to FFFFFFFFFFFFh at chip delivery from the factory.
     for (byte i = 0; i < 6; i++) {
       key.keyByte[i] = 0xFF;
     }
     if ( mfrc522.MIFARE_UnbrickUidSector(false) ) {
        Serial.println(F("Cleared sector 0, set UID to 1234. Card should be responsive again now."));
        webSocket.broadcastTXT("Cleared sector 0, set UID to 1234. Card should be responsive again now.\n");
     }
     delay(3000);
   } else {
     Serial.println(F("rwmode failed"));
     webSocket.broadcastTXT("rwmode failed\n");
   }
 }
}
