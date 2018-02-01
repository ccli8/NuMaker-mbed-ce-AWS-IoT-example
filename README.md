# Example for Connection with AWS IoT thru MQTT/HTTPS on Mbed OS

This is an example to demonstrate connection with [AWS IoT](https://aws.amazon.com/iot)
on Nuvoton Mbed-enabled boards.

## Supported platforms
On Mbed OS, connection with AWS IoT requires Mbed TLS. It requires more than 64 KB RAM.
Currently, the following Nuvoton Mbed-enalbed boards can afford such memory footprint:
- [NuMaker-PFM-NUC472](https://developer.mbed.org/platforms/Nuvoton-NUC472/)
- [NuMaker-PFM-M487](https://developer.mbed.org/platforms/NUMAKER-PFM-M487/)

## Access and manage AWS IoT Service
To run the example, you need to register one [AWS account](https://aws.amazon.com/)
to access and manage AWS IoT Service for your device to connect with.
This [link](https://docs.aws.amazon.com/iot/latest/developerguide/what-is-aws-iot.html) gives detailed
information about it.

1. Sign in to [AWS Management Console](https://aws.amazon.com/console/).
1. Enter AWS IoT Service.
1. In AWS IoT Service, create a thing.
The Console may prompt you to also create a certificate and a policy. Skip for creating them later.
1. In AWS IoT Service, create a policy. A workable example would be below.
Note that you need to replace **REGION** and **ACCOUNT** to match your case.

    <pre>
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iot:Connect",
                "Resource": "arn:aws:iot:<b>REGION</b>:<b>ACCOUNT</b>:client/*"
            },
            {
                "Effect": "Allow",
                "Action": "iot:Subscribe",
                "Resource": ["arn:aws:iot:<b>REGION</b>:<b>ACCOUNT</b>:topicfilter/*"]
            },
            {
                "Effect": "Allow",
                "Action": ["iot:Publish", "iot:Receive"],
                "Resource": "arn:aws:iot:<b>REGION</b>:<b>ACCOUNT</b>:topic/*"
            },
            {
                "Effect": "Allow",
                "Action": ["iot:UpdateThingShadow", "iot:GetThingShadow", "iot:DeleteThingShadow"],
                "Resource": "arn:aws:iot:<b>REGION</b>:<b>ACCOUNT</b>:thing/*"
            }
        ]
    }
    </pre>

1. In AWS IoT Service, create a certificate. You would get 4 security credential files from it.
   Download them for later use.
   - AWS IoT's CA certificate
   - User certificate
   - User private key
   - User public key
   
   After creating the certificate, do:
   1. Activate the certificate
   1. Attach the thing created above to the certificate
   1. Attach the policy created above to the certificate

## Configure your device with AWS IoT
Before connecting your device with AWS IoT, you need to configure security credential and
protocol dependent parameters into your device. These configurations are all centralized in `main.cpp`.

### Configure certificate into your device
From above, you've got 4 security credential files: CA certificate and user certificate/private key/public key.
Configure CA certificate, user certificate, and user private key into your device.
User public key has been included in user certificate and is not used here.
1. Replace CA certificate with downloaded from the Console.
    ```
    const char SSL_CA_CERT_PEM[] = "-----BEGIN CERTIFICATE-----\n"
        "MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\n"
        "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n"
    ```

1. Replace user certificate with downloaded from the Console.
    ```
    const char SSL_USER_CERT_PEM[] = "-----BEGIN CERTIFICATE-----\n"
        "MIIDWjCCAkKgAwIBAgIVALN/H7tr8cgpl2zwg0JjEE106XilMA0GCSqGSIb3DQEB\n"
        "CwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\n"
    ```

1. Replace user private key with downloaded from the Console.
    ```
    const char SSL_USER_PRIV_KEY_PEM[] = "-----BEGIN RSA PRIVATE KEY-----\n"
    ```

**NOTE:** The credential hard-coded in source code is deactivated or deleted.
          Use your own credential for connection with AWS IoT.

### Connect through MQTT
To connect your device with AWS IoT through MQTT, you need to configure the following parameters.

1. Enable connection through MQTT.
    ```
    #define AWS_IOT_MQTT_TEST       1
    ```

1. Replace server name (endpoint). **Endpoint** has the following format and you just 
   need to modify **IDENTIFIER** and **REGION** to match your case.
    <pre>
    #define AWS_IOT_MQTT_SERVER_NAME                "<b>IDENTIFIER</b>.iot.<b>REGION</b>.amazonaws.com"
    </pre>
   
1. Server port number is fixed. Don't change it.
    ```
    #define AWS_IOT_MQTT_SERVER_PORT                8883
    ```
    
1. Replace **THINGNAME** to match your case. The **THINGNAME** is just the name of the thing you've created above.
    <pre>
    #define AWS_IOT_MQTT_THINGNAME                  "<b>THINGNAME</b>"
    </pre>
    
1. Replace **CLIENTNAME** to match your case. If you adopt the example policy above,
   you can modify it arbitrarily because the policy permits any client name bound to your account.
    <pre>
    #define AWS_IOT_MQTT_CLIENTNAME                 "<b>CLIENTNAME</b>"
    </pre>

AWS IoT MQTT protocol supports topic subscribe/publish. The example demonstrates:
- Subscribe/publish with user topic
- Subscribe/publish with reserved topic (starting with $) to:
    - Update thing shadow
    - Get thing shadow
    - Delete thing shadow

### Connect through HTTPS
To connect your device with AWS IoT through HTTPS, you need to configure the following parameters.

1. Enable connection through HTTPS.
    ```
    #define AWS_IOT_HTTPS_TEST      1
    ```

1. Replace server name (endpoint). **Endpoint** has the following format and you just 
   need to modify **IDENTIFIER** and **REGION** to match your case.
    <pre>
    #define AWS_IOT_HTTPS_SERVER_NAME               "<b>IDENTIFIER</b>.iot.<b>REGION</b>.amazonaws.com"
    </pre>
   
1. Server port number is fixed. Don't change it.
    ```
    #define AWS_IOT_HTTPS_SERVER_PORT               8443
    ```
    
1. Replace **THINGNAME** to match your case. The **THINGNAME** is just the name of the thing you've created above.
    <pre>
    #define AWS_IOT_HTTPS_THINGNAME                 "<b>THINGNAME</b>"
    </pre>

AWS IoT HTTPS protocol supports topic publish-only and RESTful API. The example demonstrates:
- Publish to user topic
- Publish to reserved topic (starting with $) to:
    - Update thing shadow
    - Get thing shadow
    - Delete thing shadow
- RESTful API to:
    - Update thing shadow RESTfully through HTTPS/POST method
    - Get thing shadow RESTfully through HTTPS/GET method
    - Delete thing shadow RESTfully through HTTPS/DELETE method

## Patch MQTT library
Currently, MQTT library has one issue with unsubscribe from topic multiple times. Fix it:

In `MQTT/MQTTClient.h` > `MQTT::Client<Network, Timer, MAX_MQTT_PACKET_SIZE, b>::cycle`,
<pre>
switch (packet_type)
    {
        default:
            // no more data to read, unrecoverable. Or read packet fails due to unexpected network error
            rc = packet_type;
            goto exit;
        case 0: // timed out reading packet
            break;
        case CONNACK:
        case PUBACK:
        case SUBACK:
        <b>
        case UNSUBACK:
        </b>
            break;
        case PUBLISH:
        {
</pre>

## Monitor the application
If you configure your terminal program with **9600/8-N-1**, you would see output similar to:

**NOTE:** Make sure that the network is functional before running the application.

<pre>
Starting AWS IoT test
Using Mbed OS 5.7.1
[EasyConnect] IPv4 mode
Connecting with a1fbcwaqfqeozo.iot.us-east-1.amazonaws.com:8883
Connecting to a1fbcwaqfqeozo.iot.us-east-1.amazonaws.com:8883
</pre>

If you get here successfully, it means configurations with security credential are correct.
<pre>
Starting the TLS handshake...
TLS connection to a1fbcwaqfqeozo.iot.us-east-1.amazonaws.com:8883 established
Server certificate:
    cert. version     : 3
    serial number     : 3C:AC:B3:D3:3E:D8:6A:C9:2B:EF:D2:C5:B1:DC:BF:66
    issuer name       : C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 ECC 256 bit SSL CA - G2
    subject name      : C=US, ST=Washington, L=Seattle, O=Amazon.com, Inc., CN=*.iot.us-east-1.amazonaws.com
    issued  on        : 2017-03-07 00:00:00
    expires on        : 2018-03-08 23:59:59
    signed using      : ECDSA with SHA256
    EC key size       : 256 bits
    basic constraints : CA=false
    subject alt name  : iot.us-east-1.amazonaws.com, *.iot.us-east-1.amazonaws.com
    key usage         : Digital Signature
    ext key usage     : TLS Web Server Authentication, TLS Web Client Authentication
Certificate verification passed

Connects with a1fbcwaqfqeozo.iot.us-east-1.amazonaws.com:8883 OK
</pre>

MQTT handshake goes:
<pre>
MQTT connects OK

Subscribing/publishing user topic
MQTT subscribes to Nuvoton/Mbed/+ OK
Message to publish:
{ "message": "Hello from Nuvoton Mbed device" }
MQTT publishes message to Nuvoton/Mbed/D001 OK
Message arrived: qos 1, retained 0, dup 0, packetid 1
Payload:
{ "message": "Hello from Nuvoton Mbed device" }

MQTT unsubscribes from Nuvoton/Mbed/+ OK
Subscribes/publishes user topic OK

Subscribing/publishing UpdateThingShadow topic
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/update/accepted OK
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/update/rejected OK
Message to publish:
{ "state": { "reported": { "attribute1": 3, "attribute2": "1" } } }
MQTT publishes message to $aws/things/Nuvoton-Mbed-D001/shadow/update OK
Message arrived: qos 1, retained 0, dup 0, packetid 1
Payload:
{"state":{"reported":{"attribute1":3,"attribute2":"1"}},"metadata":{"reported":{"attribute1":{"timestamp":1514962195},"attribute2":{"timestamp":1514962195}}},"version":77,"timestamp":1514962195}

MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/update/accepted OK
MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/update/rejected OK
Subscribes/publishes UpdateThingShadow topic OK

Subscribing/publishing GetThingShadow topic
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/get/accepted OK
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/get/rejected OK
Message to publish:

MQTT publishes message to $aws/things/Nuvoton-Mbed-D001/shadow/get OK
Message arrived: qos 1, retained 0, dup 0, packetid 1
Payload:
{"state":{"reported":{"attribute1":3,"attribute2":"1"}},"metadata":{"reported":{"attribute1":{"timestamp":1514962195},"attribute2":{"timestamp":1514962195}}},"version":77,"timestamp":1514962198}

MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/get/accepted OK
MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/get/rejected OK
Subscribes/publishes GetThingShadow topic OK

Subscribing/publishing DeleteThingShadow topic
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/delete/accepted OK
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/delete/rejected OK
Message to publish:

MQTT publishes message to $aws/things/Nuvoton-Mbed-D001/shadow/delete OK
Message arrived: qos 1, retained 0, dup 0, packetid 1
Payload:
{"version":77,"timestamp":1514962202}

MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/delete/accepted OK
MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/delete/rejected OK
Subscribes/publishes DeleteThingShadow topic OK

MQTT disconnects OK
</pre>

Dynamic memory footprint (heap) is output below.
Static memory footprint (global/stack) could be obtained by inspecting MAP file.
You could get total memory footprint by adding these two together.
<pre>
Current heap size: 1351
Max heap size: 63022
</pre>

## Trouble-shooting
- Over ESP8266 WiFi,
  if you make a loop test like below (`main.cpp`), you may always meet errors in the following loops
  after some network error has happened in the previous one.
    <pre>
    <b>while (true) {</b>
        #if AWS_IOT_MQTT_TEST
            AWS_IoT_MQTT_Test *mqtt_test = new AWS_IoT_MQTT_Test(AWS_IOT_MQTT_SERVER_NAME, AWS_IOT_MQTT_SERVER_PORT, network);
            mqtt_test->start_test();
            delete mqtt_test;
        #endif  // End of AWS_IOT_MQTT_TEST
    
        #if AWS_IOT_HTTPS_TEST
            AWS_IoT_HTTPS_Test *https_test = new AWS_IoT_HTTPS_Test(AWS_IOT_HTTPS_SERVER_NAME, AWS_IOT_HTTPS_SERVER_PORT, network);
            https_test->start_test();
            delete https_test;
        #endif  // End of AWS_IOT_HTTPS_TEST
    <b>}</b>
    </pre>
    This issue would be caused by failure of ESP8266 AT commands **CLOSE**/**DISCONNECT**
    because ESP8266 F/W is still busy in handling previous unfinished network transfer
    due to bad network status and fails these commands.
    These commands must be OK for ESP8266 F/W to reset connection state correctly.
    If that happens, try enlarging [ESP8266 driver's](https://github.com/ARMmbed/esp8266-driver) timeout configuration.
    For example, enlarge `ESP8266_SEND_TIMEOUT`/`ESP8266_RECV_TIMEOUT`/`ESP8266_MISC_TIMEOUT` (defined in
    [ESP8266Interface.cpp](https://github.com/ARMmbed/esp8266-driver/blob/master/ESP8266Interface.cpp))
    to 5000/5000/5000 ms respectively (through `mbed_app.json`).
    <pre>
    {
        "macros": [
            "MBED_CONF_APP_MAIN_STACK_SIZE=4096",
            "MBEDTLS_USER_CONFIG_FILE=\"mbedtls_user_config.h\"",
            "MBED_HEAP_STATS_ENABLED=1",
            "MBED_MEM_TRACING_ENABLED=1",
            <b>"ESP8266_SEND_TIMEOUT=5000",</b>
            <b>"ESP8266_RECV_TIMEOUT=5000",</b>
            <b>"ESP8266_MISC_TIMEOUT=5000"</b>
        ],
        "config": {
    </pre>