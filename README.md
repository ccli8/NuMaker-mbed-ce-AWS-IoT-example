# Example for connection with AWS IoT thru MQTTS/HTTPS on Mbed CE enabled boards

This is an example to demonstrate connection with [AWS IoT](https://aws.amazon.com/iot)
on Nuvoton Mbed CE enabled boards.

## Supported platforms
On Mbed OS, connection with AWS IoT requires Mbed TLS. It requires more than 64 KB RAM.
Currently, the following Nuvoton Mbed CE enabled boards can afford such memory footprint:
- [NuMaker-PFM-NUC472](https://www.nuvoton.com/products/iot-solution/iot-platform/numaker-pfm-nuc472/)
- [NuMaker-PFM-M487](https://www.nuvoton.com/products/iot-solution/iot-platform/numaker-pfm-m487/)
- [NuMaker-IoT-M487](https://www.nuvoton.com/products/iot-solution/iot-platform/numaker-iot-m487/)
- [NuMaker-IoT-M467](https://www.nuvoton.com/board/numaker-iot-m467/)
- [NuMaker-M2354](https://www.nuvoton.com/board/numaker-m2354/)
- [NuMaker-IoT-M2354](https://www.nuvoton.com/board/numaker-iot-m2354/)

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
See `configs/awsiot_credentials.c`.

1. Replace CA certificate with downloaded from the Console.
    ```
    const char AWSIOT_ROOTCA_CERT[] = "-----BEGIN CERTIFICATE-----\n"
        "Replace Me"
    ```

1. Replace user certificate with downloaded from the Console.
    ```
    const char AWSIOT_DEVICE_CERT[] = "-----BEGIN CERTIFICATE-----\n"
        "Replace Me"
    ```

1. Replace user private key with downloaded from the Console.
    ```
    const char AWSIOT_DEVICE_PRIVKEY[] = "-----BEGIN RSA PRIVATE KEY-----\n"
        "Replace Me"
    ```

### Connect through MQTTS
To connect your device with AWS IoT through MQTT, you need to configure the following parameters.
See `configs/awsiot_user_config.h`).

1. Enable connection through MQTT.
    ```
    #define AWS_IOT_MQTTS_TEST      1
    ```

1. Replace server name (endpoint). **Endpoint** has the following format and you just 
   need to modify **IDENTIFIER** and **REGION** to match your case.
    <pre>
    #define AWS_IOT_MQTTS_SERVER_NAME               "<b>&lt;IDENTIFIER&gt;</b>.iot.<b>&lt;REGION&gt;</b>.amazonaws.com"
    </pre>
   
1. Server port number is fixed. Don't change it.
    ```
    #define AWS_IOT_MQTTS_SERVER_PORT               8883
    ```
    
1. Replace **THINGNAME** to match your case. The **THINGNAME** is just the name of the thing you've created above.
    <pre>
    #define AWS_IOT_MQTTS_THINGNAME                 "<b>&lt;THINGNAME&gt;</b>"
    </pre>
    
1. Replace **CLIENTNAME** to match your case. If you adopt the example policy above,
   you can modify it arbitrarily because the policy permits any client name bound to your account.
    <pre>
    #define AWS_IOT_MQTTS_CLIENTNAME                "<b>&lt;CLIENTNAME&gt;</b>"
    </pre>

AWS IoT MQTT protocol supports topic subscribe/publish. The example demonstrates:
- Subscribe/publish with user topic
- Subscribe/publish with reserved topic (starting with $) to:
    - Update thing shadow
    - Get thing shadow
    - Delete thing shadow

### Connect through HTTPS
To connect your device with AWS IoT through HTTPS, you need to configure the following parameters.
See `configs/awsiot_user_config.h`).

1. Enable connection through HTTPS.
    ```
    #define AWS_IOT_HTTPS_TEST      1
    ```

1. Replace server name (endpoint). **Endpoint** has the following format and you just 
   need to modify **IDENTIFIER** and **REGION** to match your case.
    <pre>
    #define AWS_IOT_HTTPS_SERVER_NAME               "<b>&lt;IDENTIFIER&gt;</b>.iot.<b>&lt;REGION&gt;</b>.amazonaws.com"
    </pre>
   
1. Server port number is fixed. Don't change it.
    ```
    #define AWS_IOT_HTTPS_SERVER_PORT               8443
    ```
    
1. Replace **THINGNAME** to match your case. The **THINGNAME** is just the name of the thing you've created above.
    <pre>
    #define AWS_IOT_HTTPS_THINGNAME                 "<b>&lt;THINGNAME&gt;</b>"
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

## Developer guide

This section is intended for developers to get started, import the example application, build, and get it running on target board.

In the following, we take NuMaker-IoT-M467 as example board to show this example.

### Hardware requirements

-   NuMaker-IoT-M467 board
-   Host OS: Windows or others

### Hardware setup

-   Switch target board
    -   NuMaker-IoT-M467's Nu-Link2: TX/RX/VCOM to ON, MSG to non-ON
-   Connect target board to host through USB
    -   NuMaker-IoT-M467: Mbed USB drive shows up in File Browser

### Build the example

1.  Clone the example and navigate into it
    ```
    $ git clone https://github.com/mbed-nuvoton/NuMaker-mbed-ce-AWS-IoT-example
    $ cd NuMaker-mbed-ce-AWS-IoT-example
    $ git checkout -f master
    ```

1.  Deploy necessary libraries
    ```
    $ git submodule update --init
    ```
    Or for fast install:
    ```
    $ git submodule update --init --filter=blob:none
    ```

1.  Configure network interface
    -   Ethernet: Need no further configuration.

        **mbed_app.json5**:
        ```json5
        "target.network-default-interface-type" : "Ethernet",
        ```

    -   WiFi: Configure WiFi `SSID`/`PASSWORD`.

        **mbed_app.json5**:
        ```json5
        "target.network-default-interface-type" : "WIFI",
        "nsapi.default-wifi-security"           : "WPA_WPA2",
        "nsapi.default-wifi-ssid"               : "\"SSID\"",
        "nsapi.default-wifi-password"           : "\"PASSWORD\"",
        ```

1.  Compile with cmake/ninja
    ```
    $ mkdir build; cd build
    $ cmake .. -GNinja -DCMAKE_BUILD_TYPE=Develop -DMBED_TARGET=NUMAKER_IOT_M467
    $ ninja
    $ cd ..
    ```

### Flash the image

Just drag-n-drop `NuMaker-mbed-ce-AWS-IoT-example.bin` or `NuMaker-mbed-ce-AWS-IoT-example.hex` onto NuMaker-IoT-M467 board.

## Monitor the application
If you configure your terminal program with **115200/8-N-1**, you would see output similar to:

**NOTE:** Make sure that the network is functional before running the application.

<pre>
Starting AWS IoT test
Using Mbed OS 6.14.0
Connected to the network successfully. IP address: 192.168.8.105
Opening network socket on network stack
Opens network socket on network stack OK
DNS resolution for a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com...
DNS resolution for a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com: 3.129.252.104:8883
</pre>

If you get here successfully, it means configurations with security credential are correct.
<pre>
Connecting with a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com:8883
Connects with a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com:8883 OK
Resolved MQTT client ID: 002E0051-013B87F3-00000021
MQTT connects OK
</pre>

MQTT handshake goes:
<pre>
MQTT connects OK

Subscribing/publishing user topic
MQTT subscribes to Nuvoton/Mbed/+ OK
Message to publish:
{ "message": "Hello from Nuvoton Mbed device" }
MQTT publishes message to Nuvoton/Mbed/D001 OK
MQTT receives message with subscribed Nuvoton/Mbed/D001...
Message arrived: qos 1, retained 0, dup 0, packetid 1
Payload:
{ "message": "Hello from Nuvoton Mbed device" }
MQTT receives message with subscribed Nuvoton/Mbed/D001 OK

MQTT unsubscribes from Nuvoton/Mbed/+ OK
Subscribes/publishes user topic OK

Subscribing/publishing UpdateThingShadow topic
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/update/accepted OK
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/update/rejected OK
Message to publish:
{ "state": { "reported": { "attribute1": 3, "attribute2": "1" } } }
MQTT publishes message to $aws/things/Nuvoton-Mbed-D001/shadow/update OK
MQTT receives message with subscribed $aws/things/Nuvoton-Mbed-D001/shadow/update...
Message arrived: qos 1, retained 0, dup 0, packetid 1
Payload:
{"state":{"reported":{"attribute1":3,"attribute2":"1"}},"metadata":{"reported":{"attribute1":{"timestamp":1630637720},"attribute2":{"timestamp":1630637720}}},"version":229,"timestamp":1630637720}
MQTT receives message with subscribed $aws/things/Nuvoton-Mbed-D001/shadow/update OK

MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/update/accepted OK
MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/update/rejected OK
Subscribes/publishes UpdateThingShadow topic OK

Subscribing/publishing GetThingShadow topic
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/get/accepted OK
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/get/rejected OK
Message to publish:

MQTT publishes message to $aws/things/Nuvoton-Mbed-D001/shadow/get OK
MQTT receives message with subscribed $aws/things/Nuvoton-Mbed-D001/shadow/get...
Message arrived: qos 1, retained 0, dup 0, packetid 1
Payload:
{"state":{"reported":{"attribute1":3,"attribute2":"1"}},"metadata":{"reported":{"attribute1":{"timestamp":1630637720},"attribute2":{"timestamp":1630637720}}},"version":229,"timestamp":1630637722}
MQTT receives message with subscribed $aws/things/Nuvoton-Mbed-D001/shadow/get OK

MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/get/accepted OK
MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/get/rejected OK
Subscribes/publishes GetThingShadow topic OK

Subscribing/publishing DeleteThingShadow topic
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/delete/accepted OK
MQTT subscribes to $aws/things/Nuvoton-Mbed-D001/shadow/delete/rejected OK
Message to publish:

MQTT publishes message to $aws/things/Nuvoton-Mbed-D001/shadow/delete OK
MQTT receives message with subscribed $aws/things/Nuvoton-Mbed-D001/shadow/delete...
Message arrived: qos 1, retained 0, dup 0, packetid 1
Payload:
{"version":229,"timestamp":1630637724}
MQTT receives message with subscribed $aws/things/Nuvoton-Mbed-D001/shadow/delete OK

MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/delete/accepted OK
MQTT unsubscribes from $aws/things/Nuvoton-Mbed-D001/shadow/delete/rejected OK
Subscribes/publishes DeleteThingShadow topic OK

MQTT disconnects OK
</pre>

## Trouble-shooting
-   Reduce memory footprint according to RFC 6066 TLS extension.
    We reduce memory footprint by:
    1. Enabling RFC 6066 max_fragment_length extension by configuing `my-tlssocket.tls-max-frag-len` to 4.

        `my-tlssocket/mbed_lib.json5`:
        ```json5
        {
            "name": "my-tlssocket",
            "config": {
                "tls-max-frag-len": {
                    "help": "Maximum fragment length value for the payload in one packet, doesn't include TLS header and encryption overhead. Is needed for constrained devices having low MTU sizes, Value 0 = disabled, 1 = MBEDTLS_SSL_MAX_FRAG_LEN_512, 2= MBEDTLS_SSL_MAX_FRAG_LEN_1024, 3 = MBEDTLS_SSL_MAX_FRAG_LEN_2048, 4 = MBEDTLS_SSL_MAX_FRAG_LEN_4096",
                    "value": 0
                },
            }
        }
        ```

        `mbed_app.json5`:
        ```json5
        "SOME_TARGET": {
            "my-tlssocket.tls-max-frag-len"         : 4,
        },
        ```

    1. Consistent with above, allocating these buffers with `MBEDTLS_SSL_IN_CONTENT_LEN`/`MBEDTLS_SSL_OUT_CONTENT_LEN` being larger than 4KiB/4KiB.

        `mbedtls_user_config.h`:
        ```C++
        /* Maximum length (in bytes) of incoming plaintext fragments */
        #define MBEDTLS_SSL_IN_CONTENT_LEN      8192 

        /* Maximum length (in bytes) of outgoing plaintext fragments */
        #define MBEDTLS_SSL_OUT_CONTENT_LEN     8192 
        ```

    **NOTE:**: With `my-tlssocket.tls-max-frag-len` being 4, `MBEDTLS_SSL_IN_CONTENT_LEN`/`MBEDTLS_SSL_OUT_CONTENT_LEN` must be larger than 4KiB/4KiB.
    We enlarge them to 8KiB/8KiB because TLS handshake also uses these buffers and may require larger.

    But this approach is risky because:
    1. AWS IoT doesn't support RFC 6066 TLS extension yet.
    1. TLS handshake may need larger I/O buffers than configured.

    If you doubt your trouble is caused by this configuration, disable it by:
    1.  Removing the line `my-tlssocket.tls-max-frag-len` in `mbed_app.json5`.
    1.  Commenting out `MBEDTLS_SSL_IN_CONTENT_LEN`/`MBEDTLS_SSL_OUT_CONTENT_LEN` in `mbedtls_user_config.h`.
        This will change back to 16KiB/16KiB.

-   If the default domain name server (DNS) can't work well, you could add one DNS by mbed API [add_dns_server](https://os.mbed.com/docs/mbed-os/v6.16/apis/dns-apis.html), for example:
    ```C++
    /* Add your DNS server */
    SocketAddress sockaddr;
    sockaddr.set_ip_address("<your-dns-server>");
    net->add_dns_server(sockaddr, NULL);
    ```
