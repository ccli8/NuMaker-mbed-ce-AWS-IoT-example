/* This example demonstrates connection with AWS IoT through MQTT/HTTPS protocol. 
 *
 * AWS IoT: Thing Shadow MQTT Topics 
 * http://docs.aws.amazon.com/iot/latest/developerguide/thing-shadow-mqtt.html
 *
 * AWS IoT: Publish to a topic through HTTPS/POST method:
 * http://docs.aws.amazon.com/iot/latest/developerguide/protocols.html
 *
 * AWS IoT: Thing Shadow RESTful API:
 * http://docs.aws.amazon.com/iot/latest/developerguide/thing-shadow-rest-api.html
 */

#define AWS_IOT_MQTT_TEST       1
#define AWS_IOT_HTTPS_TEST      0

#include "mbed.h"
#include "easy-connect.h"

/* TLSSocket = Mbed TLS over TCPSocket */
#include "TLSSocket.h"

/* Measure memory footprint */
#include "mbed_stats.h"

#if AWS_IOT_MQTT_TEST
/* MQTT-specific header files */
#include "MQTTmbed.h"
#include "MQTTClient.h"
#endif  // End of AWS_IOT_MQTT_TEST


namespace {

/* List of trusted root CA certificates
 * currently only GlobalSign, the CA for os.mbed.com
 *
 * To add more than one root, just concatenate them.
 */
const char SSL_CA_CERT_PEM[] = "-----BEGIN CERTIFICATE-----\n"
    "MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\n"
    "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n"
    "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\n"
    "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\n"
    "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\n"
    "aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\n"
    "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\n"
    "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\n"
    "biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\n"
    "U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\n"
    "aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\n"
    "nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\n"
    "t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\n"
    "SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\n"
    "BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\n"
    "rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\n"
    "NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\n"
    "BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\n"
    "BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\n"
    "aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\n"
    "MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\n"
    "p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\n"
    "5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\n"
    "WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\n"
    "4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\n"
    "hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\n"
    "-----END CERTIFICATE-----\n";

/* User certificate which has been activated and attached with specific thing and policy */
const char SSL_USER_CERT_PEM[] = "-----BEGIN CERTIFICATE-----\n"
    "MIIDWjCCAkKgAwIBAgIVALN/H7tr8cgpl2zwg0JjEE106XilMA0GCSqGSIb3DQEB\n"
    "CwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\n"
    "IEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0xNzEyMTQwOTE3\n"
    "MjdaFw00OTEyMzEyMzU5NTlaMB4xHDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\n"
    "dGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDM/Ebg1vx305GeuQk8\n"
    "UeYr+5IGBEoF6QwY9wjjliQMZKoIQk8eLYZxyjq/i0WRoXy+4l2IOZC0621bahHS\n"
    "2iPC07Uxj1BXBW+f+V0pBnUnnGK0tT3uGOFVOoPUBoiYU9mB/Anv4wXRdqrUNAMW\n"
    "Mq/lAzOvgfyFXnTu0AtvWwISNiAk3ly2E+3PC/Ma9RyMOAjsRUbQo66f2ERmd8yZ\n"
    "PgCXlb/x2kCnjnkau6MS0tg83Ro+QvyQGqBRf3fbYIS8Hz6mIKGffguuelEEoMqP\n"
    "H0beG0GO/T73uUAscbrOWzoVlNmFVt6Ly53s1tm9j/Spldl4EKmMD3vNetkInYDo\n"
    "O55zAgMBAAGjYDBeMB8GA1UdIwQYMBaAFE17U+bgCNXEKf4sP134dtHLiNtcMB0G\n"
    "A1UdDgQWBBSP7arfS0NaGmkNFBTg7SakJy0qEDAMBgNVHRMBAf8EAjAAMA4GA1Ud\n"
    "DwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAW5RDTsZjhlkThMOrrP2XH1Cr\n"
    "9rcoXGqo+jOq5a/yX/LVIM2W/9bIIaOEDScP2haJWceq0C1O6t2JGL0UtNGFyjYS\n"
    "0Z3bCv77MNLhWc8GeIRHWAd65dlEspKO8P7UHNppHhh4/oKYpP2Nu/pvguofgIw6\n"
    "XbKk9PYz4n/ebdhWi6nTBi6Yc3d9aczMh227HcUz7RFoBEhKhOi7IDWzS9X+sqfD\n"
    "fg5NV+A4w6GMTAmLVU8ryodohSTaz34+bElnCdrAnMeSpR8BElTmojSdrA5eY5qZ\n"
    "ib7kkPRPyM3QuqTiMPMyxdVDxkoNtRrJ8zw+l443oKvVsUvDZJbHURUt2d4htA==\n"
    "-----END CERTIFICATE-----\n";

/* User private key paired with above */
const char SSL_USER_PRIV_KEY_PEM[] = "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAzPxG4Nb8d9ORnrkJPFHmK/uSBgRKBekMGPcI45YkDGSqCEJP\n"
    "Hi2Gcco6v4tFkaF8vuJdiDmQtOttW2oR0tojwtO1MY9QVwVvn/ldKQZ1J5xitLU9\n"
    "7hjhVTqD1AaImFPZgfwJ7+MF0Xaq1DQDFjKv5QMzr4H8hV507tALb1sCEjYgJN5c\n"
    "thPtzwvzGvUcjDgI7EVG0KOun9hEZnfMmT4Al5W/8dpAp455GrujEtLYPN0aPkL8\n"
    "kBqgUX9322CEvB8+piChn34LrnpRBKDKjx9G3htBjv0+97lALHG6zls6FZTZhVbe\n"
    "i8ud7NbZvY/0qZXZeBCpjA97zXrZCJ2A6DuecwIDAQABAoIBAEbY7rppM6tKoWrl\n"
    "cy6487/B3E9eDiOKz5aVUyoty1nJNQdTu7qna29KwRFQ1oOl99KVtFQP6VbOg+Zz\n"
    "e6OPp4p/14FAkjjxdQoqiqtSQw2kvGzOs4/mY4MsjUGr3GwhluyZKuoRYgJqbFKZ\n"
    "g3OZozeY6rU/TQLfibS8jSc4ojeehQx3cesJmnYA16iFjN8K/D2Tw+aJiKx+0D8k\n"
    "nbpy19/2MzBW+UhunMpCtfDNx/HLQAYtzxbxczw7yUiQnmyf+0t0/+xm0m04eic1\n"
    "GRHHInZSKzMfGtzyJXliFP5o92dspCm5vsiyXMcPzqcX192IZSixbG8etrJk8jXy\n"
    "bTi85VkCgYEA6hOkrSZjbZvsgtjJCIbjMmn9rpBrG0Bv+V1gJ/dH3hZjo2qUnVB0\n"
    "8PfBZ+oOoNjEWJlS38zf4pwHSBR6WzvH/o35EHvXNCcdKA82jmv0lbbdH2a4y19n\n"
    "lnlyEocsFmPtyuSp+TwIxKI1d+mk9q9D6FgWyLHSddn/qY56txOx7M8CgYEA4C8f\n"
    "6bz4a64KBnIZ7yWwwNkZ3Jn8wI62NiZpPpY5PfKtdYCdBHyuCWApE0e8pZy6fTTN\n"
    "VVH9RJEq3UHxvEPzNOOhlAoRKT3BakmQ+Yw9Dg+xk6XiiCQuJcEnWG+IUFIjsxEK\n"
    "SgSfzrVHtF3udlbP58b3gOSZvxBt8a3qBFPARR0CgYEA08hIAz0rUn1zxIMdiHB6\n"
    "WR+anXke3v4zEVwRZreNt3tsVOtWYOrtkyOmQj17VL4rD7pRSBmWKvJeiDG27pqs\n"
    "/Tw4r1hMwmvtLlRtWPiFx3s2n3WSFrdQAs4IjojsM6nf+OVggBZ4HGhilga38VVr\n"
    "zGj+3EA/Gc/OR/uYPdI89fMCgYAHOz3qSkAxKQIFxzRy9GJJNjeRWB5BD9ls0bxf\n"
    "WnUqPGPAAJAQDv2GK+XnS08YgH+7fjKJaAWlapFZZcEoc4Cq2hTiM5juHaHZjdnx\n"
    "Usa9Z2AxBQ7TmWcrrJlaTu60uJGSOyB71r5Y6pwPg2AnzRETxuVA8R7MfPku7I85\n"
    "6IGxOQKBgHyvFe38EHJndwgTZYK0fWWghRb6XmdH4MxZip2W6yO2Kzav6JuWamV6\n"
    "0x80T4RWTpWFXVb288EkSEambrKX8Y0ihn7bFK/cAxD4j7oAGJCgW85mbMAZsj4b\n"
    "OAvPvajSMJKyKrgIX/wMfTQlTqAvcsEA2FbrgX67BEBw9HUP2Mm6\n"
    "-----END RSA PRIVATE KEY-----\n";

#if AWS_IOT_MQTT_TEST

#define AWS_IOT_MQTT_SERVER_NAME                "a1fbcwaqfqeozo.iot.us-east-1.amazonaws.com"
#define AWS_IOT_MQTT_SERVER_PORT                8883

#define AWS_IOT_MQTT_THINGNAME                  "Nuvoton-Mbed-D001"
#define AWS_IOT_MQTT_CLIENTNAME                 "Nuvoton Client"

/* User self-test topic */
const char USER_MQTT_TOPIC[] = "Nuvoton/Mbed/D001";
const char *USER_MQTT_TOPIC_FILTERS[] = {
    "Nuvoton/Mbed/+"
};
const char USER_MQTT_TOPIC_PUBLISH_MESSAGE[] = "{ \"message\": \"Hello from Nuvoton Mbed device\" }";

/* Update thing shadow */
const char UPDATETHINGSHADOW_MQTT_TOPIC[] = "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/update";
const char *UPDATETHINGSHADOW_MQTT_TOPIC_FILTERS[] = {
    "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/update/accepted",
    "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/update/rejected"
};
const char UPDATETHINGSHADOW_MQTT_TOPIC_PUBLISH_MESSAGE[] = "{ \"state\": { \"reported\": { \"attribute1\": 3, \"attribute2\": \"1\" } } }";

/* Get thing shadow */
const char GETTHINGSHADOW_MQTT_TOPIC[] = "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/get";
const char *GETTHINGSHADOW_MQTT_TOPIC_FILTERS[] = {
    "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/get/accepted",
    "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/get/rejected"
};
const char GETTHINGSHADOW_MQTT_TOPIC_PUBLISH_MESSAGE[] = "";

/* Delete thing shadow */
const char DELETETHINGSHADOW_MQTT_TOPIC[] = "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/delete";
const char *DELETETHINGSHADOW_MQTT_TOPIC_FILTERS[] = {
    "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/delete/accepted",
    "$aws/things/" AWS_IOT_MQTT_THINGNAME "/shadow/delete/rejected"
};
const char DELETETHINGSHADOW_MQTT_TOPIC_PUBLISH_MESSAGE[] = "";

/* MQTT user buffer size */
const int MQTT_USER_BUFFER_SIZE = 600;

/* Configure MAX_MQTT_PACKET_SIZE to meet your application.
 * We may meet unknown MQTT error with MAX_MQTT_PACKET_SIZE too small, but 
 * MQTT lib doesn't tell enough error message. Try to enlarge it. */
const int MAX_MQTT_PACKET_SIZE = 1000;

#endif  // End of AWS_IOT_MQTT_TEST

#if AWS_IOT_HTTPS_TEST

#define AWS_IOT_HTTPS_SERVER_NAME               "a1fbcwaqfqeozo.iot.us-east-1.amazonaws.com"
#define AWS_IOT_HTTPS_SERVER_PORT               8443

#define AWS_IOT_HTTPS_THINGNAME                 "Nuvoton-Mbed-D001"

/* Publish to user topic through HTTPS/POST 
 * HTTP POST https://"endpoint"/topics/"yourTopicHierarchy" */
const char USER_TOPIC_HTTPS_PATH[] = "/topics/Nuvoton/Mbed/D001?qos=1";
const char USER_TOPIC_HTTPS_REQUEST_METHOD[] = "POST";
const char USER_TOPIC_HTTPS_REQUEST_MESSAGE_BODY[] = "{ \"message\": \"Hello from Nuvoton Mbed device\" }";

/* Update thing shadow by publishing to UpdateThingShadow topic through HTTPS/POST
 * HTTP POST https://"endpoint"/topics/$aws/things/"thingName"/shadow/update */
const char UPDATETHINGSHADOW_TOPIC_HTTPS_PATH[] = "/topics/$aws/things/" AWS_IOT_HTTPS_THINGNAME "/shadow/update?qos=1";
const char UPDATETHINGSHADOW_TOPIC_HTTPS_REQUEST_METHOD[] = "POST";
const char UPDATETHINGSHADOW_TOPIC_HTTPS_REQUEST_MESSAGE_BODY[] = "{ \"state\": { \"reported\": { \"attribute1\": 3, \"attribute2\": \"1\" } } }";

/* Get thing shadow by publishing to GetThingShadow topic through HTTPS/POST
 * HTTP POST https://"endpoint"/topics/$aws/things/"thingName"/shadow/get */
const char GETTHINGSHADOW_TOPIC_HTTPS_PATH[] = "/topics/$aws/things/" AWS_IOT_HTTPS_THINGNAME "/shadow/get?qos=1";
const char GETTHINGSHADOW_TOPIC_HTTPS_REQUEST_METHOD[] = "POST";
const char GETTHINGSHADOW_TOPIC_HTTPS_REQUEST_MESSAGE_BODY[] = "";

/* Delete thing shadow by publishing to DeleteThingShadow topic through HTTPS/POST
 * HTTP POST https://"endpoint"/topics/$aws/things/"thingName"/shadow/delete */
const char DELETETHINGSHADOW_TOPIC_HTTPS_PATH[] = "/topics/$aws/things/" AWS_IOT_HTTPS_THINGNAME "/shadow/delete?qos=1";
const char DELETETHINGSHADOW_TOPIC_HTTPS_REQUEST_METHOD[] = "POST";
const char DELETETHINGSHADOW_TOPIC_HTTPS_REQUEST_MESSAGE_BODY[] = "";

/* Update thing shadow RESTfully through HTTPS/POST
 * HTTP POST https://endpoint/things/thingName/shadow */
const char UPDATETHINGSHADOW_THING_HTTPS_PATH[] = "/things/" AWS_IOT_HTTPS_THINGNAME "/shadow";
const char UPDATETHINGSHADOW_THING_HTTPS_REQUEST_METHOD[] = "POST";
const char UPDATETHINGSHADOW_THING_HTTPS_REQUEST_MESSAGE_BODY[] = "{ \"state\": { \"desired\": { \"attribute1\": 1, \"attribute2\": \"2\" }, \"reported\": { \"attribute1\": 2, \"attribute2\": \"1\" } } }";

/* Get thing shadow RESTfully through HTTPS/GET
 * HTTP GET https://"endpoint"/things/"thingName"/shadow */
const char GETTHINGSHADOW_THING_HTTPS_PATH[] = "/things/" AWS_IOT_HTTPS_THINGNAME "/shadow";
const char GETTHINGSHADOW_THING_HTTPS_REQUEST_METHOD[] = "GET";
const char GETTHINGSHADOW_THING_HTTPS_REQUEST_MESSAGE_BODY[] = "";

/* Delete thing shadow RESTfully through HTTPS/DELETE
 * HTTP DELETE https://endpoint/things/thingName/shadow */
const char DELETETHINGSHADOW_THING_HTTPS_PATH[] = "/things/" AWS_IOT_HTTPS_THINGNAME "/shadow";
const char DELETETHINGSHADOW_THING_HTTPS_REQUEST_METHOD[] = "DELETE";
const char DELETETHINGSHADOW_THING_HTTPS_REQUEST_MESSAGE_BODY[] = "";

/* HTTPS user buffer size */
const int HTTPS_USER_BUFFER_SIZE = 600;

const char *HTTPS_OK_STR = "200 OK";

#endif  // End of AWS_IOT_HTTPS_TEST

}

#if AWS_IOT_MQTT_TEST

/**
 * /brief   AWS_IoT_MQTT_Test implements the logic with AWS IoT User/Thing Shadow topics through MQTT.
 */
class AWS_IoT_MQTT_Test {

public:
    /**
     * @brief   AWS_IoT_MQTT_Test Constructor
     *
     * @param[in] domain    Domain name of the MQTT server
     * @param[in] port      Port number of the MQTT server
     * @param[in] net_iface Network interface
     */
    AWS_IoT_MQTT_Test(const char * domain, const uint16_t port, NetworkInterface *net_iface) :
        _domain(domain), _port(port) {
        _tlssocket = new TLSSocket(net_iface, SSL_CA_CERT_PEM, SSL_USER_CERT_PEM, SSL_USER_PRIV_KEY_PEM);
        /* Blocking mode */
        _tlssocket->set_blocking(true);
        /* Print Mbed TLS handshake log */
        _tlssocket->set_debug(true);

        _mqtt_client = new MQTT::Client<TLSSocket, Countdown, MAX_MQTT_PACKET_SIZE>(*_tlssocket);
    }

    /**
     * @brief AWS_IoT_MQTT_Test Destructor
     */
    ~AWS_IoT_MQTT_Test() {
        delete _mqtt_client;
        _mqtt_client = NULL;

        _tlssocket->close();
        delete _tlssocket;
        _tlssocket = NULL;
    }
    /**
     * @brief   Start AWS IoT test through MQTT
     */
    void start_test() {

        int tls_rc;
        int mqtt_rc;
        
        do {
            /* Connect to the server */
            /* Initialize TLS-related stuff */
            printf("Connecting with %s:%d\n", _domain, _port);
            tls_rc = _tlssocket->connect(_domain, _port);
            if (tls_rc != NSAPI_ERROR_OK) {
                printf("Connects with %s:%d failed: %d\n", _domain, _port, tls_rc);
                break;
            }
            printf("Connects with %s:%d OK\n", _domain, _port);
            
            /* See the link below for AWS IoT support for MQTT:
             * http://docs.aws.amazon.com/iot/latest/developerguide/protocols.html */
         
            /* MQTT connect */
            /* The message broker does not support persistent sessions (connections made with 
             * the cleanSession flag set to false. */
            MQTTPacket_connectData conn_data = MQTTPacket_connectData_initializer;
            /* AWS IoT message broker implementation is based on MQTT version 3.1.1
             * 3 = 3.1
             * 4 = 3.1.1 */
            conn_data.MQTTVersion = 4;
            /* Version number of this structure. Must be 0 */
            conn_data.struct_version = 0;
            /* The message broker uses the client ID to identify each client. The client ID is passed
             * in from the client to the message broker as part of the MQTT payload. Two clients with
             * the same client ID are not allowed to be connected concurrently to the message broker.
             * When a client connects to the message broker using a client ID that another client is using,
             * a CONNACK message will be sent to both clients and the currently connected client will be
             * disconnected. */
            conn_data.clientID.cstring = AWS_IOT_MQTT_CLIENTNAME;
            /* The message broker does not support persistent sessions (connections made with 
             * the cleanSession flag set to false. The AWS IoT message broker assumes all sessions 
             * are clean sessions and messages are not stored across sessions. If an MQTT client 
             * attempts to connect to the AWS IoT message broker with the cleanSession set to false, 
             * the client will be disconnected. */
            conn_data.cleansession = 1;
            //conn_data.username.cstring = "USERNAME";
            //conn_data.password.cstring = "PASSWORD";
        
            MQTT::connackData connack_data;
        
            /* _tlssocket must connect to the network endpoint before calling this. */
            printf("MQTT connecting");
            if ((mqtt_rc = _mqtt_client->connect(conn_data, connack_data)) != 0) {
                printf("\rMQTT connects failed: %d\n", mqtt_rc);
                break;
            }
            printf("\rMQTT connects OK\n\n");
            
            /* Subscribe/publish user topic */
            printf("Subscribing/publishing user topic\n");
            if (! sub_pub_topic(USER_MQTT_TOPIC, USER_MQTT_TOPIC_FILTERS, sizeof (USER_MQTT_TOPIC_FILTERS) / sizeof (USER_MQTT_TOPIC_FILTERS[0]), USER_MQTT_TOPIC_PUBLISH_MESSAGE)) {
                break;
            }
            printf("Subscribes/publishes user topic OK\n\n");
            
            /* Subscribe/publish UpdateThingShadow topic */
            printf("Subscribing/publishing UpdateThingShadow topic\n");
            if (! sub_pub_topic(UPDATETHINGSHADOW_MQTT_TOPIC, UPDATETHINGSHADOW_MQTT_TOPIC_FILTERS, sizeof (UPDATETHINGSHADOW_MQTT_TOPIC_FILTERS) / sizeof (UPDATETHINGSHADOW_MQTT_TOPIC_FILTERS[0]), UPDATETHINGSHADOW_MQTT_TOPIC_PUBLISH_MESSAGE)) {
                break;
            }
            printf("Subscribes/publishes UpdateThingShadow topic OK\n\n");
            
            /* Subscribe/publish GetThingShadow topic */
            printf("Subscribing/publishing GetThingShadow topic\n");
            if (! sub_pub_topic(GETTHINGSHADOW_MQTT_TOPIC, GETTHINGSHADOW_MQTT_TOPIC_FILTERS, sizeof (GETTHINGSHADOW_MQTT_TOPIC_FILTERS) / sizeof (GETTHINGSHADOW_MQTT_TOPIC_FILTERS[0]), GETTHINGSHADOW_MQTT_TOPIC_PUBLISH_MESSAGE)) {
                break;
            }
            printf("Subscribes/publishes GetThingShadow topic OK\n\n");
            
            /* Subscribe/publish DeleteThingShadow topic */
            printf("Subscribing/publishing DeleteThingShadow topic\n");
            if (! sub_pub_topic(DELETETHINGSHADOW_MQTT_TOPIC, DELETETHINGSHADOW_MQTT_TOPIC_FILTERS, sizeof (DELETETHINGSHADOW_MQTT_TOPIC_FILTERS) / sizeof (DELETETHINGSHADOW_MQTT_TOPIC_FILTERS[0]), DELETETHINGSHADOW_MQTT_TOPIC_PUBLISH_MESSAGE)) {
                break;
            }
            printf("Subscribes/publishes DeleteThingShadow topic OK\n\n");
            
        } while (0);
        
        printf("MQTT disconnecting");
        if ((mqtt_rc = _mqtt_client->disconnect()) != 0) {
            printf("\rMQTT disconnects failed %d\n", mqtt_rc);
        }
        printf("\rMQTT disconnects OK\n");
        
        _tlssocket->close();
    }

    
protected:

    /**
     * @brief   Subscribe/publish specific topic
     */
    bool sub_pub_topic(const char *topic, const char **topic_filters, size_t topic_filters_size, const char *publish_message_body) {
        
        bool ret = false;
        int mqtt_rc;
        
        do {
            const char **topic_filter;
            const char **topic_filter_end = topic_filters + topic_filters_size;

            for (topic_filter = topic_filters; topic_filter != topic_filter_end; topic_filter ++) {
                /* AWS IoT does not support publishing and subscribing with QoS 2.
                 * The AWS IoT message broker does not send a PUBACK or SUBACK when QoS 2 is requested. */
                printf("MQTT subscribing to %s", *topic_filter);
                if ((mqtt_rc = _mqtt_client->subscribe(*topic_filter, MQTT::QOS1, message_arrived)) != 0) {
                    printf("\rMQTT subscribes to %s failed: %d\n", *topic_filter, mqtt_rc);
                    continue;
                }
                printf("\rMQTT subscribes to %s OK\n", *topic_filter);
            }

            MQTT::Message message;

            int _bpos;
        
            _bpos = snprintf(_buffer, sizeof (_buffer) - 1, publish_message_body);
            if (_bpos < 0 || ((size_t) _bpos) > (sizeof (_buffer) - 1)) {
                printf("snprintf failed: %d\n", _bpos);
                break;
            }
            _buffer[_bpos] = 0;
            /* AWS IoT does not support publishing and subscribing with QoS 2.
             * The AWS IoT message broker does not send a PUBACK or SUBACK when QoS 2 is requested. */
            message.qos = MQTT::QOS1;
            message.retained = false;
            message.dup = false;
            message.payload = _buffer;
            message.payloadlen = strlen(_buffer);
            /* Print publish message */
            printf("Message to publish:\n");
            printf("%s\n", _buffer);
            printf("MQTT publishing message to %s", topic);
            if ((mqtt_rc = _mqtt_client->publish(topic, message)) != 0) {
                printf("\rMQTT publishes message to %s failed: %d\n", topic, mqtt_rc);
                break;
            }
            printf("\rMQTT publishes message to %s OK\n", topic);
        
            /* Receive message with subscribed topic */
            while (! _message_arrive_count) {
                _mqtt_client->yield(100);
            }
            clear_message_arrive_count();
            printf("\n");

            /* Unsubscribe 
             * We meet second unsubscribe failed. This is caused by MQTT lib bug. */
            for (topic_filter = topic_filters; topic_filter != topic_filter_end; topic_filter ++) {
                printf("MQTT unsubscribing from %s", *topic_filter);
                if ((mqtt_rc = _mqtt_client->unsubscribe(*topic_filter)) != 0) {
                    printf("\rMQTT unsubscribes from %s failed: %d\n", *topic_filter, mqtt_rc);
                    continue;
                }
                printf("\rMQTT unsubscribes from %s OK\n", *topic_filter);
            }

            ret = true;
        
        } while (0);
        
        return ret;
    }
    
protected:
    TLSSocket *                                                             _tlssocket;
    MQTT::Client<TLSSocket, Countdown, MAX_MQTT_PACKET_SIZE> *              _mqtt_client;

    const char *_domain;                    /**< Domain name of the MQTT server */
    const uint16_t _port;                   /**< Port number of the MQTT server */
    char _buffer[MQTT_USER_BUFFER_SIZE];    /**< User buffer */
    
private:
    static volatile uint16_t   _message_arrive_count;

    static void message_arrived(MQTT::MessageData& md) {
        MQTT::Message &message = md.message;
        printf("Message arrived: qos %d, retained %d, dup %d, packetid %d\r\n", message.qos, message.retained, message.dup, message.id);
        printf("Payload:\n");
        printf("%.*s\n", message.payloadlen, (char*)message.payload);
        ++ _message_arrive_count;
    }
    
    static void clear_message_arrive_count() {
        _message_arrive_count = 0;
    }
};

volatile uint16_t   AWS_IoT_MQTT_Test::_message_arrive_count = 0;

#endif  // End of AWS_IOT_MQTT_TEST


#if AWS_IOT_HTTPS_TEST

/**
 * /brief   AWS_IoT_HTTPS_Test implements the logic with AWS IoT User/Thing Shadow topics (publish-only)
 *          and Thing Shadow RESTful API through HTTPS.
 */
class AWS_IoT_HTTPS_Test {

public:
    /**
     * @brief   AWS_IoT_HTTPS_Test Constructor
     *
     * @param[in] domain    Domain name of the HTTPS server
     * @param[in] port      Port number of the HTTPS server
     * @param[in] net_iface Network interface
     */
    AWS_IoT_HTTPS_Test(const char * domain, const uint16_t port, NetworkInterface *net_iface) :
            _domain(domain), _port(port) {

        _tlssocket = new TLSSocket(net_iface, SSL_CA_CERT_PEM, SSL_USER_CERT_PEM, SSL_USER_PRIV_KEY_PEM);
        /* Non-blocking mode */
        _tlssocket->set_blocking(false);
        /* Print Mbed TLS handshake log */
        _tlssocket->set_debug(true);
    }
    /**
     * @brief AWS_IoT_HTTPS_Test Destructor
     */
    ~AWS_IoT_HTTPS_Test() {
        _tlssocket->close();
        delete _tlssocket;
        _tlssocket = NULL;
    }
    /**
     * @brief Start AWS IoT test through HTTPS
     *
     * @param[in] path  The path of the file to fetch from the HTTPS server
     */
    void start_test() {
        
        int tls_rc;
         
        do {
            /* Connect to the server */
            /* Initialize TLS-related stuff */
            printf("Connecting with %s:%d\n", _domain, _port);
            tls_rc = _tlssocket->connect(_domain, _port);
            if (tls_rc != NSAPI_ERROR_OK) {
                printf("Connects with %s:%d failed: %d\n", _domain, _port, tls_rc);
                break;
            }
            printf("Connects with %s:%d OK\n\n", _domain, _port);

            /* Publish to user topic through HTTPS/POST */
            printf("Publishing to user topic through HTTPS/POST\n");
            if (! run_req_resp(USER_TOPIC_HTTPS_PATH, USER_TOPIC_HTTPS_REQUEST_METHOD, USER_TOPIC_HTTPS_REQUEST_MESSAGE_BODY)) {
                break;
            }
            printf("Publishes to user topic through HTTPS/POST OK\n\n");
        
            /* Update thing shadow by publishing to UpdateThingShadow topic through HTTPS/POST */
            printf("Updating thing shadow by publishing to Update Thing Shadow topic through HTTPS/POST\n");
            if (! run_req_resp(UPDATETHINGSHADOW_TOPIC_HTTPS_PATH, UPDATETHINGSHADOW_TOPIC_HTTPS_REQUEST_METHOD, UPDATETHINGSHADOW_TOPIC_HTTPS_REQUEST_MESSAGE_BODY)) {
                break;
            }
            printf("Update thing shadow by publishing to Update Thing Shadow topic through HTTPS/POST OK\n\n");
            
            /* Get thing shadow by publishing to GetThingShadow topic through HTTPS/POST */
            printf("Getting thing shadow by publishing to GetThingShadow topic through HTTPS/POST\n");
            if (! run_req_resp(GETTHINGSHADOW_TOPIC_HTTPS_PATH, GETTHINGSHADOW_TOPIC_HTTPS_REQUEST_METHOD, GETTHINGSHADOW_TOPIC_HTTPS_REQUEST_MESSAGE_BODY)) {
                break;
            }
            printf("Get thing shadow by publishing to GetThingShadow topic through HTTPS/POST OK\n\n");
            
            /* Delete thing shadow by publishing to DeleteThingShadow topic through HTTPS/POST */
            printf("Deleting thing shadow by publishing to DeleteThingShadow topic through HTTPS/POST\n");
            if (! run_req_resp(DELETETHINGSHADOW_TOPIC_HTTPS_PATH, DELETETHINGSHADOW_TOPIC_HTTPS_REQUEST_METHOD, DELETETHINGSHADOW_TOPIC_HTTPS_REQUEST_MESSAGE_BODY)) {
                break;
            }
            printf("Delete thing shadow by publishing to DeleteThingShadow topic through HTTPS/POST OK\n\n");
            
            /* Update thing shadow RESTfully through HTTPS/POST */
            printf("Updating thing shadow RESTfully through HTTPS/POST\n");
            if (! run_req_resp(UPDATETHINGSHADOW_THING_HTTPS_PATH, UPDATETHINGSHADOW_THING_HTTPS_REQUEST_METHOD, UPDATETHINGSHADOW_THING_HTTPS_REQUEST_MESSAGE_BODY)) {
                break;
            }
            printf("Update thing shadow RESTfully through HTTPS/POST OK\n\n");
            
            /* Get thing shadow RESTfully through HTTPS/GET */
            printf("Getting thing shadow RESTfully through HTTPS/GET\n");
            if (! run_req_resp(GETTHINGSHADOW_THING_HTTPS_PATH, GETTHINGSHADOW_THING_HTTPS_REQUEST_METHOD, GETTHINGSHADOW_THING_HTTPS_REQUEST_MESSAGE_BODY)) {
                break;
            }
            printf("Get thing shadow RESTfully through HTTPS/GET OK\n\n");
            
            /* Delete thing shadow RESTfully through HTTPS/DELETE */
            printf("Deleting thing shadow RESTfully through HTTPS/DELETE\n");
            if (! run_req_resp(DELETETHINGSHADOW_THING_HTTPS_PATH, DELETETHINGSHADOW_THING_HTTPS_REQUEST_METHOD, DELETETHINGSHADOW_THING_HTTPS_REQUEST_MESSAGE_BODY)) {
                break;
            }
            printf("Delete thing shadow RESTfully through HTTPS/DELETE OK\n\n");
            
        } while (0);
        
        /* Close socket */
        _tlssocket->close();
    }

protected:

    /**
     * @brief   Run request/response through HTTPS
     */
    bool run_req_resp(const char *https_path, const char *https_request_method, const char *https_request_message_body) {
        
        bool ret = false;
        
        do {
            int tls_rc;
            bool _got200 = false;

            int _bpos;

            /* Fill the request buffer */
            _bpos = snprintf(_buffer, sizeof(_buffer) - 1,
                            "%s %s HTTP/1.1\r\n" "Host: %s\r\n" "Content-Length: %d\r\n" "\r\n" "%s",
                            https_request_method, https_path, AWS_IOT_HTTPS_SERVER_NAME, strlen(https_request_message_body), https_request_message_body);
            if (_bpos < 0 || ((size_t) _bpos) > (sizeof (_buffer) - 1)) {
                printf("snprintf failed: %d\n", _bpos);
                break;
            }
            _buffer[_bpos] = 0;
            /* Print request message */
            printf("HTTPS: Request message:\n");
            printf("%s\n", _buffer);
        
            int offset = 0;
            do {
                tls_rc = _tlssocket->send((const unsigned char *) _buffer + offset, _bpos - offset);
                if (tls_rc > 0) {
                    offset += tls_rc;
                }
            } while (offset < _bpos && 
                    (tls_rc > 0 || tls_rc == MBEDTLS_ERR_SSL_WANT_READ || tls_rc == MBEDTLS_ERR_SSL_WANT_WRITE));
            if (tls_rc < 0) {
                print_mbedtls_error("_tlssocket->send", tls_rc);
                break;
            }

            /* Read data out of the socket */
            offset = 0;
            size_t content_length = 0;
            size_t offset_end = 0;
            char *line_beg = _buffer;
            char *line_end = NULL;
            do {
                tls_rc = _tlssocket->recv((unsigned char *) _buffer + offset, sizeof(_buffer) - offset - 1);
                if (tls_rc > 0) {
                    offset += tls_rc;
                }
                
                /* Make it null-terminated */
                _buffer[offset] = 0;

                /* Scan response message
                 *             
                 * 1. A status line which includes the status code and reason message (e.g., HTTP/1.1 200 OK)
                 * 2. Response header fields (e.g., Content-Type: text/html)
                 * 3. An empty line (\r\n)
                 * 4. An optional message body
                 */
                if (! offset_end) {
                    line_end = strstr(line_beg, "\r\n");
                    if (line_end) {
                        /* Scan status line */
                        if (! _got200) {
                            _got200 = strstr(line_beg, HTTPS_OK_STR) != NULL;
                        }
            
                        /* Scan response header fields for Content-Length 
                         * 
                         * NOTE: Assume chunked transfer (Transfer-Encoding: chunked) is not used
                         * NOTE: Assume response field name are in lower case
                         */
                        if (content_length == 0) {
                            sscanf(line_beg, "content-length:%d", &content_length);
                        }
                    
                        /* An empty line indicates end of response header fields */
                        if (line_beg == line_end) {
                            offset_end = line_end - _buffer + 2 + content_length;
                        }
                    
                        /* Go to next line */
                        line_beg = line_end + 2;
                        line_end = NULL;
                    }
                }
            } while ((offset_end == 0 || offset < offset_end) &&
                    (tls_rc > 0 || tls_rc == MBEDTLS_ERR_SSL_WANT_READ || tls_rc == MBEDTLS_ERR_SSL_WANT_WRITE));
            if (tls_rc < 0 && 
                tls_rc != MBEDTLS_ERR_SSL_WANT_READ && 
                tls_rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error("_tlssocket->read", tls_rc);
                break;
            }
            _bpos = offset;

            _buffer[_bpos] = 0;

            /* Print status messages */
            printf("HTTPS: Received %d chars from server\n", _bpos);
            printf("HTTPS: Received 200 OK status ... %s\n", _got200 ? "[OK]" : "[FAIL]");
            printf("HTTPS: Received message:\n");
            printf("%s\n", _buffer);
        
            ret = true;
            
        } while (0);
        
        return ret;
    }
     
protected:
    TLSSocket *     _tlssocket;

    const char *_domain;                    /**< Domain name of the HTTPS server */
    const uint16_t _port;                   /**< Port number of the HTTPS server */
    char _buffer[HTTPS_USER_BUFFER_SIZE];   /**< User buffer */
};

#endif  // End of AWS_IOT_HTTPS_TEST

int main() {
    
    /* The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out. */

    printf("\nStarting AWS IoT test\n");

#if defined(MBED_MAJOR_VERSION)
    printf("Using Mbed OS %d.%d.%d\n", MBED_MAJOR_VERSION, MBED_MINOR_VERSION, MBED_PATCH_VERSION);
#else
    printf("Using Mbed OS from master.\n");
#endif

    /* Use the easy-connect lib to support multiple network bearers.   */
    /* See https://github.com/ARMmbed/easy-connect README.md for info. */

    NetworkInterface* network = easy_connect(false);
    if (NULL == network) {
        printf("Connecting to the network failed. See serial output.\n");
        return 1;
    }
    
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

    /* Heap usage */
    mbed_stats_heap_t heap_stats;
    mbed_stats_heap_get(&heap_stats);
    printf("\nCurrent heap size: %lu\n", heap_stats.current_size);
    printf("Max heap size: %lu\n\n", heap_stats.max_size);
}