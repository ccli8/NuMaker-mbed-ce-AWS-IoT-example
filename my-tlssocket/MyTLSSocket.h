#ifndef _MY_TLS_SOCKET_H_
#define _MY_TLS_SOCKET_H_

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#if MBED_CONF_MY_TLSSOCKET_TLS_DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "mbedtls_utils.h"
    
/**
 * \brief MyTLSSocket a wrapper around TCPSocket for interacting with TLS servers
 */
class MyTLSSocket {
public:
    MyTLSSocket(NetworkInterface* net_iface, const char* ssl_ca_pem, const char* ssl_owncert_pem, const char* ssl_own_priv_key_pem);
    ~MyTLSSocket();

    /** Close the socket
     *
     *  Closes any open connection and deallocates any memory associated
     *  with the socket. Called from destructor if socket is not closed.
     *
     *  @return         0 on success, negative error code on failure
     */
    nsapi_error_t close();
    
    nsapi_error_t connect(const char *hostname, uint16_t port);

    /** Send data over a TCP socket
     *
     *  The socket must be connected to a remote host. Returns the number of
     *  bytes sent from the buffer.
     *
     *  By default, send blocks until all data is sent. If socket is set to
     *  non-blocking or times out, a partial amount can be written.
     *  NSAPI_ERROR_WOULD_BLOCK is returned if no data was written.
     *
     *  @param data     Buffer of data to send to the host
     *  @param size     Size of the buffer in bytes
     *  @return         Number of sent bytes on success, negative error
     *                  code on failure
     */
    nsapi_size_or_error_t send(const void *data, nsapi_size_t size);
    
    /** Receive data over a TCP socket
     *
     *  The socket must be connected to a remote host. Returns the number of
     *  bytes received into the buffer.
     *
     *  By default, recv blocks until some data is received. If socket is set to
     *  non-blocking or times out, NSAPI_ERROR_WOULD_BLOCK can be returned to
     *  indicate no data.
     *
     *  @param data     Destination buffer for data received from the host
     *  @param size     Size of the buffer in bytes
     *  @return         Number of received bytes on success, negative error
     *                  code on failure
     */
    nsapi_size_or_error_t recv(void *data, nsapi_size_t size);
    
    /** Set blocking or non-blocking mode of the socket
     *
     *  Initially all sockets are in blocking mode. In non-blocking mode
     *  blocking operations such as send/recv/accept return
     *  NSAPI_ERROR_WOULD_BLOCK if they can not continue.
     *
     *  set_blocking(false) is equivalent to set_timeout(-1)
     *  set_blocking(true) is equivalent to set_timeout(0)
     *
     *  @param blocking true for blocking mode, false for non-blocking mode.
     */
    void set_blocking(bool blocking);
    
    /** Set timeout on blocking socket operations
     *
     *  Initially all sockets have unbounded timeouts. NSAPI_ERROR_WOULD_BLOCK
     *  is returned if a blocking operation takes longer than the specified
     *  timeout. A timeout of 0 removes the timeout from the socket. A negative
     *  value give the socket an unbounded timeout.
     *
     *  set_timeout(0) is equivalent to set_blocking(false)
     *  set_timeout(-1) is equivalent to set_blocking(true)
     *
     *  @param timeout  Timeout in milliseconds
     */
    void set_timeout(int timeout);
    
    bool connected();

    nsapi_error_t error();

    TCPSocket* get_tcp_socket();

    mbedtls_ssl_context* get_ssl_context();

    /**
     * Set the debug flag.
     *
     * If this flag is set, debug information from mbed TLS will be logged to stdout.
     */
    void set_debug(bool debug);
    
    /**
     * Timed recv for MQTT lib
     */
    int read(unsigned char* buffer, int len, int timeout);

    /**
     * Timed send for MQTT lib
     */
    int write(unsigned char* buffer, int len, int timeout);
    
protected:

#if MBED_CONF_MY_TLSSOCKET_TLS_DEBUG_LEVEL > 0
    /**
     * Debug callback for mbed TLS
     * Just prints on the USB serial port
     */
    static void my_debug(void *ctx, int level, const char *file, int line,
                         const char *str);

    /**
     * Certificate verification callback for mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
#endif

    /**
     * Receive callback for mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len);

    /**
     * Send callback for mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len);

private:
    void onError(TCPSocket *s, int error);

    TCPSocket* _tcpsocket;

    const char* DRBG_PERS;
    const char* _ssl_ca_pem;
    const char* _ssl_owncert_pem;
    const char* _ssl_own_priv_key_pem;
    const char* _hostname;
    uint16_t _port;

    bool _debug;
    bool _is_connected;

    nsapi_error_t _error;

    mbedtls_entropy_context _entropy;
    mbedtls_ctr_drbg_context _ctr_drbg;
    mbedtls_x509_crt _cacert;
    mbedtls_x509_crt _owncert;
    mbedtls_pk_context _own_priv_key;
    mbedtls_ssl_context _ssl;
    mbedtls_ssl_config _ssl_conf;
};

#endif // _MY_TLS_SOCKET_H_
