#ifndef _TLS_SOCKET_H_
#define _TLS_SOCKET_H_

/* Change to a number between 1 and 4 to debug the TLS connection */
#define DEBUG_LEVEL 0

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "mbedtls_utils.h"
    
/**
 * \brief TLSSocket a wrapper around TCPSocket for interacting with TLS servers
 */
class TLSSocket {
public:
    TLSSocket(NetworkInterface* net_iface, const char* ssl_ca_pem, const char* ssl_owncert_pem, const char* ssl_own_priv_key_pem) {
        _tcpsocket = new TCPSocket(net_iface);
        _ssl_ca_pem = ssl_ca_pem;
        _ssl_owncert_pem = ssl_owncert_pem;
        _ssl_own_priv_key_pem = ssl_own_priv_key_pem;
        _is_connected = false;
        _debug = false;
        _hostname = NULL;
        _port = 0;
        _error = 0;

        DRBG_PERS = "mbed TLS helloword client";

        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        mbedtls_x509_crt_init(&_cacert);
        mbedtls_x509_crt_init(&_owncert);
        mbedtls_pk_init(&_own_priv_key);
        mbedtls_ssl_init(&_ssl);
        mbedtls_ssl_config_init(&_ssl_conf);
    }

    ~TLSSocket() {
        mbedtls_entropy_free(&_entropy);
        mbedtls_ctr_drbg_free(&_ctr_drbg);
        mbedtls_x509_crt_free(&_cacert);
        mbedtls_x509_crt_free(&_owncert);
        mbedtls_pk_free(&_own_priv_key);
        mbedtls_ssl_free(&_ssl);
        mbedtls_ssl_config_free(&_ssl_conf);

        if (_tcpsocket) {
            _tcpsocket->close();
            delete _tcpsocket;
        }

        // @todo: free DRBG_PERS ?
    }

    /** Close the socket
     *
     *  Closes any open connection and deallocates any memory associated
     *  with the socket. Called from destructor if socket is not closed.
     *
     *  @return         0 on success, negative error code on failure
     */
    nsapi_error_t close() {
        return _tcpsocket->close();
    }
    
    nsapi_error_t connect(const char *hostname, uint16_t port) {
        _hostname = hostname;
        _port = port;
        
        /* Initialize the flags */
        /*
         * Initialize TLS-related stuf.
         */
        int ret;
        if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                          (const unsigned char *) DRBG_PERS,
                          sizeof (DRBG_PERS))) != 0) {
            print_mbedtls_error("mbedtls_crt_drbg_init", ret);
            _error = ret;
            return _error;
        }

        if ((ret = mbedtls_x509_crt_parse(&_cacert, (const unsigned char *)_ssl_ca_pem,
                           strlen(_ssl_ca_pem) + 1)) != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse", ret);
            _error = ret;
            return _error;
        }

        if ((ret = mbedtls_x509_crt_parse(&_owncert, (const unsigned char *) _ssl_owncert_pem,
                           strlen(_ssl_owncert_pem) + 1)) != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse", ret);
            _error = ret;
            return _error;
        }
        
        if ((ret = mbedtls_pk_parse_key(&_own_priv_key, (const unsigned char *) _ssl_own_priv_key_pem,
                           strlen(_ssl_own_priv_key_pem) + 1, NULL, 0)) != 0) {
            print_mbedtls_error("mbedtls_pk_parse_key", ret);
            _error = ret;
            return _error;
        }
        
        if ((ret = mbedtls_ssl_config_defaults(&_ssl_conf,
                        MBEDTLS_SSL_IS_CLIENT,
                        MBEDTLS_SSL_TRANSPORT_STREAM,
                        MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
            _error = ret;
            return _error;
        }

        mbedtls_ssl_conf_ca_chain(&_ssl_conf, &_cacert, NULL);
        mbedtls_ssl_conf_own_cert(&_ssl_conf, &_owncert, &_own_priv_key);
        mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

        /* It is possible to disable authentication by passing
         * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
         */
        mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if DEBUG_LEVEL > 0
        mbedtls_ssl_conf_verify(&_ssl_conf, my_verify, NULL);
        mbedtls_ssl_conf_dbg(&_ssl_conf, my_debug, NULL);
        mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

        if ((ret = mbedtls_ssl_setup(&_ssl, &_ssl_conf)) != 0) {
            print_mbedtls_error("mbedtls_ssl_setup", ret);
            _error = ret;
            return _error;
        }

        mbedtls_ssl_set_hostname(&_ssl, _hostname);

        mbedtls_ssl_set_bio(&_ssl, static_cast<void *>(_tcpsocket),
                                   ssl_send, ssl_recv, NULL );

        /* Connect to the server */
        if (_debug) mbedtls_printf("Connecting to %s:%d\r\n", _hostname, _port);
        ret = _tcpsocket->connect(_hostname, _port);
        if (ret != NSAPI_ERROR_OK) {
            if (_debug) mbedtls_printf("Failed to connect\r\n");
            onError(_tcpsocket, -1);
            return _error;
        }

       /* Start the handshake, the rest will be done in onReceive() */
        if (_debug) mbedtls_printf("Starting the TLS handshake...\r\n");
        do {
            ret = mbedtls_ssl_handshake(&_ssl);
        } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
        if (ret < 0) {
            print_mbedtls_error("mbedtls_ssl_handshake", ret);
            onError(_tcpsocket, ret);
            return ret;
        }
            
        /* It also means the handshake is done, time to print info */
        if (_debug) mbedtls_printf("TLS connection to %s:%d established\r\n", _hostname, _port);

        const uint32_t buf_size = 1024;
        char *buf = new char[buf_size];
        mbedtls_x509_crt_info(buf, buf_size, "\r    ",
                        mbedtls_ssl_get_peer_cert(&_ssl));
        if (_debug) mbedtls_printf("Server certificate:\r\n%s\r", buf);

        uint32_t flags = mbedtls_ssl_get_verify_result(&_ssl);
        if( flags != 0 )
        {
            mbedtls_x509_crt_verify_info(buf, buf_size, "\r  ! ", flags);
            if (_debug) mbedtls_printf("Certificate verification failed:\r\n%s\r\r\n", buf);
        }
        else {
            if (_debug) mbedtls_printf("Certificate verification passed\r\n\r\n");
        }
        delete [] buf;
        buf = NULL;

        _is_connected = true;

        return 0;
    }

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
    nsapi_size_or_error_t send(const void *data, nsapi_size_t size) {
        return mbedtls_ssl_write(&_ssl, (const uint8_t *) data, size);
    }
    
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
    nsapi_size_or_error_t recv(void *data, nsapi_size_t size) {
        return mbedtls_ssl_read(&_ssl, (uint8_t *) data, size);
    }
    
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
    void set_blocking(bool blocking) {
        _tcpsocket->set_blocking(blocking);
    }
    
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
    void set_timeout(int timeout) {
        _tcpsocket->set_timeout(timeout);
    }
    
    bool connected() {
        return _is_connected;
    }

    nsapi_error_t error() {
        return _error;
    }

    TCPSocket* get_tcp_socket() {
        return _tcpsocket;
    }

    mbedtls_ssl_context* get_ssl_context() {
        return &_ssl;
    }

    /**
     * Set the debug flag.
     *
     * If this flag is set, debug information from mbed TLS will be logged to stdout.
     */
    void set_debug(bool debug) {
        _debug = debug;
    }
    
    /**
     * Timed recv for MQTT lib
     */
    int read(unsigned char* buffer, int len, int timeout) {
        set_timeout(timeout);
        return recv(buffer, len);
    }

    /**
     * Timed send for MQTT lib
     */
    int write(unsigned char* buffer, int len, int timeout) {
        set_timeout(timeout);
        return send(buffer, len);
    }
    
protected:

#if DEBUG_LEVEL > 0
    /**
     * Debug callback for mbed TLS
     * Just prints on the USB serial port
     */
    static void my_debug(void *ctx, int level, const char *file, int line,
                         const char *str)
    {
        const char *p, *basename;
        (void) ctx;

        /* Extract basename from file */
        for(p = basename = file; *p != '\0'; p++) {
            if(*p == '/' || *p == '\\') {
                basename = p + 1;
            }
        }

        if (_debug) {
            mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
        }
    }

    /**
     * Certificate verification callback for mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
    {
        const uint32_t buf_size = 1024;
        char *buf = new char[buf_size];
        (void) data;

        if (_debug) mbedtls_printf("\nVerifying certificate at depth %d:\n", depth);
        mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
        if (_debug) mbedtls_printf("%s", buf);

        if (*flags == 0)
            if (_debug) mbedtls_printf("No verification issue for this certificate\n");
        else
        {
            mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
            if (_debug) mbedtls_printf("%s\n", buf);
        }

        delete[] buf;
        return 0;
    }
#endif

    /**
     * Receive callback for mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len) {
        int recv = -1;
        TCPSocket *socket = static_cast<TCPSocket *>(ctx);
        recv = socket->recv(buf, len);

        if (NSAPI_ERROR_WOULD_BLOCK == recv) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        else if (recv < 0) {
            return -1;
        }
        else {
            return recv;
        }
   }

    /**
     * Send callback for mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len) {
       int size = -1;
        TCPSocket *socket = static_cast<TCPSocket *>(ctx);
        size = socket->send(buf, len);

        if(NSAPI_ERROR_WOULD_BLOCK == size) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        else if (size < 0){
            return -1;
        }
        else {
            return size;
        }
    }

private:
    void onError(TCPSocket *s, int error) {
        s->close();
        _error = error;
    }

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

#endif // _TLS_SOCKET_H_
