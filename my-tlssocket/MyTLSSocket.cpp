#include "mbed.h"
#include "MyTLSSocket.h"


MyTLSSocket::MyTLSSocket(NetworkInterface* net_iface, const char* ssl_ca_pem, const char* ssl_owncert_pem, const char* ssl_own_priv_key_pem)
{
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

MyTLSSocket::~MyTLSSocket()
{
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
}

nsapi_error_t MyTLSSocket::close()
{
    return _tcpsocket->close();
}
    
nsapi_error_t MyTLSSocket::connect(const char *hostname, uint16_t port)
{
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

    /* Enable RFC 6066 max_fragment_length extension in SSL */
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) && (MBED_CONF_MY_TLSSOCKET_TLS_MAX_FRAG_LEN > 0)
    mbedtls_ssl_conf_max_frag_len(&_ssl_conf, MBED_CONF_MY_TLSSOCKET_TLS_MAX_FRAG_LEN);
#endif

#if MBED_CONF_MY_TLSSOCKET_TLS_DEBUG_LEVEL > 0
    mbedtls_ssl_conf_verify(&_ssl_conf, my_verify, this);
    mbedtls_ssl_conf_dbg(&_ssl_conf, my_debug, this);
    mbedtls_debug_set_threshold(MBED_CONF_MY_TLSSOCKET_TLS_DEBUG_LEVEL);
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
    if (_debug) {
        mbedtls_printf("Connecting to %s:%d\r\n", _hostname, _port);
    }
    ret = _tcpsocket->connect(_hostname, _port);
    if (ret != NSAPI_ERROR_OK) {
        if (_debug) {
            mbedtls_printf("Failed to connect\r\n");
        }
        onError(_tcpsocket, -1);
        return _error;
    }

    /* Start the handshake, the rest will be done in onReceive() */
    if (_debug) {
        mbedtls_printf("Starting the TLS handshake...\r\n");
    }
    do {
        ret = mbedtls_ssl_handshake(&_ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_handshake", ret);
        onError(_tcpsocket, ret);
        return ret;
    }
            
    /* It also means the handshake is done, time to print info */
    if (_debug) {
        mbedtls_printf("TLS connection to %s:%d established\r\n", _hostname, _port);
    }

    const uint32_t buf_size = 1024;
    char *buf = new char[buf_size];
    mbedtls_x509_crt_info(buf, buf_size, "\r    ", mbedtls_ssl_get_peer_cert(&_ssl));
    if (_debug) {
        mbedtls_printf("Server certificate:\r\n%s\r", buf);
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(&_ssl);
    if (flags != 0) {
        mbedtls_x509_crt_verify_info(buf, buf_size, "\r  ! ", flags);
        if (_debug) {
            mbedtls_printf("Certificate verification failed:\r\n%s\r\r\n", buf);
        }
    }
    else {
        if (_debug) mbedtls_printf("Certificate verification passed\r\n\r\n");
    }
    delete [] buf;
    buf = NULL;

    _is_connected = true;

    return 0;
}

nsapi_size_or_error_t MyTLSSocket::send(const void *data, nsapi_size_t size)
{
    return mbedtls_ssl_write(&_ssl, (const uint8_t *) data, size);
}
    
nsapi_size_or_error_t MyTLSSocket::recv(void *data, nsapi_size_t size)
{
    return mbedtls_ssl_read(&_ssl, (uint8_t *) data, size);
}

void MyTLSSocket::set_blocking(bool blocking)
{
    _tcpsocket->set_blocking(blocking);
}

void MyTLSSocket::set_timeout(int timeout)
{
    _tcpsocket->set_timeout(timeout);
}
    
bool MyTLSSocket::connected()
{
    return _is_connected;
}

nsapi_error_t MyTLSSocket::error()
{
    return _error;
}

TCPSocket* MyTLSSocket::get_tcp_socket()
{
    return _tcpsocket;
}

mbedtls_ssl_context *MyTLSSocket::get_ssl_context()
{
    return &_ssl;
}

void MyTLSSocket::set_debug(bool debug)
{
    _debug = debug;
}
    
int MyTLSSocket::read(unsigned char* buffer, int len, int timeout)
{
    set_timeout(timeout);
    int rc = recv(buffer, len);
    return (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) ? 0 : rc;
}

int MyTLSSocket::write(unsigned char* buffer, int len, int timeout)
{
    set_timeout(timeout);
    int rc = send(buffer, len);
    return (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) ? 0 : rc;
}

#if MBED_CONF_MY_TLSSOCKET_TLS_DEBUG_LEVEL > 0
void MyTLSSocket::my_debug(void *ctx, int level, const char *file, int line,
                           const char *str)
{
    const char *p, *basename;
    MyTLSSocket *tlssocket = static_cast<MyTLSSocket *>(ctx);

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    if (tlssocket->_debug) {
        mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
    }
}

int MyTLSSocket::my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    const uint32_t buf_size = 1024;
    char *buf = new char[buf_size];
    MyTLSSocket *tlssocket = static_cast<MyTLSSocket *>(data);

    if (tlssocket->_debug) {
        mbedtls_printf("\nVerifying certificate at depth %d:\n", depth);
    }
    mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
    if (tlssocket->_debug) {
        mbedtls_printf("%s", buf);
    }
    
    if (*flags == 0) {
        if (tlssocket->_debug) {
            mbedtls_printf("No verification issue for this certificate\n");
        }
    }
    else {
        mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
        if (tlssocket->_debug) mbedtls_printf("%s\n", buf);
    }

    delete[] buf;
    return 0;
}
#endif

int MyTLSSocket::ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
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

int MyTLSSocket::ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
    int size = -1;
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    size = socket->send(buf, len);

    if (NSAPI_ERROR_WOULD_BLOCK == size) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    else if (size < 0) {
        return -1;
    }
    else {
        return size;
    }
}

void MyTLSSocket::onError(TCPSocket *s, int error)
{
    s->close();
    _error = error;
}
