# retls

Re-encrypt TLS connection with a different certificate.

## Usage

```
retls 0.1.0
Re-encrypt TLS connection with a different certificate.

USAGE:
    retls [OPTIONS] --backend <backend> --backend-server-name <backend-server-name> --cert <cert> --key <key> --listen <listen>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --backend <backend>                            The address to connect to [env: RETLS_BACKEND=]
        --backend-server-name <backend-server-name>    The address to connect to [env: RETLS_BACKEND_SERVER_NAME=]
        --cert <cert>                                  Cert file [env: RETLS_CERT=]
        --key <key>                                    Key file [env: RETLS_KEY=]
        --listen <listen>                              The address to listen on [env: RETLS_LISTEN=]
        --timeout-ms <timeout-ms>
            Connect timeout in milliseconds [env: RETLS_TIMEOUT_MS=]  [default: 30000]
```
