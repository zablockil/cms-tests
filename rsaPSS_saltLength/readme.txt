`max_salt_rsapss_certs.sh` script creates 2 certificates and places them in `sha.../pair_XXXX.pem`
creation time: ~ 2h 41m.

*  ROOT
    RSA ${keySize 2048-4096}, hashAlgo: sha...WithRSAEncryption
     |
     \
 *   USER
      nistp256, hashAlgo: rsaPSS -- rsa_pss_saltlen MAX
                                                    ---


tar --lzip --touch -xvf "max_salt_rsapss_certs.tar.lz"
