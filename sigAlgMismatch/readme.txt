`sigAlgMismatch_check.sh` script creates mismatched leaf certificates, that contain
different algorithms in tbsCertificate and others in outer place within certificate.

see:

invalid_certs/

tar --lzip --touch -xvf "sigAlgMismatch_check.tar.lz"
--------------------------------------------------------------------------------

$ openssl verify -show_chain -verbose -check_ss_sig -CAfile "shared/root.cer" "invalid_certs/...cer"
openssl REJECTED all certificates from "invalid_certs/" dir
----------------

Windows 10 Pro 22H2 / CryptoAPI:
--------------------------------
accepted these certs:

rsa_md5_VS_rsa_sha1.cer
rsa_sha1_VS_sha1ABSENT_VS_rsa_sha1.cer
rsa_sha1_VS_sha256ABSENT_VS_rsa_sha256.cer
rsa_sha256_VS_md5.cer
rsa_sha256_VS_sha256ABSENT_VS_sha_256.cer
rsa_sha512_VS_sha1.cer
rsapss512_256_190_VS_rsa_sha512.cer
rsapss512_512_0_VS_rsapss512_512_190.cer
rsapss512_512_64_VS_rsa_sha1.cer
rsapss512_512_64_VS_rsapss512_512_0.cer
