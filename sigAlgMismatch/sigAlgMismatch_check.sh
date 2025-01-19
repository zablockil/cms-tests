#!/bin/bash
# RUN:
# $ ./sigAlgMismatch_check.sh

################################################################################
#                             ascii2der & der2ascii                            #
#                                    RELATED                                   #
################################################################################
# download GO_lang, compile binary files, and copy executables to a portable folder.
# path to binary executables (no spaces):
# MSYS2/UCRT64:
#ascii2der="/d/der2ascii/ascii2der.exe"
#der2ascii="/d/der2ascii/der2ascii.exe"
# Linux:
ascii2der="/home/kali/go/bin/ascii2der"
der2ascii="/home/kali/go/bin/der2ascii"
${ascii2der} -h &> /dev/null
ascii2der_status="$?"
${der2ascii} -h &> /dev/null
der2ascii_status="$?"
if [ "${ascii2der_status}" -eq 0 ] && [ "${der2ascii_status}" -eq 0 ]; then
  ascii2der_available="1"
else
  ascii2der_available="0"
fi
unset ascii2der_status der2ascii_status
if [ "${ascii2der_available}" -eq 0 ]; then
  cat <<"EOF"
We need ascii2der & der2ascii
...
bye
! ! !
EOF
  exit 1
fi
################################################################################
#                             ascii2der & der2ascii                            #
#                                    RELATED                                   #
#                                      END                                     #
################################################################################

# START ossl related
error_ossl_missing () {
  cat <<"EOF"
We need OpenSSL 3.2, or newer
...
bye
! ! !
EOF
  exit 1
}
if [ -x "$(command -v openssl)" ]; then
  openssl_version="$(openssl version)"
  openssl_version_major="$(echo "${openssl_version}" | awk -F '.' '{print $1}' | awk '{print $2}')"
  openssl_version_minor="$(echo "${openssl_version}" | awk -F '.' '{print $2}')"
else
  error_ossl_missing
fi
if [ "${openssl_version_major}" -lt 3 ]; then
  error_ossl_missing
fi
if [ "${openssl_version_major}" -eq 3 ] && [ "${openssl_version_minor}" -lt 2 ]; then
  error_ossl_missing
fi
unset openssl_version openssl_version_major openssl_version_minor
# END ossl related


custom_cert_serial () {
  echo "$(shuf -i 1-7 -n 1)$(openssl rand -hex 8)" | head -c 16
}
serial_hex5 () {
  echo "$(openssl rand -hex 3 | head -c 5)"
}
serial_alfanum5 () {
  echo "$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 5)"
}
serial_num5 () {
  echo "$(awk -v seed=${RANDOM} 'BEGIN{srand(seed);printf("%.5f",rand())}' | tail -c 5)"
}

x509v3_config_root () {
cat <<-EOF
[ req ]
	distinguished_name=smime_root_dn
	x509_extensions=x509_smime_root_ext
	string_mask=utf8only
	utf8=yes
	prompt=no
[ smime_root_dn ]
	commonName=sigAlgMismatch ROOT rsa2048
	serialNumber=$(serial_alfanum5)-$(serial_num5)
[ x509_smime_root_ext ]
	basicConstraints=critical,CA:TRUE
	keyUsage=critical,keyCertSign,cRLSign
	subjectKeyIdentifier=hash
EOF
}

x509v3_config_user () {
cat <<-EOF
[ req ]
	distinguished_name=smime_user_dn
	string_mask=utf8only
	utf8=yes
	prompt=no
[ smime_user_dn ]
	commonName=sigAlgMismatch USER ${commonName_test}
	serialNumber=$(serial_alfanum5)-$(serial_num5)
[ subject_alt_name ]
	email.0=user_$(serial_hex5)_$(serial_num5)@signatureAlgorithm.com
[ x509_smime_user_ext ]
	basicConstraints=critical,CA:FALSE
	keyUsage=critical,digitalSignature,keyAgreement
	extendedKeyUsage=emailProtection
	subjectKeyIdentifier=hash
	authorityKeyIdentifier=keyid
	subjectAltName=@subject_alt_name
EOF
}

ossl_extract_cert () {
  openssl x509 -outform DER -in <(echo "${1}") -out "${2}"
}

mkdir "shared"

user_key_flush="$(openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1)"
echo "${user_key_flush}" > "shared/user.key"

ca_key_flush="$(openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048)"
echo "${ca_key_flush}" > "shared/root.key"

ca_cert_flush="$(openssl req -new -x509 -days 36524 -set_serial "0x$(custom_cert_serial)" -config <(echo "$(x509v3_config_root)") -key <(echo "${ca_key_flush}") -sha256)"
ossl_extract_cert "${ca_cert_flush}" "shared/root.cer"

csr_user () {
  openssl req -new -config <(echo "${prepare_x509_config_user}") -key <(echo "${user_key_flush}")
}

make_user_cert () {
  local prepare_x509_config_user="$(x509v3_config_user)"
  local temp_csr="$(csr_user)"
  openssl x509 -req -days 36523 -set_serial "0x$(custom_cert_serial)" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "${prepare_x509_config_user}") -extensions x509_smime_user_ext -"${specify_sha}"
}

make_user_cert_pss () {
  local prepare_x509_config_user="$(x509v3_config_user)"
  local temp_csr="$(csr_user)"
  openssl x509 -req -days 36523 -set_serial "0x$(custom_cert_serial)" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "${prepare_x509_config_user}") -extensions x509_smime_user_ext -sigopt rsa_padding_mode:pss -"${specify_sha}" -sigopt rsa_mgf1_md:"${specify_mgf1_sha}" -sigopt rsa_pss_saltlen:"${saltLength}"
}


mkdir "base"

# sha...WithRSAEncryption
#
commonName_test="rsa_md5"; specify_sha="md5"
base_rsa_md5="$(make_user_cert)"
ossl_extract_cert "${base_rsa_md5}" "base/rsa_md5.cer"
#
commonName_test="rsa_sha1"; specify_sha="sha1"
base_rsa_sha1="$(make_user_cert)"
ossl_extract_cert "${base_rsa_sha1}" "base/rsa_sha1.cer"
#
commonName_test="rsa_sha224"; specify_sha="sha224"
base_rsa_sha224="$(make_user_cert)"
ossl_extract_cert "${base_rsa_sha224}" "base/rsa_sha224.cer"
#
commonName_test="rsa_sha256"; specify_sha="sha256"
base_rsa_sha256="$(make_user_cert)"
ossl_extract_cert "${base_rsa_sha256}" "base/rsa_sha256.cer"
#
commonName_test="rsa_sha384"; specify_sha="sha384"
base_rsa_sha384="$(make_user_cert)"
ossl_extract_cert "${base_rsa_sha384}" "base/rsa_sha384.cer"
#
commonName_test="rsa_sha512"; specify_sha="sha512"
base_rsa_sha512="$(make_user_cert)"
ossl_extract_cert "${base_rsa_sha512}" "base/rsa_sha512.cer"

## rsassaPss
#
commonName_test="rsapss_sha1_sha1_0"; specify_sha="sha1"; specify_mgf1_sha="sha1"; saltLength="0"
base_rsapss_sha1_sha1_0="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha1_sha1_0}" "base/rsapss_sha1_sha1_0.cer"
#
commonName_test="rsapss_sha1_sha1_20"; specify_sha="sha1"; specify_mgf1_sha="sha1"; saltLength="20"
base_rsapss_sha1_sha1_20="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha1_sha1_20}" "base/rsapss_sha1_sha1_20.cer"
#
commonName_test="rsapss_sha1_sha384_234"; specify_sha="sha1"; specify_mgf1_sha="sha384"; saltLength="234"
base_rsapss_sha1_sha384_234="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha1_sha384_234}" "base/rsapss_sha1_sha384_234.cer"
#
commonName_test="rsapss_sha224_sha224_0"; specify_sha="sha224"; specify_mgf1_sha="sha224"; saltLength="0"
base_rsapss_sha224_sha224_0="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha224_sha224_0}" "base/rsapss_sha224_sha224_0.cer"
#
commonName_test="rsapss_sha224_sha224_28"; specify_sha="sha224"; specify_mgf1_sha="sha224"; saltLength="28"
base_rsapss_sha224_sha224_28="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha224_sha224_28}" "base/rsapss_sha224_sha224_28.cer"
#
commonName_test="rsapss_sha224_sha1_226"; specify_sha="sha224"; specify_mgf1_sha="sha1"; saltLength="226"
base_rsapss_sha224_sha1_226="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha224_sha1_226}" "base/rsapss_sha224_sha1_226.cer"
#
commonName_test="rsapss_sha256_sha256_0"; specify_sha="sha256"; specify_mgf1_sha="sha256"; saltLength="0"
base_rsapss_sha256_sha256_0="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha256_sha256_0}" "base/rsapss_sha256_sha256_0.cer"
#
commonName_test="rsapss_sha256_sha256_32"; specify_sha="sha256"; specify_mgf1_sha="sha256"; saltLength="32"
base_rsapss_sha256_sha256_32="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha256_sha256_32}" "base/rsapss_sha256_sha256_32.cer"
#
commonName_test="rsapss_sha256_sha384_222"; specify_sha="sha256"; specify_mgf1_sha="sha384"; saltLength="222"
base_rsapss_sha256_sha384_222="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha256_sha384_222}" "base/rsapss_sha256_sha384_222.cer"
#
commonName_test="rsapss_sha384_sha384_0"; specify_sha="sha384"; specify_mgf1_sha="sha384"; saltLength="0"
base_rsapss_sha384_sha384_0="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha384_sha384_0}" "base/rsapss_sha384_sha384_0.cer"
#
commonName_test="rsapss_sha384_sha384_48"; specify_sha="sha384"; specify_mgf1_sha="sha384"; saltLength="48"
base_rsapss_sha384_sha384_48="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha384_sha384_48}" "base/rsapss_sha384_sha384_48.cer"
#
commonName_test="rsapss_sha384_sha224_206"; specify_sha="sha384"; specify_mgf1_sha="sha224"; saltLength="206"
base_rsapss_sha384_sha224_206="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha384_sha224_206}" "base/rsapss_sha384_sha224_206.cer"
#
commonName_test="rsapss_sha512_sha512_0"; specify_sha="sha512"; specify_mgf1_sha="sha512"; saltLength="0"
base_rsapss_sha512_sha512_0="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha512_sha512_0}" "base/rsapss_sha512_sha512_0.cer"
#
commonName_test="rsapss_sha512_sha512_64"; specify_sha="sha512"; specify_mgf1_sha="sha512"; saltLength="64"
base_rsapss_sha512_sha512_64="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha512_sha512_64}" "base/rsapss_sha512_sha512_64.cer"
#
commonName_test="rsapss_sha512_sha256_190"; specify_sha="sha512"; specify_mgf1_sha="sha256"; saltLength="190"
base_rsapss_sha512_sha256_190="$(make_user_cert_pss)"
ossl_extract_cert "${base_rsapss_sha512_sha256_190}" "base/rsapss_sha512_sha256_190.cer"


# https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1
# The Certificate is a SEQUENCE of three required fields.
#  * tbsCertificate
#  * signatureAlgorithm (**)
#  * signatureValue
# (**) This field MUST contain the same algorithm identifier as the signature
#      field in the sequence tbsCertificate

# extract_tbsCertificate ()
#  usage:
#  extract_tbsCertificate "${CERTIFICATE}"
#
#  INPUT:  $1  PEM encoded certificate (from bash variable)
#              only X509v3 certificates (INTEGER { 2 })
#  OUTPUT:  -  ex_tbsCertificate_text      - ascii encoded tbs
#  (bash    -  ex_signatureAlgorithm_text  - ascii encoded signatureAlgorithm
#   vars)                                    (cut from tbsCertificate)
#
# This function only exports structures. Once you edit the "tbsCertificate_text"
# code, sign it with the sign_tbsCertificate_...() function, then put everything
# together with construct_new_cert() function.
#
# We will not edit "tbsCertificate_text", we will use ready-made parts from pre-
# generated certs.
#
extract_tbsCertificate () {
  # always line number #2 (of the whole certificate)
  local tbs_offset_number="$(openssl asn1parse -in <(echo "${1}") | awk -F ':' 'NR==2 {sub(/^ +/,""); print $1}')"
  ex_tbsCertificate_text="$(openssl asn1parse -noout -strparse "${tbs_offset_number}" -in <(echo "${1}") -out /dev/stdout | ${der2ascii} | awk -v RS='\r?\n' -v ORS=' ' '$1 != "#"{gsub(/^ +/,"");print}')"

  # always line number #6 (of the whole certificate)
  local sig_alg_offset_number="$(openssl asn1parse -in <(echo "${1}") | awk -F ':' 'NR==6 {sub(/^ +/,""); print $1}')"
  ex_signatureAlgorithm_text="$(openssl asn1parse -noout -strparse "${sig_alg_offset_number}" -in <(echo "${1}") -out /dev/stdout | ${der2ascii} | awk -v RS='\r?\n' -v ORS=' ' '$1 != "#"{gsub(/^ +/,"");print}')"

  # debug:
  #echo "${ex_tbsCertificate_text}" > "ex_tbsCertificate_text.txt"
  #echo "${ex_signatureAlgorithm_text}" > "ex_signatureAlgorithm_text.txt"
}

#
# https://docs.openssl.org/master/man1/openssl-pkeyutl/
# https://github.com/google/der-ascii/blob/main/samples/certificates.md
# https://github.com/google/der-ascii/blob/main/language.txt
#

#
# sign_tbsCertificate_rsa ()
#  usage:
#  sign_tbsCertificate_rsa
#
#  INPUT:  ${ex_tbsCertificate_text} - from extract_tbsCertificate()
#          ${ca_key_flush}           - private key material
#          ${specify_sha}            - digest to use
#  OUTPUT:  -  signatureValue_hex    - hex encoded signatureValue
#  (bash var)
sign_tbsCertificate_rsa () {
  signatureValue_hex="$(echo "${ex_tbsCertificate_text}" | ${ascii2der} | openssl pkeyutl -sign -inkey <(echo "${ca_key_flush}") -rawin -digest "${specify_sha}" -out /dev/stdout | basenc --base16 --wrap=0)"
}

# sign_tbsCertificate_rsapss ()
#  usage:
#  sign_tbsCertificate_rsapss
#
#  INPUT:  ${ex_tbsCertificate_text} - from extract_tbsCertificate()
#          ${ca_key_flush}           - private key material
#          ${specify_sha}            - digest to use
#          ${specify_mgf1_sha}       - mgf1 digest to use
#          ${saltLength}             - rsa_pss_saltlen
#  OUTPUT:  -  signatureValue_hex    - hex encoded signatureValue
#  (bash var)
sign_tbsCertificate_rsapss () {
  signatureValue_hex="$(echo "${ex_tbsCertificate_text}" | ${ascii2der} | openssl pkeyutl -sign -inkey <(echo "${ca_key_flush}") -rawin -digest "${specify_sha}" -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_mgf1_md:"${specify_mgf1_sha}" -pkeyopt rsa_pss_saltlen:"${saltLength}" -out /dev/stdout | basenc --base16 --wrap=0)"
}

# construct_new_cert ()
#  usage:
#  construct_new_cert
#
#  INPUT:  ${ex_tbsCertificate_text}     - from extract_tbsCertificate()
#          ${ex_signatureAlgorithm_text} - from extract_tbsCertificate()
#          ${signatureValue_hex}         - from sign_tbsCertificate_...()
#  OUTPUT:  /dev/stdout                  - base64 encoded certificate
construct_new_cert () {
  generate_base64_code () {
    cat <<EOF | ${ascii2der} | basenc --base64 --wrap=64
SEQUENCE {
${ex_tbsCertificate_text}
${ex_signatureAlgorithm_text}
BIT_STRING { \`00\` \`${signatureValue_hex}\` }
}
EOF
}
  cat <<EOF
-----BEGIN CERTIFICATE-----
$(generate_base64_code)
-----END CERTIFICATE-----
EOF
}

################################################################################
#
# We are making sure that our functions are working as they should.
# WE DON'T CHANGE ANYTHING. certificates should be properly validated.
#
################################################################################
mkdir "test_functions"

extract_tbsCertificate "${base_rsa_sha256}"
specify_sha="sha256"
sign_tbsCertificate_rsa
test_rsa_sha256="$(construct_new_cert)"
ossl_extract_cert "${test_rsa_sha256}" "test_functions/test_rsa_sha256.cer"
echo "test_rsa_sha256"

extract_tbsCertificate "${base_rsapss_sha384_sha384_48}"
specify_sha="sha384"; specify_mgf1_sha="sha384"; saltLength="48"
sign_tbsCertificate_rsapss
test_rsapss_sha384_sha384_48="$(construct_new_cert)"
ossl_extract_cert "${test_rsapss_sha384_sha384_48}" "test_functions/test_rsapss_sha384_sha384_48.cer"
echo "test_rsapss_sha384_sha384_48"

echo "let's go ..."
echo "------------"

unset test_rsa_sha256 test_rsapss_sha384_sha384_48
################################################################################
#
# NOW WE ARE GOING TO CHANGE SOME THINGS:
#
################################################################################
mkdir "invalid_certs"
# or "structural invalid", see:
# rsa_sha1_VS_sha1ABSENT_VS_rsa_sha1.cer / rsa_sha256_VS_sha256ABSENT_VS_sha_256.cer


#  tbsCertificate      md5
#  signatureAlgorithm  sha1
#  signatureValue      sha1
extract_tbsCertificate "${base_rsa_md5}"
specify_sha="sha1"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.5 } NULL {} }'
rsa_md5_VS_rsa_sha1="$(construct_new_cert)"
ossl_extract_cert "${rsa_md5_VS_rsa_sha1}" "invalid_certs/rsa_md5_VS_rsa_sha1.cer"
echo "rsa_md5_VS_rsa_sha1"

#  tbsCertificate      md5
#  signatureAlgorithm  dsa-with-sha1
#  signatureValue      sha384
extract_tbsCertificate "${base_rsa_md5}"
specify_sha="sha384"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10040.4.3 } }'
rsa_md5_VS_sha1DSA_VS_rsa_sha384="$(construct_new_cert)"
ossl_extract_cert "${rsa_md5_VS_sha1DSA_VS_rsa_sha384}" "invalid_certs/rsa_md5_VS_sha1DSA_VS_rsa_sha384.cer"
echo "rsa_md5_VS_sha1DSA_VS_rsa_sha384"

#  tbsCertificate      md5
#  signatureAlgorithm  md5 ABSENT
#  signatureValue      sha1
extract_tbsCertificate "${base_rsa_md5}"
specify_sha="sha1"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.4 } }'
rsa_md5_VS_md5ABSENT_VS_rsa_sha1="$(construct_new_cert)"
ossl_extract_cert "${rsa_md5_VS_md5ABSENT_VS_rsa_sha1}" "invalid_certs/rsa_md5_VS_md5ABSENT_VS_rsa_sha1.cer"
echo "rsa_md5_VS_md5ABSENT_VS_rsa_sha1"

#  tbsCertificate      sha1
#  signatureAlgorithm  md5
#  signatureValue      sha1
extract_tbsCertificate "${base_rsa_sha1}"
specify_sha="sha1"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.4 } NULL {} }'
rsa_sha1_VS_md5_VS_rsa_sha1="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha1_VS_md5_VS_rsa_sha1}" "invalid_certs/rsa_sha1_VS_md5_VS_rsa_sha1.cer"
echo "rsa_sha1_VS_md5_VS_rsa_sha1"

#  tbsCertificate      sha1
#  signatureAlgorithm  sha1 ABSENT
#  signatureValue      sha1
extract_tbsCertificate "${base_rsa_sha1}"
specify_sha="sha1"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.5 } }'
rsa_sha1_VS_sha1ABSENT_VS_rsa_sha1="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha1_VS_sha1ABSENT_VS_rsa_sha1}" "invalid_certs/rsa_sha1_VS_sha1ABSENT_VS_rsa_sha1.cer"
echo "rsa_sha1_VS_sha1ABSENT_VS_rsa_sha1"

#  tbsCertificate      sha1
#  signatureAlgorithm  sha256 ABSENT
#  signatureValue      sha256
extract_tbsCertificate "${base_rsa_sha1}"
specify_sha="sha256"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.11 } }'
rsa_sha1_VS_sha256ABSENT_VS_rsa_sha256="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha1_VS_sha256ABSENT_VS_rsa_sha256}" "invalid_certs/rsa_sha1_VS_sha256ABSENT_VS_rsa_sha256.cer"
echo "rsa_sha1_VS_sha256ABSENT_VS_rsa_sha256"

#  tbsCertificate      sha1
#  signatureAlgorithm  rmd160
#  signatureValue      rmd160
extract_tbsCertificate "${base_rsa_sha1}"
specify_sha="rmd160"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.3.36.3.3.1.2 } NULL {} }'
rsa_sha1_VS_rmd160="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha1_VS_rmd160}" "invalid_certs/rsa_sha1_VS_rmd160.cer"
echo "rsa_sha1_VS_rmd160"

#  tbsCertificate      sha224
#  signatureAlgorithm  rmd160
#  signatureValue      sha224
extract_tbsCertificate "${base_rsa_sha224}"
specify_sha="sha224"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.3.36.3.3.1.2 } NULL {} }'
rsa_sha224_VS_rmd160_VS_rsa_sha224="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha224_VS_rmd160_VS_rsa_sha224}" "invalid_certs/rsa_sha224_VS_rmd160_VS_rsa_sha224.cer"
echo "rsa_sha224_VS_rmd160_VS_rsa_sha224"

#  tbsCertificate      sha224
#  signatureAlgorithm  sha512-224
#  signatureValue      sha512-224
extract_tbsCertificate "${base_rsa_sha224}"
specify_sha="sha512-224"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.15 } NULL {} }'
rsa_sha224_VS_sha512_224_VS_sha512_224="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha224_VS_sha512_224_VS_sha512_224}" "invalid_certs/rsa_sha224_VS_sha512_224_VS_sha512_224.cer"
echo "rsa_sha224_VS_sha512_224_VS_sha512_224"

#  tbsCertificate      sha224
#  signatureAlgorithm  sha3-224
#  signatureValue      sha3-224
extract_tbsCertificate "${base_rsa_sha224}"
specify_sha="sha3-224"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.13 } NULL {} }'
rsa_sha224_VS_sha3_224_VS_sha3_224="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha224_VS_sha3_224_VS_sha3_224}" "invalid_certs/rsa_sha224_VS_sha3_224_VS_sha3_224.cer"
echo "rsa_sha224_VS_sha3_224_VS_sha3_224"

#  tbsCertificate      sha256
#  signatureAlgorithm  sha1
#  signatureValue      sha256
extract_tbsCertificate "${base_rsa_sha256}"
specify_sha="sha256"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.5 } NULL {} }'
rsa_sha256_VS_sha1_VS_sha_256="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha256_VS_sha1_VS_sha_256}" "invalid_certs/rsa_sha256_VS_sha1_VS_sha_256.cer"
echo "rsa_sha256_VS_sha1_VS_sha_256"

#  tbsCertificate      sha256
#  signatureAlgorithm  sha256 ABSENT
#  signatureValue      sha256
extract_tbsCertificate "${base_rsa_sha256}"
specify_sha="sha256"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.11 } }'
rsa_sha256_VS_sha256ABSENT_VS_sha_256="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha256_VS_sha256ABSENT_VS_sha_256}" "invalid_certs/rsa_sha256_VS_sha256ABSENT_VS_sha_256.cer"
echo "rsa_sha256_VS_sha256ABSENT_VS_sha_256"

#  tbsCertificate      sha256
#  signatureAlgorithm  RSA-SHA3-384 ABSENT
#  signatureValue      RSASSA-PSS sha512/sha512/0
extract_tbsCertificate "${base_rsa_sha256}"
specify_sha="sha512"; specify_mgf1_sha="sha512"; saltLength="0"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.15 } }'
rsa_sha256_VS_sha3_384ABSENT_VS_rsapss512_512_0="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha256_VS_sha3_384ABSENT_VS_rsapss512_512_0}" "invalid_certs/rsa_sha256_VS_sha3_384ABSENT_VS_rsapss512_512_0.cer"
echo "rsa_sha256_VS_sha3_384ABSENT_VS_rsapss512_512_0"

#  tbsCertificate      sha256
#  signatureAlgorithm  md5
#  signatureValue      md5
extract_tbsCertificate "${base_rsa_sha256}"
specify_sha="md5"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.4 } NULL {} }'
rsa_sha256_VS_md5="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha256_VS_md5}" "invalid_certs/rsa_sha256_VS_md5.cer"
echo "rsa_sha256_VS_md5"

#  tbsCertificate      sha384
#  signatureAlgorithm  dsa-with-sha384
#  signatureValue      RSA-SHA3-384
extract_tbsCertificate "${base_rsa_sha384}"
specify_sha="sha3-384"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.3 } }'
rsa_sha384_VS_dsa384_VS_sha3_384="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha384_VS_dsa384_VS_sha3_384}" "invalid_certs/rsa_sha384_VS_dsa384_VS_sha3_384.cer"
echo "rsa_sha384_VS_dsa384_VS_sha3_384"

#  tbsCertificate      sha384
#  signatureAlgorithm  RSA-SHA3-384
#  signatureValue      RSASSA-PSS sha256/sha1/32
extract_tbsCertificate "${base_rsa_sha384}"
specify_sha="sha256"; specify_mgf1_sha="sha1"; saltLength="32"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.15 } NULL {} }'
rsa_sha384_VS_sha3_384_VS_rsapss256_1_32="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha384_VS_sha3_384_VS_rsapss256_1_32}" "invalid_certs/rsa_sha384_VS_sha3_384_VS_rsapss256_1_32.cer"
echo "rsa_sha384_VS_sha3_384_VS_rsapss256_1_32"

#  tbsCertificate      sha384
#  signatureAlgorithm  ecdsa-with-SHA384
#  signatureValue      sha384
extract_tbsCertificate "${base_rsa_sha384}"
specify_sha="sha384"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10045.4.3.3 } }'
rsa_sha384_VS_ecdsa_384_VS_sha384="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha384_VS_ecdsa_384_VS_sha384}" "invalid_certs/rsa_sha384_VS_ecdsa_384_VS_sha384.cer"
echo "rsa_sha384_VS_ecdsa_384_VS_sha384"

#  tbsCertificate      sha512
#  signatureAlgorithm  sha1
#  signatureValue      sha1
extract_tbsCertificate "${base_rsa_sha512}"
specify_sha="sha1"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.5 } NULL {} }'
rsa_sha512_VS_sha1="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha512_VS_sha1}" "invalid_certs/rsa_sha512_VS_sha1.cer"
echo "rsa_sha512_VS_sha1"

#  tbsCertificate      sha512
#  signatureAlgorithm  md5
#  signatureValue      sha512
extract_tbsCertificate "${base_rsa_sha512}"
specify_sha="sha512"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.4 } NULL {} }'
rsa_sha512_VS_md5_VS_sha512="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha512_VS_md5_VS_sha512}" "invalid_certs/rsa_sha512_VS_md5_VS_sha512.cer"
echo "rsa_sha512_VS_md5_VS_sha512"

#  tbsCertificate      sha512
#  signatureAlgorithm  sha224
#  signatureValue      RSASSA-PSS sha256/sha224/32
extract_tbsCertificate "${base_rsa_sha512}"
specify_sha="sha256"; specify_mgf1_sha="sha224"; saltLength="32"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.14 } NULL {} }'
rsa_sha512_VS_sha224_VS_rsapss256_224_32="$(construct_new_cert)"
ossl_extract_cert "${rsa_sha512_VS_sha224_VS_rsapss256_224_32}" "invalid_certs/rsa_sha512_VS_sha224_VS_rsapss256_224_32.cer"
echo "rsa_sha512_VS_sha224_VS_rsapss256_224_32"

#  tbsCertificate      RSASSA-PSS sha1/sha1/0
#  signatureAlgorithm  ripemd160WithRSA ABSENT
#  signatureValue      RSASSA-PSS sha1/sha1/20
extract_tbsCertificate "${base_rsapss_sha1_sha1_0}"
specify_sha="sha1"; specify_mgf1_sha="sha1"; saltLength="0"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.3.36.3.3.1.2 } }'
rsapss1_1_0_VS_rmd160_VS_rsapss1_1_20="$(construct_new_cert)"
ossl_extract_cert "${rsapss1_1_0_VS_rmd160_VS_rsapss1_1_20}" "invalid_certs/rsapss1_1_0_VS_rmd160_VS_rsapss1_1_20.cer"
echo "rsapss1_1_0_VS_rmd160_VS_rsapss1_1_20"

#  tbsCertificate      RSASSA-PSS sha1/sha1/20
#  signatureAlgorithm  RSASSA-PSS sha1/sha1/20
#  signatureValue      RSASSA-PSS sha224/sha256/0
extract_tbsCertificate "${base_rsapss_sha1_sha1_20}"
specify_sha="sha224"; specify_mgf1_sha="sha256"; saltLength="0"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE {} }'
rsapss1_1_20_VS_rsapss1_1_20_VS_rsapss224_256_0="$(construct_new_cert)"
ossl_extract_cert "${rsapss1_1_20_VS_rsapss1_1_20_VS_rsapss224_256_0}" "invalid_certs/rsapss1_1_20_VS_rsapss1_1_20_VS_rsapss224_256_0.cer"
echo "rsapss1_1_20_VS_rsapss1_1_20_VS_rsapss224_256_0"

#  tbsCertificate      RSASSA-PSS sha1/sha384/234
#  signatureAlgorithm  ed448
#  signatureValue      sha256
extract_tbsCertificate "${base_rsapss_sha1_sha384_234}"
specify_sha="sha256"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.3.101.113 } }'
rsapss1_384_234_VS_ed448_VS_rsa_sha256="$(construct_new_cert)"
ossl_extract_cert "${rsapss1_384_234_VS_ed448_VS_rsa_sha256}" "invalid_certs/rsapss1_384_234_VS_ed448_VS_rsa_sha256.cer"
echo "rsapss1_384_234_VS_ed448_VS_rsa_sha256"

#  tbsCertificate      RSASSA-PSS sha224/sha224/0
#  signatureAlgorithm  RSASSA-PSS sha224/sha224/28
#  signatureValue      RSASSA-PSS sha1/sha224/234
extract_tbsCertificate "${base_rsapss_sha224_sha224_0}"
specify_sha="sha1"; specify_mgf1_sha="sha224"; saltLength="234"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.4 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.4 } NULL {} } } } [2] { INTEGER { 28 } } } }'
rsapss224_224_0_VS_rsapss224_224_28_VS_rsapss1_224_234="$(construct_new_cert)"
ossl_extract_cert "${rsapss224_224_0_VS_rsapss224_224_28_VS_rsapss1_224_234}" "invalid_certs/rsapss224_224_0_VS_rsapss224_224_28_VS_rsapss1_224_234.cer"
echo "rsapss224_224_0_VS_rsapss224_224_28_VS_rsapss1_224_234"

#  tbsCertificate      RSASSA-PSS sha224/sha224/28
#  signatureAlgorithm  RSASSA-PSS sha224/sha224/28
#  signatureValue      sha224
extract_tbsCertificate "${base_rsapss_sha224_sha224_28}"
specify_sha="sha224"
sign_tbsCertificate_rsa
rsapss224_224_28_VS_rsapss224_224_28_VS_sha224="$(construct_new_cert)"
ossl_extract_cert "${rsapss224_224_28_VS_rsapss224_224_28_VS_sha224}" "invalid_certs/rsapss224_224_28_VS_rsapss224_224_28_VS_sha224.cer"
echo "rsapss224_224_28_VS_rsapss224_224_28_VS_sha224"

#  tbsCertificate      RSASSA-PSS sha224/sha1/226
#  signatureAlgorithm  dsa-with-sha224
#  signatureValue      sha3-224
extract_tbsCertificate "${base_rsapss_sha224_sha1_226}"
specify_sha="sha3-224"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.1 } }'
rsapss224_1_226_VS_dsa224_VS_sha3_224="$(construct_new_cert)"
ossl_extract_cert "${rsapss224_1_226_VS_dsa224_VS_sha3_224}" "invalid_certs/rsapss224_1_226_VS_dsa224_VS_sha3_224.cer"
echo "rsapss224_1_226_VS_dsa224_VS_sha3_224"

#  tbsCertificate      RSASSA-PSS sha256/sha256/0
#  signatureAlgorithm  RSASSA-PSS sha256/sha256/0
#  signatureValue      RSASSA-PSS sha256/sha256/32
extract_tbsCertificate "${base_rsapss_sha256_sha256_0}"
specify_sha="sha256"; specify_mgf1_sha="sha256"; saltLength="32"
sign_tbsCertificate_rsapss
rsapss256_256_0_VS_rsapss256_256_0_VS_rsapss256_256_32="$(construct_new_cert)"
ossl_extract_cert "${rsapss256_256_0_VS_rsapss256_256_0_VS_rsapss256_256_32}" "invalid_certs/rsapss256_256_0_VS_rsapss256_256_0_VS_rsapss256_256_32.cer"
echo "rsapss256_256_0_VS_rsapss256_256_0_VS_rsapss256_256_32"

#  tbsCertificate      RSASSA-PSS sha256/sha256/0
#  signatureAlgorithm  RSASSA-PSS sha256/sha256/0 ABSENT
#  signatureValue      RSASSA-PSS sha256/sha256/32
extract_tbsCertificate "${base_rsapss_sha256_sha256_0}"
specify_sha="sha256"; specify_mgf1_sha="sha256"; saltLength="32"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.1 } } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.1 } } } } [2] { INTEGER { 0 } } } }'
rsapss256_256_0_VS_rsapss256_256_0ABSENT_VS_rsapss256_256_32="$(construct_new_cert)"
ossl_extract_cert "${rsapss256_256_0_VS_rsapss256_256_0ABSENT_VS_rsapss256_256_32}" "invalid_certs/rsapss256_256_0_VS_rsapss256_256_0ABSENT_VS_rsapss256_256_32.cer"
echo "rsapss256_256_0_VS_rsapss256_256_0ABSENT_VS_rsapss256_256_32"

#  tbsCertificate      RSASSA-PSS sha256/sha256/32
#  signatureAlgorithm  RSASSA-PSS sha224/sha224/28
#  signatureValue      RSASSA-PSS sha256/sha256/32
extract_tbsCertificate "${base_rsapss_sha256_sha256_32}"
specify_sha="sha256"; specify_mgf1_sha="sha256"; saltLength="32"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.4 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.4 } NULL {} } } } [2] { INTEGER { 28 } } } }'
rsapss256_256_32_VS_rsapss224_224_28_VS_rsapss256_256_32="$(construct_new_cert)"
ossl_extract_cert "${rsapss256_256_32_VS_rsapss224_224_28_VS_rsapss256_256_32}" "invalid_certs/rsapss256_256_32_VS_rsapss224_224_28_VS_rsapss256_256_32.cer"
echo "rsapss256_256_32_VS_rsapss224_224_28_VS_rsapss256_256_32"

#  tbsCertificate      RSASSA-PSS sha256/sha256/32
#  signatureAlgorithm  RSASSA-PSS sha256/sha256/32
#  signatureValue      sha256
extract_tbsCertificate "${base_rsapss_sha256_sha256_32}"
specify_sha="sha256"
sign_tbsCertificate_rsa
rsapss256_256_32_VS_rsapss256_256_32_VS_sha256="$(construct_new_cert)"
ossl_extract_cert "${rsapss256_256_32_VS_rsapss256_256_32_VS_sha256}" "invalid_certs/rsapss256_256_32_VS_rsapss256_256_32_VS_sha256.cer"
echo "rsapss256_256_32_VS_rsapss256_256_32_VS_sha256"

#  tbsCertificate      RSASSA-PSS sha256/sha384/222
#  signatureAlgorithm  RSASSA-PSS sha256/sha384/222
#  signatureValue      RSASSA-PSS sha512/sha1/64
extract_tbsCertificate "${base_rsapss_sha256_sha384_222}"
specify_sha="sha512"; specify_mgf1_sha="sha1"; saltLength="64"
sign_tbsCertificate_rsapss
rsapss256_384_222_VS_rsapss256_384_222_VS_rsapss512_1_64="$(construct_new_cert)"
ossl_extract_cert "${rsapss256_384_222_VS_rsapss256_384_222_VS_rsapss512_1_64}" "invalid_certs/rsapss256_384_222_VS_rsapss256_384_222_VS_rsapss512_1_64.cer"
echo "rsapss256_384_222_VS_rsapss256_384_222_VS_rsapss512_1_64"

#  tbsCertificate      RSASSA-PSS sha256/sha384/222
#  signatureAlgorithm  RSA-SHA3-256
#  signatureValue      RSA-SHA3-256
extract_tbsCertificate "${base_rsapss_sha256_sha384_222}"
specify_sha="sha3-256"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.14 } NULL {} }'
rsapss256_384_222_VS_sha3_256_VS_sha3_256="$(construct_new_cert)"
ossl_extract_cert "${rsapss256_384_222_VS_sha3_256_VS_sha3_256}" "invalid_certs/rsapss256_384_222_VS_sha3_256_VS_sha3_256.cer"
echo "rsapss256_384_222_VS_sha3_256_VS_sha3_256"

#  tbsCertificate      RSASSA-PSS sha384/sha384/0
#  signatureAlgorithm  ecdsa-with-SHA384
#  signatureValue      RSASSA-PSS sha384/sha384/0
extract_tbsCertificate "${base_rsapss_sha384_sha384_0}"
specify_sha="sha384"; specify_mgf1_sha="sha384"; saltLength="0"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10045.4.3.3 } }'
rsapss384_384_0_VS_ecdsa384_VS_rsapss384_384_0="$(construct_new_cert)"
ossl_extract_cert "${rsapss384_384_0_VS_ecdsa384_VS_rsapss384_384_0}" "invalid_certs/rsapss384_384_0_VS_ecdsa384_VS_rsapss384_384_0.cer"
echo "rsapss384_384_0_VS_ecdsa384_VS_rsapss384_384_0"

#  tbsCertificate      RSASSA-PSS sha384/sha384/48
#  signatureAlgorithm  dsa-with-sha384
#  signatureValue      RSASSA-PSS sha384/sha256/0
extract_tbsCertificate "${base_rsapss_sha384_sha384_48}"
specify_sha="sha384"; specify_mgf1_sha="sha256"; saltLength="0"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.3 } }'
rsapss384_384_48_VS_dsa384_VS_rsapss384_256_0="$(construct_new_cert)"
ossl_extract_cert "${rsapss384_384_48_VS_dsa384_VS_rsapss384_256_0}" "invalid_certs/rsapss384_384_48_VS_dsa384_VS_rsapss384_256_0.cer"
echo "rsapss384_384_48_VS_dsa384_VS_rsapss384_256_0"

#  tbsCertificate      RSASSA-PSS sha384/sha224/206
#  signatureAlgorithm  RSASSA-PSS sha384/sha256/206
#  signatureValue      RSASSA-PSS sha384/sha256/0
extract_tbsCertificate "${base_rsapss_sha384_sha224_206}"
specify_sha="sha384"; specify_mgf1_sha="sha256"; saltLength="0"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.2 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.1 } NULL {} } } } [2] { INTEGER { 206 } } } }'
rsapss384_224_206_VS_rsapss384_256_206_VS_rsapss384_256_0="$(construct_new_cert)"
ossl_extract_cert "${rsapss384_224_206_VS_rsapss384_256_206_VS_rsapss384_256_0}" "invalid_certs/rsapss384_224_206_VS_rsapss384_256_206_VS_rsapss384_256_0.cer"
echo "rsapss384_224_206_VS_rsapss384_256_206_VS_rsapss384_256_0"

#  tbsCertificate      RSASSA-PSS sha512/sha512/0
#  signatureAlgorithm  RSASSA-PSS sha512/sha512/190
#  signatureValue      RSASSA-PSS sha512/sha512/190
extract_tbsCertificate "${base_rsapss_sha512_sha512_0}"
specify_sha="sha512"; specify_mgf1_sha="sha512"; saltLength="190"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.3 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.3 } NULL {} } } } [2] { INTEGER { 190 } } } }'
rsapss512_512_0_VS_rsapss512_512_190="$(construct_new_cert)"
ossl_extract_cert "${rsapss512_512_0_VS_rsapss512_512_190}" "invalid_certs/rsapss512_512_0_VS_rsapss512_512_190.cer"
echo "rsapss512_512_0_VS_rsapss512_512_190"

#  tbsCertificate      RSASSA-PSS sha512/sha512/64
#  signatureAlgorithm  sha1
#  signatureValue      sha1
extract_tbsCertificate "${base_rsapss_sha512_sha512_64}"
specify_sha="sha1"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.5 } NULL {} }'
rsapss512_512_64_VS_rsa_sha1="$(construct_new_cert)"
ossl_extract_cert "${rsapss512_512_64_VS_rsa_sha1}" "invalid_certs/rsapss512_512_64_VS_rsa_sha1.cer"
echo "rsapss512_512_64_VS_rsa_sha1"

#  tbsCertificate      RSASSA-PSS sha512/sha512/64
#  signatureAlgorithm  RSASSA-PSS sha512/sha512/0
#  signatureValue      RSASSA-PSS sha512/sha512/0
extract_tbsCertificate "${base_rsapss_sha512_sha512_64}"
specify_sha="sha512"; specify_mgf1_sha="sha512"; saltLength="0"
sign_tbsCertificate_rsapss
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.3 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.3 } NULL {} } } } [2] { INTEGER { 0 } } } }'
rsapss512_512_64_VS_rsapss512_512_0="$(construct_new_cert)"
ossl_extract_cert "${rsapss512_512_64_VS_rsapss512_512_0}" "invalid_certs/rsapss512_512_64_VS_rsapss512_512_0.cer"
echo "rsapss512_512_64_VS_rsapss512_512_0"

#  tbsCertificate      RSASSA-PSS sha512/sha512/64
#  signatureAlgorithm  RSA-SHA3-512
#  signatureValue      sha512-256
extract_tbsCertificate "${base_rsapss_sha512_sha512_64}"
specify_sha="sha512-256"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.16 } NULL {} }'
rsapss512_512_64_VS_sha3_512_VS_sha512_256="$(construct_new_cert)"
ossl_extract_cert "${rsapss512_512_64_VS_sha3_512_VS_sha512_256}" "invalid_certs/rsapss512_512_64_VS_sha3_512_VS_sha512_256.cer"
echo "rsapss512_512_64_VS_sha3_512_VS_sha512_256"

#  tbsCertificate      RSASSA-PSS sha512/sha256/190
#  signatureAlgorithm  sha512
#  signatureValue      sha512
extract_tbsCertificate "${base_rsapss_sha512_sha256_190}"
specify_sha="sha512"
sign_tbsCertificate_rsa
ex_signatureAlgorithm_text='SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.13 } NULL {} }'
rsapss512_256_190_VS_rsa_sha512="$(construct_new_cert)"
ossl_extract_cert "${rsapss512_256_190_VS_rsa_sha512}" "invalid_certs/rsapss512_256_190_VS_rsa_sha512.cer"
echo "rsapss512_256_190_VS_rsa_sha512"


#( set -o posix ; set ) > "posix.txt"

openssl version -a > "openssl_version.txt"

cat <<EOF > "invalid_certs/checksums.sha1"
$(cd "invalid_certs" && find . -type f -exec sha1sum {} \; | sort -k 2)
EOF

cat <<EOF > "checksums.sha256"
$(find . -type f -exec sha256sum {} \; | sort -k 2)
EOF

#
# dsa-with-sha1
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10040.4.3 } }'
#
# dsa-with-sha224
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.1 } }'
#
# dsa-with-sha256
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.2 } }'
#
# dsa-with-sha384
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.3 } }'
#
# dsa-with-sha512
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.4 } }'
#
# md5WithRSAEncryption
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.4 } NULL {} }'
#
# ripemd160WithRSA
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.3.36.3.3.1.2 } NULL {} }'
#
# sha1WithRSAEncryption
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.5 } NULL {} }'
#
# sha224WithRSAEncryption
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.14 } NULL {} }'
#
# sha512-224WithRSAEncryption
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.15 } NULL {} }'
#
# sha256WithRSAEncryption
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.11 } NULL {} }'
#
# sha512-256WithRSAEncryption
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.16 } NULL {} }'
#
# sha384WithRSAEncryption
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.12 } NULL {} }'
#
# sha512WithRSAEncryption
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.13 } NULL {} }'
#
# RSA-SHA3-224
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.13 } NULL {} }'
#
# RSA-SHA3-256
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.14 } NULL {} }'
#
# RSA-SHA3-384
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.15 } NULL {} }'
#
# RSA-SHA3-512
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.16 } NULL {} }'
#
# RSASSA-PSS sha1/sha1/20
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE {} }'
#
# RSASSA-PSS sha224/sha224/28
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.4 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.4 } NULL {} } } } [2] { INTEGER { 28 } } } }'
#
# RSASSA-PSS sha256/sha256/32
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.1 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.1 } NULL {} } } } [2] { INTEGER { 32 } } } }'
#
# RSASSA-PSS sha384/sha384/48
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.2 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.2 } NULL {} } } } [2] { INTEGER { 48 } } } }'
#
# RSASSA-PSS sha512/sha512/64
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.10 } SEQUENCE { [0] { SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.3 } NULL {} } } [1] { SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.113549.1.1.8 } SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.2.3 } NULL {} } } } [2] { INTEGER { 64 } } } }'
#
# ecdsa-with-SHA1
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10045.4.1 } }'
#
# ecdsa-with-SHA224
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10045.4.3.1 } }'
#
# ecdsa-with-SHA256
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10045.4.3.2 } }'
#
# ecdsa-with-SHA384
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10045.4.3.3 } }'
#
# ecdsa-with-SHA512
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.2.840.10045.4.3.4 } }'
#
# ecdsa_with_SHA3-224
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.9 } }'
#
# ecdsa_with_SHA3-256
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.10 } }'
#
# ecdsa_with_SHA3-384
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.11 } }'
#
# ecdsa_with_SHA3-512
# 'SEQUENCE { OBJECT_IDENTIFIER { 2.16.840.1.101.3.4.3.12 } }'
#
# ed448
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.3.101.113 } }'
#
# ed25519
# 'SEQUENCE { OBJECT_IDENTIFIER { 1.3.101.112 } }'
#
echo "-----"
echo "DONE."
#
# EOF
