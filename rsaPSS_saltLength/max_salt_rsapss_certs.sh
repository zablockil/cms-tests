#!/bin/bash
# RUN:
# $ ./max_salt_rsapss_certs.sh


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
	commonName=${keySizeInBits} ROOT
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
	commonName=${saltLength_max}_salt_${specify_sha} USER ${saltLength_max_unrounded}
	serialNumber=${keySizeInBits}-$(serial_alfanum5)-$(serial_num5)
[ subject_alt_name ]
	email.0=user_$(serial_hex5)_$(serial_num5)@rsapsstest.com
[ x509_smime_user_ext ]
	basicConstraints=critical,CA:FALSE
	keyUsage=critical,digitalSignature,keyAgreement
	extendedKeyUsage=emailProtection
	subjectKeyIdentifier=hash
	authorityKeyIdentifier=keyid
	subjectAltName=@subject_alt_name
EOF
}

# we care about a relatively small end-entity certificate
user_key_flush="$(openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1)"

csr_user () {
  openssl req -new -config <(echo "${prepare_x509_config_user}") -key <(echo "${user_key_flush}")
}

genpkey_rsa_key () {
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:${1}
}

# root certificate is not RSA-PSS signed
make_self_signed_root_cert () {
  openssl req -new -x509 -days 36524 -set_serial "0x$(custom_cert_serial)" -config <(echo "${prepare_x509_config_root}") -key <(echo "${ca_key_flush}") -sha256
}

make_user_rsapss_max_salt_cert () {
  openssl x509 -req -days 36523 -set_serial "0x$(custom_cert_serial)" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "${prepare_x509_config_user}") -extensions x509_smime_user_ext -sigopt rsa_padding_mode:pss -"${specify_sha}" -sigopt rsa_mgf1_md:"${specify_sha}" -sigopt rsa_pss_saltlen:"${saltLength_max}"
}

mkdir "sha1"
mkdir "sha224"
mkdir "sha256"
mkdir "sha384"
mkdir "sha512"

detect_rsapss_salt () {
  if [ "$1" == "sha1" ]; then
    echo "20"
  fi
  if [ "$1" == "sha224" ]; then
    echo "28"
  fi
  if [ "$1" == "sha256" ]; then
    echo "32"
  fi
  if [ "$1" == "sha384" ]; then
    echo "48"
  fi
  if [ "$1" == "sha512" ]; then
    echo "64"
  fi
}

# https://developer.mozilla.org/en-US/docs/Web/API/RsaPssParams
# digestSizeInBytes
# sha1           20
# sha224         28
# sha256         32
# sha384         48
# sha512         64
# the maximum size of saltLength:
# ((keySizeInBits - 1) / 8) - digestSizeInBytes - 2
#
# rsa4096/sha512:
# ((4096 - 1) / 8) - 64 - 2 = 446
#
# https://www.gnu.org/software/gawk/manual/html_node/Round-Function.html

rsapss_max_salt_cert () {
  keySizeInBits="${1}"
  specify_sha="${2}"
  digestSizeInBytes="$(detect_rsapss_salt ${specify_sha})"
  saltLength_max_unrounded="$(awk -v var1="${keySizeInBits}" -v var2="${digestSizeInBytes}" 'BEGIN {print((var1 - 1) / 8) - var2 - 2}')"
  saltLength_max="$(echo ${saltLength_max_unrounded} | numfmt --format="%.0f" --round=up)"
  ca_key_flush="$(genpkey_rsa_key ${keySizeInBits})"
  prepare_x509_config_root="$(x509v3_config_root)"
  ca_cert_flush="$(make_self_signed_root_cert)"
  prepare_x509_config_user="$(x509v3_config_user)"
  temp_csr="$(csr_user)"
  cert_user="$(make_user_rsapss_max_salt_cert)"
  echo "${cert_user}" > "${specify_sha}/pair_${keySizeInBits}.pem"
  echo "${ca_cert_flush}" >> "${specify_sha}/pair_${keySizeInBits}.pem"
  # may be useful:
  #echo "${ca_key_flush}" > "${specify_sha}/key_${keySizeInBits}.key"
  # print info:
  #openssl x509 -noout -text -in <(echo "${cert_user}") | awk '{ sub(/[ \t]+$/, ""); print }' > "${specify_sha}/pair_${keySizeInBits}.pem.txt"
  #openssl x509 -noout -text -in <(echo "${ca_cert_flush}") | awk '{ sub(/[ \t]+$/, ""); print }' >> "${specify_sha}/pair_${keySizeInBits}.pem.txt"
}

cat <<EOF
################################################################################
################################################################################
##
##  please wait...
##
################################################################################
################################################################################

EOF

for i in {2048..4096}; do rsapss_max_salt_cert ${i} sha1; done
for i in {2048..4096}; do rsapss_max_salt_cert ${i} sha224; done
for i in {2048..4096}; do rsapss_max_salt_cert ${i} sha256; done
for i in {2048..4096}; do rsapss_max_salt_cert ${i} sha384; done
for i in {2048..4096}; do rsapss_max_salt_cert ${i} sha512; done

openssl version -a > "openssl_version.txt"

cat <<EOF > "checksums.sha256"
$(find . -type f -exec sha256sum {} \; | sort -k 2)
EOF

cat <<EOF

################################################################################
################################################################################
##
##  done
##
################################################################################
################################################################################
EOF
