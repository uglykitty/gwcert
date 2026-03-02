#include "certmanager.h"
#include "pkistore.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QRandomGenerator>
#include <QTextStream>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pkcs12.h>
#include <openssl/asn1.h>

#include <memory>
#include <cstring>

// ── helpers ────────────────────────────────────────────────────────────────
QString CertManager::s_lastError;

namespace {

struct BioDeleter   { void operator()(BIO *p)          const { BIO_free_all(p); } };
struct X509Deleter  { void operator()(X509 *p)         const { X509_free(p); } };
struct EvpKeyDel    { void operator()(EVP_PKEY *p)     const { EVP_PKEY_free(p); } };
struct ReqDeleter   { void operator()(X509_REQ *p)     const { X509_REQ_free(p); } };
struct BnDeleter    { void operator()(BIGNUM *p)       const { BN_free(p); } };
struct X509StoreDel { void operator()(X509_STORE *p)   const { X509_STORE_free(p); } };
struct X509StoreCtxDel { void operator()(X509_STORE_CTX *p) const { X509_STORE_CTX_free(p); } };
struct Pkcs12Del    { void operator()(PKCS12 *p)       const { PKCS12_free(p); } };

using BioPtr   = std::unique_ptr<BIO, BioDeleter>;
using X509Ptr  = std::unique_ptr<X509, X509Deleter>;
using KeyPtr   = std::unique_ptr<EVP_PKEY, EvpKeyDel>;
using ReqPtr   = std::unique_ptr<X509_REQ, ReqDeleter>;
using BnPtr    = std::unique_ptr<BIGNUM, BnDeleter>;

// Password callback that never prompts on stdin.
// If userdata carries a passphrase, copy it; otherwise return 0 (fail)
// so OpenSSL won't block waiting for console input.
int noPromptPasswordCb(char *buf, int size, int /*rwflag*/, void *userdata) {
    if (!userdata) return 0;               // no passphrase → fail immediately
    const QByteArray *pp = static_cast<const QByteArray*>(userdata);
    if (pp->isEmpty()) return 0;
    int len = qMin(size, (int)pp->size());
    std::memcpy(buf, pp->constData(), len);
    return len;
}

// Convenience: read a PEM private key from file (with optional passphrase)
KeyPtr loadKey(const QString &path, const QString &passphrase = {}) {
    BioPtr bio(BIO_new_file(path.toUtf8().constData(), "r"));
    if (!bio) return nullptr;
    QByteArray ppBytes = passphrase.toUtf8();
    EVP_PKEY *k = PEM_read_bio_PrivateKey(bio.get(), nullptr,
                                           noPromptPasswordCb,
                                           ppBytes.isEmpty() ? nullptr : &ppBytes);
    return KeyPtr(k);
}

// Read PEM X509 from file
X509Ptr loadCert(const QString &path) {
    BioPtr bio(BIO_new_file(path.toUtf8().constData(), "r"));
    if (!bio) return nullptr;
    X509 *c = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    return X509Ptr(c);
}

// Read PEM CSR from file
ReqPtr loadCSR(const QString &path) {
    BioPtr bio(BIO_new_file(path.toUtf8().constData(), "r"));
    if (!bio) return nullptr;
    X509_REQ *r = PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr);
    return ReqPtr(r);
}

// Set subject on X509 or X509_REQ name
void setSubjectFields(X509_NAME *name, const SubjectInfo &info) {
    auto add = [&](const char *field, const QString &val) {
        if (!val.isEmpty())
            X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8,
                                       reinterpret_cast<const unsigned char *>(val.toUtf8().constData()),
                                       -1, -1, 0);
    };
    add("C",  info.country);
    add("ST", info.state);
    add("L",  info.locality);
    add("O",  info.organization);
    add("OU", info.organizationUnit);
    add("CN", info.commonName);
    if (!info.email.isEmpty())
        add("emailAddress", info.email);
}

// Add SAN extension to a cert
bool addSanExtension(X509 *cert, X509 *issuer, const QStringList &sanList) {
    if (sanList.isEmpty()) return true;
    QString sanStr = sanList.join(",");
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_subject_alt_name,
                                                sanStr.toUtf8().constData());
    if (!ext) return false;
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return true;
}

// Convert ASN1_TIME to human readable string
QString asn1TimeToString(const ASN1_TIME *t) {
    if (!t) return {};
    BioPtr bio(BIO_new(BIO_s_mem()));
    ASN1_TIME_print(bio.get(), t);
    char buf[256];
    int len = BIO_read(bio.get(), buf, sizeof(buf) - 1);
    if (len <= 0) return {};
    buf[len] = '\0';
    return QString::fromUtf8(buf);
}

// Convert X509_NAME to one-line string
QString nameToString(X509_NAME *name) {
    if (!name) return {};
    BioPtr bio(BIO_new(BIO_s_mem()));
    X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    char buf[1024];
    int len = BIO_read(bio.get(), buf, sizeof(buf) - 1);
    if (len <= 0) return {};
    buf[len] = '\0';
    return QString::fromUtf8(buf);
}

// Generate a random serial number
bool setRandomSerial(X509 *cert) {
    BnPtr bn(BN_new());
    if (!bn || !BN_rand(bn.get(), 128, 0, 0)) return false;
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BN_to_ASN1_INTEGER(bn.get(), serial);
    return true;
}

// Set serial number from hex string
bool setHexSerial(X509 *cert, const QString &hexSerial) {
    BIGNUM *bn = nullptr;
    if (BN_hex2bn(&bn, hexSerial.toUtf8().constData()) == 0 || !bn)
        return false;
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BN_to_ASN1_INTEGER(bn, serial);
    BN_free(bn);
    return true;
}

} // anonymous namespace

// ── SubjectInfo ────────────────────────────────────────────────────────────
QString SubjectInfo::toOneLine() const {
    QStringList parts;
    if (!country.isEmpty())           parts << "C=" + country;
    if (!state.isEmpty())             parts << "ST=" + state;
    if (!locality.isEmpty())          parts << "L=" + locality;
    if (!organization.isEmpty())      parts << "O=" + organization;
    if (!organizationUnit.isEmpty())  parts << "OU=" + organizationUnit;
    if (!commonName.isEmpty())        parts << "CN=" + commonName;
    return parts.join(", ");
}

// ── Error helpers ──────────────────────────────────────────────────────────
void CertManager::setError(const QString &msg) { s_lastError = msg; }
void CertManager::setOpenSSLError(const QString &prefix) {
    unsigned long e = ERR_get_error();
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    s_lastError = prefix + ": " + QString::fromUtf8(buf);
}
QString CertManager::lastError() { return s_lastError; }

// ── Key Generation ─────────────────────────────────────────────────────────
bool CertManager::generateRSAKey(const QString &keyPath, int bits,
                                 const QString &passphrase) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) { setOpenSSLError("RSA ctx"); return false; }

    EVP_PKEY *pkey = nullptr;
    bool ok = false;
    do {
        if (EVP_PKEY_keygen_init(ctx) <= 0) break;
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) break;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) break;
        ok = true;
    } while (false);
    EVP_PKEY_CTX_free(ctx);

    if (!ok || !pkey) {
        setOpenSSLError("RSA keygen");
        return false;
    }

    BioPtr bio(BIO_new_file(keyPath.toUtf8().constData(), "w"));
    if (!bio) { EVP_PKEY_free(pkey); setError("Cannot open key file for writing"); return false; }

    if (!passphrase.isEmpty()) {
        QByteArray pp = passphrase.toUtf8();
        ok = PEM_write_bio_PrivateKey(bio.get(), pkey, EVP_aes_256_cbc(),
                                      reinterpret_cast<const unsigned char*>(pp.constData()),
                                      pp.size(), nullptr, nullptr) == 1;
    } else {
        ok = PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    }
    EVP_PKEY_free(pkey);
    if (!ok) setOpenSSLError("Write RSA key");
    return ok;
}

bool CertManager::generateECKey(const QString &keyPath, const QString &curveName,
                                const QString &passphrase) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) { setOpenSSLError("EC ctx"); return false; }

    EVP_PKEY *pkey = nullptr;
    bool ok = false;
    do {
        if (EVP_PKEY_keygen_init(pctx) <= 0) break;
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("group",
                        const_cast<char*>(curveName.toUtf8().constData()), 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) break;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) break;
        ok = true;
    } while (false);
    EVP_PKEY_CTX_free(pctx);

    if (!ok || !pkey) {
        setOpenSSLError("EC keygen");
        return false;
    }

    BioPtr bio(BIO_new_file(keyPath.toUtf8().constData(), "w"));
    if (!bio) { EVP_PKEY_free(pkey); setError("Cannot open key file"); return false; }

    if (!passphrase.isEmpty()) {
        QByteArray pp = passphrase.toUtf8();
        ok = PEM_write_bio_PrivateKey(bio.get(), pkey, EVP_aes_256_cbc(),
                                      reinterpret_cast<const unsigned char*>(pp.constData()),
                                      pp.size(), nullptr, nullptr) == 1;
    } else {
        ok = PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    }
    EVP_PKEY_free(pkey);
    if (!ok) setOpenSSLError("Write EC key");
    return ok;
}

// ── CA Certificate ─────────────────────────────────────────────────────────
bool CertManager::generateCACert(const QString &certPath,
                                 const QString &keyPath,
                                 const SubjectInfo &subject,
                                 int days,
                                 const QString &keyType,
                                 const QString &keyParam,
                                 const QString &passphrase)
{
    // Generate key if not existing
    if (!QFileInfo::exists(keyPath)) {
        bool keyOk = false;
        if (keyType.toUpper() == "EC")
            keyOk = generateECKey(keyPath, keyParam, passphrase);
        else
            keyOk = generateRSAKey(keyPath, keyParam.toInt(), passphrase);
        if (!keyOk) return false;
    }

    KeyPtr pkey = loadKey(keyPath, passphrase);
    if (!pkey) { setOpenSSLError("Load CA key"); return false; }

    X509Ptr cert(X509_new());
    if (!cert) { setOpenSSLError("X509_new"); return false; }

    X509_set_version(cert.get(), 2); // v3
    setRandomSerial(cert.get());

    // Validity
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), (long)days * 86400);

    // Subject = Issuer (self-signed)
    X509_NAME *name = X509_get_subject_name(cert.get());
    setSubjectFields(name, subject);
    X509_set_issuer_name(cert.get(), name);

    X509_set_pubkey(cert.get(), pkey.get());

    // Extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);

    auto addExt = [&](int nid, const char *value) {
        X509_EXTENSION *ext = X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value);
        if (ext) { X509_add_ext(cert.get(), ext, -1); X509_EXTENSION_free(ext); }
    };

    addExt(NID_basic_constraints, "critical,CA:TRUE");
    addExt(NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
    addExt(NID_subject_key_identifier, "hash");
    addExt(NID_authority_key_identifier, "keyid:always");

    // Sign
    if (X509_sign(cert.get(), pkey.get(), EVP_sha256()) == 0) {
        setOpenSSLError("Sign CA cert");
        return false;
    }

    BioPtr bio(BIO_new_file(certPath.toUtf8().constData(), "w"));
    if (!bio) { setError("Cannot write cert file"); return false; }
    PEM_write_bio_X509(bio.get(), cert.get());
    return true;
}

// ── CSR ────────────────────────────────────────────────────────────────────
bool CertManager::generateCSR(const QString &csrPath,
                               const QString &keyPath,
                               const SubjectInfo &subject,
                               const QStringList &sanList,
                               const QString &keyType,
                               const QString &keyParam,
                               const QString &passphrase)
{
    // Generate key if missing
    if (!QFileInfo::exists(keyPath)) {
        bool ok = false;
        if (keyType.toUpper() == "EC")
            ok = generateECKey(keyPath, keyParam, passphrase);
        else
            ok = generateRSAKey(keyPath, keyParam.toInt(), passphrase);
        if (!ok) return false;
    }

    KeyPtr pkey = loadKey(keyPath, passphrase);
    if (!pkey) { setOpenSSLError("Load key for CSR"); return false; }

    ReqPtr req(X509_REQ_new());
    X509_REQ_set_version(req.get(), 0);

    X509_NAME *name = X509_REQ_get_subject_name(req.get());
    setSubjectFields(name, subject);

    X509_REQ_set_pubkey(req.get(), pkey.get());

    // Add SAN as a requested extension
    if (!sanList.isEmpty()) {
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
        QString sanStr = sanList.join(",");

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, nullptr, nullptr, req.get(), nullptr, 0);
        X509_EXTENSION *ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_subject_alt_name,
                                                    sanStr.toUtf8().constData());
        if (ext) {
            sk_X509_EXTENSION_push(exts, ext);
            X509_REQ_add_extensions(req.get(), exts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }

    if (X509_REQ_sign(req.get(), pkey.get(), EVP_sha256()) == 0) {
        setOpenSSLError("Sign CSR");
        return false;
    }

    BioPtr bio(BIO_new_file(csrPath.toUtf8().constData(), "w"));
    if (!bio) { setError("Cannot write CSR file"); return false; }
    PEM_write_bio_X509_REQ(bio.get(), req.get());
    return true;
}

// ── Sign CSR ───────────────────────────────────────────────────────────────
bool CertManager::signCSR(const QString &csrPath,
                           const QString &caCertPath,
                           const QString &caKeyPath,
                           const QString &outCertPath,
                           int days,
                           bool isCA,
                           int pathLen,
                           const QStringList &sanList,
                           const QString &caKeyPassphrase)
{
    ReqPtr req = loadCSR(csrPath);
    if (!req) { setOpenSSLError("Load CSR"); return false; }

    X509Ptr caCert = loadCert(caCertPath);
    if (!caCert) { setOpenSSLError("Load CA cert"); return false; }

    KeyPtr caKey = loadKey(caKeyPath, caKeyPassphrase);
    if (!caKey) { setOpenSSLError("Load CA key"); return false; }

    // Verify CSR signature
    EVP_PKEY *reqKey = X509_REQ_get0_pubkey(req.get());
    if (X509_REQ_verify(req.get(), reqKey) != 1) {
        setError("CSR signature verification failed");
        return false;
    }

    X509Ptr cert(X509_new());
    X509_set_version(cert.get(), 2);
    setRandomSerial(cert.get());

    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), (long)days * 86400);

    // Subject from CSR, Issuer from CA
    X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(req.get()));
    X509_set_issuer_name(cert.get(), X509_get_subject_name(caCert.get()));
    X509_set_pubkey(cert.get(), reqKey);

    // Extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, caCert.get(), cert.get(), nullptr, nullptr, 0);

    auto addExt = [&](int nid, const char *value) {
        X509_EXTENSION *ext = X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value);
        if (ext) { X509_add_ext(cert.get(), ext, -1); X509_EXTENSION_free(ext); }
    };

    if (isCA) {
        QString bc = "critical,CA:TRUE";
        if (pathLen >= 0) bc += ",pathlen:" + QString::number(pathLen);
        addExt(NID_basic_constraints, bc.toUtf8().constData());
        addExt(NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
    } else {
        addExt(NID_basic_constraints, "critical,CA:FALSE");
        addExt(NID_key_usage, "critical,digitalSignature,keyEncipherment");
        addExt(NID_ext_key_usage, "serverAuth,clientAuth");
    }

    addExt(NID_subject_key_identifier, "hash");
    addExt(NID_authority_key_identifier, "keyid:always");

    // SAN: prefer explicit list, then try to copy from CSR
    QStringList effectiveSan = sanList;
    if (effectiveSan.isEmpty()) {
        // Try to extract SAN from CSR extensions
        STACK_OF(X509_EXTENSION) *reqExts = X509_REQ_get_extensions(req.get());
        if (reqExts) {
            for (int i = 0; i < sk_X509_EXTENSION_num(reqExts); i++) {
                X509_EXTENSION *ext = sk_X509_EXTENSION_value(reqExts, i);
                if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) == NID_subject_alt_name) {
                    X509_add_ext(cert.get(), ext, -1);
                }
            }
            sk_X509_EXTENSION_pop_free(reqExts, X509_EXTENSION_free);
        }
    } else {
        addSanExtension(cert.get(), caCert.get(), effectiveSan);
    }

    if (X509_sign(cert.get(), caKey.get(), EVP_sha256()) == 0) {
        setOpenSSLError("Sign cert");
        return false;
    }

    BioPtr bio(BIO_new_file(outCertPath.toUtf8().constData(), "w"));
    if (!bio) { setError("Cannot write output cert"); return false; }
    PEM_write_bio_X509(bio.get(), cert.get());
    return true;
}

// ── Server Certificate (convenience) ───────────────────────────────────────
bool CertManager::generateServerCert(const QString &certPath,
                                     const QString &keyPath,
                                     const QString &caCertPath,
                                     const QString &caKeyPath,
                                     const SubjectInfo &subject,
                                     int days,
                                     const QStringList &sanList,
                                     const QString &keyType,
                                     const QString &keyParam,
                                     const QString &passphrase)
{
    // Temporary CSR file
    QString csrPath = certPath + ".csr";

    if (!generateCSR(csrPath, keyPath, subject, sanList, keyType, keyParam, passphrase))
        return false;

    bool ok = signCSR(csrPath, caCertPath, caKeyPath, certPath, days, false, -1, sanList);
    QFile::remove(csrPath); // clean up
    return ok;
}

// ── Parse Certificate ──────────────────────────────────────────────────────
CertInfo CertManager::parseCert(const QString &certPath) {
    CertInfo info;
    X509Ptr cert = loadCert(certPath);
    if (!cert) { setOpenSSLError("Parse cert"); return info; }

    info.subject = nameToString(X509_get_subject_name(cert.get()));
    info.issuer  = nameToString(X509_get_issuer_name(cert.get()));

    // Serial
    {
        ASN1_INTEGER *serial = X509_get_serialNumber(cert.get());
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial, nullptr);
        if (bn) {
            char *hex = BN_bn2hex(bn);
            info.serial = QString::fromUtf8(hex);
            OPENSSL_free(hex);
            BN_free(bn);
        }
    }

    info.notBefore = asn1TimeToString(X509_get0_notBefore(cert.get()));
    info.notAfter  = asn1TimeToString(X509_get0_notAfter(cert.get()));

    // Signature algorithm
    {
        const X509_ALGOR *sigAlg = nullptr;
        X509_get0_signature(nullptr, &sigAlg, cert.get());
        if (sigAlg) {
            BioPtr bio(BIO_new(BIO_s_mem()));
            i2a_ASN1_OBJECT(bio.get(), sigAlg->algorithm);
            char buf[128];
            int len = BIO_read(bio.get(), buf, sizeof(buf)-1);
            if (len > 0) { buf[len] = '\0'; info.signatureAlgorithm = QString::fromUtf8(buf); }
        }
    }

    // Public key info
    {
        EVP_PKEY *pubkey = X509_get0_pubkey(cert.get());
        if (pubkey) {
            info.publicKeyBits = EVP_PKEY_bits(pubkey);
            int id = EVP_PKEY_id(pubkey);
            if (id == EVP_PKEY_RSA)       info.publicKeyAlgorithm = "RSA";
            else if (id == EVP_PKEY_EC)   info.publicKeyAlgorithm = "EC";
            else if (id == EVP_PKEY_ED25519) info.publicKeyAlgorithm = "Ed25519";
            else info.publicKeyAlgorithm = "Unknown";
        }
    }

    // Basic constraints
    {
        BASIC_CONSTRAINTS *bc = (BASIC_CONSTRAINTS*)X509_get_ext_d2i(cert.get(), NID_basic_constraints, nullptr, nullptr);
        if (bc) {
            info.isCA = bc->ca ? true : false;
            BASIC_CONSTRAINTS_free(bc);
        }
    }

    // SHA-256 fingerprint
    {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int n = 0;
        if (X509_digest(cert.get(), EVP_sha256(), md, &n)) {
            QStringList parts;
            for (unsigned int i = 0; i < n; i++)
                parts << QString("%1").arg(md[i], 2, 16, QChar('0')).toUpper();
            info.fingerprint = parts.join(":");
        }
    }

    // SAN
    {
        GENERAL_NAMES *sans = (GENERAL_NAMES*)X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr);
        if (sans) {
            for (int i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(sans, i);
                if (gen->type == GEN_DNS) {
                    const char *dns = (const char*)ASN1_STRING_get0_data(gen->d.dNSName);
                    info.sanEntries << "DNS:" + QString::fromUtf8(dns);
                } else if (gen->type == GEN_IPADD) {
                    // IP address
                    ASN1_OCTET_STRING *ip = gen->d.iPAddress;
                    if (ASN1_STRING_length(ip) == 4) {
                        const unsigned char *d = ASN1_STRING_get0_data(ip);
                        info.sanEntries << QString("IP:%1.%2.%3.%4").arg(d[0]).arg(d[1]).arg(d[2]).arg(d[3]);
                    }
                } else if (gen->type == GEN_EMAIL) {
                    const char *email = (const char*)ASN1_STRING_get0_data(gen->d.rfc822Name);
                    info.sanEntries << "email:" + QString::fromUtf8(email);
                }
            }
            GENERAL_NAMES_free(sans);
        }
    }

    // PEM text
    {
        BioPtr bio(BIO_new(BIO_s_mem()));
        X509_print_ex(bio.get(), cert.get(), 0, 0);
        char *data = nullptr;
        long len = BIO_get_mem_data(bio.get(), &data);
        if (len > 0)
            info.pemText = QString::fromUtf8(data, (int)len);
    }

    return info;
}

// ── Parse CSR ──────────────────────────────────────────────────────────────
CertInfo CertManager::parseCSR(const QString &csrPath) {
    CertInfo info;
    ReqPtr req = loadCSR(csrPath);
    if (!req) { setOpenSSLError("Parse CSR"); return info; }

    info.subject = nameToString(X509_REQ_get_subject_name(req.get()));

    EVP_PKEY *pubkey = X509_REQ_get0_pubkey(req.get());
    if (pubkey) {
        info.publicKeyBits = EVP_PKEY_bits(pubkey);
        int id = EVP_PKEY_id(pubkey);
        if (id == EVP_PKEY_RSA)       info.publicKeyAlgorithm = "RSA";
        else if (id == EVP_PKEY_EC)   info.publicKeyAlgorithm = "EC";
        else info.publicKeyAlgorithm = "Unknown";
    }

    // SAN from CSR extensions
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req.get());
    if (exts) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
            if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) == NID_subject_alt_name) {
                GENERAL_NAMES *sans = (GENERAL_NAMES*)X509V3_EXT_d2i(ext);
                if (sans) {
                    for (int j = 0; j < sk_GENERAL_NAME_num(sans); j++) {
                        GENERAL_NAME *gen = sk_GENERAL_NAME_value(sans, j);
                        if (gen->type == GEN_DNS) {
                            info.sanEntries << "DNS:" + QString::fromUtf8(
                                (const char*)ASN1_STRING_get0_data(gen->d.dNSName));
                        }
                    }
                    GENERAL_NAMES_free(sans);
                }
            }
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    // PEM text
    {
        BioPtr bio(BIO_new(BIO_s_mem()));
        X509_REQ_print_ex(bio.get(), req.get(), 0, 0);
        char *data = nullptr;
        long len = BIO_get_mem_data(bio.get(), &data);
        if (len > 0)
            info.pemText = QString::fromUtf8(data, (int)len);
    }

    return info;
}

// ── Verify Certificate ─────────────────────────────────────────────────────
QString CertManager::verifyCert(const QString &certPath, const QString &caCertPath) {
    X509Ptr cert = loadCert(certPath);
    if (!cert) return "Failed to load certificate file";

    X509Ptr ca = loadCert(caCertPath);
    if (!ca) return "Failed to load CA certificate file";

    std::unique_ptr<X509_STORE, X509StoreDel> store(X509_STORE_new());
    X509_STORE_add_cert(store.get(), ca.get());

    std::unique_ptr<X509_STORE_CTX, X509StoreCtxDel> ctx(X509_STORE_CTX_new());
    X509_STORE_CTX_init(ctx.get(), store.get(), cert.get(), nullptr);

    if (X509_verify_cert(ctx.get()) == 1)
        return {};  // success

    int err = X509_STORE_CTX_get_error(ctx.get());
    return QString::fromUtf8(X509_verify_cert_error_string(err));
}

// ── Export PKCS#12 ─────────────────────────────────────────────────────────
bool CertManager::exportPKCS12(const QString &p12Path,
                                const QString &certPath,
                                const QString &keyPath,
                                const QString &password,
                                const QString &friendlyName,
                                const QString &keyPassphrase)
{
    X509Ptr cert = loadCert(certPath);
    if (!cert) { setOpenSSLError("Load cert for P12"); return false; }

    KeyPtr pkey = loadKey(keyPath, keyPassphrase);
    if (!pkey) { setOpenSSLError("Load key for P12"); return false; }

    PKCS12 *p12 = PKCS12_create(
        password.toUtf8().constData(),
        friendlyName.isEmpty() ? nullptr : friendlyName.toUtf8().constData(),
        pkey.get(), cert.get(), nullptr, 0, 0, 0, 0, 0);

    if (!p12) { setOpenSSLError("Create PKCS12"); return false; }

    BioPtr bio(BIO_new_file(p12Path.toUtf8().constData(), "wb"));
    if (!bio) { PKCS12_free(p12); setError("Cannot write P12 file"); return false; }
    i2d_PKCS12_bio(bio.get(), p12);
    PKCS12_free(p12);
    return true;
}

// ── PKI Store-aware: Generate CA cert ──────────────────────────────────────
bool CertManager::generateCACertInStore(PkiStore &store,
                                        const SubjectInfo &subject,
                                        int days,
                                        const QString &keyType,
                                        const QString &keyParam,
                                        const QString &passphrase)
{
    if (!store.isValid()) {
        setError("PKI directory not initialized");
        return false;
    }

    QString certPath = store.caCertPath();
    QString keyPath  = store.caKeyPath();

    // Ensure directories
    QDir().mkpath(QFileInfo(certPath).absolutePath());
    QDir().mkpath(QFileInfo(keyPath).absolutePath());

    if (!generateCACert(certPath, keyPath, subject, days, keyType, keyParam, passphrase))
        return false;

    // Add CA to index as serial "00"
    CertInfo info = parseCert(certPath);
    IndexEntry entry;
    entry.status     = 'V';
    entry.expiryDate = QDateTime::currentDateTimeUtc().addDays(days).toString("yyMMddHHmmss") + "Z";
    entry.serial     = "00";
    entry.filename   = "ca/ca.crt";
    entry.subject    = "/" + info.subject.replace(", ", "/");

    store.addIndexEntry(entry);
    return true;
}

// ── PKI Store-aware: Sign CSR with managed serial ─────────────────────────
bool CertManager::signCSRWithStore(PkiStore &store,
                                   const QString &csrPath,
                                   const QString &outCertPath,
                                   int days,
                                   bool isCA,
                                   int pathLen,
                                   const QStringList &sanList,
                                   QString *allocatedSerial,
                                   const QString &caKeyPassphrase)
{
    if (!store.isValid()) {
        setError("PKI directory not initialized");
        return false;
    }

    // Allocate serial
    QString serial = store.allocateSerial();
    if (serial.isEmpty()) {
        setError("Failed to allocate serial number: " + PkiStore::lastError());
        return false;
    }

    if (allocatedSerial)
        *allocatedSerial = serial;

    // Use the CA cert & key from the store
    QString caCertPath = store.caCertPath();
    QString caKeyPath  = store.caKeyPath();

    // Sign with the allocated serial
    if (!signCSRWithSerial(csrPath, caCertPath, caKeyPath, outCertPath,
                           serial, days, isCA, pathLen, sanList, caKeyPassphrase))
        return false;

    // Copy to newcerts/<serial>.pem
    QString newcertPath = store.certPathForSerial(serial);
    QFile::copy(outCertPath, newcertPath);

    // Copy to certs/<serial>.pem
    QString issuedPath = store.issuedCertPath(serial);
    QFile::copy(outCertPath, issuedPath);

    // Add to index.txt
    CertInfo info = parseCert(outCertPath);
    IndexEntry entry;
    entry.status     = 'V';
    entry.expiryDate = QDateTime::currentDateTimeUtc().addDays(days).toString("yyMMddHHmmss") + "Z";
    entry.serial     = serial;
    entry.filename   = QFileInfo(outCertPath).fileName();
    entry.subject    = "/" + info.subject.replace(", ", "/");

    store.addIndexEntry(entry);
    return true;
}

// ── PKI Store-aware: Generate CSR ─────────────────────────────────────────
bool CertManager::generateCSRInStore(PkiStore &store,
                                     const QString &name,
                                     const SubjectInfo &subject,
                                     const QStringList &sanList,
                                     const QString &keyType,
                                     const QString &keyParam,
                                     QString *csrPathOut,
                                     QString *keyPathOut,
                                     const QString &passphrase)
{
    if (!store.isValid()) {
        setError("PKI directory not initialized");
        return false;
    }

    QString csrPath = store.csrDir() + "/" + name + ".csr";
    QString keyPath = store.privateDir() + "/" + name + ".key";

    if (csrPathOut) *csrPathOut = csrPath;
    if (keyPathOut) *keyPathOut = keyPath;

    return generateCSR(csrPath, keyPath, subject, sanList, keyType, keyParam, passphrase);
}

// ── Sign CSR with explicit serial number ──────────────────────────────────
bool CertManager::signCSRWithSerial(const QString &csrPath,
                                    const QString &caCertPath,
                                    const QString &caKeyPath,
                                    const QString &outCertPath,
                                    const QString &serialHex,
                                    int days,
                                    bool isCA,
                                    int pathLen,
                                    const QStringList &sanList,
                                    const QString &caKeyPassphrase)
{
    ReqPtr req = loadCSR(csrPath);
    if (!req) { setOpenSSLError("Load CSR"); return false; }

    X509Ptr caCert = loadCert(caCertPath);
    if (!caCert) { setOpenSSLError("Load CA cert"); return false; }

    KeyPtr caKey = loadKey(caKeyPath, caKeyPassphrase);
    if (!caKey) { setOpenSSLError("Load CA key"); return false; }

    // Verify CSR signature
    EVP_PKEY *reqKey = X509_REQ_get0_pubkey(req.get());
    if (X509_REQ_verify(req.get(), reqKey) != 1) {
        setError("CSR signature verification failed");
        return false;
    }

    X509Ptr cert(X509_new());
    X509_set_version(cert.get(), 2);

    // Set the explicit serial number
    if (!setHexSerial(cert.get(), serialHex)) {
        setError("Failed to set serial number: " + serialHex);
        return false;
    }

    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), (long)days * 86400);

    // Subject from CSR, Issuer from CA
    X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(req.get()));
    X509_set_issuer_name(cert.get(), X509_get_subject_name(caCert.get()));
    X509_set_pubkey(cert.get(), reqKey);

    // Extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, caCert.get(), cert.get(), nullptr, nullptr, 0);

    auto addExt = [&](int nid, const char *value) {
        X509_EXTENSION *ext = X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value);
        if (ext) { X509_add_ext(cert.get(), ext, -1); X509_EXTENSION_free(ext); }
    };

    if (isCA) {
        QString bc = "critical,CA:TRUE";
        if (pathLen >= 0) bc += ",pathlen:" + QString::number(pathLen);
        addExt(NID_basic_constraints, bc.toUtf8().constData());
        addExt(NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
    } else {
        addExt(NID_basic_constraints, "critical,CA:FALSE");
        addExt(NID_key_usage, "critical,digitalSignature,keyEncipherment");
        addExt(NID_ext_key_usage, "serverAuth,clientAuth");
    }

    addExt(NID_subject_key_identifier, "hash");
    addExt(NID_authority_key_identifier, "keyid:always");

    // SAN: prefer explicit list, then try to copy from CSR
    QStringList effectiveSan = sanList;
    if (effectiveSan.isEmpty()) {
        STACK_OF(X509_EXTENSION) *reqExts = X509_REQ_get_extensions(req.get());
        if (reqExts) {
            for (int i = 0; i < sk_X509_EXTENSION_num(reqExts); i++) {
                X509_EXTENSION *ext = sk_X509_EXTENSION_value(reqExts, i);
                if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) == NID_subject_alt_name) {
                    X509_add_ext(cert.get(), ext, -1);
                }
            }
            sk_X509_EXTENSION_pop_free(reqExts, X509_EXTENSION_free);
        }
    } else {
        addSanExtension(cert.get(), caCert.get(), effectiveSan);
    }

    if (X509_sign(cert.get(), caKey.get(), EVP_sha256()) == 0) {
        setOpenSSLError("Sign cert");
        return false;
    }

    // Ensure output directory exists
    QDir().mkpath(QFileInfo(outCertPath).absolutePath());

    BioPtr bio(BIO_new_file(outCertPath.toUtf8().constData(), "w"));
    if (!bio) { setError("Cannot write output cert"); return false; }
    PEM_write_bio_X509(bio.get(), cert.get());
    return true;
}

// ── Build Certificate Chain ───────────────────────────────────────────────
bool CertManager::buildCertChain(const QStringList &certPaths,
                                 const QString &outPath)
{
    if (certPaths.isEmpty()) {
        setError("No certificate files provided");
        return false;
    }

    // Ensure output directory exists
    QDir().mkpath(QFileInfo(outPath).absolutePath());

    QFile outFile(outPath);
    if (!outFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        setError("Cannot open output file: " + outPath);
        return false;
    }

    for (const QString &certPath : certPaths) {
        QFile inFile(certPath);
        if (!inFile.open(QIODevice::ReadOnly)) {
            setError("Cannot read certificate file: " + certPath);
            outFile.close();
            QFile::remove(outPath);
            return false;
        }
        QByteArray data = inFile.readAll();
        inFile.close();

        // Ensure each cert ends with a newline before appending the next
        if (!data.endsWith('\n'))
            data.append('\n');

        outFile.write(data);
    }

    outFile.close();
    return true;
}