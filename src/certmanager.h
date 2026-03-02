#ifndef CERTMANAGER_H
#define CERTMANAGER_H

#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QMap>

class PkiStore;

/**
 * @brief Certificate subject information
 */
struct SubjectInfo {
    QString commonName;        // CN
    QString organization;      // O
    QString organizationUnit;  // OU
    QString country;           // C  (2-letter code)
    QString state;             // ST
    QString locality;          // L
    QString email;             // emailAddress

    QString toOneLine() const;
};

/**
 * @brief Certificate information for display
 */
struct CertInfo {
    QString subject;
    QString issuer;
    QString serial;
    QString notBefore;
    QString notAfter;
    QString signatureAlgorithm;
    QString publicKeyAlgorithm;
    int publicKeyBits = 0;
    bool isCA = false;
    QString fingerprint;       // SHA-256
    QStringList sanEntries;    // Subject Alternative Names
    QStringList extensions;
    QString pemText;
};

/**
 * @brief Core certificate management operations using OpenSSL library calls.
 *
 * All methods are static utilities – no instance state is kept.
 */
class CertManager
{
public:
    // ── Key Generation ──────────────────────────────────────────────────
    /**
     * Generate an RSA private key and write PEM to @p keyPath.
     * @param bits  Key size (2048, 3072, 4096, …).
     * @param passphrase  If non-empty, encrypt the private key with AES-256-CBC.
     * @return true on success.
     */
    static bool generateRSAKey(const QString &keyPath, int bits = 2048,
                               const QString &passphrase = {});

    /**
     * Generate an EC private key and write PEM to @p keyPath.
     * @param curveName  e.g. "prime256v1", "secp384r1".
     * @param passphrase  If non-empty, encrypt the private key with AES-256-CBC.
     */
    static bool generateECKey(const QString &keyPath,
                              const QString &curveName = "prime256v1",
                              const QString &passphrase = {});

    // ── CA Certificate ──────────────────────────────────────────────────
    /**
     * Create a self-signed root CA certificate.
     * Also generates the private key if @p keyPath does not exist.
     * @param certPath  Output certificate PEM file.
     * @param keyPath   Output (or existing) private key PEM file.
     * @param subject   DN fields.
     * @param days      Validity period.
     * @param keyType   "RSA" or "EC".
     * @param keyParam  Bits for RSA (e.g. "4096") or curve name for EC.
     */
    static bool generateCACert(const QString &certPath,
                               const QString &keyPath,
                               const SubjectInfo &subject,
                               int days = 3650,
                               const QString &keyType = "RSA",
                               const QString &keyParam = "4096",
                               const QString &passphrase = {});

    // ── CSR ─────────────────────────────────────────────────────────────
    /**
     * Generate a Certificate Signing Request.
     */
    static bool generateCSR(const QString &csrPath,
                            const QString &keyPath,
                            const SubjectInfo &subject,
                            const QStringList &sanList = {},
                            const QString &keyType = "RSA",
                            const QString &keyParam = "2048",
                            const QString &passphrase = {});

    // ── Sign Certificates ───────────────────────────────────────────────
    /**
     * Sign a CSR with a CA, producing a certificate.
     * @param isCA  If true, the resulting cert has CA:TRUE basic constraint
     *              (use for intermediate CA certs).
     * @param pathLen  Maximum path length for CA certs (-1 = no limit).
     */
    static bool signCSR(const QString &csrPath,
                        const QString &caCertPath,
                        const QString &caKeyPath,
                        const QString &outCertPath,
                        int days = 365,
                        bool isCA = false,
                        int pathLen = -1,
                        const QStringList &sanList = {},
                        const QString &caKeyPassphrase = {});

    /**
     * Convenience: generate key + CSR + sign in one step for a server cert.
     */
    static bool generateServerCert(const QString &certPath,
                                   const QString &keyPath,
                                   const QString &caCertPath,
                                   const QString &caKeyPath,
                                   const SubjectInfo &subject,
                                   int days = 365,
                                   const QStringList &sanList = {},
                                   const QString &keyType = "RSA",
                                   const QString &keyParam = "2048",
                                   const QString &passphrase = {});

    // ── PKI Store-aware Operations ──────────────────────────────────────
    /**
     * Generate CA certificate and initialize it into PKI store.
     * Outputs to store's ca/ directory and records serial 00 in index.
     */
    static bool generateCACertInStore(PkiStore &store,
                                     const SubjectInfo &subject,
                                     int days = 3650,
                                     const QString &keyType = "RSA",
                                     const QString &keyParam = "4096",
                                     const QString &passphrase = {});

    /**
     * Sign a CSR using serial number from PKI store.
     * - Allocates next serial from store
     * - Signs the CSR
     * - Copies cert to newcerts/<serial>.pem and certs/<serial>.pem
     * - Adds entry to index.txt
     * @param allocatedSerial  Output: the serial that was assigned.
     */
    static bool signCSRWithStore(PkiStore &store,
                                const QString &csrPath,
                                const QString &outCertPath,
                                int days = 365,
                                bool isCA = false,
                                int pathLen = -1,
                                const QStringList &sanList = {},
                                QString *allocatedSerial = nullptr,
                                const QString &caKeyPassphrase = {});

    /**
     * Generate CSR and store it in the PKI store's csr/ directory.
     */
    static bool generateCSRInStore(PkiStore &store,
                                  const QString &name,
                                  const SubjectInfo &subject,
                                  const QStringList &sanList = {},
                                  const QString &keyType = "RSA",
                                  const QString &keyParam = "2048",
                                  QString *csrPathOut = nullptr,
                                  QString *keyPathOut = nullptr,
                                  const QString &passphrase = {});

    /**
     * Sign CSR using a specific serial number (for explicit serial control).
     */
    static bool signCSRWithSerial(const QString &csrPath,
                                 const QString &caCertPath,
                                 const QString &caKeyPath,
                                 const QString &outCertPath,
                                 const QString &serialHex,
                                 int days = 365,
                                 bool isCA = false,
                                 int pathLen = -1,
                                 const QStringList &sanList = {},
                                 const QString &caKeyPassphrase = {});

    // ── Inspection ──────────────────────────────────────────────────────
    /**
     * Parse a PEM certificate file and return structured info.
     */
    static CertInfo parseCert(const QString &certPath);

    /**
     * Parse a PEM CSR and return subject + SAN info.
     */
    static CertInfo parseCSR(const QString &csrPath);

    /**
     * Verify a certificate against a CA certificate chain.
     * @return Empty string on success, error message on failure.
     */
    static QString verifyCert(const QString &certPath,
                              const QString &caCertPath);

    /**
     * Export a certificate + key to PKCS#12 (.pfx/.p12).
     */
    static bool exportPKCS12(const QString &p12Path,
                             const QString &certPath,
                             const QString &keyPath,
                             const QString &password,
                             const QString &friendlyName = "",
                             const QString &keyPassphrase = {});

    /**
     * Build a certificate chain by concatenating multiple PEM certificate files.
     * Certificates are written in the order provided (typically: leaf → intermediate → root).
     * @param certPaths  Ordered list of PEM certificate file paths.
     * @param outPath    Output chain file path.
     * @return true on success.
     */
    static bool buildCertChain(const QStringList &certPaths,
                               const QString &outPath);

    // ── Utilities ───────────────────────────────────────────────────────
    static QString lastError();

private:
    static QString s_lastError;
    static void setError(const QString &msg);
    static void setOpenSSLError(const QString &prefix);
};

#endif // CERTMANAGER_H
