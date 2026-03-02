#ifndef PKISTORE_H
#define PKISTORE_H

#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QList>

/**
 * @brief One entry in the certificate index database (index.txt).
 *
 * Format follows OpenSSL CA index.txt convention:
 *   Status \t Expiry \t [Revocation] \t Serial \t Filename \t Subject
 *
 * Status: V=Valid, R=Revoked, E=Expired
 */
struct IndexEntry {
    QChar   status;       // V, R, E
    QString expiryDate;   // YYMMDDHHmmssZ
    QString revokeDate;   // YYMMDDHHmmssZ (empty if not revoked)
    QString serial;       // hex string, e.g. "0001"
    QString filename;     // "unknown" or relative path
    QString subject;      // /C=CN/O=.../CN=...

    QString toLine() const;
    static IndexEntry fromLine(const QString &line);
};

/**
 * @brief Manages a PKI directory structure with serial number tracking.
 *
 * Standard PKI layout:
 *   <root>/
 *     ca/
 *       ca.crt                 - Root CA certificate
 *       private/
 *         ca.key               - Root CA private key
 *     intermediate/
 *       <name>.crt             - Intermediate CA certs
 *       private/
 *         <name>.key
 *     certs/
 *       <serial>.pem           - Issued end-entity certificates
 *     newcerts/
 *       <serial>.pem           - Archive copy of all signed certs
 *     csr/
 *       <name>.csr             - Certificate signing requests
 *     private/
 *       <name>.key             - End-entity private keys
 *     crl/                     - CRL storage
 *     serial                   - Next serial number (hex)
 *     serial.old               - Previous serial number
 *     index.txt                - Certificate database
 *     index.txt.old            - Previous database
 *     index.txt.attr           - Database attributes
 */
class PkiStore
{
public:
    explicit PkiStore(const QString &rootDir = {});

    /// Set/get the PKI root directory
    void setRootDir(const QString &dir);
    QString rootDir() const { return m_rootDir; }
    bool isValid() const;

    // ── Directory Structure ─────────────────────────────────────────────
    /**
     * Initialize a new PKI directory tree with all required sub-directories
     * and seed files (serial, index.txt, etc.).
     * @return true on success.
     */
    bool initDirectory();

    /// Convenience path getters
    QString caDir()           const { return m_rootDir + "/ca"; }
    QString caPrivateDir()    const { return m_rootDir + "/ca/private"; }
    QString caCertPath()      const { return m_rootDir + "/ca/ca.crt"; }
    QString caKeyPath()       const { return m_rootDir + "/ca/private/ca.key"; }

    QString intermediateDir()        const { return m_rootDir + "/intermediate"; }
    QString intermediatePrivateDir() const { return m_rootDir + "/intermediate/private"; }

    QString certsDir()      const { return m_rootDir + "/certs"; }
    QString newcertsDir()   const { return m_rootDir + "/newcerts"; }
    QString csrDir()        const { return m_rootDir + "/csr"; }
    QString privateDir()    const { return m_rootDir + "/private"; }
    QString crlDir()        const { return m_rootDir + "/crl"; }

    QString serialFile()    const { return m_rootDir + "/serial"; }
    QString indexFile()     const { return m_rootDir + "/index.txt"; }

    // ── Serial Number Management ────────────────────────────────────────
    /**
     * Read the current (next-to-use) serial number from the serial file.
     * @return Hex string like "0001", or empty on error.
     */
    QString currentSerial() const;

    /**
     * Allocate and consume the next serial number.
     * - Reads current serial from file
     * - Backs up to serial.old
     * - Increments and writes new serial
     * @return The allocated serial (hex), or empty on failure.
     */
    QString allocateSerial();

    /**
     * Set the serial number manually (e.g. for initial setup).
     */
    bool setSerial(const QString &hexSerial);

    // ── Index Database ──────────────────────────────────────────────────
    /**
     * Append a new entry to index.txt.
     */
    bool addIndexEntry(const IndexEntry &entry);

    /**
     * Read all index entries.
     */
    QList<IndexEntry> readIndex() const;

    /**
     * Mark a certificate as revoked by serial number.
     */
    bool revokeBySerial(const QString &serial);

    /**
     * Get path for storing a newly signed certificate by serial.
     * e.g. <root>/newcerts/0001.pem
     */
    QString certPathForSerial(const QString &serial) const;

    /**
     * Get path for the primary cert copy in certs/.
     */
    QString issuedCertPath(const QString &serial) const;

    // ── Utilities ───────────────────────────────────────────────────────
    static QString lastError();

private:
    QString m_rootDir;
    static QString s_lastError;
    static void setError(const QString &msg);
};

#endif // PKISTORE_H
