#include "pkistore.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>

// ── Static error ───────────────────────────────────────────────────────────
QString PkiStore::s_lastError;
void PkiStore::setError(const QString &msg) { s_lastError = msg; }
QString PkiStore::lastError() { return s_lastError; }

// ── IndexEntry ─────────────────────────────────────────────────────────────
QString IndexEntry::toLine() const
{
    // OpenSSL index.txt format:
    // V  250101120000Z           01  unknown  /C=CN/O=Test/CN=example.com
    // R  250101120000Z  240601  02  unknown  /C=CN/O=Test/CN=revoked.com
    QString line;
    line += status;
    line += '\t';
    line += expiryDate;
    line += '\t';
    line += revokeDate.isEmpty() ? "" : revokeDate;
    line += '\t';
    line += serial;
    line += '\t';
    line += filename.isEmpty() ? "unknown" : filename;
    line += '\t';
    line += subject;
    return line;
}

IndexEntry IndexEntry::fromLine(const QString &line)
{
    IndexEntry e;
    QStringList parts = line.split('\t');
    if (parts.size() >= 6) {
        e.status     = parts[0].trimmed().isEmpty() ? QChar('V') : parts[0].trimmed().at(0);
        e.expiryDate = parts[1].trimmed();
        e.revokeDate = parts[2].trimmed();
        e.serial     = parts[3].trimmed();
        e.filename   = parts[4].trimmed();
        e.subject    = parts[5].trimmed();
    }
    return e;
}

// ── PkiStore ───────────────────────────────────────────────────────────────
PkiStore::PkiStore(const QString &rootDir)
    : m_rootDir(rootDir)
{
}

void PkiStore::setRootDir(const QString &dir)
{
    m_rootDir = dir;
}

bool PkiStore::isValid() const
{
    if (m_rootDir.isEmpty()) return false;
    QDir dir(m_rootDir);
    return dir.exists() &&
           QFileInfo::exists(serialFile()) &&
           QFileInfo::exists(indexFile());
}

bool PkiStore::initDirectory()
{
    if (m_rootDir.isEmpty()) {
        setError("PKI root directory not set");
        return false;
    }

    QDir root(m_rootDir);

    // Create all sub-directories
    QStringList dirs = {
        "ca",
        "ca/private",
        "intermediate",
        "intermediate/private",
        "certs",
        "newcerts",
        "csr",
        "private",
        "crl"
    };

    for (const QString &d : dirs) {
        if (!root.mkpath(d)) {
            setError("Failed to create directory: " + d);
            return false;
        }
    }

    // Create serial file if not exists (start at 0001)
    if (!QFileInfo::exists(serialFile())) {
        if (!setSerial("0001")) return false;
    }

    // Create index.txt if not exists
    if (!QFileInfo::exists(indexFile())) {
        QFile f(indexFile());
        if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            setError("Failed to create index.txt");
            return false;
        }
        f.close();
    }

    // Create index.txt.attr if not exists
    QString attrFile = m_rootDir + "/index.txt.attr";
    if (!QFileInfo::exists(attrFile)) {
        QFile f(attrFile);
        if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&f);
            out << "unique_subject = no\n";
        }
    }

    return true;
}

// ── Serial Number Management ───────────────────────────────────────────────
QString PkiStore::currentSerial() const
{
    QFile f(serialFile());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }
    QString hex = f.readAll().trimmed();
    f.close();
    return hex.toUpper();
}

QString PkiStore::allocateSerial()
{
    // Read current serial
    QString current = currentSerial();
    if (current.isEmpty()) {
        setError("Failed to read serial file");
        return {};
    }

    // Back up serial -> serial.old
    {
        QString oldFile = serialFile() + ".old";
        QFile::remove(oldFile);
        QFile::copy(serialFile(), oldFile);
    }

    // Parse hex, increment, write back
    bool ok = false;
    quint64 num = current.toULongLong(&ok, 16);
    if (!ok) {
        setError("Invalid serial number format: " + current);
        return {};
    }

    quint64 next = num + 1;
    // Format with at least 4 hex digits, zero-padded
    int width = qMax(4, current.length());
    QString nextHex = QString("%1").arg(next, width, 16, QChar('0')).toUpper();

    QFile f(serialFile());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        setError("Failed to write serial file");
        return {};
    }
    QTextStream out(&f);
    out << nextHex << "\n";
    f.close();

    return current;
}

bool PkiStore::setSerial(const QString &hexSerial)
{
    QFile f(serialFile());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        setError("Failed to write serial file");
        return false;
    }
    QTextStream out(&f);
    out << hexSerial.toUpper() << "\n";
    f.close();
    return true;
}

// ── Index Database ─────────────────────────────────────────────────────────
bool PkiStore::addIndexEntry(const IndexEntry &entry)
{
    // Back up index.txt -> index.txt.old
    {
        QString oldFile = indexFile() + ".old";
        QFile::remove(oldFile);
        QFile::copy(indexFile(), oldFile);
    }

    QFile f(indexFile());
    if (!f.open(QIODevice::Append | QIODevice::Text)) {
        setError("Failed to write index.txt");
        return false;
    }
    QTextStream out(&f);
    out << entry.toLine() << "\n";
    f.close();
    return true;
}

QList<IndexEntry> PkiStore::readIndex() const
{
    QList<IndexEntry> entries;
    QFile f(indexFile());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return entries;

    QTextStream in(&f);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty()) continue;
        IndexEntry e = IndexEntry::fromLine(line);
        if (!e.serial.isEmpty())
            entries.append(e);
    }
    f.close();
    return entries;
}

bool PkiStore::revokeBySerial(const QString &serial)
{
    QList<IndexEntry> entries = readIndex();
    bool found = false;

    for (auto &e : entries) {
        if (e.serial.toUpper() == serial.toUpper() && e.status == 'V') {
            e.status = 'R';
            e.revokeDate = QDateTime::currentDateTimeUtc().toString("yyMMddHHmmss") + "Z";
            found = true;
        }
    }

    if (!found) {
        setError("Valid certificate serial not found: " + serial);
        return false;
    }

    // Back up and rewrite the entire index
    {
        QString oldFile = indexFile() + ".old";
        QFile::remove(oldFile);
        QFile::copy(indexFile(), oldFile);
    }

    QFile f(indexFile());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        setError("Failed to write index.txt");
        return false;
    }
    QTextStream out(&f);
    for (const auto &e : entries) {
        out << e.toLine() << "\n";
    }
    f.close();
    return true;
}

QString PkiStore::certPathForSerial(const QString &serial) const
{
    return newcertsDir() + "/" + serial.toUpper() + ".pem";
}

QString PkiStore::issuedCertPath(const QString &serial) const
{
    return certsDir() + "/" + serial.toUpper() + ".pem";
}
