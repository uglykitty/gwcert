#ifndef CERTSIGNDIALOG_H
#define CERTSIGNDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QTextEdit>
#include <QPushButton>

class PkiStore;

/**
 * @brief Dialog for signing a CSR with a CA certificate.
 *        Supports both intermediate CA and end-entity certificates.
 */
class CertSignDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CertSignDialog(PkiStore *store = nullptr, QWidget *parent = nullptr);

    QString outCertPath() const { return m_generatedCertPath; }
    QString allocatedSerial() const { return m_allocatedSerial; }

    /// Pre-fill the CSR path field
    void setCSRPath(const QString &path);

private:
    void updateOutputFromCSR(const QString &csrPath);

private slots:
    void onBrowseCSR();
    void onBrowseCACert();
    void onBrowseCAKey();
    void onBrowseOutput();
    void onSign();

private:
    QLineEdit *m_csrPathEdit;
    QLineEdit *m_caCertPathEdit;
    QLineEdit *m_caKeyPathEdit;
    QLineEdit *m_caKeyPassEdit;
    QLineEdit *m_outPathEdit;
    QSpinBox  *m_daysSpin;
    QCheckBox *m_isCACb;
    QSpinBox  *m_pathLenSpin;
    QTextEdit *m_sanEdit;

    QString m_generatedCertPath;
    QString m_allocatedSerial;
    PkiStore *m_store;
};

#endif // CERTSIGNDIALOG_H
