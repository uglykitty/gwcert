#include "certsigndialog.h"
#include "certmanager.h"
#include "../pkistore.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QFileInfo>
#include <QDialogButtonBox>
#include <QLabel>

CertSignDialog::CertSignDialog(PkiStore *store, QWidget *parent)
    : QDialog(parent), m_store(store)
{
    setWindowTitle(tr("Sign Certificate"));
    setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinMaxButtonsHint);
    setMinimumWidth(560);
    setSizeGripEnabled(true);

    auto *mainLayout = new QVBoxLayout(this);

    auto *titleLabel = new QLabel("<b>" + tr("Sign CSR with CA Certificate") + "</b>", this);
    titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 8px;");
    mainLayout->addWidget(titleLabel);

    auto *hint = new QLabel(
        tr("Supports signing intermediate CA certificates (check \"Sign as CA\") or regular service certificates."), this);
    hint->setStyleSheet("color: #555; margin-bottom: 8px;");
    hint->setWordWrap(true);
    mainLayout->addWidget(hint);

    // Input files
    auto *inputGroup = new QGroupBox(tr("Input Files"), this);
    auto *inputForm = new QFormLayout(inputGroup);

    // CSR
    auto *csrRow = new QHBoxLayout();
    m_csrPathEdit = new QLineEdit(this);
    m_csrPathEdit->setPlaceholderText(tr("CSR file to sign"));
    auto *csrBtn = new QPushButton(tr("Browse..."), this);
    connect(csrBtn, &QPushButton::clicked, this, &CertSignDialog::onBrowseCSR);
    csrRow->addWidget(m_csrPathEdit);
    csrRow->addWidget(csrBtn);
    inputForm->addRow(tr("CSR File:"), csrRow);

    // CA Cert
    auto *caRow = new QHBoxLayout();
    m_caCertPathEdit = new QLineEdit(this);
    m_caCertPathEdit->setPlaceholderText(tr("CA certificate for signing"));
    if (m_store && m_store->isValid())
        m_caCertPathEdit->setText(m_store->caCertPath());
    auto *caBtn = new QPushButton(tr("Browse..."), this);
    connect(caBtn, &QPushButton::clicked, this, &CertSignDialog::onBrowseCACert);
    caRow->addWidget(m_caCertPathEdit);
    caRow->addWidget(caBtn);
    inputForm->addRow(tr("CA Certificate:"), caRow);

    // CA Key
    auto *caKeyRow = new QHBoxLayout();
    m_caKeyPathEdit = new QLineEdit(this);
    m_caKeyPathEdit->setPlaceholderText(tr("CA private key"));
    if (m_store && m_store->isValid())
        m_caKeyPathEdit->setText(m_store->caKeyPath());
    auto *caKeyBtn = new QPushButton(tr("Browse..."), this);
    connect(caKeyBtn, &QPushButton::clicked, this, &CertSignDialog::onBrowseCAKey);
    caKeyRow->addWidget(m_caKeyPathEdit);
    caKeyRow->addWidget(caKeyBtn);
    inputForm->addRow(tr("CA Key:"), caKeyRow);

    m_caKeyPassEdit = new QLineEdit(this);
    m_caKeyPassEdit->setEchoMode(QLineEdit::Password);
    m_caKeyPassEdit->setPlaceholderText(tr("CA key password (leave empty if none)"));
    inputForm->addRow(tr("CA Key Password:"), m_caKeyPassEdit);

    mainLayout->addWidget(inputGroup);

    // Signing options
    auto *optGroup = new QGroupBox(tr("Signing Options"), this);
    auto *optForm = new QFormLayout(optGroup);

    m_daysSpin = new QSpinBox(this);
    m_daysSpin->setRange(1, 36500);
    m_daysSpin->setValue(365);
    m_daysSpin->setSuffix(tr(" days"));
    optForm->addRow(tr("Validity:"), m_daysSpin);

    m_isCACb = new QCheckBox(tr("Sign as CA certificate (Intermediate CA)"), this);
    optForm->addRow(tr("Certificate Type:"), m_isCACb);

    m_pathLenSpin = new QSpinBox(this);
    m_pathLenSpin->setRange(-1, 10);
    m_pathLenSpin->setValue(-1);
    m_pathLenSpin->setSpecialValueText(tr("No limit"));
    m_pathLenSpin->setEnabled(false);
    optForm->addRow(tr("Path Length Constraint:"), m_pathLenSpin);

    connect(m_isCACb, &QCheckBox::toggled, m_pathLenSpin, &QSpinBox::setEnabled);

    // SAN override
    auto *sanHint = new QLabel(tr("Override SAN (leave empty to use SAN from CSR), one per line:"), this);
    sanHint->setStyleSheet("color: #666; font-size: 11px;");
    optForm->addRow(sanHint);

    m_sanEdit = new QTextEdit(this);
    m_sanEdit->setPlaceholderText("DNS:example.com\nIP:10.0.0.1");
    optForm->addRow("SAN:", m_sanEdit);

    mainLayout->addWidget(optGroup);

    // Output
    auto *outGroup = new QGroupBox(tr("Output"), this);
    auto *outForm = new QFormLayout(outGroup);
    auto *outRow = new QHBoxLayout();
    m_outPathEdit = new QLineEdit(this);
    if (m_store && m_store->isValid())
        m_outPathEdit->setText(m_store->certsDir() + "/signed-cert.pem");
    else
        m_outPathEdit->setText(QDir::currentPath() + "/signed-cert.pem");
    auto *outBtn = new QPushButton(tr("Browse..."), this);
    connect(outBtn, &QPushButton::clicked, this, &CertSignDialog::onBrowseOutput);
    outRow->addWidget(m_outPathEdit);
    outRow->addWidget(outBtn);
    outForm->addRow(tr("Certificate Output:"), outRow);
    mainLayout->addWidget(outGroup);

    // Buttons
    auto *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    btnBox->button(QDialogButtonBox::Ok)->setText(tr("Sign"));
    connect(btnBox, &QDialogButtonBox::accepted, this, &CertSignDialog::onSign);
    connect(btnBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(btnBox);
}

void CertSignDialog::onBrowseCSR()
{
    QString path = QFileDialog::getOpenFileName(this, tr("Select CSR File"),
                        QDir::currentPath(),
                        tr("CSR Files (*.csr *.pem);;All Files (*)"));
    if (!path.isEmpty()) {
        m_csrPathEdit->setText(path);
        updateOutputFromCSR(path);
    }
}

void CertSignDialog::onBrowseCACert()
{
    QString path = QFileDialog::getOpenFileName(this, tr("Select CA Certificate"),
                        QDir::currentPath(),
                        tr("Certificate Files (*.pem *.crt *.cer);;All Files (*)"));
    if (!path.isEmpty()) m_caCertPathEdit->setText(path);
}

void CertSignDialog::onBrowseCAKey()
{
    QString path = QFileDialog::getOpenFileName(this, tr("Select CA Private Key"),
                        QDir::currentPath(),
                        tr("Key Files (*.pem *.key);;All Files (*)"));
    if (!path.isEmpty()) m_caKeyPathEdit->setText(path);
}

void CertSignDialog::onBrowseOutput()
{
    QString path = QFileDialog::getSaveFileName(this, tr("Select Certificate Output Location"),
                        m_outPathEdit->text(),
                        tr("PEM Files (*.pem *.crt);;All Files (*)"));
    if (!path.isEmpty()) m_outPathEdit->setText(path);
}

void CertSignDialog::onSign()
{
    // Validate inputs
    if (m_csrPathEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Please select a CSR file"));
        return;
    }
    if (m_caCertPathEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Please select a CA certificate"));
        return;
    }
    if (m_caKeyPathEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Please select a CA private key"));
        return;
    }
    if (m_outPathEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Please specify an output path"));
        return;
    }

    // Parse SAN
    QStringList sanList;
    QString sanText = m_sanEdit->toPlainText().trimmed();
    if (!sanText.isEmpty()) {
        for (const QString &line : sanText.split('\n', Qt::SkipEmptyParts)) {
            QString trimmed = line.trimmed();
            if (!trimmed.isEmpty())
                sanList << trimmed;
        }
    }

    setCursor(Qt::WaitCursor);

    QString caKeyPass = m_caKeyPassEdit->text();

    bool ok = false;
    if (m_store && m_store->isValid()) {
        // Use PKI store-aware signing with managed serial
        QString serial;
        ok = CertManager::signCSRWithStore(
            *m_store,
            m_csrPathEdit->text().trimmed(),
            m_outPathEdit->text().trimmed(),
            m_daysSpin->value(),
            m_isCACb->isChecked(),
            m_pathLenSpin->value(),
            sanList,
            &serial,
            caKeyPass
        );
        if (ok) {
            m_allocatedSerial = serial;
        }
    } else {
        ok = CertManager::signCSR(
            m_csrPathEdit->text().trimmed(),
            m_caCertPathEdit->text().trimmed(),
            m_caKeyPathEdit->text().trimmed(),
            m_outPathEdit->text().trimmed(),
            m_daysSpin->value(),
            m_isCACb->isChecked(),
            m_pathLenSpin->value(),
            sanList,
            caKeyPass
        );
    }

    setCursor(Qt::ArrowCursor);

    if (ok) {
        m_generatedCertPath = m_outPathEdit->text().trimmed();
        QString certType = m_isCACb->isChecked() ? tr("Intermediate CA") : tr("Service");
        QString serialInfo;
        if (!m_allocatedSerial.isEmpty())
            serialInfo = tr("\nSerial: ") + m_allocatedSerial;
        QMessageBox::information(this, tr("Success"),
            certType + tr("Certificate signed!\n\n"
            "Output: ") + m_generatedCertPath + serialInfo);
        accept();
    } else {
        QMessageBox::critical(this, tr("Signing Failed"), CertManager::lastError());
    }
}

void CertSignDialog::setCSRPath(const QString &path)
{
    m_csrPathEdit->setText(path);
    updateOutputFromCSR(path);
}

void CertSignDialog::updateOutputFromCSR(const QString &csrPath)
{
    if (csrPath.isEmpty())
        return;
    QFileInfo csrInfo(csrPath);
    QString baseName = csrInfo.completeBaseName();
    QString outDir;
    if (m_store && m_store->isValid())
        outDir = m_store->certsDir();
    else
        outDir = csrInfo.absolutePath();
    m_outPathEdit->setText(outDir + "/" + baseName + ".crt");
}
