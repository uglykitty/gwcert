#include "csrgenedialog.h"
#include "subjectwidget.h"
#include "certmanager.h"
#include "../pkistore.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QDialogButtonBox>
#include <QLabel>

CSRGeneDialog::CSRGeneDialog(PkiStore *store, QWidget *parent)
    : QDialog(parent), m_store(store)
{
    setWindowTitle(tr("Generate Certificate Signing Request (CSR)"));
    setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinMaxButtonsHint);
    setMinimumWidth(520);
    setSizeGripEnabled(true);

    auto *mainLayout = new QVBoxLayout(this);

    auto *titleLabel = new QLabel("<b>" + tr("Generate Certificate Signing Request (CSR)") + "</b>", this);
    titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 8px;");
    mainLayout->addWidget(titleLabel);

    // Subject
    m_subject = new SubjectWidget(tr("CSR Subject Information"), this);
    mainLayout->addWidget(m_subject);

    // SAN
    auto *sanGroup = new QGroupBox(tr("Subject Alternative Name (SAN)"), this);
    auto *sanLayout = new QVBoxLayout(sanGroup);
    auto *sanHint = new QLabel(tr("One per line, format: DNS:example.com or IP:1.2.3.4"), this);
    sanHint->setStyleSheet("color: #666; font-size: 11px;");
    sanLayout->addWidget(sanHint);
    m_sanEdit = new QTextEdit(this);
    m_sanEdit->setPlaceholderText("DNS:example.com\nDNS:*.example.com\nIP:127.0.0.1");
    sanLayout->addWidget(m_sanEdit);
    mainLayout->addWidget(sanGroup);

    // Settings
    auto *settings = new QGroupBox(tr("Key & Output Settings"), this);
    auto *form = new QFormLayout(settings);

    m_keyTypeCombo = new QComboBox(this);
    m_keyTypeCombo->addItems({"RSA", "EC"});
    form->addRow(tr("Key Type:"), m_keyTypeCombo);

    m_keyParamCombo = new QComboBox(this);
    m_keyParamCombo->addItems({"2048", "3072", "4096"});
    form->addRow(tr("Key Parameter:"), m_keyParamCombo);

    connect(m_keyTypeCombo, &QComboBox::currentTextChanged, this, [this](const QString &type) {
        m_keyParamCombo->clear();
        if (type == "EC")
            m_keyParamCombo->addItems({"prime256v1", "secp384r1", "secp521r1"});
        else
            m_keyParamCombo->addItems({"2048", "3072", "4096"});
    });

    // Password protection for private key
    m_encryptKeyCb = new QCheckBox(tr("Encrypt private key"), this);
    form->addRow(tr("Password Protection:"), m_encryptKeyCb);

    m_passphraseEdit = new QLineEdit(this);
    m_passphraseEdit->setEchoMode(QLineEdit::Password);
    m_passphraseEdit->setPlaceholderText(tr("Enter private key password"));
    m_passphraseEdit->setEnabled(false);
    form->addRow(tr("Password:"), m_passphraseEdit);

    m_passphraseConfirmEdit = new QLineEdit(this);
    m_passphraseConfirmEdit->setEchoMode(QLineEdit::Password);
    m_passphraseConfirmEdit->setPlaceholderText(tr("Confirm private key password"));
    m_passphraseConfirmEdit->setEnabled(false);
    form->addRow(tr("Confirm Password:"), m_passphraseConfirmEdit);

    connect(m_encryptKeyCb, &QCheckBox::toggled, this, [this](bool checked) {
        m_passphraseEdit->setEnabled(checked);
        m_passphraseConfirmEdit->setEnabled(checked);
        if (!checked) {
            m_passphraseEdit->clear();
            m_passphraseConfirmEdit->clear();
        }
    });

    // CSR path
    auto *csrRow = new QHBoxLayout();
    m_csrPathEdit = new QLineEdit(this);
    if (m_store && m_store->isValid())
        m_csrPathEdit->setText(m_store->csrDir() + "/request.csr");
    else
        m_csrPathEdit->setText(QDir::currentPath() + "/request.csr");
    auto *csrBtn = new QPushButton(tr("Browse..."), this);
    connect(csrBtn, &QPushButton::clicked, this, &CSRGeneDialog::onBrowseCSR);
    csrRow->addWidget(m_csrPathEdit);
    csrRow->addWidget(csrBtn);
    form->addRow(tr("CSR Path:"), csrRow);

    // Key path
    auto *keyRow = new QHBoxLayout();
    m_keyPathEdit = new QLineEdit(this);
    if (m_store && m_store->isValid())
        m_keyPathEdit->setText(m_store->privateDir() + "/request-key.pem");
    else
        m_keyPathEdit->setText(QDir::currentPath() + "/request-key.pem");
    auto *keyBtn = new QPushButton(tr("Browse..."), this);
    connect(keyBtn, &QPushButton::clicked, this, &CSRGeneDialog::onBrowseKey);
    keyRow->addWidget(m_keyPathEdit);
    keyRow->addWidget(keyBtn);
    form->addRow(tr("Key Path:"), keyRow);

    mainLayout->addWidget(settings);

    // Buttons
    auto *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    btnBox->button(QDialogButtonBox::Ok)->setText(tr("Generate"));
    connect(btnBox, &QDialogButtonBox::accepted, this, &CSRGeneDialog::onGenerate);
    connect(btnBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(btnBox);
}

void CSRGeneDialog::onBrowseCSR()
{
    QString path = QFileDialog::getSaveFileName(this, tr("Select CSR Save Location"),
                        m_csrPathEdit->text(),
                        tr("CSR Files (*.csr *.pem);;All Files (*)"));
    if (!path.isEmpty()) m_csrPathEdit->setText(path);
}

void CSRGeneDialog::onBrowseKey()
{
    QString path = QFileDialog::getSaveFileName(this, tr("Select Key Save Location"),
                        m_keyPathEdit->text(),
                        tr("PEM Files (*.pem *.key);;All Files (*)"));
    if (!path.isEmpty()) m_keyPathEdit->setText(path);
}

void CSRGeneDialog::onGenerate()
{
    QString errMsg;
    if (!m_subject->validate(&errMsg)) {
        QMessageBox::warning(this, tr("Input Error"), errMsg);
        return;
    }

    // Parse SAN entries
    QStringList sanList;
    QString sanText = m_sanEdit->toPlainText().trimmed();
    if (!sanText.isEmpty()) {
        for (const QString &line : sanText.split('\n', Qt::SkipEmptyParts)) {
            QString trimmed = line.trimmed();
            if (!trimmed.isEmpty())
                sanList << trimmed;
        }
    }

    // Validate passphrase
    QString passphrase;
    if (m_encryptKeyCb->isChecked()) {
        passphrase = m_passphraseEdit->text();
        if (passphrase.isEmpty()) {
            QMessageBox::warning(this, tr("Input Error"), tr("Encryption is enabled, please enter a private key password"));
            return;
        }
        if (passphrase != m_passphraseConfirmEdit->text()) {
            QMessageBox::warning(this, tr("Input Error"), tr("Passwords do not match"));
            return;
        }
    }

    setCursor(Qt::WaitCursor);

    bool ok = CertManager::generateCSR(
        m_csrPathEdit->text().trimmed(),
        m_keyPathEdit->text().trimmed(),
        m_subject->subjectInfo(),
        sanList,
        m_keyTypeCombo->currentText(),
        m_keyParamCombo->currentText(),
        passphrase
    );

    setCursor(Qt::ArrowCursor);

    if (ok) {
        m_generatedCSRPath = m_csrPathEdit->text().trimmed();
        m_generatedKeyPath = m_keyPathEdit->text().trimmed();
        QMessageBox::information(this, tr("Success"),
            tr("CSR generated!\n\n"
            "CSR: ") + m_generatedCSRPath + tr("\n"
            "Key: ") + m_generatedKeyPath);
        accept();
    } else {
        QMessageBox::critical(this, tr("Generation Failed"), CertManager::lastError());
    }
}
