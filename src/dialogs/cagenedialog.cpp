#include "cagenedialog.h"
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

CAGeneDialog::CAGeneDialog(PkiStore *store, QWidget *parent)
    : QDialog(parent), m_store(store)
{
    setWindowTitle(tr("Generate CA Root Certificate"));
    setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinMaxButtonsHint);
    setMinimumWidth(520);
    setSizeGripEnabled(true);

    auto *mainLayout = new QVBoxLayout(this);

    // Title
    auto *titleLabel = new QLabel("<b>" + tr("Generate Self-Signed CA Root Certificate") + "</b>", this);
    titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 8px;");
    mainLayout->addWidget(titleLabel);

    // Subject
    m_subject = new SubjectWidget(tr("Certificate Subject Information"), this);
    mainLayout->addWidget(m_subject);

    // Key & Output settings
    auto *settings = new QGroupBox(tr("Key & Output Settings"), this);
    auto *form = new QFormLayout(settings);

    m_keyTypeCombo = new QComboBox(this);
    m_keyTypeCombo->addItems({"RSA", "EC"});
    form->addRow(tr("Key Type:"), m_keyTypeCombo);

    m_keyParamCombo = new QComboBox(this);
    m_keyParamCombo->addItems({"4096", "3072", "2048"});
    form->addRow(tr("Key Parameter:"), m_keyParamCombo);

    connect(m_keyTypeCombo, &QComboBox::currentTextChanged, this, [this](const QString &type) {
        m_keyParamCombo->clear();
        if (type == "EC")
            m_keyParamCombo->addItems({"prime256v1", "secp384r1", "secp521r1"});
        else
            m_keyParamCombo->addItems({"4096", "3072", "2048"});
    });

    m_daysSpin = new QSpinBox(this);
    m_daysSpin->setRange(1, 36500);
    m_daysSpin->setValue(3650);
    m_daysSpin->setSuffix(tr(" days"));
    form->addRow(tr("Validity:"), m_daysSpin);

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

    // Certificate output path
    auto *certRow = new QHBoxLayout();
    m_certPathEdit = new QLineEdit(this);
    m_certPathEdit->setPlaceholderText(tr("CA certificate output path (.pem)"));
    if (m_store && m_store->isValid())
        m_certPathEdit->setText(m_store->caCertPath());
    else
        m_certPathEdit->setText(QDir::currentPath() + "/ca.pem");
    auto *certBtn = new QPushButton(tr("Browse..."), this);
    connect(certBtn, &QPushButton::clicked, this, &CAGeneDialog::onBrowseCert);
    certRow->addWidget(m_certPathEdit);
    certRow->addWidget(certBtn);
    form->addRow(tr("Certificate Path:"), certRow);

    // Key output path
    auto *keyRow = new QHBoxLayout();
    m_keyPathEdit = new QLineEdit(this);
    m_keyPathEdit->setPlaceholderText(tr("Private key output path (.pem)"));
    if (m_store && m_store->isValid())
        m_keyPathEdit->setText(m_store->caKeyPath());
    else
        m_keyPathEdit->setText(QDir::currentPath() + "/ca-key.pem");
    auto *keyBtn = new QPushButton(tr("Browse..."), this);
    connect(keyBtn, &QPushButton::clicked, this, &CAGeneDialog::onBrowseKey);
    keyRow->addWidget(m_keyPathEdit);
    keyRow->addWidget(keyBtn);
    form->addRow(tr("Key Path:"), keyRow);

    mainLayout->addWidget(settings);

    // Buttons
    auto *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    btnBox->button(QDialogButtonBox::Ok)->setText(tr("Generate"));
    connect(btnBox, &QDialogButtonBox::accepted, this, &CAGeneDialog::onGenerate);
    connect(btnBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(btnBox);
}

void CAGeneDialog::onBrowseCert()
{
    QString path = QFileDialog::getSaveFileName(this, tr("Select Certificate Save Location"),
                        m_certPathEdit->text(),
                        tr("PEM Files (*.pem);;All Files (*)"));
    if (!path.isEmpty()) m_certPathEdit->setText(path);
}

void CAGeneDialog::onBrowseKey()
{
    QString path = QFileDialog::getSaveFileName(this, tr("Select Key Save Location"),
                        m_keyPathEdit->text(),
                        tr("PEM Files (*.pem);;All Files (*)"));
    if (!path.isEmpty()) m_keyPathEdit->setText(path);
}

void CAGeneDialog::onGenerate()
{
    QString errMsg;
    if (!m_subject->validate(&errMsg)) {
        QMessageBox::warning(this, tr("Input Error"), errMsg);
        return;
    }

    if (m_certPathEdit->text().trimmed().isEmpty() ||
        m_keyPathEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Please specify output paths for certificate and key"));
        return;
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

    bool ok = false;
    if (m_store && m_store->isValid()) {
        // Use PKI store-aware generation
        ok = CertManager::generateCACertInStore(
            *m_store,
            m_subject->subjectInfo(),
            m_daysSpin->value(),
            m_keyTypeCombo->currentText(),
            m_keyParamCombo->currentText(),
            passphrase
        );
        if (ok) {
            m_generatedCertPath = m_store->caCertPath();
            m_generatedKeyPath  = m_store->caKeyPath();
        }
    } else {
        ok = CertManager::generateCACert(
            m_certPathEdit->text().trimmed(),
            m_keyPathEdit->text().trimmed(),
            m_subject->subjectInfo(),
            m_daysSpin->value(),
            m_keyTypeCombo->currentText(),
            m_keyParamCombo->currentText(),
            passphrase
        );
        if (ok) {
            m_generatedCertPath = m_certPathEdit->text().trimmed();
            m_generatedKeyPath  = m_keyPathEdit->text().trimmed();
        }
    }

    setCursor(Qt::ArrowCursor);

    if (ok) {
        QMessageBox::information(this, tr("Success"),
            tr("CA root certificate generated!\n\n"
            "Certificate: ") + m_generatedCertPath + tr("\n"
            "Key: ") + m_generatedKeyPath);
        accept();
    } else {
        QMessageBox::critical(this, tr("Generation Failed"), CertManager::lastError());
    }
}
