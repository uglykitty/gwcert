#include "certviewdialog.h"
#include "certmanager.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileInfo>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QFile>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFont>

CertViewDialog::CertViewDialog(const QString &filePath, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("View Certificate - ") + QFileInfo(filePath).fileName());
    setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinMaxButtonsHint);
    setMinimumSize(650, 500);
    setSizeGripEnabled(true);

    auto *layout = new QVBoxLayout(this);

    m_titleLabel = new QLabel(this);
    m_titleLabel->setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 6px;");
    layout->addWidget(m_titleLabel);

    m_tabs = new QTabWidget(this);

    // Info tab
    m_infoTree = new QTreeWidget(this);
    m_infoTree->setHeaderLabels({tr("Property"), tr("Value")});
    m_infoTree->header()->setStretchLastSection(true);
    m_infoTree->setColumnWidth(0, 180);
    m_infoTree->setAlternatingRowColors(true);
    m_tabs->addTab(m_infoTree, tr("Certificate Info"));

    // PEM tab
    m_pemView = new QTextEdit(this);
    m_pemView->setReadOnly(true);
    m_pemView->setFont(QFont("Courier New", 10));
    m_tabs->addTab(m_pemView, tr("Detail Text"));

    layout->addWidget(m_tabs);

    // Buttons
    auto *btnLayout = new QHBoxLayout();
    auto *copyBtn = new QPushButton(tr("Copy PEM to Clipboard"), this);
    connect(copyBtn, &QPushButton::clicked, this, [this, filePath]() {
        QFile f(filePath);
        if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QApplication::clipboard()->setText(f.readAll());
            QMessageBox::information(this, tr("Copied"), tr("PEM content copied to clipboard"));
        }
    });
    btnLayout->addWidget(copyBtn);

    auto *closeBtn = new QPushButton(tr("Close"), this);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnLayout->addStretch();
    btnLayout->addWidget(closeBtn);
    layout->addLayout(btnLayout);

    // Load data
    QString suffix = QFileInfo(filePath).suffix().toLower();
    if (suffix == "csr") {
        loadCSR(filePath);
    } else {
        loadCertificate(filePath);
    }
}

void CertViewDialog::loadCertificate(const QString &path)
{
    CertInfo info = CertManager::parseCert(path);

    m_titleLabel->setText(tr("Certificate: ") + QFileInfo(path).fileName());

    auto addItem = [this](const QString &key, const QString &value,
                          QTreeWidgetItem *parent = nullptr) -> QTreeWidgetItem* {
        auto *item = parent ? new QTreeWidgetItem(parent)
                            : new QTreeWidgetItem(m_infoTree);
        item->setText(0, key);
        item->setText(1, value);
        return item;
    };

    addItem(tr("Subject"), info.subject);
    addItem(tr("Issuer"), info.issuer);
    addItem(tr("Serial Number"), info.serial);
    addItem(tr("Valid From"), info.notBefore);
    addItem(tr("Valid Until"), info.notAfter);
    addItem(tr("Signature Algorithm"), info.signatureAlgorithm);
    addItem(tr("Public Key Algorithm"), info.publicKeyAlgorithm);
    addItem(tr("Public Key Size"), QString::number(info.publicKeyBits) + " bits");
    addItem(tr("Is CA"), info.isCA ? tr("Yes") : tr("No"));
    addItem(tr("SHA-256 Fingerprint"), info.fingerprint);

    if (!info.sanEntries.isEmpty()) {
        auto *sanItem = addItem(tr("Subject Alternative Name (SAN)"), QString::number(info.sanEntries.size()) + tr(" entries"));
        for (const QString &san : info.sanEntries) {
            addItem(san.section(':', 0, 0), san.section(':', 1), sanItem);
        }
        sanItem->setExpanded(true);
    }

    m_infoTree->expandAll();
    m_pemView->setPlainText(info.pemText);
}

void CertViewDialog::loadCSR(const QString &path)
{
    CertInfo info = CertManager::parseCSR(path);

    m_titleLabel->setText(tr("CSR: ") + QFileInfo(path).fileName());

    auto addItem = [this](const QString &key, const QString &value,
                          QTreeWidgetItem *parent = nullptr) -> QTreeWidgetItem* {
        auto *item = parent ? new QTreeWidgetItem(parent)
                            : new QTreeWidgetItem(m_infoTree);
        item->setText(0, key);
        item->setText(1, value);
        return item;
    };

    addItem(tr("Subject"), info.subject);
    addItem(tr("Public Key Algorithm"), info.publicKeyAlgorithm);
    addItem(tr("Public Key Size"), QString::number(info.publicKeyBits) + " bits");

    if (!info.sanEntries.isEmpty()) {
        auto *sanItem = addItem(tr("Subject Alternative Name (SAN)"), QString::number(info.sanEntries.size()) + tr(" entries"));
        for (const QString &san : info.sanEntries) {
            addItem(san.section(':', 0, 0), san.section(':', 1), sanItem);
        }
        sanItem->setExpanded(true);
    }

    m_infoTree->expandAll();
    m_pemView->setPlainText(info.pemText);
}
