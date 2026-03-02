#include "chainbuilddialog.h"
#include "certmanager.h"
#include "../pkistore.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileInfo>

ChainBuildDialog::ChainBuildDialog(PkiStore *store, QWidget *parent)
    : QDialog(parent), m_store(store)
{
    setWindowTitle(tr("Build Certificate Chain"));
    setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinMaxButtonsHint);
    setMinimumSize(800, 500);
    setSizeGripEnabled(true);

    auto *mainLayout = new QVBoxLayout(this);

    auto *titleLabel = new QLabel("<b>" + tr("Build Certificate Chain") + "</b>", this);
    titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 4px;");
    mainLayout->addWidget(titleLabel);

    auto *hint = new QLabel(
        tr("Select certificates from the left and add them to the chain on the right. "
           "Use the arrow buttons to adjust the order. At least 2 certificates are required."), this);
    hint->setWordWrap(true);
    hint->setStyleSheet("color: #555; margin-bottom: 8px;");
    mainLayout->addWidget(hint);

    // ── Main area: cert tree (left) + buttons (center) + chain list (right) ──
    auto *centerLayout = new QHBoxLayout();

    // Left: available certificates
    auto *leftGroup = new QGroupBox(tr("Available Certificates"), this);
    auto *leftLayout = new QVBoxLayout(leftGroup);
    m_certTree = new QTreeWidget(this);
    m_certTree->setHeaderLabels({tr("Name"), tr("Type"), tr("Serial"), tr("Subject (CN)"), tr("Status")});
    m_certTree->setAlternatingRowColors(true);
    m_certTree->setRootIsDecorated(true);
    m_certTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_certTree->setColumnWidth(0, 160);
    m_certTree->setColumnWidth(1, 100);
    m_certTree->setColumnWidth(2, 60);
    m_certTree->setColumnWidth(3, 180);
    leftLayout->addWidget(m_certTree);
    centerLayout->addWidget(leftGroup, 3);

    // Center: add/remove buttons
    auto *midLayout = new QVBoxLayout();
    midLayout->addStretch();
    m_addBtn = new QPushButton(tr("Add →"), this);
    m_removeBtn = new QPushButton(tr("← Remove"), this);
    midLayout->addWidget(m_addBtn);
    midLayout->addWidget(m_removeBtn);
    midLayout->addStretch();
    centerLayout->addLayout(midLayout);

    // Right: chain order
    auto *rightGroup = new QGroupBox(tr("Chain Order (top → bottom)"), this);
    auto *rightLayout = new QVBoxLayout(rightGroup);
    m_chainList = new QListWidget(this);
    m_chainList->setAlternatingRowColors(true);
    m_chainList->setSelectionMode(QAbstractItemView::SingleSelection);
    rightLayout->addWidget(m_chainList);

    auto *orderLayout = new QHBoxLayout();
    m_upBtn = new QPushButton(tr("↑ Move Up"), this);
    m_downBtn = new QPushButton(tr("↓ Move Down"), this);
    orderLayout->addWidget(m_upBtn);
    orderLayout->addWidget(m_downBtn);
    rightLayout->addLayout(orderLayout);
    centerLayout->addWidget(rightGroup, 2);

    mainLayout->addLayout(centerLayout, 1);

    // ── Output path ──
    auto *outGroup = new QGroupBox(tr("Output"), this);
    auto *outLayout = new QHBoxLayout(outGroup);
    m_outPathEdit = new QLineEdit(this);
    if (m_store && m_store->isValid())
        m_outPathEdit->setText(m_store->rootDir() + "/fullchain.pem");
    else
        m_outPathEdit->setText(QDir::currentPath() + "/fullchain.pem");
    auto *browseBtn = new QPushButton(tr("Browse..."), this);
    connect(browseBtn, &QPushButton::clicked, this, &ChainBuildDialog::onBrowseOutput);
    outLayout->addWidget(new QLabel(tr("Output File:"), this));
    outLayout->addWidget(m_outPathEdit, 1);
    outLayout->addWidget(browseBtn);
    mainLayout->addWidget(outGroup);

    // ── Buttons ──
    auto *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    btnBox->button(QDialogButtonBox::Ok)->setText(tr("Build Chain"));
    connect(btnBox, &QDialogButtonBox::accepted, this, &ChainBuildDialog::onBuild);
    connect(btnBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(btnBox);

    // ── Connections ──
    connect(m_addBtn, &QPushButton::clicked, this, &ChainBuildDialog::onAddToChain);
    connect(m_removeBtn, &QPushButton::clicked, this, &ChainBuildDialog::onRemoveFromChain);
    connect(m_upBtn, &QPushButton::clicked, this, &ChainBuildDialog::onMoveUp);
    connect(m_downBtn, &QPushButton::clicked, this, &ChainBuildDialog::onMoveDown);
    connect(m_chainList, &QListWidget::currentRowChanged, this, [this]() { updateButtonStates(); });
    connect(m_certTree, &QTreeWidget::itemSelectionChanged, this, [this]() { updateButtonStates(); });

    // Double-click to add
    connect(m_certTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *item, int) {
        if (item && !item->data(0, Qt::UserRole).toString().isEmpty())
            onAddToChain();
    });

    populateCertTree();
    updateButtonStates();
}

void ChainBuildDialog::populateCertTree()
{
    m_certTree->clear();
    if (!m_store || !m_store->isValid()) return;

    QFont boldFont = m_certTree->font();
    boldFont.setBold(true);

    // ── CA cert ──
    if (QFileInfo::exists(m_store->caCertPath())) {
        auto *caNode = new QTreeWidgetItem(m_certTree, {tr("CA Certificates")});
        caNode->setFirstColumnSpanned(true);
        caNode->setFont(0, boldFont);

        CertInfo info = CertManager::parseCert(m_store->caCertPath());
        auto *item = new QTreeWidgetItem(caNode);
        item->setText(0, "ca.crt");
        item->setText(1, tr("Root CA"));
        item->setText(2, info.serial);
        item->setText(3, info.subject);
        item->setText(4, tr("Valid"));
        item->setData(0, Qt::UserRole, m_store->caCertPath());  // store file path
    }

    // ── Intermediate CAs ──
    QDir intDir(m_store->intermediateDir());
    QStringList intCerts = intDir.entryList({"*.crt", "*.pem"}, QDir::Files);
    if (!intCerts.isEmpty()) {
        auto *intNode = new QTreeWidgetItem(m_certTree, {tr("Intermediate CA Certificates")});
        intNode->setFirstColumnSpanned(true);
        intNode->setFont(0, boldFont);
        for (const QString &f : intCerts) {
            QString path = intDir.absoluteFilePath(f);
            CertInfo info = CertManager::parseCert(path);
            auto *item = new QTreeWidgetItem(intNode);
            item->setText(0, f);
            item->setText(1, tr("Intermediate CA"));
            item->setText(2, info.serial);
            item->setText(3, info.subject);
            item->setText(4, tr("Valid"));
            item->setData(0, Qt::UserRole, path);
        }
    }

    // ── Issued certs from index.txt ──
    QList<IndexEntry> entries = m_store->readIndex();
    if (!entries.isEmpty()) {
        auto *issuedNode = new QTreeWidgetItem(m_certTree, {tr("Issued Certificates")});
        issuedNode->setFirstColumnSpanned(true);
        issuedNode->setFont(0, boldFont);

        for (const IndexEntry &e : entries) {
            if (e.serial == "00") continue;

            QString certFile = m_store->issuedCertPath(e.serial);
            if (!QFileInfo::exists(certFile)) {
                certFile = m_store->certPathForSerial(e.serial);
                if (!QFileInfo::exists(certFile))
                    continue;  // skip if cert file not found
            }

            auto *item = new QTreeWidgetItem(issuedNode);
            item->setText(0, e.filename);
            item->setText(1, tr("Certificate"));
            item->setText(2, e.serial);
            item->setText(3, e.subject);

            QString statusText;
            if (e.status == 'V') statusText = tr("Valid");
            else if (e.status == 'R') statusText = tr("Revoked");
            else if (e.status == 'E') statusText = tr("Expired");
            else statusText = QString(e.status);
            item->setText(4, statusText);

            item->setData(0, Qt::UserRole, certFile);
        }
    }

    m_certTree->expandAll();
}

void ChainBuildDialog::onAddToChain()
{
    QList<QTreeWidgetItem *> selected = m_certTree->selectedItems();
    for (QTreeWidgetItem *item : selected) {
        QString path = item->data(0, Qt::UserRole).toString();
        if (path.isEmpty()) continue;  // category node

        // Check if already in chain
        bool exists = false;
        for (int i = 0; i < m_chainList->count(); ++i) {
            if (m_chainList->item(i)->data(Qt::UserRole).toString() == path) {
                exists = true;
                break;
            }
        }
        if (exists) continue;

        QString label = item->text(0) + "  [" + item->text(3) + "]";
        auto *listItem = new QListWidgetItem(label, m_chainList);
        listItem->setData(Qt::UserRole, path);
    }
    updateButtonStates();
}

void ChainBuildDialog::onRemoveFromChain()
{
    QList<QListWidgetItem *> selected = m_chainList->selectedItems();
    for (QListWidgetItem *item : selected)
        delete item;
    updateButtonStates();
}

void ChainBuildDialog::onMoveUp()
{
    int row = m_chainList->currentRow();
    if (row <= 0) return;
    QListWidgetItem *item = m_chainList->takeItem(row);
    m_chainList->insertItem(row - 1, item);
    m_chainList->setCurrentRow(row - 1);
    updateButtonStates();
}

void ChainBuildDialog::onMoveDown()
{
    int row = m_chainList->currentRow();
    if (row < 0 || row >= m_chainList->count() - 1) return;
    QListWidgetItem *item = m_chainList->takeItem(row);
    m_chainList->insertItem(row + 1, item);
    m_chainList->setCurrentRow(row + 1);
    updateButtonStates();
}

void ChainBuildDialog::onBrowseOutput()
{
    QString startDir = m_store && m_store->isValid()
        ? m_store->rootDir() : QDir::currentPath();
    QString path = QFileDialog::getSaveFileName(this, tr("Save Certificate Chain"),
        m_outPathEdit->text().isEmpty() ? startDir + "/fullchain.pem" : m_outPathEdit->text(),
        tr("PEM Files (*.pem *.crt);;All Files (*)"));
    if (!path.isEmpty())
        m_outPathEdit->setText(path);
}

void ChainBuildDialog::onBuild()
{
    if (m_chainList->count() < 2) {
        QMessageBox::warning(this, tr("Insufficient Certificates"),
            tr("Please add at least 2 certificates to build a chain."));
        return;
    }

    QString outPath = m_outPathEdit->text().trimmed();
    if (outPath.isEmpty()) {
        QMessageBox::warning(this, tr("No Output Path"),
            tr("Please specify an output file path."));
        return;
    }

    QStringList certPaths;
    for (int i = 0; i < m_chainList->count(); ++i)
        certPaths << m_chainList->item(i)->data(Qt::UserRole).toString();

    if (CertManager::buildCertChain(certPaths, outPath)) {
        m_outputPath = outPath;
        accept();
    } else {
        QMessageBox::critical(this, tr("Build Failed"), CertManager::lastError());
    }
}

void ChainBuildDialog::updateButtonStates()
{
    // Add button: enabled when a cert item (not category) is selected in tree
    bool canAdd = false;
    for (QTreeWidgetItem *item : m_certTree->selectedItems()) {
        if (!item->data(0, Qt::UserRole).toString().isEmpty()) {
            canAdd = true;
            break;
        }
    }
    m_addBtn->setEnabled(canAdd);

    // Remove button
    m_removeBtn->setEnabled(!m_chainList->selectedItems().isEmpty());

    // Move buttons
    int row = m_chainList->currentRow();
    m_upBtn->setEnabled(row > 0);
    m_downBtn->setEnabled(row >= 0 && row < m_chainList->count() - 1);
}
