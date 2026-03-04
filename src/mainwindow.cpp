#include "mainwindow.h"
#include "certmanager.h"
#include "pkistore.h"
#include "dialogs/cagenedialog.h"
#include "dialogs/csrgenedialog.h"
#include "dialogs/certsigndialog.h"
#include "dialogs/certviewdialog.h"
#include "dialogs/chainbuilddialog.h"

#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QTimeZone>
#include <QIcon>
#include <QDir>
#include <QFileInfo>
#include <QDirIterator>
#include <QLabel>
#include <QInputDialog>
#include <QSettings>
#include <QFont>
#include <QPushButton>
#include <QActionGroup>

// ── Expiry date formatting helpers ─────────────────────────────────────────

/**
 * Parse raw expiry date string from either:
 *   - OpenSSL index.txt format: YYMMDDHHmmssZ  (e.g. "270303120000Z")
 *   - ASN1_TIME_print format:   "Mar  3 12:00:00 2027 GMT"
 */
QDateTime MainWindow::parseExpiryDate(const QString &raw)
{
    QString s = raw.trimmed();
    if (s.isEmpty()) return {};

    // Try index.txt format: YYMMDDHHmmssZ (13 chars) or YYYYMMDDHHmmssZ (15 chars)
    if (s.endsWith('Z') && (s.length() == 13 || s.length() == 15)) {
        QString expanded = s;
        if (s.length() == 13) {
            // 2-digit year: OpenSSL convention — values < 50 → 20xx, >= 50 → 19xx
            int yy = s.left(2).toInt();
            expanded = QString("%1%2").arg(yy < 50 ? "20" : "19").arg(s);
        }
        QDateTime dt = QDateTime::fromString(expanded, "yyyyMMddHHmmss'Z'");
        dt.setTimeZone(QTimeZone::utc());
        return dt;
    }

    // Try ASN1_TIME_print format: "Mar  3 12:00:00 2027 GMT"
    QString norm = s;
    norm.remove(" GMT").remove(" UTC");
    // Normalize multiple spaces
    norm = norm.simplified();
    QDateTime dt = QDateTime::fromString(norm, "MMM d HH:mm:ss yyyy");
    if (!dt.isValid())
        dt = QDateTime::fromString(norm, "MMM dd HH:mm:ss yyyy");
    if (dt.isValid())
        dt.setTimeZone(QTimeZone::utc());
    return dt;
}

/**
 * Format an expiry date string for display:
 *   "2027-03-03  (365 days)"  or  "2025-01-15  (Expired)"
 */
QString MainWindow::formatExpiryDisplay(const QString &raw)
{
    QDateTime dt = parseExpiryDate(raw);
    if (!dt.isValid()) return raw;  // fallback to original

    QDateTime now = QDateTime::currentDateTimeUtc();
    qint64 daysLeft = now.daysTo(dt);

    QString dateStr = dt.toLocalTime().toString("yyyy-MM-dd HH:mm");

    if (daysLeft < 0)
        return dateStr + "  (" + tr("Expired") + ")";
    else if (daysLeft == 0)
        return dateStr + "  (" + tr("Expires today") + ")";
    else if (daysLeft == 1)
        return dateStr + "  (" + tr("1 day") + ")";
    else
        return dateStr + QString("  (%1 ").arg(daysLeft) + tr("days") + ")";
}

/**
 * Apply formatted expiry text and color to a tree item column.
 *   - Red:    expired or ≤ 0 days
 *   - Orange: ≤ 30 days
 *   - Yellow-brown: ≤ 90 days
 *   - Default: > 90 days
 */
void MainWindow::applyExpiryStyle(QTreeWidgetItem *item, int column, const QString &raw)
{
    item->setText(column, formatExpiryDisplay(raw));

    QDateTime dt = parseExpiryDate(raw);
    if (!dt.isValid()) return;

    qint64 daysLeft = QDateTime::currentDateTimeUtc().daysTo(dt);
    if (daysLeft <= 0)
        item->setForeground(column, QColor("#d32f2f"));       // red
    else if (daysLeft <= 30)
        item->setForeground(column, QColor("#e65100"));       // deep orange
    else if (daysLeft <= 90)
        item->setForeground(column, QColor("#f9a825"));       // amber
}

// ──────────────────────────────────────────────────────────────────────────

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUI();
    setupMenuBar();
    setupToolBar();

    statusBar()->showMessage(tr("Ready"));
    appendLog(tr("GWCert Certificate Manager started"));

    // Restore last PKI directory
    QSettings settings;
    QString lastDir = settings.value("pki/lastDir").toString();
    if (!lastDir.isEmpty() && QDir(lastDir).exists()) {
        loadPkiDir(lastDir);
    }
}

void MainWindow::setupUI()
{
    auto *central = new QWidget(this);
    setCentralWidget(central);

    auto *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(4, 4, 4, 4);

    // PKI status bar
    auto *pkiBar = new QHBoxLayout();
    auto *pkiLabel = new QLabel(tr("PKI Directory:"), this);
    pkiLabel->setStyleSheet("font-weight: bold;");
    m_pkiStatusLabel = new QLabel(tr("Not loaded"), this);
    m_pkiStatusLabel->setStyleSheet("color: #888;");
    pkiBar->addWidget(pkiLabel);
    pkiBar->addWidget(m_pkiStatusLabel, 1);
    mainLayout->addLayout(pkiBar);

    m_splitter = new QSplitter(Qt::Vertical, this);

    // Certificate tree view — with Serial column
    m_certTree = new QTreeWidget(this);
    m_certTree->setHeaderLabels({tr("Name"), tr("Type"), tr("Serial"), tr("Subject (CN)"), tr("Expiry"), tr("Status"), tr("Path")});
    m_certTree->header()->setStretchLastSection(true);
    m_certTree->setAlternatingRowColors(true);
    m_certTree->setRootIsDecorated(true);
    m_certTree->setColumnWidth(0, 180);
    m_certTree->setColumnWidth(1, 80);
    m_certTree->setColumnWidth(2, 80);
    m_certTree->setColumnWidth(3, 200);
    m_certTree->setColumnWidth(4, 160);
    m_certTree->setColumnWidth(5, 60);

    connect(m_certTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *item, int) {
        if (!item) return;
        QString path = item->text(6);
        if (!path.isEmpty() && QFileInfo::exists(path)) {
            CertViewDialog dlg(path, this);
            dlg.exec();
        }
    });

    // Right-click context menu
    m_certTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_certTree, &QTreeWidget::customContextMenuRequested,
            this, &MainWindow::onTreeContextMenu);

    // Log output
    m_logView = new QTextEdit(this);
    m_logView->setReadOnly(true);
    m_logView->setMaximumHeight(200);
    m_logView->setStyleSheet("QTextEdit { font-family: 'Courier New', monospace; font-size: 12px; }");

    m_splitter->addWidget(m_certTree);
    m_splitter->addWidget(m_logView);
    m_splitter->setStretchFactor(0, 3);
    m_splitter->setStretchFactor(1, 1);

    mainLayout->addWidget(m_splitter);
}

void MainWindow::setupMenuBar()
{
    // ── PKI 菜单 ──
    QMenu *pkiMenu = menuBar()->addMenu(tr("PKI(&P)"));

    QAction *actInit = pkiMenu->addAction(tr("Initialize PKI Directory(&I)..."));
    connect(actInit, &QAction::triggered, this, &MainWindow::onInitPKI);

    QAction *actOpen = pkiMenu->addAction(tr("Open PKI Directory(&O)..."));
    actOpen->setShortcut(QKeySequence::Open);
    connect(actOpen, &QAction::triggered, this, &MainWindow::onOpenPKI);

    QAction *actRefresh = pkiMenu->addAction(tr("Refresh(&R)"));
    actRefresh->setShortcut(QKeySequence::Refresh);
    connect(actRefresh, &QAction::triggered, this, &MainWindow::refreshPkiTree);

    pkiMenu->addSeparator();

    QAction *actIndex = pkiMenu->addAction(tr("View Certificate Database(&D)..."));
    connect(actIndex, &QAction::triggered, this, &MainWindow::onViewIndex);

    pkiMenu->addSeparator();

    QAction *actExit = pkiMenu->addAction(tr("Quit(&Q)"));
    actExit->setShortcut(QKeySequence::Quit);
    connect(actExit, &QAction::triggered, this, &QWidget::close);

    // ── 证书操作菜单 ──
    QMenu *certMenu = menuBar()->addMenu(tr("Certificate(&C)"));

    QAction *actCA = certMenu->addAction(QIcon(":/icons/ca.svg"), tr("Generate CA Certificate(&A)..."));
    connect(actCA, &QAction::triggered, this, &MainWindow::onGenerateCA);

    QAction *actCSR = certMenu->addAction(QIcon(":/icons/csr.svg"), tr("Generate CSR(&S)..."));
    connect(actCSR, &QAction::triggered, this, &MainWindow::onGenerateCSR);

    QAction *actSign = certMenu->addAction(QIcon(":/icons/sign.svg"), tr("Sign Certificate(&I)..."));
    connect(actSign, &QAction::triggered, this, &MainWindow::onSignCert);

    certMenu->addSeparator();

    QAction *actView = certMenu->addAction(QIcon(":/icons/view.svg"), tr("View Certificate(&V)..."));
    connect(actView, &QAction::triggered, this, &MainWindow::onViewCert);

    QAction *actVerify = certMenu->addAction(tr("Verify Certificate(&E)..."));
    connect(actVerify, &QAction::triggered, this, &MainWindow::onVerifyCert);

    certMenu->addSeparator();

    QAction *actP12 = certMenu->addAction(tr("Export PKCS#12(&P)..."));
    connect(actP12, &QAction::triggered, this, &MainWindow::onExportPKCS12);

    QAction *actChain = certMenu->addAction(tr("Build Certificate Chain(&B)..."));
    connect(actChain, &QAction::triggered, this, &MainWindow::onBuildCertChain);

    // ── 帮助菜单 ──
    QMenu *helpMenu = menuBar()->addMenu(tr("Help(&H)"));
    QAction *actAbout = helpMenu->addAction(tr("About(&A)..."));
    connect(actAbout, &QAction::triggered, this, &MainWindow::onAbout);

    // ── 语言菜单 ──
    QMenu *langMenu = menuBar()->addMenu(tr("Language(&L)"));
    auto *langGroup = new QActionGroup(this);
    langGroup->setExclusive(true);

    QSettings langSettings;
    QString currentLang = langSettings.value("app/language", "en").toString();

    auto *actEN = langMenu->addAction("English");
    actEN->setCheckable(true);
    actEN->setChecked(currentLang == "en");
    actEN->setData("en");
    langGroup->addAction(actEN);

    auto *actCN = langMenu->addAction("中文");
    actCN->setCheckable(true);
    actCN->setChecked(currentLang == "zh_CN");
    actCN->setData("zh_CN");
    langGroup->addAction(actCN);

    connect(langGroup, &QActionGroup::triggered, this, [this](QAction *action) {
        onSwitchLanguage(action->data().toString());
    });
}

void MainWindow::setupToolBar()
{
    m_toolBar = addToolBar(tr("Main Toolbar"));
    m_toolBar->setIconSize(QSize(24, 24));
    m_toolBar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

    auto *actInit = m_toolBar->addAction(tr("Init PKI"));
    connect(actInit, &QAction::triggered, this, &MainWindow::onInitPKI);

    auto *actOpen = m_toolBar->addAction(tr("Open PKI"));
    connect(actOpen, &QAction::triggered, this, &MainWindow::onOpenPKI);

    m_toolBar->addSeparator();

    auto *actCA = m_toolBar->addAction(QIcon(":/icons/ca.svg"), tr("Generate CA"));
    connect(actCA, &QAction::triggered, this, &MainWindow::onGenerateCA);

    auto *actCSR = m_toolBar->addAction(QIcon(":/icons/csr.svg"), tr("Generate CSR"));
    connect(actCSR, &QAction::triggered, this, &MainWindow::onGenerateCSR);

    auto *actSign = m_toolBar->addAction(QIcon(":/icons/sign.svg"), tr("Sign Cert"));
    connect(actSign, &QAction::triggered, this, &MainWindow::onSignCert);

    m_toolBar->addSeparator();

    auto *actView = m_toolBar->addAction(QIcon(":/icons/view.svg"), tr("View Cert"));
    connect(actView, &QAction::triggered, this, &MainWindow::onViewCert);
}

void MainWindow::appendLog(const QString &msg, bool isError)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    QString color = isError ? "#d32f2f" : "#333";
    m_logView->append(
        QString("<span style='color:%1'>[%2] %3</span>")
            .arg(color, timestamp, msg.toHtmlEscaped()));
}

void MainWindow::updatePkiStatus()
{
    if (m_pkiStore.isValid()) {
        QString serial = m_pkiStore.currentSerial();
        m_pkiStatusLabel->setText(m_pkiStore.rootDir() +
            "  |  " + tr("Next Serial: ") + serial);
        m_pkiStatusLabel->setStyleSheet("color: #2e7d32; font-weight: bold;");
    } else {
        m_pkiStatusLabel->setText(tr("Not loaded"));
        m_pkiStatusLabel->setStyleSheet("color: #888;");
    }
}

void MainWindow::loadPkiDir(const QString &dir)
{
    m_pkiStore.setRootDir(dir);

    if (m_pkiStore.isValid()) {
        appendLog(tr("PKI directory loaded: ") + dir);
        QSettings settings;
        settings.setValue("pki/lastDir", dir);
        updatePkiStatus();
        refreshPkiTree();
    } else {
        appendLog(tr("Invalid PKI directory (missing serial/index.txt): ") + dir, true);
    }
}

void MainWindow::refreshPkiTree()
{
    m_certTree->clear();

    if (!m_pkiStore.isValid()) {
        appendLog(tr("PKI directory not loaded. Please initialize or open a PKI directory first"), true);
        return;
    }

    updatePkiStatus();

    QFont boldFont = m_certTree->font();
    boldFont.setBold(true);

    // ── CA section ──
    auto *caNode = new QTreeWidgetItem(m_certTree, {tr("CA Certificates")});
    caNode->setFirstColumnSpanned(true);
    caNode->setFont(0, boldFont);

    if (QFileInfo::exists(m_pkiStore.caCertPath())) {
        CertInfo info = CertManager::parseCert(m_pkiStore.caCertPath());
        auto *item = new QTreeWidgetItem(caNode);
        item->setText(0, "ca.crt");
        item->setText(1, tr("Root CA"));
        item->setText(2, info.serial);
        item->setText(3, info.subject);
        applyExpiryStyle(item, 4, info.notAfter);
        item->setText(5, tr("Valid"));
        item->setText(6, m_pkiStore.caCertPath());
    }

    // Intermediate CAs
    QDir intDir(m_pkiStore.intermediateDir());
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
            applyExpiryStyle(item, 4, info.notAfter);
            item->setText(5, tr("Valid"));
            item->setText(6, path);
        }
    }

    // ── Issued certs from index.txt ──
    QList<IndexEntry> entries = m_pkiStore.readIndex();
    if (!entries.isEmpty()) {
        auto *issuedNode = new QTreeWidgetItem(m_certTree, {tr("Issued Certificates")});
        issuedNode->setFirstColumnSpanned(true);
        issuedNode->setFont(0, boldFont);

        for (const IndexEntry &e : entries) {
            if (e.serial == "00") continue; // Skip CA self-entry
            auto *item = new QTreeWidgetItem(issuedNode);
            item->setText(0, e.filename);
            item->setText(1, tr("Certificate"));
            item->setText(2, e.serial);
            item->setText(3, e.subject);
            applyExpiryStyle(item, 4, e.expiryDate);

            if (e.status == 'V') {
                item->setText(5, tr("Valid"));
            } else if (e.status == 'R') {
                item->setText(5, tr("Revoked"));
                item->setForeground(5, QColor("#d32f2f"));
            } else if (e.status == 'E') {
                item->setText(5, tr("Expired"));
                item->setForeground(5, QColor("#f57c00"));
            }

            QString certFile = m_pkiStore.issuedCertPath(e.serial);
            if (QFileInfo::exists(certFile))
                item->setText(6, certFile);
            else {
                certFile = m_pkiStore.certPathForSerial(e.serial);
                if (QFileInfo::exists(certFile))
                    item->setText(6, certFile);
            }
        }
    }

    // ── CSRs ──
    QDir csrDir(m_pkiStore.csrDir());
    QStringList csrFiles = csrDir.entryList({"*.csr"}, QDir::Files);
    if (!csrFiles.isEmpty()) {
        auto *csrNode = new QTreeWidgetItem(m_certTree, {tr("Certificate Requests (CSR)")});
        csrNode->setFirstColumnSpanned(true);
        csrNode->setFont(0, boldFont);
        for (const QString &f : csrFiles) {
            QString path = csrDir.absoluteFilePath(f);
            CertInfo info = CertManager::parseCSR(path);
            auto *item = new QTreeWidgetItem(csrNode);
            item->setText(0, f);
            item->setText(1, "CSR");
            item->setText(2, "-");
            item->setText(3, info.subject);
            item->setText(4, "-");
            item->setText(5, tr("Pending"));
            item->setText(6, path);
        }
    }

    // ── Private keys ──
    QDir keyDir(m_pkiStore.privateDir());
    QStringList keyFiles = keyDir.entryList({"*.key", "*.pem"}, QDir::Files);
    if (!keyFiles.isEmpty()) {
        auto *keyNode = new QTreeWidgetItem(m_certTree, {tr("Private Keys")});
        keyNode->setFirstColumnSpanned(true);
        keyNode->setFont(0, boldFont);
        for (const QString &f : keyFiles) {
            auto *item = new QTreeWidgetItem(keyNode);
            item->setText(0, f);
            item->setText(1, tr("Private Key"));
            item->setText(2, "-");
            item->setText(3, "-");
            item->setText(4, "-");
            item->setText(5, "-");
            item->setText(6, keyDir.absoluteFilePath(f));
        }
    }

    m_certTree->expandAll();
    int certCount = entries.size();
    appendLog(tr("PKI directory refreshed, %1 certificate record(s)").arg(certCount));
    statusBar()->showMessage(tr("PKI: %1 | Next Serial: %2")
        .arg(m_pkiStore.rootDir(), m_pkiStore.currentSerial()));
}

// ── PKI Slots ──────────────────────────────────────────────────────────────

void MainWindow::onInitPKI()
{
    QString dir = QFileDialog::getExistingDirectory(this, tr("Select PKI Root Directory"),
                        QDir::homePath());
    if (dir.isEmpty()) return;

    QDir d(dir);
    if (!d.isEmpty() && !QFileInfo::exists(dir + "/serial")) {
        auto ret = QMessageBox::question(this, tr("Initialization Confirmation"),
            tr("Directory is not empty. Initialize PKI structure here?\n\n") + dir,
            QMessageBox::Yes | QMessageBox::No);
        if (ret != QMessageBox::Yes) return;
    }

    m_pkiStore.setRootDir(dir);
    if (m_pkiStore.initDirectory()) {
        appendLog(tr("PKI directory structure initialized: ") + dir);
        appendLog(tr("  Directories: ca/, intermediate/, certs/, newcerts/, csr/, private/, crl/"));
        appendLog(tr("  Files: serial (starting 0001), index.txt, index.txt.attr"));

        QSettings settings;
        settings.setValue("pki/lastDir", dir);
        updatePkiStatus();
        refreshPkiTree();

        QMessageBox::information(this, tr("Initialization Successful"),
            tr("PKI directory initialized!\n\n"
            "Directory: ") + dir + tr("\n\n"
            "Please generate a CA root certificate next."));
    } else {
        appendLog(tr("PKI directory initialization failed: ") + PkiStore::lastError(), true);
        QMessageBox::critical(this, tr("Initialization Failed"), PkiStore::lastError());
    }
}

void MainWindow::onOpenPKI()
{
    QString dir = QFileDialog::getExistingDirectory(this, tr("Open PKI Directory"),
                        QDir::homePath());
    if (dir.isEmpty()) return;

    loadPkiDir(dir);

    if (!m_pkiStore.isValid()) {
        QMessageBox::warning(this, tr("Invalid Directory"),
            tr("The selected directory is not a valid PKI directory.\n"
            "Please ensure it contains serial and index.txt files.\n\n"
            "To create a new one, use \"Initialize PKI Directory\"."));
    }
}

void MainWindow::onGenerateCA()
{
    CAGeneDialog dlg(m_pkiStore.isValid() ? &m_pkiStore : nullptr, this);
    if (dlg.exec() == QDialog::Accepted) {
        appendLog(tr("CA certificate generated: ") + dlg.certPath());
        appendLog(tr("  Key: ") + dlg.keyPath());
        if (m_pkiStore.isValid())
            refreshPkiTree();
    }
}

void MainWindow::onGenerateCSR()
{
    CSRGeneDialog dlg(m_pkiStore.isValid() ? &m_pkiStore : nullptr, this);
    if (dlg.exec() == QDialog::Accepted) {
        appendLog(tr("CSR generated: ") + dlg.csrPath());
        appendLog(tr("  Key: ") + dlg.keyPath());
        if (m_pkiStore.isValid())
            refreshPkiTree();
    }
}

void MainWindow::onSignCert()
{
    CertSignDialog dlg(m_pkiStore.isValid() ? &m_pkiStore : nullptr, this);
    if (dlg.exec() == QDialog::Accepted) {
        appendLog(tr("Certificate signed: ") + dlg.outCertPath());
        if (!dlg.allocatedSerial().isEmpty())
            appendLog(tr("  Serial: ") + dlg.allocatedSerial());
        if (m_pkiStore.isValid()) {
            updatePkiStatus();
            refreshPkiTree();
        }
    }
}

void MainWindow::onViewCert()
{
    QString startDir = m_pkiStore.isValid() ? m_pkiStore.rootDir() : QDir::currentPath();
    QString path = QFileDialog::getOpenFileName(this, tr("Select Certificate or CSR File"),
                        startDir,
                        tr("Certificate Files (*.pem *.crt *.cer *.csr);;All Files (*)"));
    if (path.isEmpty()) return;

    CertViewDialog dlg(path, this);
    dlg.exec();
}

void MainWindow::onVerifyCert()
{
    QString startDir = m_pkiStore.isValid() ? m_pkiStore.certsDir() : QDir::currentPath();
    QString certPath = QFileDialog::getOpenFileName(this, tr("Select Certificate to Verify"),
                            startDir,
                            tr("Certificate Files (*.pem *.crt *.cer);;All Files (*)"));
    if (certPath.isEmpty()) return;

    QString caDir = m_pkiStore.isValid() ? m_pkiStore.caDir() : QDir::currentPath();
    QString caPath = QFileDialog::getOpenFileName(this, tr("Select CA Certificate"),
                            caDir,
                            tr("Certificate Files (*.pem *.crt *.cer);;All Files (*)"));
    if (caPath.isEmpty()) return;

    QString result = CertManager::verifyCert(certPath, caPath);
    if (result.isEmpty()) {
        appendLog(tr("Certificate verification passed: ") + QFileInfo(certPath).fileName());
        QMessageBox::information(this, tr("Verification Result"), tr("Certificate verification passed!\n\nCertificate chain is valid."));
    } else {
        appendLog(tr("Certificate verification failed: ") + result, true);
        QMessageBox::warning(this, tr("Verification Result"), tr("Certificate verification failed!\n\n") + result);
    }
}

void MainWindow::onExportPKCS12()
{
    QString startDir = m_pkiStore.isValid() ? m_pkiStore.certsDir() : QDir::currentPath();

    QString certPath = QFileDialog::getOpenFileName(this, tr("Select Certificate"),
                            startDir,
                            tr("Certificate Files (*.pem *.crt *.cer);;All Files (*)"));
    if (certPath.isEmpty()) return;

    QString keyDir = m_pkiStore.isValid() ? m_pkiStore.privateDir() : QDir::currentPath();
    QString keyPath = QFileDialog::getOpenFileName(this, tr("Select Private Key"),
                            keyDir,
                            tr("Key Files (*.pem *.key);;All Files (*)"));
    if (keyPath.isEmpty()) return;

    bool ok = false;
    QString password = QInputDialog::getText(this, tr("PKCS#12 Password"),
                            tr("Set export password:"), QLineEdit::Password, "", &ok);
    if (!ok) return;

    QString p12Path = QFileDialog::getSaveFileName(this, tr("Save PKCS#12 File"),
                            startDir + "/certificate.p12",
                            tr("PKCS#12 (*.p12 *.pfx);;All Files (*)"));
    if (p12Path.isEmpty()) return;

    if (CertManager::exportPKCS12(p12Path, certPath, keyPath, password)) {
        appendLog(tr("PKCS#12 exported: ") + p12Path);
        QMessageBox::information(this, tr("Export Successful"), tr("PKCS#12 file exported:\n") + p12Path);
    } else {
        appendLog(tr("PKCS#12 export failed: ") + CertManager::lastError(), true);
        QMessageBox::critical(this, tr("Export Failed"), CertManager::lastError());
    }
}

void MainWindow::onBuildCertChain()
{
    if (!m_pkiStore.isValid()) {
        QMessageBox::warning(this, tr("Not Loaded"),
            tr("Please open or initialize a PKI directory first."));
        return;
    }

    ChainBuildDialog dlg(&m_pkiStore, this);
    if (dlg.exec() == QDialog::Accepted) {
        appendLog(tr("Certificate chain built: ") + dlg.outputPath());
        refreshPkiTree();
    }
}

void MainWindow::onViewIndex()
{
    if (!m_pkiStore.isValid()) {
        QMessageBox::warning(this, tr("Not Loaded"), tr("Please open or initialize a PKI directory first"));
        return;
    }

    QList<IndexEntry> entries = m_pkiStore.readIndex();

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Certificate Database (index.txt)"));
    dlg.setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMaximizeButtonHint | Qt::WindowMinimizeButtonHint);
    dlg.setMinimumSize(800, 400);

    auto *layout = new QVBoxLayout(&dlg);

    auto *infoLabel = new QLabel(
        tr("PKI Directory: %1\nNext Serial: %2\nRecords: %3")
            .arg(m_pkiStore.rootDir(), m_pkiStore.currentSerial())
            .arg(entries.size()),
        &dlg);
    infoLabel->setStyleSheet("font-size: 12px; margin-bottom: 8px;");
    layout->addWidget(infoLabel);

    auto *tree = new QTreeWidget(&dlg);
    tree->setHeaderLabels({tr("Serial"), tr("Status"), tr("Subject"), tr("Expiry"), tr("Revocation Date"), tr("Filename")});
    tree->setAlternatingRowColors(true);
    tree->setColumnWidth(0, 80);
    tree->setColumnWidth(1, 60);
    tree->setColumnWidth(2, 300);
    tree->setColumnWidth(3, 140);
    tree->setColumnWidth(4, 140);

    for (const IndexEntry &e : entries) {
        auto *item = new QTreeWidgetItem(tree);
        item->setText(0, e.serial);
        QString statusText;
        if (e.status == 'V') statusText = tr("Valid");
        else if (e.status == 'R') statusText = tr("Revoked");
        else if (e.status == 'E') statusText = tr("Expired");
        else statusText = QString(e.status);
        item->setText(1, statusText);
        item->setText(2, e.subject);
        applyExpiryStyle(item, 3, e.expiryDate);
        item->setText(4, e.revokeDate.isEmpty() ? QString() : formatExpiryDisplay(e.revokeDate));
        item->setText(5, e.filename);

        if (e.status == 'R')
            item->setForeground(1, QColor("#d32f2f"));
    }

    layout->addWidget(tree);

    auto *closeBtn = new QPushButton(tr("Close"), &dlg);
    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    layout->addWidget(closeBtn);

    dlg.exec();
}

void MainWindow::onAbout()
{
    QMessageBox::about(this, tr("About GWCert"),
        tr("<h2>GWCert Certificate Manager</h2>"
        "<p>Version 1.1.0</p>"
        "<p>A certificate management tool built with Qt 6 + OpenSSL.</p>"
        "<p><b>Features:</b></p>"
        "<ul>"
        "<li>PKI directory structure management</li>"
        "<li>Automatic certificate serial number management</li>"
        "<li>Certificate issuance database (index.txt)</li>"
        "<li>Generate self-signed CA root certificates</li>"
        "<li>Generate Certificate Signing Requests (CSR)</li>"
        "<li>Sign intermediate CA certificates</li>"
        "<li>Sign server/client certificates</li>"
        "<li>View certificate details</li>"
        "<li>Verify certificate chains</li>"
        "<li>Export to PKCS#12 format</li>"
        "</ul>"
        "<p><b>PKI Directory Structure:</b></p>"
        "<pre>"
        "pki/\n"
        "  ca/            - CA certificates and private keys\n"
        "  intermediate/  - Intermediate CAs\n"
        "  certs/         - Issued certificates\n"
        "  newcerts/      - Certificate archive\n"
        "  csr/           - Certificate requests\n"
        "  private/       - End-entity private keys\n"
        "  crl/           - Certificate revocation lists\n"
        "  serial         - Serial number\n"
        "  index.txt      - Certificate database\n"
        "</pre>"));
}

void MainWindow::onSwitchLanguage(const QString &lang)
{
    QSettings settings;
    settings.setValue("app/language", lang);
    settings.sync();  // Force flush to disk immediately
    QMessageBox::information(this, tr("Language Switch"),
        tr("Language setting saved. Please restart the application to apply."));
}

void MainWindow::onTreeContextMenu(const QPoint &pos)
{
    QTreeWidgetItem *item = m_certTree->itemAt(pos);

    QMenu menu(this);

    if (item) {
        QString type = item->text(1);
        QString path = item->text(6);

        if (!path.isEmpty()) {
            // View action — available for all file items
            if (QFileInfo::exists(path)) {
                QAction *actView = menu.addAction(QIcon(":/icons/view.svg"), tr("View Details"));
                connect(actView, &QAction::triggered, this, [this, path]() {
                    CertViewDialog dlg(path, this);
                    dlg.exec();
                });
            }

            // Sign action — only for CSR items
            if (type == "CSR") {
                QAction *actSign = menu.addAction(QIcon(":/icons/sign.svg"), tr("Sign This CSR..."));
                connect(actSign, &QAction::triggered, this, [this, path]() {
                    CertSignDialog dlg(m_pkiStore.isValid() ? &m_pkiStore : nullptr, this);
                    dlg.setCSRPath(path);
                    if (dlg.exec() == QDialog::Accepted) {
                        appendLog(tr("Certificate signed: ") + dlg.outCertPath());
                        if (!dlg.allocatedSerial().isEmpty())
                            appendLog(tr("  Serial: ") + dlg.allocatedSerial());
                        if (m_pkiStore.isValid()) {
                            updatePkiStatus();
                            refreshPkiTree();
                        }
                    }
                });
            }

            // Verify action — for certificate items
            if (type == tr("Root CA") || type == tr("Intermediate CA") || type == tr("Certificate")) {
                menu.addSeparator();
                QAction *actVerify = menu.addAction(tr("Verify Certificate..."));
                connect(actVerify, &QAction::triggered, this, [this, path]() {
                    QString caDir = m_pkiStore.isValid() ? m_pkiStore.caDir() : QDir::currentPath();
                    QString caPath = QFileDialog::getOpenFileName(this, tr("Select CA Certificate"),
                                            caDir,
                                            tr("Certificate Files (*.pem *.crt *.cer);;All Files (*)"));
                    if (caPath.isEmpty()) return;
                    QString result = CertManager::verifyCert(path, caPath);
                    if (result.isEmpty()) {
                        appendLog(tr("Certificate verification passed: ") + QFileInfo(path).fileName());
                        QMessageBox::information(this, tr("Verification Result"),
                            tr("Certificate verification passed!\n\nCertificate chain is valid."));
                    } else {
                        appendLog(tr("Certificate verification failed: ") + result, true);
                        QMessageBox::warning(this, tr("Verification Result"),
                            tr("Certificate verification failed!\n\n") + result);
                    }
                });
            }

            // Export actions — for certificates and private keys
            if (type == tr("Root CA") || type == tr("Intermediate CA") || type == tr("Certificate")
                || type == tr("Private Key")) {
                menu.addSeparator();

                QString displayName = item->text(0);
                QString exportLabel = (type == tr("Private Key"))
                    ? tr("Export Key...") : tr("Export Certificate...");
                QAction *actExport = menu.addAction(exportLabel);
                connect(actExport, &QAction::triggered, this, [this, path, displayName, type]() {
                    QString destDir = QFileDialog::getExistingDirectory(this,
                        tr("Select Export Directory"), QDir::homePath());
                    if (destDir.isEmpty()) return;

                    QString fileName = (type == tr("Private Key"))
                        ? QFileInfo(path).fileName()
                        : QFileInfo(displayName).fileName();
                    QString destFile = destDir + "/" + fileName;

                    if (QFile::exists(destFile)) {
                        auto ret = QMessageBox::question(this, tr("File Exists"),
                            tr("File \"%1\" already exists. Overwrite?").arg(fileName));
                        if (ret != QMessageBox::Yes) return;
                        QFile::remove(destFile);
                    }
                    if (QFile::copy(path, destFile)) {
                        appendLog(tr("Exported: ") + destFile);
                        QMessageBox::information(this, tr("Export Successful"),
                            tr("Exported to:\n") + destFile);
                    } else {
                        appendLog(tr("Export failed: ") + destFile, true);
                        QMessageBox::critical(this, tr("Export Failed"),
                            tr("Failed to copy file."));
                    }
                });
            }
        }
    }

    // Build certificate chain — always available when PKI is loaded
    if (m_pkiStore.isValid()) {
        if (!menu.isEmpty())
            menu.addSeparator();
        QAction *actChain = menu.addAction(tr("Build Certificate Chain..."));
        connect(actChain, &QAction::triggered, this, &MainWindow::onBuildCertChain);
    }

    // Refresh action — always available
    if (!menu.isEmpty())
        menu.addSeparator();
    QAction *actRefresh = menu.addAction(tr("Refresh"));
    actRefresh->setShortcut(QKeySequence::Refresh);
    connect(actRefresh, &QAction::triggered, this, &MainWindow::refreshPkiTree);

    menu.exec(m_certTree->viewport()->mapToGlobal(pos));
}
