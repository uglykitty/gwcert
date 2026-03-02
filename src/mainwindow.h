#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTextEdit>
#include <QTreeWidget>
#include <QToolBar>
#include <QStatusBar>
#include <QSplitter>
#include <QLabel>
#include <QTranslator>
#include <QActionGroup>

#include "pkistore.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);

    PkiStore& pkiStore() { return m_pkiStore; }
    const PkiStore& pkiStore() const { return m_pkiStore; }

private slots:
    void onInitPKI();
    void onOpenPKI();
    void onGenerateCA();
    void onGenerateCSR();
    void onSignCert();
    void onViewCert();
    void onVerifyCert();
    void onExportPKCS12();
    void onBuildCertChain();
    void onViewIndex();
    void onAbout();
    void onSwitchLanguage(const QString &lang);
    void onTreeContextMenu(const QPoint &pos);

private:
    void setupUI();
    void setupMenuBar();
    void setupToolBar();
    void appendLog(const QString &msg, bool isError = false);
    void refreshPkiTree();
    void updatePkiStatus();
    void loadPkiDir(const QString &dir);
    void retranslateUi();

    // Expiry date formatting helpers
    static QDateTime parseExpiryDate(const QString &raw);
    static QString formatExpiryDisplay(const QString &raw);
    static void applyExpiryStyle(QTreeWidgetItem *item, int column, const QString &raw);

    QSplitter   *m_splitter;
    QTreeWidget *m_certTree;
    QTextEdit   *m_logView;
    QToolBar    *m_toolBar;
    QLabel      *m_pkiStatusLabel;

    PkiStore     m_pkiStore;
};

#endif // MAINWINDOW_H
