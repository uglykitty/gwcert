#ifndef CERTVIEWDIALOG_H
#define CERTVIEWDIALOG_H

#include <QDialog>
#include <QTabWidget>
#include <QTextEdit>
#include <QTreeWidget>
#include <QLabel>

/**
 * @brief Dialog for viewing certificate or CSR details.
 */
class CertViewDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CertViewDialog(const QString &filePath, QWidget *parent = nullptr);

private:
    void loadCertificate(const QString &path);
    void loadCSR(const QString &path);

    QTabWidget  *m_tabs;
    QTreeWidget *m_infoTree;
    QTextEdit   *m_pemView;
    QLabel      *m_titleLabel;
};

#endif // CERTVIEWDIALOG_H
