#ifndef CHAINBUILDDIALOG_H
#define CHAINBUILDDIALOG_H

#include <QDialog>
#include <QTreeWidget>
#include <QListWidget>
#include <QPushButton>
#include <QLineEdit>

class PkiStore;

/**
 * @brief Dialog for building a certificate chain from PKI certificates.
 *
 * Displays all certificates in the PKI store (from index.txt + CA files),
 * allows the user to select and reorder them, then outputs a chain file.
 */
class ChainBuildDialog : public QDialog
{
    Q_OBJECT
public:
    explicit ChainBuildDialog(PkiStore *store, QWidget *parent = nullptr);

    QString outputPath() const { return m_outputPath; }

private slots:
    void onAddToChain();
    void onRemoveFromChain();
    void onMoveUp();
    void onMoveDown();
    void onBrowseOutput();
    void onBuild();
    void updateButtonStates();

private:
    void populateCertTree();

    PkiStore       *m_store;
    QTreeWidget    *m_certTree;      // available certs (left)
    QListWidget    *m_chainList;     // selected chain order (right)
    QPushButton    *m_addBtn;
    QPushButton    *m_removeBtn;
    QPushButton    *m_upBtn;
    QPushButton    *m_downBtn;
    QLineEdit      *m_outPathEdit;
    QString         m_outputPath;
};

#endif // CHAINBUILDDIALOG_H
