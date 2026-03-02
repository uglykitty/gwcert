#ifndef CSRGENEDIALOG_H
#define CSRGENEDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QTextEdit>
#include <QPushButton>

class SubjectWidget;
class PkiStore;

/**
 * @brief Dialog for generating a Certificate Signing Request.
 */
class CSRGeneDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CSRGeneDialog(PkiStore *store = nullptr, QWidget *parent = nullptr);

    QString csrPath() const { return m_generatedCSRPath; }
    QString keyPath() const { return m_generatedKeyPath; }

private slots:
    void onBrowseCSR();
    void onBrowseKey();
    void onGenerate();

private:
    SubjectWidget *m_subject;
    QLineEdit     *m_csrPathEdit;
    QLineEdit     *m_keyPathEdit;
    QComboBox     *m_keyTypeCombo;
    QComboBox     *m_keyParamCombo;
    QTextEdit     *m_sanEdit;
    QCheckBox     *m_encryptKeyCb;
    QLineEdit     *m_passphraseEdit;
    QLineEdit     *m_passphraseConfirmEdit;

    PkiStore *m_store;
    QString m_generatedCSRPath;
    QString m_generatedKeyPath;
};

#endif // CSRGENEDIALOG_H
