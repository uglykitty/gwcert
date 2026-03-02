#ifndef CAGENEDIALOG_H
#define CAGENEDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QPushButton>

class SubjectWidget;
class PkiStore;

/**
 * @brief Dialog for generating a self-signed CA root certificate.
 */
class CAGeneDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CAGeneDialog(PkiStore *store = nullptr, QWidget *parent = nullptr);

    QString certPath() const { return m_generatedCertPath; }
    QString keyPath()  const { return m_generatedKeyPath; }

private slots:
    void onBrowseCert();
    void onBrowseKey();
    void onGenerate();

private:
    SubjectWidget *m_subject;
    QLineEdit     *m_certPathEdit;
    QLineEdit     *m_keyPathEdit;
    QComboBox     *m_keyTypeCombo;
    QComboBox     *m_keyParamCombo;
    QSpinBox      *m_daysSpin;
    QCheckBox     *m_encryptKeyCb;
    QLineEdit     *m_passphraseEdit;
    QLineEdit     *m_passphraseConfirmEdit;

    PkiStore *m_store;
    QString m_generatedCertPath;
    QString m_generatedKeyPath;
};

#endif // CAGENEDIALOG_H
