#ifndef SUBJECTWIDGET_H
#define SUBJECTWIDGET_H

#include <QGroupBox>
#include <QLineEdit>
#include <QPushButton>
#include "certmanager.h"

/**
 * @brief Reusable widget for entering certificate subject (DN) fields.
 *
 * Supports importing / exporting subject info as JSON for reuse.
 */
class SubjectWidget : public QGroupBox
{
    Q_OBJECT
public:
    explicit SubjectWidget(const QString &title = "Subject Information", QWidget *parent = nullptr);

    SubjectInfo subjectInfo() const;
    void setSubjectInfo(const SubjectInfo &info);
    bool validate(QString *errorMsg = nullptr) const;

private slots:
    void onImport();
    void onExport();

private:
    QLineEdit *m_cn;
    QLineEdit *m_org;
    QLineEdit *m_ou;
    QLineEdit *m_country;
    QLineEdit *m_state;
    QLineEdit *m_locality;
    QLineEdit *m_email;

    QPushButton *m_importBtn;
    QPushButton *m_exportBtn;
};

#endif // SUBJECTWIDGET_H
