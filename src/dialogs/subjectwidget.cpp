#include "subjectwidget.h"
#include <QFormLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QFile>

SubjectWidget::SubjectWidget(const QString &title, QWidget *parent)
    : QGroupBox(title, parent)
{
    auto *form = new QFormLayout(this);
    form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

    m_cn       = new QLineEdit(this);
    m_org      = new QLineEdit(this);
    m_ou       = new QLineEdit(this);
    m_country  = new QLineEdit(this);
    m_state    = new QLineEdit(this);
    m_locality = new QLineEdit(this);
    m_email    = new QLineEdit(this);

    m_cn->setPlaceholderText(tr("e.g. example.com / My Root CA"));
    m_org->setPlaceholderText(tr("e.g. My Company Ltd"));
    m_ou->setPlaceholderText(tr("e.g. IT Department"));
    m_country->setPlaceholderText(tr("Two-letter country code, e.g. CN"));
    m_country->setMaxLength(2);
    m_state->setPlaceholderText(tr("e.g. Beijing"));
    m_locality->setPlaceholderText(tr("e.g. Haidian"));
    m_email->setPlaceholderText(tr("Optional"));

    form->addRow(tr("Common Name (CN)*:"), m_cn);
    form->addRow(tr("Organization (O):"),       m_org);
    form->addRow(tr("Org Unit (OU):"),      m_ou);
    form->addRow(tr("Country (C):"),       m_country);
    form->addRow(tr("State (ST):"),      m_state);
    form->addRow(tr("Locality (L):"),       m_locality);
    form->addRow(tr("Email:"),          m_email);

    // Import / Export buttons
    auto *btnLayout = new QHBoxLayout;
    m_importBtn = new QPushButton(tr("Import..."), this);
    m_exportBtn = new QPushButton(tr("Export..."), this);
    m_importBtn->setToolTip(tr("Load subject info from a JSON file"));
    m_exportBtn->setToolTip(tr("Save current subject info to a JSON file"));
    btnLayout->addStretch();
    btnLayout->addWidget(m_importBtn);
    btnLayout->addWidget(m_exportBtn);
    form->addRow(btnLayout);

    connect(m_importBtn, &QPushButton::clicked, this, &SubjectWidget::onImport);
    connect(m_exportBtn, &QPushButton::clicked, this, &SubjectWidget::onExport);
}

SubjectInfo SubjectWidget::subjectInfo() const
{
    SubjectInfo info;
    info.commonName       = m_cn->text().trimmed();
    info.organization     = m_org->text().trimmed();
    info.organizationUnit = m_ou->text().trimmed();
    info.country          = m_country->text().trimmed().toUpper();
    info.state            = m_state->text().trimmed();
    info.locality         = m_locality->text().trimmed();
    info.email            = m_email->text().trimmed();
    return info;
}

void SubjectWidget::setSubjectInfo(const SubjectInfo &info)
{
    m_cn->setText(info.commonName);
    m_org->setText(info.organization);
    m_ou->setText(info.organizationUnit);
    m_country->setText(info.country);
    m_state->setText(info.state);
    m_locality->setText(info.locality);
    m_email->setText(info.email);
}

// ── Import / Export ─────────────────────────────────────────────────

void SubjectWidget::onImport()
{
    QString path = QFileDialog::getOpenFileName(
        this, tr("Import Subject Info"), QString(),
        tr("JSON Files (*.json);;All Files (*)"));
    if (path.isEmpty())
        return;

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Import Failed"),
                             tr("Cannot open file: %1").arg(file.errorString()));
        return;
    }

    QJsonParseError parseErr;
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseErr);
    file.close();

    if (doc.isNull()) {
        QMessageBox::warning(this, tr("Import Failed"),
                             tr("Invalid JSON: %1").arg(parseErr.errorString()));
        return;
    }

    QJsonObject obj = doc.object();
    SubjectInfo info;
    info.commonName       = obj.value(QStringLiteral("CN")).toString();
    info.organization     = obj.value(QStringLiteral("O")).toString();
    info.organizationUnit = obj.value(QStringLiteral("OU")).toString();
    info.country          = obj.value(QStringLiteral("C")).toString();
    info.state            = obj.value(QStringLiteral("ST")).toString();
    info.locality         = obj.value(QStringLiteral("L")).toString();
    info.email            = obj.value(QStringLiteral("Email")).toString();
    setSubjectInfo(info);
}

void SubjectWidget::onExport()
{
    QString path = QFileDialog::getSaveFileName(
        this, tr("Export Subject Info"), QStringLiteral("subject.json"),
        tr("JSON Files (*.json);;All Files (*)"));
    if (path.isEmpty())
        return;

    SubjectInfo info = subjectInfo();
    QJsonObject obj;
    obj[QStringLiteral("CN")]    = info.commonName;
    obj[QStringLiteral("O")]     = info.organization;
    obj[QStringLiteral("OU")]    = info.organizationUnit;
    obj[QStringLiteral("C")]     = info.country;
    obj[QStringLiteral("ST")]    = info.state;
    obj[QStringLiteral("L")]     = info.locality;
    obj[QStringLiteral("Email")] = info.email;

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Export Failed"),
                             tr("Cannot write file: %1").arg(file.errorString()));
        return;
    }
    file.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
    file.close();
}

bool SubjectWidget::validate(QString *errorMsg) const
{
    if (m_cn->text().trimmed().isEmpty()) {
        if (errorMsg) *errorMsg = tr("Common Name (CN) cannot be empty");
        m_cn->setFocus();
        return false;
    }
    QString c = m_country->text().trimmed();
    if (!c.isEmpty() && c.length() != 2) {
        if (errorMsg) *errorMsg = tr("Country code must be exactly two letters (e.g. CN, US)");
        m_country->setFocus();
        return false;
    }
    return true;
}
