#include <QApplication>
#include <QStyle>
#include <QScreen>
#include <QTranslator>
#include <QSettings>
#include <QDir>
#include <QDebug>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("GWCert");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("GWCert");

    // Load translator based on saved language setting
    QTranslator translator;
    QSettings settings;
    QString lang = settings.value("app/language", "en").toString();
    qDebug() << "[i18n] language setting:" << lang;
    if (lang != "en") {
        QString baseName = "gwcert_" + lang;
        // Search paths: FHS share dir, next to executable, working directory
        QStringList searchDirs = {
            QCoreApplication::applicationDirPath() + "/../share/gwcert/translations",
            QCoreApplication::applicationDirPath() + "/translations",
            QDir::currentPath() + "/translations",
        };
        bool loaded = false;
        for (const QString &dir : searchDirs) {
            qDebug() << "[i18n] trying" << dir + "/" + baseName + ".qm";
            if (translator.load(baseName, dir)) {
                app.installTranslator(&translator);
                qDebug() << "[i18n] translator loaded from" << dir;
                loaded = true;
                break;
            }
        }
        if (!loaded)
            qDebug() << "[i18n] WARNING: failed to load translation for" << lang;
    }

    MainWindow w;
    w.setWindowTitle(QObject::tr("GWCert - Certificate Manager v1.0.0"));
    w.resize(1000, 700);

    // Center on screen
    w.setGeometry(
        QStyle::alignedRect(
            Qt::LeftToRight,
            Qt::AlignCenter,
            w.size(),
            QGuiApplication::primaryScreen()->availableGeometry()
        )
    );

    w.show();
    return app.exec();
}
