#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include "capturer.h"

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

private:
    Ui::Dialog *ui;
    Capturer *cp;
private slots:
    void updatePacketInf(QString str);
    void on_open_clicked();
    void on_about_clicked();
    void on_arp_clicked();
};

#endif // DIALOG_H
