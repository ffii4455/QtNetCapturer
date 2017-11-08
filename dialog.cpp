#include "dialog.h"
#include "ui_dialog.h"
#include <QMessageBox>

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Window);
    cp = new Capturer;
    connect(cp, SIGNAL(readyRead(QString)), this, SLOT(updatePacketInf(QString)));
    connect(cp, SIGNAL(log(QString)), this, SLOT(updatePacketInf(QString)));
    ui->deviceList->addItems(cp->getDevicesList());
    ui->version->setText("Build: " + QString(__TIMESTAMP__));
}

Dialog::~Dialog()
{
    delete ui;
    delete cp;
}

void Dialog::updatePacketInf(QString str)
{
    ui->data->append(str);
}

void Dialog::on_open_clicked()
{
    cp->openDevice(ui->deviceList->currentIndex());
}

void Dialog::on_about_clicked()
{
    QMessageBox::information(this, "信息", "Author: Lee\n"
                                         "Email: limeng89@foxmail.com");
}

void Dialog::on_arp_clicked()
{
    cp->sendArpReq(ui->deviceList->currentIndex(), "10.90.98.55");
}

void Dialog::on_clear_clicked()
{
    ui->data->clear();
}
