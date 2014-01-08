#include "widget.h"
#include "ui_widget.h"
#include <QFile>
#include <windows.h>
#include <QMessageBox>
#include <QFileDialog>
#include <QPainter>

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    plot = new QLabel("График", 0, Qt::WindowCloseButtonHint);
    plot->setWindowModality(Qt::WindowModal);
}

Widget::~Widget()
{
    delete plot;
    delete ui;
}

QString GetErrorString(DWORD mID)
{
    wchar_t buf[2048];
    QString explonation;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, mID, 0x400, &buf[0], sizeof(buf), NULL);
    explonation = QString::fromWCharArray(&buf[0]);
    return explonation;
}

HCRYPTKEY GenKey(HCRYPTPROV hCrProv, QString keyText, QByteArray* key, DWORD& keyBlobLen, bool flag)
{
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    if (flag)
    {
        CryptGenKey(hCrProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey);
    }
    else
    {
        CryptCreateHash(hCrProv, CALG_MD5, 0, 0, &hHash);
        CryptHashData(hHash, (BYTE *)keyText.toUtf8().constData(), keyText.length(), 0);
        CryptDeriveKey(hCrProv, CALG_AES_256, hHash, 0, &hKey);
    }
    CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keyBlobLen);
    key->resize(keyBlobLen);
    CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, (BYTE*)key->data(), &keyBlobLen);
    return hKey;
}

QString getFType(QString& fName)
{
    QString fType = "";
    int i = fName.length() - 1;
    while (i >= 0 && fName[i] != '.')
    {
        fType.push_front(fName[i]);
        i--;
    }
    return fType;
}

void EncodingFile(QString fName, HCRYPTKEY hKey)
{
    QFile myFile(fName);
    QFile eFile(QString(getFType(fName) + "eFile.dat"));
    DWORD blockLen = 0, fDataSize;
    BYTE* fData;

    if (eFile.exists())
        eFile.remove();
    if (!myFile.exists())
    {
        QMessageBox::critical(0, "Ошибка", "Файл не выбран", QMessageBox::Ok);
        return;
    }
    myFile.open(QIODevice::ReadOnly);
    eFile.open(QIODevice::WriteOnly);
    CryptEncrypt(hKey, 0, true, 0, NULL, &blockLen, myFile.size());
    fData = new BYTE[blockLen];
    memset(fData, 0, blockLen);
    while ((fDataSize = myFile.read((char*)fData, blockLen)))
    {
        if (!CryptEncrypt(hKey, 0, fDataSize < blockLen, 0, fData, &fDataSize, blockLen))
        {
            QMessageBox::critical(0, "Ошибка", "Шифрование данных. " + GetErrorString(GetLastError()),
                                  QMessageBox::Ok);
            return;
        }
        eFile.write((char*)fData, fDataSize);
        memset(fData, 0, blockLen);
    }
    memset(fData, 0, blockLen);
    myFile.close();
    eFile.close();
}

void DecodingFile(QString fPath, HCRYPTKEY hKey)
{
    QFile myFile(fPath);
    QString fName = myFile.fileName();

    QRegExp rx("[^eFile.dat]");
    int typeLen = 0;
    rx.indexIn(fName, typeLen);

    QFile srcFile("1" + fName.mid(0, typeLen));
    DWORD blockLen = 0, fDataSize;
    BYTE* fData;

    myFile.open(QIODevice::ReadOnly);
    if (!myFile.exists())
    {
        QMessageBox::critical(0, "Ошибка", "Файл не выбран", QMessageBox::Ok);
        return;
    }
    srcFile.open(QIODevice::WriteOnly);
    CryptDecrypt(hKey, 0, true, 0, NULL, &blockLen);
    fData = new BYTE[blockLen];
    memset(fData, 0, blockLen);
    while ((fDataSize = myFile.read((char*) fData, blockLen)))
    {
        if (!CryptDecrypt(hKey, 0, fDataSize < blockLen, 0, fData, &fDataSize))
        {
            QMessageBox::critical(0, "Ошибка", "Шифрование данных. " + GetErrorString(GetLastError()),
                                  QMessageBox::Ok);
            return;
        }
        srcFile.write((char*)fData, fDataSize);
        memset(fData, 0, blockLen);
    }
    delete[] fData;
    myFile.close();
    srcFile.close();
}

QString fName;

void Widget::on_encryptFile_clicked()
{
    HCRYPTPROV cryptProv;
    HCRYPTKEY hKey;
    QByteArray key;
    QFile keyV("key.dat");
    DWORD keyBlobLen = 0;
    QDataStream writeToFileFrom(&keyV);
    if (keyV.exists())
        keyV.remove();
    keyV.open(QIODevice::WriteOnly);

    if (!CryptAcquireContext(&cryptProv, NULL, MS_DEF_RSA_SCHANNEL_PROV, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT))
    {
        QMessageBox::critical(0, "Ошибка", "Получение контекста криптопровайдера. " + GetErrorString(GetLastError()), QMessageBox::Ok);
        return;
    }
    hKey = GenKey(cryptProv, ui->keyVal->text(), &key, keyBlobLen, ui->randKeyVal->isChecked());
    writeToFileFrom << (quint32)keyBlobLen;
    keyV.write(key);
    keyV.close();
    key.clear();
    EncodingFile(fName, hKey);
    QMessageBox::information(0, "Процесс завершён", "Файл успешно зашифрован", QMessageBox::Ok);
}

void Widget::on_browseFile_clicked()
{
    fName = QFileDialog::getOpenFileName(this, tr("File browse"), QDir::currentPath(), tr("Files(*.*)"));
}

void Widget::on_randKeyVal_stateChanged(int arg1)
{
    (arg1) ? ui->keyVal->setEnabled(false) : ui->keyVal->setEnabled(true);
}

int trueBitsCount(uint value)
{
    int k = 0;
    while (value)
    {
        if (value & 1)
            k++;
        value >>= 1;
    }
    return k;
}

void Widget::on_decryptFile_clicked()
{
    HCRYPTPROV cryptProv;
    HCRYPTKEY hKey;
    BYTE* key;
    QFile keyV("key.dat");
    DWORD keyBlobLen = 0;
    if (!keyV.exists())
    {
        QMessageBox::critical(0, "Ошибка", "Отсутствует ключ", QMessageBox::Ok);
        return;
    }
    keyV.open(QIODevice::ReadOnly);

    if (!CryptAcquireContext(&cryptProv, NULL, MS_DEF_RSA_SCHANNEL_PROV, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT))
    {
        QMessageBox::critical(0, "Ошибка", "Получение контекста криптопровайдера. " + GetErrorString(GetLastError()), QMessageBox::Ok);
        return;
    }
    keyV.read((char *)&keyBlobLen, sizeof(keyBlobLen));
    key = new BYTE[keyBlobLen];
    memset(key, 0, keyBlobLen);
    keyV.read((char *)key, keyBlobLen);
    keyV.close();
    CryptImportKey(cryptProv, key, keyBlobLen, 0, 0, &hKey);
    delete[] key;
    DecodingFile(fName, hKey);
    QMessageBox::information(0, "Процесс завершён", "Файл успешно расшифрован", QMessageBox::Ok);
}

void DrawScale(QPainter& Painter, const QPoint& Center, const int height, const int width)
{
    int startY = Center.y();
    int startX = Center.x() + 100;
    int yStep = 60;
    int xStep = 100;
    Painter.drawLine(Center, QPoint(width, Center.y())); // Рисуем ось абцисс
    Painter.drawLine(Center, QPoint(Center.x(), -height)); // Рисуем ось ординат

    for(int i = startY - yStep; i > 0; i -= yStep)
    {
        Painter.drawLine(Center.x() - 5, i, Center.x() + 5, i);
        Painter.drawText(Center.x() + 11, i + 4, QString::number((startY - i) / yStep * 16));
    }
    for(int i = startX; i < width; i += xStep)
    {
        Painter.drawLine(i, Center.y() - 5, i, Center.y() + 5);
        Painter.drawText(i - 7, Center.y() + 15, QString::number(i / xStep));
    }
}

void DrawFigure(QPainter& Painter, const QPoint center, QVector<int> values)
{
    int k = 80;
    for (int i = 0; i < values.size(); i++)
    {
        Painter.drawRect(k + center.x(), center.y(), 40, -values.at(i) * (60 / 16));
        Painter.drawText(k + center.x() + 20, -values.at(i) * (60 / 16) - 5 - center.y() + 510,
                         QString::number(values.at(i)));
        k += 100;
    }
}

void DrawPlot(QLabel* plot, QVector<int> values)
{
    QPixmap pm(350, 510);
    QPoint Center(10, pm.height() - 20);
    QPainter painter(&pm);

    pm.fill(Qt::white);
    DrawScale(painter, Center, pm.height() - 20, pm.width() - 20);
    DrawFigure(painter, Center, values);
    painter.end();
    plot->setGeometry(200, 40, pm.width(), pm.height());
    plot->setPixmap(pm);
    plot->show();
}

void Widget::on_srcTextErr_clicked()
{
    DWORD blockLen = 32; // Хотя должно быть 16ж
    DWORD dataSize;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    uchar srcData[blockLen];
    uchar newData[blockLen];
    QVector<int> values;
    QFile myFile(fName);

    plot->clear();
    if (myFile.exists())
        myFile.open(QIODevice::ReadOnly);
    else
    {
        QMessageBox::critical(0, "Ошибка", "Файл не выбран", QMessageBox::Ok);
        return;
    }
    CryptAcquireContext(&hCryptProv, NULL, MS_DEF_RSA_SCHANNEL_PROV, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT);
    CryptGenKey(hCryptProv, CALG_AES_256, 0, &hKey);
    //CryptEncrypt(hKey, 0, true, 0, NULL, &blockLen, myFile.size());
    //srcData = new uchar[blockLen];
    //newData = new uchar[blockLen];
    dataSize = myFile.read((char *)(&srcData[0]), blockLen);
    memcpy(&newData[0], &srcData[0], blockLen);
    newData[0] = -newData[0];
    for (uint i = 0; i < block; i++)
    {
        int k = 0;
        CryptEncrypt(hKey, 0, i < 2, 0, &srcData[0], &dataSize, block*blockLen);
        CryptEncrypt(hKey, 0, i < 2, 0, &newData[0], &dataSize, block*blockLen);
        for (uint j = 0; j < blockLen; j++)
            k += trueBitsCount((uint)(srcData[j] ^ newData[j]));
        values.push_back(k);
        memset(&srcData[0], 0, blockLen);
        dataSize = myFile.read((char *)(&srcData[0]), blockLen);
        memcpy(&newData[0], &srcData[0], blockLen);
    }
    myFile.close();
    CryptReleaseContext(hCryptProv, 0);
    CryptDestroyKey(hKey);
    //delete[] srcData;
    //srcData = 0;
    //delete[] newData;
    //newData = 0;
    DrawPlot(plot, values);
    plot->show();
}

void Widget::on_cipherTextErr_clicked()
{
    DWORD blockLen = 0;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    BYTE *srcData, *newData, *blockData1, *blockData2;
    QVector<int> values;
    QFile myFile(fName);

    plot->clear();
    if (myFile.exists())
        myFile.open(QIODevice::ReadOnly);
    else
    {
        QMessageBox::critical(0, "Ошибка", "Файл не выбран", QMessageBox::Ok);
        return;
    }
    CryptAcquireContext(&hCryptProv, NULL, MS_DEF_RSA_SCHANNEL_PROV, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT);
    CryptGenKey(hCryptProv, CALG_AES_256, 0, &hKey);
    CryptDecrypt(hKey, 0, true, 0, NULL, &blockLen);
    srcData = new BYTE[block * blockLen];
    newData = new BYTE[block * blockLen];
    blockData1  = new BYTE[blockLen];
    blockData2  = new BYTE[blockLen];
    myFile.read((char*)srcData, block * blockLen);
    myFile.close();
    memcpy((char*)newData, (char*)srcData, block * blockLen);
    newData[0] = -newData[0];
    for (uint i = 0; i < (block * blockLen); i++)
    {
        CryptDecrypt(hKey, 0, i < 2, 0, srcData + i, &blockLen);
        CryptDecrypt(hKey, 0, i < 2, 0, newData + i, &blockLen);
    }
    for(uint i = 0; i < (block * blockLen); i += blockLen)
    {
        int k = 0;
        memcpy(blockData1, srcData + i, blockLen);
        memcpy(blockData2, newData + i, blockLen);
        for (uint j = i; j < (i + blockLen); j++)
            k += trueBitsCount(srcData[j] ^ newData[j]);
        values.push_back(k);
    }
    delete[] newData;
    delete[] srcData;
    delete[] blockData1;
    delete[] blockData2;
    CryptReleaseContext(hCryptProv, 0);
    CryptDestroyKey(hKey);
    DrawPlot(plot, values);
    plot->show();
}

void Widget::on_IVErr_clicked()
{
    BYTE *iv, *srcData, *newData, *blockData1, *blockData2;
    DWORD ivLen, blockLen = 0;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey, newHKey;
    QVector<int> values;
    QFile myFile(fName);

    plot->clear();
    if (myFile.exists())
        myFile.open(QIODevice::ReadOnly);
    else
    {
        QMessageBox::critical(0, "Ошибка", "Файл не выбран", QMessageBox::Ok);
        return;
    }
    CryptAcquireContext(&hCryptProv, NULL, MS_DEF_RSA_SCHANNEL_PROV, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT);
    CryptGenKey(hCryptProv, CALG_AES_256, 0, &hKey);
    CryptEncrypt(hKey, 0, true, 0, NULL, &blockLen, myFile.size());
    srcData = new BYTE[block * blockLen];
    newData = new BYTE[block * blockLen];
    blockData1  = new BYTE[blockLen];
    blockData2  = new BYTE[blockLen];
    myFile.read((char*)srcData, block * blockLen);
    myFile.close();
    memcpy((char*)newData, (char*)srcData, block * blockLen);
    newData[0] = -newData[0];
    CryptDuplicateKey(hKey, NULL, 0, &newHKey);
    CryptGetKeyParam(newHKey, KP_IV, NULL, &ivLen, 0);
    iv = new BYTE[ivLen];
    CryptGetKeyParam(newHKey, KP_IV, iv, &ivLen, 0);
    iv[0] = -iv[0];
    CryptSetKeyParam(newHKey, KP_IV, iv, 0);
    for (uint i = 0; i < (block * blockLen); i++)
    {
        CryptEncrypt(hKey, 0, i < 2, 0, srcData + i, &blockLen, block * blockLen);
        CryptEncrypt(newHKey, 0, i < 2, 0, newData + i, &blockLen, block * blockLen);
    }
    for(uint i = 0; i < (block * blockLen); i += blockLen)
    {
        int k = 0;
        memcpy(blockData1, srcData + i, blockLen);
        memcpy(blockData2, newData + i, blockLen);
        for (uint j = i; j < (i + blockLen); j++)
            k += trueBitsCount(srcData[j] ^ newData[j]);
        values.push_back(k);
    }
    delete[] newData;
    delete[] srcData;
    delete[] blockData1;
    delete[] blockData2;
    delete[] iv;
    CryptReleaseContext(hCryptProv, 0);
    CryptDestroyKey(hKey);
    CryptDestroyKey(newHKey);
    DrawPlot(plot, values);
    plot->show();
}

void Widget::on_keyErr_clicked()
{
    DWORD keyBlobLen, blockLen = 0;
    BYTE *keyBlob, *srcData, *newData, *blockData1, *blockData2;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey, dhKey;
    QVector<int> values;
    QFile myFile(fName);

    plot->clear();
    if (myFile.exists())
        myFile.open(QIODevice::ReadOnly);
    else
    {
        QMessageBox::critical(0, "Ошибка", "Файл не выбран", QMessageBox::Ok);
        return;
    }
    CryptAcquireContext(&hCryptProv, NULL, MS_DEF_RSA_SCHANNEL_PROV, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT);
    CryptGenKey(hCryptProv, CALG_AES_256, 0, &hKey);
    CryptEncrypt(hKey, 0, true, 0, NULL, &blockLen, myFile.size());
    srcData = new BYTE[block * blockLen];
    newData = new BYTE[block * blockLen];
    blockData1  = new BYTE[blockLen];
    blockData2  = new BYTE[blockLen];
    myFile.read((char*)srcData, block * blockLen);
    myFile.close();
    memcpy((char*)newData, (char*)srcData, block * blockLen);
    newData[0] = -newData[0];
    CryptDuplicateKey(hKey, NULL, 0, &dhKey);
    CryptExportKey(dhKey, 0, SIMPLEBLOB, 0, NULL, &keyBlobLen);
    keyBlob = new BYTE[keyBlobLen];
    CryptExportKey(dhKey, 0, SIMPLEBLOB, 0, keyBlob, &keyBlobLen);
    keyBlob[0] = -keyBlob[0];
    CryptImportKey(hCryptProv, keyBlob, keyBlobLen, 0, 0, &dhKey);
    for (uint i = 0; i < (block * blockLen); i++)
    {
        CryptEncrypt(hKey, 0, i < 2, 0, srcData + i, &blockLen, block * blockLen);
        CryptEncrypt(dhKey, 0, i < 2, 0, newData + i, &blockLen, block * blockLen);
    }
    for(uint i = 0; i < (block * blockLen); i += blockLen)
    {
        int k = 0;
        memcpy(blockData1, srcData + i, blockLen);
        memcpy(blockData2, newData + i, blockLen);
        for (uint j = i; j < (i + blockLen); j++)
            k += trueBitsCount(srcData[j] ^ newData[j]);
        values.push_back(k);
    }
    delete[] newData;
    delete[] srcData;
    delete[] blockData1;
    delete[] blockData2;
    delete[] keyBlob;
    CryptReleaseContext(hCryptProv, 0);
    CryptDestroyKey(hKey);
    CryptDestroyKey(dhKey);
    DrawPlot(plot, values);
    plot->show();
}
