#ifndef _MY_BLUETOOTH_SERIAL_H_
#define _MY_BLUETOOTH_SERIAL_H_

#include "sdkconfig.h"

#if defined(CONFIG_BT_ENABLED) && defined(CONFIG_BLUEDROID_ENABLED)

#include "Arduino.h"
#include "Stream.h"
#include <esp_spp_api.h>
#include <functional>

typedef std::function<void(const uint8_t *buffer, size_t size)> myBluetoothSerialDataCb;

class myBluetoothSerial : public Stream
{
public:
    myBluetoothSerial(void);
    ~myBluetoothSerial(void);

    bool begin(String localName = String(), bool isMaster = false);
    int available(void);
    int peek(void);
    bool hasClient(void);
    int read(void);
    size_t write(uint8_t c);
    size_t write(const uint8_t *buffer, size_t size);
    void flush();
    void end(void);
    void onData(myBluetoothSerialDataCb cb);
    esp_err_t register_callback(esp_spp_cb_t *callback);

    void enableSSP();
    bool setPin(const char *pin);
    bool connect(String remoteName);
    bool connect(uint8_t remoteAddress[]);
    bool connect();
    bool connected(int timeout = 0);
    bool isReady(bool checkMaster = false, int timeout = 0);
    bool disconnect();
    bool unpairDevice(uint8_t remoteAddress[]);

private:
    String local_name;
};

#endif

#endif
