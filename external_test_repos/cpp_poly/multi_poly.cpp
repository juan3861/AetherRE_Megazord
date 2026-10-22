#include "multi_poly.h"

class IReader {
public:
    virtual ~IReader() {}
    virtual int read_channel() = 0;
};

class IWriter {
public:
    virtual ~IWriter() {}
    virtual void write_channel(int val) = 0;
};

class DualDevice : public IReader, public IWriter {
private:
    int channel_data;

public:
    DualDevice(int val = 100) : channel_data(val) {}
    virtual ~DualDevice() {}

    virtual int read_channel() override {
        return channel_data;
    }

    virtual void write_channel(int val) override {
        channel_data = val;
    }
};

extern "C" {

MULTI_API HDEVICE create_dual_device(int initial_val) {
    return static_cast<HDEVICE>(new DualDevice(initial_val));
}

MULTI_API int read_from_device(HREADER reader) {
    if (!reader) {
        return -1;
    }
    IReader* r = static_cast<IReader*>(reader);
    return r->read_channel();
}

MULTI_API void write_to_device(HWRITER writer, int val) {
    if (writer) {
        IWriter* w = static_cast<IWriter*>(writer);
        w->write_channel(val);
    }
}

MULTI_API void destroy_dual_device(HDEVICE device) {
    if (device) {
        DualDevice* d = static_cast<DualDevice*>(device);
        delete d;
    }
}

}
