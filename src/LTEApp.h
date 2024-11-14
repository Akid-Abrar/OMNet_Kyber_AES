#ifndef LTEAPP_H
#define LTEAPP_H

#include <omnetpp.h>
#include <inet/applications/base/ApplicationBase.h>
#include <inet/transportlayer/contract/udp/UdpSocket.h>
#include <inet/networklayer/common/L3Address.h>

using namespace omnetpp;
using namespace inet;

class LTEApp : public ApplicationBase, public UdpSocket::ICallback
{
  protected:
    // Member variables
    UdpSocket socket;
    cMessage *selfMsg = nullptr;

    L3Address destAddr; // Destination address
    int localPort = -1; // Local port number
    int destPort = -1;  // Destination port number

    // Cryptographic keys
    uint8_t *publicKey = nullptr;
    uint8_t *secretKey = nullptr;
    uint8_t *sharedSecret = nullptr;

    // ApplicationBase methods
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;
    virtual void handleMessage(cMessage *msg) override;

    // Lifecycle methods
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    // UdpSocket::ICallback methods
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override {}
    virtual void socketClosed(UdpSocket *socket) override {}

    // Application logic methods
    void processStart();
    void sendPublicKey();
    void sendEncryptedData();
    std::string formatHex(const uint8_t *data, size_t length);

  public:
    LTEApp();
    virtual ~LTEApp();
};

#endif // LTEAPP_H
