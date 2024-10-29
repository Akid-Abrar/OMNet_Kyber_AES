#ifndef __KYBERAESPROJECT_NODE_H_
#define __KYBERAESPROJECT_NODE_H_

#include <omnetpp.h>
#include <oqs/oqs.h>
#include <openssl/aes.h>
#include "messages_m.h"


using namespace omnetpp;

class Node : public cSimpleModule
{
  private:
    uint8_t *publicKey = nullptr;
    uint8_t *secretKey = nullptr;
    uint8_t *sharedSecret = nullptr;
    std::string formatHex(const uint8_t *data, size_t length);

  protected:
    virtual void initialize() override;
    virtual void sendPublickKey();
    virtual void sendEncryptedData();
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
};

#endif
