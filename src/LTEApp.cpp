#include "LTEApp.h"

// Include necessary headers
#include <inet/common/INETDefs.h>
#include <inet/common/packet/Packet.h>
#include <inet/networklayer/common/L3Address.h>
#include <inet/applications/common/SocketTag_m.h>
#include <inet/transportlayer/contract/udp/UdpControlInfo_m.h>
#include <oqs/oqs.h>
#include <openssl/aes.h>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <iostream>
#include <x86intrin.h>

using namespace omnetpp;
using namespace inet;

Define_Module(LTEApp);
const char* kyberVariantLTE = "Kyber1024";

LTEApp::LTEApp()
{
    selfMsg = nullptr;
    publicKey = nullptr;
    secretKey = nullptr;
    sharedSecret = nullptr;
}

LTEApp::~LTEApp()
{
    cancelAndDelete(selfMsg);
    delete[] publicKey;
    delete[] secretKey;
    delete[] sharedSecret;
}

void LTEApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // Initialize member variables
        selfMsg = new cMessage("start");
        localPort = par("localPort");
        destPort = par("destPort");
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        // Schedule the start of the application after all initialization stages
        //scheduleAt(simTime() + par("startTime").doubleValue(), selfMsg);
    }
}
void LTEApp::handleStartOperation(LifecycleOperation *operation)
{
    EV_INFO << getFullPath() << "KyberAESLTE LTEApp::handleStartOperation() called" << endl;
    scheduleAt(simTime() + par("startTime").doubleValue(), selfMsg);
}

void LTEApp::handleMessage(cMessage *msg)
{
    EV_INFO << getFullPath() << "KyberAESLTE LTEApp::handleMessage() called with message: " << msg->getName() << endl;
    ApplicationBase::handleMessage(msg);
}

void LTEApp::handleMessageWhenUp(cMessage *msg)
{
    EV_INFO << getFullPath() << "KyberAESLTE LTEApp::handleMessageWhenUp() called with message: " << msg->getName() << endl;
    if (msg->isSelfMessage()) {
        processStart();
        delete msg; // Delete the self-message
    } else {
        socket.processMessage(msg);
    }
}

void LTEApp::processStart()
{
    // Retrieve and print destAddr parameter
    const char* destAddrStr = par("destAddr").stringValue();
    EV_INFO << "KyberAESLTE processStart() called in " << getParentModule()->getFullName() << ". destAddr: " << destAddrStr << endl;

    // Convert the destAddr string to L3Address
    destAddr = L3Address(destAddrStr);

    if (destAddr.isUnspecified()) {
        EV_ERROR << "Failed to parse destAddr: " << destAddrStr << endl;
        throw cRuntimeError("Failed to parse destAddr: %s", destAddrStr);
    }

    // Initialize the socket
    socket.setCallback(this);
    socket.setOutputGate(gate("socketOut"));
    socket.bind(localPort);

    // Get the full name of the node
    std::string nodeName = getParentModule()->getFullName();

    // If this is ueA, send the public key
    if (nodeName == "ueA") {
        sendPublicKey();
    }
}

void LTEApp::sendPublicKey()
{
    // Initialize Kyber KEM
    OQS_KEM *kem = OQS_KEM_new(kyberVariantLTE);
    if (!kem)
        throw cRuntimeError("Failed to initialize Kyber KEM");

    // Allocate memory for keys
    publicKey = new uint8_t[kem->length_public_key];
    secretKey = new uint8_t[kem->length_secret_key];

    // Generate key pair
    if (OQS_KEM_keypair(kem, publicKey, secretKey) != OQS_SUCCESS)
        throw cRuntimeError("Failed to generate Kyber key pair");

    // Log key generation
    EV_INFO << "KyberAESLTE Generated Kyber key pair.\n";
    bubble("Key Generated");

    // Create a packet with the public key
    Packet *packet = new Packet("PublicKey");
    auto payload = makeShared<BytesChunk>(publicKey, kem->length_public_key);
    packet->insertAtBack(payload);
    packet->setTimestamp(simTime());
    // Send the packet
    EV_INFO << destAddr<<endl;
    EV_INFO << destPort<<endl;
    socket.sendTo(packet, destAddr, destPort);

    // Free KEM resources
    OQS_KEM_free(kem);
}

void LTEApp::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    std::string nodeName = getParentModule()->getFullName();
    EV_INFO<< "KyberAESLTE: " << nodeName << " received a packet: " << packet->getName() << endl;

    const auto& payload = packet->peekData<BytesChunk>();
    size_t payloadSize = payload->getChunkLength().get();

    simtime_t delay = simTime() - packet->getTimestamp();
    double delay_ms = delay.dbl() * 1e6; // Convert seconds to milliseconds

    std::ostringstream oss_ms;
    oss_ms << std::fixed << std::setprecision(9);
    oss_ms << "KyberAESLTE: Communication delay: " << delay_ms << " microseconds.\n";
    EV << oss_ms.str();

    if (nodeName == "ueB" && strcmp(packet->getName(), "PublicKey") == 0) {
        // Node B processes public key
        uint8_t *receivedPublicKey = new uint8_t[payloadSize];
        memcpy(receivedPublicKey, payload->getBytes().data(), payloadSize);

        // Initialize Kyber KEM
        OQS_KEM *kem = OQS_KEM_new(kyberVariantLTE);
        if (!kem)
            throw cRuntimeError("Failed to initialize Kyber KEM");

        uint8_t *ciphertext = new uint8_t[kem->length_ciphertext];
        sharedSecret = new uint8_t[kem->length_shared_secret];

        // Encapsulate shared secret
        if (OQS_KEM_encaps(kem, ciphertext, sharedSecret, receivedPublicKey) != OQS_SUCCESS)
            throw cRuntimeError("Failed to encapsulate shared secret");

        // Log key generation
        EV_INFO << "KyberAESLTE Generated Ciphertext and Shared Secret key.\n";
        // Send ciphertext back to ueA
        Packet *respPacket = new Packet("Ciphertext");
        auto respPayload = makeShared<BytesChunk>(ciphertext, kem->length_ciphertext);
        respPacket->insertAtBack(respPayload);
        bubble("Ciphertext Generated");

        socket->sendTo(respPacket, destAddr, destPort);

        // Free resources
        OQS_KEM_free(kem);
        delete[] receivedPublicKey;
        delete[] ciphertext;

        // Proceed to send encrypted data
        sendEncryptedData();

    }
    else if (nodeName == "ueA" && strcmp(packet->getName(), "Ciphertext") == 0) {
        // Node A processes ciphertext
        uint8_t *receivedCiphertext = new uint8_t[payloadSize];
        memcpy(receivedCiphertext, payload->getBytes().data(), payloadSize);

        // Initialize Kyber KEM
        OQS_KEM *kem = OQS_KEM_new(kyberVariantLTE);
        if (!kem)
            throw cRuntimeError("Failed to initialize Kyber KEM");

        sharedSecret = new uint8_t[kem->length_shared_secret];

        // Decapsulate shared secret
        if (OQS_KEM_decaps(kem, sharedSecret, receivedCiphertext, secretKey) != OQS_SUCCESS)
            throw cRuntimeError("Failed to decapsulate shared secret");

        bubble("Decapsulated");
        EV_INFO << "KyberAESLTE generated Shared Secret key.\n";
        // Free resources
        OQS_KEM_free(kem);
        delete[] receivedCiphertext;

        // Proceed to send encrypted data
        sendEncryptedData();
    }
    else if (strcmp(packet->getName(), "EncryptedData") == 0) {
        // Decrypt data
        size_t dataLen = payloadSize;
        unsigned char *receivedEncryptedData = new unsigned char[dataLen];
        memcpy(receivedEncryptedData, payload->getBytes().data(), dataLen);

        // Decrypt using AES
        AES_KEY aesKey;
        if (AES_set_decrypt_key(sharedSecret, 256, &aesKey) < 0)
            throw cRuntimeError("Failed to set AES decryption key");

        unsigned char *decryptedData = new unsigned char[dataLen];
        unsigned char iv[AES_BLOCK_SIZE] = {0};

        AES_cbc_encrypt(receivedEncryptedData, decryptedData, dataLen, &aesKey, iv, AES_DECRYPT);

        // Output decrypted data
        EV_INFO << nodeName << "KyberAESLTE received decrypted data: " << decryptedData << endl;

        // Clean up
        delete[] decryptedData;
        delete[] receivedEncryptedData;
    }

    delete packet;
}

void LTEApp::sendEncryptedData()
{
    std::string nodeName = getParentModule()->getFullName();

    if (!sharedSecret) {
        EV_ERROR << nodeName << " has no shared secret established. Cannot send encrypted data." << endl;
        return;
    }

    // Prepare the plaintext message
    std::string plainText = "Secret Message from " + nodeName;

    // Pad plaintext to AES block size
    size_t paddedLen = ((plainText.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *plainData = new unsigned char[paddedLen];
    memset(plainData, 0, paddedLen);
    memcpy(plainData, plainText.c_str(), plainText.size());

    // AES encryption using the shared secret
    AES_KEY aesKey;
    if (AES_set_encrypt_key(sharedSecret, 256, &aesKey) < 0) {
        throw cRuntimeError("Failed to set AES encryption key");
    }

    unsigned char *encryptedData = new unsigned char[paddedLen];
    unsigned char iv[AES_BLOCK_SIZE] = {0};

    AES_cbc_encrypt(plainData, encryptedData, paddedLen, &aesKey, iv, AES_ENCRYPT);

    // Create the packet to send the encrypted data
    Packet *encPacket = new Packet("EncryptedData");
    auto payload = makeShared<BytesChunk>(encryptedData, paddedLen);
    encPacket->insertAtBack(payload);
    encPacket->setTimestamp(simTime());

    // Send the encrypted message to the other node
    socket.sendTo(encPacket, destAddr, destPort);

    EV_INFO << nodeName << "KyberAESLTE sent encrypted data at time " << simTime() << endl;

    // Clean up
    delete[] plainData;
    delete[] encryptedData;
}


void LTEApp::handleStopOperation(LifecycleOperation *operation)
{
    socket.close();
    cancelAndDelete(selfMsg);
    selfMsg = nullptr;
}

void LTEApp::handleCrashOperation(LifecycleOperation *operation)
{
    socket.destroy();
    cancelAndDelete(selfMsg);
    selfMsg = nullptr;
}

void LTEApp::finish()
{
    ApplicationBase::finish();
    // Clean up dynamically allocated memory
    delete[] publicKey;
    delete[] secretKey;
    delete[] sharedSecret;
}

std::string LTEApp::formatHex(const uint8_t *data, size_t length)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i)
        oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}
