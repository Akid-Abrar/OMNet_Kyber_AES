#include "LTEApp.h"

// Include the necessary headers
#include <iomanip>           // For std::setw and std::setfill
#include <cstring>
#include <chrono>
#include <iostream>
#include <x86intrin.h>
#include <inet/common/INETDefs.h>
#include <inet/common/packet/Packet.h>
#include <inet/networklayer/common/L3AddressResolver.h>
#include <inet/applications/common/SocketTag_m.h>
#include <inet/transportlayer/contract/udp/UdpControlInfo_m.h>
#include <oqs/oqs.h>
#include <openssl/aes.h>

Define_Module(LTEApp);

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
        selfMsg = new cMessage("start");
    }
}

void LTEApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        processStart();
        delete msg; // Don't forget to delete the self-message
    } else {
        socket.processMessage(msg);
    }
}


// ... (rest of your methods, such as handleMessageWhenUp, processStart, etc.)


void LTEApp::processStart()
{
    // Initialize the socket
    socket.setCallback(this);
    socket.setOutputGate(gate("socketOut"));
    socket.bind(1000); // Bind to local port 1000

    // Send public key if nodeA
    const char* nodeName = getParentModule()->getName();
    if (strcmp(nodeName, "ueA") == 0) {
        sendPublicKey();
    }
}

void LTEApp::sendPublicKey()
{
    // Similar to your previous sendPublicKey implementation
    // Generate key pair, send public key over UDP socket
    OQS_KEM *kem = OQS_KEM_new("Kyber512");
    if (!kem)
        throw cRuntimeError("Failed to initialize Kyber512 KEM");

    publicKey = new uint8_t[kem->length_public_key];
    secretKey = new uint8_t[kem->length_secret_key];

    const char* nodeName = getParentModule()->getName();

    // Measure time and clock cycles for keypair generation
    auto start_time = std::chrono::high_resolution_clock::now();
    unsigned long long start_cycles = __rdtsc();

    if (OQS_KEM_keypair(kem, publicKey, secretKey) != OQS_SUCCESS)
        throw cRuntimeError("Failed to generate Kyber512 key pair");

    unsigned long long end_cycles = __rdtsc();
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
    unsigned long long cycles = end_cycles - start_cycles;

    // Print time taken and clock cycles
    EV << nodeName << " generated Kyber512 key pair in " << duration_time << " microseconds.\n";
    EV << nodeName << " key pair generation took " << cycles << " CPU cycles.\n";

    // Print sizes
    EV << "Public key size: " << kem->length_public_key << " bytes.\n";
    EV << "Secret key size: " << kem->length_secret_key << " bytes.\n";
    EV << "Shared secret size: " << kem->length_shared_secret << " bytes.\n";

    EV << nodeName << " generated Kyber512 key pair.\n";
    EV << nodeName << "'s public key: " << formatHex(publicKey, kem->length_public_key) << "\n";

    // Send public key to ueB
    Packet *packet = new Packet("PublicKey");
    auto payload = makeShared<BytesChunk>(publicKey, kem->length_public_key);
    packet->insertAtBack(payload);

    // Set UDP destination address and port
    L3AddressResolver resolver;
    L3Address destAddr = resolver.resolve("ueB");
    socket.sendTo(packet, destAddr, 1000); // Send to port 1000

    OQS_KEM_free(kem);
}

void LTEApp::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    const char* nodeName = getParentModule()->getName();
    EV << nodeName << " received a packet: " << packet->getName() << endl;

    const auto& payload = packet->peekData<BytesChunk>();
    size_t payloadSize = payload->getChunkLength().get();

    if (strcmp(nodeName, "ueB") == 0 && strcmp(packet->getName(), "PublicKey") == 0) {
        // Process public key, generate shared secret, send ciphertext
        uint8_t *receivedPublicKey = new uint8_t[payloadSize];
        memcpy(receivedPublicKey, payload->getBytes().data(), payloadSize);

        OQS_KEM *kem = OQS_KEM_new("Kyber512");
        if (!kem)
            throw cRuntimeError("Failed to initialize Kyber512 KEM");

        uint8_t *ciphertext = new uint8_t[kem->length_ciphertext];
        sharedSecret = new uint8_t[kem->length_shared_secret];

        // Measure time and clock cycles for encapsulation
        auto start_time = std::chrono::high_resolution_clock::now();
        unsigned long long start_cycles = __rdtsc();

        if (OQS_KEM_encaps(kem, ciphertext, sharedSecret, receivedPublicKey) != OQS_SUCCESS)
            throw cRuntimeError("Failed to encapsulate shared secret");

        unsigned long long end_cycles = __rdtsc();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        unsigned long long cycles = end_cycles - start_cycles;

        // Print time taken and clock cycles
        EV << nodeName << " encapsulated shared secret in " << duration_time << " microseconds.\n";
        EV << nodeName << " encapsulation took " << cycles << " CPU cycles.\n";

        // Send ciphertext back to ueA
        Packet *respPacket = new Packet("Ciphertext");
        auto respPayload = makeShared<BytesChunk>(ciphertext, kem->length_ciphertext);
        respPacket->insertAtBack(respPayload);

        // Set UDP destination address and port
        L3AddressResolver resolver;
        L3Address destAddr = resolver.resolve("ueA");
        socket->sendTo(respPacket, destAddr, 1000);

        OQS_KEM_free(kem);

        // Schedule sending encrypted data
        cMessage *sendDataMsg = new cMessage("sendEncryptedData");
        scheduleAt(simTime() + 1, sendDataMsg);

    } else if (strcmp(nodeName, "ueA") == 0 && strcmp(packet->getName(), "Ciphertext") == 0) {
        // Process ciphertext, derive shared secret
        uint8_t *receivedCiphertext = new uint8_t[payloadSize];
        memcpy(receivedCiphertext, payload->getBytes().data(), payloadSize);

        OQS_KEM *kem = OQS_KEM_new("Kyber512");
        if (!kem)
            throw cRuntimeError("Failed to initialize Kyber512 KEM");

        sharedSecret = new uint8_t[kem->length_shared_secret];

        // Measure time and clock cycles for decapsulation
        auto start_time = std::chrono::high_resolution_clock::now();
        unsigned long long start_cycles = __rdtsc();

        if (OQS_KEM_decaps(kem, sharedSecret, receivedCiphertext, secretKey) != OQS_SUCCESS)
            throw cRuntimeError("Failed to decapsulate shared secret");

        unsigned long long end_cycles = __rdtsc();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        unsigned long long cycles = end_cycles - start_cycles;

        EV << nodeName << " decapsulated shared secret in " << duration_time << " microseconds.\n";
        EV << nodeName << " decapsulation took " << cycles << " CPU cycles.\n";

        OQS_KEM_free(kem);

        // Schedule sending encrypted data
        cMessage *sendDataMsg = new cMessage("sendEncryptedData");
        scheduleAt(simTime() + 1, sendDataMsg);

    } else if (strcmp(packet->getName(), "EncryptedData") == 0) {
        // Decrypt data
        const char* nodeName = getParentModule()->getName();
        size_t dataLen = payloadSize;
        unsigned char *receivedEncryptedData = new unsigned char[dataLen];
        memcpy(receivedEncryptedData, payload->getBytes().data(), dataLen);

        AES_KEY aesKey;
        if (AES_set_decrypt_key(sharedSecret, 256, &aesKey) < 0)
            throw cRuntimeError("Failed to set AES decryption key");

        unsigned char *decryptedData = new unsigned char[dataLen];
        unsigned char iv[AES_BLOCK_SIZE] = {0};

        AES_cbc_encrypt(receivedEncryptedData, decryptedData, dataLen, &aesKey, iv, AES_DECRYPT);

        // Output decrypted data
        EV << nodeName << " received decrypted data: " << decryptedData << endl;

        delete[] decryptedData;
    }

    delete packet;
}

void LTEApp::handleStartOperation(LifecycleOperation *operation)
{
    scheduleAt(simTime() + uniform(0, 1), selfMsg); // Schedule self-message to start
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

void LTEApp::sendEncryptedData()
{
    const char* nodeName = getParentModule()->getName();

    if (!sharedSecret) {
        EV << nodeName << " has no shared secret established. Cannot send encrypted data." << endl;
        return;
    }

    // Prepare the plaintext message
    std::string plainText = "Secret Message from " + std::string(nodeName);

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
    unsigned char iv[AES_BLOCK_SIZE] = {0}; // Initialization vector (should be random in practice)

    AES_cbc_encrypt(plainData, encryptedData, paddedLen, &aesKey, iv, AES_ENCRYPT);

    // Create the packet to send the encrypted data
    Packet *encPacket = new Packet("EncryptedData");
    auto payload = makeShared<BytesChunk>(encryptedData, paddedLen);
    encPacket->insertAtBack(payload);

    // Send the encrypted message to the other node
    L3AddressResolver resolver;
    L3Address destAddr = resolver.resolve(strcmp(nodeName, "ueA") == 0 ? "ueB" : "ueA");
    socket.sendTo(encPacket, destAddr, 1000);

    EV << nodeName << " sent encrypted data at time " << simTime() << endl;

    // Clean up
    delete[] plainData;
    delete[] encryptedData;
}

void LTEApp::finish()
{
    ApplicationBase::finish();
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
