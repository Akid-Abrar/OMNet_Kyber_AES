#include "Node.h"
#include <cstring>
#include <iomanip>
#include <sstream>


Define_Module(Node);

size_t key_length;

//remove unnecessary comments
void Node::initialize()
{
    const char* nodeName = getName();
    if (strcmp(nodeName, "nodeA") == 0) {
        sendPublickKey();
    }
}

void Node::sendPublickKey()
{
    // Node A: Generate key pair and send public key
    OQS_KEM *kem = OQS_KEM_new("Kyber512");
    if (!kem) error("Failed to initialize Kyber512 KEM");

    publicKey = new uint8_t[kem->length_public_key];
    secretKey = new uint8_t[kem->length_secret_key];

    const char* nodeName = getName();


    if (OQS_KEM_keypair(kem, publicKey, secretKey) != OQS_SUCCESS)
        error("Failed to generate Kyber512 key pair");

    EV << nodeName << " generated Kyber512 key pair.\n";
    EV << nodeName << "'s public key: " << formatHex(publicKey, kem->length_public_key) << "\n";
    key_length = kem->length_public_key;
    bubble("Generated key pair");

    // Send public key to Node B
    KyberMessage *msg = new KyberMessage("PublicKey");
    msg->setMsgType(0);

    // Set the payload size
    msg->setPayloadArraySize(kem->length_public_key);
    // Copy public key into payload array
    for (size_t i = 0; i < kem->length_public_key; ++i) {
        msg->setPayload(i, static_cast<char>(publicKey[i]));
    }

    //msg->setPayload(std::string(reinterpret_cast<char*>(publicKey), kem->length_public_key));
    send(msg, "outPort");

    OQS_KEM_free(kem);
}

void Node::sendEncryptedData()
{
    const char* nodeName = getName();

    // Ensure that the shared secret has been established
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
        error("Failed to set AES encryption key");
    }

    unsigned char *encryptedData = new unsigned char[paddedLen];
    unsigned char iv[AES_BLOCK_SIZE] = {0}; // Initialization vector (should be random in practice)

    AES_cbc_encrypt(plainData, encryptedData, paddedLen, &aesKey, iv, AES_ENCRYPT);

    // Create the KyberMessage to send the encrypted data
    KyberMessage *encMsg = new KyberMessage("EncryptedData");
    encMsg->setMsgType(2);

    // Set the payload array size
    encMsg->setPayloadArraySize(paddedLen);

    // Copy the encrypted data into the payload array
    for (size_t i = 0; i < paddedLen; ++i) {
        encMsg->setPayload(i, static_cast<int>(encryptedData[i]));
    }

    // Send the encrypted message to the other node
    send(encMsg, "outPort");

    EV << nodeName << " sent encrypted data at time " << simTime() << endl;

    // Clean up dynamically allocated memory
    delete[] plainData;
    delete[] encryptedData;
}

void Node::handleMessage(cMessage *msg)
{
    const char* nodeName = getName();
    EV << nodeName << " received a message: " << msg->getName() << endl;
    KyberMessage *kMsg = dynamic_cast<KyberMessage*>(msg);

    if (!kMsg) {
            // Handle self-messages
        if (msg->isSelfMessage()) {
            if (strcmp(msg->getName(), "sendEncryptedData") == 0) {
                // Process self-message to send encrypted data
                sendEncryptedData();
            }
            delete msg;
        } else {
            // Unknown message type
            delete msg;
            EV << "deleting for unknown type\n";
        }
        return;
    }

    size_t payloadSize = kMsg->getPayloadArraySize();
    if (strcmp(nodeName, "nodeB") == 0 && kMsg->getMsgType() == 0) {
        // Node B: Receive public key and send ciphertext
        EV << nodeName << " received public key from Node.\n";
        bubble("Received public key");

//      std::string pubKeyStr = kMsg->getPayload();
//      const uint8_t *receivedPublicKey = reinterpret_cast<const uint8_t*>(pubKeyStr.data());

        // Allocate memory to store the payload
        uint8_t *receivedPublicKey = new uint8_t[payloadSize];

        // Copy data from the message to your buffer
        for (size_t i = 0; i < payloadSize; ++i) {
            receivedPublicKey[i] = static_cast<uint8_t>(kMsg->getPayload(i));
        }

        EV <<"public key: "<< formatHex(receivedPublicKey, key_length) << endl;

        OQS_KEM *kem = OQS_KEM_new("Kyber512");
        if (!kem) error("Failed to initialize Kyber512 KEM");

        uint8_t *ciphertext = new uint8_t[kem->length_ciphertext];
        sharedSecret = new uint8_t[kem->length_shared_secret];

        if (OQS_KEM_encaps(kem, ciphertext, sharedSecret, receivedPublicKey) != OQS_SUCCESS)
            error("Failed to encapsulate shared secret");

        EV <<nodeName << "'s shared secret: " << formatHex(sharedSecret, kem->length_shared_secret) << "\n";
        // Send ciphertext back to Node A
        KyberMessage *respMsg = new KyberMessage("Ciphertext");
        respMsg->setMsgType(1);
        // Set the payload size
        respMsg->setPayloadArraySize(kem->length_ciphertext);
        // Copy public key into payload array
        for (size_t i = 0; i < kem->length_ciphertext; ++i) {
            respMsg->setPayload(i, static_cast<char>(ciphertext[i]));
        }

        //respMsg->setPayload(std::string(reinterpret_cast<char*>(ciphertext), kem->length_ciphertext));

        send(respMsg, "outPort");

        delete[] ciphertext;
        OQS_KEM_free(kem);

        // Schedule sending encrypted data
        scheduleAt(simTime() + 1, new cMessage("sendEncryptedData"));

    } else if (strcmp(nodeName, "nodeA") == 0 && kMsg->getMsgType() == 1) {
        // Node A: Receive ciphertext and derive shared secret
//        std::string cipherTextStr = kMsg->getPayload();
//        const uint8_t *receivedCiphertext = reinterpret_cast<const uint8_t*>(cipherTextStr.data());

        // Allocate memory to store the payload
        uint8_t *receivedCiphertext = new uint8_t[payloadSize];

        // Copy data from the message to your buffer
        for (size_t i = 0; i < payloadSize; ++i) {
            receivedCiphertext[i] = static_cast<uint8_t>(kMsg->getPayload(i));
        }

        OQS_KEM *kem = OQS_KEM_new("Kyber512");
        if (!kem) error("Failed to initialize Kyber512 KEM");

        sharedSecret = new uint8_t[kem->length_shared_secret];

        if (OQS_KEM_decaps(kem, sharedSecret, receivedCiphertext, secretKey) != OQS_SUCCESS)
            error("Failed to decapsulate shared secret");

        EV <<nodeName << " decapsulated shared secret.\n";
        EV <<nodeName << "'s shared secret: " << formatHex(sharedSecret, kem->length_shared_secret) << "\n";
        bubble("Shared secret derived");

        OQS_KEM_free(kem);

        // Schedule sending encrypted data
        scheduleAt(simTime() + 1, new cMessage("sendEncryptedData"));

    }
//        else if (strcmp(msg->getName(), "sendEncryptedData") == 0) {
//        bubble("yooooooooooooooooooooooooooooooooooooo");
//        EV<<"chk\n";
//        // Both nodes send encrypted data
//        std::string plainText = "Secret Message";
//        // Pad plaintext to AES block size
//        size_t paddedLen = ((plainText.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
//        unsigned char *plainData = new unsigned char[paddedLen];
//        memset(plainData, 0, paddedLen);
//        memcpy(plainData, plainText.c_str(), plainText.size());
//
//        // AES encryption
//        AES_KEY aesKey;
//        if (AES_set_encrypt_key(sharedSecret, 256, &aesKey) < 0)
//            error("Failed to set AES encryption key");
//
//        unsigned char *encryptedData = new unsigned char[paddedLen];
//        unsigned char iv[AES_BLOCK_SIZE] = {0};
//
//        AES_cbc_encrypt(plainData, encryptedData, paddedLen, &aesKey, iv, AES_ENCRYPT);
//
//        // Send encrypted data
//        KyberMessage *encMsg = new KyberMessage("EncryptedData");
//        encMsg->setMsgType(2);
//
//        // Set the payload array size
//        encMsg->setPayloadArraySize(paddedLen);
//        EV << "before generating payload"<<endl;
//        // Copy the encrypted data into the payload array
//        for (size_t i = 0; i < paddedLen; ++i) {
//            encMsg->setPayload(i, static_cast<char>(encryptedData[i]));
//        }
//        EV << "after generating payload"<<endl;
//        //encMsg->setPayload(std::string(reinterpret_cast<char*>(encryptedData), paddedLen));
//        send(encMsg, "outPort");
//
//        delete[] plainData;
//        delete[] encryptedData;
//
//    }
        else if (kMsg->getMsgType() == 2) {
        // Receive and decrypt data
//        std::string encryptedDataStr = kMsg->getPayload();
//        const unsigned char *receivedEncryptedData = reinterpret_cast<const unsigned char*>(encryptedDataStr.data());
//        size_t dataLen = encryptedDataStr.size();


        size_t dataLen = kMsg->getPayloadArraySize();
        unsigned char *receivedEncryptedData = new unsigned char[dataLen];

        for (size_t i = 0; i < dataLen; ++i) {
            receivedEncryptedData[i] = static_cast<unsigned char>(kMsg->getPayload(i));
        }

        AES_KEY aesKey;
        if (AES_set_decrypt_key(sharedSecret, 256, &aesKey) < 0)
            error("Failed to set AES decryption key");

        unsigned char *decryptedData = new unsigned char[dataLen];
        unsigned char iv[AES_BLOCK_SIZE] = {0};

        AES_cbc_encrypt(receivedEncryptedData, decryptedData, dataLen, &aesKey, iv, AES_DECRYPT);

        // Output decrypted data
        EV << nodeName << " received decrypted data: " << decryptedData << endl;

        delete[] decryptedData;
    }

    delete msg;
}

void Node::finish()
{
    delete[] publicKey;
    delete[] secretKey;
    delete[] sharedSecret;
}

std::string Node::formatHex(const uint8_t *data, size_t length)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i)
        oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

