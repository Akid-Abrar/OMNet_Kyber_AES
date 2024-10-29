packet KyberMessage
{
    int msgType; // 0: public key, 1: ciphertext, 2: encrypted data
    char payload[];
}
