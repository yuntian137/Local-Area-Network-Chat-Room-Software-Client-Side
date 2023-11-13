#include <iostream>
#include <string>
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <thread>
#include <tchar.h>
#include <mutex>
#pragma comment(lib, "ws2_32.lib")
#include <Windows.h>
#include <Wincrypt.h>

int client_socket;
std::mutex inputMutex;


// ������ϢժҪ��ʹ��MD5��ϣ�㷨��
std::string generateDigest(const std::string& message) {
    HCRYPTPROV hCryptProv;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        HCRYPTHASH hHash;
        if (CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)message.c_str(), message.size(), 0)) {
                DWORD digestSize = 16; // MD5ժҪ��СΪ16�ֽ�
                BYTE digest[16];
                if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestSize, 0)) {
                    std::string result;
                    for (int i = 0; i < digestSize; i++) {
                        char buf[3];
                        sprintf_s(buf, "%02x", digest[i]);
                        result += buf;
                    }
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hCryptProv, 0);
                    return result;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hCryptProv, 0);
    }
    return "";
}

// ������Ϣ��������
void send_message() {
    std::cout << "Enter a message (type 'exit' to quit): ";
    while (true) {
        int taskCode = 1; // ��ʼ��������룬��ʾִ�в���1
        std::string messageToSend;
        {
            std::lock_guard<std::mutex> lock(inputMutex);
            std::getline(std::cin, messageToSend);
        }

        if (messageToSend == "exit") {
            // �û�ѡ���˳�������ѭ��
            break;
        }


        if (!messageToSend.empty()) {
            if (messageToSend[0] == '$') {
                // Ⱥ����Ϣ���Ƴ� $ ����
                messageToSend = messageToSend.substr(1);

                taskCode = 1; // ������룬��ʾ��Ч��Ϣ
                std::string digest = generateDigest(messageToSend);
                std::string messageWithDigestAndTaskCode = std::to_string(taskCode) + messageToSend + digest;
                send(client_socket, messageWithDigestAndTaskCode.c_str(), messageWithDigestAndTaskCode.size(), 0);
            }
            else {
                // ��ͨ��Ϣ
                taskCode = 2; // ������룬��ʾִ�й㲥��Ϣ
                std::string digest = generateDigest(messageToSend);
                std::string messageWithDigestAndTaskCode = std::to_string(taskCode) + messageToSend + digest;
                send(client_socket, messageWithDigestAndTaskCode.c_str(), messageWithDigestAndTaskCode.size(), 0);
            }
        }
    }
}

// �������Է���������Ϣ
void receive_message() {
    char buffer[1024];
    while (true) {
        int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            std::cout << "Connection lost." << std::endl;
            closesocket(client_socket);
            break;
        }
        else {
            buffer[bytes_received] = '\0';
            std::string message(buffer);

            // ��ȡ��Ϣ���ݣ���������ϣֵ��
            std::string messageContent = message.substr(0, message.length() - 32); // �ٶ�MD5ժҪ����Ϊ32

            std::cout << "Received: " << messageContent << std::endl;
        }
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(521); // �������˿ں�

    // ʹ�� InetPton ��� inet_pton
    if (InetPton(AF_INET, _T("127.0.0.1"), &(server_address.sin_addr)) != 1) {
        std::cerr << "Invalid address" << std::endl;
        WSACleanup();
        return 1;
    }

    // ���ӵ�������
    connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address));

    // �������ͺͽ�����Ϣ���߳�
    std::thread send_thread(send_message);
    std::thread receive_thread(receive_message);

    // �ȴ��߳����
    send_thread.join();
    receive_thread.join();

    // ����Winsock
    WSACleanup();

    return 0;
}
