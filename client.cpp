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


// 生成消息摘要（使用MD5哈希算法）
std::string generateDigest(const std::string& message) {
    HCRYPTPROV hCryptProv;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        HCRYPTHASH hHash;
        if (CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)message.c_str(), message.size(), 0)) {
                DWORD digestSize = 16; // MD5摘要大小为16字节
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

// 发送消息到服务器
void send_message() {
    std::cout << "Enter a message (type 'exit' to quit): ";
    while (true) {
        int taskCode = 1; // 初始化任务代码，表示执行操作1
        std::string messageToSend;
        {
            std::lock_guard<std::mutex> lock(inputMutex);
            std::getline(std::cin, messageToSend);
        }

        if (messageToSend == "exit") {
            // 用户选择退出，跳出循环
            break;
        }


        if (!messageToSend.empty()) {
            if (messageToSend[0] == '$') {
                // 群发消息，移除 $ 符号
                messageToSend = messageToSend.substr(1);

                taskCode = 1; // 任务代码，表示有效消息
                std::string digest = generateDigest(messageToSend);
                std::string messageWithDigestAndTaskCode = std::to_string(taskCode) + messageToSend + digest;
                send(client_socket, messageWithDigestAndTaskCode.c_str(), messageWithDigestAndTaskCode.size(), 0);
            }
            else {
                // 普通消息
                taskCode = 2; // 任务代码，表示执行广播消息
                std::string digest = generateDigest(messageToSend);
                std::string messageWithDigestAndTaskCode = std::to_string(taskCode) + messageToSend + digest;
                send(client_socket, messageWithDigestAndTaskCode.c_str(), messageWithDigestAndTaskCode.size(), 0);
            }
        }
    }
}

// 接收来自服务器的消息
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

            // 提取消息内容（不包括哈希值）
            std::string messageContent = message.substr(0, message.length() - 32); // 假定MD5摘要长度为32

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
    server_address.sin_port = htons(521); // 服务器端口号

    // 使用 InetPton 替代 inet_pton
    if (InetPton(AF_INET, _T("127.0.0.1"), &(server_address.sin_addr)) != 1) {
        std::cerr << "Invalid address" << std::endl;
        WSACleanup();
        return 1;
    }

    // 连接到服务器
    connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address));

    // 启动发送和接收消息的线程
    std::thread send_thread(send_message);
    std::thread receive_thread(receive_message);

    // 等待线程完成
    send_thread.join();
    receive_thread.join();

    // 清理Winsock
    WSACleanup();

    return 0;
}
