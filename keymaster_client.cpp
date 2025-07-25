#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <google/protobuf/message.h>
#include <fstream>
#include "keymaster_proxy_client.pb.h"

#define DEBUG

using namespace quasar::keymaster_proxy_client::proto;

// Function to encode a string to Base64
std::string toBase64(const std::string& input) {
    const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    size_t i = 0;
    unsigned char char_array_3[3], char_array_4[4];

    for (size_t j = 0; j < input.size();) {
        char_array_3[0] = char_array_3[1] = char_array_3[2] = 0;
        for (i = 0; i < 3 && j < input.size(); i++, j++) {
            char_array_3[i] = static_cast<unsigned char>(input[j]);
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) | ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) | ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (size_t k = 0; k < (i < 3 ? i + 1 : 4); k++) {
            result += base64_chars[char_array_4[k]];
        }

        if (i < 3) {
            for (size_t k = i + 1; k < 4; k++) {
                result += '=';
            }
        }
    }

    return result;
}

// Function to read file content into a string
std::string readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open input file: " << filename << std::endl;
        return "";
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return content;
}

// Function to write string to file
bool writeFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open output file: " << filename << std::endl;
        return false;
    }
    file.write(content.data(), content.size());
    file.close();
    return true;
}

// Function to send a protobuf message over a socket
bool sendProtobufMessage(int sockfd, const google::protobuf::Message& message) {
    #ifdef DEBUG
    std::cerr << "DEBUG: Starting sendProtobufMessage" << std::endl;
    #endif

    std::string serialized;
    if (!message.SerializeToString(&serialized)) {
        std::cerr << "Failed to serialize protobuf message" << std::endl;
        return false;
    }

    // Send magic number (0x42fa851f in big-endian)
    uint32_t magic = htonl(0x42fa851f);
    if (write(sockfd, &magic, sizeof(magic)) != sizeof(magic)) {
        std::cerr << "Failed to send magic number" << std::endl;
        return false;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Sent magic number" << std::endl;
    #endif

    // Send message length (4 bytes, big-endian)
    uint32_t length = htonl(serialized.size());
    if (write(sockfd, &length, sizeof(length)) != sizeof(length)) {
        std::cerr << "Failed to send message length" << std::endl;
        return false;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Sent message length: " << serialized.size() << std::endl;
    #endif

    // Send the serialized message
    if (write(sockfd, serialized.data(), serialized.size()) != static_cast<ssize_t>(serialized.size())) {
        std::cerr << "Failed to send message" << std::endl;
        return false;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Sent serialized message" << std::endl;
    #endif
    return true;
}

// Function to receive a protobuf message from a socket
bool receiveProtobufMessage(int sockfd, google::protobuf::Message& message) {
    #ifdef DEBUG
    std::cerr << "DEBUG: Starting receiveProtobufMessage" << std::endl;
    #endif

    // Read magic number (4 bytes, big-endian)
    uint32_t magic;
    if (read(sockfd, &magic, sizeof(magic)) != sizeof(magic)) {
        std::cerr << "Failed to read magic number" << std::endl;
        return false;
    }
    magic = ntohl(magic);
    if (magic != 0x42fa851f) {
        std::cerr << "Invalid magic number received: 0x" << std::hex << magic << std::dec << std::endl;
        return false;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Received valid magic number: 0x42fa851f" << std::endl;
    #endif

    // Read message length (4 bytes, big-endian)
    uint32_t length;
    if (read(sockfd, &length, sizeof(length)) != sizeof(length)) {
        std::cerr << "Failed to read message length" << std::endl;
        return false;
    }
    length = ntohl(length);
    #ifdef DEBUG
    std::cerr << "DEBUG: Received message length: " << length << std::endl;
    #endif

    // Read the serialized message
    std::vector<char> buffer(length);
    ssize_t bytes_read = 0;
    while (bytes_read < static_cast<ssize_t>(length)) {
        ssize_t result = read(sockfd, buffer.data() + bytes_read, length - bytes_read);
        if (result <= 0) {
            std::cerr << "Failed to read message data" << std::endl;
            return false;
        }
        bytes_read += result;
        #ifdef DEBUG
        std::cerr << "DEBUG: Read " << result << " bytes, total: " << bytes_read << "/" << length << std::endl;
        #endif
    }

    // Parse the message
    if (!message.ParseFromArray(buffer.data(), length)) {
        std::cerr << "Failed to parse protobuf message" << std::endl;
        return false;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Successfully parsed protobuf message" << std::endl;
    #endif
    return true;
}

int main(int argc, char* argv[]) {
    #ifdef DEBUG
    std::cerr << "DEBUG: Starting main" << std::endl;
    #endif

    // Validate command-line arguments
    if (argc < 2 || ((std::string(argv[2]) == "sign" || std::string(argv[2]) == "decrypt") && argc != 5)) {
        std::cerr << "Usage: " << argv[0] << " <socket_path> <operation> [input_file] [output_file]" << std::endl;
        std::cerr << "Operations: export, sign, decrypt" << std::endl;
        return 1;
    }

    std::string socket_path = argv[1];
    std::string operation = argv[2];
    if (operation != "export" && operation != "sign" && operation != "decrypt") {
        std::cerr << "Invalid operation: " << operation << ". Supported: export, sign, decrypt" << std::endl;
        return 1;
    }

    // Create Unix domain socket
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return 1;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Created socket, fd: " << sockfd << std::endl;
    #endif

    // Connect to the keymaster service
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to connect to keymaster service at " << socket_path << ": " << strerror(errno) << std::endl;
        close(sockfd);
        return 1;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Connected to keymaster service at " << socket_path << std::endl;
    #endif

    // Create and send request based on operation
    Request request;
    if (operation == "export") {
        request.mutable_export_key_request();
        #ifdef DEBUG
        std::cerr << "DEBUG: Created ExportKeyRequest" << std::endl;
        #endif
    } else if (operation == "sign") {
        std::string input_file = argv[3];
        std::string input_content = readFile(input_file);
        if (input_content.empty()) {
            std::cerr << "Failed to read input file: " << input_file << std::endl;
            close(sockfd);
            return 1;
        }
        auto* sign_request = request.mutable_sign_request();
        sign_request->set_payload(input_content);
        #ifdef DEBUG
        std::cerr << "DEBUG: Created SignRequest with payload size: " << input_content.size() << std::endl;
        #endif
    } else if (operation == "decrypt") {
        std::string input_file = argv[3];
        std::string input_content = readFile(input_file);
        if (input_content.empty()) {
            std::cerr << "Failed to read input file: " << input_file << std::endl;
            close(sockfd);
            return 1;
        }
        auto* decrypt_request = request.mutable_decrypt_request();
        decrypt_request->set_payload(input_content);
        #ifdef DEBUG
        std::cerr << "DEBUG: Created DecryptRequest with payload size: " << input_content.size() << std::endl;
        #endif
    }

    if (!sendProtobufMessage(sockfd, request)) {
        std::cerr << "Failed to send request" << std::endl;
        close(sockfd);
        return 1;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Sent request" << std::endl;
    #endif

    // Receive and process response
    Response response;
    if (!receiveProtobufMessage(sockfd, response)) {
        std::cerr << "Failed to receive response" << std::endl;
        close(sockfd);
        return 1;
    }
    #ifdef DEBUG
    std::cerr << "DEBUG: Received response" << std::endl;
    #endif

    // Process response based on operation
    if (operation == "export" && response.has_export_key_response()) {
        const auto& export_response = response.export_key_response();
        #ifdef DEBUG
        std::cerr << "DEBUG: Response is ExportKeyResponse" << std::endl;
        #endif
        if (export_response.has_payload()) {
            std::string payload(export_response.payload().begin(), export_response.payload().end());
            std::string base64_payload = toBase64(payload);
            std::cout << "Received payload (Base64): " << base64_payload << std::endl;
            #ifdef DEBUG
            std::cerr << "DEBUG: Payload size: " << payload.size() << ", Base64 size: " << base64_payload.size() << std::endl;
            #endif
        } else {
            std::cout << "ExportKeyResponse received, but no payload present" << std::endl;
            #ifdef DEBUG
            std::cerr << "DEBUG: No payload in ExportKeyResponse" << std::endl;
            #endif
        }
    } else if (operation == "sign" && response.has_sign_response()) {
        const auto& sign_response = response.sign_response();
        #ifdef DEBUG
        std::cerr << "DEBUG: Response is SignResponse" << std::endl;
        #endif
        if (sign_response.has_payload()) {
            std::string output_file = argv[4];
            std::string payload(sign_response.payload().begin(), sign_response.payload().end());
            if (!writeFile(output_file, payload)) {
                std::cerr << "Failed to write to output file: " << output_file << std::endl;
                close(sockfd);
                return 1;
            }
            std::cout << "Signature written to: " << output_file << std::endl;
            #ifdef DEBUG
            std::cerr << "DEBUG: Payload size: " << payload.size() << std::endl;
            #endif
        } else {
            std::cout << "SignResponse received, but no payload present" << std::endl;
            #ifdef DEBUG
            std::cerr << "DEBUG: No payload in SignResponse" << std::endl;
            #endif
        }
    } else if (operation == "decrypt" && response.has_decrypt_response()) {
        const auto& decrypt_response = response.decrypt_response();
        #ifdef DEBUG
        std::cerr << "DEBUG: Response is DecryptResponse" << std::endl;
        #endif
        if (decrypt_response.has_payload()) {
            std::string output_file = argv[4];
            std::string payload(decrypt_response.payload().begin(), decrypt_response.payload().end());
            if (!writeFile(output_file, payload)) {
                std::cerr << "Failed to write to output file: " << output_file << std::endl;
                close(sockfd);
                return 1;
            }
            std::cout << "Decrypted data written to: " << output_file << std::endl;
            #ifdef DEBUG
            std::cerr << "DEBUG: Payload size: " << payload.size() << std::endl;
            #endif
        } else {
            std::cout << "DecryptResponse received, but no payload present" << std::endl;
            #ifdef DEBUG
            std::cerr << "DEBUG: No payload in DecryptResponse" << std::endl;
            #endif
        }
    } else if (response.has_error_response()) {
        const auto& error = response.error_response();
        std::cerr << "Error response received: code=" << error.code() << ", text=" 
                  << (error.has_text() ? error.text() : "no text") << std::endl;
        #ifdef DEBUG
        std::cerr << "DEBUG: Error response, code: " << error.code() << std::endl;
        #endif
    } else {
        std::cerr << "Unexpected response type received" << std::endl;
        #ifdef DEBUG
        std::cerr << "DEBUG: Unexpected response type" << std::endl;
        #endif
    }

    // Cleanup
    #ifdef DEBUG
    std::cerr << "DEBUG: Closing socket" << std::endl;
    #endif
    close(sockfd);
    #ifdef DEBUG
    std::cerr << "DEBUG: Program exiting" << std::endl;
    #endif
    return 0;
}