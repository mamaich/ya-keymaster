# ya-keymaster
Исходники по работе с keymaster на устройствах Яндекса  
keymaster_client - аналог keymaster_proxy_app  

Компиляция:  
protoc --cpp_out=. ./keymaster_proxy_client.proto  
arm-linux-gnueabihf-g++ -static -o keymaster_client keymaster_client.cpp keymaster_proxy_client.pb.cc -lprotobuf -std=c++11  


Файл ./keymaster_proxy_client.proto получен из maind утилитой https://github.com/mamaich/protodump  