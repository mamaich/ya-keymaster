# ya-keymaster
Исходники по работе с keymaster на устройствах Яндекса  
keymaster_client - аналог keymaster_proxy_app  
blobs.py - утилита по разбору key_blob на устройствах с процессорами Amlogic. Первоисточник: https://gist.github.com/mildsunrise/585dba677395f1f0a9413c5cbc1c8f2e (в оригинале отсутствовали enums, я добавил)  


Компиляция:  
protoc --cpp_out=. ./keymaster_proxy_client.proto  
arm-linux-gnueabihf-g++ -static -o keymaster_client keymaster_client.cpp keymaster_proxy_client.pb.cc -lprotobuf -std=c++11  


Файл ./keymaster_proxy_client.proto получен из maind утилитой https://github.com/mamaich/protodump  