cd ecdsa/
gcc ecdsa.c -o ecdsa -lssl -lcrypto
./ecdsa 0 > ../result/ecdsa_256.txt
# ./ecdsa_test 0

./ecdsa 1 > ../result/ecdsa_384.txt

cd ../