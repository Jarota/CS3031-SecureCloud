package main

import (
	"bufio"
	"crypto/aes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func GenerateSharedSecret(privateKey []byte, publicKey []byte, curve elliptic.Curve) []byte {
	publicX := new(big.Int).SetBytes(publicKey[:32])
	publicY := new(big.Int).SetBytes(publicKey[32:])
	sharedX, sharedY := curve.ScalarMult(publicX, publicY, privateKey)
	return elliptic.Marshal(curve, sharedX, sharedY)
}

func main() {
	//key generation
	curve := elliptic.P256()
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	check(err)

	xBytes := x.Bytes()
	yBytes := y.Bytes()
	publicKey := append(xBytes, yBytes...)

	//connect to cloud
	conn, err := net.Dial("tcp", "localhost:8080")
	check(err)

	//send cloud the public key
	conn.Write(publicKey)
	conn.Write([]byte("\n"))

	//receive cloud's public key
	cloudKey, err := bufio.NewReader(conn).ReadString('\n')
	check(err)

	//calculate shared key
	cloudKeyBytes := []byte(cloudKey)
	sharedKey := GenerateSharedSecret(privateKey, cloudKeyBytes[:len(cloudKey)-1], curve)

	//use first 32 bytes (x coordinate) of shared key as aes cipher block key
	cipher, err := aes.NewCipher(sharedKey[:32])
	check(err)

	//read message from console
	fmt.Print("Message to encrypt: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	msg := scanner.Bytes()

	//calculate and init padding
	length := len(msg)
	padding := 16 - (length % 16)
	zeros := make([]byte, padding)

	//add padding to msg buffer
	msg = append(msg, zeros...)
	encrypted := make([]byte, length+padding)

	//encrypt msg
	for i := 0; i < length+padding; i += 16 {
		cipher.Encrypt(encrypted[i:i+16], msg[i:i+16])
	}

	//send message length to cloud
	conn.Write([]byte(strconv.Itoa(length)))
	conn.Write([]byte("\n"))

	//throw away ack
	_, err = bufio.NewReader(conn).ReadString('\n')
	check(err)

	//send encrypted message to cloud
	conn.Write(encrypted)
	conn.Write([]byte("\n"))

}