package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
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

func transmissionError(conn net.Conn) {
	fmt.Println("Error in received bytes")
	//close the connection
	err := conn.Close()
	check(err)
	fmt.Println("Connection Closed")
}

func initKeysFile() {
	fmt.Println("Initializing keys.txt")
	//make the file
	keys, err := os.Create("keys.txt")
	check(err)
	defer keys.Close()

	//key generation
	curve := elliptic.P256()
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	check(err)

	xBytes := x.Bytes()
	yBytes := y.Bytes()
	publicKey := append(xBytes, yBytes...)

	//write private and public keys to file
	n, err := keys.Write(privateKey)
	if n != 32 {
		panic(errors.New("Error writing private key"))
	}
	check(err)
	n, err = keys.Write(publicKey)
	if n != 64 {
		panic(errors.New("Error writing public key"))
	}
	check(err)
}

func GenerateSharedSecret(privateKey []byte, publicKey []byte, curve elliptic.Curve) []byte {
	publicX := new(big.Int).SetBytes(publicKey[:32])
	publicY := new(big.Int).SetBytes(publicKey[32:])
	sharedX, sharedY := curve.ScalarMult(publicX, publicY, privateKey)
	return elliptic.Marshal(curve, sharedX, sharedY)
}

func receiveAndDecrypt(conn net.Conn, cipher cipher.Block) ([]byte, error) {
	//receive message length from user
	lengthString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, err
	}
	lengthNoPadding, err := strconv.Atoi(lengthString[:len(lengthString)-1])
	if err != nil {
		return nil, err
	}

	//send ack
	conn.Write([]byte("ack"))

	padding := 16 - (lengthNoPadding % 16)
	length := lengthNoPadding + padding
	//receive encrypted message from user
	encrypted := make([]byte, length)
	n, err := conn.Read(encrypted)
	check(err)
	if n != length {
		return nil, errors.New("invalid message length")
	}

	msg := make([]byte, length)
	for i := 0; i < length; i += 16 {
		cipher.Decrypt(msg[i:i+16], encrypted[i:i+16])
	}
	return msg[:lengthNoPadding], nil
}

func main() {
	//check for keys file
	_, err := os.Open("keys.txt")
	if os.IsNotExist(err) {
		initKeysFile()
	} else {
		check(err)
	}

	//open keys file
	keysFile, err := os.OpenFile("keys.txt", os.O_RDWR|os.O_APPEND, 0777)
	check(err)
	defer keysFile.Close()

	//retrieve user's public and private keys
	privateKey := make([]byte, 32)
	_, err = keysFile.Read(privateKey)
	check(err)

	publicKey := make([]byte, 64)
	_, err = keysFile.ReadAt(publicKey, 32)
	check(err)

	//connect to cloud
	conn, err := net.Dial("tcp", "localhost:8080")
	check(err)

	//send cloud the public key
	conn.Write(publicKey)

	//receive cloud's public key
	cloudKey := make([]byte, 64)
	n, err := conn.Read(cloudKey)
	check(err)
	if n != 64 {
		fmt.Println("138")
		transmissionError(conn)
		return
	}

	//ack cloud's public key
	conn.Write([]byte("ack"))

	//calculate shared key
	sharedKey := GenerateSharedSecret(privateKey, cloudKey, elliptic.P256())

	//use first 32 bytes (x coordinate) of shared key as aes cipher block key
	cipher, err := aes.NewCipher(sharedKey[:32])
	check(err)

	msg, err := receiveAndDecrypt(conn, cipher)
	if err != nil {
		if err.Error() == "invalid message length" {
			fmt.Println("153")
			transmissionError(conn)
			return
		} else {
			check(err)
		}
	}

	//dump received bytes into image
	err = ioutil.WriteFile("image.jpg", msg, 0777)

	//close the connection
	err = conn.Close()
	check(err)
	fmt.Println("Connection Closed")
}
