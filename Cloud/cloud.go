package main

import (
	"bufio"
	"crypto/aes"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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

func handleConnection(conn net.Conn) {
	//key generation
	curve := elliptic.P256()
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	check(err)

	xBytes := x.Bytes()
	yBytes := y.Bytes()
	publicKey := append(xBytes, yBytes...)

	//receive user's public key
	var userKey = make([]byte, 64)
	n, err := conn.Read(userKey)
	check(err)
	if n != 64 {
		fmt.Println(n)
		panic(errors.New("User's public key not properly received."))
	}

	//send the public key to user
	conn.Write(publicKey)

	//calculate shared key
	sharedKey := GenerateSharedSecret(privateKey, userKey, curve)

	//use first 32 bytes (x coordinate) of shared key as aes cipher block key
	cipher, err := aes.NewCipher(sharedKey[:32])
	check(err)

	//receive message length from user
	lengthString, err := bufio.NewReader(conn).ReadString('\n')
	check(err)
	lengthNoPadding, err := strconv.Atoi(lengthString[:len(lengthString)-1])
	check(err)

	//send ack
	conn.Write([]byte("ack"))

	//receive encrypted message from user
	encryptedString, err := bufio.NewReader(conn).ReadString('\n')
	check(err)

	//decrypt msg
	encrypted := []byte(encryptedString)
	length := len(encrypted) - 1
	msg := make([]byte, length)
	for i := 0; i < length; i += 16 {
		cipher.Decrypt(msg[i:i+16], encrypted[i:i+16])
	}

	fmt.Println("Message received:", string(msg[:lengthNoPadding]))

	//close the connection
	err = conn.Close()
	check(err)
	fmt.Println("Connection Closed")
}

func main() {
	userKeys, err := os.Open("keys.csv")
	if os.IsNotExist(err) {
		userKeys, err = os.Create("keys.csv")
		check(err)
	} else {
		check(err)
	}
	info, err := userKeys.Stat()
	check(err)
	data := make([]byte, info.Size())
	userKeys.Read(data)
	fmt.Println(string(data))

	ln, err := net.Listen("tcp", ":8080")
	check(err)
	fmt.Println("Cloud Activated")
	for {
		conn, err := ln.Accept()
		check(err)
		fmt.Println("Connection Accepted...")
		go handleConnection(conn)
	}
}
