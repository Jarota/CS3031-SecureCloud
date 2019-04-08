package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
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

func transmissionError(conn net.Conn) {
	fmt.Println("Error in received bytes")
	//close the connection
	err := conn.Close()
	check(err)
	fmt.Println("Connection Closed")
}

func initKeysCSV() {
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

func addKeyToGroup(userKey []byte) bool {
	fmt.Println("Add new user to group?")
	//fmt.Println(string(userKey))
	fmt.Print("y/n:")

	//read message from console
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	ans := scanner.Text()
	if ans == "y" {
		return true
	}
	return false
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

	//receive encrypted message from user
	encryptedString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, err
	}

	//decrypt msg
	encrypted := []byte(encryptedString)
	length := len(encrypted) - 1

	if length%16 != 0 {
		return nil, errors.New("invalid message length")
	}

	msg := make([]byte, length)
	for i := 0; i < length; i += 16 {
		cipher.Decrypt(msg[i:i+16], encrypted[i:i+16])
	}
	return msg[:lengthNoPadding], nil
}

func handleConnection(conn net.Conn) {
	curve := elliptic.P256()

	//open keys file
	keysFile, err := os.OpenFile("keys.txt", os.O_RDWR|os.O_APPEND, 0666)
	check(err)

	//retrieve cloud's public and private keys
	privateKey := make([]byte, 32)
	_, err = keysFile.Read(privateKey)
	check(err)

	publicKey := make([]byte, 64)
	_, err = keysFile.ReadAt(publicKey, 32)
	check(err)

	//receive user's public key
	var userKey = make([]byte, 64)
	n, err := conn.Read(userKey)
	check(err)
	if n != 64 {
		transmissionError(conn)
		return
	}

	//check if user is whitelisted
	var sharedKey []byte
	var inGroup bool = false
	fi, err := keysFile.Stat()
	check(err)
	size := fi.Size()
	var i int64
	for i = 96; i < size; i += 128 {
		storedKey := make([]byte, 128)
		_, e := keysFile.ReadAt(storedKey, i)
		check(e)
		if string(userKey) == string(storedKey[:64]) {
			inGroup = true
			sharedKey = storedKey[64:]
			break
		}
	}
	//ecdhke
	if !inGroup {
		if addKeyToGroup(userKey) {
			//send the public key to user
			conn.Write(publicKey)
			//calculate shared key
			sharedKey = GenerateSharedSecret(privateKey, userKey, curve)

			//save public and shared key for future use
			_, e := keysFile.Write(userKey)
			check(e)
			_, err = keysFile.Write(sharedKey)
			check(err)
		} else {
			sharedKey = privateKey
		}
	}

	//use first 32 bytes (x coordinate) of shared key as aes cipher block key
	cipher, err := aes.NewCipher(sharedKey[:32])
	check(err)

	msg, err := receiveAndDecrypt(conn, cipher)
	if err != nil {
		if err.Error() == "invalid message length" {
			transmissionError(conn)
			return
		} else {
			check(err)
		}
	}

	fmt.Println("Message received:", string(msg))

	//close the connection
	err = conn.Close()
	check(err)
	fmt.Println("Connection Closed")
}

func main() {
	//check for keys file
	_, err := os.Open("keys.csv")
	if os.IsNotExist(err) {
		initKeysCSV()
	} else {
		check(err)
	}

	//listen for connections on localhost:8080
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
