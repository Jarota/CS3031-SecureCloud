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

func encryptAndSend(conn net.Conn, msg []byte, cipher cipher.Block) {
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
	_, err := conn.Read(make([]byte, 8))
	check(err)

	//send encrypted message to cloud
	conn.Write(encrypted)
	conn.Write([]byte("\n"))
}

func handleConnection(conn net.Conn) {
	curve := elliptic.P256()

	//open keys file
	keysFile, err := os.OpenFile("keys.txt", os.O_RDWR|os.O_APPEND, 0777)
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
			//fmt.Println("Adding new user!")

			//calculate shared key
			sharedKey = GenerateSharedSecret(privateKey, userKey, curve)

			//save public and shared key for future use
			_, e := keysFile.Write(userKey)
			check(e)
			_, err = keysFile.Write(sharedKey)
			check(err)
		} else {
			//encrypt using private key
			sharedKey = privateKey
		}
	}

	//send the public key to user
	n, e := conn.Write(publicKey)
	check(e)
	if n != 64 {
		transmissionError(conn)
		return
	}
	//throw away ack
	_, err = conn.Read(make([]byte, 8))
	check(err)

	//use first 32 bytes (x coordinate) of shared key as aes cipher block key
	cipher, err := aes.NewCipher(sharedKey[:32])
	check(err)

	//read file bytes
	msg, err := ioutil.ReadFile("image.jpg")
	check(err)

	//send file to user
	encryptAndSend(conn, msg, cipher)
	fmt.Println("File Sent")

	//close the connection
	err = conn.Close()
	check(err)
	fmt.Println("Connection Closed")
}

func main() {
	//check for keys file
	_, err := os.Open("keys.txt")
	if os.IsNotExist(err) {
		initKeysFile()
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
