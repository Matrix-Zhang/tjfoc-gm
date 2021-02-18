package gmcredentials

import (
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Hyperledger-TWGC/tjfoc-gm/gmtls"
	"github.com/Hyperledger-TWGC/tjfoc-gm/gmtls/gmcredentials/echo"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"google.golang.org/grpc"
)

const caNoGM = "testdata_nogm/ca.cert"
const serverCert = "testdata_nogm/server.cert"
const serverKey = "testdata_nogm/server.key"
const clientCert = "testdata_nogm/client.cert"
const clientKey = "testdata_nogm/client.key"

const (
	portNoGM    = ":50052"
	addressNoGM = "localhost:50052"
)

func serverRunNoGM() {
	signCert, err := gmtls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Fatal(err)
	}

	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(caNoGM)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	lis, err := net.Listen("tcp", portNoGM)
	if err != nil {
		log.Fatalf("fail to listen: %v", err)
	}
	creds := NewTLS(&gmtls.Config{
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
		Certificates: []gmtls.Certificate{signCert},
		ClientCAs:    certPool,
	})
	s := grpc.NewServer(grpc.Creds(creds))
	echo.RegisterEchoServer(s, &server{})
	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("Serve: %v", err)
	}
}

func clientRunNoGM() {
	cert, err := gmtls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(caNoGM)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	creds := NewTLS(&gmtls.Config{
		ServerName:   "peer0.org1.example.com",
		Certificates: []gmtls.Certificate{cert},
		RootCAs:      certPool,
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
	})
	conn, err := grpc.Dial(addressNoGM, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("cannot to connect: %v", err)
	}
	defer conn.Close()
	c := echo.NewEchoClient(conn)
	echoTest(c)
	end <- true
}

func TestNoGM(t *testing.T) {
	end = make(chan bool, 64)
	go serverRunNoGM()
	time.Sleep(1000000)
	go clientRunNoGM()
	<-end
}
