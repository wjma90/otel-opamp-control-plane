//go:build integration

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAWSSESSenderSignsMockRequest(t *testing.T) {
	var received *http.Request
	var payload string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Clone(context.Background())
		body, _ := io.ReadAll(r.Body)
		payload = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sender := &multiProviderEmailSender{client: server.Client()}
	settings := emailPublicConfig{
		Provider: emailProviderAWSSES, FromName: "O11y", FromAddress: "no-reply@example.test",
		AWSSES: AWSSESEmailConfig{Region: "us-east-1", AccessKeyID: "AKIATEST", Endpoint: server.URL},
	}
	secrets := emailSecretEnvelope{AWSSecretAccessKey: "secret-value", AWSSessionToken: "session-token"}
	err := sender.Send(context.Background(), settings, secrets, OutboundEmail{
		ToEmail: "ana@example.test", Subject: "Test", Text: "text", HTML: "<p>text</p>",
	})
	if err != nil {
		t.Fatal(err)
	}
	if received.URL.Path != "/v2/email/outbound-emails" ||
		!strings.HasPrefix(received.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIATEST/") ||
		received.Header.Get("X-Amz-Security-Token") != "session-token" {
		t.Fatalf("AWS request was not signed correctly: %#v", received.Header)
	}
	if !strings.Contains(payload, "ana@example.test") || strings.Contains(payload, "secret-value") {
		t.Fatalf("unexpected SES payload: %s", payload)
	}
}

func TestAzureACSSenderSignsMockRequest(t *testing.T) {
	var received *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Clone(context.Background())
		w.Header().Set("Operation-Location", serverURLForTest(r)+"/operations/1")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sender := &multiProviderEmailSender{client: server.Client()}
	settings := emailPublicConfig{
		Provider: emailProviderAzureACS, FromAddress: "DoNotReply@example.test",
		AzureACS: AzureACSEmailConfig{Endpoint: server.URL, APIVersion: "2025-09-01"},
	}
	accessKey := base64.StdEncoding.EncodeToString([]byte("azure-test-key"))
	err := sender.Send(context.Background(), settings, emailSecretEnvelope{AzureAccessKey: accessKey}, OutboundEmail{
		ToEmail: "ana@example.test", Subject: "Test", Text: "text", HTML: "<p>text</p>",
	})
	if err != nil {
		t.Fatal(err)
	}
	if received.URL.Path != "/emails:send" || received.URL.Query().Get("api-version") != "2025-09-01" ||
		!strings.HasPrefix(received.Header.Get("Authorization"), "HMAC-SHA256 SignedHeaders=") ||
		received.Header.Get("x-ms-content-sha256") == "" || received.Header.Get("x-ms-date") == "" {
		t.Fatalf("Azure request was not signed correctly: %#v %s", received.Header, received.URL)
	}
}

func TestSMTPSenderDeliversMIMEMessageToLoopbackRelay(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	delivered := make(chan string, 1)
	go serveTestSMTP(listener, delivered)
	port := listener.Addr().(*net.TCPAddr).Port
	settings := emailPublicConfig{
		Provider: emailProviderSMTP, FromName: "O11y", FromAddress: "no-reply@example.test",
		SMTP: SMTPEmailConfig{
			Host: "127.0.0.1", Port: port, Username: "test-user", TLSMode: "NONE",
		},
	}
	err = sendSMTPEmail(context.Background(), settings,
		emailSecretEnvelope{SMTPPassword: "test-password"}, OutboundEmail{
			ToEmail: "ana@example.test", Subject: "Prueba O11y", Text: "mensaje de prueba",
		})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-delivered:
		if !strings.Contains(message, "Subject:") || !strings.Contains(message, "multipart/alternative") {
			t.Fatalf("unexpected MIME message: %s", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP relay did not receive the message")
	}
}

func serveTestSMTP(listener net.Listener, delivered chan<- string) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	write := func(value string) {
		_, _ = writer.WriteString(value)
		_ = writer.Flush()
	}
	write("220 smtp.test ESMTP\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(command, "EHLO "):
			write("250-smtp.test\r\n250 AUTH PLAIN\r\n")
		case strings.HasPrefix(command, "AUTH PLAIN "):
			write("235 2.7.0 authenticated\r\n")
		case strings.HasPrefix(command, "MAIL FROM:"):
			write("250 2.1.0 sender accepted\r\n")
		case strings.HasPrefix(command, "RCPT TO:"):
			write("250 2.1.5 recipient accepted\r\n")
		case command == "DATA":
			write("354 end with dot\r\n")
			var message strings.Builder
			for {
				dataLine, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				if dataLine == ".\r\n" {
					break
				}
				message.WriteString(dataLine)
			}
			delivered <- message.String()
			write("250 2.0.0 queued\r\n")
		case command == "QUIT":
			write("221 2.0.0 bye\r\n")
			return
		default:
			write("500 unsupported\r\n")
		}
	}
}

func serverURLForTest(r *http.Request) string {
	return "http://" + r.Host
}
