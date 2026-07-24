package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

type multiProviderEmailSender struct {
	client *http.Client
}

func secureEmailHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 8 * time.Second
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.IdleConnTimeout = 30 * time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   12 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("email provider redirects are not allowed")
		},
	}
}

func (s *multiProviderEmailSender) Send(
	ctx context.Context,
	settings emailPublicConfig,
	secrets emailSecretEnvelope,
	message OutboundEmail,
) error {
	switch settings.Provider {
	case emailProviderSMTP:
		return sendSMTPEmail(ctx, settings, secrets, message)
	case emailProviderAWSSES:
		return s.sendAWSSESEmail(ctx, settings, secrets, message)
	case emailProviderAzureACS:
		return s.sendAzureACSEmail(ctx, settings, secrets, message)
	default:
		return fmt.Errorf("unsupported email provider %q", settings.Provider)
	}
}

func sendSMTPEmail(
	ctx context.Context,
	settings emailPublicConfig,
	secrets emailSecretEnvelope,
	message OutboundEmail,
) error {
	address := net.JoinHostPort(settings.SMTP.Host, fmt.Sprintf("%d", settings.SMTP.Port))
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: settings.SMTP.Host,
	}
	var conn net.Conn
	var err error
	if settings.SMTP.TLSMode == "TLS" {
		conn, err = (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", address)
	} else {
		conn, err = (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(15 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	session := newSMTPSession(conn, settings.SMTP.Host)
	if err := session.greeting(); err != nil {
		return err
	}
	capabilities, err := session.ehlo()
	if err != nil {
		return err
	}
	if settings.SMTP.TLSMode == "STARTTLS" {
		if !smtpCapability(capabilities, "STARTTLS") {
			return errors.New("SMTP server does not advertise STARTTLS")
		}
		if _, err := session.command([]int{220}, "STARTTLS"); err != nil {
			return fmt.Errorf("start SMTP TLS: %w", err)
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("negotiate SMTP TLS: %w", err)
		}
		session = newSMTPSession(tlsConn, settings.SMTP.Host)
		capabilities, err = session.ehlo()
		if err != nil {
			return err
		}
	}
	if settings.SMTP.Username != "" {
		if !smtpCapability(capabilities, "AUTH") {
			return errors.New("SMTP server does not advertise authentication")
		}
		plain := base64.StdEncoding.EncodeToString([]byte("\x00" + settings.SMTP.Username + "\x00" + secrets.SMTPPassword))
		if _, err := session.command([]int{235}, "AUTH PLAIN %s", plain); err != nil {
			return fmt.Errorf("authenticate with SMTP server: %w", err)
		}
	}
	from, _ := mail.ParseAddress(settings.FromAddress)
	to, _ := mail.ParseAddress(message.ToEmail)
	if _, err := session.command([]int{250}, "MAIL FROM:<%s>", from.Address); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}
	if _, err := session.command([]int{250, 251}, "RCPT TO:<%s>", to.Address); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}
	if _, err := session.command([]int{354}, "DATA"); err != nil {
		return fmt.Errorf("start SMTP message: %w", err)
	}
	payload, err := buildMIMEMessage(settings, message)
	if err != nil {
		return err
	}
	w := session.conn.DotWriter()
	_, err = w.Write(payload)
	closeErr := w.Close()
	if err != nil {
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("finish SMTP message: %w", closeErr)
	}
	if _, _, err := session.conn.ReadResponse(250); err != nil {
		return fmt.Errorf("accept SMTP message: %w", err)
	}
	if _, err := session.command([]int{221}, "QUIT"); err != nil {
		return fmt.Errorf("complete SMTP session: %w", err)
	}
	return nil
}

type smtpSession struct {
	conn       *textproto.Conn
	serverName string
}

func newSMTPSession(conn net.Conn, serverName string) *smtpSession {
	return &smtpSession{conn: textproto.NewConn(conn), serverName: serverName}
}

func (s *smtpSession) greeting() error {
	if _, _, err := s.conn.ReadResponse(220); err != nil {
		return fmt.Errorf("read SMTP greeting: %w", err)
	}
	return nil
}

func (s *smtpSession) ehlo() (string, error) {
	message, err := s.command([]int{250}, "EHLO o11y-control-plane")
	if err != nil {
		return "", fmt.Errorf("SMTP EHLO failed: %w", err)
	}
	return message, nil
}

func (s *smtpSession) command(expected []int, format string, args ...any) (string, error) {
	id, err := s.conn.Cmd(format, args...)
	if err != nil {
		return "", err
	}
	s.conn.StartResponse(id)
	defer s.conn.EndResponse(id)
	code, message, err := s.conn.ReadResponse(expected[0])
	if err == nil {
		return message, nil
	}
	for _, allowed := range expected[1:] {
		if code == allowed {
			return message, nil
		}
	}
	return "", err
}

func smtpCapability(capabilities string, name string) bool {
	name = strings.ToUpper(name)
	for _, line := range strings.Split(capabilities, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		field := strings.ToUpper(strings.TrimSpace(fields[0]))
		if field == name {
			return true
		}
	}
	return false
}

func buildMIMEMessage(settings emailPublicConfig, message OutboundEmail) ([]byte, error) {
	from := mail.Address{Name: sanitizeHeader(settings.FromName), Address: settings.FromAddress}
	to, err := mail.ParseAddress(message.ToEmail)
	if err != nil {
		return nil, err
	}
	boundaryBuffer := &bytes.Buffer{}
	multipartWriter := multipart.NewWriter(boundaryBuffer)
	if err := writeMIMEPart(multipartWriter, "text/plain; charset=UTF-8", message.Text); err != nil {
		return nil, err
	}
	if message.HTML != "" {
		if err := writeMIMEPart(multipartWriter, "text/html; charset=UTF-8", message.HTML); err != nil {
			return nil, err
		}
	}
	if err := multipartWriter.Close(); err != nil {
		return nil, err
	}
	headers := &bytes.Buffer{}
	fmt.Fprintf(headers, "From: %s\r\n", from.String())
	fmt.Fprintf(headers, "To: %s\r\n", to.String())
	fmt.Fprintf(headers, "Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", sanitizeHeader(message.Subject)))
	fmt.Fprint(headers, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(headers, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", multipartWriter.Boundary())
	headers.Write(boundaryBuffer.Bytes())
	return headers.Bytes(), nil
}

func writeMIMEPart(writer *multipart.Writer, contentType string, body string) error {
	header := make(textproto.MIMEHeader)
	header["Content-Type"] = []string{contentType}
	header["Content-Transfer-Encoding"] = []string{"quoted-printable"}
	part, err := writer.CreatePart(header)
	if err != nil {
		return err
	}
	encoded := quotedprintable.NewWriter(part)
	if _, err := encoded.Write([]byte(body)); err != nil {
		return err
	}
	return encoded.Close()
}

func sanitizeHeader(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(value))
}

func (s *multiProviderEmailSender) sendAWSSESEmail(
	ctx context.Context,
	settings emailPublicConfig,
	secrets emailSecretEnvelope,
	message OutboundEmail,
) error {
	endpoint := settings.AWSSES.Endpoint
	if endpoint == "" {
		endpoint = "https://email." + settings.AWSSES.Region + ".amazonaws.com"
	}
	requestURL, err := appendURLPath(endpoint, "/v2/email/outbound-emails")
	if err != nil {
		return err
	}
	fromAddress := (&mail.Address{Name: settings.FromName, Address: settings.FromAddress}).String()
	body := map[string]any{
		"FromEmailAddress": fromAddress,
		"Destination":      map[string]any{"ToAddresses": []string{message.ToEmail}},
		"Content": map[string]any{"Simple": map[string]any{
			"Subject": map[string]string{"Data": message.Subject, "Charset": "UTF-8"},
			"Body": map[string]any{
				"Text": map[string]string{"Data": message.Text, "Charset": "UTF-8"},
				"Html": map[string]string{"Data": message.HTML, "Charset": "UTF-8"},
			},
		}},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode AWS SES request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create AWS SES request: %w", err)
	}
	now := time.Now().UTC()
	req.Header.Set("Content-Type", "application/json")
	signAWSSigV4(req, payload, settings.AWSSES.Region, settings.AWSSES.AccessKeyID,
		secrets.AWSSecretAccessKey, secrets.AWSSessionToken, now)
	_, err = executeEmailRequest(s.client, req, "AWS SES", http.StatusOK)
	return err
}

func signAWSSigV4(
	req *http.Request,
	payload []byte,
	region string,
	accessKeyID string,
	secretAccessKey string,
	sessionToken string,
	now time.Time,
) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256Hex(payload)
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	headers := map[string]string{
		"content-type": "application/json",
		"host":         req.URL.Host,
		"x-amz-date":   amzDate,
	}
	if sessionToken != "" {
		headers["x-amz-security-token"] = sessionToken
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(headers[name]))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		awsCanonicalURI(req.URL.EscapedPath()),
		req.URL.Query().Encode(),
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	scope := dateStamp + "/" + region + "/ses/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	dateKey := hmacSHA256([]byte("AWS4"+secretAccessKey), dateStamp)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, "ses")
	signingKey := hmacSHA256(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKeyID+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func awsCanonicalURI(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}
	return escapedPath
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sha256Hex(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func (s *multiProviderEmailSender) sendAzureACSEmail(
	ctx context.Context,
	settings emailPublicConfig,
	secrets emailSecretEnvelope,
	message OutboundEmail,
) error {
	requestURL, err := appendURLPath(settings.AzureACS.Endpoint, "/emails:send")
	if err != nil {
		return err
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return fmt.Errorf("parse Azure ACS endpoint: %w", err)
	}
	query := parsed.Query()
	query.Set("api-version", settings.AzureACS.APIVersion)
	parsed.RawQuery = query.Encode()
	body := map[string]any{
		"senderAddress": settings.FromAddress,
		"recipients": map[string]any{
			"to": []map[string]string{{"address": message.ToEmail}},
		},
		"content": map[string]string{
			"subject":   message.Subject,
			"plainText": message.Text,
			"html":      message.HTML,
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode Azure ACS request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create Azure ACS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := signAzureACSRequest(req, payload, secrets.AzureAccessKey, time.Now().UTC()); err != nil {
		return err
	}
	headers, err := executeEmailRequest(s.client, req, "Azure ACS", http.StatusAccepted)
	if err != nil {
		return err
	}
	if strings.TrimSpace(headers.Get("Operation-Location")) == "" {
		return errors.New("Azure ACS accepted the request without Operation-Location")
	}
	return nil
}

func signAzureACSRequest(req *http.Request, payload []byte, encodedAccessKey string, now time.Time) error {
	accessKey, err := base64.StdEncoding.DecodeString(encodedAccessKey)
	if err != nil {
		return errors.New("azureAcs.accessKey must be base64 encoded")
	}
	digest := sha256.Sum256(payload)
	contentHash := base64.StdEncoding.EncodeToString(digest[:])
	date := now.Format(http.TimeFormat)
	req.Header.Set("x-ms-date", date)
	req.Header.Set("x-ms-content-sha256", contentHash)
	pathAndQuery := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		pathAndQuery += "?" + req.URL.RawQuery
	}
	stringToSign := req.Method + "\n" + pathAndQuery + "\n" +
		"x-ms-date:" + date + ";host:" + req.URL.Host + ";x-ms-content-sha256:" + contentHash
	signature := base64.StdEncoding.EncodeToString(hmacSHA256(accessKey, stringToSign))
	req.Header.Set("Authorization", "HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+signature)
	return nil
}

func appendURLPath(base string, suffix string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse email provider endpoint: %w", err)
	}
	parsed.Path = path.Join(parsed.Path, suffix)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func executeEmailRequest(
	client *http.Client,
	req *http.Request,
	provider string,
	expectedStatus int,
) (http.Header, error) {
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request failed: %w", provider, err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("%s returned HTTP %d: %s", provider, response.StatusCode, sanitizeProviderError(body))
	}
	return response.Header.Clone(), nil
}

func sanitizeProviderError(body []byte) string {
	value := strings.TrimSpace(string(body))
	if len(value) > 512 {
		value = value[:512]
	}
	value = strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
	if value == "" {
		return "request rejected"
	}
	return value
}
