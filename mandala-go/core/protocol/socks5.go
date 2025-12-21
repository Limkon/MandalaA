package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

// HandshakeSocks5 执行 SOCKS5 客户端握手
func HandshakeSocks5(conn io.ReadWriter, username, password, targetHost string, targetPort int) error {
	log.Printf("[Socks5] Handshaking for %s:%d", targetHost, targetPort)

	// 1. 发送 Method
	var methods []byte
	if username != "" {
		methods = []byte{0x02}
	} else {
		methods = []byte{0x00}
	}
	
	initBuf := make([]byte, 2+len(methods))
	initBuf[0] = 0x05 
	initBuf[1] = byte(len(methods)) 
	copy(initBuf[2:], methods)
	
	if _, err := conn.Write(initBuf); err != nil {
		return fmt.Errorf("write init failed: %v", err)
	}

	// 2. 读取 Method Resp
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read init resp failed: %v", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("invalid version: %d", resp[0])
	}
	authMethod := resp[1]

	// 3. 认证
	if authMethod == 0x02 {
		uLen := len(username)
		pLen := len(password)
		authBuf := make([]byte, 3+uLen+pLen)
		authBuf[0] = 0x01 
		authBuf[1] = byte(uLen)
		copy(authBuf[2:], username)
		authBuf[2+uLen] = byte(pLen)
		copy(authBuf[3+uLen:], password)
		
		if _, err := conn.Write(authBuf); err != nil {
			return fmt.Errorf("write auth failed: %v", err)
		}
		
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("read auth resp failed: %v", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("auth failed status: 0x%02x", authResp[1])
		}
	} else if authMethod != 0x00 {
		return fmt.Errorf("unsupported method: 0x%02x", authMethod)
	}

	// 4. 发送 Connect Request (内联地址构造，确保无误)
	var buf bytes.Buffer
	buf.Write([]byte{0x05, 0x01, 0x00}) // VER, CMD=CONNECT, RSV

	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01) // IPv4
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x04) // IPv6
			buf.Write(ip.To16())
		}
	} else {
		if len(targetHost) > 255 {
			return errors.New("domain too long")
		}
		buf.WriteByte(0x03) // Domain
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write connect failed: %v", err)
	}

	// 5. 读取 Connect Resp (只读前 4 字节，防止卡死)
	// C 版本 proxy.c 也是只读了 4 字节
	connRespHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, connRespHead); err != nil {
		return fmt.Errorf("read connect resp failed: %v", err)
	}

	if connRespHead[1] != 0x00 {
		return fmt.Errorf("connect failed status: 0x%02x", connRespHead[1])
	}
	
	// 成功
	return nil
}
