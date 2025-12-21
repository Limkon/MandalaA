package protocol

import (
	"fmt"
	"io"
)

// HandshakeSocks5 执行 SOCKS5 客户端握手
// 支持 No Auth (0x00) 和 Username/Password Auth (0x02)
// 文档: RFC 1928, RFC 1929
func HandshakeSocks5(conn io.ReadWriter, username, password, targetHost string, targetPort int) error {
	// 1. 发送版本和支持的认证方法
	// 构造方法列表: 总是支持 0x00 (No Auth)
	// 如果提供了用户名，额外支持 0x02 (User/Pass)
	methods := []byte{0x00}
	if username != "" {
		methods = append(methods, 0x02)
	}
	
	initBuf := make([]byte, 2+len(methods))
	initBuf[0] = 0x05 // Ver
	initBuf[1] = byte(len(methods)) // NMethods
	copy(initBuf[2:], methods)
	
	if _, err := conn.Write(initBuf); err != nil {
		return fmt.Errorf("socks5 init write failed: %v", err)
	}

	// 2. 读取服务端选定的方法
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 init read failed: %v", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5 invalid version: %d", resp[0])
	}

	authMethod := resp[1]

	// 3. 根据选定的方法进行认证
	if authMethod == 0x02 {
		// Username/Password 认证 (RFC 1929)
		uLen := len(username)
		pLen := len(password)
		if uLen > 255 || pLen > 255 {
			return fmt.Errorf("socks5 username/password too long")
		}
		
		// 构造认证包: [Ver(0x01)] [ULen] [User...] [PLen] [Pass...]
		authBuf := make([]byte, 3+uLen+pLen)
		authBuf[0] = 0x01 // Auth Version (必须是 0x01)
		authBuf[1] = byte(uLen)
		copy(authBuf[2:], username)
		authBuf[2+uLen] = byte(pLen)
		copy(authBuf[3+uLen:], password)
		
		if _, err := conn.Write(authBuf); err != nil {
			return fmt.Errorf("socks5 auth write failed: %v", err)
		}
		
		// 读取认证响应: [Ver(0x01)] [Status]
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("socks5 auth resp read failed: %v", err)
		}
		
		// Status 0x00 表示成功
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 authentication failed (status: 0x%02x)", authResp[1])
		}

	} else if authMethod != 0x00 {
		return fmt.Errorf("socks5 unsupported auth method selected: 0x%02x", authMethod)
	}

	// 4. 发送连接请求 (CONNECT CMD=0x01)
	// 格式: 05 01 00 [ATYP] [ADDR] [PORT]
	head := []byte{0x05, 0x01, 0x00}
	addr, err := ToSocksAddr(targetHost, targetPort) // 使用 utils.go 中的通用函数
	if err != nil {
		return err
	}
	
	if _, err := conn.Write(append(head, addr...)); err != nil {
		return fmt.Errorf("socks5 connect write failed: %v", err)
	}

	// 5. 读取连接响应
	// 响应格式: 05 00 00 [ATYP] [ADDR] [PORT]
	// 我们至少需要读取前 4 个字节来判断状态和地址类型
	connRespHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, connRespHead); err != nil {
		return fmt.Errorf("socks5 connect resp header read failed: %v", err)
	}

	// REP 字段: 0x00 表示成功
	if connRespHead[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed with error: 0x%02x", connRespHead[1])
	}

	// 读取剩余的 BND.ADDR 和 BND.PORT (消耗掉缓冲区，以便后续数据透传)
	var left int
	switch connRespHead[3] {
	case 0x01: left = 4 + 2 // IPv4(4) + Port(2)
	case 0x04: left = 16 + 2 // IPv6(16) + Port(2)
	case 0x03: // Domain
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("socks5 read domain len failed: %v", err)
		}
		left = int(lenByte[0]) + 2 // DomainBody + Port
	default:
		return fmt.Errorf("socks5 invalid address type in response: 0x%02x", connRespHead[3])
	}

	discard := make([]byte, left)
	if _, err := io.ReadFull(conn, discard); err != nil {
		return fmt.Errorf("socks5 connect resp body read failed: %v", err)
	}

	return nil
}
