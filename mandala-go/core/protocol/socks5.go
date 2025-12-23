package protocol

import (
	"fmt"
	"io"
	"log"
)

// HandshakeSocks5 执行 SOCKS5 客户端握手
// 修改：强制密码认证模式（当存在用户名时，仅发送 0x02 方法，不发送 0x00）
// [新增] 详细的流程日志记录
func HandshakeSocks5(conn io.ReadWriter, username, password, targetHost string, targetPort int) error {
	log.Printf("[Socks5] 开始握手: 目标=%s:%d, 用户名=%s", targetHost, targetPort, username)

	// 1. 发送版本和支持的认证方法
	var methods []byte
	if username != "" {
		methods = []byte{0x02} // USERNAME/PASSWORD
	} else {
		methods = []byte{0x00} // NO AUTHENTICATION REQUIRED
	}
	
	log.Printf("[Socks5] 发送初始化包 (Methods: %v)", methods)
	
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
	log.Printf("[Socks5] 服务端选定认证方法: 0x%02x", authMethod)

	// 3. 根据选定的方法进行认证
	if authMethod == 0x02 {
		log.Printf("[Socks5] 执行用户名密码认证 (RFC 1929)...")
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
			log.Printf("[Socks5] 认证失败，状态码: 0x%02x", authResp[1])
			return fmt.Errorf("socks5 authentication failed (status: 0x%02x)", authResp[1])
		}
		log.Printf("[Socks5] 认证成功")

	} else if authMethod == 0xFF {
		log.Printf("[Socks5] 服务端拒绝了所有认证方法")
		return fmt.Errorf("socks5 no acceptable methods (server rejected auth)")
	} else if authMethod != 0x00 {
		log.Printf("[Socks5] 不支持的认证方法: 0x%02x", authMethod)
		return fmt.Errorf("socks5 unsupported auth method selected: 0x%02x", authMethod)
	}

	// 4. 发送连接请求 (CONNECT CMD=0x01)
	log.Printf("[Socks5] 发送连接请求 (CMD=0x01) 到目标地址")
	head := []byte{0x05, 0x01, 0x00}
	addr, err := ToSocksAddr(targetHost, targetPort) 
	if err != nil {
		return err
	}
	
	if _, err := conn.Write(append(head, addr...)); err != nil {
		return fmt.Errorf("socks5 connect write failed: %v", err)
	}

	// 5. 读取连接响应
	connRespHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, connRespHead); err != nil {
		return fmt.Errorf("socks5 connect resp header read failed: %v", err)
	}

	// REP 字段: 0x00 表示成功
	if connRespHead[1] != 0x00 {
		log.Printf("[Socks5] 连接目标失败，错误码: 0x%02x", connRespHead[1])
		return fmt.Errorf("socks5 connect failed with error: 0x%02x", connRespHead[1])
	}

	// 读取剩余的 BND.ADDR 和 BND.PORT
	var left int
	switch connRespHead[3] {
	case 0x01: left = 4 + 2 // IPv4
	case 0x04: left = 16 + 2 // IPv6
	case 0x03: // Domain
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("socks5 read domain len failed: %v", err)
		}
		left = int(lenByte[0]) + 2
	default:
		return fmt.Errorf("socks5 invalid address type in response: 0x%02x", connRespHead[3])
	}

	discard := make([]byte, left)
	if _, err := io.ReadFull(conn, discard); err != nil {
		return fmt.Errorf("socks5 connect resp body read failed: %v", err)
	}

	log.Printf("[Socks5] 连接建立完成")
	return nil
}
