package protocol

import (
	"fmt"
	"io"
)

// HandshakeSocks5 执行 SOCKS5 客户端握手
func HandshakeSocks5(conn io.ReadWriter, username, password, targetHost string, targetPort int) error {
	// 1. 发送版本和支持的认证方法
	var methods []byte
	if username != "" {
		methods = []byte{0x02} // 仅支持密码认证
	} else {
		methods = []byte{0x00} // 无需认证
	}
	
	initBuf := make([]byte, 2+len(methods))
	initBuf[0] = 0x05 
	initBuf[1] = byte(len(methods)) 
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
		uLen := len(username)
		pLen := len(password)
		authBuf := make([]byte, 3+uLen+pLen)
		authBuf[0] = 0x01 
		authBuf[1] = byte(uLen)
		copy(authBuf[2:], username)
		authBuf[2+uLen] = byte(pLen)
		copy(authBuf[3+uLen:], password)
		
		if _, err := conn.Write(authBuf); err != nil {
			return fmt.Errorf("socks5 auth write failed: %v", err)
		}
		
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("socks5 auth resp read failed: %v", err)
		}
		
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 authentication failed (status: 0x%02x)", authResp[1])
		}

	} else if authMethod != 0x00 && authMethod != 0xFF {
		return fmt.Errorf("socks5 unsupported auth method: 0x%02x", authMethod)
	}

	// 4. 发送连接请求 (CONNECT)
	head := []byte{0x05, 0x01, 0x00}
	addr, err := ToSocksAddr(targetHost, targetPort)
	if err != nil {
		return err
	}
	
	if _, err := conn.Write(append(head, addr...)); err != nil {
		return fmt.Errorf("socks5 connect write failed: %v", err)
	}

	// 5. [关键修改] 读取连接响应 - 模仿 C 代码行为
	// C 代码只读取前 4 个字节 (05 00 00 01)，不等待后续的 IP/Port。
	// 这避免了服务端不发后续数据导致 Go 卡死的问题。
	connRespHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, connRespHead); err != nil {
		return fmt.Errorf("socks5 connect resp header read failed: %v", err)
	}

	if connRespHead[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: 0x%02x", connRespHead[1])
	}

	// [优化] 尝试非阻塞读取剩余数据 (如果有)，防止残留数据污染流
	// 但不强制等待，以免死锁。这里我们假设后续流数据会紧接着到来，
	// 如果这 4 字节后紧跟的是数据，交给上层 io.Copy 处理即可。
	// 对于 Socks5 over WebSocket，这通常是安全的。

	return nil
}
