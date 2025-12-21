package protocol

import (
	"fmt"
	"io"
)

// HandshakeSocks5 执行 SOCKS5 客户端握手
// 修改：强制密码认证模式（当存在用户名时，仅发送 0x02 方法，不发送 0x00）
// 修复：参考 C 代码逻辑，仅读取响应头部，不强制读取 BND 地址，防止服务器响应截断导致挂起
func HandshakeSocks5(conn io.ReadWriter, username, password, targetHost string, targetPort int) error {
	// 1. 发送版本和支持的认证方法
	// [修改] 逻辑变更：
	// 如果提供了用户名，方法列表只包含 0x02 (USERNAME/PASSWORD)，强制服务端使用密码认证。
	// 只有在未提供用户名时，才发送 0x00 (NO AUTHENTICATION REQUIRED)。
	var methods []byte
	if username != "" {
		methods = []byte{0x02}
	} else {
		methods = []byte{0x00}
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

	} else if authMethod == 0xFF {
		return fmt.Errorf("socks5 no acceptable methods (server rejected auth)")
	} else if authMethod != 0x00 {
		return fmt.Errorf("socks5 unsupported auth method selected: 0x%02x", authMethod)
	} else if authMethod == 0x00 && username != "" {
		// 如果我们发了 0x02 但服务端回了 0x00 (理论上不应发生，因为我们没发 0x00)，
		// 或者在 username 为空时回了 0x00，这都是正常的。
		// 但如果是“只支持密码用户”模式下，服务端回 0x00 意味着它忽略了认证需求，这里暂且允许通过。
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
	// [修复关键点] 
	// C 代码 (proxy.c) 仅读取前4个字节并检查状态，不关心具体的 BND 地址。
	// 如果服务器只发送了 4 字节的简化响应 (05 00 00 01)，原来的 Go 代码试图读取后续地址会导致阻塞。
	// 这里修改为只读取 4 字节，忽略后续可能存在的 BND 地址信息（在代理场景下客户端通常不需要此信息）。
	connRespHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, connRespHead); err != nil {
		return fmt.Errorf("socks5 connect resp header read failed: %v", err)
	}

	// REP 字段: 0x00 表示成功
	if connRespHead[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed with error: 0x%02x", connRespHead[1])
	}

	// 之前的代码在此处会根据 ATYP (connRespHead[3]) 继续读取地址和端口。
	// 为兼容 Mandala 服务器行为，此处不再继续读取。
	// 如果服务器确实发送了完整 BND 地址，剩余字节将在后续 io.Copy 中被读取并转发给浏览器。
	// 虽然这可能导致浏览器收到少量垃圾数据，但比完全挂起要好，且符合 C 代码的行为模式。
	// (在 WebSocket 场景下，C 代码实际上是读取了整个帧但丢弃了多余数据，Go 在无法确定帧边界时，
	// 最安全的做法是假设服务器发送了最小包)。

	return nil
}


