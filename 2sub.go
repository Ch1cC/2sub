package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	url2 "net/url"
	"os"
	"strings"
)

type node struct {
	Protocol      string `json:"protocol"`
	V             string `json:"v"`
	Ps            string `json:"ps"`
	Add           string `json:"add"`
	Port          string `json:"port"`
	ID            string `json:"id"`
	Aid           string `json:"aid"`
	Scy           string `json:"scy"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	Sni           string `json:"sni"`
	Alpn          string `json:"alpn"`
	Udp           int    `json:"udp"`
	Mux           bool   `json:"mux"`
	AllowInsecure bool   `json:"allowInsecure"`
}

type user struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

var (
	vmessProtocol  = "vmess://"
	trojanProtocol = "trojan://"
	vlessProtocol  = "vless://"
	vmessPath      string
	userPath       string
)

func main() {
	flag.StringVar(&vmessPath, "config", "vmess模板.json", "节点模板json文件路径")
	flag.StringVar(&userPath, "user", "user模板.json", "user模板json文件路径")
	flag.Parse()
	/*vmessPath := ""
	if len(os.Args) < 2 {
		fmt.Println("请输入文件路径")
		fmt.Scanln(&path)
		vmessPath = path
	} else {
		vmessPath = os.Args[1]
		fmt.Println("读取路径:", vmessPath)
	}*/
	nodes := formatNodes()
	users := formatUser()
	os.RemoveAll("sub")
	os.Mkdir("sub", 0555)
	//循环vmess,user对象
	for _, user := range users {
		//字符串拼接
		urlBuilder := strings.Builder{}
		UUID := user.ID
		email := user.Email
		for _, node := range nodes {
			node.ID = UUID
			protocol := node.Protocol
			node.Alpn = "h2,http/1.1"
			//每个对象都进行base64转换
			switch protocol {
			case "trojan":
				base64Url := toTrojan(node)
				urlBuilder.WriteString(base64Url)
				urlBuilder.WriteString("\r")
			case "vmess":
				// fmt.Println(vmess)
				base64Url := toVmess(node)
				urlBuilder.WriteString(base64Url)
				urlBuilder.Cap()
				urlBuilder.WriteString("\r")
			case "vless":
				base64Url := toVless(node)
				urlBuilder.WriteString(base64Url)
				urlBuilder.WriteString("\r")
			}
		}
		builder := urlBuilder.String()
		//最后再base64一次符合小火箭订阅格式
		toString := base64.StdEncoding.EncodeToString([]byte(builder))
		os.WriteFile("sub/"+email, []byte(toString), 0555)
	}
	/*fmt.Println(toString)
	clipboard.WriteAll(toString)
	fmt.Println("已复制到剪切板")*/
	fmt.Printf("文件写入到sub文件夹共%d位用户\n", len(users))
	// fmt.Println("回车退出")
	// b := make([]byte, 1)
	// os.Stdin.Read(b)
}
func toTrojan(n node) (base64Url string) {
	url := trojanProtocol + n.ID + "@" + n.Add + ":" + n.Port + "?security=tls&alpn=h2%2Chttp%2F1.1&type=tcp&headerType=none#" + url2.QueryEscape(n.Ps)
	return url
}
func toVless(n node) (base64Url string) {
	url := vlessProtocol + n.ID + "@" + n.Add + ":" + n.Port + "?encryption=none&security=tls&alpn=h2%2Chttp%2F1.1&" + "type=" + n.Net
	if n.Net == "grpc" {
		url = url + "&mode=gun&serviceName=" + n.Path
	} else if n.Net == "tcp" {
		url = url + "&headerType=none"
	} else {
		if len(n.Path) > 0 {
			url = url + "&path=%2F" + n.Path
		}
	}
	url = url + "#" + url2.QueryEscape(n.Ps)
	return url
}

func toVmess(n node) (base64Url string) {
	if n.Net == "grpc" {
		n.Type = "gun"
	}
	json, _ := json.Marshal(n)
	vmess := string(json)
	return vmessProtocol + base64.StdEncoding.EncodeToString([]byte(vmess))
}

func formatNodes() []node {
	vmessArr := make([]node, 0)
	vmess, _ := readJSON(vmessPath)
	//获取json数组
	JSONArr := json.Unmarshal(vmess, &vmessArr)
	if JSONArr != nil {
		fmt.Println("节点模板.json is error")
		fmt.Println("回车退出")
		b := make([]byte, 1)
		os.Stdin.Read(b)
		panic(JSONArr)
	}
	return vmessArr
}

func formatUser() []user {
	//获取json数组
	userArr := make([]user, 0)
	user, _ := readJSON(userPath)
	JSONArr := json.Unmarshal(user, &userArr)
	if JSONArr != nil {
		fmt.Println("user模板.json is error")
		fmt.Println("回车退出")
		b := make([]byte, 1)
		os.Stdin.Read(b)
		panic(JSONArr)
	}
	return userArr
}
func readJSON(path string) ([]byte, error) {
	open, _ := os.Open(path)
	defer open.Close()
	return io.ReadAll(open)
}

//判断文件文件夹是否存在
func isFileExist(path string) (bool, error) {
	fileInfo, err := os.Stat(path)

	if os.IsNotExist(err) {
		return false, nil
	}
	//我这里判断了如果是0也算不存在
	if fileInfo.Size() == 0 {
		return false, nil
	}
	if err == nil {
		return true, nil
	}
	return false, err
}
