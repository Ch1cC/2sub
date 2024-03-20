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

	"github.com/DisposaBoy/JsonConfigReader"
)

type node struct {
	Hiden         bool   `json:"hiden"`
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
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Protocol []string `json:"protocol"`
}

var (
	vmessProtocol     = "vmess://"
	trojanProtocol    = "trojan://"
	vlessProtocol     = "vless://"
	hysteria2Protocol = "hysteria2://"
	nodePath          string
	userPath          string
)

func main() {
	flag.StringVar(&nodePath, "config", "node模板.json", "node模板json文件路径")
	flag.StringVar(&userPath, "user", "user模板.json", "user模板json文件路径")
	flag.Parse()
	/*nodePath := ""
	if len(os.Args) < 2 {
		fmt.Println("请输入文件路径")
		fmt.Scanln(&path)
		nodePath = path
	} else {
		nodePath = os.Args[1]
		fmt.Println("读取路径:", nodePath)
	}*/
	//判断文件夹是否存在
	if fileInfo, _ := os.Stat("sub"); fileInfo != nil {
		if fileInfo.IsDir() {
			fmt.Println("sub文件夹存在,任意键将删除")
			fmt.Scanln()
			os.RemoveAll("sub")
			os.Mkdir("sub", 0555)
		}
	}
	nodes := formatNodes()
	users := formatUser()
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
			case "hysteria2":
				for _, item := range user.Protocol {
					if item == "hysteria2" {
						base64Url := toHysteria2(node, email)
						urlBuilder.WriteString(base64Url)
						urlBuilder.WriteString("\r")
					}
				}
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
		//别名
		if len(user.Name) > 0 {
			email = user.Name
		}
		builder := urlBuilder.String()
		//最后再base64一次符合小火箭订阅格式
		toString := base64.StdEncoding.EncodeToString([]byte(builder))
		os.WriteFile("sub/"+email, []byte(toString), 0555)
	}
	/*fmt.Println(toString)
	clipboard.WriteAll(toString)
	fmt.Println("已复制到剪切板")*/
	if len(nodes) > 0 {
		fmt.Printf("文件写入到sub文件夹共%d位用户\n", len(users))
	} else {
		fmt.Println("未找到有效节点")
	}
	// fmt.Println("回车退出")
	// b := make([]byte, 1)
	// os.Stdin.Read(b)
}
func toTrojan(n node) (base64Url string) {
	url := trojanProtocol + url2.QueryEscape(n.ID) + "@" + n.Add + ":" + n.Port + "?security=tls&alpn=h2%2Chttp%2F1.1&type=tcp&headerType=none#" + url2.QueryEscape(n.Ps)
	return url
}
func toHysteria2(n node, email string) (base64Url string) {
	url := hysteria2Protocol + email + ":" + url2.QueryEscape(n.ID) + "@" + n.Add + ":" + n.Port + "?sni=" + n.Host + "&alpn=h3&upmbps=500&downmbps=500#" + url2.QueryEscape(n.Ps)
	return url
}
func toVless(n node) (base64Url string) {
	url := vlessProtocol + url2.QueryEscape(n.ID) + "@" + n.Add + ":" + n.Port + "?encryption=none&security=tls&alpn=h2%2Chttp%2F1.1&" + "type=" + n.Net
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
	// 如果n的网络为grpc
	if n.Net == "grpc" {
		// 将n的类型设置为gun
		n.Type = "gun"
	}
	// 将n转换为json格式
	json, _ := json.Marshal(n)
	// 将json格式转换为base64Url格式
	vmess := string(json)
	// 返回vmess协议+base64Url格式的字符串
	return vmessProtocol + base64.StdEncoding.EncodeToString([]byte(vmess))
}

func formatNodes() []node {
	//创建一个空的节点数组
	tempArr := make([]node, 0)
	vmessArr := make([]node, 0)
	//读取json文件
	vmess, _ := readJSON(nodePath)
	//获取json数组
	//将json数组解析为节点数组
	JSONArr := json.Unmarshal(vmess, &tempArr)
	//如果解析出错，则打印错误信息，并退出
	if JSONArr != nil {
		fmt.Println("node模板.json is error")
		fmt.Println("回车退出")
		b := make([]byte, 1)
		os.Stdin.Read(b)
		panic(JSONArr)
	}
	//移除tempArr中hidden为true的
	for _, item := range tempArr {
		if !item.Hiden {
			vmessArr = append(vmessArr, item)
		}
	}
	// fmt.Println(vmessArr)
	//返回节点数组
	return vmessArr
}

func formatUser() []user {
	//获取json数组
	userArr := make([]user, 0)
	user, _ := readJSON(userPath)
	//将json数组解析为userArr
	JSONArr := json.Unmarshal(user, &userArr)
	//如果解析失败
	if JSONArr != nil {
		fmt.Println("user模板.json is error")
		fmt.Println("回车退出")
		b := make([]byte, 1)
		//读取回车
		os.Stdin.Read(b)
		//抛出异常
		panic(JSONArr)
	}
	//返回userArr
	return userArr
}
func readJSON(path string) ([]byte, error) {
	open, _ := os.Open(path)
	defer open.Close()
	return io.ReadAll(JsonConfigReader.New(open))
}

// 判断文件文件夹是否存在
func isFileExist(path string) (bool, error) {
	//获取文件信息
	fileInfo, err := os.Stat(path)

	//如果文件不存在
	if os.IsNotExist(err) {
		return false, nil
	}
	//我这里判断了如果是0也算不存在
	//如果文件大小为0
	if fileInfo.Size() == 0 {
		return false, nil
	}
	//如果文件存在
	if err == nil {
		return true, nil
	}
	return false, err
}
