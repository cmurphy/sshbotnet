package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	net, err := setup("bots.txt")
	if err != nil {
		panic(err)
	}
	for _, b := range net.bots {
		cleanup, err := b.connect()
		if err != nil {
			panic(err)
		}
		defer func(cleanup cleanupFn) { fmt.Println(); cleanup() }(cleanup)
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(": ")
		cmd, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		for _, b := range net.bots {
			if b.conn != nil {
				err = b.sendCommand(cmd)
				if err != nil {
					panic(err)
				}
			}
		}
	}
	if err != nil && err != io.EOF {
		panic(err)
	}
}

type conn struct {
	session *ssh.Session
	stdin   io.WriteCloser
}

type bot struct {
	user     string
	password string
	host     string
	port     string
	conn     *conn
}

type network struct {
	bots []*bot
}

func setup(configPath string) (network, error) {
	file, err := os.Open(configPath)
	n := network{}
	if err != nil {
		return n, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		botCfg := scanner.Text()
		hostParts := strings.Split(botCfg, " ")
		if len(hostParts) != 2 {
			return n, fmt.Errorf("invalid config")
		}
		password := hostParts[1]
		hostParts = strings.Split(hostParts[0], "@")
		if len(hostParts) != 2 {
			return n, fmt.Errorf("invalid config")
		}
		user := hostParts[0]
		hostParts = strings.Split(hostParts[1], ":")
		if len(hostParts) < 1 || len(hostParts) > 2 {
			return n, fmt.Errorf("invalid config")
		}
		port := ""
		host := hostParts[0]
		if len(hostParts) == 2 {
			port = hostParts[1]
		} else {
			port = "22"
		}
		n.bots = append(n.bots, &bot{user: user, password: password, host: host, port: port})
	}
	return n, nil
}

type cleanupFn func()

func makeSession(client *ssh.Client) (conn, cleanupFn, error) {
	session, err := client.NewSession()
	if err != nil {
		return conn{}, func() {}, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return conn{}, func() {}, err
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	c := conn{session: session, stdin: stdin}
	err = c.session.Shell()
	if err != nil {
		return conn{}, func() {}, err
	}

	cleanup := func() {
		fmt.Printf("cleaning up bot %s\n", client.RemoteAddr().String())
		client.Close()
		if c.session != nil {
			c.session.Close()
			c.session = nil
		}
	}
	return c, cleanup, nil
}

func (c *conn) sendCommand(cmd string) error {
	_, err := fmt.Fprintf(c.stdin, "%s\n", cmd)
	return err
}

func (b *bot) connect() (cleanupFn, error) {
	config := &ssh.ClientConfig{
		User: b.user,
		Auth: []ssh.AuthMethod{
			ssh.Password(b.password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if b.port == "" {
		b.port = "22"
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", b.host, b.port), config)
	if err != nil {
		return func() {}, err
	}
	conn, cleanup, err := makeSession(client)
	if err != nil {
		client.Close()
		return func() {}, err
	}
	b.conn = &conn
	fmt.Printf("connected: %s\n", b.host)
	return cleanup, nil
}

func (b *bot) sendCommand(cmd string) error {
	return b.conn.sendCommand(cmd)
}
