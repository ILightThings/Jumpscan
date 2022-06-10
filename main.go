package main

import (
	"errors"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/go-playground/validator"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//type port struct {
//	PortNumber int
//	PortStatus bool
//}

type targetHost struct {
	Ipaddr   string
	Hostname string
	Ports    []int
}

type options struct {
	hosts   []string
	ports   []int
	timeout int64 //Seconds
}

func main() {
	parser := argparse.NewParser("Jumpscan", "A quick, concurrent port scanner, that can be dropped onto a victem machine and ran.")
	portarg := parser.String("p", "ports", &argparse.Options{Required: true, Help: "TCP ports to scan. Single port, range, comma seperated"})
	hostarg := parser.String("t", "target", &argparse.Options{Required: true, Help: "IPv4 to target. Single, CIDR, comma seperated"})
	timeoutarg := parser.Int("T", "timeout", &argparse.Options{Required: false, Default: .5, Help: "Timeout in seconds"})
	err := parser.Parse(os.Args)

	valPorts, err := ParsePorts(*portarg)
	if err != nil {
		log.Fatal(err)
	}
	valHost, err := ParseHost(*hostarg)
	if err != nil {
		log.Fatal(err)
	}

	args := options{ports: valPorts,
		hosts:   valHost,
		timeout: int64(*timeoutarg)}

	startScan(&args)

}

func Cidr(cidr string) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
	}

	var ipstring []string
	for ipClass := range ips {
		ipstring = append(ipstring, ips[ipClass].String())
	}

	return ipstring, nil
}

func ParsePorts(ports string) ([]int, error) {
	var validports []int
	//v := validator.New()

	//Single Port
	IntVar, err := strconv.Atoi(ports)
	if err == nil {
		validports = append(validports, IntVar)
		return validports, nil
	}

	// Port range 1-500
	if strings.Contains(ports, "-") {
		rangePorts := strings.Split(ports, "-")
		if len(rangePorts) != 2 {
			return validports, errors.New("could not parse range between two numbers.")
		}
		minPort, err := strconv.Atoi(rangePorts[0])
		if err != nil {
			return validports, errors.New("could not parse int from port range")
		}
		maxPort, err := strconv.Atoi(rangePorts[1])
		if err != nil {
			return validports, errors.New("could not parse int from port range")
		}

		if minPort > maxPort {
			return validports, errors.New("error validating port range. first number should be smaller. ex. 1-100")
		}
		for i := minPort; i < maxPort+1; i++ {
			validports = append(validports, i)
		}
		if len(validports) == 0 {
			return validports, errors.New("port range is empty somehow")
		}
		return validports, nil
	}

	if strings.Contains(ports, ",") {
		portsComma := strings.Split(ports, ",")
		for x := range portsComma {
			portsComma[x] = strings.TrimSpace(portsComma[x])
			p, err := strconv.Atoi(portsComma[x])
			if err != nil {
				continue
			}
			validports = append(validports, p)
		}
		if len(validports) == 0 {
			return validports, errors.New("port range is empty somehow")
		}
		return validports, nil
	}
	return nil, errors.New(fmt.Sprintf("could not parse ports from argument for %s", ports))

}

func ParseHost(host string) ([]string, error) {
	v := validator.New()
	var p []string

	//Single Host
	err := v.Var(host, "ip")
	if err == nil {
		p = append(p, host)
		return p, nil
	}

	//Cidr
	err = v.Var(host, "cidr")
	if err == nil {
		p, err = Cidr(host)
		if err != nil {
			return p, err
		}
		return p, nil
	}

	//Comma seperated
	if strings.Contains(host, ",") {
		potentialTarget := strings.Split(host, ",")
		for ahost := range potentialTarget {
			potentialTarget[ahost] = strings.TrimSpace(potentialTarget[ahost])
			err = v.Var(potentialTarget[ahost], "ip4_addr")
			if err != nil {
				continue
			}
			p = append(p, potentialTarget[ahost])

		}
		return p, err
	}
	return p, errors.New("could not parse IP address")

}

func startScan(options *options) {
	var allhosts []targetHost
	var WAIT sync.WaitGroup

	for _, h := range options.hosts {

		WAIT.Add(1)
		go func(host string) {

			defer WAIT.Done()

			//fmt.Printf("starting host %s\n", host)
			th := scanTarget(host, options)
			allhosts = append(allhosts, th)
		}(h)

	}
	WAIT.Wait()

	for ahost := range allhosts {
		if len(allhosts[ahost].Ports) != 0 {
			fmt.Println(allhosts[ahost].Ipaddr)
			for p := range allhosts[ahost].Ports {
				fmt.Printf("\tPort %d Open\n", allhosts[ahost].Ports[p])
			}
		}
	}
	fmt.Printf("Scan Finished \n")

}

func scanTarget(host string, options *options) targetHost {
	var t targetHost
	t.Ipaddr = host
	var wg sync.WaitGroup
	for _, y := range options.ports {

		wg.Add(1)
		go func(port int) {

			defer wg.Done()
			status := scanport(port, host, options.timeout)
			if status {
				t.Ports = append(t.Ports, port)
			}
		}(y)

	}
	wg.Wait()
	return t
}

func scanport(port int, host string, timeout int64) bool {

	target := fmt.Sprintf("%s:%d", host, port)
	//fmt.Printf("Testing %s\n", target)

	_, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Second)
	if err == nil {
		fmt.Printf("Found %s\n", target)
		return true
	}
	return false
}
