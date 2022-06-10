package main

import (
	"github.com/google/go-cmp/cmp"
	"testing"
)

func TestParsePorts(t *testing.T) {
	singleport := "90"
	singleportresult := []int{90}

	multiport := "139,445,3389"

	multiportresult := []int{139, 445, 3389}

	portrange := "20-25"
	portrangeresult := []int{20, 21, 22, 23, 24, 25}

	badTest := "niceport 25 loser"

	test1, err := ParsePorts(singleport)
	if err != nil {
		t.Errorf("single port error %s", err)
	}
	if !cmp.Equal(test1, singleportresult) {
		t.Errorf("Single port test failed. Expected %+v, returned %+v", singleportresult, test1)
	}

	test2, err := ParsePorts(multiport)
	if err != nil {
		t.Errorf("Multi port error %s", err)
	}
	if !cmp.Equal(test2, multiportresult) {
		t.Errorf("Multi port test failed. Expected %+v, returned %+v", multiportresult, test2)
	}

	test3, err := ParsePorts(portrange)
	if err != nil {
		t.Errorf("Range port error %s", err)
	}
	if !cmp.Equal(test3, portrangeresult) {
		t.Errorf("Range port test failed. Expected %+v, returned %+v", portrangeresult, test3)
	}

	_, err = ParsePorts(badTest)
	if err == nil {
		t.Error("There should been an error here")
	}

}

func TestParseHost(t *testing.T) {

	singlehostTest := "192.168.1.1"
	singlehostresult := []string{"192.168.1.1"}

	cidrhost := "10.0.0.0/30"
	cidrresult := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}

	commahost := "172.16.0.1, 172.16.0.15"
	commaresult := []string{"172.16.0.1", "172.16.0.15"}

	bad := "goproantonio"

	test1, err := ParseHost(singlehostTest)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(test1, singlehostresult) {
		t.Errorf("Single Host error. Expected %+v, returned %+v", singlehostresult, test1)
	}

	test2, err := ParseHost(cidrhost)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(test2, cidrresult) {
		t.Errorf("Cidr host error. Expected %+v, returned %+v", cidrresult, test2)
	}

	test3, err := ParseHost(commahost)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(test3, commaresult) {
		t.Errorf("Comma Host error. Expected %+v, returned %+v", commaresult, test3)
	}

	_, err = ParseHost(bad)
	if err == nil {
		t.Error("This should have been an error")
	}
}
