package routefinder

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EndpointType string

const (
	IP   EndpointType = "IP"
	FQDN EndpointType = "FQDN"
	EC2  EndpointType = "EC2"
)

type Endpoint struct {
	ID   string
	Type EndpointType
}

type EC2Instance struct {
	ID               string
	State            int32
	VpcId            string
	PrivateIpAddress string
	PublicIpAddress  string
	Name             string
}

type InternetGateway struct {
	ID string
}

type NetworkInterface struct {
	ID               string
	status           string
	PrivateIpAddress string
	Name             string
	// PrivateIpAddresses []string
	// Association      map[string]string
}

type RouteFindingResult struct {
	NetworkInsightPathID     string
	NetworkInsightAnalysisID string
	RegionName               string
	IsRunning                bool
}

type RouteFinder struct {
	proxy       *ec2.Client
	instanceMap map[string]EC2Instance
	igwMap      map[string]InternetGateway
	eniMap      map[string]NetworkInterface
	ipMap       map[string]NetworkInterface
	endpointMap map[string]map[string]interface{}
}

func resolveToIP(address string) (string, error) {
	if net.ParseIP(address) != nil {
		return address, nil
	}
	ips, err := net.LookupIP(address)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("failed to resolve address %s: %v", address, err)
	}
	return ips[0].String(), nil
}

func NewRouteFinder(cfg aws.Config) *RouteFinder {
	proxy := ec2.NewFromConfig(cfg)
	// networkManager := networkmanager.NewFromConfig(cfg)
	rf := &RouteFinder{
		proxy: proxy,
		// networkManager: networkManager,
		instanceMap: make(map[string]EC2Instance),
		igwMap:      make(map[string]InternetGateway),
		eniMap:      make(map[string]NetworkInterface),
		ipMap:       make(map[string]NetworkInterface),
		endpointMap: make(map[string]map[string]interface{}),
	}

	return rf
}

func (rf *RouteFinder) Load() {
	// rf.registerIGW()
	rf.RegisterInstances()
	rf.RegisterENI()
}

func (rf *RouteFinder) RegisterInstances() {
	diInput := &ec2.DescribeInstancesInput{}
	diOutput, err := rf.proxy.DescribeInstances(context.TODO(), diInput)

	if err != nil {
		fmt.Println("Error Msg", err)
	}

	for _, rev := range diOutput.Reservations {
		var instance = rev.Instances[0]
		var instanceName = ""
		var publicIpAddress = ""

		for _, tag := range rev.Instances[0].Tags {
			if strings.Compare(*tag.Key, "Name") == 0 {
				instanceName = *tag.Value
			}
		}
		if instance.PublicIpAddress != nil {
			publicIpAddress = *instance.PublicIpAddress
		}

		rf.instanceMap[*rev.Instances[0].InstanceId] = EC2Instance{
			ID:               *instance.InstanceId,
			State:            *instance.State.Code,
			PrivateIpAddress: *instance.PrivateIpAddress,
			PublicIpAddress:  publicIpAddress,
			Name:             instanceName,
		}
	}
}

func (rf *RouteFinder) RegisterENI() {
	dENIInput := &ec2.DescribeNetworkInterfacesInput{}
	dENIOutput, err := rf.proxy.DescribeNetworkInterfaces(context.TODO(), dENIInput)

	if err != nil {
		fmt.Println("Error Msg", err)
	}

	for _, eni := range dENIOutput.NetworkInterfaces {
		var eniName = ""
		for _, tag := range eni.TagSet {
			if strings.Compare(*tag.Key, "Name") == 0 {
				eniName = *tag.Value
			}
		}

		eniObj := NetworkInterface{
			ID:               *eni.NetworkInterfaceId,
			PrivateIpAddress: *eni.PrivateIpAddress,
			Name:             eniName,
		}
		rf.eniMap[eniObj.ID] = eniObj
		rf.ipMap[eniObj.PrivateIpAddress] = eniObj
	}
}

func (rf *RouteFinder) BuildNetworkPath(source Endpoint, destination Endpoint, protocol string, sourceIP string, destinationIP string, destinationPort int32, syncFlag bool) *ec2.CreateNetworkInsightsPathInput {

	nipInput := &ec2.CreateNetworkInsightsPathInput{
		Source:      aws.String(source.ID),
		Destination: aws.String(destination.ID),
		Protocol:    types.Protocol(protocol),
		FilterAtSource: &types.PathRequestFilter{
			DestinationAddress: aws.String(""),
		},
	}

	switch destination.Type {
	case EC2:
		nipInput.Destination = aws.String(destination.ID)
	case FQDN:
		fmt.Println("Destination FQDN Type")
		nipInput.Destination = aws.String("")
		resolvedIPAddress, err := resolveToIP(destination.ID)

		if err != nil {
			log.Fatalf("Failed to resolve", err)
		}

		nipInput.Destination = nil
		nipInput.FilterAtSource = &types.PathRequestFilter{
			DestinationAddress: aws.String(resolvedIPAddress),
			DestinationPortRange: &types.RequestFilterPortRange{
				FromPort: &destinationPort,
				ToPort:   &destinationPort,
			},
		}

	case IP:
		nipInput.Destination = nil
		nipInput.FilterAtSource = &types.PathRequestFilter{
			DestinationAddress: aws.String(destination.ID),
			DestinationPortRange: &types.RequestFilterPortRange{
				FromPort: &destinationPort,
				ToPort:   &destinationPort,
			},
		}
	}

	return nipInput
}

func (rf *RouteFinder) Run(nipInput *ec2.CreateNetworkInsightsPathInput) *ec2.StartNetworkInsightsAnalysisOutput {
	nipOutput, nipErr := rf.proxy.CreateNetworkInsightsPath(context.TODO(), nipInput)
	fmt.Println(*nipOutput.NetworkInsightsPath.NetworkInsightsPathId, nipErr)

	// Start VPC Reachability Analyzer
	niaInput := &ec2.StartNetworkInsightsAnalysisInput{
		NetworkInsightsPathId: aws.String(*nipOutput.NetworkInsightsPath.NetworkInsightsPathId),
	}

	niaOutput, niaErr := rf.proxy.StartNetworkInsightsAnalysis(context.TODO(), niaInput)

	fmt.Println(*niaOutput.NetworkInsightsAnalysis.NetworkInsightsAnalysisId, niaErr)
	return niaOutput
}
