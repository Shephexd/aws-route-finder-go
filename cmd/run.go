package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/spf13/cobra"
	"log"
	"net"
	"strings"
	"time"
)

type EndpointType string

const (
	IP   EndpointType = "IP"
	ENI  EndpointType = "ENI"
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

func isPrivateIP(ip string) bool {
	privateIPBlocks := []*net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
	}
	parsedIP := net.ParseIP(ip)
	for _, block := range privateIPBlocks {
		if block.Contains(parsedIP) {
			return true
		}
	}
	return false
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
	rf := &RouteFinder{
		proxy:       proxy,
		instanceMap: make(map[string]EC2Instance),
		igwMap:      make(map[string]InternetGateway),
		eniMap:      make(map[string]NetworkInterface),
		ipMap:       make(map[string]NetworkInterface),
		endpointMap: make(map[string]map[string]interface{}),
	}

	return rf
}

func (rf *RouteFinder) LoadResources() {
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

func (rf *RouteFinder) BuildNetworkPath(source Endpoint, destination Endpoint, protocol string, destinationPort int32) *ec2.CreateNetworkInsightsPathInput {
	nipInput := &ec2.CreateNetworkInsightsPathInput{
		Source:         aws.String(source.ID),
		Destination:    aws.String(destination.ID),
		Protocol:       types.Protocol(protocol),
		FilterAtSource: &types.PathRequestFilter{},
	}

	switch destination.Type {
	case EC2:
		nipInput.Destination = aws.String(destination.ID)
	case ENI:
		nipInput.Destination = aws.String(destination.ID)
	case FQDN:
		nipInput.Destination = aws.String("")
		resolvedIPAddress, err := resolveToIP(destination.ID)

		if err != nil {
			log.Fatalf("failed to resolve", err)
		}
		nipInput.Destination = nil
		nipInput.FilterAtSource = &types.PathRequestFilter{
			DestinationAddress: aws.String(resolvedIPAddress),
		}
		if destinationPort > 0 {
			nipInput.FilterAtSource.DestinationPortRange = &types.RequestFilterPortRange{
				FromPort: &destinationPort,
				ToPort:   &destinationPort,
			}
		}

	case IP:
		nipInput.Destination = nil
		nipInput.FilterAtSource = &types.PathRequestFilter{
			DestinationAddress: aws.String(destination.ID),
		}
		if destinationPort > 0 {
			nipInput.FilterAtSource.DestinationPortRange = &types.RequestFilterPortRange{
				FromPort: &destinationPort,
				ToPort:   &destinationPort,
			}
		}
	}

	return nipInput
}

func (rf *RouteFinder) GetAnalysisResult(networkInsightAnalysisId string) types.NetworkInsightsAnalysis {
	nias := []string{networkInsightAnalysisId}

	tic := 0
	maxWaitTime := 1200

	fmt.Print("Analyzing")

	for tic < maxWaitTime {
		niaInput := &ec2.DescribeNetworkInsightsAnalysesInput{NetworkInsightsAnalysisIds: nias}

		niaOutput, err := rf.proxy.DescribeNetworkInsightsAnalyses(context.TODO(), niaInput)
		if err != nil {
			fmt.Println("Error Msg", err)
			return types.NetworkInsightsAnalysis{
				Status: types.AnalysisStatusFailed,
			}
		}

		switch niaOutput.NetworkInsightsAnalyses[0].Status {
		case types.AnalysisStatusRunning:
			time.Sleep(time.Second)
			fmt.Print(".")
			maxWaitTime += 1
		case types.AnalysisStatusSucceeded:
			fmt.Println("\nAnalysis Result")
			return niaOutput.NetworkInsightsAnalyses[0]
		case types.AnalysisStatusFailed:
			return types.NetworkInsightsAnalysis{
				Status: types.AnalysisStatusFailed,
			}
		}
	}
	return types.NetworkInsightsAnalysis{
		Status: types.AnalysisStatusFailed,
	}
}

func (rf *RouteFinder) Run(nipInput *ec2.CreateNetworkInsightsPathInput) *ec2.StartNetworkInsightsAnalysisOutput {
	nipOutput, nipErr := rf.proxy.CreateNetworkInsightsPath(context.TODO(), nipInput)
	if nipErr != nil {
		fmt.Println("Fail to create NetworkInsightsPath", nipErr)
		return &ec2.StartNetworkInsightsAnalysisOutput{}
	}

	// Start VPC Reachability Analyzer
	niaInput := &ec2.StartNetworkInsightsAnalysisInput{
		NetworkInsightsPathId: aws.String(*nipOutput.NetworkInsightsPath.NetworkInsightsPathId),
	}

	niaOutput, niaErr := rf.proxy.StartNetworkInsightsAnalysis(context.TODO(), niaInput)
	if niaErr != nil {
		fmt.Println("Fail to start NetworkInsightsAnalysis", niaErr)
		return &ec2.StartNetworkInsightsAnalysisOutput{}
	}
	return niaOutput
}

func (rf *RouteFinder) GetInstanceByID(instanceID string) (*types.Instance, error) {
	describeEC2Input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := rf.proxy.DescribeInstances(context.TODO(), describeEC2Input)
	if err != nil {
		log.Fatalf("failed to describe instances, %v", err)
	}
	if len(result.Reservations) > 0 && len(result.Reservations[0].Instances) > 0 {
		instance := result.Reservations[0].Instances[0]
		return &instance, nil
	}
	return &types.Instance{}, errors.New("no ENI Found")
}

func (rf *RouteFinder) GetENIbyID(networkInterfaceID string) (*types.NetworkInterface, error) {
	DescribeENIInput := &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{networkInterfaceID},
	}
	result, err := rf.proxy.DescribeNetworkInterfaces(context.TODO(), DescribeENIInput)
	if err != nil {
		log.Fatalf("failed to describe network interfaces, %v", err)
	}

	for _, eniObj := range result.NetworkInterfaces {
		return &eniObj, nil
	}
	return &types.NetworkInterface{}, errors.New("no ENI Found")
}

func (rf *RouteFinder) GetENIbyIPAddress(ipAddress string) (*types.NetworkInterface, error) {
	filterName := ""
	if isPrivateIP(ipAddress) {
		filterName = "addresses.private-ip-address"
	} else {
		filterName = "association.public-ip"
	}

	DescribeENIInput := &ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String(filterName),
				Values: []string{ipAddress},
			},
		},
	}
	result, err := rf.proxy.DescribeNetworkInterfaces(context.TODO(), DescribeENIInput)
	if err != nil {
		log.Fatalf("failed to describe network interfaces, %v", err)
	}

	for _, eniObj := range result.NetworkInterfaces {
		return &eniObj, nil
	}
	return &types.NetworkInterface{}, errors.New("no ENI Found")
}

func (rf *RouteFinder) GetSource(sourceId string) (Endpoint, error) {
	source := Endpoint{}

	if strings.HasPrefix(sourceId, "i-") {
		instance, err := rf.GetInstanceByID(sourceId)
		if err != nil {
			return source, errors.New("not registered EC2 on AWS")
		}
		return Endpoint{ID: *instance.InstanceId, Type: EC2}, nil

	} else if strings.HasPrefix(sourceId, "eni-") {
		eni, err := rf.GetENIbyID(sourceId)
		if err != nil {
			return source, errors.New("not registered ENI on AWS")
		}
		return Endpoint{ID: *eni.NetworkInterfaceId, Type: ENI}, nil
	} else if IsIPAddress(sourceId) {
		eni, err := rf.GetENIbyIPAddress(sourceId)
		if err != nil {
			return source, errors.New("not registered IP on AWS")
		}
		return Endpoint{ID: *eni.NetworkInterfaceId, Type: ENI}, nil
	}
	return source, nil
}

func (rf *RouteFinder) GetDestination(destinationId string) (Endpoint, error) {
	destination := Endpoint{}
	if strings.HasPrefix(destinationId, "i-") {
		instance, err := rf.GetInstanceByID(destinationId)
		if err != nil {
			return destination, errors.New("not registered EC2 on AWS")
		}
		return Endpoint{ID: *instance.InstanceId, Type: EC2}, nil

	} else if strings.HasPrefix(destinationId, "eni-") {
		eni, err := rf.GetENIbyID(destinationId)
		if err != nil {
			return destination, errors.New("not registered ENI on AWS")
		}
		return Endpoint{ID: *eni.NetworkInterfaceId, Type: ENI}, nil
	} else if IsIPAddress(destinationId) {
		return Endpoint{ID: destinationId, Type: IP}, nil
	}

	return Endpoint{ID: destinationId, Type: FQDN}, nil
}

func IsIPAddress(ip string) bool {
	trial := net.ParseIP(ip)
	if trial.To4() == nil {
		return false
	}
	return true
}

var subACmd = &cobra.Command{
	Use:   "run",
	Short: "RouteFinder allows users to analyze and debug network reachability between resources within an Amazon Virtual Private Cloud (VPC).",
	Long: `The VPC Reachability Analyzer CLI tool, RouteFinder, is a powerful utility for network diagnostics within an Amazon VPC. 
It helps users troubleshoot connectivity issues, verify network configurations, and ensure that network paths align with intended connectivity policies.

example: arf run sourceIPOnAWS targetIP --protocol tcp --port 800
`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		region, _ := cmd.Flags().GetString("region")

		cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
		if err != nil {
			fmt.Println("Error loading configuration:", err)
			return
		}
		rf := NewRouteFinder(cfg)

		source, err := rf.GetSource(args[0])
		if err != nil {
			fmt.Println("Error getting source:", err)
			return
		}
		destination, err := rf.GetDestination(args[1])
		if err != nil {
			fmt.Println("Error getting destination:", err)
			return
		}
		protocol, _ := cmd.Flags().GetString("protocol")
		destinationPort, _ := cmd.Flags().GetInt32("port")

		fmt.Printf("RouteFinder start analysis from %s to %s through(%s(%d))\n", source.ID, destination.ID, protocol, destinationPort)
		nip := rf.BuildNetworkPath(source, destination, protocol, destinationPort)
		nia := rf.Run(nip)
		niaResult := rf.GetAnalysisResult(*nia.NetworkInsightsAnalysis.NetworkInsightsAnalysisId)
		if *niaResult.NetworkPathFound {
			fmt.Println("- Reachability OK! Network Route Found")
		} else {
			fmt.Println("- Reachability Not OK... Fail to find Network Route")
			for idx, e := range niaResult.Explanations {
				fmt.Println("- Explanation", idx+1, ": ", *e.ExplanationCode)
			}
		}

		if len(niaResult.ReturnPathComponents) == 0 {
			fmt.Println("- Only For Forward Path, An unidirectional path will be shown if analysis involves Transit Gateway.")
		}
		consoleURL := fmt.Sprintf("https://console.aws.amazon.com/networkinsights/home?#NetworkPathAnalysis:analysisId=%s",
			*nia.NetworkInsightsAnalysis.NetworkInsightsAnalysisId)
		fmt.Println("Detail Information in Console URL:", consoleURL)
	},
}

func init() {
	var protocol = "tcp"
	var port = int32(0)
	subACmd.Flags().String("protocol", protocol, "Destination Protocol")
	subACmd.Flags().Int32("port", port, "Destination Port")
	rootCmd.AddCommand(subACmd)
}
