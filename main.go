package main

import (
	"context"
	"fmt"

	"github.com/wavesoft/docker-lb/utils"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

type ContainerEndpoints struct {
	Hostname string
	IP       string
	Port     string
}

func getContainerEndpoints(cli *client.Client) ([]ContainerEndpoints, error) {
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("Could not enumerate containers: %s", err.Error())
	}

	for _, container := range containers {
		fmt.Printf("%s %s\n", container.ID[:10], container.Image)
		for k, v := range container.Labels {
			fmt.Printf(" k=%s, v=%v\n", k, v)
		}
		if domain, ok := container.Labels["expose.domain"]; ok {
			fmt.Printf("Expose %s: %s\n", container.ID, domain)
			if container.NetworkSettings != nil {
				for netName, netInfo := range container.NetworkSettings.Networks {
					fmt.Printf("> net=%s, ep=%s, gw=%s\n", netName, netInfo.IPAddress, netInfo.Gateway)
				}
			}
		}
	}

	return nil, nil
}

func main() {
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	getContainerEndpoints(cli)

	cfg := utils.CertificateProviderConfig{
		ConfigDir:     "./autocert",
		Email:         "demo@example.com",
		AuthPortHTTP:  5002,
		AuthPortHTTPS: 5003,
	}
	cert, err := utils.CreateCertificateProvider(cfg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", cert)
}
