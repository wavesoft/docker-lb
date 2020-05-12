package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/crc64"
	"strconv"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	log "github.com/sirupsen/logrus"
)

var crc64Table = crc64.MakeTable(0xC96C5795D7870F42)

func CreateDockerMonitor() (*DockerMonitor, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, fmt.Errorf("Could not create docker monitor: %s", err.Error())
	}

	return &DockerMonitor{
		client: cli,
	}, nil
}

func (m *DockerMonitor) GetProxyEndpoints() ([]ProxyEndpoint, error) {
	var ep []ProxyEndpoint

	containers, err := m.client.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("Could not enumerate containers: %s", err.Error())
	}

	for _, container := range containers {
		cid := container.ID[:10]
		if domain, ok := container.Labels["publish.domain"]; ok {

			// Find port
			port := 80
			if sv, ok := container.Labels["publish.port"]; ok {
				v, err := strconv.Atoi(sv)
				if err != nil {
					log.Warnf("[c-%s] 'publish.port' of was not numeric", cid)
				} else {
					port = v
				}
			}

			// Find source path
			pathFrom := "/"
			pathTo := "/"
			if sv, ok := container.Labels["publish.path"]; ok {
				pathFrom = sv
				pathTo = sv
			}
			if sv, ok := container.Labels["publish.path.frontend"]; ok {
				pathFrom = sv
			}
			if sv, ok := container.Labels["publish.path.backend"]; ok {
				pathTo = sv
			}

			// Get autocert flag
			autoCert := false
			if sv, ok := container.Labels["publish.ssl"]; ok {
				if sv == "yes" || sv == "true" || sv == "on" || sv == "1" {
					autoCert = true
				}
			}

			if container.NetworkSettings != nil {
				for _, netInfo := range container.NetworkSettings.Networks {
					log.Infof("[c-%s] Exposing %s:%d%s -> %s%s ", cid,
						netInfo.IPAddress, port, pathFrom, domain, pathTo)
					ep = append(ep, ProxyEndpoint{
						FrontendDomain: domain,
						FrontendPath:   pathFrom,
						BackendIP:      netInfo.IPAddress,
						BackendPort:    port,
						BackendPath:    pathTo,
						SSLAutoCert:    autoCert,
					})
				}
			}
		}
	}

	return ep, nil
}

func (e *ProxyEndpoint) Hash() uint64 {
	bt, err := json.Marshal(e)
	if err != nil {
		log.Warnf("Could not marshal %+v: %s", e, err.Error())
		return 0
	}

	return crc64.Checksum(bt, crc64Table)
}
