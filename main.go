package main

import (
  "time"

  log "github.com/sirupsen/logrus"
  "github.com/wavesoft/docker-lb/utils"
)

func syncThread(docker *utils.DockerMonitor, haproxy *utils.HAProxyManager) {
  var (
    crc  uint64 = 0
    ncrc uint64 = 0
  )

  for {
    eps, err := docker.GetProxyEndpoints()
    if err != nil {
      log.Errorf("Could not get docker status: %s", err.Error())
    } else {
      ncrc = 0
      for _, ep := range eps {
        ncrc ^= ep.Hash()
        log.Infof("ep hash=%08x -> %08x", ep.Hash(), ncrc)
      }

      // Detect changes
      if ncrc != crc {
        crc = ncrc
        log.Infof("Endpoint configuration changed")
        err = haproxy.SetConfig(&utils.HAProxyConfig{
          eps,
        })

        if err != nil {
          log.Errorf("Could not apply configuration: %s", err.Error())
        }
      }
    }

    time.Sleep(30 * time.Second)
  }
}

func main() {
  docker, err := utils.CreateDockerMonitor()
  if err != nil {
    panic(err)
  }

  cfg := utils.CertificateProviderConfig{
    ConfigDir:     "./autocert",
    Email:         "demo@example.com",
    AuthPortHTTP:  5002,
    AuthPortHTTPS: 5003,
  }
  certPovider, err := utils.CreateCertificateProvider(cfg)
  if err != nil {
    panic(err)
  }

  // cert, err := certPovider.GetCertificate("example.me")
  // if err != nil {
  //  panic(err)
  // }
  // fmt.Printf("%+v\n", cert)

  proxy := utils.CreateHAProxyManager("/usr/local/sbin/haproxy", certPovider)
  err = proxy.Start()
  if err != nil {
    panic(err)
  }

  // Start monitor thread
  go syncThread(docker, proxy)

  // Wait forever
  select {}
}
