package main

import (
  "os"
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

  sslEmail := os.Getenv("AUTOCERT_EMAIL")
  if sslEmail == "" {
    sslEmail = "demo@example.com"
  }

  certDir := os.Getenv("AUTOCERT_DIR")
  if certDir == "" {
    certDir = "/var/lib/docker-lb"
  }

  cfg := utils.CertificateProviderConfig{
    ConfigDir:     certDir,
    Email:         sslEmail,
    AuthPortHTTP:  5002,
    AuthPortHTTPS: 5003,
  }
  certPovider, err := utils.CreateCertificateProvider(cfg)
  if err != nil {
    panic(err)
  }

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
