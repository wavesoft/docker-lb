package main

import (
  "fmt"
  "net/http"
  "os"
  "time"

  log "github.com/sirupsen/logrus"
  "github.com/wavesoft/docker-lb/utils"
)

func httpServerThread(staticDir string, listenPort int) {
  log.Infof("Serving static files from %s", staticDir)
  http.Handle("/", http.FileServer(http.Dir(staticDir)))
  http.ListenAndServe(fmt.Sprintf(":%d", listenPort), nil)
}

func dockerSyncThread(docker *utils.DockerMonitor, haproxy *utils.HAProxyManager) {
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
        err = haproxy.SetState(&utils.HAProxyState{eps})

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

  sslOrg := os.Getenv("AUTOCERT_ORGANISATION")
  if sslOrg == "" {
    sslOrg = "HAProxy"
  }

  certDir := os.Getenv("CONFIG_DIR")
  if certDir == "" {
    certDir = "/var/lib/docker-lb"
  }

  wwwDir := os.Getenv("STATIC_WWW_DIR")

  // Configure Certificate Manager
  cfg := utils.DefaultCertificateProviderConfig{
    ConfigDir:     certDir,
    Email:         sslEmail,
    Organization:  sslOrg,
    AuthPortHTTP:  5002,
    AuthPortHTTPS: 5003,
  }
  certPovider, err := utils.CreateDefaultCertificateProvider(cfg)
  if err != nil {
    panic(err)
  }

  // Configure HAProxy Manager
  haCfg := utils.HAProxyManagerConfig{
    Certificates:           certPovider,
    BinaryPath:             "/usr/local/sbin/haproxy",
    DefaultLocalServerPort: 0,
  }
  if wwwDir != "" {
    haCfg.DefaultLocalServerPort = 8080
  }
  proxy := utils.CreateHAProxyManager(haCfg)
  err = proxy.Start()
  if err != nil {
    panic(err)
  }

  // Start monitor thread
  go dockerSyncThread(docker, proxy)

  // Start default web thread, if enabled
  if wwwDir != "" {
    go httpServerThread(wwwDir, 8080)
  }

  // Wait forever
  select {}
}
