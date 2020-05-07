# docker-lb
> A dynamic front-end Load Balancer simple docker environments

Docker-LB is a Layer-7 load-balancer and web front-end for simple docker environments. It can be used for exposing microservices under different virtual servers and paths.

## Usage

Deploy Docker-LB to your public-facing node(s):

```sh
docker run -d --name docker-lb \
    -p 80:80 -p 443:443 \
    -e AUTOCERT_EMAIL=admin@mydomain.com \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/run/docker-lb:/var/run/docker-lb \
    wavesoft/docker-lb:latest
```

Then you can expose one or more services attached on the same docker network as the `docker-lb` service by specifying the following [labels](#labels):

```sh
docker run \
    -l publish.domain=mydomain.com \
    -l publish.port=8080 \
    -l publish.ssl=on \
    ...
```

## Labels

The following labels can be used on the service containers:

<table>
    <thead>
        <tr>
            <th>Label</th>
            <th>Default</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th><code>publish.domain</code></th>
            <td><em>Required</em></td>
            <td>The VirtualServer under which to make this container available under. (Eg <code>mydomain.com</code>)</td>
        </tr>
        <tr>
            <th><code>publish.port</code></th>
            <td>80</td>
            <td>Which container port to use as the back-end server. This does not have to be published via <code>-p</code>, since docker-lb will reach it through the container network.</td>
        </tr>
        <tr>
            <th><code>publish.path</code></th>
            <td>/</td>
            <td>The HTTP path to match and forward to the back-end. This is a shorthand to set both <code>publish.path.frontend</code> and <code>publish.path.backend</code> to the same value.</td>
        </tr>
        <tr>
            <th><code>publish.path.frontend</code></th>
            <td>/</td>
            <td>The HTTP path to match on the Virtual Server. You can use this option to implement path-based routing.</td>
        </tr>
        <tr>
            <th><code>publish.path.backend</code></th>
            <td>/</td>
            <td>The HTTP path to match redirect to the back-end server to. If this is different than the <code>publish.path.frontend</code>, an HTTP rewrite rule will be established.</td>
        </tr>
        <tr>
            <th><code>publish.ssl</code></th>
            <td>off</td>
            <td>Set to <code>on</code> to expose this service under HTTPS. A certificate will be automatically issued for this service using Lets-Encrypt.</td>
        </tr>
    </tbody>
</table>
