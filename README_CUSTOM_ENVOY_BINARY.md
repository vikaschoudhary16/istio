# Which envoy code base a particular proxyv2 image is running?
Proxyv2 image name has SHA of the commit in the tetrateio/istio repo. For example, in `tetrate/proxyv2:0.6.8-istio-f6cab05a8`, `f6cab05a8` is the SHA of the commit in tetrateio/istio
* Checkout to the commit SHA in tetrateio/istio 
* [tetrateio/istio/istio.deps]((https://github.com/tetrateio/istio/blob/f6cab05a86011e59c59c0366e10f71019b35c13d/istio.deps#L7)) file has SHA of the commit in the istio/proxy repo. 
* In [istio.io/proxy/WORKSPACE](https://github.com/istio/proxy/blob/e4df956fb629490dbc7af43ec9c5edda3245d45f/WORKSPACE#L41), there is SHA of the commit at the [envoyproxy/envoy-wasm](https://github.com/envoyproxy/envoy-wasm)
* envoyproxy/envoy-wasm is a fork of envoyproxy/envoy for wasm filter support development

# Envoy dev env setup
Prepare ubuntu vm preferabbly on gcp as explained [here](https://github.com/tetratelabs/getenvoy-package/wiki/Envoy-dev-env-setup)

# Building proxyv2 image with custom envoy binary
* On the ubuntu vm, `git clone https://github.com/istio/proxy` and `git clone https://github.com/envoyproxy/envoy-wasm`
* Let say proxy and envoy-wasm are checked out at /home/vikas/
* For remote build execution, add following in /home/vikas/proxy/.bazelrc:
```
build --remote_instance_name=projects/getenvoy-package/instances/default_instance
build --config=remote-clang-libc++
build --config=remote-ci
build --jobs=80
build --remote_download_outputs=all
```
* Make your changes in the /home/vikas/envoy-wasm
* `export BAZEL_BUILD_ARGS="--override_repository=envoy=/home/vikas/envoy-wasm”`
* `cd /home/vikas/proxy; make`
* On local machine, `cd <istio-repo-path>`
* `make init`
* `scp -i <gcp-key> <ubuntu-vm-ip>:/home/vikas/proxy/bazel-bin/src/envoy/envoy        out/linux_amd64/release/envoy`
* `make docker.proxyv2`
