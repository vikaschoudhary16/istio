# How to sync with upstream Istio

1. Sync the upstream-istio branch with istio

```
git pull https://github.com/tetrateio/istio
git checkout upstream-istio
git remote add istio https://github.com/istio/istio
git pull istio
git merge istio/master
git push origin upstream-istio
```

Note down the `SHA` in the `upstream-istio` branch that corresponds to the Istio commit that you pulled in.

2. Now update the [tcc](https://github.com/tetrateio/istio/tree/tcc) branch of this repo.

```
git checkout tcc
# update UPSTREAM-SHA with the SHA that you noted down
git merge upstream-istio
# fix merge conflicts
git push origin tcc
```


3. If you have to rebuild all Istio docker containers, run the `trigger_istio_release.sh` script below.

```bash
#!/bin/bash
set +x
BRANCH=tcc
SHORTSHA=`git rev-parse --short HEAD`
DATE=`date +"%Y-%m-%d-%H-%M"`
TAG=0.6.2-istio-1.3.0-${SHORTSHA}
# istio version
VERSION=1.3.0
echo $TAG

# MAKE SURE TO SET CIRCLE_CI_PERSONAL_API_TOKEN with the token from circleci
curl -X POST --header "Content-Type: application/json" -d '{
  "build_parameters": {
    "CIRCLE_JOB" : "dockerpush",
    "HUB" : "docker.io/tetrate",
    "TAG" : '\"${TAG}\"',
    "VERSION" : '\"${VERSION}\"'
  }
}
' https://circleci.com/api/v1.1/project/github/tetrateio/istio/tree/${BRANCH}?circle-token=${CIRCLE_CI_PERSONAL_API_TOKEN}

```

Wait for 5 minutes for the images to build.

4. Update [dependencies.sh](https://github.com/tetrateio/tetrate/blob/master/dependencies.sh) in [tetrateio/tetrate](https://github.com/tetrateio/tetrate) with the `TAG` and the commit `SHA`.

5. It is encouraged to update the `istio.io/istio`'s replace entry in [go.mod](https://github.com/tetrateio/tetrate/blob/master/go.mod) to use the latest SHA of this repo (`tcc` branch).

```
$ go mod edit -replace istio.io/istio=github.com/tetrateio/istio@<LATEST_SHA_OF_THIS_REPO>
# For example
$ go mod edit -replace istio.io/istio=github.com/tetrateio/istio@23393db
```
