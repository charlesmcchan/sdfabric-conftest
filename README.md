# ConfTest for SD-Fabric configurations

## Prerequisite
* Docker
* https://www.conftest.dev/

## Verify ONOS network config
```
cd netcfg
docker run --rm -v $(pwd):/project openpolicyagent/conftest test sample.json
```