#!/bin/bash -eux

pushd dp-retrieve-public-signing-keys-aws-cognito
  make build
  cp build/dp-retrieve-public-signing-keys-aws-cognito Dockerfile.concourse ../build
popd
