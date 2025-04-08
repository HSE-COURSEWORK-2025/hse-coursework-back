#!/bin/bash

export $(cat .env | sed 's/#.*//g' | xargs) || true
docker build -t awesomecosmonaut/results-provider-app . || true
docker push awesomecosmonaut/results-provider-app || true
kubectl delete -f deployment -n hse-coursework-health || true
kubectl delete -f network-policy.yaml -n hse-coursework-health || true
kubectl apply -f deployment -n hse-coursework-health || true
kubectl apply -f network-policy.yaml -n hse-coursework-health || true
