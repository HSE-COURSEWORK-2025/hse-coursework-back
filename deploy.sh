kubectl delete -f deployment -n hse-coursework-health
kubectl delete -f network-policy.yaml -n hse-coursework-health
docker build -t awesomecosmonaut/results-provider-app .
docker push awesomecosmonaut/results-provider-app
kubectl apply -f deployment -n hse-coursework-health
kubectl apply -f network-policy.yaml -n hse-coursework-health