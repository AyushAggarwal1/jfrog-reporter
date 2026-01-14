## Steps To Deploy Jfrog Reporter in k8s env

1. Create `Secret` 
```bash
kubectl create secret generic jfrog-reporter-secret \
  --from-literal=JFROG_URL="https://trialcmqekv.jfrog.io" \
  --from-literal=JFROG_API_KEY="ey...." \
  --from-literal=JFROG_REPO="poc-docker-local" \
  --from-literal=CSPM_BASE_URL="https://cspm.dev.accuknox.com" \
  --from-literal=LABEL="github" \
  --from-literal=ARTIFACT_TOKEN="ey....""
```

2. Verify Secret
```bash
kubectl get secret jfrog-reporter-secret
```

3. Kubernetes CronJob
- Deploy [jfrog-cronjob.yaml](jfrog-cronjob.yaml)

```bash
kubectl apply -f jfrog-cronjob.yaml
```

4. Verify Execution
```bash
kubectl get cronjobs
kubectl get jobs
```

5. Trigger Manually
```bash
kubectl create job --from=cronjob/jfrog-reporter jfrog-reporter-manual
```

6. Delete 
- Suspend Job
```bash
kubectl patch cronjob jfrog-reporter -p '{"spec":{"suspend":true}}'
```

- Delete Secret 
```bash
kubectl delete secret jfrog-reporter-secret
```

- Delete CronJob
```bash
kubectl delete cronjob jfrog-reporter
```

