## Steps to Run via Docker
1. Create a `env` file, containing
- base_url={{Your_sonatype_URL}} 
- user_id=yd..
- api_key={{Your_API_Key}}
- application={{application-public-id}} e.g. sandbox
- convert_to_sarif={{true}} e.g. `true`/ 'false'

2. Pull Docker Image
```bash
docker pull ayush1136/sonatype-reporter:v1.0
```

3. Run the Sonatype Reporter
```bash 
docker run -it --env-file {{env-file}} ayush1136/sonatype-reporter:v1.0
```

## Steps To Deploy Sonatype Reporter in k8s env

1. Create `Secret` 
```bash
kubectl create secret generic sonatype-reporter-secret \
  --from-literal=base_url="https://{{domain}}.iq.sonatype.app/" \
  --from-literal=user_id="abcd" \
  --from-literal=api_key="token" \
  --from-literal=application="sandbox" \
  --from-literal=convert_to_sarif="true"
```

2. Verify Secret
```bash
kubectl get secret sonatype-reporter-secret
```

3. Kubernetes CronJob
- Deploy [sonatype-cronjob.yaml](k8s/sonatype-cronjob.yaml)

```bash
kubectl apply -f sonatype-cronjob.yaml
```

4. Verify Execution
```bash
kubectl get cronjobs
kubectl get jobs
```

5. Trigger Manually
```bash
kubectl create job --from=cronjob/sonatype-reporter sonatype-reporter-manual
```

6. Delete 
- Suspend Job
```bash
kubectl patch cronjob sonatype-reporter -p '{"spec":{"suspend":true}}'
```

- Delete Secret 
```bash
kubectl delete secret sonatype-reporter-secret
```

- Delete CronJob
```bash
kubectl delete cronjob sonatype-reporter
```

