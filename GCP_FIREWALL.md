### Primary VPN Port (Essential)
```bash
gcloud compute firewall-rules create flunk-vpn-main \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=udp:1194 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=vpn-server
```

### HTTP masquerading (from your evasion config) (Essential)
```bash
gcloud compute firewall-rules create flunk-vpn-http \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:80,tcp:443 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=vpn-server
```

### DNS outbound traffic
```bash
gcloud compute firewall-rules create flunk-vpn-dns-out \
    --direction=EGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:53,udp:53,tcp:443 \
    --destination-ranges=0.0.0.0/0 \
    --target-tags=vpn-server
```

### Additional common ports for steganographic traffic
```bash
gcloud compute firewall-rules create flunk-vpn-stego \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:8080,tcp:8443 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=vpn-server
```
### Alternative TLS port for wrapped traffic
```bash
gcloud compute firewall-rules create flunk-vpn-tls-alt \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:993,tcp:995 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=vpn-server
```

### Minimal Configuration (Recommended Start)
For your lightweight setup, start with these essential rules only:
- UDP 1194 (main VPN port)
- TCP 22 (SSH management)
- TCP 80/443 (HTTP/HTTPS masquerading)


### Server-side
```bash
gcloud compute instances create instance-20250910-173643 --project=hallowed-chain-471421-n5 --zone=asia-southeast1-b --machine-type=e2-micro --network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default --maintenance-policy=MIGRATE --provisioning-model=STANDARD --service-account=356530250501-compute@developer.gserviceaccount.com --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/trace.append --create-disk=auto-delete=yes,boot=yes,device-name=instance-20250910-173643,image=projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20250826,mode=rw,size=10,type=pd-balanced --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring --labels=goog-ec-src=vm_add-gcloud --reservation-affinity=any
```