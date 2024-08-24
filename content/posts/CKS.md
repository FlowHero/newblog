+++
title = 'Certified Kubernetes Security - Chapter 1 Notes'
date = 2024-08-23T23:17:59+01:00
draft = false
description = "This blog is a summary of the first chapter from CKS Exam (Certified Kubernetes Security Specialist)"
+++


## Overview

![image](https://flowhero.github.io/assets/images/shemas/2024_08_24_150951.png)


The first domain of the exam (**Cluster Setup**) delves into the security-specific aspects of setting up and configuring Kubernetes clusters, distinct from the broader responsibilities of a Kubernetes administrator. This chapter focuses on advanced security considerations, assuming a foundational understanding of Kubernetes.

At a high level, the chapter addresses the following key areas:

- **Implementing Network Policies**: Restricting Pod-to-Pod communication within and across namespaces to minimize the attack surface.
- **Using CIS Benchmark Tools**: Identifying and addressing security risks within cluster components by running automated tools like kube-bench.
- **Configuring Ingress with TLS**: Setting up Ingress objects with Transport Layer Security (TLS) termination to secure external access.
- **Securing Cluster Components**: Protecting node ports, API endpoints, and graphical user interfaces (GUIs) to prevent unauthorized access.
- **Validating Platform Binaries**: Ensuring the integrity of Kubernetes binaries such as kubectl, kubeadm, and kubelet by verifying their checksums to detect any tampering.

This blog is a practical summary of everything covered in this chapter.


## Using Network Policies to Restrict Pod-to-Pod Communication

For a Microservice architecture to function in Kubernetes, a Pod needs to be able to communicate with another pod running on same or different node without NAT. Kubernetes assign IP to a pod upon creation from the pod CIDR range of its node, the IP is ephemeral (not stable overtime), every restart of a pod leases a new IP Address.
It's recommended to use Pod-to-Service Communication over Pod-to-Pod communication so that you can rely on a consistent Network Interface.

The IP of a pod is unique across different nodes and namespaces. This is achieved by assigning a dedicated subnet to every node when registering it.

Newly created pod will then get an ip from the subnet of the node, this is handled by CNI plugin

Pods on a node can communicate with all other pods running on any other node of the cluster.

- https://networkpolicy.io/ : Provide a visual editor for network policies that renders a graphical representation in the browser

### Attacker gain initial access to a Pod

![image](https://flowhero.github.io/assets/images/shemas/2024_08_17_193605.png)

Without defining Network Policies, Attacker can talk to all pods and cause additional damage.
### Denying Directional Network Traffic

The best way to restrict Pod-to-Pod network traffic is with the principle of least privilege

Setup the cluster on `ng04.yml`.

```yml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    app: orion
  name: g04
---
apiVersion: v1
kind: Pod
metadata:
  labels:
    tier: backend
  name: backend
  namespace: g04
spec:
  containers:
  - image: bmuschko/nodejs-hello-world:1.0.0
    name: hello
    ports:
    - containerPort: 3000
  restartPolicy: Never
---
apiVersion: v1
kind: Pod
metadata:
  labels:
    tier: frontend
  name: frontend
  namespace: g04
spec:
  containers:
  - image: alpine
    name: frontend
    args:
    - /bin/sh
    - -c
    - while true; do sleep 5; done;
  restartPolicy: Never
---
apiVersion: v1
kind: Pod
metadata:
  labels:
    tier: outside
  name: other
spec:
  containers:
  - image: alpine
    name: other
    args:
    - /bin/sh
    - -c
    - while true; do sleep 5; done;
  restartPolicy: Never
```

```sh
kubectl apply -f ng04.yml
```

Verify that the pods are up and running:

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_222913.png)

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_222953.png)


The cluster have 2 pods on g04 namespace and a pod on default namespace.
By default communication is allowed between these pods, even though the namespace is different.

To test the connectivity from frontend to backend:
```sh
kubectl exec frontend -it -n g04 -- /bin/sh

/ # wget --spider --timeout=1 10.0.0.43:3000 
Connecting to 10.0.0.43:3000 (10.0.0.43:3000) 
remote file exists
/ # exit
```

same applies from other to backend:

```sh
kubectl exec other -it -- /bin/sh 

/ # wget --spider --timeout=1 10.0.0.43:3000 
Connecting to 10.0.0.43:3000 (10.0.0.43:3000) 
remote file exists 
/ # exit
```

Let's now apply the default deny all ingress traffic policy. 
```yml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: g04
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

Selecting all Pods is denoted by the value `{}` assigned to the `spec.podSelector` attribute. The value attribute `spec.policyTypes` defines the denied direction of traffic. For incoming traffic, you can add *Ingress* to the array. Outgoing traffic can be specified by the value *Egress*. In this particular example, we disallow all ingress traffic. Egress traffic is still permitted.

You’d usually start by disallowing traffic in any direction and then opening up the traffic needed by the application architecture.

```sh
kubectl apply -f deny-all-ingress-network-policy.yaml

networkpolicy.networking.k8s.io/default-deny-ingress created
```

Pod-to-pod connectivity is now denied: 

```sh
kubectl exec frontend -it -n g04 -- /bin/sh

/ # wget --spider --timeout=1 10.0.0.43:3000 
Connecting to 10.0.0.43:3000 (10.0.0.43:3000)
wget: download timed out
/ # exit
```

```sh
kubectl exec other -it -- /bin/sh 

/ # wget --spider --timeout=1 10.0.0.43:3000 
Connecting to 10.0.0.43:3000 (10.0.0.43:3000) 
wget: download timed out
/ # exit
```

Now we'll use the namespace label (orion) and pod label (frontend), and port 3000, and add them to the policy to be the only one who could talk to backend:

```yml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-ingress
  namespace: g04
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          app: orion
      podSelector:
        matchLabels:
          tier: frontend
    ports:
    - protocol: TCP
      port: 3000
```

This is how the network policy look like now:
Frontend --> Backend , Port: 3000 ✅ Allow
Other --> Backend ❌ Deny

## Run CIS Benchmark to identify security risks for cluster components

To run CIS benchmark on Control Plane:
```sh
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml
```

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_230627.png)

Upon Job execution, the corresponding Pod running the verification process can be identified by its name in the default namespace. The Pod’s name starts with the prefix kube-bench, then appended with the type of the node plus a hash at the end.

Wait until the Pod transitions into the “Completed” status to ensure that all verifica‐ tion checks have finished. You can have a look at the benchmark result by dumping the logs of the Pod. A more convenient way would be to redirect logs to a file.

To see pods in a different POV:
```sh
minikube ssh
docker ps
```
## Creating an Ingress with TLS Termination

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_132607.png)

It’s important to point out that the communication typically uses unencrypted HTTP network communication as soon as it passes the Ingress.

Configuring the Ingress for HTTPS communication relieves you from having to deal with securing the network communication on the Service level. In this section, we will learn how to create a TLS certificate and key, how to feed the certificate and key to a TLS-typed Secret object, and how to configure an Ingress object so that it supports HTTPS communication
### Deploy service and pods

In the context of an Ingress, a backend is the combination of Service name and port. Before creating the Ingress, we’ll take care of the Service, a Deployment, and the Pods running nginx so we can later on demonstrate the routing of HTTPS traffic to an actual application. All of those objects are supposed to exist in the namespace t75. `t75.yml` defines all of those resources as a means to quickly create the Ingress backend.

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_115911.png)


This command runs a one-off Pod named `tmp` with the `busybox` image. It does not automatically restart if the container exits and will be deleted after the command completes. Inside this Pod, it executes `wget` to attempt a connection to the IP address `10.107.8.33` on port `80`, which is useful for testing network connectivity or checking if a web server is reachable from within the cluster.

```sh
kubectl run tmp --image=busybox --restart=Never -it --rm -- wget 10.107.8.33:80

Connecting to 10.107.8.33:80 (10.107.8.33:80)
saving to 'index.html'
index.html           100% |********************************|   612  0:00:00 ETA
'index.html' saved
pod "tmp" deleted
```

### Create TLS Certificate and Key

```sh
$env:OPENSSL_CONF = "C:\Program Files\Git\usr\ssl\openssl.cnf
```

```sh
openssl req -nodes -new -x509 -keyout accounting.key -out accounting.crt -subj "/CN=accounting.tls"
```

This command generates a new self-signed TLS certificate and private key without encrypting the key. The certificate will have the Common Name (CN) set to `accounting.tls`, and the files will be saved as `accounting.key` and `accounting.crt`, respectively.

Here’s what each file is used for:

- **`accounting.key`**: The private key used to sign the certificate.
- **`accounting.crt`**: The self-signed certificate that can be used for SSL/TLS connections.

For use in production environments, you’d generate a key file and use it to obtain a TLS certificate from a certificate authority (CA). For more information on creating a TLS certification and key.

### Creating the TLS-Typed Secret:

using kubectl will automatically base64 encode the tls certificate accounting.crt.

```sh
kubectl create secret tls accounting-secret --cert=accounting.crt key=accounting.key -n t75
```

or you can manually base64 encode it then put it on a yaml then apply the tls secret.

```yml
apiVersion: v1
kind: Secret
metadata:
  name: accounting-secret
  namespace: t75
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk... # (Truncated base64-encoded certificate data)
  tls.key: LS0tLS1CRUdJTiBQUklWVRFIEtFWS0tLS0tCk... # (Truncated base64-encoded private key data)
```

This command will create a Kubernetes Secret named `accounting-secret` in the `t75` namespace. The Secret will contain the TLS certificate and private key that you generated earlier. This Secret can be used by Kubernetes resources like Ingress controllers or Pods to secure communications using SSL/TLS.

### Create Ingress:

```ad-info
*Ingress*, *LoadBalancer*, and *NodePort* are all ways of exposing services within your K8S cluster for external consumption.

An ingress controller acts as a reverse proxy and load balancer inside the Kubernetes cluster. It provides an entry point for external traffic based on the defined Ingress rules. Without the Ingress Controller, Ingress resources won’t work.

The Ingress Controller doesn’t run automatically with a Kubernetes cluster, so you will need to configure your own. An ingress controller is typically a reverse web proxy server implementation in the cluster.

```

```sh
kubectl apply -f accounting-ingress.yml
```

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_120222.png)

or with kubectl: 

```sh
kubectl create ingress accounting-ingress \ --rule="accounting.internal.acme.com/*=accounting-service:80, \ tls=accounting-secret" -n t75
```

the port 443 is listed in the “PORT” column, indicating that TLS termination has been enabled.

Creating an ingress object with no ingress controller in place will result in the following outpout:

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_123006.png)

your ingress object will not get an ip address.

so we first need to create an ingress controller which will be type: LoadBalancer, then the ingress object will get an ip from this LB.

to install the ingress controller:

```sh
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.3.0/deploy/static/provider/cloud/deploy.yaml
```

```bash
kubectl get service ingress-nginx-controller --namespace=ingress-nginx
```

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_123146.png)

Now your ingress object will get an ip:

```sh
kubectl get ingress accounting-ingress -n t75 

NAME                 CLASS   HOSTS                          ADDRESS         PORTS     AGE
accounting-ingress   nginx   accounting.internal.acme.com   10.102.150.36   80, 443   10m
```

or for more details on the ingress object, use describe:

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_123415.png)


add this line to your hosts file, for windows it's on `C:\Windows\system32\drivers\etc\hosts`: 

```
10.102.150.36 accounting.internal.acme.com 
```

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_124233.png)

- **Encryption Provided by TLS:** The TLS configuration in the Ingress resource only encrypts traffic from external clients to the Ingress controller.
- **Internal Communication (Service to Pod):** Within the Kubernetes cluster, communication between services and pods remains unencrypted unless additional measures are taken.

#### Securing Internal Communication (Pod-To-Pod):

If you need to encrypt internal traffic between services and pods (e.g., for sensitive data or compliance reasons), consider the following options:

- **mTLS (Mutual TLS):** Implement mTLS using tools like Istio or Linkerd to encrypt traffic within the cluster.
- **Service Mesh:** Deploy a service mesh like Istio to manage and enforce encryption policies for inter-service communication.
- **Pod-Level TLS:** Implement TLS directly in the applications running in your pods.
## Protecting Node Metadata and Endpoints

Kubernetes clusters expose ports used to communicate with cluster components. For example, the API server uses the port 6443 by default to enable clients like kubectl to talk to it when executing commands.

Inbound control plane node ports:

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_135818.png)

Many of those ports are configurable. For example, you can modify the API server port by providing a different value with the flag --secure-port in the configuration file `/etc/kubernetes/manifests/kube-apiserver.yaml`, as documented for the cluster component. For all other cluster components, please refer to their corresponding documentation.

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_135919.png)

To secure the ports used by cluster components, set up firewall rules to minimize the attack surface area. For example, you could decide not to expose the API server to anyone outside of the intranet. Clients using kubectl would only be able to run commands against the Kubernetes cluster if logged into the VPN, making the cluster less vulnerable to attacks. 

Cloud provider Kubernetes clusters (e.g., on AWS, Azure, or Google Cloud) expose so-called metadata services. Metadata services are APIs that can provide sensitive data like an authentication token for consumption from VMs or Pods without any additional authorization

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_140112.png)

For example, In AWS, the metadata server can be reached with the IP address 169.254.169.254.

This link for example is the metadata endpoint of an Ec2 Instance in aws http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance

This is how content would look like:

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_224321.png)

The attacker would then simply create a profile file under  `~/.aws/credentials/exploited-endpoint`

```
[exploited-endpoint]
aws_acces_key_id=ASIA6GG7PSQG6BYGNVKC
aws_secret_key_access=Hm2Bcnbgjy+fUUhnLRejnKGTl8AcoIDrNP/HZjfY
aws_session_token=IQoJb3JpZ2luX....
```

then run the following line to use this user when using aws cli to interact with the target.
```shell
export AWS_PROFILE=exploited-endpoint
```

To prevent any Pod in a namespace from reaching the IP address of the metadata server, set up a network policy that allows egress traffic to all IP addresses except 169.254.169.254.

```yml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress-metadata-server
  namespace: a12
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
```

Once the network policy has been created, Pods in the namespace a12 should not be able to reach the metadata endpoints anymore.
## Protecting GUI Elements

The kubectl tool isn’t the only user interface (UI) for managing a cluster. While kubectl allows for fine-grained operations, most organizations prefer a more convenient graphical user interface (GUI) for managing the objects of a cluster. You can choose from a variety of options. The Kubernetes *Dashboard* is a free, web-based application.

Other GUI dashboards for Kubernetes like *Portainer* go beyond the basic functionality by adding tracing of events or visualizations of hardware resource consumption. In this section, we’ll focus on the Kubernetes Dashboard as it is easy to install and configure.

The Kubernetes Dashboard runs as a Pod inside of the cluster. 

In order to install Kubernetes Dashboard simply run:

```shell
# Add kubernetes-dashboard repository
helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/
# Deploy a Helm Release named "kubernetes-dashboard" using the kubernetes-dashboard chart
helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard

kubectl get deployments,pods,services -n kubernetes-dashboard
```

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_140834.png)

As we can see, kong-proxy type in *ClusterIP*, which means we can't access it outside the cluster, it needs to be type of *NodePort* and we need to enable http communication so that we can access it via the browser.

Create values.yaml:
```yml
kong:
  proxy:
    type: NodePort
  http:
    enabled: true
```

```sh
helm upgrade kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard -f values.yaml --namespace kubernetes-dashboard  
```

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_152814.png)

To access Dashboard run:

```sh
kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443

Forwarding from 127.0.0.1:8443 -> 8443
Forwarding from [::1]:8443 -> 8443
```

Now go to `https://localhost:8443` and it will ask you to prompt the bearer token.

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_153040.png)

### Creating a User with Administration Privileges

Before you can authenticate in the login screen, you need to create a ServiceAccount and ClusterRoleBinding object that grant admin permissions. Start by creating the file admin-user-serviceaccount.yaml .

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_144426.png)

```sh
kubectl create -f admin-user-serviceaccount.yaml
kubectl create -f admin-user-clusterrole\ binding.yaml
```

You can now create the bearer token of the admin user with the following command. The command will generate a token for the provided ServiceAccount object and render it on the console.

```sh
kubectl create token admin-user -n kubernetes-dashboard
```

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_223627.png)

Go to the Dashboard and feed it the token to access.

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_153249.png)

### Creating a User with Restricted Privileges

In the previous section, you learned how to create a user with cluster-wide admin‐ istrative permissions. Most users of the Dashboard only need a restricted set of per‐ missions, though. For example, developers implementing and operating cloud-native applications will likely only need a subset of administrative permissions to perform their tasks on a Kubernetes cluster.

Creating a user for the Dashboard with restricted privileges consists of a three-step approach:

1. Create a ServiceAccount object. 
2. Create a ClusterRole object that defines the permissions. 
3. Create a ClusterRoleBinding that maps the ClusterRole to the ServiceAccount.

```yml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: developer-user
  namespace: kubernetes-dashboard
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  name: cluster-developer
rules:
- apiGroups:
  - '*'
  resources:
  - '*'
  verbs:
  - get
  - list
  - watch
- nonResourceURLs:
  - '*'
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: developer-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-developer
subjects:
- kind: ServiceAccount
  name: developer-user
  namespace: kubernetes-dashboard

```

```sh
kubectl create token developer-user -n kubernetes-dashboard
```

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_223352.png)

Developer user cannot delete a pod, let's try;

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_155914.png)

An error message rendered when trying to invoke a permitted operation.

### Avoiding Insecure Configuration Arguments

Securing the Dashboard in production environments involves the usage of execution arguments necessary for properly configuring authentication and authorization. By default, login functionality is enabled and the HTTPS endpoint will be exposed on port 8443. You can provide TLS certificates with the --tls-cert-file and --tlscert-key command line options if you don’t want them to be auto-generated. 

Avoid setting the command line arguments --insecure-port to expose an HTTP endpoint and --enable-insecure-login to enable serving the login page over HTTP instead of HTTPS. Furthermore, make sure you don’t use the option --enable-skip-login as it would allow circumventing an authentication method by simply clicking a Skip button in the login screen.

## Verifying Kubernetes Platform Binaries

The Kubernetes project publishes client and server binaries with every release

The executables kubectl and kubeadm are essential for interacting with Kubernetes. kubectl lets you run commands against the API server.

Know how to detect modified platform binaries 

Platform binaries like kubectl and kubeadm can be verified against their corresponding hash code. Know where to find the hash file and how to use a validation tool to identify if the binary has been tempered with.

You can download the corresponding hash code for a binary from https://dl.k8s.io. The full URL for a hash code reflects the version, operating system, and architecture of the binary. The following list shows example URLs for platform binaries compati‐ ble with Linux AMD64:

- kubectl: https://dl.k8s.io/v1.26.1/bin/linux/amd64/kubectl.sha256 
- kubeadm: https://dl.k8s.io/v1.26.1/bin/linux/amd64/kubeadm.sha256 
- kubelet: https://dl.k8s.io/v1.26.1/bin/linux/amd64/kubelet.sha256 
- kube-apiserver: https://dl.k8s.io/v1.26.1/bin/linux/amd64/kube-apiserver.sha256

The following commands demonstrate downloading the kubeadm binary for version 1.26.1 and its corresponding SHA256 hash file:

```sh
curl -LO "https://dl.k8s.io/v1.26.1/bin/linux/amd64/kubeadm" 
curl -LO "https://dl.k8s.io/v1.26.1/bin/linux/amd64/kubeadm.sha256" 
```

The validation tool shasum can verify if the checksum matches: 

```sh
echo "$(cat kubeadm.sha256) kubeadm" | shasum -a 256 --check 
kubeadm: OK 
```

The previous command returned with an “OK” message. The binary file wasn’t tampered with. Any other message indicates a potential security risk when executing the binary


## Summary

![image](https://flowhero.github.io/assets/images/shemas/2024_08_18_130827.png)

#### Understand the Purpose and Effects of Network Policies

- **Default Behavior**: By default, Pod-to-Pod communication is unrestricted.
- **Default Deny Rule**: Instantiate a default deny rule to restrict Pod-to-Pod network traffic, applying the principle of least privilege.
- **Network Policy Attributes**:
    - **`spec.podSelector`**: Selects the target Pod for the rules based on label selection.
    - **Ingress and Egress Rules**: Define Pods, namespaces, IP addresses, and ports for allowing incoming and outgoing traffic.
- **Aggregation of Policies**: Network policies can be aggregated. A default deny rule may disallow ingress and/or egress traffic. Additional policies can open up those rules with more fine-grained definitions.

#### Practice the Use of `kube-bench` to Detect Cluster Component Vulnerabilities

- **Kubernetes CIS Benchmark**: A set of best practices for recommended security settings in a production Kubernetes environment.
- **Automation with `kube-bench`**: Automate the detection of security risks using `kube-bench`.
- **Report Interpretation**: The generated report describes detailed remediation actions to fix detected issues. Learn to interpret the results and mitigate issues.

#### Know How to Configure Ingress with TLS Termination**

- **Ingress Configuration**: An Ingress can be configured to expose an HTTPS endpoint to send and receive encrypted data.
- **TLS Secret**: Create a TLS Secret object and assign it a TLS certificate and key. The Secret can be consumed by the Ingress using the `spec.tls[]` attribute.

#### Know How to Configure GUI Elements for Secure Access**

- **GUI Protection**: GUI elements, like the Kubernetes Dashboard, must be protected from unauthorized access to prevent potential harm.
- **RBAC Configuration**: Properly set up RBAC (Role-Based Access Control) for specific stakeholders.
- **Security-Related Command Line Arguments**: Have a rough understanding of security-related command line arguments. Practice installing the Dashboard, tweaking command line arguments, and setting permissions for different users.

#### Know How to Detect Modified Platform Binaries

- **Binary Verification**: Platform binaries like `kubectl` and `kubeadm` can be verified against their corresponding hash codes.
- **Hash Files and Validation**: Know where to find the hash files and how to use validation tools to check if the binaries have been tampered with.