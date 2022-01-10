# k8s-certchecker

## What is it?

This is a simple system designed to detect (and ultimately re-issue) SSL certificates in a Kubernetes cluster.

It is written in Go and consists of several modules:

- **certchecker** This does the actual work of checking the certificates. It's intended to be run as a cron job
and requires fairly intrusive permissions (the ability to decode secrets) so you should be careful about where you host
it and how it's run
- **datapersistence** This consists of data models for sharing data between **webserver** and **certchecker**
- **webserver** This will present a UI to allow an administrator to see the results of **certchecker** runs. It's not
completed yet.

## How do I build it?

You'll require a recent version of the Go SDK (1.11+, ideally 1.16+) and GNU make installed (you should be able
to get that with your distro's standard development tools).

With that done, simply:

```bash
make test && make
```

in the root directory of the repo.  This will give you Mac and Linux binaries of each of the two main tools in their
source directories.

Then simply run them:

```bash
cd certchecker
./certchecker.macos -help
```

## How does it work?

In a Kubernetes environment, SSL certificates for HTTPS are normally stored in the cluster as Secrets,
with a `type` of `kubernetes.io/tls`.

Using the function `certfinder.ScanForCertificates`, we first list out the available namespaces from the cluster
and then for each namespace we search for Secrets with the type `kubernetes.io/tls`.

We then request the server to give us the content for each of these, and decode the certificate itself (`tls.crt`)
using standard Go crypto routines. 

We examine the starting time, expiry time and compare them with the current date to give one of five outcomes:
- the cert is not valid yet
- the cert is valid
- the cert is valid, but will expire soon ("soon" is defined with a commandline option to `certchecker`)
- the cert has expired
- the cert is valid, but it's valid for longer than Chrome will accept (more of a warning than anything else)

The result is logged, and a json file is output to shared storage from where it can be read by a webserver
to present to a frontend.

### Permissions

Now, obviously Kubernetes does not just allow _any_ process to decode the contents of Secrets (or access anything else
in the cluster, for that matter).

In order for the software to work, you must grant it permissions.  Assuming that your cluster is in RBAC mode, you need
to allow `get` and `list` for both `namespaces` and `secrets` at the cluster level, if you want to examine everything.
In order to do this, you must:
 - create a `ClusterRole` giving these permissions
 - create a `ServiceAccount` for the app to run with
 - add a `ClusterRoleBinding` to associate the `ClusterRole` with the `ServiceAccount`
 - update the pod template for `cert-checker` to run with the given `ServiceAccount`.

The provided `sample_deployment` shows how to do this in practise.

Alternatively, you can set up a per-namespace `Role` to allow `get` and `list` of secrets if you want to limit the visibility
off the app.

## How do I set it up?

1. Use the Dockerfile provided to build a docker image and push it to where you host your secure images:
```bash
cd certchecker
docker build . -t myorg.io/certchecker/certchecker:DEV
docker push myorg.io/certchecker/certchecker:DEV
```

2. Examine "certchecker.yaml" in the sample_deployment directory.

- You will see that this is not quite as simple as just running the app.
- Reading from the bottom up, you'll see a `ClusterRoleBinding`, a `ServiceAccount` and a `ClusterRole` all created
in order to give the app permission to read the certificates from the server. As with any security-related config,
you should examine these carefully before deploying to a real system.
- You will also notice that a `PersistentVolumeClaim` called `certchecker-logs` is requested, but not defined in the
manifest.  You should provide your own claim, this is just somewhere to put the json files created when the process runs
so that they can be shared elsewhere.  Any old available storage will do.

3. Update the `image` field to the image you uploaded in step 1 and the `schedule` field to when you want it to run.
- There's not much point in running it more than once a day.

4. Deploy the manifest with `kubectl apply -f` and then trigger a job to test that it is working.