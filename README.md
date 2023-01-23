
# Welcome to your CDK Python project!

You should explore the contents of this project. It demonstrates a CDK app with an instance of a stack (`project_cloud_stack`)
which contains an Amazon SQS queue that is subscribed to an Amazon SNS topic.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

This project is set up like a standard Python project.  The initialization process also creates
a virtualenv within this project, stored under the .venv directory.  To create the virtualenv
it assumes that there is a `python3` executable in your path with access to the `venv` package.
If for any reason the automatic creation of the virtualenv fails, you can create the virtualenv
manually once the init process completes.

To manually create a virtualenv on MacOS and Linux:

```
$ python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
$ source .venv/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
% .venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
$ pip install -r requirements.txt
```

At this point you can now synthesize the CloudFormation template for this code.

```
$ cdk synth
```

You can now begin exploring the source code, contained in the hello directory.
There is also a very trivial test included that can be run like this:

```
$ pytest
```

To add additional dependencies, for example other CDK libraries, just add to
your requirements.txt file and rerun the `pip install -r requirements.txt`
command.

## Useful commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation

Enjoy!

How to connect with the webserver

Get ID key pair
aws ec2 describe-key-pairs --filters Name=key-name,Values=[key-name-file] --query KeyPairs[*].KeyPairId --output text

outcome:
key-0c1517b5ea1f3f72f (EXAMPLE)

Create private key file with content
aws ssm get-parameter --name /ec2/keypair/[outcome] --with-decryption --query Parameter.Value --output text > [key-name-file]

If ‘Pem-file’ is created for the webserver then:
In the windows rdp, open the powershell console.

Run these commands:

Make file:
New-Item C:\Users\Administrator\web_KPR.pem

Put content in file command:
(Copy paste the private key content between the brackets.)
Set-Content D:\temp\test\test.txt ‘PRIVATE KEY CONTENT’

It should look something like this:
Set-Content C:\Users\Administrator\web_KPR.pem '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAjXJ6rU2CMP6/RBCclMZxxCQGus0KOXYW5CgqSF9C33CusQCn
JCfp5jTHvCoHRlIwrmk2cu23hJ/Be7EbuaEABbSwQj+/FQtVnBpIMyNVo8XfT9V2
fJ4phXvcr/xYJwkIXsRcBz4VvTIDtYbvf4hBLSH2vbqxpKeQmwfofH1b6qJEgWVi
hk/70YuxA6U4fquqir6mcQrkXpiqsonqwyYnTGxtyuArPnudyjN5rDVs2UD3XGuq
Ei38wPvLGCmGfXtXG9+7hPRkssW4GYzOXyObkMAuCnr9k4G5Pv7elOqT5AQ8APIA
kRf6XubWKYzv1YwKwM5HKVXcWpnReTkZqOwHeQIDAQABAoIBAAnHd2nR6QVgJ3Ma
PukeSzFHWFvD30gXvP9rM3krdOEj1kAQjn22cLpkvcZplXUsK4dzaLtLahu2O9dE
aGlOE0VRt7ns1FYtIW8YdhNrBvm6rXTEiluVR8Ody6UzKhkQy85Zfw9VIIWjFpSP
TrGfhvoK1hdJ+AwtNZcyVcV9mURAd1xHXHTqEdbGgD2do0MYPrbMadFIyPEGyZn/
8JSQpfszww4yP9jxP4npL3Y+jpIFRkUAUb+xgl6uR4LGqp2nsR0VPf8UTNvX7q17
Sp32oq9hzxF5lPey03mD5Kyh4muZMbfIkSgXbRZA5/Yfu3Jp1MEcX8Yj+4GV+Dr5
00QAxvECgYEAzjajS2q00DSXAHJjXUVZXb1IsWuEagVcZ6+Y1cMJ8EiTo7OePCj0
8TAg6VPjwNL0OJrV8iwKUOySx2/I4upOyLAkh3ZWmTn/IBc4p1IW+txv9e369SyL
oH1Gfg6Dl0F+6tNcDn76saZABj5ZU4pY2Vir66tEwHvSHveWwPLf680CgYEAr5jb
P2BkmwoJl/vEGFCvBtqBR1vSoHCkPf667C3craw6+KYgxCItNUP7jCPF9XEJUxvW
iaACOEb0cdQ2EpQd/hOvRwXXmPP081h+Edlk9ONLDWGs7NCDrNK0saD7aJQUIWFv
st3uqWkLQaag2T+oiIhU7lzNYr7GPRpn9/5O1l0CgYAJwrBL+4r/Z93V2ZQ2b/fg
5fqw2yPzWLmc9sTHKWopA2ZpkzDkLBQb7mlAYgYftFx26W1C/y6l0ezIn9PkWa7M
9PllqAZFTmdy/2ZhFROdYB20iEUeobMiL4vMn6c+24zEVKjAzuXSzsmtAfp8Z8n4
z6ejigHBEptJd/Kcw2Ix6QKBgHUeD4Waxh8+N53d9zF8hvCcRkOQ88+8sV8ECipC
gIB5ci+rpgkK/nobaKhUp9EHXn/G/nV2emSMtrdBIfuMPODcwjgtplnGxOaVbCh9
hb9r5f/72LlubZSUSJ58z5I1yaNl+HklWuw1OqPD/l5H/iFqRLNixD4LHe9dMGEQ
hgalAoGBAKS2Q3nGMd0UpnyCyf3EdGNI30dra9TI8nAq4arqOv9TKn6ebcbif3WK
J0i7MlWKca7RQXd7C5Cp06qisXvLm+E0+Lc1gM5T+DCNBfPUaCnLcbxPotVzMTZA
1dM6MxMYMGZ9xIxESaFPXtASWNldiBkkkk2UTKE+2DHztXNFvuNu
-----END RSA PRIVATE KEY-----'

Then run this command:
ssh -i “web_KPR.pem" ec2-user@<private IP Webserver>

Now you are connected to the web server!

With this command you can check if the server is running correctly:
sudo systemctl status httpd


