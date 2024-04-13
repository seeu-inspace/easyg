## Cloud hacking

**Resources**
- [cloud_metadata.txt](https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b), Cloud Metadata Dictionary useful for SSRF Testing


### <ins>Abusing S3 Bucket Permissions</ins>

Target example: `http://[name_of_bucket].s3.amazonaws.com`

**Read Permission**

- `aws s3 ls s3://[name_of_bucket]  --no-sign-request`
- `aws s3 ls s3://pyx-pkgs --recursive --human-readable --summarize`

**Write Permission**

- `aws s3 cp localfile s3://[name_of_bucket]/test_file.txt –-no-sign-request`

**READ_ACP**

- `aws s3api get-bucket-acl --bucket [bucketname] --no-sign`
- `aws s3api get-object-acl --bucket [bucketname] --key index.html --no-sign-request`

**WRITE_ACP**

- `aws s3api put-bucket-acl --bucket [bucketname] [ACLPERMISSIONS] --no-sign-request`
- `aws s3api put-object-acl --bucket [bucketname] --key file.txt [ACLPERMISSIONS] --no-sign-request`

**Tools**
- [Anonymous Cloud](https://portswigger.net/bappstore/ea60f107b25d44ddb59c1aee3786c6a1)
- [AWS CLI](https://aws.amazon.com/it/cli/)
- [S3Scanner](https://github.com/sa7mon/S3Scanner) A tool to find open S3 buckets and dump their contents
- [Cloud - AWS Pentest](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md)
- [s3enum](https://github.com/koenrh/s3enum)
- To find secrets, you can use [trufflehog](https://github.com/trufflesecurity/trufflehog).

**Resources**
- [Abusing S3 Bucket Permissions](https://blog.yeswehack.com/yeswerhackers/abusing-s3-bucket-permissions/)
- [Amazon S3: Allows read and write access to objects in an S3 Bucket](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_s3_rw-bucket.html)


### <ins>AWS Cognito</ins>

If you've found aws cognito client id and secret
1. `clientID:clientSercret` => `base64KEY`
2. `curl -X POST 'https://xx.amazoncognito.com/oauth2/token' \   -H 'Authorization: Basic base64KEY'\   -H 'Content-Type: application/x-www-form-urlencoded' \   -d 'grant_type=client_credentials'`
3. [Source](https://twitter.com/GodfatherOrwa/status/1670617783510376448)



### <ins>Google Cloud Storage bucket</ins>

**Tools**
- [Anonymous Cloud](https://portswigger.net/bappstore/ea60f107b25d44ddb59c1aee3786c6a1)
- https://github.com/RhinoSecurityLabs/GCPBucketBrute

**Resources**
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/
