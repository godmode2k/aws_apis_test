# AWS APIs Test


Summary
----------
> AWS APIs Test: </br>
> Bills APIs, ... test </br>


Environment
----------
> build all and tested on GNU/Linux

    GNU/Linux: Ubuntu 20.04_x64 LTS
    Python: v3.x


Run
----------
```sh
$ pip3 install boto3

~/.aws/credentials
[default]
aws_access_key_id = <YOUR_KEY>
aws_secret_access_key = <YOUR_SECRET>

~/.aws/config
[default]
region=us-east-1


$ python3 ./test_aws-cost-and-usage-report.py --datestart="2021-11-01" --dateend="2021-12-01"

```
