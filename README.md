# A Solution to Revoke Unwanted IAM permissions in AWS
This reference solution detects IAM API callers who do not belong to *"Administrators"* group and automatically revokes their permissions. Optionally, it then sends an e-mail notification via an SNS topic. The solution is useful in a large organization where number of users grows rapidly and tracking permissions for each user is a challenge. It ensures that only users added to *"Administrators"* group are given permission to invoke IAM APIs. It is an implementation of the [sample solution](https://aws.amazon.com/blogs/security/how-to-detect-and-automatically-revoke-unintended-iam-access-with-amazon-cloudwatch-events/) proposed by AWS.

<br/>

> Note that this process is a reactive approach because it gets triggered after the user has already invoked the IAM API.

<br/>

![Architecture diagram](https://github.com/oyenamit/aws-revoke-unintended-iam-access/blob/master/docs/architecture.png)

## Solution Components
The CloudFormation template contains the following:
1. An IAM managed policy which denies all IAM operations.
2. An IAM Role that allows Lambda to call IAM service and create CloudWatch Logs.
3. An IAM role that allows CloudTrail to log events to CloudWatch Logs.
4. A CloudTrail that logs IAM API calls to CloudWatch Logs.
5. A rule added to CloudWatch Events to detect IAM API calls and invoke a Lambda function.
6. A Lambda function which checks if user is in *"admins"* group. If not, it attaches the policy to the user denying all IAM operations. The name of the group is configurable via an environment variable (*ADMIN_GROUP_NAME*). The lambda then sends a notification via e-mail if an SNS topic has been provided at the time of CloudFormation stack creation.

## Input Parameters
The Cloudformation template requires the following input:
1. *TrailDestS3BucketName*: The name of S3 bucket where CloudTrail will save logs. The bucket must have its [bucket policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html) set to allow CloudTrail to write these logs.
2. *LambdaS3BucketName*: S3 bucket name where Lambda code resides
3. *LambdaZipfileName*: Lambda code zipfile name
4. *LambdaHandler*: Lambda code handler name (default: *index.handler*)
5. *AdminGroupName*: If the user is part of this group, his IAM permissions will not be revoked (default: *Administrators*)
6. *SNSTopicArn*: Optionaly, you can specify an SNS topic which would be notified after IAM permissions have been revoked

## Instructions
1. To test the solution, create an IAM user who is not part of the *"Administrators"* group but has full privileges for IAM service.
2. Login using this user's credentials and perform any IAM configuration change (for example, adding or removing a rule)
3. The solution will detect this change and deny all IAM permissions for this user.
4. Verify that the user no longer has access to IAM service by revisting the [AWS Console](https://console.aws.amazon.com/iam/).
5. If an SNS topic was provided while provisioning the CloudFormation template, the solution will also send an e-mail notification.

## Cleanup
To remove all created resources:
1. Detach the managed policy from the IAM user that was created to test the solution.
2. Delete the AWS CloudFormation stack.
3. Optionally, remove the IAM test user.

<br/><br/>

> **Note 1**: This solution should be deployed in us-east-1 (N. Virginia) region. This is because IAM is a global service and its API calls are available to CloudTrail in that region only.

<br/>

> **Note 2**: When a user changes IAM configuration, it can take several minutes before the API call is logged to CloudWatch via CloudTrail. As per [AWS documentation](https://aws.amazon.com/cloudtrail/faqs/), CloudTrail delivers an event within 15 minutes of the API call.

<br/>

> **Note 3**: When a user changes IAM configuration (for example, creates a new role), it is possible that multiple IAM API calls are invoked (*CreateRole*, *AttachRolePolicy*). This can cause CloudWatch event to be raised multiple times. The lambda function checks if IAM permissions for the user are already revoked. If so, it does not process the event. However, if the event is generated almost simultaneously, the lambda function is called multiple times almost simultaneously. This can cause e-mail notification to be sent multiple times for the same user. To workaround this problem, [SQS Message Deduplication](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-messagededuplicationid-property.html) can be used.
