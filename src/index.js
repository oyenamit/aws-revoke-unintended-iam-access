/* ***** BEGIN LICENSE BLOCK *****
 *
 * Copyright (C) 2020 Namit Bhalla (oyenamit@gmail.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 * ***** END LICENSE BLOCK ***** */



const aws = require('aws-sdk');
const iam = new aws.IAM();
const sns = new aws.SNS();


exports.handler = async (event) => {

    try {
        console.log('Received event:', JSON.stringify(event, null, 2));

        // ---------------------------------------------------------------------------------------------
        // If the caller is not an IAM user, do nothing
        // ---------------------------------------------------------------------------------------------
        if (event.detail.userIdentity.type != 'IAMUser') {

            console.log('This call was not made by an IAM user!');
            return "";

        } else {

            // -----------------------------------------------------------------------------------------
            // Get the user name which invoked the IAM API call
            // -----------------------------------------------------------------------------------------
            let userName = event.detail.userIdentity.userName;    

            // -----------------------------------------------------------------------------------------
            // List the groups for the user. If the user is not part of the 'Administrators' group,
            // revoke their IAM access
            // -----------------------------------------------------------------------------------------
            let groups = await iam.listGroupsForUser({UserName: userName}).promise();

            for (let i = 0; i < groups.Groups.length; i++)
            {
                if (groups.Groups[i].GroupName == process.env.ADMIN_GROUP_NAME)
                {
                    console.log('Not revoking permissions as \'' + userName + '\' is part of the \'' + process.env.ADMIN_GROUP_NAME + '\' group');
                    return "";
                }
            }

            await revokeAccess(userName);
        }
    }
    catch(e) {
        console.log(e);
    }

    return "";
};


// -------------------------------------------------------------------------------------------------
// Helper function to revoke IAM access by attaching a 'Deny' policy to the IAM user.
// If the IAM user already has more than the allowed number of managed policies attached, add an
// inline policy to deny access.
// -------------------------------------------------------------------------------------------------
async function revokeAccess(userName)
{
    let denyPolicyArn = process.env.DENY_POLICY_ARN;

    try {
        // -----------------------------------------------------------------------------------------
        // Before attaching policy, check if it is already attached
        // -----------------------------------------------------------------------------------------
        let policies = await iam.listAttachedUserPolicies({ UserName: userName }).promise();
        for (let i = 0; i < policies.AttachedPolicies.length; ++i)
        {
            if (policies.AttachedPolicies[i].PolicyArn == denyPolicyArn)
            {
                console.log('Managed policy already attached to user!');
                return "";
            }
        }

        await iam.attachUserPolicy({ UserName: userName, PolicyArn: denyPolicyArn }).promise();
        console.log('Revoked IAM access for IAM user ' + userName);

        await notify(process.env.SNS_TOPIC_ARN, userName);
    }
    catch(e) {
        if (e.code == 'LimitExceeded')
        {
            await revokeAccessByInlinePolicy(userName);
        }
        else
        {
            console.log('Error in attaching user policy!');
            throw e;
        }
    }

    return "";
}


// -------------------------------------------------------------------------------------------------
// Helper function to revoke IAM access by adding an inline policy
// -------------------------------------------------------------------------------------------------
async function revokeAccessByInlinePolicy(userName)
{
    const INLINE_POLICY_NAME = 'DenyIAM';
    const policyDocument =
        '{' +
        '"Version": "2012-10-17",' +
        '"Statement": [' +
        '{' +
        '"Effect": "Deny",' +
        '"Action": "iam:*",' +
        '"Resource": "*"' +
        '}' +
        ']' +
        '}';

    // ---------------------------------------------------------------------------------------------
    // Before attaching policy, check if it is already attached
    // ---------------------------------------------------------------------------------------------
    let policies = await iam.listUserPolicies({ UserName: userName }).promise();
    for (let i = 0; i < policies.PolicyNames.length; ++i)
    {
        if (policies.PolicyNames[i] == INLINE_POLICY_NAME)
        {
            console.log('Inline policy already attached to user!');
            return "";
        }
    }

    await iam.putUserPolicy({ UserName: userName, PolicyName: INLINE_POLICY_NAME, PolicyDocument: policyDocument }).promise();
    console.log('Revoked access via inline policy for IAM user ' + userName);

    await notify(process.env.SNS_TOPIC_ARN, userName);
}


// -------------------------------------------------------------------------------------------------
// Helper function to notify by sending a message to an SNS topic
// -------------------------------------------------------------------------------------------------
async function notify(topicArn, userName)
{
    if (topicArn)
    {
        const params = {
            TopicArn: topicArn,
            Message: "This is to notify you that IAM permissions for user '" + userName + "' have been revoked.",
            Subject: "IAM permissions revoked"
        };

        await sns.publish(params).promise();
        console.log('Sending notification successful');
    }
    else
    {
        console.log("No SNS topic specified !");
    }

    return "";
}

