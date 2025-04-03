import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';

export class RoleReaperStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const bucket = s3.Bucket.fromBucketName(
            this,
            `${this.stackName}-bucket`,
            'security-tooling-bucket'
        );

        const role = new iam.Role(this, `${this.stackName}-role`, {
            roleName: `${this.stackName}-role`,
            assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName(
                    'service-role/AWSLambdaBasicExecutionRole'
                ),
                iam.ManagedPolicy.fromAwsManagedPolicyName(
                    'service-role/AWSLambdaVPCAccessExecutionRole'
                )
            ]
        });

        const policy = new iam.ManagedPolicy(this, `${this.stackName}-policy`, {
            managedPolicyName: `${this.stackName}-policy`,
            statements: [
                new iam.PolicyStatement({
                    sid: 'AllowWritingToBucket',
                    effect: iam.Effect.ALLOW,
                    actions: [
                        's3:GetObject',
                        's3:PutObject',
                        's3:DeleteObject',
                        's3:ListBucket',
                        's3:ListObjects'
                    ],
                    resources: [
                        bucket.arnForObjects(`${this.stackName}/*`),
                        bucket.bucketArn
                    ]
                }),
                new iam.PolicyStatement({
                    sid: 'AllowReadingRoles',
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'iam:GetRole',
                        'iam:ListRoles',
                        'iam:TagRole',
                        'iam:UntagRole'
                    ],
                    resources: ['*']
                }),
                new iam.PolicyStatement({
                    sid: 'AllowDeletingRoles',
                    effect: iam.Effect.ALLOW,
                    actions: ['iam:DeleteRole'],
                    resources: ['*'],
                    conditions: {
                        StringEquals: {
                            'iam:ResourceTag/RoleReaper': 'true'
                        }
                    }
                })
            ]
        });

        policy.attachToRole(role);

        const fn = new lambda.Function(this, `${this.stackName}-function`, {
            functionName: `${this.stackName}-function`,
            runtime: lambda.Runtime.PYTHON_3_12,
            code: lambda.Code.fromAsset('lambda'),
            handler: 'index.handler',
            role: role,
            environment: {
                BUCKET_NAME: bucket.bucketName,
                BUCKET_FOLDER: `${this.stackName}/`,
                DRY_RUN: 'false',
                DELETE: 'false',
                TAG_KEY: 'RoleReaper',

            }
        });
    }
}
