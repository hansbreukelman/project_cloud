#!/usr/bin/env python3

import aws_cdk as cdk

from project_cloud.project_cloud_stack import ProjectCloudStack


app = cdk.App()
ProjectCloudStack(app, "project-cloud")

app.synth()
